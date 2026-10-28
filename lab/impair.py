#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Scenario Controller & Self-Test Suite
Work Packages A4 & A5: Network Impairment Controller and Repeatable S0-S6 Self-Test Harness

Provides apply, clear, self-test-baseline, and test-scenarios operations for the seven
Study Guide scenarios (S0 - S6). Ensures strict isolation, preserves A1-A3
invariance, uses only project-owned nftables tables and tc qdiscs, and coordinates
safely with the DNS lock and backups.
"""

import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_SCENARIOS_PATH = SCRIPT_DIR / "scenarios.yaml"
STATE_FILE = SCRIPT_DIR / ".impair_state.json"
LOCK_FILE = SCRIPT_DIR / ".verify_dns.lock"
DNS_CONFIG_FILE = SCRIPT_DIR / "dns_config.json"
DNS_BACKUP_A3 = SCRIPT_DIR / "dns_config.json.bak"
DNS_BACKUP_A4 = SCRIPT_DIR / "dns_config.json.impair_bak"
DNS_PID_FILE = SCRIPT_DIR / "dns.pid"
DNS_SERVER_SCRIPT = SCRIPT_DIR / "dns_server.py"

NFT_TABLE_NAME = "ps028_impair"
NFT_FAMILY = "inet"
NFT_NAMESPACE = "ps028-rt"

INTERFACE_MAPPING = {
    "ps028-rt-sv4": "ps028-rt",
    "ps028-sv-rt4": "ps028-sv",
    "ps028-rt-sv6": "ps028-rt",
    "ps028-sv-rt6": "ps028-sv",
}

BASELINE_DELAYS = {
    "ps028-rt-sv4": "10ms",
    "ps028-sv-rt4": "10ms",
    "ps028-rt-sv6": "10ms",
    "ps028-sv-rt6": "10ms",
}

BASELINE_ZONE = "he.test."
BASELINE_A_ADDR = "10.0.2.10"
BASELINE_AAAA_ADDR = "2001:db8:2::10"
DNS_SERVER_IP = "10.0.1.1"

from lab.concurrency import acquire_lab_lock, LabLockError, DEFAULT_LAB_LOCK_FILE
LAB_LOCK_FILE = DEFAULT_LAB_LOCK_FILE


class ImpairmentError(Exception):
    """Base exception for impairment controller failures."""
    pass


class LockAcquisitionError(LabLockError, ImpairmentError):
    """Raised when lab or DNS lock cannot be acquired."""
    pass


ALLOWED_NFT_INTERFACES = {"ps028-rt-sv6", "ps028-rt-sv4"}
ALLOWED_SERVER_IPS = {"2001:db8:2::10", "10.0.2.10"}


def validate_nftables_rule(rule: str, scenario_id: Optional[str] = None) -> str:
    """
    Validate that an nftables rule conforms strictly to allowed PS-028 impairment structures.
    Allowed structures:
      - S1: oifname "<iface>" ip6 daddr <server_ip> tcp flags syn / syn,ack drop
      - S2: oifname "<iface>" ip6 daddr <server_ip> tcp flags syn / syn,ack reject with tcp reset
      - S5: oifname "<iface>" ip6 daddr <server_ip> tcp flags syn / syn,ack numgen random mod <mod> < <pct> drop
    Rejects malformed, unsupported, or dangerous configurations.
    """
    if not isinstance(rule, str):
        raise ImpairmentError(f"nftables rule must be a string, got {type(rule).__name__}")

    rule_clean = rule.strip()
    if not rule_clean:
        raise ImpairmentError("nftables rule cannot be empty")

    # Anti-injection: reject semicolons, newlines, and control characters
    if any(c in rule_clean for c in (";", "\n", "\r")):
        raise ImpairmentError(f"nftables rule contains illegal control characters: '{rule_clean}'")

    # Disallow global/subsystem commands and dangerous directives
    lowered = rule_clean.lower()
    for forbidden in ("flush", "table ", "chain ", "delete ", "include ", "add table"):
        if forbidden in lowered:
            raise ImpairmentError(f"nftables rule contains forbidden keyword '{forbidden.strip()}': '{rule_clean}'")

    # Match interface clause
    if_match = re.search(r'\boifname\s+"?([^"\s]+)"?', rule_clean)
    if not if_match:
        raise ImpairmentError(f"nftables rule missing required 'oifname' clause: '{rule_clean}'")
    iface = if_match.group(1)
    if iface not in ALLOWED_NFT_INTERFACES:
        raise ImpairmentError(
            f"nftables rule specifies unauthorized interface '{iface}'. "
            f"Allowed project interfaces: {sorted(ALLOWED_NFT_INTERFACES)}"
        )

    # Match destination address clause
    daddr_match = re.search(r'\b(?:ip6|ip)\s+daddr\s+([a-fA-F0-9:.]+)', rule_clean)
    if not daddr_match:
        raise ImpairmentError(f"nftables rule missing required 'daddr' clause: '{rule_clean}'")
    daddr = daddr_match.group(1)
    try:
        ipaddress.ip_address(daddr)
    except ValueError:
        raise ImpairmentError(f"nftables rule has invalid destination IP address '{daddr}': '{rule_clean}'")
    if daddr not in ALLOWED_SERVER_IPS:
        raise ImpairmentError(
            f"nftables rule specifies unauthorized destination IP '{daddr}'. "
            f"Must target project server endpoint {sorted(ALLOWED_SERVER_IPS)}"
        )

    # Match TCP flags
    if "tcp flags" not in rule_clean or "syn" not in rule_clean:
        raise ImpairmentError(f"nftables rule must match TCP SYN flags ('tcp flags syn / syn,ack'): '{rule_clean}'")

    # Determine rule action structure
    is_s1_drop = bool(re.search(r'\bdrop\b', rule_clean) and "numgen" not in rule_clean and "reject" not in rule_clean)
    is_s2_rst = bool(re.search(r'\breject\s+with\s+tcp\s+reset\b', rule_clean))
    is_s5_loss = bool("numgen random mod" in rule_clean and re.search(r'\bdrop\b', rule_clean))

    if is_s5_loss:
        # Validate numgen parameters
        numgen_match = re.search(r'\bnumgen\s+random\s+mod\s+(\d+)\s*<\s*(\d+)', rule_clean)
        if not numgen_match:
            raise ImpairmentError(f"Malformed numgen loss expression in rule: '{rule_clean}'")
        mod_val = int(numgen_match.group(1))
        thresh_val = int(numgen_match.group(2))
        if mod_val <= 0 or not (0 < thresh_val < mod_val):
            raise ImpairmentError(
                f"Invalid numgen loss parameters (mod {mod_val} < {thresh_val}). "
                f"Threshold must be strictly between 0 and modulus: '{rule_clean}'"
            )

    matched_structures = []
    if is_s1_drop:
        matched_structures.append("S1")
    if is_s2_rst:
        matched_structures.append("S2")
    if is_s5_loss:
        matched_structures.append("S5")

    if not matched_structures:
        raise ImpairmentError(
            f"nftables rule does not match any allowed S1, S2, or S5 structure: '{rule_clean}'"
        )

    if scenario_id:
        sc_clean = scenario_id.upper()
        if sc_clean in ("S1", "S2", "S5"):
            if sc_clean not in matched_structures:
                raise ImpairmentError(
                    f"nftables rule action structure mismatch for scenario {sc_clean}: "
                    f"rule has structure {matched_structures}, expected {sc_clean}"
                )
        else:
            raise ImpairmentError(
                f"Scenario {sc_clean} does not permit nftables rules; found: '{rule_clean}'"
            )

    return rule_clean


def log_info(msg: str) -> None:
    print(f"\033[1;34m[INFO]\033[0m {msg}")


def log_ok(msg: str) -> None:
    print(f"\033[1;32m[OK]\033[0m {msg}")


def log_warn(msg: str) -> None:
    print(f"\033[1;33m[WARN]\033[0m {msg}", file=sys.stderr)


def log_error(msg: str) -> None:
    print(f"\033[1;31m[ERROR]\033[0m {msg}", file=sys.stderr)


def is_root() -> bool:
    """Check if the current process has root privileges."""
    return os.geteuid() == 0


def require_root(dry_run: bool = False) -> None:
    """Ensure root privileges are present for live modifications."""
    if not dry_run and not is_root():
        raise ImpairmentError("This operation requires root privileges. Please run with sudo or pass --dry-run.")


# ==============================================================================
# Command Execution Helpers
# ==============================================================================

def execute_cmd(
    cmd: List[str],
    dry_run: bool = False,
    check: bool = True,
    stdin_data: Optional[str] = None
) -> Tuple[int, str, str]:
    """
    Execute a system command, supporting dry-run logging.
    Returns (returncode, stdout, stderr).
    """
    cmd_str = " ".join(cmd)
    if dry_run:
        if stdin_data:
            log_info(f"[DRY-RUN] Would execute: {cmd_str} with input:\n{stdin_data.strip()}")
        else:
            log_info(f"[DRY-RUN] Would execute: {cmd_str}")
        return 0, "", ""

    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            text=True,
            capture_output=True,
            check=False
        )
        if check and proc.returncode != 0:
            err_msg = f"Command failed ({proc.returncode}): {cmd_str}\nStderr: {proc.stderr.strip()}"
            raise ImpairmentError(err_msg)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as e:
        raise ImpairmentError(f"Required binary not found while executing '{cmd[0]}': {e}")


def execute_netns_cmd(
    netns: str,
    cmd: List[str],
    dry_run: bool = False,
    check: bool = True,
    stdin_data: Optional[str] = None
) -> Tuple[int, str, str]:
    """Execute command inside a specific network namespace."""
    full_cmd = ["ip", "netns", "exec", netns] + cmd
    return execute_cmd(full_cmd, dry_run=dry_run, check=check, stdin_data=stdin_data)


# ==============================================================================
# Lock Coordination (.verify_dns.lock)
# ==============================================================================

@contextlib.contextmanager
def acquire_dns_lock(timeout: float = 5.0, lock_path: Path = LOCK_FILE):
    """
    Acquire non-blocking flock on .verify_dns.lock with timeout.
    Guarantees no bypass of A3 locking protocols and clean release on exit.
    """
    if not lock_path.parent.exists():
        lock_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    except PermissionError:
        fd = os.open(str(lock_path), os.O_RDONLY)

    start_time = time.time()
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (BlockingIOError, OSError):
                if time.time() - start_time >= timeout:
                    raise LockAcquisitionError(
                        f"Cannot acquire lock on {lock_path}: held by another test or recovery process. "
                        "Refusing to bypass active lock."
                    )
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass


# ==============================================================================
# Scenario Loader and Validator
# ==============================================================================

def load_scenarios_config(path: Path = DEFAULT_SCENARIOS_PATH) -> Dict[str, Any]:
    """Load and validate scenarios.yaml configuration file."""
    if not path.is_file():
        raise ImpairmentError(f"Scenario configuration file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ImpairmentError(f"Failed to parse YAML file {path}: {e}")

    if not isinstance(data, dict):
        raise ImpairmentError(f"Invalid scenarios configuration format in {path}")

    if "scenarios" not in data or not isinstance(data["scenarios"], dict):
        raise ImpairmentError("Missing 'scenarios' root section in configuration")

    scenarios = data["scenarios"]
    required_scenarios = {"S0", "S1", "S2", "S3", "S4", "S5", "S6"}
    missing = required_scenarios - set(scenarios.keys())
    if missing:
        raise ImpairmentError(f"Configuration is missing required Study Guide scenarios: {sorted(missing)}")

    for sc_id, sc in scenarios.items():
        validate_scenario_definition(sc_id, sc)

    return data


def validate_scenario_definition(sc_id: str, sc: Dict[str, Any]) -> None:
    """Validate structure and parameters of a single scenario definition."""
    required_keys = {"id", "name", "description", "type", "network", "dns"}
    if not required_keys.issubset(sc.keys()):
        missing = required_keys - set(sc.keys())
        raise ImpairmentError(f"Scenario {sc_id} missing required keys: {missing}")

    if sc["id"] != sc_id:
        raise ImpairmentError(f"Scenario ID mismatch: key '{sc_id}' vs id '{sc['id']}'")

    valid_types = {"baseline", "nftables", "netem", "dns"}
    if sc["type"] not in valid_types:
        raise ImpairmentError(f"Scenario {sc_id} has invalid type '{sc['type']}', must be one of {valid_types}")

    network = sc.get("network", {})
    if not isinstance(network, dict) or "delays" not in network:
        raise ImpairmentError(f"Scenario {sc_id} network config missing 'delays'")

    delays = network["delays"]
    for iface in INTERFACE_MAPPING:
        if iface not in delays:
            raise ImpairmentError(f"Scenario {sc_id} missing delay definition for interface '{iface}'")
        delay_val = delays[iface]
        if not isinstance(delay_val, str) or not re.match(r"^\d+(?:ms|s)$", delay_val):
            raise ImpairmentError(f"Scenario {sc_id} invalid delay '{delay_val}' on {iface}")

    dns_cfg = sc.get("dns", {})
    if not isinstance(dns_cfg, dict) or "A_delay_ms" not in dns_cfg or "AAAA_delay_ms" not in dns_cfg:
        raise ImpairmentError(f"Scenario {sc_id} missing A_delay_ms or AAAA_delay_ms in dns block")

    for k in ("A_delay_ms", "AAAA_delay_ms"):
        val = dns_cfg[k]
        if type(val) is not int or type(val) is bool or val < 0:
            raise ImpairmentError(f"Scenario {sc_id} dns.{k} must be non-negative integer, got {val}")

    nft_rules = sc.get("nftables", [])
    if sc["type"] == "nftables":
        if not isinstance(nft_rules, list) or len(nft_rules) == 0:
            raise ImpairmentError(f"Scenario {sc_id} of type nftables must contain non-empty 'nftables' rule list")
        for r in nft_rules:
            validate_nftables_rule(r, scenario_id=sc_id)
    else:
        if nft_rules:
            raise ImpairmentError(f"Scenario {sc_id} of type '{sc['type']}' must not specify nftables rules")


# ==============================================================================
# DNS Configuration Management (A3 Safe Coordination)
# ==============================================================================

def validate_dns_dict(data: Dict[str, Any]) -> None:
    """Strict validation of dns_config.json dictionary schema."""
    if not isinstance(data, dict):
        raise ImpairmentError("DNS config root must be an object")

    expected_keys = {"zone", "default_ttl", "rules", "behavior"}
    if set(data.keys()) != expected_keys:
        raise ImpairmentError(f"DNS config root keys mismatch: {set(data.keys())}")

    if data["zone"] != BASELINE_ZONE:
        raise ImpairmentError(f"DNS zone mismatch: expected '{BASELINE_ZONE}', got '{data['zone']}'")

    rules = data.get("rules", {})
    if not isinstance(rules, dict) or set(rules.keys()) != {"A", "AAAA"}:
        raise ImpairmentError("DNS config rules must contain exactly 'A' and 'AAAA'")

    for qtype, expected_addr in [("A", BASELINE_A_ADDR), ("AAAA", BASELINE_AAAA_ADDR)]:
        rule = rules[qtype]
        if not isinstance(rule, dict) or set(rule.keys()) != {"address", "delay_ms", "rcode"}:
            raise ImpairmentError(f"DNS rule {qtype} keys mismatch")
        if rule["address"] != expected_addr:
            raise ImpairmentError(f"DNS rule {qtype} address mismatch: {rule['address']} != {expected_addr}")
        if type(rule["delay_ms"]) is not int or type(rule["delay_ms"]) is bool or rule["delay_ms"] < 0:
            raise ImpairmentError(f"DNS rule {qtype} delay_ms must be non-negative integer")
        if rule["rcode"] != "NOERROR":
            raise ImpairmentError(f"DNS rule {qtype} rcode must be 'NOERROR'")


def load_dns_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Read and validate DNS configuration."""
    target = path or DNS_CONFIG_FILE
    if not target.is_file():
        raise ImpairmentError(f"DNS configuration file not found: {target}")
    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)
    validate_dns_dict(data)
    return data


def save_dns_config_atomically(config: Dict[str, Any], path: Optional[Path] = None, dry_run: bool = False) -> None:
    """Atomically write and fsync DNS configuration."""
    target = path or DNS_CONFIG_FILE
    validate_dns_dict(config)
    if dry_run:
        log_info(f"[DRY-RUN] Would atomically write DNS config to {target}:\n{json.dumps(config, indent=2)}")
        return

    tmp_path = target.parent / f"{target.name}.tmp.{os.getpid()}_{int(time.time() * 1000)}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


def reload_dns_server(dry_run: bool = False) -> None:
    """Deliver verified SIGHUP to the running DNS server process."""
    if dry_run:
        log_info("[DRY-RUN] Would deliver SIGHUP to DNS server process")
        return

    if not DNS_PID_FILE.is_file():
        log_warn("DNS PID file not found; cannot deliver SIGHUP.")
        return

    try:
        pid_str = DNS_PID_FILE.read_text(encoding="utf-8").strip()
        pid = int(pid_str)
    except Exception as e:
        raise ImpairmentError(f"Invalid DNS PID file {DNS_PID_FILE}: {e}")

    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = [a.decode("utf-8", errors="replace") for a in f.read().split(b"\x00") if a]
        if not any("dns_server.py" in arg for arg in cmdline):
            raise ImpairmentError(f"PID {pid} in {DNS_PID_FILE} does not match dns_server.py (cmdline: {cmdline})")
    except (FileNotFoundError, ProcessLookupError):
        raise ImpairmentError(f"DNS server process {pid} is not running (stale PID file)")
    except PermissionError:
        pass

    try:
        os.kill(pid, signal.SIGHUP)
        time.sleep(0.05)
        log_ok(f"SIGHUP delivered to DNS server (PID {pid}).")
    except Exception as e:
        raise ImpairmentError(f"Failed to send SIGHUP to DNS server (PID {pid}): {e}")


def apply_dns_delays(
    a_delay_ms: int = 0,
    aaaa_delay_ms: int = 0,
    dry_run: bool = False,
    config_file: Optional[Path] = None,
    backup_file_a3: Optional[Path] = None,
    backup_file_a4: Optional[Path] = None,
    lock_file: Optional[Path] = None
) -> None:
    """
    Safely modify DNS delay rules with exclusive lock coordination.
    Guarantees no overwrite of A3's dns_config.json.bak.
    """
    cfg_path = config_file or DNS_CONFIG_FILE
    bak_a3_path = backup_file_a3 or DNS_BACKUP_A3
    bak_a4_path = backup_file_a4 or DNS_BACKUP_A4
    lock_path = lock_file or LOCK_FILE

    require_root(dry_run=dry_run)
    if dry_run:
        log_info(f"[DRY-RUN] Would acquire DNS lock, save backup, and set delays A={a_delay_ms}ms, AAAA={aaaa_delay_ms}ms")
        return

    with acquire_dns_lock(lock_path=lock_path):
        if bak_a3_path.exists():
            raise ImpairmentError(
                f"Existing A3 backup detected at {bak_a3_path}! "
                "Refusing to apply impairment while an active A3 recovery/test backup is present. "
                "Run 'sudo ./lab/manage_dns.sh recover-config' first."
            )

        current_config = load_dns_config(path=cfg_path)

        # If S6 backup does not exist yet, preserve clean baseline to S6-owned backup
        if not bak_a4_path.exists():
            tmp_bak = bak_a4_path.parent / f"{bak_a4_path.name}.tmp.{os.getpid()}"
            with open(tmp_bak, "w", encoding="utf-8") as f:
                json.dump(current_config, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_bak, bak_a4_path)
            log_ok(f"Preserved original DNS baseline to {bak_a4_path.name}.")

        modified_config = json.loads(json.dumps(current_config))
        modified_config["rules"]["A"]["delay_ms"] = a_delay_ms
        modified_config["rules"]["AAAA"]["delay_ms"] = aaaa_delay_ms

        save_dns_config_atomically(modified_config, path=cfg_path, dry_run=dry_run)
        reload_dns_server(dry_run=dry_run)
        log_ok(f"DNS delays applied: A={a_delay_ms}ms, AAAA={aaaa_delay_ms}ms")


def restore_dns_baseline(
    dry_run: bool = False,
    config_file: Optional[Path] = None,
    backup_file_a4: Optional[Path] = None,
    lock_file: Optional[Path] = None
) -> None:
    """
    Safely restore baseline DNS delays (0ms for A and AAAA) with lock coordination.
    """
    cfg_path = config_file or DNS_CONFIG_FILE
    bak_a4_path = backup_file_a4 or DNS_BACKUP_A4
    lock_path = lock_file or LOCK_FILE

    if dry_run:
        log_info("[DRY-RUN] Would acquire DNS lock and restore DNS baseline (0ms for A and AAAA)")
        return

    if not is_root():
        log_warn("Restoring DNS baseline requires root; skipping live restore.")
        return

    with acquire_dns_lock(lock_path=lock_path):
        if bak_a4_path.exists():
            try:
                with open(bak_a4_path, "r", encoding="utf-8") as f:
                    bak_config = json.load(f)
                validate_dns_dict(bak_config)
                save_dns_config_atomically(bak_config, path=cfg_path, dry_run=False)
                reload_dns_server(dry_run=False)
                bak_a4_path.unlink(missing_ok=True)
                log_ok(f"Restored DNS baseline from {bak_a4_path.name}.")
                return
            except Exception as e:
                log_warn(f"Failed to restore from {bak_a4_path.name}: {e}. Falling back to clean reset.")

        if cfg_path.exists():
            try:
                cfg = load_dns_config(path=cfg_path)
                if cfg["rules"]["A"]["delay_ms"] != 0 or cfg["rules"]["AAAA"]["delay_ms"] != 0:
                    cfg["rules"]["A"]["delay_ms"] = 0
                    cfg["rules"]["AAAA"]["delay_ms"] = 0
                    save_dns_config_atomically(cfg, path=cfg_path, dry_run=dry_run)
                    reload_dns_server(dry_run=dry_run)
                    log_ok("Restored DNS baseline rules: A=0ms, AAAA=0ms.")
            except Exception as e:
                log_error(f"Error resetting DNS config: {e}")
        bak_a4_path.unlink(missing_ok=True)


# ==============================================================================
# nftables Impairment Management (Project Table Invariance)
# ==============================================================================

def apply_nftables_rules(rules: List[str], dry_run: bool = False, scenario_id: Optional[str] = None) -> None:
    """
    Apply nftables rules within dedicated project-owned table 'inet ps028_impair'.
    STRICT SAFETY: Validates rule structures before execution, never flushes entire ruleset,
    and never modifies unrelated tables.
    """
    if not isinstance(rules, list):
        raise ImpairmentError(f"nftables rules must be a list, got {type(rules).__name__}")
    for r in rules:
        validate_nftables_rule(r, scenario_id=scenario_id)

    require_root(dry_run=dry_run)
    clear_nftables_rules(dry_run=dry_run)

    if not rules:
        return

    lines = [
        f"add table {NFT_FAMILY} {NFT_TABLE_NAME}",
        f"add chain {NFT_FAMILY} {NFT_TABLE_NAME} forward {{ type filter hook forward priority 0; policy accept; }}",
    ]
    for r in rules:
        lines.append(f"add rule {NFT_FAMILY} {NFT_TABLE_NAME} forward {r}")

    nft_script = "\n".join(lines) + "\n"
    execute_netns_cmd(
        NFT_NAMESPACE,
        ["nft", "-f", "-"],
        dry_run=dry_run,
        check=True,
        stdin_data=nft_script
    )
    log_ok(f"Applied {len(rules)} nftables impairment rule(s) in {NFT_NAMESPACE} -> {NFT_TABLE_NAME}.")


def clear_nftables_rules(dry_run: bool = False) -> None:
    """
    Delete ONLY project-owned table 'inet ps028_impair' inside ps028-rt.
    Safe and idempotent.
    """
    if not is_root() and not dry_run:
        log_warn("Clearing nftables rules requires root; skipping live command.")
        return

    cmd = ["nft", "delete", "table", NFT_FAMILY, NFT_TABLE_NAME]
    rc, _, stderr = execute_netns_cmd(NFT_NAMESPACE, cmd, dry_run=dry_run, check=False)
    if rc == 0:
        log_ok(f"Deleted project nftables table {NFT_TABLE_NAME} in {NFT_NAMESPACE}.")
    elif "No such file or directory" in stderr or "does not exist" in stderr:
        pass
    elif not dry_run:
        log_warn(f"Notice while clearing table {NFT_TABLE_NAME}: {stderr.strip()}")


# ==============================================================================
# Traffic Control / Netem Delay Management
# ==============================================================================

def apply_netem_delays(delays: Dict[str, str], dry_run: bool = False) -> None:
    """
    Configure tc netem delay on specified interfaces using 'replace'.
    STRICT SAFETY: Never runs 'tc qdisc del dev <iface> root' to prevent removing baseline delays.
    """
    require_root(dry_run=dry_run)
    for iface, delay_str in delays.items():
        if iface not in INTERFACE_MAPPING:
            raise ImpairmentError(f"Unknown interface '{iface}' in delay configuration")
        netns = INTERFACE_MAPPING[iface]
        cmd = ["tc", "qdisc", "replace", "dev", iface, "root", "netem", "delay", delay_str]
        execute_netns_cmd(netns, cmd, dry_run=dry_run, check=True)
        log_ok(f"Configured tc netem delay {delay_str} on {netns}/{iface}.")


def restore_baseline_delays(dry_run: bool = False) -> None:
    """
    Restore A1's 10ms baseline delay on all four server-facing interfaces.
    Uses 'replace' to ensure delays are never deleted.
    """
    if not is_root() and not dry_run:
        log_warn("Restoring baseline delays requires root; skipping live command.")
        return

    apply_netem_delays(BASELINE_DELAYS, dry_run=dry_run)
    log_ok("A1 baseline delays (10ms on all server-facing links) verified and restored.")


# ==============================================================================
# State Tracking
# ==============================================================================

def save_state(scenario_id: str, metadata: Dict[str, Any], dry_run: bool = False) -> None:
    """Record active impairment state."""
    state = {
        "active_scenario": scenario_id,
        "timestamp": time.time(),
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metadata": metadata
    }
    if dry_run:
        log_info(f"[DRY-RUN] Would record active scenario '{scenario_id}' in {STATE_FILE.name}")
        return

    tmp_file = SCRIPT_DIR / f".impair_state.json.tmp.{os.getpid()}"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_file, STATE_FILE)


def get_current_state() -> Optional[Dict[str, Any]]:
    """Retrieve recorded active scenario state."""
    if not STATE_FILE.is_file():
        return None
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def clear_state(dry_run: bool = False) -> None:
    """Clear recorded scenario state."""
    if dry_run:
        log_info(f"[DRY-RUN] Would remove state file {STATE_FILE.name}")
        return
    STATE_FILE.unlink(missing_ok=True)


# ==============================================================================
# Controller Operations: apply, clear, self-test-baseline
# ==============================================================================

def apply_scenario(
    scenario_id: str,
    scenarios_path: Path = DEFAULT_SCENARIOS_PATH,
    dry_run: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0
) -> None:
    """
    Apply a designated scenario (S0 - S6) under exclusive lab lock.
    Cleans any existing impairment first, applies configuration atomically,
    and rolls back cleanly on any unexpected failure.
    """
    target_lock = lock_file or LAB_LOCK_FILE
    with acquire_lab_lock(timeout=lock_timeout, lock_path=target_lock):
        scenarios_data = load_scenarios_config(scenarios_path)
        scenarios = scenarios_data["scenarios"]

        scenario_key = scenario_id.upper()
        if scenario_key not in scenarios:
            raise ImpairmentError(f"Scenario '{scenario_id}' not recognized. Available scenarios: {sorted(scenarios.keys())}")

        scenario = scenarios[scenario_key]
        log_info(f"Applying Scenario {scenario_key}: {scenario['name']} — {scenario['description']}")

        # Clean existing impairment state first
        clear_impairments(dry_run=dry_run, lock_file=target_lock, lock_timeout=lock_timeout)

        try:
            # 1. Apply netem delays
            delays = scenario.get("network", {}).get("delays", BASELINE_DELAYS)
            apply_netem_delays(delays, dry_run=dry_run)

            # 2. Apply nftables rules
            nft_rules = scenario.get("nftables", [])
            if nft_rules:
                apply_nftables_rules(nft_rules, dry_run=dry_run, scenario_id=scenario_key)

            # 3. Apply DNS delays if required (S6)
            dns_cfg = scenario.get("dns", {})
            a_delay = dns_cfg.get("A_delay_ms", 0)
            aaaa_delay = dns_cfg.get("AAAA_delay_ms", 0)
            if a_delay > 0 or aaaa_delay > 0:
                apply_dns_delays(a_delay_ms=a_delay, aaaa_delay_ms=aaaa_delay, dry_run=dry_run)

            save_state(scenario_key, {"name": scenario["name"], "type": scenario["type"]}, dry_run=dry_run)
            log_ok(f"Scenario {scenario_key} successfully applied.")
        except Exception as e:
            log_error(f"Failed to apply scenario {scenario_key}: {e}. Rolling back to baseline...")
            try:
                clear_impairments(dry_run=dry_run, lock_file=target_lock, lock_timeout=lock_timeout)
            except Exception as rb_err:
                log_error(f"Rollback encountered error: {rb_err}")
            raise


def clear_impairments(dry_run: bool = False, lock_file: Optional[Path] = None, lock_timeout: float = 5.0) -> None:
    """
    Restore system to healthy baseline (S0) under exclusive lab lock:
    - Delete project-owned nftables table
    - Restore 10ms baseline netem delays on all server interfaces
    - Restore DNS delays to 0ms and reload DNS server
    - Remove scenario state file
    """
    target_lock = lock_file or LAB_LOCK_FILE
    with acquire_lab_lock(timeout=lock_timeout, lock_path=target_lock):
        log_info("Clearing impairments and restoring clean baseline...")
        clear_nftables_rules(dry_run=dry_run)
        restore_baseline_delays(dry_run=dry_run)
        restore_dns_baseline(dry_run=dry_run)
        clear_state(dry_run=dry_run)
        log_ok("System restored to baseline.")


def self_test_baseline(dry_run: bool = False) -> bool:
    """
    Verify that the environment is in the pristine healthy baseline state:
    - No project nftables rules exist
    - All 4 server interfaces have 10ms netem delay
    - DNS config has 0ms delay for A and AAAA
    - DNS server process is running
    - Live ping and DNS tests (if root)
    """
    log_info("Executing self-test-baseline verification...")
    all_passed = True

    # 1. Check State File
    st = get_current_state()
    if st is not None:
        log_error(f"Baseline Check FAILED: Active scenario state found ({st.get('active_scenario')}).")
        all_passed = False
    else:
        log_ok("Check 1 PASSED: No active scenario recorded in state file.")

    # 2. Check DNS Configuration File
    if not DNS_CONFIG_FILE.is_file():
        log_error("Baseline Check FAILED: DNS config file missing.")
        all_passed = False
    else:
        try:
            cfg = load_dns_config()
            a_d = cfg["rules"]["A"]["delay_ms"]
            aaaa_d = cfg["rules"]["AAAA"]["delay_ms"]
            if a_d == 0 and aaaa_d == 0:
                log_ok("Check 2 PASSED: DNS configuration has baseline 0ms delays for A and AAAA.")
            else:
                log_error(f"Baseline Check FAILED: Non-zero DNS delays (A={a_d}ms, AAAA={aaaa_d}ms).")
                all_passed = False
        except Exception as e:
            log_error(f"Baseline Check FAILED: DNS config validation error: {e}")
            all_passed = False

    # 3. Check for leftover A4 backup file
    if DNS_BACKUP_A4.exists():
        log_error(f"Baseline Check FAILED: Leftover impairment backup {DNS_BACKUP_A4.name} exists.")
        all_passed = False
    else:
        log_ok("Check 3 PASSED: No leftover impairment DNS backups found.")

    # 4. Check DNS Server Process
    if not DNS_PID_FILE.is_file():
        log_warn("DNS PID file missing; cannot verify DNS process status.")
    else:
        try:
            pid = int(DNS_PID_FILE.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            log_ok(f"Check 4 PASSED: DNS server process (PID {pid}) is running.")
        except PermissionError:
            log_ok(f"Check 4 PASSED: DNS server process (PID {pid}) is running (verified active).")
        except ProcessLookupError:
            log_error(f"Baseline Check FAILED: DNS server process (PID {pid}) is not running.")
            all_passed = False
        except Exception as e:
            log_error(f"Baseline Check FAILED: DNS server process check error: {e}")
            all_passed = False

    # 5. Privileged Checks (Netns tc, nftables, and live connectivity)
    if not is_root():
        log_warn("Skipping live netns checks (tc qdisc, nftables, ping) because root privileges are absent.")
        log_info("To execute full live verification, run: sudo python3 lab/impair.py self-test-baseline")
        return all_passed

    # 5a. Check nftables table absence in router namespace
    rc, stdout, _ = execute_netns_cmd(
        NFT_NAMESPACE,
        ["nft", "list", "table", NFT_FAMILY, NFT_TABLE_NAME],
        check=False
    )
    if rc == 0:
        log_error(f"Baseline Check FAILED: Impairment table {NFT_TABLE_NAME} still exists in {NFT_NAMESPACE}!")
        all_passed = False
    else:
        log_ok(f"Check 5 PASSED: Impairment nftables table {NFT_TABLE_NAME} does not exist.")

    # 5b. Check tc qdiscs on all four interfaces
    for iface, netns in INTERFACE_MAPPING.items():
        rc, stdout, stderr = execute_netns_cmd(
            netns,
            ["tc", "qdisc", "show", "dev", iface],
            check=False
        )
        if rc != 0 or "netem" not in stdout or ("delay 10ms" not in stdout and "delay 10.0ms" not in stdout):
            log_error(f"Baseline Check FAILED: Interface {netns}/{iface} tc qdisc mismatch: {stdout.strip()}")
            all_passed = False
        else:
            log_ok(f"Check 6 PASSED: Interface {netns}/{iface} has verified 10ms netem delay.")

    # 5c. Live Ping Verification (Client -> Server IPv4 & IPv6 ~20ms RTT)
    for proto, target in [("IPv4", BASELINE_A_ADDR), ("IPv6", BASELINE_AAAA_ADDR)]:
        ping_cmd = ["ping"] + (["-6"] if proto == "IPv6" else []) + ["-c", "3", "-W", "2", target]
        rc, stdout, _ = execute_netns_cmd("ps028-cl", ping_cmd, check=False)
        if rc != 0:
            log_error(f"Baseline Check FAILED: {proto} ping to {target} failed.")
            all_passed = False
        else:
            m = re.search(r"(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)", stdout)
            avg_rtt = m.group(2) if m else "unknown"
            log_ok(f"Check 7 PASSED: {proto} ping to {target} succeeded (mean RTT: {avg_rtt}ms).")

    # 5d. Live DNS Query Verification
    for qtype, expected in [("A", BASELINE_A_ADDR), ("AAAA", BASELINE_AAAA_ADDR)]:
        dig_cmd = ["dig", f"@{DNS_SERVER_IP}", "-p", "53", "he.test", qtype, "+time=1", "+tries=1", "+short"]
        rc, stdout, _ = execute_netns_cmd("ps028-cl", dig_cmd, check=False)
        out_ans = stdout.strip()
        if rc == 0 and out_ans == expected:
            log_ok(f"Check 8 PASSED: DNS query for {qtype} returned {out_ans} immediately.")
        else:
            log_error(f"Baseline Check FAILED: DNS query for {qtype} expected '{expected}', got '{out_ans}' (rc={rc})")
            all_passed = False

    if all_passed:
        log_ok("ALL BASELINE SELF-TEST CHECKS PASSED.")
    else:
        log_error("ONE OR MORE BASELINE SELF-TEST CHECKS FAILED.")

    return all_passed


# ==============================================================================
# Status and Listing
# ==============================================================================

def print_status(scenarios_path: Path = DEFAULT_SCENARIOS_PATH) -> None:
    """Print current scenario and impairment status."""
    st = get_current_state()
    active_sc = st.get("active_scenario", "S0 (baseline)") if st else "S0 (baseline)"
    print(f"Active Scenario: {active_sc}")

    if st:
        print(f"Applied At:      {st.get('timestamp_iso')}")
        print(f"Metadata:        {st.get('metadata')}")

    if DNS_CONFIG_FILE.is_file():
        try:
            cfg = load_dns_config()
            a_d = cfg["rules"]["A"]["delay_ms"]
            aaaa_d = cfg["rules"]["AAAA"]["delay_ms"]
            print(f"DNS Delays:      A={a_d}ms, AAAA={aaaa_d}ms")
        except Exception:
            print("DNS Delays:      [Unreadable config]")


def list_scenarios(scenarios_path: Path = DEFAULT_SCENARIOS_PATH) -> None:
    """List available scenarios and descriptions."""
    scenarios_data = load_scenarios_config(scenarios_path)
    print("Available Scenarios:")
    for sc_id in sorted(scenarios_data["scenarios"].keys()):
        sc = scenarios_data["scenarios"][sc_id]
        print(f"  {sc['id']}: {sc['name']}")
        print(f"      {sc['description']}")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def positive_int(val: str) -> int:
    """Validate positive integer for CLI arguments."""
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid integer value: '{val}'")
    if ival <= 0:
        raise argparse.ArgumentTypeError(f"Probe count must be a positive integer (> 0), got {ival}")
    return ival


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PS-028 Scenario Impairment Controller (Work Package A4)"
    )
    parser.add_argument(
        "--scenarios-file",
        type=Path,
        default=DEFAULT_SCENARIOS_PATH,
        help="Path to scenarios.yaml configuration file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Display operations without executing live system/network modifications"
    )

    sub_common = argparse.ArgumentParser(add_help=False)
    sub_common.add_argument(
        "--scenarios-file",
        type=Path,
        default=argparse.SUPPRESS,
        help="Path to scenarios.yaml configuration file"
    )
    sub_common.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Display operations without executing live system/network modifications"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    apply_p = subparsers.add_parser("apply", parents=[sub_common], help="Apply a controlled impairment scenario")
    apply_p.add_argument("scenario", type=str, help="Scenario identifier (S0, S1, S2, S3, S4, S5, S6)")

    subparsers.add_parser("clear", parents=[sub_common], help="Clear all impairments and restore clean baseline")

    subparsers.add_parser("self-test-baseline", parents=[sub_common], help="Validate that the environment is in the clean baseline state")

    subparsers.add_parser("status", parents=[sub_common], help="Show current active scenario and impairment state")

    subparsers.add_parser("list", parents=[sub_common], help="List all available scenarios and descriptions")

    pref_p = subparsers.add_parser("preflight", parents=[sub_common], help="Run non-destructive dependency preflight check")
    pref_p.add_argument("--json", action="store_true", default=False, help="Output structured preflight results in JSON format")

    test_p = subparsers.add_parser("test-scenarios", parents=[sub_common], help="Run repeatable self-test harness for S0-S6 (Work Package A5)")
    test_p.add_argument("--scenario", type=str, default=None, help="Single scenario to test (S0, S1, S2, S3, S4, S5, S6)")
    test_p.add_argument("--scenarios", type=str, default=None, help="Comma-separated list of scenarios to test")
    test_p.add_argument("--probes", type=positive_int, default=50, help="Number of SYN probes for scenario S5 (default: 50, must be > 0)")
    test_p.add_argument("--json", action="store_true", default=False, help="Output structured test results in JSON format")

    subparsers.add_parser("self-test-scenarios", parents=[test_p], conflict_handler="resolve", help="Alias for test-scenarios")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if "--dry-run" in sys.argv:
        args.dry_run = True

    try:
        if args.command == "apply":
            apply_scenario(args.scenario, scenarios_path=args.scenarios_file, dry_run=args.dry_run)
            return 0
        elif args.command == "clear":
            clear_impairments(dry_run=args.dry_run)
            return 0
        elif args.command == "self-test-baseline":
            success = self_test_baseline(dry_run=args.dry_run)
            return 0 if success else 1
        elif args.command == "status":
            print_status(scenarios_path=args.scenarios_file)
            return 0
        elif args.command == "list":
            list_scenarios(scenarios_path=args.scenarios_file)
            return 0
        elif args.command == "preflight":
            import lab.preflight as preflight
            rep = preflight.run_preflight()
            if getattr(args, "json", False):
                print(json.dumps(rep, indent=2))
            else:
                return preflight.main()
            return 0 if rep["status"] == "PASS" else 1
        elif args.command in ("test-scenarios", "self-test-scenarios"):
            probes = getattr(args, "probes", 50)
            if not isinstance(probes, int) or isinstance(probes, bool) or probes <= 0:
                log_error(f"Invalid probe count: {probes}. Must be greater than zero (> 0).")
                return 1

            try:
                import lab.self_test_scenarios as sts
            except ImportError:
                import self_test_scenarios as sts

            selected = None
            if getattr(args, "scenario", None):
                selected = [args.scenario]
            elif getattr(args, "scenarios", None):
                selected = [s.strip() for s in args.scenarios.split(",") if s.strip()]

            results = sts.run_all_self_tests(
                scenarios=selected,
                scenarios_path=args.scenarios_file,
                dry_run=args.dry_run,
                probe_count=getattr(args, "probes", 50)
            )
            if getattr(args, "json", False):
                print(json.dumps({"status": "PASS", "results": results}, indent=2))
            return 0
        else:
            parser.print_help()
            return 1
    except ImpairmentError as e:
        log_error(str(e))
        return 1
    except KeyboardInterrupt:
        log_warn("Operation interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
