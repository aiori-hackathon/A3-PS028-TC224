#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Scenario Self-Test Harness
Work Package A5: Automated Self-Test and Validation Suite for Scenarios S0 - S6

Executes repeatable, verifiable end-to-end self-tests for each Study Guide scenario:
  - S0: Dual-stack HTTP, DNS (A & AAAA), and baseline latency (~20ms RTT)
  - S1: IPv4 HTTP succeeds; IPv6 TCP SYN times out (blackhole drop)
  - S2: IPv4 HTTP succeeds and stays at baseline; IPv6 TCP SYN actively rejected with TCP RST
  - S3: IPv6 RTT near 150ms; IPv4 RTT stays near baseline (~20ms); HTTP succeeds
  - S4: IPv6 RTT near 600ms; IPv4 RTT stays near baseline (~20ms); HTTP succeeds
  - S5: Measure SYN packet count, dropped packets, and observed loss % (~50% with random variation)
  - S6: A resolves immediately (<100ms); AAAA is delayed approximately 500ms (450-750ms)

LIFECYCLE GUARANTEE:
  Always clears impairments and runs `sudo python3 lab/impair.py self-test-baseline`
  after each live scenario to prevent cross-scenario contamination and maintain baseline invariants.
"""

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SCENARIOS_PATH = SCRIPT_DIR / "scenarios.yaml"

# Safe imports supporting both module and direct script execution
try:
    import lab.impair as impair
except ImportError:
    import impair

CLIENT_NETNS = "ps028-cl"
ROUTER_NETNS = "ps028-rt"
SERVER_NETNS = "ps028-sv"

DNS_SERVER_IP = "10.0.1.1"
DNS_DOMAIN = "he.test"
SERVER_IPV4 = "10.0.2.10"
SERVER_IPV6 = "2001:db8:2::10"

# Baseline RTT tolerances in milliseconds (nominal ~20ms)
BASELINE_RTT_MIN = 15.0
BASELINE_RTT_MAX = 27.0

# S3 IPv6 RTT tolerance in milliseconds (nominal 150ms: 75ms + 75ms)
S3_IPV6_RTT_MIN = 135.0
S3_IPV6_RTT_MAX = 175.0

# S4 IPv6 RTT tolerance in milliseconds (nominal 600ms: 300ms + 300ms)
S4_IPV6_RTT_MIN = 550.0
S4_IPV6_RTT_MAX = 660.0

# S6 DNS delay tolerances in milliseconds
S6_A_MAX_DELAY_MS = 100.0
S6_AAAA_MIN_DELAY_MS = 450.0
S6_AAAA_MAX_DELAY_MS = 750.0

# S5 SYN loss tolerance percentage bounds (nominal 50%, random variation allowed)
S5_LOSS_MIN_PCT = 20.0
S5_LOSS_MAX_PCT = 80.0

REQUIRED_S5_COUNTERS = ("syn_total", "syn_dropped", "syn_not_dropped")


def validate_probe_count(probe_count: Any) -> int:
    """
    Validate that probe count is a positive integer (> 0).
    Rejects probe_count <= 0 before applying any scenario or executing measurement.
    """
    if isinstance(probe_count, bool) or not isinstance(probe_count, int):
        raise impair.ImpairmentError(
            f"Invalid probe count: {probe_count!r}. Probe count must be a positive integer (> 0)."
        )
    if probe_count <= 0:
        raise impair.ImpairmentError(
            f"Invalid probe count: {probe_count}. Probe count must be greater than zero (> 0)."
        )
    return probe_count


# ==============================================================================
# Network Measurement Probes (Executed in Client Namespace)
# ==============================================================================

def measure_ping_rtt(
    target_ip: str,
    is_ipv6: bool = False,
    count: int = 4,
    timeout: float = 2.0,
    interval: float = 0.2,
    netns: str = CLIENT_NETNS,
    dry_run: bool = False,
    simulated_rtt: Optional[float] = None
) -> float:
    """
    Measure average ping round-trip time (ms) to target_ip inside netns.
    Parses and calculates RTT once, in milliseconds, directly from ping output.
    Ping measures round-trip time; the returned value is never doubled or scaled.
    """
    if dry_run:
        val = simulated_rtt if simulated_rtt is not None else 20.0
        impair.log_info(f"[DRY-RUN] Ping {target_ip} in {netns} (simulated mean RTT: {val:.2f}ms)")
        return val

    ping_bin = "ping"
    cmd = [ping_bin]
    if is_ipv6 or ":" in target_ip:
        cmd.append("-6")
    cmd.extend(["-c", str(count), "-i", str(interval), "-W", str(int(timeout)), target_ip])

    rc, stdout, stderr = impair.execute_netns_cmd(netns, cmd, check=False)
    if rc != 0:
        raise impair.ImpairmentError(
            f"Ping to {target_ip} in {netns} failed (exit code {rc}): {stderr.strip() or stdout.strip()}"
        )

    # Robustly parse the ping statistics summary line:
    # Linux iputils format: rtt min/avg/max/mdev = 150.112/150.309/150.512/0.145 ms
    # BSD/macOS format: round-trip min/avg/max/stddev = ...
    match = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)",
        stdout,
    )
    if not match:
        match = re.search(r"(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)/(\d+(?:\.\d+)?)", stdout)
    if not match:
        raise impair.ImpairmentError(f"Could not parse ping summary from stdout: {stdout.strip()}")

    # Extract average RTT once directly in milliseconds from group 2 (avg).
    # RTT is the complete round-trip duration measured by ping; do not double or recalculate.
    mean_rtt = float(match.group(2))
    return mean_rtt


def query_dns_with_timing(
    qtype: str,
    domain: str = DNS_DOMAIN,
    server_ip: str = DNS_SERVER_IP,
    netns: str = CLIENT_NETNS,
    timeout: float = 2.0,
    dry_run: bool = False,
    simulated_delay_ms: Optional[float] = None
) -> Tuple[str, float]:
    """
    Execute a DNS query using dig from netns, measuring elapsed resolution time.
    Returns (resolved_address, elapsed_ms).
    """
    if dry_run:
        expected_addr = SERVER_IPV4 if qtype == "A" else SERVER_IPV6
        delay = simulated_delay_ms if simulated_delay_ms is not None else 5.0
        impair.log_info(f"[DRY-RUN] DNS query {qtype} {domain} via {server_ip} -> {expected_addr} ({delay:.1f}ms)")
        return expected_addr, delay

    dig_cmd = [
        "dig",
        f"@{server_ip}",
        "-p", "53",
        domain,
        qtype,
        f"+time={int(timeout)}",
        "+tries=1",
        "+stats"
    ]

    rc, stdout, stderr = impair.execute_netns_cmd(netns, dig_cmd, check=False)

    if rc != 0:
        raise impair.ImpairmentError(f"DNS query {qtype} failed (rc={rc}): {stderr.strip()}")

    # Parse address from answer section
    address = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[3] == qtype:
            address = parts[4]
            break

    if not address:
        raise impair.ImpairmentError(f"No {qtype} record found in DNS response:\n{stdout}")

    # Parse DNS transaction duration from dig stdout's ';; Query time: N msec' line
    time_match = re.search(r";;\s*Query time:(.*)$", stdout, re.IGNORECASE | re.MULTILINE)
    if not time_match:
        raise impair.ImpairmentError(f"Missing query time in dig output:\n{stdout}")

    val_str = time_match.group(1).strip()
    msec_match = re.match(r"^(\d+(?:\.\d+)?)\s*msec$", val_str, re.IGNORECASE)
    if not msec_match:
        raise impair.ImpairmentError(f"Malformed query time '{val_str}' in dig output:\n{stdout}")

    elapsed_ms = float(msec_match.group(1))

    return address, elapsed_ms


def probe_http(
    url: str,
    timeout: float = 3.0,
    netns: str = CLIENT_NETNS,
    dry_run: bool = False
) -> Tuple[int, float]:
    """
    Execute HTTP GET request via curl inside netns.
    Returns (http_status_code, elapsed_ms).
    """
    if dry_run:
        impair.log_info(f"[DRY-RUN] HTTP GET {url} in {netns} -> 200 OK (20.0ms)")
        return 200, 20.0

    curl_cmd = [
        "curl",
        "-s",
        "-S",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--connect-timeout", str(timeout),
        "-m", str(timeout + 2.0),
        url
    ]

    t_start = time.perf_counter()
    rc, stdout, stderr = impair.execute_netns_cmd(netns, curl_cmd, check=False)
    elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    if rc != 0:
        raise impair.ImpairmentError(f"HTTP GET {url} failed (curl rc={rc}): {stderr.strip()}")

    status_str = stdout.strip()
    try:
        status_code = int(status_str)
    except ValueError:
        raise impair.ImpairmentError(f"Invalid HTTP status code returned: '{status_str}'")

    return status_code, elapsed_ms


def probe_tcp_connect(
    target_ip: str,
    port: int = 80,
    timeout: float = 2.0,
    netns: str = CLIENT_NETNS,
    dry_run: bool = False,
    simulated_outcome: Optional[str] = None
) -> Tuple[str, float]:
    """
    Attempt TCP connection from netns to target_ip:port.
    Returns (outcome, elapsed_sec) where outcome is one of:
      - 'connected': 3-way handshake succeeded
      - 'timeout': connection timed out waiting for SYN-ACK
      - 'refused': connection actively rejected with TCP RST
      - 'error': other connection failure
    """
    if dry_run:
        outcome = simulated_outcome or "connected"
        el = 2.0 if outcome == "timeout" else 0.02
        impair.log_info(f"[DRY-RUN] TCP connect to [{target_ip}]:{port} -> {outcome} ({el*1000:.1f}ms)")
        return outcome, el

    py_script = (
        "import socket, sys, time\n"
        "ip = sys.argv[1]\n"
        "port = int(sys.argv[2])\n"
        "timeout = float(sys.argv[3])\n"
        "af = socket.AF_INET6 if ':' in ip else socket.AF_INET\n"
        "s = socket.socket(af, socket.SOCK_STREAM)\n"
        "s.settimeout(timeout)\n"
        "t0 = time.perf_counter()\n"
        "try:\n"
        "    s.connect((ip, port))\n"
        "    s.close()\n"
        "    print(f'connected,{time.perf_counter() - t0:.4f}')\n"
        "except (socket.timeout, TimeoutError):\n"
        "    print(f'timeout,{time.perf_counter() - t0:.4f}')\n"
        "except ConnectionRefusedError:\n"
        "    print(f'refused,{time.perf_counter() - t0:.4f}')\n"
        "except Exception as e:\n"
        "    print(f'error:{e},{time.perf_counter() - t0:.4f}')\n"
    )

    cmd = ["python3", "-c", py_script, target_ip, str(port), str(timeout)]
    rc, stdout, stderr = impair.execute_netns_cmd(netns, cmd, check=False)
    if rc != 0:
        raise impair.ImpairmentError(f"TCP probe execution failed: {stderr.strip()}")

    parts = stdout.strip().split(",")
    outcome = parts[0]
    elapsed = float(parts[1]) if len(parts) > 1 else 0.0
    return outcome, elapsed


def setup_s5_nftables_counters(
    port: int = 80,
    target_ip: str = SERVER_IPV6,
    client_ip: str = "2001:db8:1::2",
    oifname: str = "ps028-rt-sv6",
    dry_run: bool = False
) -> None:
    """
    Configure project-scoped nftables counters inside router namespace (ps028-rt).
    Preserves the S5 50% random-drop rule while tracking:
      - syn_total: Total SYN packets arriving from client destined for target_ip:port
      - syn_dropped: Packets dropped by the 50% random-drop rule
      - syn_not_dropped: Packets accepted and forwarded
    Applies consistent client IP, server IP, destination port, SYN flags,
    and outgoing-interface filters across all three counters.
    """
    if dry_run:
        impair.log_info(f"[DRY-RUN] Would configure project-scoped nftables counters in {impair.NFT_NAMESPACE}")
        return

    impair.require_root(dry_run=dry_run)
    common_filter = (
        f"oifname \"{oifname}\" ip6 saddr {client_ip} ip6 daddr {target_ip} "
        f"tcp dport {port} tcp flags syn / syn,ack"
    )
    nft_script = (
        f"add counter {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} syn_total\n"
        f"add counter {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} syn_dropped\n"
        f"add counter {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} syn_not_dropped\n"
        f"flush chain {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward\n"
        f"add rule {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {common_filter} "
        f"counter name \"syn_total\"\n"
        f"add rule {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {common_filter} "
        f"numgen random mod 100 < 50 counter name \"syn_dropped\" drop\n"
        f"add rule {impair.NFT_FAMILY} {impair.NFT_TABLE_NAME} forward {common_filter} "
        f"counter name \"syn_not_dropped\"\n"
    )
    impair.execute_netns_cmd(
        impair.NFT_NAMESPACE,
        ["nft", "-f", "-"],
        dry_run=dry_run,
        check=True,
        stdin_data=nft_script
    )
    impair.log_ok(f"Configured project-scoped nftables counters in {impair.NFT_NAMESPACE} -> {impair.NFT_TABLE_NAME}.")


def read_s5_nftables_counters(dry_run: bool = False) -> Dict[str, int]:
    """
    Read named counters from inet ps028_impair in ps028-rt.
    Returns dict with keys: 'syn_total', 'syn_dropped', 'syn_not_dropped'.
    Supports both JSON format and standard text output fallback.
    Raises ImpairmentError if any required named counter is missing, malformed,
    or cannot be read through either supported output format.
    """
    if dry_run:
        return {"syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0}

    json_err: Optional[str] = None
    # 1. Attempt JSON query first
    rc_json, stdout_json, stderr_json = impair.execute_netns_cmd(
        impair.NFT_NAMESPACE,
        ["nft", "-j", "list", "counters", "table", impair.NFT_FAMILY, impair.NFT_TABLE_NAME],
        dry_run=dry_run,
        check=False
    )
    if rc_json == 0 and stdout_json.strip():
        try:
            data = json.loads(stdout_json)
            json_counters: Dict[str, int] = {}
            for item in data.get("nftables", []):
                ctr = item.get("counter")
                if ctr and isinstance(ctr, dict) and "name" in ctr and "packets" in ctr:
                    name = ctr["name"]
                    if name in REQUIRED_S5_COUNTERS:
                        val = ctr["packets"]
                        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                            raise ValueError(f"Malformed non-integer or negative packet count for '{name}': {val!r}")
                        json_counters[name] = val
            missing_json = set(REQUIRED_S5_COUNTERS) - json_counters.keys()
            if not missing_json:
                return json_counters
            json_err = f"Missing required counter(s) in JSON output: {sorted(missing_json)}"
        except Exception as e:
            json_err = f"Malformed JSON output: {e}"
    else:
        json_err = f"Command failed with rc={rc_json}: {stderr_json.strip() or stdout_json.strip() or 'empty stdout'}"

    # 2. Fallback to standard text output
    text_err: Optional[str] = None
    rc_txt, stdout_txt, stderr_txt = impair.execute_netns_cmd(
        impair.NFT_NAMESPACE,
        ["nft", "list", "counters", "table", impair.NFT_FAMILY, impair.NFT_TABLE_NAME],
        dry_run=dry_run,
        check=False
    )
    if rc_txt == 0 and stdout_txt.strip():
        try:
            text_counters: Dict[str, int] = {}
            for block_match in re.finditer(r"counter\s+(\w+)\s*(?:\{([^}]*)\}|packets\s+(\S+))", stdout_txt):
                cname = block_match.group(1)
                body = block_match.group(2)
                direct_pkt = block_match.group(3)
                if cname in REQUIRED_S5_COUNTERS:
                    if direct_pkt is not None:
                        pkts_str = direct_pkt
                    elif body is not None:
                        pkt_match = re.search(r"\bpackets\s+(\S+)", body)
                        if not pkt_match:
                            raise ValueError(f"Counter '{cname}' missing 'packets' field in text output")
                        pkts_str = pkt_match.group(1)
                    else:
                        raise ValueError(f"Counter '{cname}' has no body or packets field")

                    val = int(pkts_str)
                    if val < 0:
                        raise ValueError(f"Negative packet count for counter '{cname}': {val}")
                    text_counters[cname] = val

            missing_txt = set(REQUIRED_S5_COUNTERS) - text_counters.keys()
            if not missing_txt:
                return text_counters
            text_err = f"Missing required counter(s) in text output: {sorted(missing_txt)}"
        except Exception as e:
            text_err = f"Malformed text output: {e}"
    else:
        text_err = f"Command failed with rc={rc_txt}: {stderr_txt.strip() or stdout_txt.strip() or 'empty stdout'}"

    raise impair.ImpairmentError(
        f"Unable to read required S5 nftables counters {list(REQUIRED_S5_COUNTERS)} in {impair.NFT_NAMESPACE} "
        f"table {impair.NFT_TABLE_NAME} through either JSON or text output format. "
        f"JSON error: {json_err}. Text error: {text_err}."
    )


def build_s5_probe_script() -> str:
    """
    Construct the embedded Python probe script executed inside client namespace (ps028-cl).
    Generates a multi-threaded TCP SYN probe runner that reliably connects and
    closes sockets in a try/finally structure even if connect() times out or raises an OSError.
    """
    return (
        "import concurrent.futures, socket, sys, time\n"
        "ip = sys.argv[1]\n"
        "port = int(sys.argv[2])\n"
        "total = int(sys.argv[3])\n"
        "timeout = float(sys.argv[4])\n"
        "concurrency = int(sys.argv[5])\n"
        "af = socket.AF_INET6 if ':' in ip else socket.AF_INET\n"
        "def probe_one(idx):\n"
        "    s = socket.socket(af, socket.SOCK_STREAM)\n"
        "    try:\n"
        "        s.settimeout(timeout)\n"
        "        s.connect((ip, port))\n"
        "    except (socket.timeout, TimeoutError, OSError):\n"
        "        pass\n"
        "    except Exception:\n"
        "        pass\n"
        "    finally:\n"
        "        try:\n"
        "            s.close()\n"
        "        except Exception:\n"
        "            pass\n"
        "with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:\n"
        "    list(ex.map(probe_one, range(total)))\n"
        "print('PROBES_DONE')\n"
    )


def measure_syn_loss(
    target_ip: str = SERVER_IPV6,
    port: int = 80,
    total_probes: int = 50,
    timeout: float = 0.4,
    concurrency: int = 10,
    netns: str = CLIENT_NETNS,
    dry_run: bool = False,
    simulated_loss_pct: Optional[float] = None
) -> Dict[str, Any]:
    """
    Measure SYN packet count, dropped packets, and observed loss percentage
    using evidence-based project-scoped nftables counters.
    Clearly defines:
      - total_syn_count: Total TCP SYN packets arriving at router matching filter
      - dropped_packets: SYN packets dropped by the 50% random-drop impairment rule
      - not_dropped_packets: SYN packets forwarded/accepted to destination
      - observed_loss_pct: Exact packet-level loss ratio (dropped / total * 100)
      - extra_syn_packets: Inferred count of extra SYN packets beyond initial probe count
        (calculated as max(0, total_syn_count - total_probes); inferred from packet count
        delta rather than directly measured via sequence tracking)
    Ensures unrelated traffic cannot contaminate the measurement by applying
    consistent client IP, server IP, destination port, SYN flags, and outgoing-interface
    filters across all counters, and does NOT label failed TCP connections as dropped packets.
    """
    validate_probe_count(total_probes)

    if dry_run:
        sim_pct = simulated_loss_pct if simulated_loss_pct is not None else 50.0
        dropped = int(round(total_probes * (sim_pct / 100.0)))
        accepted = total_probes - dropped
        loss_pct = (dropped / total_probes * 100.0) if total_probes > 0 else 0.0
        impair.log_info(
            f"[DRY-RUN] S5 SYN Loss (simulated counts): simulated_total={total_probes}, "
            f"simulated_dropped={dropped}, simulated_accepted={accepted}, "
            f"simulated_not_dropped={accepted}, simulated_loss={loss_pct:.1f}%"
        )
        return {
            "total_syn_count": total_probes,
            "dropped_packets": dropped,
            "accepted_packets": accepted,
            "not_dropped_packets": accepted,
            "extra_syn_packets": 0,
            "initial_probes": total_probes,
            "observed_loss_pct": loss_pct,
            "measurement_method": "dry_run_simulation",
            "evidence": {
                "source": "simulation",
                "table": impair.NFT_TABLE_NAME,
                "chain": "forward",
                "counters": {
                    "syn_total": total_probes,
                    "syn_dropped": dropped,
                    "syn_not_dropped": accepted
                }
            }
        }

    impair.require_root(dry_run=dry_run)

    # 1. Setup project-scoped nftables counters in ps028-rt
    setup_s5_nftables_counters(port=port, target_ip=target_ip, dry_run=dry_run)
    initial_counters = read_s5_nftables_counters(dry_run=dry_run)

    # 2. Transmit probes from client namespace (initiates TCP SYNs on wire)
    # Failed connections are NOT counted as dropped packets; kernel counters provide ground truth.
    py_script = build_s5_probe_script()
    compile(py_script, "<ps028_s5_probe>", "exec")

    cmd = ["python3", "-c", py_script, target_ip, str(port), str(total_probes), str(timeout), str(concurrency)]
    rc, stdout, stderr = impair.execute_netns_cmd(netns, cmd, check=False)
    if rc != 0:
        raise impair.ImpairmentError(f"SYN probe execution failed in {netns}: {stderr.strip()}")

    # Allow tiny grace period for in-flight packets or extra SYN probes to reach router
    time.sleep(0.05)

    # 3. Read final counter evidence from router nftables table
    final_counters = read_s5_nftables_counters(dry_run=dry_run)

    total_syn_count = final_counters["syn_total"] - initial_counters["syn_total"]
    dropped_packets = final_counters["syn_dropped"] - initial_counters["syn_dropped"]
    not_dropped_packets = final_counters["syn_not_dropped"] - initial_counters["syn_not_dropped"]

    if total_syn_count == 0:
        raise impair.ImpairmentError(
            f"No SYN packets recorded by nftables counters in {impair.NFT_NAMESPACE} table {impair.NFT_TABLE_NAME}"
        )

    # Validate counter consistency: total must equal dropped + not_dropped.
    # Preserve raw counter values and fail immediately if they do not match.
    # Never overwrite a measured counter to force consistency.
    if total_syn_count != (dropped_packets + not_dropped_packets):
        raise impair.ImpairmentError(
            f"S5 Counter accounting mismatch: total_syn_count ({total_syn_count}) != "
            f"dropped_packets ({dropped_packets}) + not_dropped_packets ({not_dropped_packets})"
        )

    loss_pct = (dropped_packets / total_syn_count * 100.0) if total_syn_count > 0 else 0.0
    extra_syn_packets = max(0, total_syn_count - total_probes)

    impair.log_info(
        f"S5 Evidence [nftables counters]: total={total_syn_count} (probes={total_probes}, "
        f"inferred_extra_syn={extra_syn_packets}), dropped={dropped_packets}, "
        f"not_dropped={not_dropped_packets}, loss={loss_pct:.1f}%"
    )

    return {
        "total_syn_count": total_syn_count,
        "dropped_packets": dropped_packets,
        "accepted_packets": not_dropped_packets,
        "not_dropped_packets": not_dropped_packets,
        "extra_syn_packets": extra_syn_packets,
        "initial_probes": total_probes,
        "observed_loss_pct": loss_pct,
        "measurement_method": "nftables_counters",
        "evidence": {
            "source": "nftables",
            "table": impair.NFT_TABLE_NAME,
            "chain": "forward",
            "counters": {
                "syn_total": total_syn_count,
                "syn_dropped": dropped_packets,
                "syn_not_dropped": not_dropped_packets
            }
        }
    }


# ==============================================================================
# Scenario Verifiers (S0 - S6)
# ==============================================================================

def verify_s0(dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S0: Healthy Baseline
    - Dual-stack HTTP (IPv4, IPv6, and he.test domain)
    - DNS resolution (immediate A and AAAA records)
    - Baseline latency (~20ms RTT for IPv4 and IPv6)
    """
    impair.log_info("--- Verifying Scenario S0 (Healthy Baseline) ---")

    # 1. DNS Verification
    a_addr, a_delay = query_dns_with_timing("A", dry_run=dry_run)
    if a_addr != SERVER_IPV4:
        raise impair.ImpairmentError(f"S0 DNS A returned '{a_addr}', expected '{SERVER_IPV4}'")
    if not dry_run and a_delay > S6_A_MAX_DELAY_MS:
        raise impair.ImpairmentError(f"S0 DNS A resolution delayed: {a_delay:.1f}ms > {S6_A_MAX_DELAY_MS}ms")

    aaaa_addr, aaaa_delay = query_dns_with_timing("AAAA", dry_run=dry_run)
    if aaaa_addr != SERVER_IPV6:
        raise impair.ImpairmentError(f"S0 DNS AAAA returned '{aaaa_addr}', expected '{SERVER_IPV6}'")
    if not dry_run and aaaa_delay > S6_A_MAX_DELAY_MS:
        raise impair.ImpairmentError(f"S0 DNS AAAA resolution delayed: {aaaa_delay:.1f}ms > {S6_A_MAX_DELAY_MS}ms")
    impair.log_ok(f"S0 Check 1 PASSED: DNS A={a_addr} ({a_delay:.1f}ms), AAAA={aaaa_addr} ({aaaa_delay:.1f}ms)")

    # 2. Latency Verification
    v4_rtt = measure_ping_rtt(SERVER_IPV4, is_ipv6=False, dry_run=dry_run, simulated_rtt=20.1)
    if not dry_run and not (BASELINE_RTT_MIN <= v4_rtt <= BASELINE_RTT_MAX):
        raise impair.ImpairmentError(
            f"S0 IPv4 RTT out of baseline range ({BASELINE_RTT_MIN}-{BASELINE_RTT_MAX}ms): got {v4_rtt:.2f}ms"
        )

    v6_rtt = measure_ping_rtt(SERVER_IPV6, is_ipv6=True, dry_run=dry_run, simulated_rtt=20.2)
    if not dry_run and not (BASELINE_RTT_MIN <= v6_rtt <= BASELINE_RTT_MAX):
        raise impair.ImpairmentError(
            f"S0 IPv6 RTT out of baseline range ({BASELINE_RTT_MIN}-{BASELINE_RTT_MAX}ms): got {v6_rtt:.2f}ms"
        )
    impair.log_ok(f"S0 Check 2 PASSED: Baseline Latency IPv4 RTT={v4_rtt:.2f}ms, IPv6 RTT={v6_rtt:.2f}ms")

    # 3. Dual-Stack HTTP Verification
    http4_status, http4_ms = probe_http(f"http://{SERVER_IPV4}/", dry_run=dry_run)
    if http4_status != 200:
        raise impair.ImpairmentError(f"S0 IPv4 HTTP failed: status {http4_status}")

    http6_status, http6_ms = probe_http(f"http://[{SERVER_IPV6}]/", dry_run=dry_run)
    if http6_status != 200:
        raise impair.ImpairmentError(f"S0 IPv6 HTTP failed: status {http6_status}")

    http_domain_status, http_domain_ms = probe_http(f"http://{DNS_DOMAIN}/", dry_run=dry_run)
    if http_domain_status != 200:
        raise impair.ImpairmentError(f"S0 Domain HTTP ({DNS_DOMAIN}) failed: status {http_domain_status}")
    impair.log_ok(f"S0 Check 3 PASSED: Dual-Stack HTTP 200 OK on IPv4, IPv6, and {DNS_DOMAIN}")

    return {
        "dns_a": a_addr, "dns_a_ms": a_delay,
        "dns_aaaa": aaaa_addr, "dns_aaaa_ms": aaaa_delay,
        "ipv4_rtt_ms": v4_rtt, "ipv6_rtt_ms": v6_rtt,
        "http_ipv4_status": http4_status, "http_ipv6_status": http6_status,
        "http_domain_status": http_domain_status
    }


def verify_s1(dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S1: IPv6 SYN Blackhole
    - IPv4 HTTP succeeds
    - IPv6 TCP SYN times out (blackhole drop)
    """
    impair.log_info("--- Verifying Scenario S1 (IPv6 SYN Blackhole) ---")

    # 1. IPv4 must succeed
    http4_status, http4_ms = probe_http(f"http://{SERVER_IPV4}/", timeout=2.0, dry_run=dry_run)
    if http4_status != 200:
        raise impair.ImpairmentError(f"S1 IPv4 HTTP check failed: status {http4_status}")
    impair.log_ok(f"S1 Check 1 PASSED: IPv4 HTTP succeeded (200 OK, {http4_ms:.1f}ms)")

    # 2. IPv6 TCP SYN must time out
    outcome, elapsed = probe_tcp_connect(
        SERVER_IPV6, port=80, timeout=1.5, dry_run=dry_run, simulated_outcome="timeout"
    )
    if not dry_run and outcome != "timeout":
        raise impair.ImpairmentError(f"S1 IPv6 TCP SYN did not time out as expected: got '{outcome}' in {elapsed:.2f}s")
    impair.log_ok(f"S1 Check 2 PASSED: IPv6 TCP SYN timed out after {elapsed:.2f}s (silent blackhole drop verified)")

    return {"ipv4_http_status": http4_status, "ipv6_tcp_outcome": outcome, "ipv6_timeout_sec": elapsed}


def verify_s2(dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S2: IPv6 TCP RST Rejection
    - IPv4 HTTP succeeds and IPv4 latency stays near baseline (~20ms)
    - IPv6 TCP SYN is actively rejected with TCP RST (immediate connection refusal, <100ms)
    """
    impair.log_info("--- Verifying Scenario S2 (IPv6 TCP RST Rejection) ---")

    # 1. IPv4 must succeed and remain at baseline
    http4_status, http4_ms = probe_http(f"http://{SERVER_IPV4}/", timeout=2.0, dry_run=dry_run)
    if http4_status != 200:
        raise impair.ImpairmentError(f"S2 IPv4 HTTP check failed: status {http4_status}")

    v4_rtt = measure_ping_rtt(SERVER_IPV4, is_ipv6=False, dry_run=dry_run, simulated_rtt=20.1)
    if not dry_run and not (BASELINE_RTT_MIN <= v4_rtt <= BASELINE_RTT_MAX):
        raise impair.ImpairmentError(
            f"S2 IPv4 RTT deviated from baseline ({BASELINE_RTT_MIN}-{BASELINE_RTT_MAX}ms): got {v4_rtt:.2f}ms"
        )
    impair.log_ok(f"S2 Check 1 PASSED: IPv4 HTTP succeeded (200 OK) with baseline RTT {v4_rtt:.2f}ms")

    # 2. IPv6 TCP SYN must be actively rejected with TCP reset
    outcome, elapsed = probe_tcp_connect(
        SERVER_IPV6, port=80, timeout=2.0, dry_run=dry_run, simulated_outcome="refused"
    )
    if not dry_run and outcome != "refused":
        raise impair.ImpairmentError(f"S2 IPv6 TCP SYN did not receive TCP RST: got '{outcome}' in {elapsed:.2f}s")
    if not dry_run and elapsed > 0.15:
        raise impair.ImpairmentError(f"S2 IPv6 TCP RST took too long ({elapsed:.3f}s), expected immediate rejection")
    impair.log_ok(f"S2 Check 2 PASSED: IPv6 TCP SYN actively rejected with TCP RST in {elapsed*1000:.1f}ms")

    return {"ipv4_http_status": http4_status, "ipv4_rtt_ms": v4_rtt, "ipv6_tcp_outcome": outcome, "rst_elapsed_sec": elapsed}


def verify_s3(dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S3: IPv6 RTT 150ms
    - IPv6 RTT near 150ms (75ms + 75ms symmetric delay)
    - IPv4 RTT stays near baseline (~20ms)
    - Dual-stack HTTP succeeds
    """
    impair.log_info("--- Verifying Scenario S3 (IPv6 RTT 150ms) ---")

    # 1. Latency Verification (measured once in ms from ping summary, no scaling)
    v4_rtt = measure_ping_rtt(SERVER_IPV4, is_ipv6=False, count=4, timeout=2.0, interval=0.2, dry_run=dry_run, simulated_rtt=20.2)
    if not dry_run and not (BASELINE_RTT_MIN <= v4_rtt <= BASELINE_RTT_MAX):
        raise impair.ImpairmentError(
            f"S3 IPv4 RTT deviated from baseline ({BASELINE_RTT_MIN}-{BASELINE_RTT_MAX}ms): got {v4_rtt:.2f}ms"
        )

    v6_rtt = measure_ping_rtt(SERVER_IPV6, is_ipv6=True, count=4, timeout=3.0, interval=0.2, dry_run=dry_run, simulated_rtt=150.3)
    if not dry_run and not (S3_IPV6_RTT_MIN <= v6_rtt <= S3_IPV6_RTT_MAX):
        raise impair.ImpairmentError(
            f"S3 IPv6 RTT out of 150ms target range ({S3_IPV6_RTT_MIN}-{S3_IPV6_RTT_MAX}ms): got {v6_rtt:.2f}ms"
        )
    impair.log_ok(f"S3 Check 1 PASSED: Latency verified (IPv6 RTT={v6_rtt:.2f}ms ~150ms, IPv4 RTT={v4_rtt:.2f}ms ~baseline)")

    # 2. Dual-Stack HTTP Verification
    http4_status, _ = probe_http(f"http://{SERVER_IPV4}/", timeout=3.0, dry_run=dry_run)
    http6_status, _ = probe_http(f"http://[{SERVER_IPV6}]/", timeout=3.0, dry_run=dry_run)
    if http4_status != 200 or http6_status != 200:
        raise impair.ImpairmentError(f"S3 HTTP failed: IPv4={http4_status}, IPv6={http6_status}")
    impair.log_ok("S3 Check 2 PASSED: Dual-stack HTTP 200 OK on both IPv4 and IPv6")

    return {"ipv4_rtt_ms": v4_rtt, "ipv6_rtt_ms": v6_rtt, "http_ipv4_status": http4_status, "http_ipv6_status": http6_status}


def verify_s4(dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S4: IPv6 RTT 600ms
    - IPv6 RTT near 600ms (300ms + 300ms symmetric delay)
    - IPv4 RTT stays near baseline (~20ms)
    - Dual-stack HTTP succeeds
    """
    impair.log_info("--- Verifying Scenario S4 (IPv6 RTT 600ms) ---")

    # 1. Latency Verification (measured once in ms from ping summary, no scaling)
    v4_rtt = measure_ping_rtt(SERVER_IPV4, is_ipv6=False, count=4, timeout=2.0, interval=0.2, dry_run=dry_run, simulated_rtt=20.2)
    if not dry_run and not (BASELINE_RTT_MIN <= v4_rtt <= BASELINE_RTT_MAX):
        raise impair.ImpairmentError(
            f"S4 IPv4 RTT deviated from baseline ({BASELINE_RTT_MIN}-{BASELINE_RTT_MAX}ms): got {v4_rtt:.2f}ms"
        )

    v6_rtt = measure_ping_rtt(SERVER_IPV6, is_ipv6=True, count=3, timeout=4.0, interval=0.5, dry_run=dry_run, simulated_rtt=600.4)
    if not dry_run and not (S4_IPV6_RTT_MIN <= v6_rtt <= S4_IPV6_RTT_MAX):
        raise impair.ImpairmentError(
            f"S4 IPv6 RTT out of 600ms target range ({S4_IPV6_RTT_MIN}-{S4_IPV6_RTT_MAX}ms): got {v6_rtt:.2f}ms"
        )
    impair.log_ok(f"S4 Check 1 PASSED: Latency verified (IPv6 RTT={v6_rtt:.2f}ms ~600ms, IPv4 RTT={v4_rtt:.2f}ms ~baseline)")

    # 2. Dual-Stack HTTP Verification
    http4_status, _ = probe_http(f"http://{SERVER_IPV4}/", timeout=3.0, dry_run=dry_run)
    http6_status, _ = probe_http(f"http://[{SERVER_IPV6}]/", timeout=4.0, dry_run=dry_run)
    if http4_status != 200 or http6_status != 200:
        raise impair.ImpairmentError(f"S4 HTTP failed: IPv4={http4_status}, IPv6={http6_status}")
    impair.log_ok("S4 Check 2 PASSED: Dual-stack HTTP 200 OK on both IPv4 and IPv6")

    return {"ipv4_rtt_ms": v4_rtt, "ipv6_rtt_ms": v6_rtt, "http_ipv4_status": http4_status, "http_ipv6_status": http6_status}


def verify_s5(probe_count: int = 50, dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S5: IPv6 SYN Loss 50%
    - Measure SYN packet count, dropped packets, and observed loss percentage
    - Validate probe_count > 0 before applying scenario or measurement
    - Track extra SYN packets (inferred from total SYN count - probe count; not directly measured)
    - Clearly define total, dropped, and not-dropped packets
    - Allow random variation around the 50% target (acceptable window: 20% - 80%)
    """
    validate_probe_count(probe_count)
    impair.log_info(f"--- Verifying Scenario S5 (IPv6 SYN Loss 50%, {probe_count} probes) ---")

    data = measure_syn_loss(
        target_ip=SERVER_IPV6,
        port=80,
        total_probes=probe_count,
        timeout=0.4,
        concurrency=10,
        dry_run=dry_run,
        simulated_loss_pct=48.0
    )

    total = data["total_syn_count"]
    dropped = data["dropped_packets"]
    accepted = data["accepted_packets"]
    loss_pct = data["observed_loss_pct"]

    if dry_run and total != probe_count:
        raise impair.ImpairmentError(f"S5 Probe count mismatch: expected {probe_count}, recorded {total}")

    if not dry_run and total < probe_count:
        raise impair.ImpairmentError(f"S5 Recorded SYN packets ({total}) less than requested probes ({probe_count})")

    if total != dropped + accepted:
        raise impair.ImpairmentError(f"S5 Accounting error: total ({total}) != dropped ({dropped}) + accepted ({accepted})")

    expected_loss_pct = (dropped / total * 100.0) if total > 0 else 0.0
    if abs(loss_pct - expected_loss_pct) > 1e-4:
        raise impair.ImpairmentError(
            f"S5 Accounting error: observed_loss_pct ({loss_pct:.1f}%) inconsistent with "
            f"dropped ({dropped}) / total ({total}) * 100 ({expected_loss_pct:.1f}%)"
        )

    if not dry_run and not (S5_LOSS_MIN_PCT <= loss_pct <= S5_LOSS_MAX_PCT):
        raise impair.ImpairmentError(
            f"S5 observed loss {loss_pct:.1f}% outside acceptable random variation ({S5_LOSS_MIN_PCT}% - {S5_LOSS_MAX_PCT}%)"
        )

    extra_syn = data.get("extra_syn_packets", 0)
    if dry_run:
        impair.log_ok(
            f"[DRY-RUN] S5 PASSED (simulated counts): simulated SYN packet count={total} "
            f"(initial probes={probe_count}, extra SYN packets={extra_syn}), "
            f"simulated dropped packets={dropped}, simulated not-dropped packets={accepted}, "
            f"simulated loss percentage={loss_pct:.1f}% (target ~50% random loss)"
        )
    else:
        impair.log_ok(
            f"S5 PASSED: SYN packet count={total} (initial probes={probe_count}, extra SYN packets={extra_syn}), "
            f"dropped packets={dropped}, not-dropped packets={accepted}, "
            f"observed loss percentage={loss_pct:.1f}% (target ~50% random loss)"
        )
    return data


def verify_s6(dry_run: bool = False) -> Dict[str, Any]:
    """
    Verify S6: Delay AAAA DNS Responses by 500ms
    - Query A: resolves immediately (<100ms) with 10.0.2.10
    - Query AAAA: delayed approximately 500ms (450ms - 750ms) with 2001:db8:2::10
    """
    impair.log_info("--- Verifying Scenario S6 (AAAA Delayed ~500ms, A Immediate) ---")

    # 1. Query A Record
    a_addr, a_delay_ms = query_dns_with_timing("A", dry_run=dry_run, simulated_delay_ms=3.5)
    if a_addr != SERVER_IPV4:
        raise impair.ImpairmentError(f"S6 A record mismatch: got '{a_addr}', expected '{SERVER_IPV4}'")
    if not dry_run and a_delay_ms > S6_A_MAX_DELAY_MS:
        raise impair.ImpairmentError(f"S6 A record resolution delayed: {a_delay_ms:.1f}ms > {S6_A_MAX_DELAY_MS}ms")
    impair.log_ok(f"S6 Check 1 PASSED: A record resolved immediately ({a_delay_ms:.1f}ms < {S6_A_MAX_DELAY_MS}ms -> {a_addr})")

    # 2. Query AAAA Record
    aaaa_addr, aaaa_delay_ms = query_dns_with_timing("AAAA", dry_run=dry_run, simulated_delay_ms=508.0)
    if aaaa_addr != SERVER_IPV6:
        raise impair.ImpairmentError(f"S6 AAAA record mismatch: got '{aaaa_addr}', expected '{SERVER_IPV6}'")
    if not dry_run and not (S6_AAAA_MIN_DELAY_MS <= aaaa_delay_ms <= S6_AAAA_MAX_DELAY_MS):
        raise impair.ImpairmentError(
            f"S6 AAAA resolution delay {aaaa_delay_ms:.1f}ms outside expected ~500ms window "
            f"({S6_AAAA_MIN_DELAY_MS}ms - {S6_AAAA_MAX_DELAY_MS}ms)"
        )
    impair.log_ok(
        f"S6 Check 2 PASSED: AAAA record delayed approximately 500ms "
        f"({aaaa_delay_ms:.1f}ms -> {aaaa_addr}, delta={aaaa_delay_ms - a_delay_ms:.1f}ms)"
    )

    return {
        "a_address": a_addr, "a_delay_ms": a_delay_ms,
        "aaaa_address": aaaa_addr, "aaaa_delay_ms": aaaa_delay_ms,
        "observed_delay_delta_ms": aaaa_delay_ms - a_delay_ms
    }


# ==============================================================================
# Self-Test Orchestrator with Mandatory Lifecycle Cleanup and Baseline Testing
# ==============================================================================

SCENARIO_VERIFIERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "S0": verify_s0,
    "S1": verify_s1,
    "S2": verify_s2,
    "S3": verify_s3,
    "S4": verify_s4,
    "S5": verify_s5,
    "S6": verify_s6,
}


def run_scenario_self_test(
    scenario_id: str,
    scenarios_path: Path = DEFAULT_SCENARIOS_PATH,
    dry_run: bool = False,
    probe_count: int = 50
) -> Dict[str, Any]:
    """
    Execute repeatable self-test harness for a single scenario with lifecycle guarantees:
      1. Reject invalid probe count (<= 0) BEFORE applying any scenario
      2. Apply scenario
      3. Run scenario-specific verification
      4. ALWAYS attempt cleanup impairments
      5. ALWAYS attempt baseline verification
      6. Do not suppress cleanup exceptions when baseline check passes
      7. Handle baseline-verification exceptions too
      8. Preserve original verification error plus cleanup and baseline errors
    """
    validate_probe_count(probe_count)

    sc_key = scenario_id.upper()
    verifier_name = f"verify_{sc_key.lower()}"
    verifier = getattr(sys.modules[__name__], verifier_name, None)
    if verifier is None:
        raise impair.ImpairmentError(
            f"Unknown scenario '{scenario_id}'. Supported: {sorted(SCENARIO_VERIFIERS.keys())}"
        )
    impair.log_info(f"============================================================")
    impair.log_info(f"Starting Self-Test Harness for Scenario {sc_key}")
    impair.log_info(f"============================================================")

    result_details: Dict[str, Any] = {}
    test_passed = False
    scenario_error: Optional[Exception] = None
    cleanup_error: Optional[Exception] = None
    baseline_error: Optional[Exception] = None

    try:
        # Step 1: Apply scenario
        impair.apply_scenario(sc_key, scenarios_path=scenarios_path, dry_run=dry_run)

        # Step 2: Run verification
        if sc_key == "S5":
            result_details = verifier(probe_count=probe_count, dry_run=dry_run)
        else:
            result_details = verifier(dry_run=dry_run)

        test_passed = True
        impair.log_ok(f"Scenario {sc_key} self-test verification SUCCEEDED.")
    except Exception as e:
        scenario_error = e
        impair.log_error(f"Scenario {sc_key} self-test verification FAILED: {scenario_error}")
    finally:
        # Step 3: MANDATORY CLEANUP (Always attempted)
        impair.log_info(f"Post-scenario {sc_key} lifecycle: clearing impairments and restoring baseline...")
        try:
            impair.clear_impairments(dry_run=dry_run)
        except Exception as clr_err:
            cleanup_error = clr_err
            impair.log_error(f"Post-scenario {sc_key} cleanup failed: {clr_err}")

        # Step 4: MANDATORY BASELINE VERIFICATION (Always attempted, even if cleanup raised)
        impair.log_info(f"Running self-test-baseline after scenario {sc_key}...")
        try:
            baseline_passed = impair.self_test_baseline(dry_run=dry_run)
            if not baseline_passed:
                baseline_error = impair.ImpairmentError(
                    f"CRITICAL: Baseline self-test failed following scenario {sc_key} execution!"
                )
                impair.log_error(str(baseline_error))
            else:
                impair.log_ok(f"Post-scenario {sc_key} baseline verified pristine.")
        except Exception as base_err:
            baseline_error = base_err
            impair.log_error(f"Post-scenario {sc_key} baseline check exception: {base_err}")

    # Step 5: Composite error handling preserving all errors
    errors: List[str] = []
    if scenario_error:
        errors.append(f"Scenario verification error: {scenario_error}")
    if cleanup_error:
        errors.append(f"Cleanup error: {cleanup_error}")
    if baseline_error:
        errors.append(f"Baseline error: {baseline_error}")

    if errors:
        if len(errors) == 1:
            err_msg = errors[0]
        else:
            err_msg = (
                f"Scenario {sc_key} lifecycle failed with multiple errors:\n"
                + "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))
            )
        exc = impair.ImpairmentError(err_msg)
        exc.scenario_error = scenario_error
        exc.cleanup_error = cleanup_error
        exc.baseline_error = baseline_error
        raise exc

    return {
        "scenario": sc_key,
        "passed": test_passed,
        "details": result_details,
        "post_baseline_verified": True
    }


def run_all_self_tests(
    scenarios: Optional[List[str]] = None,
    scenarios_path: Path = DEFAULT_SCENARIOS_PATH,
    dry_run: bool = False,
    probe_count: int = 50
) -> List[Dict[str, Any]]:
    """
    Run the self-test harness across all requested scenarios (defaults to S0 - S6).
    Rejects invalid probe counts before applying any scenario.
    Guarantees baseline verification between every scenario and at the conclusion.
    """
    validate_probe_count(probe_count)
    target_scenarios = [s.upper() for s in scenarios] if scenarios else ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
    impair.log_info(f"Executing self-test harness for scenarios: {', '.join(target_scenarios)}")

    results = []
    overall_start = time.perf_counter()

    for sc_id in target_scenarios:
        t_sc_start = time.perf_counter()
        res = run_scenario_self_test(sc_id, scenarios_path=scenarios_path, dry_run=dry_run, probe_count=probe_count)
        res["elapsed_sec"] = time.perf_counter() - t_sc_start
        results.append(res)

    overall_elapsed = time.perf_counter() - overall_start
    impair.log_info(f"============================================================")
    impair.log_ok(f"ALL {len(target_scenarios)} SCENARIO SELF-TESTS COMPLETED SUCCESSFULLY in {overall_elapsed:.2f}s")
    impair.log_info(f"============================================================")
    return results


# ==============================================================================
# Standalone CLI Entry Point
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
        description="PS-028 Repeatable Self-Test Harness for S0-S6 Scenarios (Work Package A5)"
    )
    parser.add_argument(
        "--scenarios-file",
        type=Path,
        default=DEFAULT_SCENARIOS_PATH,
        help="Path to scenarios.yaml configuration file"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Single scenario to test (S0, S1, S2, S3, S4, S5, S6)"
    )
    parser.add_argument(
        "--scenarios",
        type=str,
        default=None,
        help="Comma-separated list of scenarios to test (e.g. S0,S1,S2)"
    )
    parser.add_argument(
        "--probes",
        type=positive_int,
        default=50,
        help="Number of SYN probes for scenario S5 (default: 50, must be > 0)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Simulate operations without executing live network/system modifications"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output structured test results in JSON format"
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not isinstance(args.probes, int) or isinstance(args.probes, bool) or args.probes <= 0:
        impair.log_error(f"Invalid probe count: {args.probes}. Must be greater than zero (> 0).")
        return 1

    selected_scenarios: Optional[List[str]] = None
    if args.scenario:
        selected_scenarios = [args.scenario]
    elif args.scenarios:
        selected_scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]

    try:
        results = run_all_self_tests(
            scenarios=selected_scenarios,
            scenarios_path=args.scenarios_file,
            dry_run=args.dry_run,
            probe_count=args.probes
        )
        if args.json:
            print(json.dumps({"status": "PASS", "results": results}, indent=2))
        return 0
    except impair.ImpairmentError as e:
        impair.log_error(str(e))
        if args.json:
            print(json.dumps({"status": "FAIL", "error": str(e)}, indent=2))
        return 1
    except KeyboardInterrupt:
        impair.log_warn("Self-test harness interrupted by user. Performing emergency cleanup...")
        impair.clear_impairments(dry_run=args.dry_run)
        return 130


if __name__ == "__main__":
    sys.exit(main())
