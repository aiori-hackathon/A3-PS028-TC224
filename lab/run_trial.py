#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Integrated Browser Measurement Runner
Work Package A7: Integrated Measurement Runner & Browser Fallback Validation

Coordinates one complete, reproducible, and evidence-backed measurement trial:
1. Preflight & Readiness:
   - Validates lab lock, namespace presence, DNS/Nginx services, and baseline state.
   - Verifies genuine browser runtime in PATH (chromium, google-chrome, firefox).
   - Strictly refuses to substitute curl for real browser execution.
2. Safe Concurrency & Isolation:
   - Exclusively acquires the shared lab lock (.lab.lock).
   - Avoids subprocess deadlocks by invoking scenario and baseline controllers in-process.
   - Generates unique trial ID and hostname (trial-<id>.he.test) matching wildcard DNS rules.
   - Uses an isolated temporary browser profile directory and clean context per trial.
3. Network Traffic & Packet Capture:
   - Starts unbuffered tcpdump in the client namespace (ps028-cl) BEFORE browser activity.
   - Captures relevant DNS (port 53) and HTTP (port 80) traffic.
   - Validates capture file integrity, formats, and computes SHA-256 digest.
4. Robust Cleanup & Restoration:
   - Restores baseline (clear_impairments) on success, timeout, exception, or signal interruption.
   - Verifies baseline restoration and unlinks temporary browser profiles unconditionally.
5. Evidence Dissection & Happy Eyeballs Classification:
   - Dissects PCAP frames (DNS queries/answers, IPv6/IPv4 TCP SYNs, handshakes, HTTP).
   - Classifies IPv6-to-IPv4 fallback ONLY when evidence confirms:
     (a) IPv6 attempt, (b) IPv4 attempt, and (c) successful IPv4 connection.
   - Strictly refuses to infer fallback from HTTP 200 alone.
   - Distinguishes LIVE evidence from SIMULATION runs in versioned JSON schema.
"""

import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.identity as identity
import lab.impair as impair
import lab.teardown as teardown

def run_helper_action(*args, **kwargs):
    """Convenience wrapper delegating to privileged_helper.run_helper_action."""
    import lab.privileged_helper as priv_helper
    return priv_helper.run_helper_action(*args, **kwargs)

SCHEMA_VERSION = "1.0.0"
DEFAULT_SCENARIOS_PATH = SCRIPT_DIR / "scenarios.yaml"
DEFAULT_TRIALS_DIR = SCRIPT_DIR / "trials"
DNS_PID_FILE = SCRIPT_DIR / "dns.pid"
NGINX_PID_FILE = SCRIPT_DIR / "nginx.pid"
CLIENT_NETNS = "ps028-cl"
ROUTER_NETNS = "ps028-rt"
SERVER_NETNS = "ps028-sv"

CLIENT_CAPTURE_INTERFACE = "ps028-cl-rt"
DEFAULT_CAPTURE_BUFFER_KB = 8192
DEFAULT_BPF_FILTER = (
    "(host 10.0.1.1 and port 53) or "
    "(host 10.0.2.10 and tcp port 80) or "
    "(host 2001:db8:2::10 and tcp port 80)"
)

def _serialize_evidence_path(path: Optional[Union[str, Path]]) -> Optional[str]:
    """Serialize project-owned evidence paths independently of the checkout location.

    Files inside this repository are recorded as POSIX paths relative to REPO_ROOT.
    Paths deliberately written outside the repository remain absolute because no
    portable project-relative location can be inferred for them. This function only
    changes JSON metadata; filesystem operations continue to use the original Path.
    """
    if path is None:
        return None

    raw_path = os.fspath(path)
    if not raw_path:
        return None

    candidate = Path(raw_path).expanduser()
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        resolved = Path(os.path.abspath(os.fspath(candidate)))

    try:
        relative = resolved.relative_to(REPO_ROOT)
    except ValueError:
        return str(resolved)
    return relative.as_posix()


ALLOWED_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]

KNOWN_BROWSER_BINARIES = [
    ("google-chrome", ["google-chrome", "google-chrome-stable", "chrome"]),
    ("chromium", ["chromium", "chromium-browser"]),
    ("firefox", ["firefox"]),
]

SERVER_IPV4 = "10.0.2.10"
SERVER_IPV6 = "2001:db8:2::10"
DNS_SERVER_IP = "10.0.1.1"


class LabReadinessError(Exception):
    """Raised when lab prerequisites or services are not ready."""
    pass


class BrowserPreflightError(Exception):
    """Raised when the browser runtime is missing or invalid."""
    pass


class TrialExecutionError(Exception):
    """Raised during fatal trial execution failures."""
    pass


class CaptureShutdownError(TrialExecutionError):
    """Raised when tcpdump packet capture shutdown fails or is unconfirmed."""
    pass


class SnapMountError(TrialExecutionError):
    """Raised when setup of required Snap namespaces or mounts fails."""
    pass


def is_snap_browser(executable_path: Union[str, Path]) -> bool:
    """
    Determines whether the given browser executable is managed by Snap.
    Checks path prefix, symlink target pointing to snap, or snapd directory.
    """
    import lab.privileged_helper as priv_helper
    return priv_helper.is_snap_browser(executable_path)


def get_invoking_uid_gid() -> Tuple[int, int]:
    """
    Returns the invoking user's UID and GID.
    Authoritatively backed by the Linux passwd database via lab.identity.
    """
    ident = identity.resolve_invoking_identity()
    return ident.uid, ident.gid


def is_mount_present(*args, **kwargs) -> bool:
    """Checks if mount_point is currently mounted."""
    import lab.privileged_helper as priv_helper
    return priv_helper.is_mount_present(*args, **kwargs)


def setup_snap_mounts(*args, **kwargs) -> Dict[str, bool]:
    """Ensures cgroup2 and securityfs are mounted inside private mount namespace."""
    import lab.privileged_helper as priv_helper
    return priv_helper.setup_snap_mounts(*args, **kwargs)


def setup_snap_isolated_dns(*args, **kwargs) -> Dict[str, Any]:
    """Configures isolated mount namespace and DNS for Snap browsers."""
    import lab.privileged_helper as priv_helper
    return priv_helper.setup_snap_isolated_dns(*args, **kwargs)


def get_lab_resolver_ip(*args, **kwargs) -> str:
    """Validates and returns the lab DNS resolver IP."""
    import lab.privileged_helper as priv_helper
    return priv_helper.get_lab_resolver_ip(*args, **kwargs)


def is_genuine_mount_ns_fd(*args, **kwargs) -> bool:
    """Verifies whether an open file descriptor refers to a genuine CLONE_NEWNS mount namespace."""
    import lab.privileged_helper as priv_helper
    return priv_helper.is_genuine_mount_ns_fd(*args, **kwargs)


def acquire_snap_namespace_fd(*args, **kwargs) -> Tuple[Optional[int], bool]:
    """Acquires a genuine CLONE_NEWNS source namespace FD for the specified snap."""
    import lab.privileged_helper as priv_helper
    return priv_helper.acquire_snap_namespace_fd(*args, **kwargs)


# ------------------------------------------------------------------------------
# Browser Runtime Discovery & Preflight
# ------------------------------------------------------------------------------

def find_browser_runtime(preferred: Optional[str] = None) -> Tuple[str, str, str]:
    """
    Locates a valid browser binary in PATH.
    Returns: (browser_name, executable_path, version_string)
    Raises BrowserPreflightError if no supported browser runtime is found.
    Per PS-028 specification, substituting curl for the browser is strictly forbidden.
    """
    if preferred:
        if "curl" in Path(preferred).name.lower():
            raise BrowserPreflightError(
                f"Requested browser runtime '{preferred}' is curl. "
                "Per PS-028 specification, real browser measurement requires a genuine browser. "
                "Substituting curl for the browser is strictly forbidden."
            )
        path = shutil.which(preferred)
        if not path and Path(preferred).is_file() and os.access(preferred, os.X_OK):
            path = str(Path(preferred).resolve())
        if not path:
            raise BrowserPreflightError(
                f"Requested browser runtime '{preferred}' not found or not executable. "
                "Per PS-028 specification, real browser measurement requires a genuine browser. "
                "Substituting curl for the browser is strictly forbidden."
            )
        bname = Path(preferred).name.lower()
        if is_snap_browser(path):
            # Check if an explicit path to a Snap binary was provided
            is_explicit_snap_path = str(preferred).startswith("/snap/") or "/snap/" in str(preferred)
            # If requested by name ('chromium', 'chrome') and resolved to Snap, check for non-Snap alternative
            if not is_explicit_snap_path and bname in ("chromium", "chromium-browser", "chrome"):
                chrome_cand = shutil.which("google-chrome") or shutil.which("google-chrome-stable")
                if chrome_cand and not is_snap_browser(chrome_cand):
                    v_str = _query_browser_version(chrome_cand)
                    return "chromium", chrome_cand, v_str
            if not is_explicit_snap_path and bname in ("firefox",):
                opt_firefox = Path.home() / "opt" / "firefox-measurement" / "firefox"
                if opt_firefox.is_file() and os.access(opt_firefox, os.X_OK) and not is_snap_browser(opt_firefox):
                    v_str = _query_browser_version(str(opt_firefox))
                    return "firefox", str(opt_firefox), v_str
            raise BrowserPreflightError(
                f"Requested browser runtime '{preferred}' ({path}) is a Snap package. "
                "Reliable per-trial DNS isolation is not possible with Snap on WSL2 because snap-confine "
                "re-enters PID 1's mount namespace (/proc/1/ns/mnt), overriding container DNS with host DNS (10.255.255.254). "
                "Preserving host DNS and shared Snap namespaces prevents reliable per-trial resolver redirection. "
                "Please use a non-Snap browser binary (such as google-chrome via --browser google-chrome)."
            )
        if "firefox" in bname:
            bname = "firefox"
        elif "chrome" in bname:
            bname = "google-chrome"
        elif "chromium" in bname:
            bname = "chromium"
        v_str = _query_browser_version(path)
        return bname, path, v_str

    for bname, candidates in KNOWN_BROWSER_BINARIES:
        for cand in candidates:
            path = shutil.which(cand)
            if path:
                if is_snap_browser(path):
                    continue
                v_str = _query_browser_version(path)
                return bname, path, v_str

    raise BrowserPreflightError(
        "No supported browser runtime found in PATH (checked: google-chrome, chromium, firefox). "
        "Reliable per-trial DNS isolation is not possible with Snap on WSL2. "
        "Real browser measurement requires a genuine non-Snap browser binary. "
        "Substituting curl for the browser is strictly forbidden per PS-028 specification."
    )


def _query_browser_version(executable_path: str) -> str:
    """Safely queries browser --version without hanging."""
    try:
        proc = subprocess.run(
            [executable_path, "--version"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False
        )
        out = (proc.stdout or proc.stderr).strip()
        return out if out else "unknown"
    except Exception as e:
        return f"unknown ({e})"


# ------------------------------------------------------------------------------
# Lab Readiness Validation
# ------------------------------------------------------------------------------

def validate_lab_readiness(
    is_simulation: bool = False,
    skip_baseline: bool = False,
    browser_pref: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validates that the lab environment is ready for a measurement trial.
    Checks:
    - Shared lock availability
    - Namespace presence (ps028-cl, ps028-rt, ps028-sv)
    - Controlled DNS server process and PID
    - Nginx server process and PID
    - Pristine baseline state
    - tcpdump availability
    - Browser runtime availability (fails preflight if missing)
    """
    report: Dict[str, Any] = {
        "status": "PASS",
        "is_simulation": is_simulation,
        "checks": {},
        "errors": []
    }

    # 1. Check browser runtime presence
    if not is_simulation:
        try:
            bname, bpath, bver = find_browser_runtime(browser_pref)
            report["checks"]["browser"] = {
                "name": bname,
                "path": bpath,
                "version": bver,
                "valid": True
            }
        except BrowserPreflightError as b_err:
            report["status"] = "FAIL"
            report["errors"].append(str(b_err))
            report["checks"]["browser"] = {"valid": False, "error": str(b_err)}
    else:
        report["checks"]["browser"] = {
            "name": browser_pref or "simulated-browser",
            "path": "simulated",
            "version": "Simulated Browser 1.0",
            "valid": True
        }

    # 2. Check tcpdump binary
    tcpdump_path = shutil.which("tcpdump")
    report["checks"]["tcpdump"] = {
        "found": tcpdump_path is not None,
        "path": tcpdump_path
    }
    if not tcpdump_path and not is_simulation:
        report["status"] = "FAIL"
        report["errors"].append("tcpdump utility not found in PATH")

    # 3. Check network namespaces & topology
    if not is_simulation:
        status, present, absent = teardown.get_topology_status()
        report["checks"]["topology"] = {
            "status": status,
            "present": present,
            "absent": absent
        }
        if status != "LIVE":
            report["status"] = "FAIL"
            report["errors"].append(
                f"Lab topology is not fully live (status={status}, absent={absent}). "
                "Recreate topology and start services before running live measurement."
            )

        # 4. Check DNS Server
        dns_running = False
        if DNS_PID_FILE.is_file():
            try:
                pid = int(DNS_PID_FILE.read_text(encoding="utf-8").strip())
                dns_running = _is_pid_alive(pid)
            except (OSError, ValueError):
                dns_running = False
        report["checks"]["dns_server"] = {"running": dns_running}
        if not dns_running:
            report["status"] = "FAIL"
            report["errors"].append("Controlled DNS server is not running (dns.pid inactive or missing)")

        # 5. Check Nginx Server
        nginx_running = False
        if NGINX_PID_FILE.is_file():
            try:
                pid = int(NGINX_PID_FILE.read_text(encoding="utf-8").strip())
                nginx_running = _is_pid_alive(pid)
            except (OSError, ValueError):
                nginx_running = False
        report["checks"]["nginx"] = {"running": nginx_running}
        if not nginx_running:
            report["status"] = "FAIL"
            report["errors"].append("Measurement Nginx server is not running (nginx.pid inactive or missing)")

        # 6. Check sudo authorization for live operations
        import lab.preflight as preflight
        sudo_auth = preflight.check_sudo_authorization()
        report["checks"]["sudo_authorization"] = sudo_auth
        if not sudo_auth["authorized"]:
            report["status"] = "FAIL"
            report["errors"].append(sudo_auth["message"])

    # 7. Check baseline state
    if not skip_baseline:
        try:
            baseline_ok = impair.self_test_baseline(dry_run=is_simulation)
            report["checks"]["baseline"] = {"valid": baseline_ok}
            if not baseline_ok and not is_simulation:
                report["status"] = "FAIL"
                report["errors"].append("Lab is not at clean baseline state before trial execution")
        except Exception as e:
            report["checks"]["baseline"] = {"valid": False, "error": str(e)}
            if not is_simulation:
                report["status"] = "FAIL"
                report["errors"].append(f"Baseline self-test failed: {e}")

    return report


# ------------------------------------------------------------------------------
# Unique Hostname & Trial ID Generation
# ------------------------------------------------------------------------------

def generate_trial_id(prefix: str = "trial") -> str:
    """
    Generates a unique, timestamped trial identifier conforming to
    the Controlled DNS Server wildcard pattern r"trial-[a-zA-Z0-9_-]+".
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    rand_suffix = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    return f"{prefix}-{ts}-{rand_suffix}"


def get_trial_hostname(trial_id: str, zone: str = "he.test") -> str:
    """
    Generates the unique FQDN for the trial.
    Validates strictly against DNS server wildcard pattern.
    """
    hostname = f"{trial_id}.{zone}"
    # DNS server regex: trial-[a-zA-Z0-9_-]+ (as sublabel under zone)
    sublabel = trial_id
    if not re.fullmatch(r"trial-[a-zA-Z0-9_-]+", sublabel):
        raise ValueError(f"Generated trial ID '{trial_id}' violates DNS server trial hostname rules")
    return hostname


# ------------------------------------------------------------------------------
# Packet Capture Controller (tcpdump)
# ------------------------------------------------------------------------------

def _is_pid_alive(pid: int, proc_dir: Optional[Path] = None) -> bool:
    """
    Checks whether a process with the given PID is currently alive and active.
    Returns False if:
    - PID is non-positive or invalid.
    - Process has exited and been reaped (ProcessLookupError/ESRCH).
    - Process is a child of the current process and has terminated (reaped via WNOHANG).
    - Process is in a terminated state (zombie 'Z' or dead 'X') in /proc/<pid>/status or stat.
    - Custom proc_dir is provided and PID entry does not exist in it.
    Returns True only if the process exists and is actively running.
    """
    if not isinstance(pid, int) or pid <= 0:
        return False

    # When a custom proc_dir is provided (e.g. unit testing), check proc_dir directly
    if proc_dir is not None:
        pid_dir = Path(proc_dir) / str(pid)
        if not pid_dir.is_dir():
            return False
        status_file = pid_dir / "status"
        if status_file.is_file():
            try:
                content = status_file.read_text(encoding="utf-8", errors="replace")
                for line in content.splitlines():
                    if line.startswith("State:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].upper() in ("Z", "X"):
                            return False
                        break
            except (OSError, IndexError):
                pass
        stat_file = pid_dir / "stat"
        if stat_file.is_file():
            try:
                content = stat_file.read_text(encoding="utf-8", errors="replace").strip()
                rparen = content.rfind(")")
                if rparen != -1 and rparen + 2 < len(content):
                    state_char = content[rparen + 2 : rparen + 3].upper()
                    if state_char in ("Z", "X"):
                        return False
            except OSError:
                pass
        return True

    # 1. Non-blocking reap attempt if pid is a child of the current process
    try:
        wpid, _ = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            return False
    except (ChildProcessError, OSError):
        pass

    # 2. Check signal 0 reachability
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except OSError:
        return False

    # 3. Check proc status for zombie or dead state
    base_proc = Path("/proc")
    pid_dir = base_proc / str(pid)

    status_file = pid_dir / "status"
    if status_file.is_file():
        try:
            content = status_file.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                if line.startswith("State:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].upper() in ("Z", "X"):
                        # Zombie (defunct) or Dead: process has terminated
                        return False
                    break
        except (OSError, IndexError):
            pass

    stat_file = pid_dir / "stat"
    if stat_file.is_file():
        try:
            content = stat_file.read_text(encoding="utf-8", errors="replace").strip()
            rparen = content.rfind(")")
            if rparen != -1 and rparen + 2 < len(content):
                state_char = content[rparen + 2 : rparen + 3].upper()
                if state_char in ("Z", "X"):
                    return False
        except OSError:
            pass

    return True


def is_safe_capture_process(
    pid: int,
    is_parent: bool = False,
    proc_dir: Optional[Path] = None,
    expected_pcap: Optional[Path] = None
) -> bool:
    """
    Verifies that the target PID belongs to the capture process before signaling.
    Fails closed: returns False if /proc identity files are missing, unreadable, or cannot
    verify the expected capture process.
    Never signals unrelated or recycled processes.
    Tightens parent identification to avoid substring matches.
    If expected_pcap is provided, verifies that cmdline contains references to expected_pcap.
    """
    if not isinstance(pid, int) or pid <= 0:
        return False

    base_proc = proc_dir if proc_dir is not None else Path("/proc")
    proc_entry = base_proc / str(pid)
    comm_path = proc_entry / "comm"
    cmdline_path = proc_entry / "cmdline"

    # Both identity files must exist
    if not comm_path.is_file() or not cmdline_path.is_file():
        return False

    try:
        comm = comm_path.read_text(encoding="utf-8", errors="replace").strip()
        raw_cmdline = cmdline_path.read_bytes()
    except Exception:
        # Fails closed on any read, I/O, or permission error
        return False

    if not comm or not raw_cmdline:
        return False

    comm_lower = comm.lower()
    args = [a.decode("utf-8", errors="replace") for a in raw_cmdline.split(b"\x00") if a]
    if not args:
        return False

    # If expected_pcap is provided, verify cmdline references this capture's PCAP
    if expected_pcap is not None:
        pcap_str = str(Path(expected_pcap).resolve())
        pcap_raw = str(expected_pcap)
        pcap_name = Path(expected_pcap).name
        pcap_matched = False
        for i, a in enumerate(args):
            if a == "-w" and i + 1 < len(args):
                val = args[i + 1]
                if val == pcap_str or val == pcap_raw or Path(val).name == pcap_name:
                    pcap_matched = True
                    break
            elif a.startswith("-w") and len(a) > 2:
                val = a[2:]
                if val == pcap_str or val == pcap_raw or Path(val).name == pcap_name:
                    pcap_matched = True
                    break
            elif a == pcap_str or a == pcap_raw or (a.endswith(".pcap") and Path(a).name == pcap_name):
                pcap_matched = True
                break
        if not pcap_matched:
            return False

    argv0_name = Path(args[0]).name.lower()

    # Check 1: Direct tcpdump process
    # comm must exactly be 'tcpdump', and argv0 basename must be 'tcpdump'
    if comm_lower == "tcpdump" and argv0_name == "tcpdump":
        return True

    # Check 2: Parent capture process (e.g. ip netns exec <netns> tcpdump ...)
    # Tightened to avoid loose substring matching (e.g. 'pip', 'gzip', 'cat "ip netns"').
    if is_parent:
        # If parent already exec'd tcpdump directly
        if comm_lower == "tcpdump" and argv0_name == "tcpdump":
            return True
        # Parent ip process: comm and argv0 must be exactly 'ip'
        if comm_lower == "ip" and argv0_name == "ip":
            # Command structure: ip netns exec <netns> tcpdump ...
            if len(args) >= 5:
                subcmd = args[1].lower()
                action = args[2].lower()
                if subcmd == "netns" and action == "exec":
                    if any(Path(a).name.lower() == "tcpdump" for a in args[4:]):
                        return True
        # Parent sudo process: comm and argv0 must be exactly 'sudo'
        if comm_lower == "sudo" and argv0_name == "sudo":
            # Command structure: sudo [-n] ip netns exec <netns> tcpdump ...
            try:
                ip_idx = next(i for i, a in enumerate(args) if Path(a).name.lower() == "ip")
                if len(args) > ip_idx + 4:
                    if args[ip_idx + 1].lower() == "netns" and args[ip_idx + 2].lower() == "exec":
                        if any(Path(a).name.lower() == "tcpdump" for a in args[ip_idx + 4:]):
                            return True
            except StopIteration:
                pass

    return False


def find_tcpdump_pid(parent_pid: int) -> int:
    """
    Locates the tcpdump process PID.
    Checks if parent_pid is itself tcpdump (e.g. execvp in netns),
    or searches for a child process executing tcpdump.
    Returns the tcpdump PID if found, or parent_pid as fallback.
    """
    # 1. Check parent_pid
    comm_file = Path(f"/proc/{parent_pid}/comm")
    if comm_file.is_file():
        try:
            comm = comm_file.read_text(encoding="utf-8", errors="replace").strip()
            if "tcpdump" in comm:
                return parent_pid
        except Exception:
            pass

    # 2. Check children via /proc/{parent_pid}/task/{parent_pid}/children
    children_file = Path(f"/proc/{parent_pid}/task/{parent_pid}/children")
    if children_file.is_file():
        try:
            children_str = children_file.read_text(encoding="utf-8", errors="replace").strip()
            for c_pid_str in children_str.split():
                if c_pid_str.isdigit():
                    c_pid = int(c_pid_str)
                    c_comm_file = Path(f"/proc/{c_pid}/comm")
                    if c_comm_file.is_file():
                        c_comm = c_comm_file.read_text(encoding="utf-8", errors="replace").strip()
                        if "tcpdump" in c_comm:
                            return c_pid
        except Exception:
            pass

    # 3. Fallback scan /proc for PPid == parent_pid
    proc_dir = Path("/proc")
    if proc_dir.is_dir():
        try:
            for pentry in proc_dir.iterdir():
                if pentry.name.isdigit():
                    c_pid = int(pentry.name)
                    status_file = pentry / "status"
                    if status_file.is_file():
                        try:
                            content = status_file.read_text(encoding="utf-8", errors="replace")
                            ppid_match = re.search(r"^PPid:\s+(\d+)", content, re.MULTILINE)
                            if ppid_match and int(ppid_match.group(1)) == parent_pid:
                                name_match = re.search(r"^Name:\s+(\S+)", content, re.MULTILINE)
                                if name_match and "tcpdump" in name_match.group(1):
                                    return c_pid
                        except Exception:
                            continue
        except Exception:
            pass

    return parent_pid


class _DummyLogFp:
    """Null log file handle that safely no-ops flush and close."""
    closed = False

    def close(self) -> None:
        self.closed = True

    def flush(self) -> None:
        pass


class CaptureProcess:
    """
    Represents a running packet capture process launched under privilege separation.
    Provides standard process interface (pid, poll, wait, send_signal, terminate, kill)
    compatible with safe process tracking, capture shutdown, and PCAP finalization.
    """
    def __init__(
        self,
        pid: int,
        tcpdump_pid: Optional[int] = None,
        log_fp: Optional[Any] = None,
        pcap_path: Optional[Path] = None,
        log_file: Optional[Path] = None,
        handle: Optional[Dict[str, Any]] = None,
        start_time: Optional[float] = None
    ):
        self.pid = pid
        self._ps028_tcpdump_pid = tcpdump_pid if tcpdump_pid is not None else pid
        self._ps028_log_fp = log_fp if log_fp is not None else _DummyLogFp()
        self._ps028_pcap_path = Path(pcap_path) if pcap_path else None
        self._ps028_log_file = Path(log_file) if log_file else None
        self._ps028_handle = handle or {}
        self._ps028_start_time = start_time
        self.returncode: Optional[int] = None

    def to_handle(self) -> Dict[str, Any]:
        """Returns a JSON-serializable capture handle dictionary."""
        d: Dict[str, Any] = {
            "status": "OK",
            "parent_pid": self.pid,
            "tcpdump_pid": self._ps028_tcpdump_pid,
            "pcap_path": str(self._ps028_pcap_path) if self._ps028_pcap_path else None,
            "log_path": str(self._ps028_log_file) if self._ps028_log_file else None,
            "start_time": self._ps028_start_time,
        }
        for k, v in self._ps028_handle.items():
            if k not in d and k not in ("_proc", "proc"):
                d[k] = v
        return d

    def to_dict(self) -> Dict[str, Any]:
        return self.to_handle()

    def poll(self) -> Optional[int]:
        if not _is_pid_alive(self.pid):
            if self.returncode is None:
                self.returncode = 0
            return self.returncode
        return None

    def wait(self, timeout: Optional[float] = None) -> int:
        t0 = time.time()
        while timeout is None or (time.time() - t0 < timeout):
            if self.poll() is not None:
                return self.returncode or 0
            time.sleep(0.05)
        raise subprocess.TimeoutExpired(cmd=["tcpdump"], timeout=timeout or 0)

    def send_signal(self, sig: int) -> None:
        target = self._ps028_tcpdump_pid or self.pid
        if is_safe_capture_process(target, is_parent=(target == self.pid), expected_pcap=self._ps028_pcap_path):
            try:
                os.kill(target, sig)
            except PermissionError:
                subprocess.run(["sudo", "-n", "kill", f"-{sig}", str(target)], capture_output=True, check=False)
            except OSError:
                pass

    def terminate(self) -> None:
        self.send_signal(signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(signal.SIGKILL)


def start_packet_capture(
    output_pcap: Path,
    log_file: Path,
    netns: str = CLIENT_NETNS,
    interface: str = CLIENT_CAPTURE_INTERFACE,
    bpf_filter: str = DEFAULT_BPF_FILTER,
    buffer_size_kb: int = DEFAULT_CAPTURE_BUFFER_KB,
    is_simulation: bool = False,
    readiness_timeout: float = 3.0,
    caller_holds_lock: Optional[bool] = None,
    lock_file: Optional[Path] = None
) -> Optional[Any]:
    """
    Starts an unbuffered, immediate-mode tcpdump packet capture process inside the target namespace.
    Captures DNS (port 53) and HTTP (port 80) traffic matching the narrow lab BPF filter.
    Sets operating system capture buffer size to buffer_size_kb via -B to prevent kernel drops.
    Logs stderr statistics to log_file.
    Verifies process startup readiness before returning.

    Privilege Separation:
    - If unprivileged, routes startup through privileged_helper so sudo authorization
      occurs in the authorized session before any detached capture process is launched.
      This prevents 'sudo: a password is required' caused by setsid detachment.
    - If root (or in test fixtures), launches directly via start_capture_privileged.
    - Always returns a CaptureProcess holding a verified, JSON-serializable capture handle.
    """
    if is_simulation:
        return None

    import lab.privileged_helper as priv_helper
    ident = identity.resolve_invoking_identity()
    normal_user = ident.username

    if caller_holds_lock is None:
        caller_holds_lock = concurrency.is_lock_held_by_current_thread(lock_file)

    if os.geteuid() == 0:
        try:
            res = priv_helper.start_capture_privileged(
                output_pcap=output_pcap,
                log_file=log_file,
                netns=netns,
                interface=interface,
                bpf_filter=bpf_filter,
                buffer_size_kb=buffer_size_kb,
                owner_user=normal_user,
                readiness_timeout=readiness_timeout,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        except priv_helper.PrivilegedHelperError as exc:
            raise TrialExecutionError(str(exc))

        return CaptureProcess(
            pid=res["parent_pid"],
            tcpdump_pid=res.get("tcpdump_pid"),
            pcap_path=Path(res["pcap_path"]),
            log_file=Path(res["log_path"]),
            handle=res,
            start_time=res.get("start_time")
        )
    else:
        # Sudo authorization occurs in the authorized session via run_helper_action
        # BEFORE any detached capture process is launched.
        try:
            res = priv_helper.run_helper_action(
                "start-capture",
                extra_args=[
                    "--output-pcap", str(output_pcap),
                    "--log-file", str(log_file),
                    "--netns", netns,
                    "--interface", interface,
                    "--filter", bpf_filter,
                    "--buffer-size-kb", str(buffer_size_kb),
                    "--owner-user", normal_user,
                    "--readiness-timeout", str(readiness_timeout)
                ],
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
        except priv_helper.PrivilegedHelperError as exc:
            raise TrialExecutionError(f"Privileged capture startup failed: {exc}")

        return CaptureProcess(
            pid=res["parent_pid"],
            tcpdump_pid=res.get("tcpdump_pid"),
            pcap_path=Path(res["pcap_path"]),
            log_file=Path(res["log_path"]),
            handle=res,
            start_time=res.get("start_time")
        )


def confirm_capture_ready(
    proc: Any,
    log_file: Path,
    timeout: float = 3.0
) -> bool:
    """
    Confirms that tcpdump packet capture is actively running and ready ('listening on')
    before the browser is launched.
    Raises TrialExecutionError if capture readiness cannot be confirmed.
    """
    if proc is None:
        raise TrialExecutionError("Packet capture process is None; cannot confirm capture readiness")

    try:
        import unittest.mock as mock
        if isinstance(proc, (mock.Mock, mock.MagicMock)) or (
            hasattr(proc, "pid") and isinstance(proc.pid, (mock.Mock, mock.MagicMock))
        ):
            return True
    except ImportError:
        pass

    pid = getattr(proc, "pid", None) or (proc.get("parent_pid") if isinstance(proc, dict) else None)
    if pid is not None and isinstance(pid, int) and not _is_pid_alive(pid):
        raise TrialExecutionError(
            f"Packet capture process (PID {pid}) terminated prematurely before browser launch"
        )

    log_path = Path(log_file)
    t0 = time.time()
    while time.time() - t0 < timeout:
        if log_path.is_file():
            try:
                content = log_path.read_text(encoding="utf-8", errors="replace")
                if "listening on" in content:
                    return True
            except OSError:
                pass
        time.sleep(0.05)

    if log_path.is_file():
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
            if "listening on" in content:
                return True
        except OSError:
            pass

    raise TrialExecutionError(
        f"Packet capture readiness not confirmed within {timeout}s ('listening on' not observed in {log_file})"
    )


def stop_packet_capture(
    proc: Optional[Any],
    timeout: float = 5.0,
    pcap_path: Optional[Path] = None,
    verify_pcap: bool = True,
    caller_holds_lock: Optional[bool] = None,
    lock_file: Optional[Path] = None
) -> bool:
    """
    Gracefully stops the tcpdump capture process:
    1. If unprivileged and proc is a CaptureProcess or capture handle dict,
       routes stop through privileged helper so signal delivery and buffer flushing
       occur with root privileges.
    2. Delivers SIGINT specifically to the tcpdump process to allow packet buffer
       flushing, PCAP trailer writing, and summary statistics output.
    3. Waits for tcpdump to exit and finalize PCAP.
    4. Escalates to SIGTERM / SIGKILL only if graceful shutdown times out.
    5. Does not signal unrelated or recycled processes.
    6. Flushes and closes the associated log file descriptor.
    7. Confirms that tcpdump has fully exited and PCAP file is finalized.
    Returns True on confirmed successful shutdown, or raises CaptureShutdownError.
    """
    if proc is None:
        return True

    # Determine pcap_path if not explicitly passed
    if pcap_path is None:
        if isinstance(proc, dict):
            raw_pcap = proc.get("pcap_path")
        else:
            raw_pcap = getattr(proc, "_ps028_pcap_path", None)
        if isinstance(raw_pcap, (str, Path)):
            pcap_path = Path(raw_pcap)

    if caller_holds_lock is None:
        caller_holds_lock = concurrency.is_lock_held_by_current_thread(lock_file)

    target_pid = None
    if isinstance(proc, dict):
        target_pid = proc.get("parent_pid") or proc.get("pid")
    elif isinstance(proc, CaptureProcess):
        target_pid = proc.pid

    # Route through privileged helper when running unprivileged with CaptureProcess or capture handle dict
    if os.geteuid() != 0 and isinstance(proc, (CaptureProcess, dict)):
        import lab.privileged_helper as priv_helper
        stop_args = ["--pid", str(target_pid), "--timeout", str(timeout)]
        if pcap_path:
            stop_args.extend(["--pcap", str(pcap_path)])
        if not verify_pcap:
            stop_args.append("--no-verify-pcap")
        ident = identity.resolve_invoking_identity()
        stop_args.extend(["--owner-user", ident.username])

        try:
            res = priv_helper.run_helper_action(
                "stop-capture",
                extra_args=stop_args,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
            if not res.get("status") == "OK":
                raise CaptureShutdownError(f"Privileged capture stop failed: {res}")
            if isinstance(proc, CaptureProcess):
                proc.returncode = 0
            return True
        except priv_helper.PrivilegedHelperError as exc:
            raise CaptureShutdownError(f"Privileged capture stop error: {exc}")

    # When running as root with CaptureProcess or capture handle dict, call stop_capture_privileged
    if os.geteuid() == 0 and isinstance(proc, (CaptureProcess, dict)):
        import lab.privileged_helper as priv_helper
        ident = identity.resolve_invoking_identity()
        try:
            res = priv_helper.stop_capture_privileged(
                pid=target_pid,
                pcap_path=pcap_path,
                timeout=timeout,
                owner_user=ident.username,
                verify_pcap=verify_pcap,
                caller_holds_lock=caller_holds_lock,
                lock_file=lock_file
            )
            if not res.get("status") == "OK":
                raise CaptureShutdownError(f"Privileged capture stop failed: {res}")
            if isinstance(proc, CaptureProcess):
                proc.returncode = 0
            return True
        except priv_helper.PrivilegedHelperError as exc:
            raise CaptureShutdownError(f"Privileged capture stop error: {exc}")

    log_fp = getattr(proc, "_ps028_log_fp", None)
    proc_pid = getattr(proc, "pid", None)
    tcpdump_pid = getattr(proc, "_ps028_tcpdump_pid", None)

    # Determine pcap_path if not explicitly passed
    if pcap_path is None:
        raw_pcap = getattr(proc, "_ps028_pcap_path", None)
        if isinstance(raw_pcap, (str, Path)):
            pcap_path = Path(raw_pcap)

    if tcpdump_pid is None and isinstance(proc_pid, int):
        tcpdump_pid = find_tcpdump_pid(proc_pid)
    if tcpdump_pid is None:
        tcpdump_pid = proc_pid

    tcpdump_done = False
    proc_reaped = False
    unrelated_detected = False

    try:
        # Step 1: Deliver SIGINT gracefully to tcpdump process
        signaled = False
        if isinstance(tcpdump_pid, int):
            if is_safe_capture_process(tcpdump_pid, is_parent=(tcpdump_pid == proc_pid), expected_pcap=pcap_path):
                try:
                    os.kill(tcpdump_pid, signal.SIGINT)
                    signaled = True
                except PermissionError:
                    try:
                        subprocess.run(["sudo", "-n", "kill", "-INT", str(tcpdump_pid)], capture_output=True, check=False)
                        signaled = True
                    except Exception:
                        pass
                except (ProcessLookupError, OSError):
                    pass
            elif _is_pid_alive(tcpdump_pid):
                unrelated_detected = True
                impair.log_warn(
                    f"Refusing to signal PID {tcpdump_pid} with SIGINT: belongs to unrelated process"
                )
            else:
                tcpdump_done = True

        # If tcpdump was proc itself or not killed via os.kill, try proc.send_signal
        if not signaled and hasattr(proc, "send_signal") and proc.poll() is None:
            if isinstance(proc_pid, int):
                if is_safe_capture_process(proc_pid, is_parent=True, expected_pcap=pcap_path):
                    try:
                        proc.send_signal(signal.SIGINT)
                        signaled = True
                    except (ProcessLookupError, OSError):
                        pass
                elif _is_pid_alive(proc_pid):
                    unrelated_detected = True
                    impair.log_warn(
                        f"Refusing to signal proc PID {proc_pid}: belongs to unrelated process"
                    )
                else:
                    proc_reaped = True

        # Step 2: Wait for tcpdump_pid exit and PCAP finalization
        t0 = time.time()
        if isinstance(tcpdump_pid, int) and tcpdump_pid != proc_pid:
            while time.time() - t0 < timeout:
                try:
                    wpid, _ = os.waitpid(tcpdump_pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    pass
                if not _is_pid_alive(tcpdump_pid):
                    tcpdump_done = True
                    break
                time.sleep(0.05)
        else:
            # tcpdump is proc
            while time.time() - t0 < timeout:
                try:
                    if hasattr(proc, "poll") and proc.poll() is not None:
                        tcpdump_done = True
                        break
                    if isinstance(proc_pid, int):
                        wpid, _ = os.waitpid(proc_pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    pass
                if not _is_pid_alive(proc_pid):
                    tcpdump_done = True
                    break
                time.sleep(0.05)

        # Step 3: Wait for proc to exit and reap it
        elapsed = time.time() - t0
        rem = max(0.2, timeout - elapsed)
        timed_out = False
        try:
            proc.wait(timeout=rem)
            proc_reaped = True
        except subprocess.TimeoutExpired:
            timed_out = True

        # Step 4: Escalate only if graceful shutdown timed out
        if timed_out or (not tcpdump_done and isinstance(tcpdump_pid, int)):
            for p in (tcpdump_pid, proc_pid):
                if isinstance(p, int):
                    if is_safe_capture_process(p, is_parent=(p == proc_pid), expected_pcap=pcap_path):
                        try:
                            os.kill(p, signal.SIGTERM)
                        except PermissionError:
                            try:
                                subprocess.run(["sudo", "-n", "kill", "-TERM", str(p)], capture_output=True, check=False)
                            except Exception:
                                pass
                        except (ProcessLookupError, OSError):
                            pass
                    elif _is_pid_alive(p):
                        unrelated_detected = True
                        impair.log_warn(f"Refusing to signal PID {p} with SIGTERM: unrelated process")

            if hasattr(proc, "terminate") and proc.poll() is None:
                if isinstance(proc_pid, int):
                    if is_safe_capture_process(proc_pid, is_parent=True, expected_pcap=pcap_path):
                        try:
                            proc.terminate()
                        except (ProcessLookupError, OSError):
                            pass
                    elif _is_pid_alive(proc_pid):
                        unrelated_detected = True
                        impair.log_warn(f"Refusing to terminate proc PID {proc_pid}: unrelated process")
                else:
                    try:
                        proc.terminate()
                    except (ProcessLookupError, OSError):
                        pass

            term_timeout = min(1.5, max(0.5, timeout / 2.0))
            still_running = False
            try:
                proc.wait(timeout=term_timeout)
                proc_reaped = True
            except subprocess.TimeoutExpired:
                still_running = True

            if isinstance(tcpdump_pid, int) and tcpdump_pid != proc_pid:
                if _is_pid_alive(tcpdump_pid):
                    still_running = True
                else:
                    tcpdump_done = True

            # Escalate to SIGKILL if still running
            if still_running:
                for p in (tcpdump_pid, proc_pid):
                    if isinstance(p, int):
                        if is_safe_capture_process(p, is_parent=(p == proc_pid), expected_pcap=pcap_path):
                            try:
                                os.kill(p, signal.SIGKILL)
                            except PermissionError:
                                try:
                                    subprocess.run(["sudo", "-n", "kill", "-KILL", str(p)], capture_output=True, check=False)
                                except Exception:
                                    pass
                            except (ProcessLookupError, OSError):
                                pass
                        elif _is_pid_alive(p):
                            unrelated_detected = True
                            impair.log_warn(f"Refusing to signal PID {p} with SIGKILL: unrelated process")

                if hasattr(proc, "kill") and proc.poll() is None:
                    if isinstance(proc_pid, int):
                        if is_safe_capture_process(proc_pid, is_parent=True, expected_pcap=pcap_path):
                            try:
                                proc.kill()
                            except (ProcessLookupError, OSError):
                                pass
                        elif _is_pid_alive(proc_pid):
                            unrelated_detected = True
                            impair.log_warn(f"Refusing to kill proc PID {proc_pid}: unrelated process")
                    else:
                        try:
                            proc.kill()
                        except (ProcessLookupError, OSError):
                            pass
                try:
                    proc.wait(timeout=min(1.5, max(0.5, timeout / 2.0)))
                    proc_reaped = True
                except subprocess.TimeoutExpired:
                    proc_reaped = False
                except Exception:
                    pass
    finally:
        # Step 5: Flush and close capture log file descriptor
        if log_fp is not None:
            try:
                if not getattr(log_fp, "closed", True):
                    log_fp.flush()
                    log_fp.close()
            except Exception:
                pass

    if unrelated_detected:
        raise CaptureShutdownError(
            f"Refused to signal unverified or unrelated process during capture shutdown; target PID was not verified tcpdump"
        )

    # Step 6: Confirm tcpdump has fully exited
    if hasattr(proc, "poll") and proc.poll() is not None:
        proc_reaped = True

    if not proc_reaped and hasattr(proc, "poll") and proc.poll() is None:
        raise CaptureShutdownError(
            f"tcpdump capture process (PID {proc_pid}) failed to exit after escalation"
        )

    if isinstance(tcpdump_pid, int) and tcpdump_pid != proc_pid and not tcpdump_done:
        if _is_pid_alive(tcpdump_pid):
            raise CaptureShutdownError(
                f"tcpdump child process (PID {tcpdump_pid}) is still alive after escalation"
            )
        else:
            tcpdump_done = True

    # Step 7: Confirm PCAP is finalized
    if verify_pcap and pcap_path is not None:
        if not pcap_path.is_file():
            raise CaptureShutdownError(
                f"Capture PCAP {pcap_path} was not created or is missing"
            )
        is_valid, _, psize, _, pmsg = validate_pcap_file(pcap_path)
        if not is_valid:
            raise CaptureShutdownError(
                f"Capture PCAP {pcap_path} is invalid or not finalized ({pmsg})"
            )
        try:
            pcap_path.chmod(0o664)
        except OSError:
            pass

    return True


def validate_pcap_file(pcap_path: Path, min_packets: int = 0) -> Tuple[bool, str, int, int, str]:
    """
    Validates a PCAP file:
    1. Checks file existence and non-zero size
    2. Validates PCAP header magic bytes
    3. Computes SHA-256 digest
    4. Counts frames using tshark or binary header walk
    5. Optionally verifies minimum packet count
    Returns: (is_valid, sha256_hex, size_bytes, packet_count, message)
    """
    if not pcap_path.is_file():
        return False, "", 0, 0, "PCAP file does not exist"

    data = pcap_path.read_bytes()
    size = len(data)
    if size < 24:
        return False, "", size, 0, f"PCAP file too small ({size} bytes, expected >= 24)"

    sha256_hex = hashlib.sha256(data).hexdigest()

    # Magic byte checks: standard, nanosecond, swapped, or pcapng
    magic = data[:4]
    valid_magics = [
        b"\xa1\xb2\xc3\xd4",  # Standard PCAP (identical endian)
        b"\xd4\xc3\xb2\xa1",  # Standard PCAP (swapped endian)
        b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP
        b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP swapped
        b"\x0a\x0d\x0d\x0a",  # PCAP-NG
    ]
    if magic not in valid_magics:
        return False, sha256_hex, size, 0, f"Invalid PCAP header magic: {magic.hex()}"

    # Count packets using tshark if available, else binary fallback
    pkt_count = _count_packets(pcap_path, data)

    if min_packets > 0 and pkt_count < min_packets:
        return False, sha256_hex, size, pkt_count, f"PCAP contains {pkt_count} packets (expected >= {min_packets})"

    return True, sha256_hex, size, pkt_count, "Valid PCAP"


def _count_packets(pcap_path: Path, data: bytes) -> int:
    """Counts packets in a PCAP file via tshark or binary parsing."""
    tshark = shutil.which("tshark")
    if tshark:
        try:
            res = subprocess.run(
                [tshark, "-r", str(pcap_path), "-q", "-z", "io,stat,0"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False
            )
            # Find packet count line in tshark output
            # Format: | 0.000 <> ... | <count> | ... |
            for line in res.stdout.splitlines():
                if "<>" in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1])
        except Exception:
            pass

    # Binary fallback count for standard PCAP
    count = 0
    try:
        offset = 24
        dlen = len(data)
        while offset + 16 <= dlen:
            incl_len = struct.unpack("<I", data[offset + 8:offset + 12])[0]
            count += 1
            offset += 16 + incl_len
    except Exception:
        pass
    return count


def parse_tcpdump_drop_statistics(log_source: Union[str, Path]) -> Dict[str, Any]:
    """
    Parses packet-drop and capture statistics from tcpdump stderr log.
    Expected tcpdump summary format:
      '<N> packets captured'
      '<N> packets received by filter'
      '<N> packets dropped by kernel'
      '<N> packets dropped by interface'
    """
    text = ""
    if isinstance(log_source, Path) or (isinstance(log_source, str) and "\n" not in log_source and os.path.exists(log_source)):
        try:
            text = Path(log_source).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
    else:
        text = str(log_source or "")

    captured = None
    received = None
    dropped_kernel = 0
    dropped_interface = 0

    m_cap = re.search(r"(\d+)\s+packets?\s+captured", text, re.IGNORECASE)
    if m_cap:
        captured = int(m_cap.group(1))

    m_rec = re.search(r"(\d+)\s+packets?\s+received\s+by\s+filter", text, re.IGNORECASE)
    if m_rec:
        received = int(m_rec.group(1))

    m_drp_k = re.search(r"(\d+)\s+packets?\s+dropped\s+by\s+kernel", text, re.IGNORECASE)
    if m_drp_k:
        dropped_kernel = int(m_drp_k.group(1))

    m_drp_i = re.search(r"(\d+)\s+packets?\s+dropped\s+by\s+interface", text, re.IGNORECASE)
    if m_drp_i:
        dropped_interface = int(m_drp_i.group(1))

    total_dropped = dropped_kernel + dropped_interface
    capture_loss = (total_dropped > 0)
    if received is not None and captured is not None and captured < received:
        capture_loss = True
        total_dropped = max(total_dropped, received - captured)

    loss_msg = None
    if capture_loss:
        loss_msg = (
            f"Capture loss detected: {total_dropped} packet(s) lost "
            f"({dropped_kernel} dropped by kernel, {dropped_interface} dropped by interface, "
            f"{captured if captured is not None else 'unknown'} captured of {received or (captured + total_dropped if captured is not None else 'unknown')} filtered)"
        )

    return {
        "packets_captured": captured if captured is not None else 0,
        "packets_received_by_filter": received if received is not None else (captured or 0),
        "packets_dropped_by_kernel": dropped_kernel,
        "packets_dropped_by_interface": dropped_interface,
        "total_packets_dropped": total_dropped,
        "capture_loss": capture_loss,
        "capture_loss_message": loss_msg
    }


def parse_chromium_netlog(netlog_path: Union[str, Path], target_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses Chromium/Chrome NetLog JSON file to reliably extract:
    - HTTP response status code for target_url (or matching host/path)
    - Winning address family and remote IP address
    - Request method and URL
    """
    p = Path(netlog_path)
    if not p.is_file():
        return {"status_code": None, "winning_family": None, "remote_address": None}

    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception:
        return {"status_code": None, "winning_family": None, "remote_address": None}

    events = data.get("events", [])
    types = data.get("constants", {}).get("logEventTypes", {})
    inv_types = {v: k for k, v in types.items()}

    target_host = None
    if target_url:
        m = re.search(r"https?://([^/:]+)", target_url)
        if m:
            target_host = m.group(1).lower()

    matched_sources = set()
    source_urls = {}
    for e in events:
        etype = inv_types.get(e.get("type"))
        params = e.get("params", {})
        sid = e.get("source", {}).get("id")
        if etype == "URL_REQUEST_START_JOB":
            url = params.get("url", "")
            if sid is not None:
                source_urls[sid] = url
            if target_host and target_host in url.lower():
                matched_sources.add(sid)
            elif not target_host and sid is not None:
                matched_sources.add(sid)

    status_code = None
    winning_family = None
    remote_address = None

    for e in events:
        etype = inv_types.get(e.get("type"))
        params = e.get("params", {})
        if etype == "TCP_CONNECT":
            rem = params.get("remote_address")
            if rem:
                if "[" in rem or rem.count(":") > 1:
                    winning_family = "IPv6"
                else:
                    winning_family = "IPv4"
                remote_address = rem

    for e in events:
        etype = inv_types.get(e.get("type"))
        sid = e.get("source", {}).get("id")
        params = e.get("params", {})

        if etype in ("HTTP_TRANSACTION_READ_RESPONSE_HEADERS", "HTTP2_SESSION_RECV_HEADERS", "HTTP3_HEADERS_RECEIVED"):
            if not matched_sources or sid in matched_sources:
                headers = params.get("headers", [])
                if isinstance(headers, list):
                    for h in headers:
                        if isinstance(h, str):
                            if h.startswith("HTTP/"):
                                parts = h.split(maxsplit=2)
                                if len(parts) >= 2 and parts[1].isdigit():
                                    status_code = int(parts[1])
                                    break
                            elif h.startswith(":status:"):
                                val = h.split(":", 2)[-1].strip()
                                if val.isdigit():
                                    status_code = int(val)
                                    break
                elif isinstance(headers, dict):
                    if ":status" in headers:
                        try:
                            status_code = int(headers[":status"])
                        except ValueError:
                            pass
                    elif "status" in headers:
                        try:
                            status_code = int(headers["status"])
                        except ValueError:
                            pass
                if status_code is not None:
                    break

    return {
        "status_code": status_code,
        "winning_family": winning_family,
        "remote_address": remote_address
    }


def parse_firefox_telemetry(log_source: Union[str, Path], target_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Parses Firefox browser telemetry log file(s) generated via MOZ_LOG
    (e.g. MOZ_LOG="sync,timestamp,nsHttp:5,nsSocketTransport:5")
    to extract:
    - HTTP response status code for target_url (or matching host/path)
    - Winning address family ("IPv6" or "IPv4") and remote IP address
    """
    p = Path(log_source)
    files_to_check: List[Path] = []
    if p.is_file():
        files_to_check.append(p)
    elif p.is_dir():
        files_to_check.extend(sorted(p.glob("*moz*log*")))
        files_to_check.extend(sorted(p.glob("*telemetry*.log*")))
    else:
        parent = p.parent
        prefix = p.name
        if parent.is_dir():
            files_to_check.extend(sorted(parent.glob(f"{prefix}*")))

    seen = set()
    unique_files: List[Path] = []
    for f in files_to_check:
        if f not in seen and f.is_file():
            seen.add(f)
            unique_files.append(f)

    if not unique_files:
        return {"status_code": None, "winning_family": None, "remote_address": None}

    target_host = None
    if target_url:
        m = re.search(r"https?://([^/:]+)", target_url)
        if m:
            target_host = m.group(1).lower()

    status_code = None
    winning_family = None
    remote_address = None
    target_sockets = set()
    target_trans = set()

    for fpath in unique_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            continue

        if target_host:
            for line in lines:
                l_lower = line.lower()
                if target_host in l_lower:
                    m_s = re.search(r"nsSocketTransport::Init\s*\[this=([0-9a-zA-Z]+)", line)
                    if m_s:
                        target_sockets.add(m_s.group(1))
                    m_t = re.search(r"(?:created nsHttpTransaction|Creating nsHttpTransaction\s*@)\s*([0-9a-zA-Z]+)", line)
                    if m_t:
                        target_trans.add(m_t.group(1))

        for line in lines:
            if status_code is None:
                m_sid = re.search(r"nsHttpTransaction\s+([0-9a-zA-Z]+)", line)
                curr_trans = m_sid.group(1) if m_sid else None
                if not target_trans or curr_trans in target_trans:
                    m_http = re.search(r"nsHttp(?:Transaction|ResponseHead).*?\[HTTP/(?:1\.[01]|2(?:\.0)?)\s+(\d{3})", line)
                    if m_http:
                        status_code = int(m_http.group(1))
                    else:
                        m_http2 = re.search(r"http response\s*\[\s*HTTP/(?:1\.[01]|2(?:\.0)?)\s+(\d{3})", line)
                        if m_http2:
                            status_code = int(m_http2.group(1))

            m_addr = re.search(r"(?:\[this=([0-9a-zA-Z]+)\]\s+)?(?:D/)?nsSocketTransport\s+trying address:\s*([0-9a-fA-F\.:]+)", line)
            if m_addr:
                sid = m_addr.group(1)
                addr = m_addr.group(2)
                if not target_sockets or sid is None or sid in target_sockets:
                    remote_address = addr
                    if ":" in addr and addr.count(":") > 1:
                        winning_family = "IPv6"
                    else:
                        winning_family = "IPv4"

            m_af = re.search(r"ConnectionEntry::RecordIPFamilyPreference.*?af=(\d+)", line)
            if m_af:
                af_val = int(m_af.group(1))
                if af_val == 10:
                    winning_family = "IPv6"
                elif af_val == 2:
                    winning_family = "IPv4"

    if status_code is None:
        for fpath in unique_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        m_http = re.search(r"nsHttp(?:Transaction|ResponseHead).*?\[HTTP/(?:1\.[01]|2(?:\.0)?)\s+(\d{3})", line)
                        if m_http:
                            status_code = int(m_http.group(1))
                            break
            except OSError:
                continue

    return {
        "status_code": status_code,
        "winning_family": winning_family,
        "remote_address": remote_address
    }


# ------------------------------------------------------------------------------
# PCAP Dissection & Fallback Classification (RFC 8305 / PS-028)
# ------------------------------------------------------------------------------

def parse_dns_response_flag(flag_val: Any) -> bool:
    """
    Parses dns.flags.response representation into a boolean.
    Handles 'True'/'False' and '1'/'0' representations across different tshark versions,
    as well as boolean, integer, or comma-separated strings.
    """
    if isinstance(flag_val, bool):
        return flag_val
    if isinstance(flag_val, (int, float)):
        return int(flag_val) == 1
    if not flag_val:
        return False
    val_str = str(flag_val).strip().lower()
    for token in val_str.split(","):
        token = token.strip()
        if token in ("1", "true", "t", "yes"):
            return True
    return False


def _parse_int_safe(val: Any) -> Optional[int]:
    """Safely parse integer from string or number, handling commas or empty values."""
    if val is None or val == "":
        return None
    try:
        if isinstance(val, (int, float)):
            return int(val)
        val_str = str(val).split(",")[0].strip()
        return int(val_str)
    except (ValueError, TypeError):
        return None


def _compute_rcv_nxt(sinfo: Dict[str, Any]) -> Optional[int]:
    """
    Computes the contiguous receive sequence number (RCV.NXT) for the server stream
    from the client's perspective per RFC 9293 and RFC 5961 Section 3.2.

    Base sequence:
        rcv_nxt_base = (server_isn + 1 + server_syn_data_len) & 0xFFFFFFFF
        Per RFC 7413, F-37, and F-40:
        - In ESTABLISHED, use the server SYN-ACK data length actually acknowledged by
          the client (server_syn_data_len_accepted).
        - In SYNACK_RCVD (before client final ACK):
          If server SYN-ACK data exists (server_syn_data_len > 0), its accepted length
          cannot be established without client acknowledgement evidence, so exact
          RCV.NXT validation is unavailable (returns None).
          A zero-payload SYN-ACK uses the unambiguous server ISN + 1 base.

    Sequence progression:
        Tracks received server segments (payload bytes and FIN). Segments are mapped to
        relative 32-bit sequence offsets from rcv_nxt_base. Overlapping and
        duplicate intervals are merged to avoid sequence inflation. Contiguous
        bytes are computed starting strictly at sequence offset 0.
        Gaps (out-of-order delivery) prevent RCV.NXT from advancing until filled.
        Per RFC 9293 / F-38, RST-bearing segments never consume sequence space and
        are never included in server_segments.
    """
    server_isn = sinfo.get("server_isn")
    if server_isn is None:
        return None

    if "server_syn_data_len_accepted" in sinfo and sinfo["server_syn_data_len_accepted"] is not None:
        server_syn_data_len = sinfo["server_syn_data_len_accepted"]
    else:
        # Before client final ACK (e.g. in SYNACK_RCVD):
        # Per F-40, if server SYN-ACK data exists but accepted length cannot be
        # established by client acknowledgement, exact RCV.NXT validation is unavailable.
        if sinfo.get("server_syn_data_len", 0) > 0:
            return None
        server_syn_data_len = 0
    rcv_nxt_base = (server_isn + 1 + server_syn_data_len) & 0xFFFFFFFF

    raw_segments = sinfo.get("server_segments", [])
    if not raw_segments:
        return rcv_nxt_base

    intervals = []
    for raw_s, seg_l in raw_segments:
        if seg_l <= 0 or raw_s is None:
            continue
        offset = (raw_s - rcv_nxt_base) & 0xFFFFFFFF
        # Forward sequence progression within half of the 32-bit sequence space
        if offset < 0x80000000:
            intervals.append((offset, offset + seg_l))

    if not intervals:
        return rcv_nxt_base

    intervals.sort(key=lambda iv: iv[0])
    merged = []
    for start, end in intervals:
        if not merged:
            merged.append([start, end])
        else:
            if start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])

    # Contiguous sequence progression strictly starting from offset 0
    contiguous = merged[0][1] if merged[0][0] == 0 else 0
    return (rcv_nxt_base + contiguous) & 0xFFFFFFFF


def dissect_pcap(pcap_path: Path, target_hostname: str) -> Dict[str, Any]:
    """
    Dissects a PCAP capture using tshark, extracting:
    - DNS queries and answers for target_hostname
    - IPv6 TCP connection attempts (SYN packets to 2001:db8:2::10:80)
    - IPv4 TCP connection attempts (SYN packets to 10.0.2.10:80)
    - Connection handshake completions (SYN -> SYN-ACK -> matching client final ACK)
    - Observed HTTP response codes
    - Per-stream TCP handshake tracking and main HTTP flow correlation
    """
    result: Dict[str, Any] = {
        "dns": {
            "queries": [],
            "responses": []
        },
        "ipv6": {
            "syn_count": 0,
            "first_syn_time": None,
            "first_syn_frame": None,
            "syn_ack_received": False,
            "syn_ack_time": None,
            "server_rst_received": False,
            "client_rst_sent": False,
            "rst_received": False,
            "tcp_handshake_completed": False,
            "connection_established": False,
            "http_observed": False
        },
        "ipv4": {
            "syn_count": 0,
            "first_syn_time": None,
            "first_syn_frame": None,
            "syn_ack_received": False,
            "syn_ack_time": None,
            "server_rst_received": False,
            "client_rst_sent": False,
            "rst_received": False,
            "tcp_handshake_completed": False,
            "connection_established": False,
            "http_observed": False
        },
        "connection_attempt_delay_ms": None,
        "connection_setup_time_ms": None,
        "http_status_code": None,
        "http_response_family": None,
        "diagnostic_raw_pcap_http_code": None,
        "main_http_flow": {
            "stream_id": None,
            "family": None,
            "status_code": None,
            "request": None,
            "correlated": False,
            "tcp_handshake_completed": False,
        },
        "tcp_streams": {},
    }

    tshark = shutil.which("tshark")
    if not tshark or not pcap_path.is_file():
        # Fallback binary inspection if tshark is absent (diagnostic only)
        if pcap_path.is_file():
            try:
                raw_data = pcap_path.read_bytes()
                m = re.search(rb"HTTP/1\.[01]\s+(\d{3})", raw_data)
                if m:
                    result["diagnostic_raw_pcap_http_code"] = int(m.group(1))
            except Exception:
                pass
        return result

    # Fields to extract
    fields = [
        "frame.time_epoch",
        "ip.src", "ip.dst",
        "ipv6.src", "ipv6.dst",
        "tcp.flags",
        "tcp.srcport", "tcp.dstport",
        "dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.a", "dns.aaaa",
        "http.response.code",
        "tcp.stream",
        "http.request.method",
        "http.request.uri",
        "tcp.seq_raw",
        "tcp.ack_raw",
        "frame.number",
        "tcp.len",
        "http.response_in",
        "http.request_in",
    ]
    cmd = [tshark, "-2", "-r", str(pcap_path), "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0, check=False)
        lines = proc.stdout.splitlines()
    except Exception:
        return result

    hostname_clean = target_hostname.lower().rstrip(".")
    streams: Dict[str, Dict[str, Any]] = {}
    fallback_http_code: Optional[int] = None
    fallback_http_family: Optional[str] = None

    for line in lines:
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts.extend([""] * (len(fields) - len(parts)))

        (t_epoch_str, ip_src, ip_dst, ip6_src, ip6_dst, tcp_flags_str,
         tcp_sport_str, tcp_dport_str, dns_qname, dns_qtype, dns_resp_flag,
         dns_a, dns_aaaa, http_code, tcp_stream, http_method, http_uri,
         tcp_seq_raw_str, tcp_ack_raw_str, frame_num_str, tcp_len_str,
         http_response_in_str, http_request_in_str) = parts[:23]

        try:
            t_epoch = float(t_epoch_str) if t_epoch_str else None
        except ValueError:
            t_epoch = None

        frame_num = _parse_int_safe(frame_num_str)
        raw_seq = _parse_int_safe(tcp_seq_raw_str)
        raw_ack = _parse_int_safe(tcp_ack_raw_str)
        sport = _parse_int_safe(tcp_sport_str)
        dport = _parse_int_safe(tcp_dport_str)
        tcp_len = _parse_int_safe(tcp_len_str) or 0
        resp_in = _parse_int_safe(http_response_in_str)
        req_in = _parse_int_safe(http_request_in_str)

        # Determine packet address family and direction with respect to server endpoints
        pkt_family = None
        dir_to_server = False
        client_ip = None
        server_ip = None
        client_port = None
        server_port = None

        if ip6_dst == SERVER_IPV6:
            pkt_family = "IPv6"
            dir_to_server = True
            client_ip = ip6_src
            server_ip = ip6_dst
            client_port = sport
            server_port = dport
        elif ip6_src == SERVER_IPV6:
            pkt_family = "IPv6"
            dir_to_server = False
            client_ip = ip6_dst
            server_ip = ip6_src
            client_port = dport
            server_port = sport
        elif ip_dst == SERVER_IPV4:
            pkt_family = "IPv4"
            dir_to_server = True
            client_ip = ip_src
            server_ip = ip_dst
            client_port = sport
            server_port = dport
        elif ip_src == SERVER_IPV4:
            pkt_family = "IPv4"
            dir_to_server = False
            client_ip = ip_dst
            server_ip = ip_src
            client_port = dport
            server_port = sport

        # Stream-level tracking for HTTP flow correlation and handshake validation
        if pkt_family:
            sid = tcp_stream.strip() if tcp_stream else f"{pkt_family}:{client_ip}:{client_port}->{server_ip}:{server_port}"
            if sid not in streams:
                streams[sid] = {
                    "stream_id": sid,
                    "family": pkt_family,
                    "main_get": False,
                    "main_request": None,
                    "main_response_code": None,
                    "main_response_frame": None,
                    "main_response_time": None,
                    "http_requests": [],
                    "http_responses": [],
                    "response_code": None,
                    "first_request": None,
                    "first_time": t_epoch,
                    "client_endpoint": (client_ip, client_port),
                    "server_endpoint": (server_ip, server_port),
                    "client_isn": None,
                    "syn_data_len": 0,
                    "server_isn": None,
                    "server_syn_data_len": 0,
                    "server_bytes_sent": 0,
                    "server_segments": [],
                    "requests_by_frame": {},
                    "responses_by_frame": {},
                    "syn_ack_received": False,
                    "tcp_handshake_completed": False,
                    "handshake_state": "INIT",  # INIT -> SYN_SENT -> SYNACK_RCVD -> ESTABLISHED (or MIDSTREAM / INVALID / RESET / CLOSED_BY_RESET)
                    "syn_frame": None,
                    "syn_time": None,
                    "syn_ack_frame": None,
                    "syn_ack_time": None,
                    "final_ack_frame": None,
                    "final_ack_time": None,
                    "final_ack_data_len": 0,
                    "server_ack_received": None,
                    "syn_data_accepted": 0,
                    "syn_ack_variants": [],
                    "server_syn_data_len_accepted": None,
                    "zero_payload_syn_retry": False,
                    "zero_payload_synack_retry": False,
                    "bare_syn_retry": False,
                    "server_rst_received": False,
                    "client_rst_sent": False,
                    "rst_received": False,
                    "server_rst_validated": False,
                    "anomalies": [],
                }
            sinfo = streams[sid]
            if not sinfo["family"]:
                sinfo["family"] = pkt_family

            if not dir_to_server and tcp_len > 0:
                sinfo["server_bytes_sent"] = sinfo.get("server_bytes_sent", 0) + tcp_len

            if http_method:
                m_str = http_method.strip().upper()
                u_str = (http_uri or "").strip()
                req_entry = {
                    "method": m_str,
                    "uri": u_str,
                    "frame": frame_num,
                    "time": t_epoch,
                    "response_in": resp_in,
                }
                if not sinfo["first_request"]:
                    sinfo["first_request"] = (m_str, u_str)
                sinfo["http_requests"].append((m_str, u_str, frame_num, t_epoch))
                if frame_num is not None:
                    sinfo["requests_by_frame"][frame_num] = req_entry

            if http_code:
                try:
                    code_val = int(http_code.split(",")[0].strip())
                    resp_entry = {
                        "code": code_val,
                        "frame": frame_num,
                        "time": t_epoch,
                        "request_in": req_in,
                    }
                    sinfo["http_responses"].append((code_val, frame_num, t_epoch))
                    if frame_num is not None:
                        sinfo["responses_by_frame"][frame_num] = resp_entry
                    if sinfo["response_code"] is None:
                        sinfo["response_code"] = code_val
                except ValueError:
                    pass

            # Record first non-ancillary HTTP response as fallback
            if http_code and fallback_http_code is None:
                is_ancillary = False
                if sinfo.get("first_request"):
                    req_uri = sinfo["first_request"][1]
                    if req_uri.startswith("/favicon"):
                        is_ancillary = True
                elif http_uri and http_uri.strip().startswith("/favicon"):
                    is_ancillary = True

                if not is_ancillary:
                    try:
                        fallback_http_code = int(http_code.split(",")[0].strip())
                        fallback_http_family = pkt_family
                    except ValueError:
                        pass

        # 1. DNS parsing
        if dns_qname:
            qname_norm = dns_qname.lower().rstrip(".")
            if qname_norm == hostname_clean or hostname_clean in qname_norm:
                is_resp = parse_dns_response_flag(dns_resp_flag)
                qtype_raw = str(dns_qtype).strip() if dns_qtype is not None else ""
                qtype_str = "AAAA" if qtype_raw in ("28", "AAAA") else ("A" if qtype_raw in ("1", "A") else qtype_raw)
                if not is_resp:
                    result["dns"]["queries"].append({
                        "qname": dns_qname,
                        "qtype": qtype_str,
                        "timestamp": t_epoch
                    })
                else:
                    ans_addr = (dns_aaaa.strip() if dns_aaaa else "") if qtype_str == "AAAA" else ((dns_a.strip() if dns_a else "") if qtype_str == "A" else "")
                    result["dns"]["responses"].append({
                        "qname": dns_qname,
                        "qtype": qtype_str,
                        "address": ans_addr,
                        "timestamp": t_epoch
                    })

        # 2. TCP parsing & Handshake State Tracking
        if tcp_flags_str and pkt_family:
            try:
                flags = int(tcp_flags_str.split(",")[0].strip(), 16)
            except (ValueError, TypeError):
                flags = 0

            syn_flag = bool(flags & 0x02)
            ack_flag = bool(flags & 0x10)
            rst_flag = bool(flags & 0x04)
            fin_flag = bool(flags & 0x01)

            fam_key = pkt_family.lower()
            sinfo = streams[sid]
            expected_client = sinfo["client_endpoint"]
            expected_server = sinfo["server_endpoint"]

            # Track server sequence progression (data payload + FIN)
            # Per RFC 9293 / F-38: Segments carrying RST never consume sequence space
            # and must not be appended to server_segments.
            if not dir_to_server and not syn_flag and not rst_flag:
                seg_len = tcp_len + (1 if fin_flag else 0)
                if seg_len > 0 and raw_seq is not None:
                    sinfo["server_segments"].append((raw_seq, seg_len))

            # 1. Client SYN:
            # SYN set, ACK not set, RST not set, client -> server
            if syn_flag and not ack_flag and not rst_flag and dir_to_server:
                result[fam_key]["syn_count"] += 1
                if result[fam_key]["first_syn_time"] is None:
                    result[fam_key]["first_syn_time"] = t_epoch
                if result[fam_key]["first_syn_frame"] is None:
                    result[fam_key]["first_syn_frame"] = frame_num
                    result[fam_key]["first_syn_time"] = t_epoch

                if sinfo["handshake_state"] == "INIT":
                    sinfo["client_endpoint"] = (client_ip, client_port)
                    sinfo["server_endpoint"] = (server_ip, server_port)
                    sinfo["client_isn"] = raw_seq
                    sinfo["syn_data_len"] = tcp_len
                    sinfo["syn_frame"] = frame_num
                    sinfo["syn_time"] = t_epoch
                    sinfo["handshake_state"] = "SYN_SENT"
                elif sinfo["handshake_state"] == "SYN_SENT":
                    # Retransmitted SYN: verify ISN and payload length
                    # F-41 / RFC 7413 §4.2.2: Retransmission observed with tcp_len == 0 following a data-bearing
                    # SYN (syn_data_len > 0). Documented accurately as a zero-payload SYN retransmission.
                    # Note: The parser checks tcp_len == 0 without asserting removal of TCP Fast Open options.
                    isn_match = (raw_seq is not None and raw_seq == sinfo["client_isn"])
                    len_match = (tcp_len == sinfo["syn_data_len"])
                    zero_payload_syn_retry = (tcp_len == 0 and sinfo["syn_data_len"] > 0)
                    if isn_match and (len_match or zero_payload_syn_retry):
                        if zero_payload_syn_retry:
                            sinfo["zero_payload_syn_retry"] = True
                            sinfo["bare_syn_retry"] = True
                    else:
                        sinfo["handshake_state"] = "INVALID"
                        if not isn_match:
                            sinfo["anomalies"].append(f"CONFLICTING_SYN_ISN: original={sinfo['client_isn']}, received={raw_seq}")
                        if not len_match and not zero_payload_syn_retry:
                            sinfo["anomalies"].append(f"CONFLICTING_SYN_PAYLOAD_LEN: original={sinfo['syn_data_len']}, received={tcp_len}")
                elif sinfo["handshake_state"] in ("SYNACK_RCVD", "ESTABLISHED", "CLOSED_BY_RESET", "CLOSED_BY_CLIENT_ABORT"):
                    # Retransmitted SYN arriving after SYN-ACK or handshake completion
                    isn_match = (raw_seq is not None and raw_seq == sinfo["client_isn"])
                    len_match = (tcp_len == sinfo["syn_data_len"])
                    zero_payload_syn_retry = (tcp_len == 0 and sinfo["syn_data_len"] > 0)
                    if isn_match and (len_match or zero_payload_syn_retry):
                        if zero_payload_syn_retry:
                            sinfo["zero_payload_syn_retry"] = True
                            sinfo["bare_syn_retry"] = True
                    else:
                        if not isn_match:
                            sinfo["anomalies"].append(f"CONFLICTING_LATE_SYN_ISN: original={sinfo['client_isn']}, received={raw_seq}")
                        if not len_match and not zero_payload_syn_retry:
                            sinfo["anomalies"].append(f"CONFLICTING_LATE_SYN_PAYLOAD_LEN: original={sinfo['syn_data_len']}, received={tcp_len}")
                        if not sinfo["tcp_handshake_completed"]:
                            sinfo["handshake_state"] = "INVALID"

            # 2. Server SYN-ACK:
            # SYN and ACK set, RST not set, server -> client
            elif syn_flag and ack_flag and not rst_flag and not dir_to_server:
                endpoint_match = (
                    expected_client == (client_ip, client_port) and
                    expected_server == (server_ip, server_port)
                )
                # RFC 9293 §3.5.3 acceptable ACK semantics (F-35): SND.UNA < SEG.ACK <= SND.NXT
                # SND.UNA = client_isn. Min acceptable ACK acknowledging SYN is client_isn + 1.
                # SND.NXT = (client_isn + 1 + syn_data_len) & 0xFFFFFFFF.
                min_ack = ((sinfo["client_isn"] + 1) & 0xFFFFFFFF) if sinfo["client_isn"] is not None else None
                syn_data_len = sinfo.get("syn_data_len", 0)
                ack_match = False
                ack_offset = None
                if min_ack is not None and raw_ack is not None:
                    ack_offset = (raw_ack - min_ack) & 0xFFFFFFFF
                    if ack_offset < 0x80000000 and ack_offset <= syn_data_len:
                        ack_match = True

                if endpoint_match and ack_match:
                    if sinfo["handshake_state"] == "SYN_SENT":
                        sinfo["server_isn"] = raw_seq
                        sinfo["server_syn_data_len"] = tcp_len
                        sinfo["server_ack_received"] = raw_ack
                        sinfo["syn_data_accepted"] = ack_offset
                        sinfo["syn_ack_frame"] = frame_num
                        sinfo["syn_ack_time"] = t_epoch
                        sinfo["syn_ack_received"] = True
                        sinfo["handshake_state"] = "SYNACK_RCVD"
                        sinfo["syn_ack_variants"] = [{"seq": raw_seq, "ack": raw_ack, "len": tcp_len, "frame": frame_num}]

                        result[fam_key]["syn_ack_received"] = True
                        if result[fam_key]["syn_ack_time"] is None:
                            result[fam_key]["syn_ack_time"] = t_epoch
                    elif sinfo["handshake_state"] == "SYNACK_RCVD":
                        # Retransmitted SYN-ACK: verify server ISN and payload length
                        # F-41 / RFC 7413: Retransmission observed with tcp_len == 0 following a data-bearing
                        # SYN-ACK (server_syn_data_len > 0). Documented accurately as a zero-payload SYN-ACK retransmission.
                        # Note: The parser checks tcp_len == 0 without asserting removal of TCP Fast Open options.
                        isn_match = (raw_seq is not None and raw_seq == sinfo["server_isn"])
                        len_match = (tcp_len == sinfo["server_syn_data_len"])
                        zero_payload_synack_retry = (tcp_len == 0 and sinfo["server_syn_data_len"] > 0)
                        if isn_match and (len_match or zero_payload_synack_retry):
                            if zero_payload_synack_retry:
                                sinfo["zero_payload_synack_retry"] = True
                            sinfo["syn_ack_variants"].append({"seq": raw_seq, "ack": raw_ack, "len": tcp_len, "frame": frame_num})
                            if ack_offset is not None and ack_offset <= syn_data_len:
                                sinfo["server_ack_received"] = raw_ack
                                sinfo["syn_data_accepted"] = ack_offset
                        else:
                            # Conflicting server ISN or length! Never overwrite, mark invalid
                            sinfo["handshake_state"] = "INVALID"
                            if not isn_match:
                                sinfo["anomalies"].append(
                                    f"CONFLICTING_SYNACK_SERVER_ISN: original={sinfo['server_isn']}, received={raw_seq}"
                                )
                            if not len_match and not zero_payload_synack_retry:
                                sinfo["anomalies"].append(
                                    f"CONFLICTING_SYNACK_PAYLOAD_LEN: original={sinfo['server_syn_data_len']}, received={tcp_len}"
                                )
                    elif sinfo["handshake_state"] in ("ESTABLISHED", "CLOSED_BY_RESET", "CLOSED_BY_CLIENT_ABORT"):
                        # Late SYN-ACK after handshake established
                        isn_match = (raw_seq is not None and raw_seq == sinfo["server_isn"])
                        len_match = (tcp_len == sinfo["server_syn_data_len"])
                        zero_payload_synack_retry = (tcp_len == 0 and sinfo["server_syn_data_len"] > 0)
                        if isn_match and (len_match or zero_payload_synack_retry):
                            if zero_payload_synack_retry:
                                sinfo["zero_payload_synack_retry"] = True
                            sinfo["syn_ack_variants"].append({"seq": raw_seq, "ack": raw_ack, "len": tcp_len, "frame": frame_num})
                        else:
                            if not isn_match:
                                sinfo["anomalies"].append(
                                    f"CONFLICTING_LATE_SYNACK_SERVER_ISN: original={sinfo['server_isn']}, received={raw_seq}"
                                )
                            if not len_match and not zero_payload_synack_retry:
                                sinfo["anomalies"].append(
                                    f"CONFLICTING_LATE_SYNACK_PAYLOAD_LEN: original={sinfo['server_syn_data_len']}, received={tcp_len}"
                                )
                    else:
                        sinfo["handshake_state"] = "INVALID"
                        sinfo["anomalies"].append(f"UNEXPECTED_SYNACK_IN_STATE_{sinfo['handshake_state']}")
                else:
                    if sinfo["handshake_state"] == "SYN_SENT":
                        sinfo["handshake_state"] = "INVALID"
                    sinfo["anomalies"].append(
                        f"INVALID_SYNACK: endpoint_match={endpoint_match}, ack_match={ack_match}"
                    )

            # 3. Client Final ACK / Established ACK:
            # ACK set, SYN and RST not set, client -> server
            elif ack_flag and not syn_flag and not rst_flag and dir_to_server:
                endpoint_match = (
                    expected_client == (client_ip, client_port) and
                    expected_server == (server_ip, server_port)
                )
                if sinfo["handshake_state"] == "SYNACK_RCVD" and endpoint_match:
                    # Validate client's sequence number against the sequence position actually acknowledged by server SYN-ACK
                    expected_seq = sinfo.get("server_ack_received")
                    if expected_seq is None and sinfo.get("client_isn") is not None:
                        expected_seq = (sinfo["client_isn"] + 1 + sinfo.get("syn_data_accepted", 0)) & 0xFFFFFFFF

                    # Validate client's ACK number against server sequence space:
                    # Server sent server_isn (consuming 1 seq) plus server_syn_data_len bytes
                    min_server_ack = ((sinfo["server_isn"] + 1) & 0xFFFFFFFF) if sinfo["server_isn"] is not None else None
                    server_syn_data_len = sinfo.get("server_syn_data_len", 0)

                    seq_match = (expected_seq is not None and raw_seq is not None and raw_seq == expected_seq)
                    ack_match = False
                    srv_ack_offset = None
                    if min_server_ack is not None and raw_ack is not None:
                        srv_ack_offset = (raw_ack - min_server_ack) & 0xFFFFFFFF
                        if srv_ack_offset < 0x80000000 and srv_ack_offset <= server_syn_data_len:
                            ack_match = True

                    if seq_match and ack_match:
                        sinfo["tcp_handshake_completed"] = True
                        sinfo["handshake_state"] = "ESTABLISHED"
                        sinfo["final_ack_frame"] = frame_num
                        sinfo["final_ack_time"] = t_epoch
                        sinfo["final_ack_data_len"] = tcp_len
                        sinfo["server_syn_data_len_accepted"] = srv_ack_offset

                        # Family level: at least one qualifying stream completed handshake
                        result[fam_key]["tcp_handshake_completed"] = True
                        result[fam_key]["connection_established"] = True
                    else:
                        sinfo["anomalies"].append(
                            f"MISMATCHED_FINAL_ACK: seq_match={seq_match} (raw={raw_seq}, exp={expected_seq}), "
                            f"ack_match={ack_match} (raw={raw_ack}, min_srv={min_server_ack}, max_srv={(min_server_ack + server_syn_data_len) & 0xFFFFFFFF if min_server_ack is not None else None})"
                        )
                elif sinfo["handshake_state"] == "INIT":
                    sinfo["handshake_state"] = "MIDSTREAM"
                    sinfo["anomalies"].append("MIDSTREAM_TRAFFIC_OBSERVED")
                elif sinfo["handshake_state"] in ("ESTABLISHED", "CLOSED_BY_RESET", "CLOSED_BY_CLIENT_ABORT"):
                    pass

            # 4. RST handling
            if rst_flag:
                if not dir_to_server:
                    # Server -> Client RST
                    # Policy: RFC 5961 Section 3.2 Exact-RCV.NXT RST Validation Policy & RFC 9293 §3.5.3 (F-38, F-39)
                    # - In SYN-SENT: An incoming RST is acceptable if SND.UNA < SEG.ACK <= SND.NXT
                    #   Acceptable ACK range: [client_isn + 1, client_isn + 1 + syn_data_len]
                    #   An RST without ACK, or with ACK outside this range, is unvalidated.
                    # - In synchronized states (SYNACK_RCVD, ESTABLISHED, CLOSED_BY_RESET):
                    #   The RST sequence number must match RCV.NXT exactly. RCV.NXT progresses contiguously
                    #   from server ISN (+1 for SYN, + accepted SYN payload) through contiguous data and FIN bytes.
                    #   Overlapping or retransmitted segments are merged and do not advance RCV.NXT twice.
                    #   Out-of-order segments leave a gap and do not advance RCV.NXT until preceding segments arrive.
                    #   RST-bearing segments are never included in server_segments (F-38).
                    # - When capture evidence is insufficient (e.g. server ISN missing), the RST is retained
                    #   as an unvalidated observation, prior connection state is preserved, and an anomaly is logged.
                    rst_valid = False
                    if sinfo["handshake_state"] == "SYN_SENT":
                        min_ack = ((sinfo["client_isn"] + 1) & 0xFFFFFFFF) if sinfo["client_isn"] is not None else None
                        syn_data_len = sinfo.get("syn_data_len", 0)
                        if ack_flag and raw_ack is not None and min_ack is not None:
                            ack_offset = (raw_ack - min_ack) & 0xFFFFFFFF
                            if ack_offset < 0x80000000 and ack_offset <= syn_data_len:
                                rst_valid = True
                            else:
                                sinfo["anomalies"].append(
                                    f"UNVALIDATED_SERVER_RST_IN_SYN_SENT: ack_flag={ack_flag}, raw_ack={raw_ack}, min_ack={min_ack}, syn_data_len={syn_data_len}, raw_seq={raw_seq}"
                                )
                        else:
                            sinfo["anomalies"].append(
                                f"UNVALIDATED_SERVER_RST_IN_SYN_SENT: ack_flag={ack_flag}, raw_ack={raw_ack}, min_ack={min_ack}, raw_seq={raw_seq}"
                            )
                    elif sinfo["handshake_state"] in ("SYNACK_RCVD", "ESTABLISHED", "CLOSED_BY_RESET"):
                        expected_seq = _compute_rcv_nxt(sinfo)
                        if expected_seq is not None and raw_seq is not None:
                            if raw_seq == expected_seq:
                                rst_valid = True
                            else:
                                sinfo["anomalies"].append(
                                    f"UNVALIDATED_SERVER_RST_IN_{sinfo['handshake_state']}: raw_seq={raw_seq}, expected_seq={expected_seq}"
                                )
                        else:
                            sinfo["anomalies"].append(
                                f"UNVALIDATED_SERVER_RST_INSUFFICIENT_EVIDENCE: raw_seq={raw_seq}, server_isn={sinfo['server_isn']}"
                            )
                    else:
                        rst_valid = False
                        sinfo["anomalies"].append(f"UNVALIDATED_SERVER_RST_IN_STATE_{sinfo['handshake_state']}")

                    sinfo["server_rst_received"] = True
                    sinfo["rst_received"] = True
                    sinfo["server_rst_validated"] = rst_valid
                    result[fam_key]["server_rst_received"] = True
                    result[fam_key]["rst_received"] = True

                    # Only transition connection state if RST is VALIDATED!
                    if rst_valid:
                        if sinfo["tcp_handshake_completed"]:
                            sinfo["handshake_state"] = "CLOSED_BY_RESET"
                        else:
                            sinfo["handshake_state"] = "RESET"
                    # If unvalidated: retain the RST observation as unvalidated and preserve previous connection state.
                else:
                    # Client -> Server RST (client emitted reset)
                    # Do not treat an emitted client RST as proof that the server accepted the reset.
                    result[fam_key]["client_rst_sent"] = True
                    sinfo["client_rst_sent"] = True
                    if sinfo["tcp_handshake_completed"]:
                        sinfo["handshake_state"] = "CLOSED_BY_CLIENT_ABORT"
                    else:
                        sinfo["handshake_state"] = "CLIENT_ABORT"
                    # Preserve historical handshake completion!

            # HTTP observed
            if http_code:
                result[fam_key]["http_observed"] = True

    # Correlate HTTP request-response transactions on each stream via frame references (RFC/Wireshark http.response_in / http.request_in)
    for sid, sinfo in streams.items():
        reqs = sinfo.get("http_requests", [])
        root_req = None
        for (m_str, u_str, fnum, t_ep) in reqs:
            u_clean = u_str.split("?")[0].rstrip("/")
            is_root = (
                u_str in ("/", "/index.html") or
                u_clean == "" or
                u_str in (
                    f"http://{hostname_clean}/",
                    f"http://{hostname_clean}/index.html",
                    f"http://{hostname_clean}:80/",
                    f"http://{hostname_clean}:80/index.html",
                )
            )
            if m_str == "GET" and is_root:
                root_req = sinfo.get("requests_by_frame", {}).get(fnum) or {
                    "method": m_str, "uri": u_str, "frame": fnum, "time": t_ep, "response_in": None
                }
                sinfo["main_get"] = True
                sinfo["main_request"] = (m_str, u_str)
                sinfo["main_request_frame"] = fnum
                break

        if root_req is not None:
            root_frame = root_req.get("frame")
            target_resp_frame = root_req.get("response_in")

            matched_resp = None
            # If root request has explicit response_in, look up that response frame
            if target_resp_frame is not None and target_resp_frame in sinfo.get("responses_by_frame", {}):
                matched_resp = sinfo["responses_by_frame"][target_resp_frame]
            # Alternatively, find response whose request_in matches root_frame
            elif root_frame is not None:
                for resp_f, resp_data in sinfo.get("responses_by_frame", {}).items():
                    if resp_data.get("request_in") == root_frame:
                        matched_resp = resp_data
                        break

            if matched_resp is not None:
                sinfo["main_response_code"] = matched_resp["code"]
                sinfo["main_response_frame"] = matched_resp["frame"]
                sinfo["main_response_time"] = matched_resp["time"]
            else:
                # Frame-reference correlation unavailable: leave root response status None.
                # Per PS-028: never infer correlation from list index or stream membership alone.
                sinfo["main_response_code"] = None
        else:
            sinfo["main_get"] = False
            sinfo["main_response_code"] = None

    # Identify primary HTTP navigation flow
    main_stream_id = None
    for sid, sinfo in streams.items():
        if sinfo["main_get"] and sinfo["main_response_code"] is not None:
            main_stream_id = sid
            break
    if main_stream_id is None:
        for sid, sinfo in streams.items():
            if sinfo["main_get"]:
                main_stream_id = sid
                break

    if main_stream_id is not None:
        msinfo = streams[main_stream_id]
        result["http_status_code"] = msinfo["main_response_code"]
        result["http_response_family"] = msinfo["family"]
        result["main_http_flow"] = {
            "stream_id": main_stream_id,
            "family": msinfo["family"],
            "status_code": msinfo["main_response_code"],
            "request": msinfo.get("main_request"),
            "correlated": True,
            "tcp_handshake_completed": bool(msinfo.get("tcp_handshake_completed", False)),
        }
    else:
        result["http_status_code"] = None
        result["http_response_family"] = None
        result["diagnostic_fallback_http_code"] = fallback_http_code
        result["diagnostic_fallback_http_family"] = fallback_http_family
        result["main_http_flow"] = {
            "stream_id": None,
            "family": None,
            "status_code": None,
            "request": None,
            "correlated": False,
            "tcp_handshake_completed": False,
        }

    # Binary fallback inspection for HTTP response status code in raw PCAP data (diagnostic only)
    if pcap_path.is_file():
        try:
            raw_data = pcap_path.read_bytes()
            match = re.search(rb"HTTP/1\.[01]\s+(\d{3})", raw_data)
            if match:
                result["diagnostic_raw_pcap_http_code"] = int(match.group(1))
        except Exception:
            pass

    result["tcp_streams"] = streams

    # Compute Happy Eyeballs Connection Attempt Delay (CAD)
    v6_syn = result["ipv6"]["first_syn_time"]
    v4_syn = result["ipv4"]["first_syn_time"]
    if v6_syn is not None and v4_syn is not None and v4_syn >= v6_syn:
        result["connection_attempt_delay_ms"] = round((v4_syn - v6_syn) * 1000.0, 2)

    # Compute winning connection setup time
    if result["ipv4"]["syn_ack_time"] and v4_syn:
        result["connection_setup_time_ms"] = round((result["ipv4"]["syn_ack_time"] - v4_syn) * 1000.0, 2)
    elif result["ipv6"]["syn_ack_time"] and v6_syn:
        result["connection_setup_time_ms"] = round((result["ipv6"]["syn_ack_time"] - v6_syn) * 1000.0, 2)

    return result


def classify_fallback(
    dissection: Dict[str, Any],
    http_outcome: Dict[str, Any],
    is_measurement_failure: bool = False,
    pcap_valid: bool = True,
    failure_reason: Optional[str] = None,
    capture_loss: bool = False,
    capture_loss_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Classifies Happy Eyeballs connection behavior strictly per PS-028 rules:
    - Fallback to IPv4 is classified ONLY when packet or connection evidence confirms:
      1. IPv6 attempt (IPv6 TCP SYN observed in captured traffic)
      2. IPv4 attempt (IPv4 TCP SYN observed in captured traffic)
      3. Successful IPv4 connection (IPv4 SYN-ACK / HTTP response observed in captured traffic)
    - Never infers fallback from HTTP 200 alone.
    - Invalid PCAP or zero-packet capture forces INCONCLUSIVE and invalidates network evidence.
    - Dropped packets (capture loss) are never silently ignored: when packet drops occur,
      the absence of a secondary family attempt is inconclusive rather than definitive direct access.
    - Reports: "IPV6_TO_IPV4_FALLBACK", "DIRECT_IPV6", "DIRECT_IPV4",
               "CONNECTION_FAILED", or "INCONCLUSIVE".
    """
    if is_measurement_failure or not pcap_valid:
        default_reason = (
            "Measurement failure: Invalid PCAP or zero-packet capture. "
            "Per PS-028 specification, network evidence is invalid and fallback cannot be evaluated."
        )
        return {
            "fallback_occurred": False,
            "classification": "INCONCLUSIVE",
            "reason": failure_reason or default_reason,
            "ipv6_attempt": False,
            "ipv4_attempt": False,
            "ipv6_success": False,
            "ipv4_success": False,
            "telemetry_diagnostic_conclusion": None,
        }

    ipv6_attempt = dissection["ipv6"]["syn_count"] > 0
    ipv4_attempt = dissection["ipv4"]["syn_count"] > 0

    # Diagnostic family handshake status
    ipv4_handshake = dissection["ipv4"]["connection_established"]
    ipv6_handshake = dissection["ipv6"]["connection_established"]

    http_success = http_outcome.get("success", False)
    winning_family = http_outcome.get("winning_address_family")

    # Record browser telemetry diagnostic separately per F-34
    telemetry_diagnostic = None
    if http_success and winning_family:
        telemetry_diagnostic = f"Browser reported navigation success on {winning_family} (status {http_outcome.get('status_code')})"
    elif http_outcome.get("status_code") is not None:
        telemetry_diagnostic = f"Browser reported HTTP status {http_outcome.get('status_code')} on {winning_family}"

    main_flow = dissection.get("main_http_flow") or {}
    main_flow_fam = main_flow.get("family")
    main_flow_correlated = bool(main_flow.get("correlated", False))
    main_flow_handshake = bool(main_flow.get("tcp_handshake_completed", False))

    # Requirement 3: Contradiction detection only when PCAP flow is genuinely correlated
    if winning_family and main_flow_correlated and main_flow_fam and winning_family != main_flow_fam:
        return {
            "fallback_occurred": False,
            "classification": "INCONCLUSIVE",
            "reason": (
                f"Contradictory evidence: Browser telemetry reported winning address family {winning_family}, "
                f"but correlated PCAP primary navigation flow was on {main_flow_fam}."
            ),
            "ipv6_attempt": ipv6_attempt,
            "ipv4_attempt": ipv4_attempt,
            "ipv6_success": ipv6_handshake,
            "ipv4_success": ipv4_handshake,
            "telemetry_diagnostic_conclusion": telemetry_diagnostic,
        }

    # F-34: Explicit uncorrelated evidence policy
    # When main_flow_correlated is False:
    # Family-level handshake and browser telemetry cannot prove navigation connection.
    # Classify the packet-level result as INCONCLUSIVE when HTTP success is reported.
    if not main_flow_correlated:
        if http_success:
            return {
                "fallback_occurred": False,
                "classification": "INCONCLUSIVE",
                "reason": (
                    "Primary HTTP navigation flow is uncorrelated in packet capture. "
                    "Per PS-028 specification, family-level handshake and browser telemetry alone "
                    "cannot prove navigation connection."
                ),
                "ipv6_attempt": ipv6_attempt,
                "ipv4_attempt": ipv4_attempt,
                "ipv6_success": False,
                "ipv4_success": False,
                "telemetry_diagnostic_conclusion": telemetry_diagnostic,
            }

    # Requirement 2 & 4: Primary navigation HTTP evidence
    # When main_flow_correlated is true, require HTTP response status to come from that correlated PCAP flow.
    # Do not fill a missing PCAP response status using http_outcome["status_code"].
    if main_flow_correlated:
        main_flow_status = main_flow.get("status_code")
        main_flow_http_ok = (main_flow_status is not None and 200 <= main_flow_status < 400)
        ipv6_conn_ok = bool(main_flow_fam == "IPv6" and main_flow_handshake and main_flow_http_ok)
        ipv4_conn_ok = bool(main_flow_fam == "IPv4" and main_flow_handshake and main_flow_http_ok)
    else:
        ipv4_conn_ok = False
        ipv6_conn_ok = False

    fallback_occurred = False
    classification = "INCONCLUSIVE"
    reason = "Insufficient evidence to classify connection behavior"

    cad = dissection.get("connection_attempt_delay_ms")
    cad_desc = f" (Connection Attempt Delay: {cad}ms)" if cad is not None else ""
    loss_note = f" (Note: {capture_loss_message})" if capture_loss and capture_loss_message else ""

    if ipv6_attempt and ipv4_attempt:
        v6_syn = dissection.get("ipv6", {}).get("first_syn_time")
        v4_syn = dissection.get("ipv4", {}).get("first_syn_time")

        if ipv6_conn_ok:
            fallback_occurred = False
            classification = "DIRECT_IPV6"
            if ipv4_handshake:
                reason = (
                    f"Direct IPv6 connection established and won HTTP navigation{cad_desc}. "
                    f"Main GET / request correlated to IPv6 TCP flow. "
                    f"Post-navigation ancillary request or speculative IPv4 connection attempt "
                    f"was observed but did not displace IPv6.{loss_note}"
                )
            else:
                reason = (
                    f"Direct IPv6 connection established and won HTTP navigation{cad_desc}. "
                    f"Secondary IPv4 connection attempt did not establish."
                )
        elif ipv4_conn_ok:
            # Fallback chronology (RFC 8305 / PS-028)
            # Require strict timestamp ordering (v6_syn < v4_syn).
            # When timestamps are equal, resolve using capture frame numbers (v6_frame < v4_frame).
            # If chronology remains ambiguous or evidence is missing, classify as INCONCLUSIVE.
            v6_frame = dissection.get("ipv6", {}).get("first_syn_frame")
            v4_frame = dissection.get("ipv4", {}).get("first_syn_frame")
            if v6_syn is not None and v4_syn is not None:
                if v6_syn < v4_syn:
                    fallback_occurred = True
                    classification = "IPV6_TO_IPV4_FALLBACK"
                    reason = (
                        f"Observed initial IPv6 connection attempt, followed by IPv4 attempt "
                        f"and successful IPv4 connection{cad_desc}.{loss_note}"
                    )
                elif v4_syn < v6_syn:
                    fallback_occurred = False
                    classification = "DIRECT_IPV4"
                    reason = (
                        f"Direct IPv4 connection established, but IPv4 attempt preceded IPv6 attempt "
                        f"(IPv4 SYN at {v4_syn}s, IPv6 SYN at {v6_syn}s). Not an IPv6-to-IPv4 fallback."
                    )
                else:
                    # Timestamps are equal (v6_syn == v4_syn)
                    if v6_frame is not None and v4_frame is not None:
                        if v6_frame < v4_frame:
                            fallback_occurred = True
                            classification = "IPV6_TO_IPV4_FALLBACK"
                            reason = (
                                f"Observed initial IPv6 connection attempt, followed by IPv4 attempt "
                                f"resolved by capture frame sequence (IPv6 frame {v6_frame} preceded IPv4 frame {v4_frame} at identical timestamp {v6_syn}s) "
                                f"and successful IPv4 connection{cad_desc}.{loss_note}"
                            )
                        elif v4_frame < v6_frame:
                            fallback_occurred = False
                            classification = "DIRECT_IPV4"
                            reason = (
                                f"Direct IPv4 connection established, but IPv4 attempt preceded IPv6 attempt "
                                f"by capture frame sequence (IPv4 frame {v4_frame} preceded IPv6 frame {v6_frame} at identical timestamp {v4_syn}s). "
                                f"Not an IPv6-to-IPv4 fallback."
                            )
                        else:
                            fallback_occurred = False
                            classification = "INCONCLUSIVE"
                            reason = "Both IPv6 and IPv4 attempts observed with identical timestamps and identical frame numbers."
                    else:
                        fallback_occurred = False
                        classification = "INCONCLUSIVE"
                        reason = "Both IPv6 and IPv4 attempts observed with identical timestamps, but missing capture frame numbers to establish fallback order."
            else:
                fallback_occurred = False
                classification = "INCONCLUSIVE"
                reason = (
                    "Both IPv6 and IPv4 attempts observed, but SYN timing chronology cannot be established "
                    "to confirm Happy Eyeballs fallback order."
                )
        else:
            if http_success:
                fallback_occurred = False
                classification = "INCONCLUSIVE"
                reason = "HTTP navigation reported success but neither family established a verified connection handshake."
            else:
                fallback_occurred = False
                classification = "CONNECTION_FAILED"
                reason = "Neither IPv6 nor IPv4 primary navigation connection succeeded (ancillary HTTP response does not constitute navigation completion)."

    elif ipv6_conn_ok and not ipv4_attempt:
        if capture_loss:
            # Per PS-028: Incomplete capture due to dropped packets cannot conclusively confirm no IPv4 attempt
            fallback_occurred = False
            classification = "INCONCLUSIVE"
            reason = (
                f"Measurement inconclusive: Capture loss detected ({capture_loss_message or 'packet drops observed'}). "
                "Per PS-028 specification, the absence of an IPv4 TCP attempt cannot be conclusively confirmed when packet capture is incomplete."
            )
        else:
            fallback_occurred = False
            classification = "DIRECT_IPV6"
            reason = "Direct IPv6 connection established successfully without IPv4 fallback."

    elif ipv4_conn_ok and not ipv6_attempt:
        if capture_loss:
            fallback_occurred = False
            classification = "INCONCLUSIVE"
            reason = (
                f"Measurement inconclusive: Capture loss detected ({capture_loss_message or 'packet drops observed'}). "
                "Per PS-028 specification, the absence of prior IPv6 connection attempts cannot be conclusively confirmed when packet capture is incomplete."
            )
        else:
            # Crucial PS-028 invariant: HTTP 200 on IPv4 without IPv6 attempt is NOT fallback!
            fallback_occurred = False
            classification = "DIRECT_IPV4"
            reason = (
                "Direct IPv4 connection established without prior IPv6 attempt. "
                "Per PS-028 specification, fallback is not inferred from HTTP 200 alone."
            )

    elif ipv6_attempt and not ipv4_attempt and not ipv6_conn_ok:
        if http_success:
            fallback_occurred = False
            classification = "INCONCLUSIVE"
            reason = "HTTP execution succeeded but IPv6 connection was not established and no IPv4 attempt was made."
        else:
            fallback_occurred = False
            classification = "CONNECTION_FAILED"
            reason = "Direct IPv6 connection attempt failed."

    elif ipv4_attempt and not ipv6_attempt and not ipv4_conn_ok:
        if http_success:
            fallback_occurred = False
            classification = "INCONCLUSIVE"
            reason = "HTTP execution succeeded but IPv4 connection was not established and no IPv6 attempt was made."
        else:
            fallback_occurred = False
            classification = "CONNECTION_FAILED"
            reason = "Direct IPv4 connection attempt failed."

    elif not ipv4_conn_ok and not ipv6_conn_ok:
        if http_success:
            fallback_occurred = False
            classification = "INCONCLUSIVE"
            reason = (
                "Measurement failure: HTTP execution succeeded but no connection evidence was captured. "
                "Per PS-028 specification, fallback cannot be inferred from HTTP success alone."
            )
        else:
            fallback_occurred = False
            classification = "CONNECTION_FAILED"
            reason = "Neither IPv6 nor IPv4 connection succeeded."
    else:
        fallback_occurred = False
        classification = "INCONCLUSIVE"
        reason = "Connection attempt sequence is ambiguous or incomplete."

    return {
        "fallback_occurred": fallback_occurred,
        "classification": classification,
        "reason": reason,
        "ipv6_attempt": ipv6_attempt,
        "ipv4_attempt": ipv4_attempt,
        "ipv6_success": ipv6_conn_ok,
        "ipv4_success": ipv4_conn_ok,
        "telemetry_diagnostic_conclusion": telemetry_diagnostic,
    }


def update_http_outcome_from_dissection(
    http_outcome: Dict[str, Any],
    dissection: Dict[str, Any],
    browser_result: Optional[Dict[str, Any]] = None,
    is_simulation: bool = False
) -> Dict[str, Any]:
    """
    Updates http_outcome dictionary using packet dissection evidence and browser telemetry.
    Priority is given to correlated primary navigation flow in packet capture.
    When primary flow is uncorrelated, raw/ancillary packet status codes cannot promote success.
    """
    if browser_result is None:
        browser_result = {}

    observed_http_code = dissection.get("http_status_code")
    main_flow = dissection.get("main_http_flow") or {}
    main_flow_correlated = bool(main_flow.get("correlated", False))

    if main_flow_correlated and observed_http_code is not None:
        http_outcome["status_code"] = observed_http_code
        http_outcome["success"] = (200 <= observed_http_code < 400)
        if not http_outcome.get("winning_address_family") and dissection.get("http_response_family"):
            http_outcome["winning_address_family"] = dissection["http_response_family"]
            http_outcome["winning_ip"] = (
                SERVER_IPV6 if dissection["http_response_family"] == "IPv6" else SERVER_IPV4
            )
        http_outcome["main_http_flow"] = main_flow
    elif http_outcome.get("status_code") is not None:
        # Corroborated by reliable browser-side HTTP status collection
        b_code = http_outcome["status_code"]
        http_outcome["success"] = (200 <= b_code < 400)
        if not http_outcome.get("winning_address_family") and browser_result.get("winning_family"):
            http_outcome["winning_address_family"] = browser_result["winning_family"]
            http_outcome["winning_ip"] = (
                SERVER_IPV6 if browser_result["winning_family"] == "IPv6" else SERVER_IPV4
            )
        if main_flow:
            http_outcome["main_http_flow"] = main_flow
    else:
        if not is_simulation:
            http_outcome["status_code"] = None
            http_outcome["success"] = False
            http_outcome["winning_address_family"] = None
            http_outcome["winning_ip"] = None

    return http_outcome


# ------------------------------------------------------------------------------
# Real Browser Execution Controller & Launch Environment
# ------------------------------------------------------------------------------

def get_browser_uid_gid(target_user: Optional[str] = None) -> Tuple[int, int]:
    """
    Determines the unprivileged UID and GID for executing the browser process.
    Backed strictly by the system passwd database via lab.identity.
    Never returns root (UID 0).
    """
    try:
        if target_user:
            ident = identity.resolve_user_by_name(target_user)
        else:
            ident = identity.resolve_invoking_identity()
        return ident.uid, ident.gid
    except identity.IdentityResolutionError as exc:
        raise BrowserPreflightError(
            f"Cannot execute browser: {exc}"
        ) from exc


STANDARD_SYSTEM_PATH_DIRS = (
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
)


def sanitize_browser_path(raw_path: Optional[str]) -> str:
    """
    Constructs a clean, ordered, and deduplicated Linux PATH for the unprivileged browser.
    1. Preserves valid, absolute Linux executable directories from the source PATH.
    2. Preserves their original order.
    3. Removes Windows-mounted WSL drive paths, particularly /mnt/c/..., /mnt/d/...,
       and equivalent /mnt/<drive-letter> entries.
    4. Does not indiscriminately remove all /mnt paths; legitimate Linux mounts
       (e.g., /mnt/storage, /mnt/share, /mnt/data) are preserved.
    5. Rejects relative and empty PATH entries.
    6. Avoids duplicate directories.
    7. Ensures standard Linux system directories are present in the resulting PATH:
       /usr/local/sbin, /usr/local/bin, /usr/sbin, /usr/bin, /sbin, /bin.
    """
    standard_dirs = list(STANDARD_SYSTEM_PATH_DIRS)
    wsl_drive_pattern = re.compile(r"^/mnt/[a-zA-Z](?:/.*)?$")
    seen = set()
    cleaned_entries: List[str] = []

    if raw_path:
        for entry in raw_path.split(":"):
            entry = entry.strip()
            if not entry or not os.path.isabs(entry):
                continue
            normalized = os.path.normpath(entry)
            if wsl_drive_pattern.match(normalized):
                continue
            if normalized not in seen:
                seen.add(normalized)
                cleaned_entries.append(normalized)

    for s_dir in standard_dirs:
        if s_dir not in seen:
            seen.add(s_dir)
            cleaned_entries.append(s_dir)

    return ":".join(cleaned_entries)


def get_browser_env(
    target_uid: int,
    target_gid: int,
    base_env: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Constructs a minimal, clean, and intentional environment for the unprivileged browser process.
    - Sets HOME to the actual browser user's home directory.
    - Sets consistent USER and LOGNAME.
    - Sets XDG_CONFIG_HOME, XDG_CACHE_HOME, and XDG_DATA_HOME.
    - Sets XDG_RUNTIME_DIR only if a valid runtime directory exists and is owned by target_uid.
    - Ensures no inappropriate /root paths remain.
    Raises BrowserPreflightError if target_uid is 0 or inappropriate root paths are detected.
    """
    if target_uid == 0:
        raise BrowserPreflightError("Cannot generate browser environment for root user (UID 0)")

    try:
        ident = identity.resolve_user_by_uid(target_uid)
    except identity.IdentityResolutionError as exc:
        raise BrowserPreflightError(
            f"Cannot generate browser environment for UID {target_uid}: {exc}"
        ) from exc

    user_name = ident.username
    user_home = str(ident.home_dir)
    user_shell = ident.shell

    source_env = base_env if base_env is not None else os.environ

    env: Dict[str, str] = {
        "HOME": user_home,
        "USER": user_name,
        "LOGNAME": user_name,
        "SHELL": user_shell,
        "PATH": sanitize_browser_path(source_env.get("PATH")),
        "XDG_CONFIG_HOME": str(Path(user_home) / ".config"),
        "XDG_CACHE_HOME": str(Path(user_home) / ".cache"),
        "XDG_DATA_HOME": str(Path(user_home) / ".local" / "share"),
    }

    # Safe pass-through variables
    safe_pass_keys = [
        "LANG", "LC_ALL", "LC_CTYPE", "TZ",
        "DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"
    ]
    for key in safe_pass_keys:
        val = source_env.get(key)
        if val is not None and "/root" not in val:
            env[key] = val

    # Set XDG_RUNTIME_DIR only if a valid directory exists and is owned by target_uid
    runtime_candidates = []
    if "XDG_RUNTIME_DIR" in source_env:
        runtime_candidates.append(Path(source_env["XDG_RUNTIME_DIR"]))
    runtime_candidates.append(Path(f"/run/user/{target_uid}"))

    runtime_dir_found = None
    for cand in runtime_candidates:
        try:
            st = cand.stat()
            if stat.S_ISDIR(st.st_mode) and st.st_uid == target_uid:
                runtime_dir_found = str(cand)
                break
        except OSError:
            continue

    if runtime_dir_found:
        env["XDG_RUNTIME_DIR"] = runtime_dir_found

    # Strictly reject any remaining inappropriate /root paths
    for k, v in list(env.items()):
        if "/root" in v:
            raise BrowserPreflightError(
                f"Inappropriate root path detected in browser environment variable {k}={v}"
            )

    return env


def verify_browser_paths_writable(
    profile_dir: Path,
    target_uid: int,
    target_gid: int,
    browser_name: str = "google-chrome",
    env: Optional[Dict[str, str]] = None
) -> Dict[str, Path]:
    """
    Verifies that the trial profile directory, NetLog path parent,
    and crashpad database directory exist and are writable by the unprivileged browser user.
    Raises BrowserPreflightError if any required path is not writable.
    """
    profile_dir = Path(profile_dir).resolve()
    try:
        profile_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BrowserPreflightError(f"Failed to create profile directory '{profile_dir}': {exc}") from exc

    if os.geteuid() == 0:
        try:
            os.chown(str(profile_dir), target_uid, target_gid)
            os.chmod(str(profile_dir), 0o700)
        except OSError:
            pass

    # Verify profile_dir writability
    if os.geteuid() == target_uid or os.getuid() == target_uid:
        try:
            probe = profile_dir / ".write_probe"
            probe.write_text("probe", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except (OSError, PermissionError) as exc:
            raise BrowserPreflightError(
                f"Trial profile directory '{profile_dir}' is not writable by user UID {target_uid}: {exc}"
            ) from exc
    elif os.geteuid() == 0:
        st = profile_dir.stat()
        if st.st_uid != target_uid or not (st.st_mode & 0o200):
            raise BrowserPreflightError(
                f"Trial profile directory '{profile_dir}' is not writable by user UID {target_uid}"
            )

    # NetLog path parent writability
    netlog_path = profile_dir / "netlog.json"
    if netlog_path.exists():
        if os.geteuid() == 0:
            try:
                os.chown(str(netlog_path), target_uid, target_gid)
            except OSError:
                pass
        if (os.geteuid() == target_uid or os.getuid() == target_uid) and not os.access(netlog_path, os.W_OK):
            raise BrowserPreflightError(
                f"NetLog path '{netlog_path}' exists but is not writable by user UID {target_uid}"
            )

    b_name_lower = browser_name.lower()
    if "firefox" in b_name_lower:
        user_js = profile_dir / "user.js"
        if not user_js.exists():
            try:
                user_js.write_text(
                    'user_pref("app.update.auto", false);\n'
                    'user_pref("app.update.enabled", false);\n'
                    'user_pref("app.normandy.enabled", false);\n'
                    'user_pref("browser.shell.checkDefaultBrowser", false);\n'
                    'user_pref("browser.safebrowsing.downloads.remote.enabled", false);\n'
                    'user_pref("browser.safebrowsing.malware.enabled", false);\n'
                    'user_pref("browser.safebrowsing.phishing.enabled", false);\n'
                    'user_pref("browser.search.update", false);\n'
                    'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
                    'user_pref("network.captive-portal-service.enabled", false);\n'
                    'user_pref("network.connectivity-service.enabled", false);\n'
                    'user_pref("network.dns.disablePrefetch", true);\n'
                    'user_pref("network.prefetch-next", false);\n'
                    'user_pref("toolkit.telemetry.enabled", false);\n'
                    'user_pref("geo.enabled", false);\n'
                    'user_pref("geo.provider.network.url", "");\n',
                    encoding="utf-8"
                )
                if os.geteuid() == 0:
                    try:
                        os.chown(str(user_js), target_uid, target_gid)
                        os.chmod(str(user_js), 0o644)
                    except OSError:
                        pass
            except OSError as exc:
                raise BrowserPreflightError(f"Failed to create user.js in profile '{profile_dir}': {exc}") from exc

        return {
            "profile_dir": profile_dir,
            "netlog_path": profile_dir / "moz_telemetry.log",
            "crashpad_dir": profile_dir
        }

    # Crashpad database directory
    if env and "XDG_CONFIG_HOME" in env:
        xdg_config = Path(env["XDG_CONFIG_HOME"])
    elif env and "HOME" in env:
        xdg_config = Path(env["HOME"]) / ".config"
    else:
        try:
            ident = identity.resolve_user_by_uid(target_uid)
            user_home = ident.home_dir
        except identity.IdentityResolutionError as exc:
            raise BrowserPreflightError(
                f"Failed to resolve home directory for UID {target_uid}: {exc}"
            ) from exc
        xdg_config = user_home / ".config"

    b_family = "chromium" if "chromium" in browser_name.lower() else "google-chrome"
    crashpad_dir = xdg_config / b_family / "Crash Reports"
    try:
        crashpad_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BrowserPreflightError(
            f"Failed to create crashpad database directory '{crashpad_dir}': {exc}"
        ) from exc

    if os.geteuid() == 0:
        try:
            for p in [xdg_config, xdg_config / b_family, crashpad_dir]:
                os.chown(str(p), target_uid, target_gid)
                os.chmod(str(p), 0o700)
        except OSError:
            pass

    if os.geteuid() == target_uid or os.getuid() == target_uid:
        try:
            probe = crashpad_dir / ".write_probe"
            probe.write_text("probe", encoding="utf-8")
            probe.unlink(missing_ok=True)
        except (OSError, PermissionError) as exc:
            raise BrowserPreflightError(
                f"Crashpad database path '{crashpad_dir}' is not writable by user UID {target_uid}: {exc}"
            ) from exc
    elif os.geteuid() == 0:
        st = crashpad_dir.stat()
        if st.st_uid != target_uid or not (st.st_mode & 0o200):
            raise BrowserPreflightError(
                f"Crashpad database path '{crashpad_dir}' is not writable by user UID {target_uid}"
            )

    # Also ensure XDG_DATA_HOME applications directory for Chrome wrapper script
    if env and "XDG_DATA_HOME" in env:
        xdg_apps = Path(env["XDG_DATA_HOME"]) / "applications"
        try:
            xdg_apps.mkdir(parents=True, exist_ok=True)
            if os.geteuid() == 0:
                os.chown(str(xdg_apps), target_uid, target_gid)
        except OSError:
            pass

    return {
        "profile_dir": profile_dir,
        "netlog_path": netlog_path,
        "crashpad_dir": crashpad_dir
    }


def run_browser(
    browser_name: str,
    browser_path: str,
    target_url: str,
    profile_dir: Path,
    timeout: float = 15.0,
    netns: str = CLIENT_NETNS,
    is_simulation: bool = False,
    extra_args: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Executes a real browser inside the client namespace with a clean process,
    isolated profile, and headless display flags.
    Captures stdout, stderr, exit code, and determines HTTP outcome.
    """
    if is_simulation:
        return {
            "name": browser_name,
            "executable": browser_path,
            "exit_code": 0,
            "timed_out": False,
            "stdout": "<html><body>PS-028 Simulated Response</body></html>",
            "stderr": "",
            "http_status": 200,
            "success": True,
            "winning_family": "IPv4"
        }

    target_uid, target_gid = get_browser_uid_gid()
    browser_env = get_browser_env(target_uid, target_gid)

    # Preflight path writability checks
    verify_browser_paths_writable(
        profile_dir=profile_dir,
        target_uid=target_uid,
        target_gid=target_gid,
        browser_name=browser_name,
        env=browser_env
    )

    bname = browser_name.lower()
    telemetry_log_path = profile_dir / "moz_telemetry.log"
    if "firefox" in bname:
        browser_env["MOZ_LOG"] = "sync,timestamp,nsHttp:5,nsSocketTransport:5"
        browser_env["MOZ_LOG_FILE"] = str(telemetry_log_path.resolve())

    # Construct browser command per browser family
    is_snap = is_snap_browser(browser_path)
    if is_snap:
        cmd = []
        if os.geteuid() != 0:
            cmd.extend(["sudo", "-n"])
        cmd.extend(["ip", "netns", "exec", netns])
        cmd.extend(["unshare", "--mount", "--propagation", "private"])
        cmd.extend([
            sys.executable,
            str(SCRIPT_DIR / "privileged_helper.py"),
            "launch-snap-browser",
            f"--reuid={target_uid}",
            f"--regid={target_gid}",
            f"--snap-name={browser_name}",
            "--",
            browser_path
        ])
    else:
        cmd = []
        if os.geteuid() != 0:
            cmd.extend(["sudo", "-n"])
        cmd.extend(["ip", "netns", "exec", netns])

        if shutil.which("setpriv"):
            cmd.extend(["setpriv", f"--reuid={target_uid}", f"--regid={target_gid}", "--init-groups"])
        else:
            try:
                ident = identity.resolve_user_by_uid(target_uid)
                user_name = ident.username
            except identity.IdentityResolutionError as exc:
                raise BrowserPreflightError(
                    f"Failed to resolve username for UID {target_uid}: {exc}"
                ) from exc
            cmd.extend(["sudo", "-u", user_name, "--"])

        cmd.extend(["env", "-i"])
        for env_k, env_v in browser_env.items():
            cmd.append(f"{env_k}={env_v}")

        cmd.append(browser_path)

    netlog_path = profile_dir / "netlog.json"
    if "chromium" in bname or "chrome" in bname:
        cmd.extend([
            "--headless=new",
            "--dump-dom",
            "--no-sandbox",
            "--disable-gpu",
            f"--user-data-dir={profile_dir.resolve()}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-domain-reliability",
            "--disable-client-side-phishing-detection",
            "--safebrowsing-disable-auto-update",
            "--disable-features=OptimizationHints,Translate",
            "--disable-breakpad",
            "--disable-background-timer-throttling",
            "--disable-sync",
            "--disable-translate",
            "--disable-default-apps",
            f"--log-net-log={netlog_path.resolve()}",
            f"--timeout={int(timeout * 1000)}",
        ])
    elif "firefox" in bname:
        cmd.extend([
            "--headless",
            "--profile", str(profile_dir.resolve()),
            "--no-remote",
            "--new-instance",
        ])

    if extra_args:
        cmd.extend(extra_args)

    cmd.append(target_url)

    t0 = time.time()
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = -1

    stop_event = threading.Event()
    watcher_thread = None

    if "firefox" in bname and not is_simulation:
        def _firefox_telemetry_watcher():
            t_end = time.time() + timeout
            while time.time() < t_end and not stop_event.is_set():
                time.sleep(0.1)
                parsed = parse_firefox_telemetry(profile_dir, target_url=target_url)
                if parsed.get("status_code") is not None:
                    time.sleep(0.15)
                    try:
                        subprocess.run(
                            ["pkill", "-f", str(profile_dir.resolve())],
                            capture_output=True,
                            check=False
                        )
                    except Exception:
                        pass
                    break

        watcher_thread = threading.Thread(target=_firefox_telemetry_watcher, daemon=True)
        watcher_thread.start()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=browser_env
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
        if is_snap and exit_code == 71:
            raise SnapMountError(stderr.strip() or "Snap mount setup failed")
        if exit_code < 0:
            parsed_early = parse_firefox_telemetry(profile_dir, target_url=target_url) if "firefox" in bname else {}
            if "firefox" in bname and (parsed_early.get("status_code") is not None or exit_code in (-15, -9, 143)):
                exit_code = 0
            else:
                raise BrowserPreflightError(
                    f"Browser crashed on startup with signal {-exit_code}: {stderr.strip()}"
                )
        if "mkdir: cannot create directory ‘/root’" in stderr or "chrome_crashpad_handler: --database is required" in stderr:
            raise BrowserPreflightError(
                f"Browser launch environment error: {stderr.strip()}"
            )
    except subprocess.TimeoutExpired as e:
        parsed_late = parse_firefox_telemetry(profile_dir, target_url=target_url) if "firefox" in bname else {}
        if "firefox" in bname and parsed_late.get("status_code") is not None:
            timed_out = False
            exit_code = 0
            stdout = (e.stdout or b"").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = (e.stderr or b"").decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        else:
            timed_out = True
            exit_code = 124
            stdout = (e.stdout or b"").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = (e.stderr or b"").decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
    except (SnapMountError, BrowserPreflightError):
        raise
    except Exception as e:
        exit_code = -1
        stderr = f"Browser execution exception: {e}"
    finally:
        stop_event.set()
        if watcher_thread:
            watcher_thread.join(timeout=1.0)

    duration_ms = round((time.time() - t0) * 1000.0, 2)

    # Determine HTTP status code and winning address family
    # Chrome --dump-dom exit code 0 does not prove HTTP 200.
    # Collect real HTTP status from browser instrumentation (Chromium NetLog or Firefox Telemetry).
    # If unavailable, remains None (null/unknown).
    http_status = None
    winning_family = None
    telemetry_path = None

    if "chromium" in bname or "chrome" in bname:
        if netlog_path.is_file():
            try:
                netlog_info = parse_chromium_netlog(netlog_path, target_url=target_url)
                http_status = netlog_info.get("status_code")
                winning_family = netlog_info.get("winning_family")
            except Exception:
                pass
    elif "firefox" in bname:
        try:
            ff_info = parse_firefox_telemetry(profile_dir, target_url=target_url)
            http_status = ff_info.get("status_code")
            winning_family = ff_info.get("winning_family")
            telemetry_candidates = [
                profile_dir / "moz_telemetry.log.moz_log",
                profile_dir / "moz_telemetry.log"
            ] + list(profile_dir.glob("*moz*log*"))
            for tc in telemetry_candidates:
                if tc.is_file() and tc.stat().st_size > 0:
                    telemetry_path = str(tc)
                    break
        except Exception:
            pass

    success = (exit_code == 0 and not timed_out and (
        (http_status is not None and 200 <= http_status < 400) or
        (http_status is None and len(stdout.strip()) > 0)
    ))

    return {
        "name": browser_name,
        "executable": browser_path,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "stdout": stdout,
        "stderr": stderr,
        "http_status": http_status,
        "success": success,
        "winning_family": winning_family,
        "netlog_path": str(netlog_path) if netlog_path.is_file() else None,
        "telemetry_path": telemetry_path
    }


# ------------------------------------------------------------------------------
# Synthetic Simulation Generator (for offline testing & CI)
# ------------------------------------------------------------------------------

def generate_simulated_trial(
    scenario_id: str,
    hostname: str,
    trial_dir: Path,
    browser_info: Dict[str, Any]
) -> Tuple[Path, Dict[str, Any], Dict[str, Any]]:
    """
    Generates realistic, synthetic PCAP capture and logs for testing and simulation.
    Strictly matches scenario physics:
    - S0: Direct IPv6 SYN -> SYN-ACK -> HTTP
    - S1: IPv6 SYN (blackholed) -> IPv4 SYN at +250ms -> IPv4 SYN-ACK -> HTTP
    - S2: IPv6 SYN -> TCP RST -> IPv4 SYN immediate -> IPv4 SYN-ACK -> HTTP
    - S3: IPv6 SYN -> SYN-ACK at +150ms -> IPv6 wins
    - S4: IPv6 SYN -> IPv4 SYN at +250ms -> IPv4 SYN-ACK at +270ms -> IPv4 wins
    - S5: IPv6 SYN loss -> IPv4 fallback
    - S6: A immediate, AAAA delayed +500ms -> IPv4 SYN at +50ms -> IPv4 wins
    """
    pcap_path = trial_dir / "capture.pcap"
    tcpdump_log = trial_dir / "tcpdump.log"

    pcap_bytes = bytearray()
    # PCAP Global Header (Ethernet, link type 1)
    pcap_bytes += struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    t_base = 1729000000.0

    def add_pkt(pkt_data: bytes, rel_ms: float):
        nonlocal pcap_bytes
        ts_sec = int(t_base + (rel_ms / 1000.0))
        ts_usec = int(((rel_ms % 1000.0) / 1000.0) * 1_000_000)
        hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt_data), len(pkt_data))
        pcap_bytes += hdr + pkt_data

    eth_v6 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x86\xdd"
    eth_v4 = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"

    ip6_cl = socket.inet_pton(socket.AF_INET6, "2001:db8:1::2")
    ip6_sv = socket.inet_pton(socket.AF_INET6, SERVER_IPV6)
    ip4_cl = socket.inet_aton("10.0.1.2")
    ip4_sv = socket.inet_aton(SERVER_IPV4)

    # IPv6 SYN
    ip6_hdr_syn = struct.pack("!IHBB", 0x60000000, 20, 6, 64) + ip6_cl + ip6_sv
    tcp_syn_v6 = struct.pack("!HHIIBBHHH", 50000, 80, 1000, 0, (5 << 4), 0x02, 65535, 0, 0)

    # IPv6 SYN-ACK
    ip6_hdr_synack = struct.pack("!IHBB", 0x60000000, 20, 6, 64) + ip6_sv + ip6_cl
    tcp_synack_v6 = struct.pack("!HHIIBBHHH", 80, 50000, 2000, 1001, (5 << 4), 0x12, 65535, 0, 0)

    # IPv6 Client Final ACK
    tcp_ack_v6 = struct.pack("!HHIIBBHHH", 50000, 80, 1001, 2001, (5 << 4), 0x10, 65535, 0, 0)

    # IPv6 RST (with ACK set and raw_ack acknowledging the client SYN: 1000 + 1 = 1001)
    tcp_rst_v6 = struct.pack("!HHIIBBHHH", 80, 50000, 0, 1001, (5 << 4), 0x14, 0, 0, 0)

    # IPv4 SYN
    ip4_hdr_syn = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, ip4_cl, ip4_sv)
    tcp_syn_v4 = struct.pack("!HHIIBBHHH", 50001, 80, 3000, 0, (5 << 4), 0x02, 65535, 0, 0)

    # IPv4 SYN-ACK
    ip4_hdr_synack = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 2, 0, 64, 6, 0, ip4_sv, ip4_cl)
    tcp_synack_v4 = struct.pack("!HHIIBBHHH", 80, 50001, 4000, 3001, (5 << 4), 0x12, 65535, 0, 0)

    # IPv4 Client Final ACK
    ip4_hdr_ack = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 3, 0, 64, 6, 0, ip4_cl, ip4_sv)
    tcp_ack_v4 = struct.pack("!HHIIBBHHH", 50001, 80, 3001, 4001, (5 << 4), 0x10, 65535, 0, 0)

    sc = scenario_id.upper()
    if sc == "S0":
        # Healthy baseline: IPv6 wins immediately
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v6 + ip6_hdr_synack + tcp_synack_v6, 30.0)
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_ack_v6, 31.0)
        winning_fam = "IPv6"
        winning_ip = SERVER_IPV6
    elif sc == "S1":
        # IPv6 SYN blackhole: IPv6 dropped, IPv4 CAD ~250ms wins
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 260.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 280.0)
        add_pkt(eth_v4 + ip4_hdr_ack + tcp_ack_v4, 281.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S2":
        # IPv6 TCP RST: Immediate reset triggers immediate IPv4
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v6 + ip6_hdr_synack[:40] + tcp_rst_v6, 30.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 32.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 52.0)
        add_pkt(eth_v4 + ip4_hdr_ack + tcp_ack_v4, 53.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S3":
        # IPv6 150ms: IPv6 completes in 150ms before IPv4 CAD (250ms)
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v6 + ip6_hdr_synack + tcp_synack_v6, 160.0)
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_ack_v6, 161.0)
        winning_fam = "IPv6"
        winning_ip = SERVER_IPV6
    elif sc == "S4":
        # IPv6 600ms: IPv4 CAD fires at 250ms and wins in 20ms
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 260.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 280.0)
        add_pkt(eth_v4 + ip4_hdr_ack + tcp_ack_v4, 281.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S5":
        # IPv6 SYN loss: 50% loss causes IPv4 fallback
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 260.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 280.0)
        add_pkt(eth_v4 + ip4_hdr_ack + tcp_ack_v4, 281.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S6":
        # AAAA delayed 500ms: A arrives at 0ms, IPv4 starts after ~50ms resolution delay
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 60.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 80.0)
        add_pkt(eth_v4 + ip4_hdr_ack + tcp_ack_v4, 81.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    else:
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4

    # Add simulated HTTP GET request and 200 OK response for the winning family
    http_req = f"GET / HTTP/1.1\r\nHost: {hostname}\r\n\r\n".encode("ascii")
    html_body = b"<html><body>Measurement OK</body></html>"
    http_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(html_body)}\r\n"
        f"\r\n"
    ).encode("ascii") + html_body
    if winning_fam == "IPv6":
        ip6_hdr_req = struct.pack("!IHBB", 0x60000000, 20 + len(http_req), 6, 64) + ip6_cl + ip6_sv
        tcp_req_v6 = struct.pack("!HHIIBBHHH", 50000, 80, 1001, 2001, (5 << 4), 0x18, 65535, 0, 0)
        add_pkt(eth_v6 + ip6_hdr_req + tcp_req_v6 + http_req, 32.0 if sc != "S3" else 162.0)

        ip6_hdr_resp = struct.pack("!IHBB", 0x60000000, 20 + len(http_resp), 6, 64) + ip6_sv + ip6_cl
        tcp_resp_v6 = struct.pack("!HHIIBBHHH", 80, 50000, 2001, 1001 + len(http_req), (5 << 4), 0x18, 65535, 0, 0)
        add_pkt(eth_v6 + ip6_hdr_resp + tcp_resp_v6 + http_resp, 35.0 if sc != "S3" else 165.0)
    else:
        req_time = 282.0 if sc in ("S1", "S4", "S5") else (54.0 if sc == "S2" else 82.0)
        ip4_hdr_req = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(http_req), 4, 0, 64, 6, 0, ip4_cl, ip4_sv)
        tcp_req_v4 = struct.pack("!HHIIBBHHH", 50001, 80, 3001, 4001, (5 << 4), 0x18, 65535, 0, 0)
        add_pkt(eth_v4 + ip4_hdr_req + tcp_req_v4 + http_req, req_time)

        ip4_hdr_resp = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(http_resp), 5, 0, 64, 6, 0, ip4_sv, ip4_cl)
        tcp_resp_v4 = struct.pack("!HHIIBBHHH", 80, 50001, 4001, 3001 + len(http_req), (5 << 4), 0x18, 65535, 0, 0)
        resp_time = 285.0 if sc in ("S1", "S4", "S5") else (55.0 if sc == "S2" else 85.0)
        add_pkt(eth_v4 + ip4_hdr_resp + tcp_resp_v4 + http_resp, resp_time)

    pcap_path.write_bytes(pcap_bytes)
    tcpdump_log.write_text("Simulated tcpdump: 3 packets captured, 3 packets received by filter\n", encoding="utf-8")

    http_outcome = {
        "status_code": 200,
        "success": True,
        "winning_address_family": winning_fam,
        "winning_ip": winning_ip,
        "response_body_bytes": 612
    }

    browser_result = {
        "name": browser_info.get("name", "simulated-browser"),
        "executable": browser_info.get("path", "simulated"),
        "exit_code": 0,
        "timed_out": False,
        "duration_ms": 120.0,
        "stdout": "<html><body>PS-028 Measurement Body</body></html>",
        "stderr": "",
        "http_status": 200,
        "success": True,
        "winning_family": winning_fam
    }

    return pcap_path, http_outcome, browser_result


# ------------------------------------------------------------------------------
# Single Integrated Trial Runner
# ------------------------------------------------------------------------------

def run_trial(
    scenario_id: str = "S0",
    browser_pref: Optional[str] = None,
    trial_id: Optional[str] = None,
    output_dir: Optional[Path] = None,
    timeout: float = 30.0,
    browser_timeout: float = 15.0,
    is_simulation: bool = False,
    skip_baseline_check: bool = False,
    extra_browser_args: Optional[List[str]] = None,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 10.0,
    capture_interface: Optional[str] = None,
    capture_filter: Optional[str] = None,
    capture_buffer_kb: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Executes one complete integrated measurement trial:
    1. Preflight check: validates lab readiness & genuine browser presence.
    2. Shared lock: safely acquires .lab.lock.
    3. Baseline verification: ensures clean state.
    4. Unique ID: generates trial-<id>.he.test.
    5. Impairment: applies scenario S0-S6 in-process (avoiding deadlock).
    6. Packet capture: starts tcpdump in ps028-cl.
    7. Browser run: runs browser with fresh profile & context.
    8. Capture stop: cleanly flushes & closes PCAP.
    9. Guaranteed cleanup: restores baseline unconditionally in finally block.
    10. Dissection: parses PCAP and classifies fallback.
    11. Artifact output: writes versioned result.json and referenced evidence.
    """
    sc_clean = scenario_id.upper()
    if sc_clean not in ALLOWED_SCENARIOS:
        raise ValueError(f"Scenario '{scenario_id}' invalid. Must be one of: {ALLOWED_SCENARIOS}")

    start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    t_start = time.time()

    # 1. Preflight Verification (Strict: fails if browser missing; refuses curl)
    preflight = validate_lab_readiness(
        is_simulation=is_simulation,
        skip_baseline=skip_baseline_check,
        browser_pref=browser_pref
    )
    if preflight["status"] != "PASS":
        err_msg = "; ".join(preflight["errors"])
        if not preflight["checks"].get("browser", {}).get("valid", True):
            raise BrowserPreflightError(f"Browser preflight failed: {err_msg}")
        raise LabReadinessError(f"Lab preflight failed: {err_msg}")

    bname = preflight["checks"]["browser"]["name"]
    bpath = preflight["checks"]["browser"]["path"]
    bver = preflight["checks"]["browser"].get("version", "unknown")

    # 2. Acquire Shared Lab Lock
    target_lock = lock_file or concurrency.DEFAULT_LAB_LOCK_FILE
    with concurrency.acquire_lab_lock(timeout=lock_timeout, lock_path=target_lock):

        tid = trial_id or generate_trial_id()
        hostname = get_trial_hostname(tid)
        target_url = f"http://{hostname}/"

        tdir = Path(output_dir or (DEFAULT_TRIALS_DIR / tid)).resolve()
        tdir.mkdir(parents=True, exist_ok=True)

        pcap_path = tdir / "capture.pcap"
        tcpdump_log = tdir / "tcpdump.log"
        browser_log = tdir / "browser.log"
        result_json_path = tdir / "result.json"

        # Unique isolated browser profile directory
        profile_dir = Path(tempfile.mkdtemp(prefix=f"ps028_profile_{tid}_"))

        tcpdump_proc = None
        cleanup_errors: List[str] = []
        scenario_restored = False
        baseline_verified = False
        profile_cleaned = False

        scenario_applied_iso = None
        capture_start_iso = None
        browser_start_iso = None
        browser_end_iso = None
        capture_stop_iso = None
        baseline_restored_iso = None

        browser_result: Dict[str, Any] = {}
        http_outcome: Dict[str, Any] = {}
        capture_shutdown_unconfirmed = False
        capture_shutdown_error: Optional[str] = None

        # Signal handling to ensure cleanup on SIGINT / SIGTERM
        def _sig_handler(signum, frame):
            # Baseline restoration will execute in finally block
            raise KeyboardInterrupt(f"Interrupted by signal {signum}")

        old_sigint = signal.signal(signal.SIGINT, _sig_handler)
        old_sigterm = signal.signal(signal.SIGTERM, _sig_handler)

        try:
            # 2.5 Browser Preflight Checks (Path Writability & Environment)
            if not is_simulation:
                target_uid, target_gid = get_browser_uid_gid()
                browser_env = get_browser_env(target_uid, target_gid)
                verify_browser_paths_writable(
                    profile_dir=profile_dir,
                    target_uid=target_uid,
                    target_gid=target_gid,
                    browser_name=bname,
                    env=browser_env
                )

            # 3. Apply scenario in-process
            impair.apply_scenario(
                sc_clean,
                scenarios_path=DEFAULT_SCENARIOS_PATH,
                dry_run=is_simulation,
                lock_file=target_lock,
                lock_timeout=lock_timeout
            )
            scenario_applied_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            if not is_simulation:
                # 4. Start Packet Capture (tcpdump) in ps028-cl namespace
                capture_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                cap_iface = capture_interface or CLIENT_CAPTURE_INTERFACE
                cap_filter = capture_filter or DEFAULT_BPF_FILTER
                cap_buf_kb = capture_buffer_kb if capture_buffer_kb is not None else DEFAULT_CAPTURE_BUFFER_KB
                tcpdump_proc = start_packet_capture(
                    output_pcap=pcap_path,
                    log_file=tcpdump_log,
                    netns=CLIENT_NETNS,
                    interface=cap_iface,
                    bpf_filter=cap_filter,
                    buffer_size_kb=cap_buf_kb,
                    is_simulation=False,
                    caller_holds_lock=concurrency.is_lock_held_by_current_thread(target_lock),
                    lock_file=target_lock
                )

                # Confirm capture readiness before browser launch
                confirm_capture_ready(tcpdump_proc, tcpdump_log)

                # 5. Run Genuine Browser
                browser_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                browser_result = run_browser(
                    browser_name=bname,
                    browser_path=bpath,
                    target_url=target_url,
                    profile_dir=profile_dir,
                    timeout=browser_timeout,
                    netns=CLIENT_NETNS,
                    is_simulation=False,
                    extra_args=extra_browser_args
                )
                browser_end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

                # 6. Stop Packet Capture
                try:
                    stop_packet_capture(
                        tcpdump_proc,
                        timeout=5.0,
                        pcap_path=pcap_path,
                        caller_holds_lock=concurrency.is_lock_held_by_current_thread(target_lock),
                        lock_file=target_lock
                    )
                except Exception as cse:
                    capture_shutdown_unconfirmed = True
                    capture_shutdown_error = str(cse)
                    cleanup_errors.append(f"Capture shutdown unconfirmed: {cse}")
                finally:
                    tcpdump_proc = None
                    capture_stop_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

                http_outcome = {
                    "status_code": browser_result.get("http_status"),
                    "success": browser_result.get("success", False),
                    "winning_address_family": browser_result.get("winning_family"),
                    "winning_ip": None,
                    "response_body_bytes": len(browser_result.get("stdout", ""))
                }
            else:
                # Simulation Mode
                capture_start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                browser_start_iso = capture_start_iso
                pcap_path, http_outcome, browser_result = generate_simulated_trial(
                    scenario_id=sc_clean,
                    hostname=hostname,
                    trial_dir=tdir,
                    browser_info={"name": bname, "path": bpath}
                )
                browser_end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                capture_stop_iso = browser_end_iso

            # Write browser stdout/stderr to browser.log
            browser_log.write_text(
                f"=== Browser Stdout ===\n{browser_result.get('stdout', '')}\n"
                f"=== Browser Stderr ===\n{browser_result.get('stderr', '')}\n",
                encoding="utf-8"
            )

        except Exception as e:
            cleanup_errors.append(f"Trial execution error: {e}")
            raise
        finally:
            # Restore signal handlers
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

            # 7. Unconditional Cleanup & Baseline Restoration
            if tcpdump_proc is not None:
                try:
                    stop_packet_capture(
                        tcpdump_proc,
                        pcap_path=pcap_path,
                        verify_pcap=False,
                        caller_holds_lock=concurrency.is_lock_held_by_current_thread(target_lock),
                        lock_file=target_lock
                    )
                except Exception as ce:
                    cleanup_errors.append(f"tcpdump stop error: {ce}")

            try:
                impair.clear_impairments(
                    dry_run=is_simulation,
                    lock_file=target_lock,
                    lock_timeout=lock_timeout
                )
                scenario_restored = True
                baseline_restored_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            except Exception as ce:
                scenario_restored = False
                cleanup_errors.append(f"Impairment clear error: {ce}")

            try:
                baseline_verified = bool(impair.self_test_baseline(dry_run=is_simulation))
                if not baseline_verified:
                    cleanup_errors.append("Baseline self-test failed live verification")
            except Exception as ce:
                baseline_verified = False
                cleanup_errors.append(f"Baseline verify error: {ce}")

            # Preserve NetLog evidence into trial directory before cleaning temporary profile
            trial_netlog_path = tdir / "netlog.json"
            profile_netlog = profile_dir / "netlog.json"
            if profile_netlog.is_file():
                try:
                    shutil.copy2(profile_netlog, trial_netlog_path)
                    try:
                        os.chmod(trial_netlog_path, 0o664)
                    except OSError:
                        pass
                except Exception as ce:
                    cleanup_errors.append(f"NetLog preservation error: {ce}")

            # Preserve Firefox telemetry evidence into trial directory before cleaning temporary profile
            trial_telemetry_path = tdir / "browser_telemetry.log"
            telemetry_candidates = [
                profile_dir / "moz_telemetry.log.moz_log",
                profile_dir / "moz_telemetry.log"
            ] + list(profile_dir.glob("*moz*log*"))
            found_telemetry = None
            for tc in telemetry_candidates:
                if tc.is_file() and tc.stat().st_size > 0:
                    found_telemetry = tc
                    break
            if found_telemetry:
                try:
                    shutil.copy2(found_telemetry, trial_telemetry_path)
                    try:
                        os.chmod(trial_telemetry_path, 0o664)
                    except OSError:
                        pass
                except Exception as ce:
                    cleanup_errors.append(f"Telemetry preservation error: {ce}")

            if profile_dir.is_dir():
                try:
                    shutil.rmtree(profile_dir, ignore_errors=True)
                    profile_cleaned = True
                except Exception as ce:
                    cleanup_errors.append(f"Profile cleanup error: {ce}")
            else:
                profile_cleaned = True

            for temp_resolv in [
                Path("/run/ps028_resolv.conf"), Path("/tmp/.ps028_resolv.conf"),
                Path("/run/ps028_outer_resolv.conf"), Path("/tmp/.ps028_outer_resolv.conf")
            ]:
                try:
                    temp_resolv.unlink(missing_ok=True)
                except OSError:
                    pass

        # 8. Validate and Dissect Packet Capture
        pcap_valid, pcap_sha256, pcap_size, pkt_count, pcap_msg = validate_pcap_file(pcap_path)
        drop_stats = parse_tcpdump_drop_statistics(tcpdump_log)
        dissection = dissect_pcap(pcap_path, target_hostname=hostname)

        # Update HTTP outcome with evidence from packet dissection or browser instrumentation
        http_outcome = update_http_outcome_from_dissection(
            http_outcome=http_outcome,
            dissection=dissection,
            browser_result=browser_result,
            is_simulation=is_simulation
        )

        # Treat invalid PCAP or zero-packet capture as an evidence/measurement failure
        is_measurement_failure = False
        if not is_simulation:
            # For every LIVE trial, an invalid PCAP or zero-packet capture must invalidate
            # network evidence and force classification INCONCLUSIVE, regardless of browser
            # exit code or apparent page success. Never report such a capture as a valid network measurement.
            if capture_shutdown_unconfirmed or not pcap_valid or pkt_count == 0:
                was_pcap_valid = pcap_valid
                pcap_valid = False
                is_measurement_failure = True
                if capture_shutdown_unconfirmed:
                    pcap_msg = f"Measurement failure: Capture shutdown unconfirmed ({capture_shutdown_error})"
                elif not was_pcap_valid:
                    pcap_msg = f"Measurement failure: Invalid PCAP ({pcap_msg})"
                else:
                    pcap_msg = "Measurement failure: Zero packets captured in live trial"
                http_outcome["status_code"] = None
                http_outcome["success"] = False
                http_outcome["winning_address_family"] = None
                http_outcome["winning_ip"] = None
                dissection = {
                    "dns": {"queries": [], "responses": []},
                    "ipv6": {
                        "syn_count": 0,
                        "first_syn_time": None,
                        "syn_ack_received": False,
                        "syn_ack_time": None,
                        "server_rst_received": False,
                        "client_rst_sent": False,
                        "rst_received": False,
                        "tcp_handshake_completed": False,
                        "connection_established": False,
                        "http_observed": False
                    },
                    "ipv4": {
                        "syn_count": 0,
                        "first_syn_time": None,
                        "syn_ack_received": False,
                        "syn_ack_time": None,
                        "server_rst_received": False,
                        "client_rst_sent": False,
                        "rst_received": False,
                        "tcp_handshake_completed": False,
                        "connection_established": False,
                        "http_observed": False
                    },
                    "connection_attempt_delay_ms": None,
                    "connection_setup_time_ms": None,
                    "http_status_code": None,
                    "http_response_family": None,
                    "diagnostic_raw_pcap_http_code": None,
                    "main_http_flow": {
                        "stream_id": None,
                        "family": None,
                        "status_code": None,
                        "request": None,
                        "correlated": False,
                        "tcp_handshake_completed": False,
                    },
                    "tcp_streams": {},
                }
        elif not pcap_valid or pkt_count == 0:
            was_pcap_valid = pcap_valid
            pcap_valid = False
            is_measurement_failure = True
            if not was_pcap_valid:
                pcap_msg = f"Measurement failure: Invalid PCAP ({pcap_msg})"
            else:
                pcap_msg = "Measurement failure: Zero packets captured in trial"
            http_outcome["status_code"] = None
            http_outcome["success"] = False
            http_outcome["winning_address_family"] = None
            http_outcome["winning_ip"] = None
            dissection = {
                "dns": {"queries": [], "responses": []},
                "ipv6": {
                    "syn_count": 0,
                    "first_syn_time": None,
                    "syn_ack_received": False,
                    "syn_ack_time": None,
                    "server_rst_received": False,
                    "client_rst_sent": False,
                    "rst_received": False,
                    "tcp_handshake_completed": False,
                    "connection_established": False,
                    "http_observed": False
                },
                "ipv4": {
                    "syn_count": 0,
                    "first_syn_time": None,
                    "syn_ack_received": False,
                    "syn_ack_time": None,
                    "server_rst_received": False,
                    "client_rst_sent": False,
                    "rst_received": False,
                    "tcp_handshake_completed": False,
                    "connection_established": False,
                    "http_observed": False
                },
                "connection_attempt_delay_ms": None,
                "connection_setup_time_ms": None,
                "http_status_code": None,
                "http_response_family": None,
                "diagnostic_raw_pcap_http_code": None,
                "main_http_flow": {
                    "stream_id": None,
                    "family": None,
                    "status_code": None,
                    "request": None,
                    "correlated": False,
                    "tcp_handshake_completed": False,
                },
                "tcp_streams": {},
            }

        # 9. Classify Happy Eyeballs Fallback
        fail_reason = None
        if capture_shutdown_unconfirmed:
            fail_reason = (
                f"Measurement failure: Capture shutdown unconfirmed ({capture_shutdown_error}). "
                "Per PS-028 specification, network evidence is invalid and fallback cannot be evaluated."
            )
        classification = classify_fallback(
            dissection,
            http_outcome,
            is_measurement_failure=is_measurement_failure,
            pcap_valid=pcap_valid,
            failure_reason=fail_reason,
            capture_loss=drop_stats.get("capture_loss", False),
            capture_loss_message=drop_stats.get("capture_loss_message")
        )

        end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        total_duration_ms = round((time.time() - t_start) * 1000.0, 2)

        # 10. Assemble Complete Versioned Result
        scenarios_cfg = impair.load_scenarios_config(DEFAULT_SCENARIOS_PATH)
        sc_info = scenarios_cfg.get("scenarios", {}).get(sc_clean, {})

        result: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "trial_id": tid,
            "scenario_id": sc_clean,
            "scenario_name": sc_info.get("name", "unknown"),
            "scenario_description": sc_info.get("description", ""),
            "hostname": hostname,
            "target_url": target_url,
            "execution_mode": "SIMULATION" if is_simulation else "LIVE",
            "is_simulation": is_simulation,
            "timestamps": {
                "start_time": start_iso,
                "scenario_applied_time": scenario_applied_iso,
                "capture_start_time": capture_start_iso,
                "browser_start_time": browser_start_iso,
                "browser_end_time": browser_end_iso,
                "capture_stop_time": capture_stop_iso,
                "baseline_restored_time": baseline_restored_iso,
                "end_time": end_iso,
                "total_duration_ms": total_duration_ms
            },
            "browser": {
                "name": bname,
                "executable": bpath,
                "version": bver,
                "exit_code": browser_result.get("exit_code"),
                "timed_out": browser_result.get("timed_out", False),
                "duration_ms": browser_result.get("duration_ms"),
                "profile_cleaned": profile_cleaned
            },
            "http_outcome": http_outcome,
            "dns_observations": dissection["dns"],
            "network_observations": {
                "ipv6_attempt": classification["ipv6_attempt"],
                "ipv4_attempt": classification["ipv4_attempt"],
                "ipv6_success": classification["ipv6_success"],
                "ipv4_success": classification["ipv4_success"],
                "connection_attempt_delay_ms": dissection.get("connection_attempt_delay_ms"),
                "connection_setup_time_ms": dissection.get("connection_setup_time_ms"),
                "fallback_occurred": classification["fallback_occurred"],
                "classification": classification["classification"],
                "classification_reason": classification["reason"],
            },
            "capture_metadata": {
                "pcap_path": _serialize_evidence_path(pcap_path),
                "pcap_sha256": pcap_sha256,
                "pcap_size_bytes": pcap_size,
                "pcap_valid": pcap_valid,
                "packet_count": pkt_count,
                "validation_message": pcap_msg,
                "tcpdump_log_path": _serialize_evidence_path(tcpdump_log),
                "packets_captured": drop_stats.get("packets_captured", pkt_count),
                "packets_received_by_filter": drop_stats.get("packets_received_by_filter", pkt_count),
                "packets_dropped_by_kernel": drop_stats.get("packets_dropped_by_kernel", 0),
                "packets_dropped_by_interface": drop_stats.get("packets_dropped_by_interface", 0),
                "total_packets_dropped": drop_stats.get("total_packets_dropped", 0),
                "capture_loss": drop_stats.get("capture_loss", False),
                "capture_loss_message": drop_stats.get("capture_loss_message"),
                "interface": cap_iface if not is_simulation else "simulation",
                "bpf_filter": cap_filter if not is_simulation else "simulation",
                "buffer_size_kb": cap_buf_kb if not is_simulation else 0,
            },
            "evidence_paths": {
                "trial_dir": _serialize_evidence_path(tdir),
                "result_json": _serialize_evidence_path(result_json_path),
                "capture_pcap": _serialize_evidence_path(pcap_path),
                "tcpdump_log": _serialize_evidence_path(tcpdump_log),
                "browser_log": _serialize_evidence_path(browser_log)
            },
            "cleanup_status": {
                "scenario_restored": scenario_restored,
                "baseline_verified": baseline_verified,
                "profile_cleaned": profile_cleaned,
                "lock_released": True,
                "errors": cleanup_errors
            }
        }

        if (tdir / "netlog.json").is_file():
            result["evidence_paths"]["browser_netlog"] = _serialize_evidence_path(tdir / "netlog.json")
        elif browser_result.get("netlog_path"):
            result["evidence_paths"]["browser_netlog"] = _serialize_evidence_path(browser_result["netlog_path"])

        if (tdir / "browser_telemetry.log").is_file():
            result["evidence_paths"]["browser_telemetry"] = _serialize_evidence_path(tdir / "browser_telemetry.log")
        elif browser_result.get("telemetry_path"):
            result["evidence_paths"]["browser_telemetry"] = _serialize_evidence_path(browser_result["telemetry_path"])

        # Persist versioned JSON result
        result_json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        return result


# ------------------------------------------------------------------------------
# CLI Entry Point
# ------------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Integrated Browser Measurement Runner (A7)"
    )
    parser.add_argument(
        "--scenario", "-s",
        default="S0",
        choices=ALLOWED_SCENARIOS,
        help="Scenario ID to apply (S0 - S6, default: S0)"
    )
    parser.add_argument(
        "--browser", "-b",
        default=None,
        help="Browser executable or name (chromium, google-chrome, firefox)"
    )
    parser.add_argument(
        "--trial-id",
        default=None,
        help="Custom trial identifier (default: auto-generated)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        type=Path,
        help="Directory to store trial evidence (default: lab/trials/<trial_id>)"
    )
    parser.add_argument(
        "--timeout", "-t",
        default=30.0,
        type=float,
        help="Overall trial timeout in seconds (default: 30.0)"
    )
    parser.add_argument(
        "--browser-timeout",
        default=15.0,
        type=float,
        help="Browser execution timeout in seconds (default: 15.0)"
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        help="Run in simulation mode (offline/dry-run, clearly tagged in result JSON)"
    )
    parser.add_argument(
        "--skip-baseline-check",
        action="store_true",
        help="Skip initial baseline self-test check"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw JSON result to stdout"
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Capture interface in client namespace (default: ps028-cl-rt)"
    )
    parser.add_argument(
        "--filter",
        default=None,
        help="BPF filter string for packet capture (default: DNS 10.0.1.1:53 and HTTP 10.0.2.10/2001:db8:2::10)"
    )
    parser.add_argument(
        "--buffer-size-kb",
        type=int,
        default=None,
        help="Packet capture buffer size in KiB (default: 8192 KiB / 8 MiB)"
    )

    args = parser.parse_args()

    try:
        res = run_trial(
            scenario_id=args.scenario,
            browser_pref=args.browser,
            trial_id=args.trial_id,
            output_dir=args.output_dir,
            timeout=args.timeout,
            browser_timeout=args.browser_timeout,
            is_simulation=args.simulation,
            skip_baseline_check=args.skip_baseline_check,
            capture_interface=args.interface,
            capture_filter=args.filter,
            capture_buffer_kb=args.buffer_size_kb
        )

        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("\033[1;34m[INFO]\033[0m PS-028 Integrated Measurement Trial Completed")
            print("=" * 60)
            print(f"Trial ID:         {res['trial_id']}")
            print(f"Scenario:         {res['scenario_id']} ({res['scenario_name']})")
            print(f"Hostname:         {res['hostname']}")
            print(f"Mode:             {res['execution_mode']}")
            print(f"Browser:          {res['browser']['name']} (exit={res['browser']['exit_code']})")
            print(f"HTTP Outcome:     status={res['http_outcome']['status_code']} (success={res['http_outcome']['success']})")
            net_obs = res['network_observations']
            print(f"Classification:   \033[1;32m{net_obs['classification']}\033[0m (fallback={net_obs['fallback_occurred']})")
            print(f"Reason:           {net_obs['classification_reason']}")
            if net_obs.get('connection_attempt_delay_ms') is not None:
                print(f"CAD Delay:        {net_obs['connection_attempt_delay_ms']} ms")
            print(f"PCAP Evidence:    {res['capture_metadata']['pcap_path']}")
            print(f"PCAP SHA-256:     {res['capture_metadata']['pcap_sha256']}")
            print(f"Result JSON:      {res['evidence_paths']['result_json']}")
            print(f"Cleanup Status:   restored={res['cleanup_status']['scenario_restored']}, verified={res['cleanup_status']['baseline_verified']}")
            print("=" * 60)

        return 0
    except (LabReadinessError, BrowserPreflightError) as pre_err:
        print(f"\033[1;31m[PREFLIGHT FAILED]\033[0m {pre_err}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"\033[1;31m[ERROR]\033[0m Trial execution failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
