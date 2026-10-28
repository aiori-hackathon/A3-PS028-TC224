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
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.impair as impair
import lab.teardown as teardown

SCHEMA_VERSION = "1.0.0"
DEFAULT_SCENARIOS_PATH = SCRIPT_DIR / "scenarios.yaml"
DEFAULT_TRIALS_DIR = SCRIPT_DIR / "trials"
DNS_PID_FILE = SCRIPT_DIR / "dns.pid"
NGINX_PID_FILE = SCRIPT_DIR / "nginx.pid"
CLIENT_NETNS = "ps028-cl"
ROUTER_NETNS = "ps028-rt"
SERVER_NETNS = "ps028-sv"

ALLOWED_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]

KNOWN_BROWSER_BINARIES = [
    ("chromium", ["chromium", "chromium-browser"]),
    ("google-chrome", ["google-chrome", "google-chrome-stable", "chrome"]),
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
        v_str = _query_browser_version(path)
        return bname, path, v_str

    for bname, candidates in KNOWN_BROWSER_BINARIES:
        for cand in candidates:
            path = shutil.which(cand)
            if path:
                v_str = _query_browser_version(path)
                return bname, path, v_str

    raise BrowserPreflightError(
        "No supported browser runtime found in PATH (checked: chromium, google-chrome, firefox). "
        "Real browser measurement requires a genuine browser binary. "
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
                os.kill(pid, 0)
                dns_running = True
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
                os.kill(pid, 0)
                nginx_running = True
            except (OSError, ValueError):
                nginx_running = False
        report["checks"]["nginx"] = {"running": nginx_running}
        if not nginx_running:
            report["status"] = "FAIL"
            report["errors"].append("Measurement Nginx server is not running (nginx.pid inactive or missing)")

    # 6. Check baseline state
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

def _is_pid_alive(pid: int) -> bool:
    """
    Checks whether a process with the given PID is currently alive.
    Returns False if the process has already exited (ProcessLookupError/ESRCH).
    Returns True if the process exists or access is denied (PermissionError/EPERM).
    """
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True


def is_safe_capture_process(
    pid: int,
    is_parent: bool = False,
    proc_dir: Optional[Path] = None
) -> bool:
    """
    Verifies that the target PID belongs to the capture process before signaling.
    Fails closed: returns False if /proc identity files are missing, unreadable, or cannot
    verify the expected capture process.
    Never signals unrelated or recycled processes.
    Tightens parent identification to avoid substring matches.
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


def start_packet_capture(
    output_pcap: Path,
    log_file: Path,
    netns: str = CLIENT_NETNS,
    interface: str = "any",
    is_simulation: bool = False,
    readiness_timeout: float = 3.0
) -> Optional[subprocess.Popen]:
    """
    Starts an unbuffered, immediate-mode tcpdump packet capture process inside the target namespace.
    Captures DNS (port 53) and HTTP (port 80) traffic.
    Logs stderr statistics to log_file.
    Verifies process startup readiness before returning.
    If tcpdump exits prematurely or readiness times out, fails startup clearly and cleans up the process.
    Returns the running Popen process.
    """
    if is_simulation:
        return None

    # Filter captures only relevant DNS and IPv4/IPv6 TCP HTTP traffic
    bpf_filter = "port 53 or port 80"

    cmd = [
        "ip", "netns", "exec", netns,
        "tcpdump",
        "-i", interface,
        "-n",
        "--immediate-mode",
        "-U",
    ]
    if os.geteuid() == 0:
        cmd.extend(["-Z", "root"])
    cmd.extend([
        "-w", str(output_pcap.resolve()),
        bpf_filter
    ])

    log_fp = open(log_file, "w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=log_fp,
            start_new_session=True
        )
    except Exception as e:
        log_fp.close()
        raise TrialExecutionError(f"Failed to spawn tcpdump capture: {e}")

    # Attach open file descriptor to proc so stop_packet_capture can flush and close it
    proc._ps028_log_fp = log_fp
    proc._ps028_tcpdump_pid = None
    proc._ps028_pcap_path = None

    # Readiness check: poll until tcpdump logs that it is actively listening
    t0 = time.time()
    ready = False
    while time.time() - t0 < readiness_timeout:
        if proc.poll() is not None:
            if hasattr(proc, "_ps028_log_fp") and not proc._ps028_log_fp.closed:
                proc._ps028_log_fp.close()
            raise TrialExecutionError(
                f"tcpdump terminated prematurely with code {proc.returncode}. Check {log_file}."
            )
        if log_file.is_file():
            try:
                log_content = log_file.read_text(encoding="utf-8", errors="replace")
                if "listening on" in log_content:
                    ready = True
                    break
            except Exception:
                pass
        time.sleep(0.05)

    if not ready:
        if proc.poll() is not None:
            if hasattr(proc, "_ps028_log_fp") and not proc._ps028_log_fp.closed:
                proc._ps028_log_fp.close()
            raise TrialExecutionError(
                f"tcpdump terminated prematurely with code {proc.returncode}. Check {log_file}."
            )
        # Timeout occurred: fail capture startup clearly and clean up the process
        stop_packet_capture(proc, timeout=1.0)
        if hasattr(proc, "_ps028_log_fp") and not proc._ps028_log_fp.closed:
            try:
                proc._ps028_log_fp.close()
            except Exception:
                pass
        raise TrialExecutionError(
            f"tcpdump capture startup timed out waiting for readiness ('listening on' not observed within {readiness_timeout}s). Check {log_file}."
        )

    # Track actual tcpdump PID
    if isinstance(proc.pid, int):
        proc._ps028_tcpdump_pid = find_tcpdump_pid(proc.pid)
    else:
        proc._ps028_tcpdump_pid = proc.pid
    proc._ps028_pcap_path = Path(output_pcap)

    return proc


def stop_packet_capture(
    proc: Optional[subprocess.Popen],
    timeout: float = 5.0,
    pcap_path: Optional[Path] = None,
    verify_pcap: bool = True
) -> bool:
    """
    Gracefully stops the tcpdump capture process:
    1. Delivers SIGINT specifically to the tcpdump process to allow packet buffer
       flushing, PCAP trailer writing, and summary statistics output.
    2. Waits for tcpdump to exit and finalize PCAP.
    3. Reaps proc.
    4. Escalates to SIGTERM / SIGKILL only if graceful shutdown times out.
    5. Does not signal unrelated processes.
    6. Flushes and closes the associated log file descriptor.
    7. Confirms that tcpdump has fully exited and PCAP file is finalized.
    Returns True on confirmed successful shutdown, or raises CaptureShutdownError.
    """
    if proc is None:
        return True

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
            if is_safe_capture_process(tcpdump_pid, is_parent=(tcpdump_pid == proc_pid)):
                try:
                    os.kill(tcpdump_pid, signal.SIGINT)
                    signaled = True
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
                if is_safe_capture_process(proc_pid, is_parent=True):
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
                if not _is_pid_alive(tcpdump_pid):
                    tcpdump_done = True
                    break
                time.sleep(0.05)
        else:
            # tcpdump is proc
            while time.time() - t0 < timeout:
                if proc.poll() is not None or not _is_pid_alive(proc_pid):
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
                    if is_safe_capture_process(p, is_parent=(p == proc_pid)):
                        try:
                            os.kill(p, signal.SIGTERM)
                        except (ProcessLookupError, OSError):
                            pass
                    elif _is_pid_alive(p):
                        unrelated_detected = True
                        impair.log_warn(f"Refusing to signal PID {p} with SIGTERM: unrelated process")

            if hasattr(proc, "terminate") and proc.poll() is None:
                if isinstance(proc_pid, int):
                    if is_safe_capture_process(proc_pid, is_parent=True):
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
                        if is_safe_capture_process(p, is_parent=(p == proc_pid)):
                            try:
                                os.kill(p, signal.SIGKILL)
                            except (ProcessLookupError, OSError):
                                pass
                        elif _is_pid_alive(p):
                            unrelated_detected = True
                            impair.log_warn(f"Refusing to signal PID {p} with SIGKILL: unrelated process")

                if hasattr(proc, "kill") and proc.poll() is None:
                    if isinstance(proc_pid, int):
                        if is_safe_capture_process(proc_pid, is_parent=True):
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


def dissect_pcap(pcap_path: Path, target_hostname: str) -> Dict[str, Any]:
    """
    Dissects a PCAP capture using tshark, extracting:
    - DNS queries and answers for target_hostname
    - IPv6 TCP connection attempts (SYN packets to 2001:db8:2::10:80)
    - IPv4 TCP connection attempts (SYN packets to 10.0.2.10:80)
    - Connection handshake completions (SYN-ACK / ACK)
    - Observed HTTP response codes
    """
    result: Dict[str, Any] = {
        "dns": {
            "queries": [],
            "responses": []
        },
        "ipv6": {
            "syn_count": 0,
            "first_syn_time": None,
            "syn_ack_received": False,
            "syn_ack_time": None,
            "rst_received": False,
            "connection_established": False,
            "http_observed": False
        },
        "ipv4": {
            "syn_count": 0,
            "first_syn_time": None,
            "syn_ack_received": False,
            "syn_ack_time": None,
            "rst_received": False,
            "connection_established": False,
            "http_observed": False
        },
        "connection_attempt_delay_ms": None,
        "connection_setup_time_ms": None,
        "http_status_code": None,
        "http_response_family": None,
    }

    tshark = shutil.which("tshark")
    if not tshark or not pcap_path.is_file():
        # Fallback binary inspection if tshark is absent
        if pcap_path.is_file():
            try:
                raw_data = pcap_path.read_bytes()
                m = re.search(rb"HTTP/1\.[01]\s+(\d{3})", raw_data)
                if m:
                    result["http_status_code"] = int(m.group(1))
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
        "http.response.code"
    ]
    cmd = [tshark, "-r", str(pcap_path), "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0, check=False)
        lines = proc.stdout.splitlines()
    except Exception:
        return result

    hostname_clean = target_hostname.lower().rstrip(".")

    for line in lines:
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts.extend([""] * (len(fields) - len(parts)))

        (t_epoch_str, ip_src, ip_dst, ip6_src, ip6_dst, tcp_flags_str,
         tcp_sport_str, tcp_dport_str, dns_qname, dns_qtype, dns_resp_flag,
         dns_a, dns_aaaa, http_code) = parts[:14]

        try:
            t_epoch = float(t_epoch_str) if t_epoch_str else None
        except ValueError:
            t_epoch = None

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

        # 2. TCP parsing
        if tcp_flags_str:
            try:
                flags = int(tcp_flags_str, 16)
            except ValueError:
                flags = 0

            is_syn = bool(flags & 0x02) and not bool(flags & 0x10)
            is_synack = bool(flags & 0x12 == 0x12)
            is_rst = bool(flags & 0x04)
            is_ack = bool(flags & 0x10) and not bool(flags & 0x02)

            # IPv6 traffic
            if ip6_dst == SERVER_IPV6 or ip6_src == SERVER_IPV6:
                if is_syn and ip6_dst == SERVER_IPV6:
                    result["ipv6"]["syn_count"] += 1
                    if result["ipv6"]["first_syn_time"] is None:
                        result["ipv6"]["first_syn_time"] = t_epoch
                elif is_synack and ip6_src == SERVER_IPV6:
                    result["ipv6"]["syn_ack_received"] = True
                    result["ipv6"]["syn_ack_time"] = t_epoch
                    result["ipv6"]["connection_established"] = True
                elif is_rst and ip6_src == SERVER_IPV6:
                    result["ipv6"]["rst_received"] = True

                if http_code:
                    result["ipv6"]["http_observed"] = True
                    try:
                        code_val = int(http_code.split(",")[0].strip())
                        if result["http_status_code"] is None:
                            result["http_status_code"] = code_val
                            result["http_response_family"] = "IPv6"
                    except ValueError:
                        pass

            # IPv4 traffic
            if ip_dst == SERVER_IPV4 or ip_src == SERVER_IPV4:
                if is_syn and ip_dst == SERVER_IPV4:
                    result["ipv4"]["syn_count"] += 1
                    if result["ipv4"]["first_syn_time"] is None:
                        result["ipv4"]["first_syn_time"] = t_epoch
                elif is_synack and ip_src == SERVER_IPV4:
                    result["ipv4"]["syn_ack_received"] = True
                    result["ipv4"]["syn_ack_time"] = t_epoch
                    result["ipv4"]["connection_established"] = True
                elif is_rst and ip_src == SERVER_IPV4:
                    result["ipv4"]["rst_received"] = True

                if http_code:
                    result["ipv4"]["http_observed"] = True
                    try:
                        code_val = int(http_code.split(",")[0].strip())
                        if result["http_status_code"] is None:
                            result["http_status_code"] = code_val
                            result["http_response_family"] = "IPv4"
                    except ValueError:
                        pass

    # Binary fallback inspection for HTTP response status code in raw PCAP data
    if result["http_status_code"] is None and pcap_path.is_file():
        try:
            raw_data = pcap_path.read_bytes()
            match = re.search(rb"HTTP/1\.[01]\s+(\d{3})", raw_data)
            if match:
                result["http_status_code"] = int(match.group(1))
        except Exception:
            pass

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
    failure_reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Classifies Happy Eyeballs connection behavior strictly per PS-028 rules:
    - Fallback to IPv4 is classified ONLY when packet or connection evidence confirms:
      1. IPv6 attempt (IPv6 TCP SYN observed in captured traffic)
      2. IPv4 attempt (IPv4 TCP SYN observed in captured traffic)
      3. Successful IPv4 connection (IPv4 SYN-ACK / HTTP response observed in captured traffic)
    - Never infers fallback from HTTP 200 alone.
    - Invalid PCAP or zero-packet capture forces INCONCLUSIVE and invalidates network evidence.
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
        }

    ipv6_attempt = dissection["ipv6"]["syn_count"] > 0
    ipv4_attempt = dissection["ipv4"]["syn_count"] > 0

    ipv4_conn_ok = dissection["ipv4"]["connection_established"] or dissection["ipv4"]["http_observed"]
    ipv6_conn_ok = dissection["ipv6"]["connection_established"] or dissection["ipv6"]["http_observed"]

    # Incorporate HTTP outcome only when supported by packet connection evidence
    http_success = http_outcome.get("success", False)
    winning_family = http_outcome.get("winning_address_family")

    if winning_family == "IPv4" and http_success and dissection["ipv4"]["connection_established"]:
        ipv4_conn_ok = True
    elif winning_family == "IPv6" and http_success and dissection["ipv6"]["connection_established"]:
        ipv6_conn_ok = True

    fallback_occurred = False
    classification = "INCONCLUSIVE"
    reason = "Insufficient evidence to classify connection behavior"

    if ipv6_attempt and ipv4_attempt and ipv4_conn_ok:
        fallback_occurred = True
        classification = "IPV6_TO_IPV4_FALLBACK"
        cad = dissection.get("connection_attempt_delay_ms")
        cad_desc = f" (Connection Attempt Delay: {cad}ms)" if cad is not None else ""
        reason = (
            f"Observed initial IPv6 connection attempt, followed by IPv4 attempt "
            f"and successful IPv4 connection{cad_desc}."
        )
    elif ipv6_conn_ok and not ipv4_attempt:
        fallback_occurred = False
        classification = "DIRECT_IPV6"
        reason = "Direct IPv6 connection established successfully without IPv4 fallback."
    elif ipv4_conn_ok and not ipv6_attempt:
        # Crucial PS-028 invariant: HTTP 200 on IPv4 without IPv6 attempt is NOT fallback!
        fallback_occurred = False
        classification = "DIRECT_IPV4"
        reason = (
            "Direct IPv4 connection established without prior IPv6 attempt. "
            "Per PS-028 specification, fallback is not inferred from HTTP 200 alone."
        )
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
    }


# ------------------------------------------------------------------------------
# Real Browser Execution Controller
# ------------------------------------------------------------------------------

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

    # Construct browser command per browser family
    cmd = ["ip", "netns", "exec", netns, browser_path]

    bname = browser_name.lower()
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
            "--disable-sync",
            "--disable-translate",
            "--disable-default-apps",
            f"--timeout={int(timeout * 1000)}",
        ])
    elif "firefox" in bname:
        cmd.extend([
            "--headless",
            "--profile", str(profile_dir.resolve()),
            "--no-remote",
        ])

    if extra_args:
        cmd.extend(extra_args)

    cmd.append(target_url)

    t0 = time.time()
    timed_out = False
    stdout = ""
    stderr = ""
    exit_code = -1

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        exit_code = 124
        stdout = (e.stdout or b"").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = (e.stderr or b"").decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
    except Exception as e:
        exit_code = -1
        stderr = f"Browser execution exception: {e}"

    duration_ms = round((time.time() - t0) * 1000.0, 2)

    # Determine HTTP status code and winning address family
    # Chrome --dump-dom exit code 0 does not prove HTTP 200.
    # Status code is extracted from packet evidence; if unavailable, remains None (null/unknown).
    http_status = None
    success = (exit_code == 0 and not timed_out and len(stdout.strip()) > 0)
    winning_family = None

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
        "winning_family": winning_family
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

    # IPv6 RST
    tcp_rst_v6 = struct.pack("!HHIIBBHHH", 80, 50000, 0, 1001, (5 << 4), 0x04, 0, 0, 0)

    # IPv4 SYN
    ip4_hdr_syn = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, ip4_cl, ip4_sv)
    tcp_syn_v4 = struct.pack("!HHIIBBHHH", 50001, 80, 3000, 0, (5 << 4), 0x02, 65535, 0, 0)

    # IPv4 SYN-ACK
    ip4_hdr_synack = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 2, 0, 64, 6, 0, ip4_sv, ip4_cl)
    tcp_synack_v4 = struct.pack("!HHIIBBHHH", 80, 50001, 4000, 3001, (5 << 4), 0x12, 65535, 0, 0)

    sc = scenario_id.upper()
    if sc == "S0":
        # Healthy baseline: IPv6 wins immediately
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v6 + ip6_hdr_synack + tcp_synack_v6, 30.0)
        winning_fam = "IPv6"
        winning_ip = SERVER_IPV6
    elif sc == "S1":
        # IPv6 SYN blackhole: IPv6 dropped, IPv4 CAD ~250ms wins
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 260.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 280.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S2":
        # IPv6 TCP RST: Immediate reset triggers immediate IPv4
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v6 + ip6_hdr_synack[:40] + tcp_rst_v6, 30.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 32.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 52.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S3":
        # IPv6 150ms: IPv6 completes in 150ms before IPv4 CAD (250ms)
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v6 + ip6_hdr_synack + tcp_synack_v6, 160.0)
        winning_fam = "IPv6"
        winning_ip = SERVER_IPV6
    elif sc == "S4":
        # IPv6 600ms: IPv4 CAD fires at 250ms and wins in 20ms
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 260.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 280.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S5":
        # IPv6 SYN loss: 50% loss causes IPv4 fallback
        add_pkt(eth_v6 + ip6_hdr_syn + tcp_syn_v6, 10.0)
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 260.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 280.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    elif sc == "S6":
        # AAAA delayed 500ms: A arrives at 0ms, IPv4 starts after ~50ms resolution delay
        add_pkt(eth_v4 + ip4_hdr_syn + tcp_syn_v4, 60.0)
        add_pkt(eth_v4 + ip4_hdr_synack + tcp_synack_v4, 80.0)
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4
    else:
        winning_fam = "IPv4"
        winning_ip = SERVER_IPV4

    # Add simulated HTTP GET request and 200 OK response for the winning family
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 42\r\n"
        b"\r\n"
        b"<html><body>Measurement OK</body></html>"
    )
    if winning_fam == "IPv6":
        ip6_hdr_resp = struct.pack("!IHBB", 0x60000000, 20 + len(http_resp), 6, 64) + ip6_sv + ip6_cl
        tcp_resp_v6 = struct.pack("!HHIIBBHHH", 80, 50000, 2001, 1001, (5 << 4), 0x18, 65535, 0, 0)
        add_pkt(eth_v6 + ip6_hdr_resp + tcp_resp_v6 + http_resp, 35.0 if sc != "S3" else 165.0)
    else:
        ip4_hdr_resp = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(http_resp), 3, 0, 64, 6, 0, ip4_sv, ip4_cl)
        tcp_resp_v4 = struct.pack("!HHIIBBHHH", 80, 50001, 4001, 3001, (5 << 4), 0x18, 65535, 0, 0)
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
    lock_timeout: float = 10.0
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
                tcpdump_proc = start_packet_capture(
                    output_pcap=pcap_path,
                    log_file=tcpdump_log,
                    netns=CLIENT_NETNS,
                    is_simulation=False
                )

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
                    stop_packet_capture(tcpdump_proc, timeout=5.0, pcap_path=pcap_path)
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
                    stop_packet_capture(tcpdump_proc, pcap_path=pcap_path, verify_pcap=False)
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
                cleanup_errors.append(f"Impairment clear error: {ce}")

            try:
                baseline_verified = impair.self_test_baseline(dry_run=is_simulation)
            except Exception as ce:
                cleanup_errors.append(f"Baseline verify error: {ce}")

            if profile_dir.is_dir():
                try:
                    shutil.rmtree(profile_dir, ignore_errors=True)
                    profile_cleaned = True
                except Exception as ce:
                    cleanup_errors.append(f"Profile cleanup error: {ce}")
            else:
                profile_cleaned = True

        # 8. Validate and Dissect Packet Capture
        pcap_valid, pcap_sha256, pcap_size, pkt_count, pcap_msg = validate_pcap_file(pcap_path)
        dissection = dissect_pcap(pcap_path, target_hostname=hostname)

        # Update HTTP outcome with evidence from packet dissection
        observed_http_code = dissection.get("http_status_code")
        if observed_http_code is not None:
            http_outcome["status_code"] = observed_http_code
            http_outcome["success"] = (200 <= observed_http_code < 400)
            if dissection.get("http_response_family"):
                http_outcome["winning_address_family"] = dissection["http_response_family"]
                http_outcome["winning_ip"] = (
                    SERVER_IPV6 if dissection["http_response_family"] == "IPv6" else SERVER_IPV4
                )
        else:
            if not is_simulation:
                http_outcome["status_code"] = None
                http_outcome["success"] = False
                http_outcome["winning_address_family"] = None
                http_outcome["winning_ip"] = None

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
                        "rst_received": False,
                        "connection_established": False,
                        "http_observed": False
                    },
                    "ipv4": {
                        "syn_count": 0,
                        "first_syn_time": None,
                        "syn_ack_received": False,
                        "syn_ack_time": None,
                        "rst_received": False,
                        "connection_established": False,
                        "http_observed": False
                    },
                    "connection_attempt_delay_ms": None,
                    "connection_setup_time_ms": None,
                    "http_status_code": None,
                    "http_response_family": None,
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
                    "rst_received": False,
                    "connection_established": False,
                    "http_observed": False
                },
                "ipv4": {
                    "syn_count": 0,
                    "first_syn_time": None,
                    "syn_ack_received": False,
                    "syn_ack_time": None,
                    "rst_received": False,
                    "connection_established": False,
                    "http_observed": False
                },
                "connection_attempt_delay_ms": None,
                "connection_setup_time_ms": None,
                "http_status_code": None,
                "http_response_family": None,
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
            failure_reason=fail_reason
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
                "pcap_path": str(pcap_path),
                "pcap_sha256": pcap_sha256,
                "pcap_size_bytes": pcap_size,
                "pcap_valid": pcap_valid,
                "packet_count": pkt_count,
                "validation_message": pcap_msg,
                "tcpdump_log_path": str(tcpdump_log)
            },
            "evidence_paths": {
                "trial_dir": str(tdir),
                "result_json": str(result_json_path),
                "capture_pcap": str(pcap_path),
                "tcpdump_log": str(tcpdump_log),
                "browser_log": str(browser_log)
            },
            "cleanup_status": {
                "scenario_restored": scenario_restored,
                "baseline_verified": baseline_verified,
                "profile_cleaned": profile_cleaned,
                "lock_released": True,
                "errors": cleanup_errors
            }
        }

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
            skip_baseline_check=args.skip_baseline_check
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
