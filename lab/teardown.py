#!/usr/bin/env python3
"""
PS-028 Safe Lab Teardown Controller
Work Package A6: PS-028 Lab Hardening

Orchestrates safe, ordered, and idempotent destruction of PS-028 resources:
1. Concurrency: Exclusively acquires lab lock (.lab.lock)
2. Topology Detection & Idempotence:
   - When topology is absent: skips impossible namespace operations and live baseline checks,
     explicitly reporting that the lab is absent without claiming baseline verification.
   - When topology is live or partial: restores impairments and baseline delays safely.
3. Restoration Safety:
   - Never deletes a live or partial topology when restoration fails or an active scenario
     cannot be safely cleared (unless separate verification proves the lab is at baseline).
4. DNS Reconciliation:
   - Reconciles lingering DNS backups (.impair_bak, .bak, .tmp.*) and resets delays to 0ms baseline.
5. Process Stoppage:
   - Stops only verified project-managed services (DNS server, Nginx) after validating cmdline & netns.
6. Resolver Cleanup:
   - Cleans only project-owned resolver files (/etc/netns/ps028-cl/resolv.conf) if marked as PS-028 owned.
7. Interface & Namespace Cleanup:
   - Removes only project namespaces and dangling project interfaces, preserving all unrelated host resources.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.impair as impair

DNS_PID_FILE = SCRIPT_DIR / "dns.pid"
NGINX_PID_FILE = SCRIPT_DIR / "nginx.pid"
RESOLV_MARKER = SCRIPT_DIR / ".resolv_installed_by_ps028"
NETNS_RESOLV_FILE = Path("/etc/netns/ps028-cl/resolv.conf")
NETNS_RESOLV_DIR = Path("/etc/netns/ps028-cl")
RESOLV_SOURCE = SCRIPT_DIR / "cl_resolv.conf"

PROJECT_NAMESPACES = ["ps028-cl", "ps028-rt", "ps028-sv"]
PROJECT_INTERFACES = [
    "ps028-cl-rt", "ps028-rt-cl",
    "ps028-rt-sv4", "ps028-sv-rt4",
    "ps028-rt-sv6", "ps028-sv-rt6",
]


def get_existing_namespaces() -> List[str]:
    """Return list of existing network namespaces on the host."""
    run_netns = Path("/run/netns")
    if run_netns.is_dir():
        try:
            entries = [p.name for p in run_netns.iterdir()]
            if entries:
                return entries
        except Exception:
            pass

    try:
        rc, stdout, _ = impair.execute_cmd(["ip", "netns", "list"], dry_run=False, check=False)
        if rc == 0:
            return [line.strip().split()[0] for line in stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return []


def get_topology_status(
    namespaces: Optional[List[str]] = None,
    existing_namespaces: Optional[List[str]] = None
) -> Tuple[str, List[str], List[str]]:
    """
    Check the presence of project namespaces.
    Returns: (status, present_namespaces, absent_namespaces)
    status is one of: "ABSENT", "PARTIAL", "LIVE"
    """
    target = namespaces if namespaces is not None else PROJECT_NAMESPACES
    existing = set(existing_namespaces if existing_namespaces is not None else get_existing_namespaces())
    present = [ns for ns in target if ns in existing]
    absent = [ns for ns in target if ns not in existing]

    if not present:
        status = "ABSENT"
    elif len(present) == len(target):
        status = "LIVE"
    else:
        status = "PARTIAL"
    return status, present, absent


def verify_process_identity(pid: int, expected_service: str) -> Tuple[bool, Optional[str]]:
    """
    Verify if process PID corresponds to the expected project service.
    Returns: (is_verified, reason_if_not)
    """
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, OSError):
        return False, "stale_pid"

    try:
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        if not cmdline_path.is_file():
            return False, "stale_pid"
        raw_bytes = cmdline_path.read_bytes()
        args = [a.decode("utf-8", errors="replace") for a in raw_bytes.split(b"\x00") if a]
    except Exception as e:
        return False, f"cannot_read_cmdline:{e}"

    cmdline_str = " ".join(args)

    if "DNS" in expected_service:
        if not any("dns_server.py" in arg for arg in args):
            return False, f"cmdline_mismatch:expected dns_server.py in '{cmdline_str}'"
        netns_path = Path("/run/netns/ps028-rt")
        if netns_path.exists():
            try:
                proc_ns = os.stat(f"/proc/{pid}/ns/net").st_ino
                target_ns = os.stat(netns_path).st_ino
                if proc_ns != target_ns:
                    return False, f"netns_mismatch:PID in netns {proc_ns}, expected ps028-rt ({target_ns})"
            except Exception:
                pass
        return True, None

    elif "Nginx" in expected_service or "nginx" in expected_service:
        is_nginx_bin = any("nginx" in Path(arg).name for arg in args)
        has_conf = any("nginx.conf" in arg for arg in args)
        if not (is_nginx_bin and has_conf):
            return False, f"cmdline_mismatch:expected nginx with nginx.conf in '{cmdline_str}'"
        netns_path = Path("/run/netns/ps028-sv")
        if netns_path.exists():
            try:
                proc_ns = os.stat(f"/proc/{pid}/ns/net").st_ino
                target_ns = os.stat(netns_path).st_ino
                if proc_ns != target_ns:
                    return False, f"netns_mismatch:PID in netns {proc_ns}, expected ps028-sv ({target_ns})"
            except Exception:
                pass
        return True, None

    return False, f"unknown_service:{expected_service}"


def stop_process_by_pid_file(
    pid_file: Path,
    process_name: str,
    dry_run: bool = False,
    verifier: Optional[Callable[[int, str], Tuple[bool, Optional[str]]]] = None
) -> Tuple[bool, Optional[str]]:
    """Terminate process recorded in pid_file safely, only after identity verification."""
    if not pid_file.is_file():
        return True, None

    try:
        pid_text = pid_file.read_text(encoding="utf-8").strip()
        if not pid_text or not pid_text.isdigit():
            if not dry_run:
                pid_file.unlink(missing_ok=True)
            return True, None
        pid = int(pid_text)
    except Exception as e:
        return False, f"Error reading PID from {pid_file}: {e}"

    if dry_run:
        impair.log_info(f"[DRY-RUN] Would terminate {process_name} (PID {pid}) and unlink {pid_file.name}")
        return True, None

    # Verify process identity
    verify_fn = verifier or verify_process_identity
    verified, reason = verify_fn(pid, process_name)
    if not verified:
        if reason == "stale_pid":
            pid_file.unlink(missing_ok=True)
            impair.log_info(f"Cleaned stale PID file for inactive {process_name} (PID {pid}).")
            return True, None
        else:
            # PID belongs to an unrelated process! Refuse to terminate!
            impair.log_warn(
                f"PID {pid} in {pid_file.name} is not a verified {process_name} ({reason}). "
                "Refusing to terminate unrelated process."
            )
            pid_file.unlink(missing_ok=True)
            return True, None

    # Send SIGTERM
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.2)
        try:
            os.kill(pid, 0)
            time.sleep(0.3)
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    except ProcessLookupError:
        pass
    except Exception as e:
        return False, f"Failed to signal {process_name} (PID {pid}): {e}"

    pid_file.unlink(missing_ok=True)
    impair.log_ok(f"Stopped verified {process_name} (PID {pid}).")
    return True, None


def clean_owned_resolver(
    marker_file: Path = RESOLV_MARKER,
    resolv_file: Path = NETNS_RESOLV_FILE,
    resolv_source: Path = RESOLV_SOURCE,
    dry_run: bool = False
) -> Tuple[bool, Optional[str]]:
    """Clean resolver configuration only if installed and owned by PS-028."""
    if not marker_file.is_file():
        impair.log_info("No project resolver marker found; leaving external resolver untouched.")
        return True, None

    if dry_run:
        impair.log_info(f"[DRY-RUN] Would remove owned resolver file {resolv_file} and marker {marker_file.name}")
        return True, None

    try:
        if resolv_file.is_file():
            # Invariance check: verify it matches our source before deleting
            matches = False
            try:
                if resolv_source.is_file():
                    matches = (resolv_file.read_bytes() == resolv_source.read_bytes())
            except Exception:
                pass

            if matches or not resolv_source.is_file():
                try:
                    resolv_file.unlink(missing_ok=True)
                    impair.log_ok(f"Removed owned resolver configuration {resolv_file}.")
                except PermissionError:
                    impair.log_warn(f"Permission denied deleting {resolv_file}; skipping (requires root).")
                    return True, None

                if resolv_file.parent.is_dir():
                    try:
                        resolv_file.parent.rmdir()
                    except OSError:
                        pass
            else:
                impair.log_warn(f"{resolv_file} was modified externally; preserving file.")

        try:
            marker_file.unlink(missing_ok=True)
        except PermissionError:
            impair.log_warn(f"Permission denied deleting {marker_file}; skipping (requires root).")
            return True, None

        return True, None
    except Exception as e:
        return False, f"Error cleaning resolver configuration: {e}"


def reconcile_dns_backups(
    script_dir: Optional[Path] = None,
    config_file: Optional[Path] = None,
    dry_run: bool = False
) -> Tuple[bool, List[str]]:
    """
    Safely reconcile any lingering DNS backups (.impair_bak, .bak, .tmp.*),
    restoring clean baseline configuration (0ms delays for A and AAAA).
    """
    failures = []
    target_dir = script_dir or SCRIPT_DIR
    cfg_path = config_file or (target_dir / "dns_config.json")

    # 1. Check for backups in priority order
    for bak_name in ("dns_config.json.impair_bak", "dns_config.json.bak"):
        bak_file = target_dir / bak_name
        if bak_file.is_file():
            if dry_run:
                impair.log_info(f"[DRY-RUN] Would reconcile {bak_name} to {cfg_path.name}")
            else:
                try:
                    with open(bak_file, "r", encoding="utf-8") as f:
                        bak_data = json.load(f)
                    impair.validate_dns_dict(bak_data)
                    shutil.copyfile(bak_file, cfg_path)
                    bak_file.unlink(missing_ok=True)
                    impair.log_ok(f"Restored and reconciled {cfg_path.name} from {bak_name}")
                except Exception as e:
                    failures.append(f"restore_dns_backup:{bak_name}:{e}")

    # 2. Clean lingering tmp files
    try:
        for tmp_file in target_dir.glob("dns_config.json.*.tmp*"):
            if tmp_file.is_file() and not dry_run:
                try:
                    tmp_file.unlink(missing_ok=True)
                except Exception:
                    pass
    except Exception:
        pass

    # 3. Ensure baseline rules in active dns_config.json
    if cfg_path.is_file():
        try:
            cfg = impair.load_dns_config(path=cfg_path)
            rules = cfg.get("rules", {})
            a_delay = rules.get("A", {}).get("delay_ms", 0)
            aaaa_delay = rules.get("AAAA", {}).get("delay_ms", 0)
            if a_delay != 0 or aaaa_delay != 0:
                if dry_run:
                    impair.log_info("[DRY-RUN] Would reset non-zero DNS delays to 0ms baseline")
                else:
                    cfg["rules"]["A"]["delay_ms"] = 0
                    cfg["rules"]["AAAA"]["delay_ms"] = 0
                    impair.save_dns_config_atomically(cfg, path=cfg_path, dry_run=False)
                    impair.log_ok(f"Reset non-zero DNS delays to 0ms baseline in {cfg_path.name}")
        except Exception as e:
            failures.append(f"reconcile_dns_config_baseline:{e}")

    return len(failures) == 0, failures


def remove_project_topology(
    namespaces: List[str] = PROJECT_NAMESPACES,
    interfaces: List[str] = PROJECT_INTERFACES,
    dry_run: bool = False
) -> List[str]:
    """Remove project network namespaces and dangling interfaces."""
    failures = []

    # 1. Delete Namespaces
    for ns in namespaces:
        if dry_run:
            impair.log_info(f"[DRY-RUN] Would delete namespace: {ns}")
            continue

        rc, _, stderr = impair.execute_cmd(["ip", "netns", "del", ns], check=False)
        if rc == 0:
            impair.log_ok(f"Deleted project namespace: {ns}")
        elif "No such file or directory" in stderr or "Cannot remove namespace" in stderr:
            pass  # Already absent
        else:
            impair.log_error(f"Failed to delete namespace {ns}: {stderr.strip()}")
            failures.append(f"namespace:{ns}")
            # If namespace deletion failed, clean any project interfaces inside it
            for iface in interfaces:
                chk_rc, _, _ = impair.execute_cmd(["ip", "-n", ns, "link", "show", iface], check=False)
                if chk_rc == 0:
                    del_rc, _, del_err = impair.execute_cmd(["ip", "-n", ns, "link", "del", iface], check=False)
                    if del_rc != 0:
                        failures.append(f"interface:{ns}/{iface}")

    # 2. Delete dangling interfaces in host namespace
    for iface in interfaces:
        if dry_run:
            impair.log_info(f"[DRY-RUN] Would check and delete host interface: {iface}")
            continue

        rc, _, _ = impair.execute_cmd(["ip", "link", "show", iface], check=False)
        if rc == 0:
            del_rc, _, del_err = impair.execute_cmd(["ip", "link", "del", iface], check=False)
            if del_rc == 0:
                impair.log_ok(f"Deleted dangling host interface: {iface}")
            else:
                impair.log_error(f"Failed to delete dangling host interface {iface}: {del_err.strip()}")
                failures.append(f"interface:{iface}")

    return failures


def is_lab_at_baseline(dry_run: bool = False, verify_fn: Optional[Callable[..., bool]] = None) -> bool:
    """
    Separate verification proving the lab is already at baseline.
    Returns True if baseline is verified, False otherwise.
    """
    verifier = verify_fn or impair.self_test_baseline
    try:
        return bool(verifier(dry_run=dry_run))
    except Exception as e:
        impair.log_error(f"Baseline verification failed with exception: {e}")
        return False


def teardown_lab(
    dry_run: bool = False,
    lock_file: Optional[Path] = None,
    lock_timeout: float = 5.0,
    verify_baseline_fn: Optional[Callable[..., bool]] = None,
    namespaces: Optional[List[str]] = None,
    interfaces: Optional[List[str]] = None,
    existing_namespaces: Optional[List[str]] = None,
    process_verifier: Optional[Callable[[int, str], Tuple[bool, Optional[str]]]] = None,
) -> Dict[str, Any]:
    """
    Execute complete safe teardown under exclusive lab-wide lock.
    Returns structured results dict.
    """
    target_lock = Path(lock_file or concurrency.DEFAULT_LAB_LOCK_FILE).resolve()
    target_namespaces = namespaces if namespaces is not None else PROJECT_NAMESPACES
    target_interfaces = interfaces if interfaces is not None else PROJECT_INTERFACES
    failures: List[str] = []

    impair.log_info(f"Initiating safe teardown (dry_run={dry_run})...")

    with concurrency.acquire_lab_lock(timeout=lock_timeout, lock_path=target_lock):
        # Determine topology state
        topo_status, present_ns, absent_ns = get_topology_status(
            namespaces=target_namespaces,
            existing_namespaces=existing_namespaces
        )

        restoration_failed = False
        active_scenario_uncleared = False
        can_delete_namespaces = True

        # Check if an active scenario exists before teardown
        prior_state = impair.get_current_state()
        has_active_scenario = (prior_state is not None and bool(prior_state.get("active_scenario")))

        if topo_status == "ABSENT":
            impair.log_info("Lab topology is absent; skipping namespace operations and live baseline checks.")
            # Reconcile DNS backups
            dns_reconciled, dns_failures = reconcile_dns_backups(dry_run=dry_run)
            if not dns_reconciled:
                failures.extend(dns_failures)
                restoration_failed = True

            # Clear state file if lingering
            state_file = SCRIPT_DIR / ".impair_state.json"
            if state_file.is_file():
                if not dry_run:
                    try:
                        state_file.unlink(missing_ok=True)
                    except Exception as e:
                        failures.append(f"clear_state_file:{e}")
                        active_scenario_uncleared = True
        else:
            # Stage 1: Restore Impairments & DNS Baseline (LIVE or PARTIAL)
            impair.log_info(f"Teardown Stage 1: Restoring impairments and DNS (topology {topo_status})...")
            try:
                impair.clear_impairments(dry_run=dry_run, lock_file=target_lock, lock_timeout=lock_timeout)
            except Exception as e:
                impair.log_error(f"Error during impairment clear: {e}")
                failures.append(f"impairments_clear:{e}")
                restoration_failed = True

            # Reconcile lingering DNS backups
            dns_reconciled, dns_failures = reconcile_dns_backups(dry_run=dry_run)
            if not dns_reconciled:
                failures.extend(dns_failures)
                restoration_failed = True

            # Clear state file if lingering
            state_file = SCRIPT_DIR / ".impair_state.json"
            if state_file.is_file():
                if not dry_run:
                    try:
                        state_file.unlink(missing_ok=True)
                    except Exception as e:
                        failures.append(f"clear_state_file:{e}")
                        restoration_failed = True

            # Verify active scenario was cleared
            post_state = impair.get_current_state()
            if has_active_scenario and post_state is not None:
                impair.log_error(
                    f"Active scenario '{post_state.get('active_scenario')}' could not be cleared."
                )
                active_scenario_uncleared = True

            # Check shared-lock safety: Never delete live or partial topology if restoration failed
            # or active scenario cannot be safely cleared
            if restoration_failed or active_scenario_uncleared:
                if topo_status == "LIVE" and not active_scenario_uncleared:
                    impair.log_warn("Impairment/DNS restoration failed. Verifying whether lab is already at baseline...")
                    baseline_verified = is_lab_at_baseline(dry_run=dry_run, verify_fn=verify_baseline_fn)
                    if not baseline_verified:
                        impair.log_error(
                            "Lab baseline could not be verified following restoration failure. "
                            "Aborting namespace deletion to prevent inconsistent state."
                        )
                        failures.append("abort_topology_deletion:baseline_not_verified")
                        can_delete_namespaces = False
                    else:
                        impair.log_ok("Separate verification proved lab is already at baseline despite restoration failure.")
                else:
                    if active_scenario_uncleared:
                        impair.log_error(
                            "Active scenario could not be safely cleared. "
                            "Aborting topology deletion to prevent inconsistent state."
                        )
                        failures.append("abort_topology_deletion:active_scenario_not_cleared")
                    else:
                        impair.log_error(
                            "Restoration failed on partial topology. "
                            "Aborting namespace deletion to prevent inconsistent state."
                        )
                        failures.append("abort_topology_deletion:restoration_failed_partial_topology")
                    can_delete_namespaces = False

        # Stage 2: Stop Lab-Managed Services
        impair.log_info("Teardown Stage 2: Stopping verified lab-managed services...")
        dns_ok, dns_err = stop_process_by_pid_file(
            DNS_PID_FILE, "Controlled DNS Server", dry_run=dry_run, verifier=process_verifier
        )
        if not dns_ok:
            failures.append(f"stop_dns:{dns_err}")

        nginx_ok, nginx_err = stop_process_by_pid_file(
            NGINX_PID_FILE, "Nginx Measurement Endpoint", dry_run=dry_run, verifier=process_verifier
        )
        if not nginx_ok:
            failures.append(f"stop_nginx:{nginx_err}")

        # Stage 3: Clean Owned Resolver Configuration
        impair.log_info("Teardown Stage 3: Cleaning owned client resolver configuration...")
        resolv_ok, resolv_err = clean_owned_resolver(dry_run=dry_run)
        if not resolv_ok:
            failures.append(f"clean_resolver:{resolv_err}")

        # Stage 4: Remove Project Network Topology
        impair.log_info("Teardown Stage 4: Removing project network namespaces and interfaces...")
        if not can_delete_namespaces:
            impair.log_warn("Skipping removal of project network namespaces because restoration failed or active scenario could not be cleared.")
        elif topo_status == "ABSENT":
            # Only clean dangling host interfaces, skip namespace deletion calls
            dangling_failures = []
            for iface in target_interfaces:
                if dry_run:
                    impair.log_info(f"[DRY-RUN] Would check and delete host interface: {iface}")
                    continue
                rc, _, _ = impair.execute_cmd(["ip", "link", "show", iface], check=False)
                if rc == 0:
                    del_rc, _, del_err = impair.execute_cmd(["ip", "link", "del", iface], check=False)
                    if del_rc == 0:
                        impair.log_ok(f"Deleted dangling host interface: {iface}")
                    else:
                        impair.log_error(f"Failed to delete dangling host interface {iface}: {del_err.strip()}")
                        dangling_failures.append(f"interface:{iface}")
            failures.extend(dangling_failures)
        elif not dry_run and not impair.is_root():
            impair.log_warn("Removing network namespaces requires root; skipping live namespace deletion.")
        else:
            topo_failures = remove_project_topology(
                namespaces=target_namespaces,
                interfaces=target_interfaces,
                dry_run=dry_run
            )
            failures.extend(topo_failures)

    status = "SUCCESS" if len(failures) == 0 else "PARTIAL_FAILURE"
    if status == "SUCCESS":
        impair.log_ok("Teardown completed successfully. Unrelated host resources preserved.")
    else:
        impair.log_error(f"Teardown finished with errors: {failures}")

    return {
        "status": status,
        "failures": failures,
        "dry_run": dry_run,
        "topology_status": topo_status,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="PS-028 Safe Lab Teardown Controller")
    parser.add_argument("--dry-run", action="store_true", help="Simulate teardown without modifying live resources")
    args = parser.parse_args()

    try:
        result = teardown_lab(dry_run=args.dry_run)
        return 0 if result["status"] == "SUCCESS" else 1
    except concurrency.LabLockError as e:
        impair.log_error(f"Cannot execute teardown: {e}")
        return 1
    except Exception as e:
        impair.log_error(f"Teardown aborted unexpectedly: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
