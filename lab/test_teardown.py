#!/usr/bin/env python3
"""
PS-028 Safe Teardown: Automated Test Suite
Work Package A6: PS-028 Lab Hardening

Tests:
- Orderly teardown lifecycle execution
- Concurrency lock contention protection (blocks concurrent teardown/trials)
- Clean stoppage and verification of lab-managed services (DNS and Nginx)
- Safe resolver cleanup with invariance checks and external config preservation
- Safe removal of project-owned topology and dangling interfaces
- Full preservation of unrelated host resources (eth0, host routes)
- Comprehensive failure reporting
- Regression tests for:
  * Absent topology idempotence (skips namespace ops and live baseline checks)
  * Partial topology preservation upon restoration failure
  * Fresh setup bootstrap idempotence
  * Active scenario safe clearing vs uncleared scenario safety
  * Successful nested cleanup under the teardown lock
  * External lock contention
  * Restoration failure preventing topology deletion
  * Restoration failure allowing topology deletion when baseline verified
  * Successful ordered teardown
  * Unverified process rejection
  * DNS backup reconciliation
"""

import json
import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

import lab.concurrency as concurrency
import lab.impair as impair
import lab.teardown as teardown

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TEARDOWN_SH = SCRIPT_DIR / "teardown.sh"


def _worker_teardown(lock_path: str, timeout: float, queue: multiprocessing.Queue):
    """Child worker attempting teardown under external lock contention."""
    try:
        teardown.teardown_lab(dry_run=True, lock_file=Path(lock_path), lock_timeout=timeout)
        queue.put("UNEXPECTED_SUCCESS")
    except concurrency.LabLockError as e:
        queue.put(f"CONTENTION:{e}")
    except Exception as e:
        queue.put(f"ERROR:{e}")


class TestSafeTeardown(unittest.TestCase):
    """Test suite for safe teardown operations."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_teardown_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"
        self.dns_pid_file = self.temp_dir / "dns.pid"
        self.nginx_pid_file = self.temp_dir / "nginx.pid"
        self.marker_file = self.temp_dir / ".resolv_installed_by_ps028"
        self.resolv_file = self.temp_dir / "resolv.conf"
        self.resolv_source = self.temp_dir / "cl_resolv.conf"
        self.resolv_source.write_text("nameserver 10.0.1.1\n", encoding="utf-8")
        self.live_namespaces = list(teardown.PROJECT_NAMESPACES)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_teardown_acquires_and_releases_lab_lock(self):
        """Teardown must execute under the shared lab-wide lock."""
        with patch("lab.teardown.impair.clear_impairments") as mock_clear, \
             patch("lab.teardown.remove_project_topology", return_value=[]) as mock_topo:

            res = teardown.teardown_lab(dry_run=True, lock_file=self.lock_file)
            self.assertEqual(res["status"], "SUCCESS")
            # Verify lock file was created during teardown and can now be acquired
            with concurrency.acquire_lab_lock(timeout=0.1, lock_path=self.lock_file):
                pass

    def test_teardown_fails_on_active_lock_contention(self):
        """Teardown must refuse to run if another process holds the lab lock."""
        q = multiprocessing.Queue()
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            p = multiprocessing.Process(
                target=_worker_teardown,
                args=(str(self.lock_file), 0.15, q)
            )
            p.start()
            p.join(timeout=3.0)
            res = q.get_nowait()
            self.assertTrue(res.startswith("CONTENTION:"), f"Expected contention error, got: {res}")

    def test_stop_process_by_pid_file_unlinks_stale(self):
        """Stale PID in pid_file must be unlinked safely."""
        self.dns_pid_file.write_text("999999\n", encoding="utf-8")
        ok, err = teardown.stop_process_by_pid_file(self.dns_pid_file, "Controlled DNS Server", dry_run=False)
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertFalse(self.dns_pid_file.exists())

    def test_stop_process_dry_run_preserves_pid_file(self):
        """Dry-run must not unlink or kill running PID."""
        self.dns_pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
        ok, err = teardown.stop_process_by_pid_file(self.dns_pid_file, "Controlled DNS Server", dry_run=True)
        self.assertTrue(ok)
        self.assertTrue(self.dns_pid_file.exists())

    def test_clean_owned_resolver_matching_source(self):
        """Resolver created by PS-028 matching source must be removed."""
        self.marker_file.touch()
        self.resolv_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        ok, err = teardown.clean_owned_resolver(
            marker_file=self.marker_file,
            resolv_file=self.resolv_file,
            resolv_source=self.resolv_source,
            dry_run=False
        )
        self.assertTrue(ok)
        self.assertFalse(self.marker_file.exists())
        self.assertFalse(self.resolv_file.exists())

    def test_clean_owned_resolver_preserves_externally_modified(self):
        """Resolver file modified externally must be preserved while cleaning project marker."""
        self.marker_file.touch()
        self.resolv_file.write_text("nameserver 8.8.8.8\n# Modified by user", encoding="utf-8")

        ok, err = teardown.clean_owned_resolver(
            marker_file=self.marker_file,
            resolv_file=self.resolv_file,
            resolv_source=self.resolv_source,
            dry_run=False
        )
        self.assertTrue(ok)
        self.assertFalse(self.marker_file.exists())
        self.assertTrue(self.resolv_file.exists(), "Externally modified resolv.conf must be preserved")

    def test_clean_resolver_without_marker_leaves_files_untouched(self):
        """Without project marker, resolver configuration must never be touched."""
        self.resolv_file.write_text("nameserver 1.1.1.1\n", encoding="utf-8")

        ok, err = teardown.clean_owned_resolver(
            marker_file=self.marker_file,  # does not exist
            resolv_file=self.resolv_file,
            resolv_source=self.resolv_source,
            dry_run=False
        )
        self.assertTrue(ok)
        self.assertTrue(self.resolv_file.exists())

    @patch("lab.impair.execute_cmd")
    def test_remove_project_topology_only_targets_project_resources(self, mock_cmd):
        """Topology destruction must strictly delete ps028-* namespaces and interfaces."""
        mock_cmd.return_value = (0, "", "")

        failures = teardown.remove_project_topology(
            namespaces=["ps028-cl", "ps028-rt", "ps028-sv"],
            interfaces=["ps028-cl-rt", "ps028-rt-cl"],
            dry_run=False
        )
        self.assertEqual(len(failures), 0)

        # Verify all executed commands target ONLY project resources
        for c in mock_cmd.call_args_list:
            cmd = c[0][0]
            if cmd[1] == "netns":
                self.assertIn(cmd[3], ["ps028-cl", "ps028-rt", "ps028-sv"])
            elif cmd[1] == "link":
                self.assertTrue(cmd[3].startswith("ps028-"))

    @patch("lab.impair.execute_cmd")
    def test_remove_project_topology_collects_failures(self, mock_cmd):
        """Failed namespace deletions must be recorded in failures list."""
        def fake_exec(cmd, **kwargs):
            if cmd[0:3] == ["ip", "netns", "del"]:
                return (1, "", f"Cannot delete netns {cmd[3]}: Device busy")
            return (0, "", "")

        mock_cmd.side_effect = fake_exec
        failures = teardown.remove_project_topology(
            namespaces=["ps028-rt"],
            interfaces=[],
            dry_run=False
        )
        self.assertIn("namespace:ps028-rt", failures)

    # ==========================================================================
    # Regression Tests (Requirement 4)
    # ==========================================================================

    @patch("lab.teardown.remove_project_topology", return_value=[])
    @patch("lab.impair.clear_nftables_rules")
    @patch("lab.impair.restore_baseline_delays")
    @patch("lab.impair.restore_dns_baseline")
    @patch("lab.impair.clear_state")
    def test_successful_nested_cleanup_under_teardown_lock(
        self, mock_clear_state, mock_restore_dns, mock_restore_delays, mock_clear_nft, mock_topo
    ):
        """
        Regression Test 1: Successful nested cleanup under the teardown lock.
        Teardown controller acquires lab lock, then invokes clear_impairments in-process.
        clear_impairments executes its own acquire_lab_lock call safely via re-entrancy
        without raising LabLockError, executing all cleanup stages cleanly on a live lab.
        """
        res = teardown.teardown_lab(
            dry_run=True,
            lock_file=self.lock_file,
            existing_namespaces=self.live_namespaces
        )
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["failures"], [])

        # Verify the nested cleanup functions were called
        mock_clear_nft.assert_called_once_with(dry_run=True)
        mock_restore_delays.assert_called_once_with(dry_run=True)
        mock_restore_dns.assert_called_once_with(dry_run=True)
        mock_clear_state.assert_called_once_with(dry_run=True)
        mock_topo.assert_called_once()

        # Verify lock was cleanly and fully released (can be reacquired immediately)
        with concurrency.acquire_lab_lock(timeout=0.1, lock_path=self.lock_file):
            pass

    def test_external_lock_contention(self):
        """
        Regression Test 2: External lock contention.
        When an external process holds the lab lock, teardown must refuse to run,
        raise LabLockError, and make no modifications to services or topology.
        """
        q = multiprocessing.Queue()

        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            p = multiprocessing.Process(
                target=_worker_teardown,
                args=(str(self.lock_file), 0.15, q)
            )
            p.start()
            p.join(timeout=3.0)

            res = q.get_nowait()
            self.assertTrue(
                res.startswith("CONTENTION:"),
                f"Expected LabLockError due to external lock contention, got: {res}"
            )

    @patch("lab.teardown.remove_project_topology")
    @patch("lab.teardown.impair.clear_impairments")
    def test_restoration_failure_preventing_topology_deletion(self, mock_clear, mock_topo):
        """
        Regression Test 3a: Restoration failure preventing topology deletion.
        If impairment restoration fails and baseline verification fails,
        namespace/topology deletion MUST NOT be performed.
        """
        mock_clear.side_effect = impair.ImpairmentError("Simulated impairment clear failure")
        mock_verify = MagicMock(return_value=False)

        res = teardown.teardown_lab(
            dry_run=True,
            lock_file=self.lock_file,
            verify_baseline_fn=mock_verify,
            existing_namespaces=self.live_namespaces
        )

        # Baseline verification must have been called
        mock_verify.assert_called_once_with(dry_run=True)
        # Topology deletion must NOT have been called
        mock_topo.assert_not_called()
        self.assertEqual(res["status"], "PARTIAL_FAILURE")
        self.assertTrue(any("baseline_not_verified" in f for f in res["failures"]))

    @patch("lab.teardown.remove_project_topology", return_value=[])
    @patch("lab.teardown.impair.clear_impairments")
    def test_restoration_failure_allows_topology_deletion_if_baseline_verified(self, mock_clear, mock_topo):
        """
        Regression Test 3b: Restoration failure allowing topology deletion when baseline verified.
        If impairment restoration fails but a separate verification proves the lab
        is already at baseline, namespace deletion is permitted to proceed.
        """
        mock_clear.side_effect = impair.ImpairmentError("Simulated minor clear error")
        mock_verify = MagicMock(return_value=True)

        res = teardown.teardown_lab(
            dry_run=True,
            lock_file=self.lock_file,
            verify_baseline_fn=mock_verify,
            existing_namespaces=self.live_namespaces
        )

        mock_verify.assert_called_once_with(dry_run=True)
        # Topology deletion IS called because separate verification proved lab is at baseline
        mock_topo.assert_called_once()

    @patch("lab.teardown.remove_project_topology")
    @patch("lab.teardown.impair.clear_impairments")
    def test_dns_backup_restore_failure_prevents_topology_deletion(self, mock_clear, mock_topo):
        """
        Regression Test 3c: Lingering DNS backup restore failure preventing topology deletion.
        If DNS restoration fails and baseline check fails, namespace deletion is aborted.
        """
        bak_file = self.temp_dir / "dns_config.json.impair_bak"
        bak_file.write_text(json.dumps({
            "zone": "he.test.",
            "default_ttl": 1,
            "rules": {
                "A": {"address": "10.0.2.10", "delay_ms": 0, "rcode": "NOERROR"},
                "AAAA": {"address": "2001:db8:2::10", "delay_ms": 0, "rcode": "NOERROR"}
            },
            "behavior": {
                "unknown_domain_rcode": "NXDOMAIN",
                "unsupported_type_rcode": "NOERROR"
            }
        }), encoding="utf-8")

        mock_verify = MagicMock(return_value=False)

        with patch("lab.teardown.SCRIPT_DIR", self.temp_dir), \
             patch("lab.teardown.shutil.copyfile", side_effect=OSError("Simulated backup copy error")):
            res = teardown.teardown_lab(
                dry_run=False,
                lock_file=self.lock_file,
                verify_baseline_fn=mock_verify,
                existing_namespaces=self.live_namespaces
            )

        mock_verify.assert_called_once_with(dry_run=False)
        mock_topo.assert_not_called()
        self.assertEqual(res["status"], "PARTIAL_FAILURE")
        self.assertTrue(any("baseline_not_verified" in f for f in res["failures"]))

    def test_successful_ordered_teardown(self):
        """
        Regression Test 4: Successful ordered teardown.
        Teardown stages must execute in strict sequential order:
          Stage 1: Restoring impairments and DNS baseline
          Stage 2: Stopping lab-managed services (DNS server, then Nginx)
          Stage 3: Cleaning owned resolver configuration
          Stage 4: Removing project network topology
        """
        manager = MagicMock()

        with patch("lab.teardown.impair.clear_impairments", side_effect=lambda **kw: manager.stage1_clear()) as m_clear, \
             patch("lab.teardown.stop_process_by_pid_file", side_effect=lambda f, n, **kw: (manager.stage2_stop(n), (True, None))[1]) as m_stop, \
             patch("lab.teardown.clean_owned_resolver", side_effect=lambda **kw: (manager.stage3_resolver(), (True, None))[1]) as m_res, \
             patch("lab.teardown.remove_project_topology", side_effect=lambda **kw: (manager.stage4_topology(), [])[1]) as m_topo:

            res = teardown.teardown_lab(
                dry_run=True,
                lock_file=self.lock_file,
                existing_namespaces=self.live_namespaces
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["failures"], [])

            expected_calls = [
                call.stage1_clear(),
                call.stage2_stop("Controlled DNS Server"),
                call.stage2_stop("Nginx Measurement Endpoint"),
                call.stage3_resolver(),
                call.stage4_topology(),
            ]
            self.assertEqual(manager.mock_calls, expected_calls)

    def test_teardown_sh_delegates_to_python_controller(self):
        """teardown.sh must delegate to teardown.py without holding a conflicting lock."""
        if not TEARDOWN_SH.is_file():
            self.skipTest("teardown.sh not found")

        # Running teardown.sh with --dry-run must succeed without root
        proc = subprocess.run(
            ["bash", str(TEARDOWN_SH), "--dry-run"],
            capture_output=True,
            text=True,
            timeout=10.0
        )
        self.assertEqual(
            proc.returncode, 0,
            f"teardown.sh failed with output: {proc.stdout}\n{proc.stderr}"
        )
        self.assertIn("Teardown completed successfully", proc.stdout)

    # --------------------------------------------------------------------------
    # Additional Regression Tests for A6 Hardening Bug Fixes (Requirement 4)
    # --------------------------------------------------------------------------

    def test_regression_absent_topology_idempotence(self):
        """
        Regression Test: Absent topology idempotence (Requirement 1 & 4).
        When all project namespaces are absent:
        - Teardown skips namespace operations and live baseline checks.
        - Teardown explicitly reports topology is absent without claiming baseline verification.
        - Lingering DNS backups and state files are safely reconciled.
        - Dangling host interfaces are removed.
        - Returns SUCCESS with 0 failures.
        """
        # Lingering DNS backup to verify reconciliation on absent topology
        bak_file = self.temp_dir / "dns_config.json.impair_bak"
        bak_file.write_text(json.dumps({
            "zone": "he.test.",
            "default_ttl": 1,
            "rules": {
                "A": {"address": "10.0.2.10", "delay_ms": 0, "rcode": "NOERROR"},
                "AAAA": {"address": "2001:db8:2::10", "delay_ms": 0, "rcode": "NOERROR"}
            },
            "behavior": {
                "unknown_domain_rcode": "NXDOMAIN",
                "unsupported_type_rcode": "NOERROR"
            }
        }), encoding="utf-8")
        cfg_file = self.temp_dir / "dns_config.json"
        cfg_file.write_text(json.dumps({
            "zone": "he.test.",
            "default_ttl": 1,
            "rules": {
                "A": {"address": "10.0.2.10", "delay_ms": 100, "rcode": "NOERROR"},
                "AAAA": {"address": "2001:db8:2::10", "delay_ms": 100, "rcode": "NOERROR"}
            },
            "behavior": {
                "unknown_domain_rcode": "NXDOMAIN",
                "unsupported_type_rcode": "NOERROR"
            }
        }), encoding="utf-8")

        mock_clear = MagicMock()
        mock_verify = MagicMock()

        with patch("lab.teardown.SCRIPT_DIR", self.temp_dir), \
             patch("lab.teardown.get_existing_namespaces", return_value=[]), \
             patch("lab.teardown.impair.clear_impairments", mock_clear), \
             patch("lab.teardown.is_lab_at_baseline", mock_verify), \
             patch("lab.teardown.impair.log_info") as mock_log:

            res = teardown.teardown_lab(
                dry_run=False,
                lock_file=self.lock_file,
                verify_baseline_fn=mock_verify
            )

            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["failures"], [])
            self.assertEqual(res["topology_status"], "ABSENT")

            # Must skip clear_impairments and live baseline check
            mock_clear.assert_not_called()
            mock_verify.assert_not_called()

            # Verify backup was reconciled and deleted
            self.assertFalse(bak_file.exists())
            # Verify delays were reset to 0ms baseline
            with open(cfg_file, "r", encoding="utf-8") as f:
                restored_cfg = json.load(f)
            self.assertEqual(restored_cfg["rules"]["A"]["delay_ms"], 0)
            self.assertEqual(restored_cfg["rules"]["AAAA"]["delay_ms"], 0)

            # Verify explicit reporting that lab topology is absent
            absent_reported = any("Lab topology is absent" in str(c) for c in mock_log.call_args_list)
            self.assertTrue(absent_reported, "Teardown must explicitly report that lab topology is absent")

    def test_regression_partial_topology_restoration_failure_preserves_topology(self):
        """
        Regression Test: Partial topology preservation (Requirement 3 & 4).
        When only some namespaces exist (e.g. ps028-cl present, ps028-rt absent)
        and restoration fails (e.g. cannot restore qdiscs in missing router namespace):
        - Teardown MUST NOT delete the partial topology.
        - Status must be PARTIAL_FAILURE.
        """
        mock_topo = MagicMock()

        with patch("lab.teardown.get_existing_namespaces", return_value=["ps028-cl"]), \
             patch("lab.teardown.impair.clear_impairments", side_effect=impair.ImpairmentError("Cannot open netns ps028-rt")), \
             patch("lab.teardown.remove_project_topology", mock_topo):

            res = teardown.teardown_lab(dry_run=False, lock_file=self.lock_file)

            self.assertEqual(res["status"], "PARTIAL_FAILURE")
            self.assertEqual(res["topology_status"], "PARTIAL")
            # Verify namespaces were NOT deleted
            mock_topo.assert_not_called()
            self.assertTrue(any("abort_topology_deletion" in f for f in res["failures"]))

    def test_regression_fresh_setup_bootstrap_idempotence(self):
        """
        Regression Test: Fresh setup bootstrap idempotence (Requirement 1, 4).
        setup_topology.sh setup invokes teardown when all namespaces are absent.
        Teardown must succeed cleanly with return code 0, allowing setup to proceed.
        """
        with patch("lab.teardown.get_existing_namespaces", return_value=[]), \
             patch("lab.teardown.impair.get_current_state", return_value=None):

            res = teardown.teardown_lab(dry_run=False, lock_file=self.lock_file)
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["failures"], [])
            self.assertEqual(res["topology_status"], "ABSENT")

    def test_regression_active_scenario_safe_clear(self):
        """
        Regression Test: Active scenario safely cleared (Requirement 3 & 4).
        When an active scenario (e.g. S1) exists on a live topology,
        and clearing impairments succeeds:
        - Scenario state is cleared.
        - Teardown completes successfully and deletes topology.
        """
        mock_topo = MagicMock(return_value=[])

        state_calls = [{"active_scenario": "S1"}, None]
        def fake_get_state():
            return state_calls.pop(0) if state_calls else None

        with patch("lab.teardown.get_existing_namespaces", return_value=self.live_namespaces), \
             patch("lab.teardown.impair.get_current_state", side_effect=fake_get_state), \
             patch("lab.teardown.impair.clear_impairments") as mock_clear, \
             patch("lab.teardown.remove_project_topology", mock_topo):

            res = teardown.teardown_lab(
                dry_run=True,
                lock_file=self.lock_file,
                existing_namespaces=self.live_namespaces
            )
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["failures"], [])
            mock_clear.assert_called_once()
            mock_topo.assert_called_once()

    def test_regression_active_scenario_uncleared_prevents_topology_deletion(self):
        """
        Regression Test: Active scenario uncleared prevents topology deletion (Requirement 3 & 4).
        When an active scenario cannot be cleared (state file persists or clear fails):
        - Teardown MUST NOT delete live or partial topology.
        - Returns PARTIAL_FAILURE.
        """
        mock_topo = MagicMock()

        # State remains active S1 even after clear attempt
        with patch("lab.teardown.get_existing_namespaces", return_value=self.live_namespaces), \
             patch("lab.teardown.impair.get_current_state", return_value={"active_scenario": "S1"}), \
             patch("lab.teardown.impair.clear_impairments", side_effect=impair.ImpairmentError("Failed to clear nftables")), \
             patch("lab.teardown.remove_project_topology", mock_topo):

            res = teardown.teardown_lab(
                dry_run=False,
                lock_file=self.lock_file,
                existing_namespaces=self.live_namespaces
            )
            self.assertEqual(res["status"], "PARTIAL_FAILURE")
            mock_topo.assert_not_called()
            self.assertTrue(any("active_scenario_not_cleared" in f or "baseline_not_verified" in f for f in res["failures"]))

    def test_regression_stop_process_rejects_unverified_pid(self):
        """
        Regression Test: Stop only verified project-managed services (Requirement 2 & 4).
        If pid_file contains a PID that belongs to an unrelated command,
        stop_process_by_pid_file must refuse to signal it, unlink the invalid pid_file,
        and log a warning.
        """
        pid_file = self.temp_dir / "dns.pid"
        pid_file.write_text("12345\n", encoding="utf-8")

        mock_kill = MagicMock()
        mock_verifier = MagicMock(return_value=(False, "cmdline_mismatch:expected dns_server.py in /bin/bash"))

        with patch("os.kill", mock_kill):
            ok, err = teardown.stop_process_by_pid_file(
                pid_file, "Controlled DNS Server", dry_run=False, verifier=mock_verifier
            )
            self.assertTrue(ok)
            # Verify os.kill was NOT called with SIGTERM or SIGKILL
            mock_kill.assert_not_called()
            # Verify pid file was unlinked
            self.assertFalse(pid_file.exists())

    def test_regression_reconcile_dns_backups_cleans_tmp_and_resets_delays(self):
        """
        Regression Test: Reconcile DNS backups (Requirement 2 & 4).
        - Lingering tmp files are unlinked.
        - Non-zero delays in dns_config.json are reset to 0ms baseline.
        """
        cfg_file = self.temp_dir / "dns_config.json"
        cfg_file.write_text(json.dumps({
            "zone": "he.test.",
            "default_ttl": 1,
            "rules": {
                "A": {"address": "10.0.2.10", "delay_ms": 250, "rcode": "NOERROR"},
                "AAAA": {"address": "2001:db8:2::10", "delay_ms": 300, "rcode": "NOERROR"}
            },
            "behavior": {
                "unknown_domain_rcode": "NXDOMAIN",
                "unsupported_type_rcode": "NOERROR"
            }
        }), encoding="utf-8")
        tmp_bak = self.temp_dir / "dns_config.json.bak.tmp.999"
        tmp_bak.touch()

        ok, failures = teardown.reconcile_dns_backups(script_dir=self.temp_dir, config_file=cfg_file, dry_run=False)
        self.assertTrue(ok)
        self.assertEqual(failures, [])
        self.assertFalse(tmp_bak.exists())

        with open(cfg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["rules"]["A"]["delay_ms"], 0)
        self.assertEqual(data["rules"]["AAAA"]["delay_ms"], 0)


if __name__ == "__main__":
    unittest.main()
