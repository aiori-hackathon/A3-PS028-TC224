#!/usr/bin/env python3
"""
PS-028 Integrated Browser Measurement Runner Test Suite
Work Package A7: Integrated Measurement Runner & Browser Fallback Validation

Tests:
1. Browser runtime preflight & discovery (Chromium, Firefox, Google Chrome)
2. Strict refusal to substitute curl for real browser
3. Lab readiness and topology presence validation
4. Unique trial ID and hostname conformance with DNS server wildcard rules
5. tcpdump packet capture lifecycle, pcap validation, and SHA-256 calculation
6. Happy Eyeballs fallback classification matrix (RFC 8305 / PS-028)
   - Strict refusal to infer fallback from HTTP 200 alone
   - Fallback classified ONLY when IPv6 attempt + IPv4 attempt + IPv4 success are evidenced
7. Lock safety and in-process re-entrancy without subprocess deadlock
8. Robust cleanup on timeout, exception, and signal interruption
9. Full S0-S6 end-to-end simulated measurement runs with versioned JSON validation
"""

import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
from typing import List, Optional
from unittest.mock import MagicMock, patch
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.dns_server as dns_server
import lab.impair as impair
import lab.run_trial as run_trial


class TestBrowserRuntimeDiscoveryAndPreflight(unittest.TestCase):
    """Tests for browser discovery, preflight checks, and curl substitution refusal."""

    @patch("shutil.which")
    @patch("lab.run_trial._query_browser_version")
    def test_find_browser_runtime_locates_chromium(self, mock_ver, mock_which):
        mock_which.side_effect = lambda cmd: "/usr/bin/chromium" if cmd == "chromium" else None
        mock_ver.return_value = "Chromium 124.0.0.0"

        bname, bpath, bver = run_trial.find_browser_runtime()
        self.assertEqual(bname, "chromium")
        self.assertEqual(bpath, "/usr/bin/chromium")
        self.assertIn("Chromium", bver)

    @patch("shutil.which")
    @patch("lab.run_trial._query_browser_version")
    def test_find_browser_runtime_locates_firefox(self, mock_ver, mock_which):
        def which_side_effect(cmd):
            return "/usr/bin/firefox" if cmd == "firefox" else None
        mock_which.side_effect = which_side_effect
        mock_ver.return_value = "Mozilla Firefox 125.0"

        bname, bpath, bver = run_trial.find_browser_runtime()
        self.assertEqual(bname, "firefox")
        self.assertEqual(bpath, "/usr/bin/firefox")

    @patch("shutil.which", return_value=None)
    def test_preflight_fails_when_browser_missing(self, mock_which):
        """Must raise BrowserPreflightError when no supported browser is installed."""
        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.find_browser_runtime()

        err_msg = str(ctx.exception).lower()
        self.assertIn("no supported browser runtime found", err_msg)
        self.assertIn("substituting curl for the browser is strictly forbidden", err_msg)

    @patch("shutil.which", return_value=None)
    def test_preflight_rejects_nonexistent_preferred_browser(self, mock_which):
        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.find_browser_runtime(preferred="my-custom-browser")
        self.assertIn("my-custom-browser", str(ctx.exception))
        self.assertIn("strictly forbidden", str(ctx.exception).lower())

    @patch("subprocess.run")
    def test_query_browser_version_handles_timeout_gracefully(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["browser", "--version"], timeout=3.0)
        ver = run_trial._query_browser_version("/usr/bin/browser")
        self.assertIn("unknown", ver)

    @patch("lab.run_trial.is_snap_browser")
    @patch("shutil.which")
    @patch("lab.run_trial._query_browser_version")
    def test_find_browser_runtime_skips_snap_in_favor_of_non_snap(self, mock_ver, mock_which, mock_is_snap):
        """Verifies auto-discovery skips Snap browsers and selects non-Snap alternative."""
        def which_side_effect(cmd):
            if cmd == "google-chrome":
                return "/snap/bin/google-chrome"
            if cmd == "chromium":
                return "/usr/bin/chromium"
            return None
        mock_which.side_effect = which_side_effect
        mock_is_snap.side_effect = lambda p: str(p).startswith("/snap/")
        mock_ver.return_value = "Chromium 124.0.0.0"

        bname, bpath, bver = run_trial.find_browser_runtime()
        self.assertEqual(bname, "chromium")
        self.assertEqual(bpath, "/usr/bin/chromium")

    @patch("lab.run_trial.is_snap_browser")
    @patch("shutil.which")
    @patch("lab.run_trial._query_browser_version")
    def test_find_browser_runtime_preferred_chromium_falls_back_to_non_snap_chrome(self, mock_ver, mock_which, mock_is_snap):
        """When preferred chromium is Snap, falls back to non-Snap google-chrome."""
        def which_side_effect(cmd):
            if cmd in ("chromium", "chromium-browser"):
                return "/snap/bin/chromium"
            if cmd == "google-chrome":
                return "/usr/bin/google-chrome"
            return None
        mock_which.side_effect = which_side_effect
        mock_is_snap.side_effect = lambda p: str(p).startswith("/snap/")
        mock_ver.return_value = "Google Chrome 124.0.0.0"

        bname, bpath, bver = run_trial.find_browser_runtime(preferred="chromium")
        self.assertEqual(bname, "chromium")
        self.assertEqual(bpath, "/usr/bin/google-chrome")

    @patch("lab.run_trial.is_snap_browser")
    @patch("shutil.which")
    def test_find_browser_runtime_rejects_explicit_snap_path(self, mock_which, mock_is_snap):
        """Explicit path to Snap binary raises BrowserPreflightError reporting the blocker."""
        mock_which.return_value = "/snap/bin/chromium"
        mock_is_snap.return_value = True

        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.find_browser_runtime(preferred="/snap/bin/chromium")
        err = str(ctx.exception)
        self.assertIn("Snap package", err)
        self.assertIn("snap-confine", err)
        self.assertIn("google-chrome", err)

    @patch("lab.run_trial.is_snap_browser")
    @patch("shutil.which")
    def test_find_browser_runtime_rejects_snap_when_no_non_snap_available(self, mock_which, mock_is_snap):
        """When requested browser is Snap and no non-Snap alternative exists, raises BrowserPreflightError."""
        mock_which.side_effect = lambda cmd: "/snap/bin/firefox" if cmd == "firefox" else None
        mock_is_snap.return_value = True

        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.find_browser_runtime(preferred="firefox")
        err = str(ctx.exception)
        self.assertIn("firefox", err)
        self.assertIn("Snap package", err)


class TestLabReadinessValidation(unittest.TestCase):
    """Tests for lab environment validation and readiness checks."""

    @patch("lab.teardown.get_topology_status")
    @patch("shutil.which", return_value=None)
    def test_readiness_fails_when_topology_absent(self, mock_which, mock_top):
        mock_top.return_value = ("ABSENT", [], ["ps028-cl", "ps028-rt", "ps028-sv"])
        report = run_trial.validate_lab_readiness(is_simulation=False, skip_baseline=True)

        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("topology is not fully live" in err for err in report["errors"]))
        self.assertTrue(any("browser runtime" in err.lower() for err in report["errors"]))

    def test_readiness_passes_in_simulation_mode(self):
        report = run_trial.validate_lab_readiness(is_simulation=True, skip_baseline=True)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["is_simulation"])
        self.assertTrue(report["checks"]["browser"]["valid"])


class TestTrialIdentifierAndHostname(unittest.TestCase):
    """Tests for unique trial ID and hostname generation conforming to DNS server wildcard."""

    def test_generate_trial_id_format(self):
        tid1 = run_trial.generate_trial_id()
        tid2 = run_trial.generate_trial_id()
        self.assertNotEqual(tid1, tid2)
        self.assertTrue(tid1.startswith("trial-"))

    def test_trial_hostname_matches_dns_server_supported_pattern(self):
        tid = run_trial.generate_trial_id()
        hostname = run_trial.get_trial_hostname(tid)
        self.assertTrue(hostname.endswith(".he.test"))

        # Verify DNS server is_supported_hostname accepts it
        self.assertTrue(
            dns_server.is_supported_hostname(hostname, "he.test."),
            f"DNS server rejected generated trial hostname: {hostname}"
        )

    def test_invalid_trial_id_rejected(self):
        with self.assertRaises(ValueError):
            run_trial.get_trial_hostname("invalid.subdomain.test")


class TestPacketCaptureValidationAndDissection(unittest.TestCase):
    """Tests for PCAP validation, SHA-256 computation, and frame dissection."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_pcap_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validate_pcap_validates_standard_magic_and_sha256(self):
        pcap_file = self.temp_dir / "valid.pcap"
        # Standard pcap header + one dummy packet record
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt_data = b"\x00" * 40
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(pkt_data), len(pkt_data))
        content = header + pkt_hdr + pkt_data
        pcap_file.write_bytes(content)

        is_valid, sha256_hex, size, count, msg = run_trial.validate_pcap_file(pcap_file)
        self.assertTrue(is_valid)
        self.assertEqual(size, len(content))
        self.assertEqual(count, 1)
        self.assertEqual(len(sha256_hex), 64)

    def test_validate_pcap_rejects_truncated_file(self):
        pcap_file = self.temp_dir / "truncated.pcap"
        pcap_file.write_bytes(b"\xa1\xb2\xc3")  # Less than 24 bytes

        is_valid, _, _, _, msg = run_trial.validate_pcap_file(pcap_file)
        self.assertFalse(is_valid)
        self.assertIn("too small", msg)

    def test_validate_pcap_rejects_invalid_magic(self):
        pcap_file = self.temp_dir / "bad_magic.pcap"
        bad_header = struct.pack("<IHHIIII", 0x12345678, 2, 4, 0, 0, 65535, 1)
        pcap_file.write_bytes(bad_header)

        is_valid, _, _, _, msg = run_trial.validate_pcap_file(pcap_file)
        self.assertFalse(is_valid)
        self.assertIn("Invalid PCAP header magic", msg)


class TestHappyEyeballsFallbackClassification(unittest.TestCase):
    """
    Tests for PS-028 / RFC 8305 Happy Eyeballs Fallback Classification Matrix.
    Verifies:
    1. IPv6 attempt + IPv4 attempt + IPv4 success -> IPV6_TO_IPV4_FALLBACK
    2. IPv6 success without IPv4 attempt -> DIRECT_IPV6
    3. IPv4 success without IPv6 attempt -> DIRECT_IPV4 (Do not infer fallback from HTTP 200 alone)
    4. Neither succeeds -> CONNECTION_FAILED
    """

    def test_fallback_classified_when_ipv6_and_ipv4_attempted_and_ipv4_wins(self):
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.25},
            "connection_attempt_delay_ms": 250.0
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertTrue(res["fallback_occurred"])
        self.assertEqual(res["classification"], "IPV6_TO_IPV4_FALLBACK")
        self.assertIn("Connection Attempt Delay: 250.0ms", res["reason"])

    def test_direct_ipv6_classified_when_ipv6_succeeds_without_ipv4_attempt(self):
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "DIRECT_IPV6")

    def test_do_not_infer_fallback_from_http_200_alone_when_ipv6_not_attempted(self):
        """
        CRITICAL PS-028 REQUIREMENT:
        HTTP 200 on IPv4 without prior IPv6 attempt MUST NOT be classified as fallback!
        It must report DIRECT_IPV4 and fallback_occurred=False.
        """
        dissection = {
            "ipv6": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"], "Must not infer fallback from HTTP 200 alone")
        self.assertEqual(res["classification"], "DIRECT_IPV4")
        self.assertIn("fallback is not inferred from http 200 alone", res["reason"].lower())

    def test_connection_failed_classified_when_both_fail(self):
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.25},
        }
        http_outcome = {"status_code": None, "success": False, "winning_address_family": None}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "CONNECTION_FAILED")


class TestLockingAndCleanupSafety(unittest.TestCase):
    """Tests for shared lock safety, deadlock prevention, and cleanup guarantees."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_lock_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_in_process_reentrancy_avoids_subprocess_deadlock(self):
        """
        run_trial acquires the shared lab lock and calls apply_scenario/clear_impairments
        in-process, verifying that lock re-entrancy succeeds smoothly.
        """
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            # Simulated trial inside the lock
            res = run_trial.run_trial(
                scenario_id="S0",
                is_simulation=True,
                skip_baseline_check=True,
                lock_file=self.lock_file,
                output_dir=self.temp_dir / "trial_reentry"
            )
            self.assertEqual(res["scenario_id"], "S0")
            self.assertTrue(res["cleanup_status"]["scenario_restored"])

    @patch("lab.impair.apply_scenario")
    def test_cleanup_restores_baseline_on_trial_exception(self, mock_apply):
        mock_apply.side_effect = RuntimeError("Simulated failure during scenario application")

        with self.assertRaises(RuntimeError):
            run_trial.run_trial(
                scenario_id="S1",
                is_simulation=True,
                skip_baseline_check=True,
                lock_file=self.lock_file,
                output_dir=self.temp_dir / "trial_err"
            )

        # Baseline check passes because cleanup ran in finally
        self.assertTrue(impair.self_test_baseline(dry_run=True))


class TestFullSimulatedTrialsS0ThroughS6(unittest.TestCase):
    """Executes complete end-to-end simulated trials for all scenarios S0 through S6."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_s0_s6_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_all_scenarios_s0_to_s6_produce_valid_results(self):
        expected_classifications = {
            "S0": ("DIRECT_IPV6", False),
            "S1": ("IPV6_TO_IPV4_FALLBACK", True),
            "S2": ("IPV6_TO_IPV4_FALLBACK", True),
            "S3": ("DIRECT_IPV6", False),
            "S4": ("IPV6_TO_IPV4_FALLBACK", True),
            "S5": ("IPV6_TO_IPV4_FALLBACK", True),
            "S6": ("DIRECT_IPV4", False),
        }

        for sc_id, (exp_class, exp_fallback) in expected_classifications.items():
            with self.subTest(scenario=sc_id):
                out_dir = self.temp_dir / f"trial_{sc_id}"
                res = run_trial.run_trial(
                    scenario_id=sc_id,
                    is_simulation=True,
                    skip_baseline_check=True,
                    lock_file=self.lock_file,
                    output_dir=out_dir
                )

                # 1. Verify Schema & Identifiers
                self.assertEqual(res["schema_version"], run_trial.SCHEMA_VERSION)
                self.assertEqual(res["scenario_id"], sc_id)
                self.assertEqual(res["execution_mode"], "SIMULATION")
                self.assertTrue(res["is_simulation"])
                self.assertTrue(res["hostname"].endswith(".he.test"))

                # 2. Verify Classification & Fallback
                net_obs = res["network_observations"]
                self.assertEqual(net_obs["classification"], exp_class)
                self.assertEqual(net_obs["fallback_occurred"], exp_fallback)

                # 3. Verify Artifacts & SHA-256
                pcap_path = Path(res["capture_metadata"]["pcap_path"])
                self.assertTrue(pcap_path.is_file())
                self.assertTrue(res["capture_metadata"]["pcap_valid"])
                self.assertEqual(
                    res["capture_metadata"]["pcap_sha256"],
                    run_trial.validate_pcap_file(pcap_path)[1]
                )

                # 4. Verify Result JSON exists on disk
                res_json = Path(res["evidence_paths"]["result_json"])
                self.assertTrue(res_json.is_file())
                loaded = json.loads(res_json.read_text(encoding="utf-8"))
                self.assertEqual(loaded["trial_id"], res["trial_id"])

                # 5. Verify Cleanup
                self.assertTrue(res["cleanup_status"]["scenario_restored"])
                self.assertTrue(res["cleanup_status"]["profile_cleaned"])


class TestCaptureLifecycleAndHTTPStatusRegression(unittest.TestCase):
    """
    Regression tests for A7 capture lifecycle, empty capture handling,
    and unknown HTTP status extraction per PS-028 requirements.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_regress_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("os.geteuid", return_value=0)
    @patch("subprocess.Popen")
    def test_start_packet_capture_includes_immediate_mode_and_readiness(self, mock_popen, mock_euid):
        """Verifies start_packet_capture uses immediate mode, packet buffering, and validates readiness."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 12345

        pcap_path = self.temp_dir / "test.pcap"
        log_file = self.temp_dir / "tcpdump.log"

        def _popen_side_effect(*args, **kwargs):
            # Simulate tcpdump outputting readiness after process launch
            log_file.write_text("tcpdump: listening on any, link-type LINUX_SLL2\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side_effect

        proc = run_trial.start_packet_capture(
            output_pcap=pcap_path,
            log_file=log_file,
            netns="ps028-cl",
            is_simulation=False
        )
        self.assertIsNotNone(proc)
        mock_popen.assert_called_once()
        cmd_called = mock_popen.call_args[0][0]

        # Must include --immediate-mode and -U for prompt packet flushing
        self.assertIn("--immediate-mode", cmd_called)
        self.assertIn("-U", cmd_called)
        self.assertIn("-i", cmd_called)
        self.assertTrue(mock_popen.call_args[1].get("start_new_session"))
        self.assertTrue(hasattr(proc, "_ps028_log_fp"))
        self.assertTrue(hasattr(proc, "_ps028_tcpdump_pid"))
        # Clean up file handle
        proc._ps028_log_fp.close()

    @patch("os.geteuid", return_value=0)
    @patch("subprocess.Popen")
    @patch("lab.run_trial.stop_packet_capture")
    def test_start_packet_capture_fails_and_cleans_up_on_readiness_timeout(self, mock_stop, mock_popen, mock_euid):
        """
        Requirement 2:
        Verifies start_packet_capture raises TrialExecutionError and stops process
        if readiness ('listening on') times out.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9999
        mock_popen.return_value = mock_proc

        pcap_path = self.temp_dir / "test.pcap"
        log_file = self.temp_dir / "tcpdump.log"
        log_file.write_text("tcpdump: initializing socket...\n", encoding="utf-8")

        with self.assertRaises(run_trial.TrialExecutionError) as ctx:
            run_trial.start_packet_capture(
                output_pcap=pcap_path,
                log_file=log_file,
                netns="ps028-cl",
                is_simulation=False,
                readiness_timeout=0.1
            )
        self.assertIn("timed out waiting for readiness", str(ctx.exception))
        mock_stop.assert_called_once_with(mock_proc, timeout=1.0)

    @patch("os.geteuid", return_value=0)
    @patch("subprocess.Popen")
    def test_start_packet_capture_fails_when_tcpdump_terminates_prematurely(self, mock_popen, mock_euid):
        """
        Requirement 2:
        Verifies start_packet_capture raises TrialExecutionError and closes log
        if tcpdump exits before readiness.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        mock_proc.pid = 9998
        mock_popen.return_value = mock_proc

        pcap_path = self.temp_dir / "test.pcap"
        log_file = self.temp_dir / "tcpdump.log"
        log_file.write_text("tcpdump: permission denied on socket\n", encoding="utf-8")

        with self.assertRaises(run_trial.TrialExecutionError) as ctx:
            run_trial.start_packet_capture(
                output_pcap=pcap_path,
                log_file=log_file,
                netns="ps028-cl",
                is_simulation=False,
                readiness_timeout=0.5
            )
        self.assertIn("terminated prematurely with code 1", str(ctx.exception))

    @patch("lab.run_trial.is_safe_capture_process", return_value=True)
    @patch("os.kill")
    def test_stop_packet_capture_clean_shutdown_and_flush(self, mock_kill, mock_safe):
        """
        Requirement 1:
        Verifies capture shutdown targets the actual tcpdump child PID gracefully with SIGINT,
        waits for exit and PCAP finalization, reaps the process, and flushes/closes the log.
        Does not signal unrelated processes.
        """
        mock_proc = MagicMock()
        mock_proc.pid = 54321
        mock_proc._ps028_tcpdump_pid = 54322
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0

        mock_log_fp = MagicMock()
        mock_log_fp.closed = False
        mock_proc._ps028_log_fp = mock_log_fp

        # Simulate tcpdump_pid exiting when checked via os.kill(54322, 0)
        mock_kill.side_effect = [None, ProcessLookupError]

        run_trial.stop_packet_capture(mock_proc, timeout=2.0)

        # Delivered SIGINT specifically to tcpdump_pid
        mock_kill.assert_any_call(54322, signal.SIGINT)
        # Reaped proc
        mock_proc.wait.assert_called_once()
        # Flushed and closed log file
        mock_log_fp.flush.assert_called_once()
        mock_log_fp.close.assert_called_once()

    @patch("lab.run_trial.is_safe_capture_process", return_value=True)
    @patch("os.kill")
    def test_stop_packet_capture_escalates_only_on_timeout(self, mock_kill, mock_safe):
        """
        Requirement 1:
        Verifies escalation to SIGTERM and SIGKILL occurs only when graceful shutdown times out.
        Reaps process and closes log file descriptor.
        """
        mock_proc = MagicMock()
        mock_proc.pid = 54321
        mock_proc._ps028_tcpdump_pid = 54321
        mock_proc.poll.return_value = None
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="tcpdump", timeout=0.5),
            subprocess.TimeoutExpired(cmd="tcpdump", timeout=1.5),
            0
        ]
        mock_log_fp = MagicMock()
        mock_log_fp.closed = False
        mock_proc._ps028_log_fp = mock_log_fp

        run_trial.stop_packet_capture(mock_proc, timeout=0.5)

        mock_kill.assert_any_call(54321, signal.SIGINT)
        mock_kill.assert_any_call(54321, signal.SIGTERM)
        mock_kill.assert_any_call(54321, signal.SIGKILL)
        mock_log_fp.close.assert_called_once()

    def test_empty_pcap_zero_packets_fails_min_packets_validation(self):
        """Verifies validate_pcap_file with min_packets rejects 0-packet PCAP."""
        pcap_file = self.temp_dir / "empty.pcap"
        # Valid PCAP header with 0 packet records
        pcap_file.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        is_valid, _, size, count, msg = run_trial.validate_pcap_file(pcap_file, min_packets=1)
        self.assertFalse(is_valid)
        self.assertEqual(count, 0)
        self.assertIn("PCAP contains 0 packets", msg)

    def test_zero_packet_capture_treated_as_measurement_failure_not_connection_failed(self):
        """
        CRITICAL REQUIREMENT:
        A zero-packet capture for a successful HTTP trial must be treated as an evidence/measurement failure,
        reporting INCONCLUSIVE with a measurement failure reason, NOT CONNECTION_FAILED or valid normal run.
        """
        empty_dissection = {
            "dns": {"queries": [], "responses": []},
            "ipv6": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "ipv4": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "http_status_code": None
        }
        # Browser returned exit code 0 / rendered DOM (HTTP success claimed)
        http_outcome = {"status_code": None, "success": True, "winning_address_family": None}

        res = run_trial.classify_fallback(empty_dissection, http_outcome, is_measurement_failure=True)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "INCONCLUSIVE")
        self.assertIn("measurement failure", res["reason"].lower())
        self.assertNotEqual(res["classification"], "CONNECTION_FAILED")

    @patch("subprocess.run")
    def test_run_browser_does_not_fabricate_http_200_from_exit_zero(self, mock_run):
        """
        CRITICAL REQUIREMENT:
        Chrome --dump-dom exit code 0 does NOT prove HTTP 200.
        run_browser must return http_status = None rather than fabricated 200.
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "<html><body>Some content</body></html>"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "profile"
        profile.mkdir()
        res = run_trial.run_browser("google-chrome", "/usr/bin/google-chrome", "http://test/", profile)

        self.assertEqual(res["exit_code"], 0)
        self.assertTrue(res["success"])
        # http_status must NOT be 200; it must be None (to be extracted from packet evidence)
        self.assertIsNone(res["http_status"])

    def test_dissect_pcap_extracts_actual_http_status_from_raw_pcap_data(self):
        """Verifies dissect_pcap extracts HTTP status code (200) from packet evidence."""
        pcap_file = self.temp_dir / "http.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        http_data = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 12\r\n\r\nHello World!"
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(http_data), len(http_data))
        pcap_file.write_bytes(header + pkt_hdr + http_data)

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname="trial-1.he.test")
        self.assertEqual(dissection["http_status_code"], 200)

    def test_unknown_http_status_when_packet_evidence_missing(self):
        """Verifies dissect_pcap leaves http_status_code as None when no HTTP response exists in PCAP."""
        pcap_file = self.temp_dir / "syn_only.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        dummy_syn = b"\x00" * 40
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(dummy_syn), len(dummy_syn))
        pcap_file.write_bytes(header + pkt_hdr + dummy_syn)

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname="trial-1.he.test")
        self.assertIsNone(dissection["http_status_code"])

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.impair.apply_scenario")
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.stop_packet_capture")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_zero_packet_live_capture_forces_inconclusive_when_browser_succeeds(
        self, mock_base, mock_clear, mock_stop, mock_browser, mock_cap, mock_apply, mock_ready
    ):
        """
        Requirement 3:
        For every LIVE trial, zero-packet capture MUST invalidate network evidence and force
        classification INCONCLUSIVE, even when browser succeeded (exit 0, rendered DOM).
        Never report such a capture as a valid network measurement.
        """
        mock_ready.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "chromium", "path": "/usr/bin/chromium", "version": "120"}}
        }
        mock_browser.return_value = {
            "name": "chromium",
            "executable": "/usr/bin/chromium",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 100.0,
            "stdout": "<html><body>Hello</body></html>",
            "stderr": "",
            "http_status": None,
            "success": True,
            "winning_family": None
        }

        trial_dir = self.temp_dir / "live_zero_pkt_success"
        trial_dir.mkdir(parents=True, exist_ok=True)
        # Create empty PCAP with 0 packet records
        pcap_file = trial_dir / "capture.pcap"
        pcap_file.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        res = run_trial.run_trial(
            scenario_id="S0",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        # Network evidence must be invalidated
        self.assertFalse(res["capture_metadata"]["pcap_valid"])
        self.assertEqual(res["capture_metadata"]["packet_count"], 0)
        self.assertIn("Zero packets captured in live trial", res["capture_metadata"]["validation_message"])

        net_obs = res["network_observations"]
        self.assertEqual(net_obs["classification"], "INCONCLUSIVE")
        self.assertFalse(net_obs["fallback_occurred"])
        self.assertFalse(net_obs["ipv6_attempt"])
        self.assertFalse(net_obs["ipv4_attempt"])
        self.assertFalse(net_obs["ipv6_success"])
        self.assertFalse(net_obs["ipv4_success"])
        self.assertIsNone(net_obs["connection_attempt_delay_ms"])

        # HTTP outcome must not claim success or status without packet evidence
        self.assertIsNone(res["http_outcome"]["status_code"])
        self.assertFalse(res["http_outcome"]["success"])

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.impair.apply_scenario")
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.stop_packet_capture")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_zero_packet_live_capture_forces_inconclusive_when_browser_fails(
        self, mock_base, mock_clear, mock_stop, mock_browser, mock_cap, mock_apply, mock_ready
    ):
        """
        Requirement 3:
        For every LIVE trial, zero-packet capture MUST force classification INCONCLUSIVE,
        even when browser failed (exit 1). Must NOT report CONNECTION_FAILED or valid measurement.
        """
        mock_ready.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "chromium", "path": "/usr/bin/chromium", "version": "120"}}
        }
        mock_browser.return_value = {
            "name": "chromium",
            "executable": "/usr/bin/chromium",
            "exit_code": 1,
            "timed_out": False,
            "duration_ms": 100.0,
            "stdout": "",
            "stderr": "net::ERR_FAILED",
            "http_status": None,
            "success": False,
            "winning_family": None
        }

        trial_dir = self.temp_dir / "live_zero_pkt_fail"
        trial_dir.mkdir(parents=True, exist_ok=True)
        pcap_file = trial_dir / "capture.pcap"
        pcap_file.write_bytes(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        res = run_trial.run_trial(
            scenario_id="S1",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        self.assertFalse(res["capture_metadata"]["pcap_valid"])
        self.assertEqual(res["capture_metadata"]["packet_count"], 0)
        self.assertEqual(res["network_observations"]["classification"], "INCONCLUSIVE")
        self.assertNotEqual(res["network_observations"]["classification"], "CONNECTION_FAILED")
        self.assertFalse(res["network_observations"]["fallback_occurred"])

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.impair.apply_scenario")
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.stop_packet_capture")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_invalid_pcap_live_capture_forces_inconclusive(
        self, mock_base, mock_clear, mock_stop, mock_browser, mock_cap, mock_apply, mock_ready
    ):
        """
        Requirement 3:
        An invalid/corrupt PCAP file in a LIVE trial invalidates network evidence and forces INCONCLUSIVE.
        """
        mock_ready.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "chromium", "path": "/usr/bin/chromium", "version": "120"}}
        }
        mock_browser.return_value = {
            "name": "chromium",
            "executable": "/usr/bin/chromium",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 100.0,
            "stdout": "<html>OK</html>",
            "stderr": "",
            "http_status": None,
            "success": True,
            "winning_family": None
        }

        trial_dir = self.temp_dir / "live_invalid_pcap"
        trial_dir.mkdir(parents=True, exist_ok=True)
        pcap_file = trial_dir / "capture.pcap"
        pcap_file.write_bytes(b"\x00\x01\x02\x03\x04\x05")  # Corrupt, less than 24 bytes

        res = run_trial.run_trial(
            scenario_id="S0",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        self.assertFalse(res["capture_metadata"]["pcap_valid"])
        self.assertIn("too small", res["capture_metadata"]["validation_message"])
        self.assertEqual(res["network_observations"]["classification"], "INCONCLUSIVE")
        self.assertFalse(res["network_observations"]["fallback_occurred"])

    def test_fallback_requires_valid_packet_evidence_for_all_three_criteria(self):
        """
        Requirement 5:
        Fallback must be classified ONLY when valid packet evidence demonstrates:
        (1) IPv6 attempt, (2) IPv4 attempt, and (3) successful IPv4 connection.
        If IPv4 connection is NOT established in packet evidence, fallback must NOT be classified.
        """
        # Both attempted, but IPv4 connection not established in packet evidence
        dissection_no_v4_success = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.25},
            "connection_attempt_delay_ms": 250.0
        }
        http_outcome = {"status_code": None, "success": False, "winning_address_family": None}

        res = run_trial.classify_fallback(dissection_no_v4_success, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "CONNECTION_FAILED")

        # Even if http_outcome claims success, if packet evidence lacks IPv4 connection, refuse fallback
        http_outcome_claimed_success = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}
        res2 = run_trial.classify_fallback(dissection_no_v4_success, http_outcome_claimed_success)
        self.assertFalse(res2["fallback_occurred"])
        self.assertNotEqual(res2["classification"], "IPV6_TO_IPV4_FALLBACK")

    def test_classify_fallback_with_pcap_valid_false_forces_inconclusive(self):
        """Verifies classify_fallback immediately returns INCONCLUSIVE when pcap_valid is False."""
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.25},
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        res = run_trial.classify_fallback(dissection, http_outcome, pcap_valid=False)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "INCONCLUSIVE")
        self.assertIn("measurement failure", res["reason"].lower())
        self.assertFalse(res["ipv6_attempt"])
        self.assertFalse(res["ipv4_attempt"])

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.impair.apply_scenario")
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.stop_packet_capture")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_live_run_leaves_http_status_unknown_when_no_packet_http_response(
        self, mock_base, mock_clear, mock_stop, mock_browser, mock_cap, mock_apply, mock_ready
    ):
        """
        Requirement 4:
        Keep HTTP status null unless a real response status is extracted from the captured traffic.
        Do not infer status from Chrome's exit code or rendered HTML.
        """
        mock_ready.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "google-chrome", "path": "/usr/bin/google-chrome", "version": "120"}}
        }
        mock_browser.return_value = {
            "name": "google-chrome",
            "executable": "/usr/bin/google-chrome",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 150.0,
            "stdout": "<html><body>Hello from Chrome</body></html>",
            "stderr": "",
            "http_status": None,
            "success": True,
            "winning_family": None
        }

        trial_dir = self.temp_dir / "live_syn_only"
        trial_dir.mkdir(parents=True, exist_ok=True)
        # Create PCAP with 1 TCP SYN packet but no HTTP response
        pcap_file = trial_dir / "capture.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        dummy_pkt = b"\x00" * 40
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(dummy_pkt), len(dummy_pkt))
        pcap_file.write_bytes(header + pkt_hdr + dummy_pkt)

        res = run_trial.run_trial(
            scenario_id="S0",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        # HTTP status must remain None (null in JSON)
        self.assertIsNone(res["http_outcome"]["status_code"])
        self.assertFalse(res["http_outcome"]["success"])

    def test_find_tcpdump_pid_returns_parent_when_not_found(self):
        """Verifies find_tcpdump_pid safely returns parent_pid when /proc is not populated."""
        self.assertEqual(run_trial.find_tcpdump_pid(9999999), 9999999)


class TestCaptureShutdownAndInvalidationRegression(unittest.TestCase):
    """
    Regression tests for A7 capture-shutdown defect:
    1. Confirming tcpdump has exited and PCAP is finalized; returning success or raising a clear error.
    2. Timeout escalation only on timeout to SIGTERM/SIGKILL; never signaling unrelated processes.
    3. Invalidation of LIVE capture and classification as INCONCLUSIVE on unconfirmed shutdown,
       with baseline restoration and cleanup.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_shutdown_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.run_trial.is_safe_capture_process", return_value=True)
    def test_stop_packet_capture_confirms_exit_and_pcap_finalized(self, mock_safe):
        """Verifies stop_packet_capture confirms exit, validates PCAP, and returns True."""
        mock_proc = MagicMock()
        mock_proc.pid = 43210
        mock_proc._ps028_tcpdump_pid = 43210
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0

        mock_log = MagicMock()
        mock_log.closed = False
        mock_proc._ps028_log_fp = mock_log

        pcap_path = self.temp_dir / "valid.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pcap_path.write_bytes(header)

        with patch("os.kill") as mock_kill:
            mock_kill.return_value = None
            res = run_trial.stop_packet_capture(mock_proc, timeout=2.0, pcap_path=pcap_path)

        self.assertTrue(res)
        mock_proc.wait.assert_called_once()
        mock_log.flush.assert_called_once()
        mock_log.close.assert_called_once()

    def test_stop_packet_capture_refuses_to_signal_unrelated_process(self):
        """
        Verifies stop_packet_capture never signals unrelated processes
        if PID was recycled or belongs to an unrelated command.
        """
        mock_proc = MagicMock()
        # Use our own PID (python3), which is definitely not tcpdump
        current_pid = os.getpid()
        mock_proc.pid = current_pid
        mock_proc._ps028_tcpdump_pid = current_pid
        mock_proc.poll.return_value = None

        with patch("os.kill") as mock_kill:
            with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                run_trial.stop_packet_capture(mock_proc, timeout=0.5)

            # Crucial check: os.kill MUST NOT have been called with SIGINT, SIGTERM, or SIGKILL
            for call_args in mock_kill.call_args_list:
                sig_sent = call_args[0][1] if len(call_args[0]) > 1 else None
                self.assertNotIn(sig_sent, [signal.SIGINT, signal.SIGTERM, signal.SIGKILL])
            self.assertIn("unrelated", str(ctx.exception).lower())

    @patch("lab.run_trial.is_safe_capture_process", return_value=True)
    def test_stop_packet_capture_fails_when_process_fails_to_exit_after_sigkill(self, mock_safe):
        """Verifies stop_packet_capture raises CaptureShutdownError if process survives SIGKILL."""
        mock_proc = MagicMock()
        mock_proc.pid = 43210
        mock_proc._ps028_tcpdump_pid = 43210
        mock_proc.poll.return_value = None
        mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="tcpdump", timeout=0.5)

        mock_log = MagicMock()
        mock_log.closed = False
        mock_proc._ps028_log_fp = mock_log

        with patch("os.kill") as mock_kill:
            with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                run_trial.stop_packet_capture(mock_proc, timeout=0.5)

        self.assertIn("failed to exit", str(ctx.exception).lower())
        # Log should still be closed in finally
        mock_log.close.assert_called_once()

    def test_stop_packet_capture_fails_when_pcap_missing(self):
        """Verifies stop_packet_capture raises CaptureShutdownError when output PCAP does not exist."""
        mock_proc = MagicMock()
        mock_proc.pid = 43210
        mock_proc._ps028_tcpdump_pid = 43210
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0

        pcap_path = self.temp_dir / "nonexistent.pcap"
        with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
            run_trial.stop_packet_capture(mock_proc, timeout=1.0, pcap_path=pcap_path)
        self.assertIn("missing", str(ctx.exception).lower())

    def test_stop_packet_capture_fails_when_pcap_truncated(self):
        """Verifies stop_packet_capture raises CaptureShutdownError when PCAP file is truncated."""
        mock_proc = MagicMock()
        mock_proc.pid = 43210
        mock_proc._ps028_tcpdump_pid = 43210
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0

        pcap_path = self.temp_dir / "truncated.pcap"
        pcap_path.write_bytes(b"\xa1\xb2\xc3")  # less than 24 bytes

        with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
            run_trial.stop_packet_capture(mock_proc, timeout=1.0, pcap_path=pcap_path)
        self.assertIn("invalid or not finalized", str(ctx.exception).lower())

    def test_stop_packet_capture_fails_when_pcap_invalid_magic(self):
        """Verifies stop_packet_capture raises CaptureShutdownError when PCAP magic bytes are corrupted."""
        mock_proc = MagicMock()
        mock_proc.pid = 43210
        mock_proc._ps028_tcpdump_pid = 43210
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0

        pcap_path = self.temp_dir / "bad_magic.pcap"
        bad_header = struct.pack("<IHHIIII", 0x11223344, 2, 4, 0, 0, 65535, 1)
        pcap_path.write_bytes(bad_header)

        with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
            run_trial.stop_packet_capture(mock_proc, timeout=1.0, pcap_path=pcap_path)
        self.assertIn("invalid", str(ctx.exception).lower())

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.impair.apply_scenario")
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.stop_packet_capture")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_live_trial_unconfirmed_shutdown_invalidates_capture_and_forces_inconclusive(
        self, mock_base, mock_clear, mock_stop, mock_browser, mock_cap, mock_apply, mock_ready
    ):
        """
        CRITICAL REQUIREMENT:
        If shutdown is unconfirmed in a LIVE trial, invalidate the LIVE capture,
        classify it as INCONCLUSIVE, always restore the lab baseline and clean up.
        """
        mock_ready.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "chromium", "path": "/usr/bin/chromium", "version": "120"}}
        }
        # Simulate browser that ran and claims HTTP success
        mock_browser.return_value = {
            "name": "chromium",
            "executable": "/usr/bin/chromium",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 120.0,
            "stdout": "<html><body>Measurement Page</body></html>",
            "stderr": "",
            "http_status": None,
            "success": True,
            "winning_family": None
        }

        # stop_packet_capture fails and raises CaptureShutdownError
        mock_stop.side_effect = run_trial.CaptureShutdownError("tcpdump process failed to exit after escalation")

        trial_dir = self.temp_dir / "live_unconfirmed_shutdown"
        trial_dir.mkdir(parents=True, exist_ok=True)
        # Even if a PCAP file exists from the trial
        pcap_file = trial_dir / "capture.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt_data = b"\x00" * 40
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(pkt_data), len(pkt_data))
        pcap_file.write_bytes(header + pkt_hdr + pkt_data)

        res = run_trial.run_trial(
            scenario_id="S0",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        # 1. LIVE capture must be invalidated
        self.assertFalse(res["capture_metadata"]["pcap_valid"])
        self.assertIn("Capture shutdown unconfirmed", res["capture_metadata"]["validation_message"])

        # 2. Must be classified as INCONCLUSIVE
        net_obs = res["network_observations"]
        self.assertEqual(net_obs["classification"], "INCONCLUSIVE")
        self.assertFalse(net_obs["fallback_occurred"])
        self.assertFalse(net_obs["ipv6_attempt"])
        self.assertFalse(net_obs["ipv4_attempt"])
        self.assertFalse(net_obs["ipv6_success"])
        self.assertFalse(net_obs["ipv4_success"])
        self.assertIn("Capture shutdown unconfirmed", net_obs["classification_reason"])

        # 3. HTTP outcome stripped of success
        self.assertIsNone(res["http_outcome"]["status_code"])
        self.assertFalse(res["http_outcome"]["success"])

        # 4. Lab baseline must ALWAYS be restored and cleaned up
        mock_clear.assert_called()
        mock_base.assert_called()
        self.assertTrue(res["cleanup_status"]["scenario_restored"])
        self.assertTrue(res["cleanup_status"]["baseline_verified"])
        self.assertTrue(res["cleanup_status"]["profile_cleaned"])
        self.assertTrue(any("Capture shutdown unconfirmed" in err for err in res["cleanup_status"]["errors"]))

        # 5. Result JSON persisted
        result_json_path = trial_dir / "result.json"
        self.assertTrue(result_json_path.is_file())
        loaded = json.loads(result_json_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["network_observations"]["classification"], "INCONCLUSIVE")

    def test_is_safe_capture_process_distinguishes_tcpdump_from_unrelated(self):
        """Verifies is_safe_capture_process correctly identifies safe vs unrelated processes."""
        # Non-existent PID returns False (fails closed when /proc identity files are missing)
        self.assertFalse(run_trial.is_safe_capture_process(99999999))

        # Current process is python3 -> not safe for tcpdump
        self.assertFalse(run_trial.is_safe_capture_process(os.getpid(), is_parent=False))
        self.assertFalse(run_trial.is_safe_capture_process(os.getpid(), is_parent=True))

        # Invalid PIDs
        self.assertFalse(run_trial.is_safe_capture_process(-1))
        self.assertFalse(run_trial.is_safe_capture_process(0))
        self.assertFalse(run_trial.is_safe_capture_process(None))


class TestSafeCaptureProcessRegression(unittest.TestCase):
    """
    Regression tests for is_safe_capture_process fail-closed behavior,
    missing/unreadable /proc handling, substring avoidance, and safe process shutdown.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_proc_regress_"))
        self.mock_proc = self.temp_dir / "proc"
        self.mock_proc.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _setup_proc_pid(
        self,
        pid: int,
        comm: Optional[str] = None,
        cmdline_args: Optional[List[str]] = None
    ) -> Path:
        pid_dir = self.mock_proc / str(pid)
        pid_dir.mkdir(parents=True, exist_ok=True)
        if comm is not None:
            (pid_dir / "comm").write_text(comm, encoding="utf-8")
        if cmdline_args is not None:
            raw = b"\x00".join(arg.encode("utf-8") for arg in cmdline_args) + (b"\x00" if cmdline_args else b"")
            (pid_dir / "cmdline").write_bytes(raw)
        return pid_dir

    def test_fails_closed_when_proc_entry_missing(self):
        """Must return False when the /proc PID directory or files are completely absent."""
        self.assertFalse(run_trial.is_safe_capture_process(12345, proc_dir=self.mock_proc))
        self.assertFalse(run_trial.is_safe_capture_process(99999999, proc_dir=self.mock_proc))

    def test_fails_closed_when_comm_missing(self):
        """Must return False when /proc/<pid>/comm is missing even if cmdline matches."""
        self._setup_proc_pid(12345, comm=None, cmdline_args=["tcpdump", "-i", "any"])
        self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=False, proc_dir=self.mock_proc))
        self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=True, proc_dir=self.mock_proc))

    def test_fails_closed_when_cmdline_missing(self):
        """Must return False when /proc/<pid>/cmdline is missing even if comm matches."""
        self._setup_proc_pid(12345, comm="tcpdump", cmdline_args=None)
        self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=False, proc_dir=self.mock_proc))
        self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=True, proc_dir=self.mock_proc))

    def test_fails_closed_when_comm_or_cmdline_empty(self):
        """Must return False when /proc identity files are empty."""
        # Empty comm
        self._setup_proc_pid(12345, comm="", cmdline_args=["tcpdump", "-i", "any"])
        self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=False, proc_dir=self.mock_proc))

        # Empty cmdline (e.g. kernel threads or zombie processes)
        self._setup_proc_pid(12346, comm="tcpdump", cmdline_args=[])
        self.assertFalse(run_trial.is_safe_capture_process(12346, is_parent=False, proc_dir=self.mock_proc))

    def test_fails_closed_when_proc_file_unreadable(self):
        """Must return False when reading /proc files raises permission or I/O errors."""
        self._setup_proc_pid(12345, comm="tcpdump", cmdline_args=["tcpdump", "-i", "any"])

        with patch.object(Path, "read_text", side_effect=PermissionError("Permission denied")):
            self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=False, proc_dir=self.mock_proc))

        with patch.object(Path, "read_bytes", side_effect=OSError("I/O error")):
            self.assertFalse(run_trial.is_safe_capture_process(12345, is_parent=False, proc_dir=self.mock_proc))

    def test_rejects_substring_matches_on_comm_and_parent(self):
        """
        Tightened parent and capture identification must reject substring matches:
        - comm containing 'ip' (e.g. pip, gzip)
        - cmdline containing 'ip netns' as an argument
        - comm containing 'tcpdump' (e.g. mytcpdump, tcpdump_fake)
        - ip commands not running tcpdump in netns exec
        """
        # Substring 'ip' in comm: 'pip'
        self._setup_proc_pid(2001, comm="pip", cmdline_args=["pip", "install", "something"])
        self.assertFalse(run_trial.is_safe_capture_process(2001, is_parent=False, proc_dir=self.mock_proc))
        self.assertFalse(run_trial.is_safe_capture_process(2001, is_parent=True, proc_dir=self.mock_proc))

        # Substring 'ip' in comm: 'gzip'
        self._setup_proc_pid(2002, comm="gzip", cmdline_args=["gzip", "-d", "file.gz"])
        self.assertFalse(run_trial.is_safe_capture_process(2002, is_parent=True, proc_dir=self.mock_proc))

        # Substring in capture command: 'mytcpdump'
        self._setup_proc_pid(2003, comm="mytcpdump", cmdline_args=["mytcpdump", "-i", "any"])
        self.assertFalse(run_trial.is_safe_capture_process(2003, is_parent=False, proc_dir=self.mock_proc))

        # Substring 'ip netns' in cmdline of unrelated process
        self._setup_proc_pid(2004, comm="cat", cmdline_args=["cat", "ip netns notes.txt"])
        self.assertFalse(run_trial.is_safe_capture_process(2004, is_parent=True, proc_dir=self.mock_proc))

        # ip command but unrelated action (e.g. ip route show)
        self._setup_proc_pid(2005, comm="ip", cmdline_args=["ip", "route", "show"])
        self.assertFalse(run_trial.is_safe_capture_process(2005, is_parent=True, proc_dir=self.mock_proc))

        # ip netns exec but running sleep rather than tcpdump
        self._setup_proc_pid(2006, comm="ip", cmdline_args=["ip", "netns", "exec", "ps028-cl", "sleep", "100"])
        self.assertFalse(run_trial.is_safe_capture_process(2006, is_parent=True, proc_dir=self.mock_proc))

        # Fake parent binary containing 'ip' (e.g. pip netns exec ... tcpdump)
        self._setup_proc_pid(2007, comm="pip", cmdline_args=["pip", "netns", "exec", "ps028-cl", "tcpdump"])
        self.assertFalse(run_trial.is_safe_capture_process(2007, is_parent=True, proc_dir=self.mock_proc))

    def test_accepts_verified_tcpdump_and_parent_processes(self):
        """Verifies genuine tcpdump and parent capture processes pass identification."""
        # Direct tcpdump invocation
        self._setup_proc_pid(3001, comm="tcpdump", cmdline_args=["tcpdump", "-i", "any", "-n"])
        self.assertTrue(run_trial.is_safe_capture_process(3001, is_parent=False, proc_dir=self.mock_proc))

        # Direct tcpdump with absolute path
        self._setup_proc_pid(3002, comm="tcpdump", cmdline_args=["/usr/sbin/tcpdump", "-i", "any"])
        self.assertTrue(run_trial.is_safe_capture_process(3002, is_parent=False, proc_dir=self.mock_proc))

        # Parent process: ip netns exec ps028-cl tcpdump ...
        self._setup_proc_pid(3003, comm="ip", cmdline_args=["ip", "netns", "exec", "ps028-cl", "tcpdump", "-i", "any"])
        self.assertTrue(run_trial.is_safe_capture_process(3003, is_parent=True, proc_dir=self.mock_proc))
        self.assertFalse(run_trial.is_safe_capture_process(3003, is_parent=False, proc_dir=self.mock_proc))

        # Parent process with absolute paths
        self._setup_proc_pid(3004, comm="ip", cmdline_args=["/sbin/ip", "netns", "exec", "ps028-cl", "/usr/sbin/tcpdump"])
        self.assertTrue(run_trial.is_safe_capture_process(3004, is_parent=True, proc_dir=self.mock_proc))

        # Parent process that exec'd tcpdump directly
        self._setup_proc_pid(3005, comm="tcpdump", cmdline_args=["tcpdump", "-i", "any"])
        self.assertTrue(run_trial.is_safe_capture_process(3005, is_parent=True, proc_dir=self.mock_proc))

    def test_stop_packet_capture_distinguishes_exited_process_from_recycled_unrelated_pid(self):
        """
        Confirms stop_packet_capture distinguishes an already exited process from a live unrelated/recycled PID:
        1. Exited process: does not signal, does not raise unrelated process error, confirms exit cleanly.
        2. Live unrelated PID: refuses to signal, raises CaptureShutdownError.
        """
        # Case 1: Exited process (os.kill(pid, 0) raises ProcessLookupError)
        mock_proc_exited = MagicMock()
        mock_proc_exited.pid = 40001
        mock_proc_exited._ps028_tcpdump_pid = 40002
        mock_proc_exited.poll.return_value = 0
        mock_proc_exited.wait.return_value = 0

        pcap_path = self.temp_dir / "valid_exited.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pcap_path.write_bytes(header)

        # When os.kill raises ProcessLookupError, PID is recognized as exited (not unrelated)
        with patch("os.kill", side_effect=ProcessLookupError):
            res = run_trial.stop_packet_capture(mock_proc_exited, timeout=1.0, pcap_path=pcap_path)
            self.assertTrue(res)

        # Case 2: Live unrelated PID (os.kill(pid, 0) succeeds, but is_safe_capture_process returns False)
        mock_proc_live = MagicMock()
        mock_proc_live.pid = 40003
        mock_proc_live._ps028_tcpdump_pid = 40003
        mock_proc_live.poll.return_value = None
        mock_proc_live.wait.return_value = None

        with patch("os.kill") as mock_kill:
            # os.kill(pid, 0) returns None -> indicates process is currently alive
            mock_kill.return_value = None
            with patch("lab.run_trial.is_safe_capture_process", return_value=False):
                with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                    run_trial.stop_packet_capture(mock_proc_live, timeout=0.5)

            self.assertIn("unrelated", str(ctx.exception).lower())
            # Verify no termination signals (SIGINT, SIGTERM, SIGKILL) were sent to the unrelated live PID
            for call_args in mock_kill.call_args_list:
                sig_sent = call_args[0][1] if len(call_args[0]) > 1 else None
                self.assertNotIn(sig_sent, [signal.SIGINT, signal.SIGTERM, signal.SIGKILL])


class TestDNSObservationParsingRegression(unittest.TestCase):
    """
    Offline regression tests for DNS query and response parsing in dissect_pcap:
    - Verifies dns.flags.response handling for 'True'/'False' and '1'/'0' representations.
    - Preserves hostname filtering against background traffic (Google services, telemetry).
    - Preserves existing JSON schema for dns_observations.queries and dns_observations.responses.
    - Correctly includes responses without A/AAAA records, such as type 65 (HTTPS RR).
    - Offline execution without live network or root requirements.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_dns_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parse_dns_response_flag_representations(self):
        """Verifies parse_dns_response_flag handles boolean, numeric, string, and token formats."""
        # True representations
        for val in ["True", "true", "TRUE", "1", "t", "yes", True, 1, 1.0, "True,True", "1,1", "1, 0", "false,true"]:
            self.assertTrue(
                run_trial.parse_dns_response_flag(val),
                f"Expected True for response flag value: {val!r}"
            )

        # False representations
        for val in ["False", "false", "FALSE", "0", "f", "no", False, 0, 0.0, "", None, "False,False", "0,0", "invalid"]:
            self.assertFalse(
                run_trial.parse_dns_response_flag(val),
                f"Expected False for response flag value: {val!r}"
            )

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dissect_pcap_dns_boolean_flags_types_65_a_aaaa(self, mock_run, mock_which):
        """
        Verifies dissect_pcap parses queries and responses with boolean flags ('True'/'False'),
        including types 65, A, and AAAA, adhering to the schema and including type 65 responses without A/AAAA records.
        """
        pcap_file = self.temp_dir / "test.pcap"
        pcap_file.touch()

        target_host = "trial-20261028163450-0ee0c712.he.test"
        # Synthetic tshark output lines with 14 fields separated by tabs:
        # 0: frame.time_epoch, 1: ip.src, 2: ip.dst, 3: ip6.src, 4: ip6.dst, 5: tcp.flags,
        # 6: tcp.srcport, 7: tcp.dstport, 8: dns.qry.name, 9: dns.qry.type, 10: dns.flags.response,
        # 11: dns.a, 12: dns.aaaa, 13: http.response.code
        tshark_lines = [
            f"1793205291.347157\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t65\tFalse\t\t\t",
            f"1793205291.347297\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t28\tFalse\t\t\t",
            f"1793205291.347484\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t1\tFalse\t\t\t",
            f"1793205291.350512\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t65\tTrue\t\t\t",
            f"1793205291.352642\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t28\tTrue\t\t2001:db8:2::10\t",
            f"1793205291.355056\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t1\tTrue\t10.0.2.10\t\t",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(tshark_lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname=target_host)
        dns_obs = dissection["dns"]

        # Validate queries
        queries = dns_obs["queries"]
        self.assertEqual(len(queries), 3)
        self.assertEqual(queries[0], {"qname": target_host, "qtype": "65", "timestamp": 1793205291.347157})
        self.assertEqual(queries[1], {"qname": target_host, "qtype": "AAAA", "timestamp": 1793205291.347297})
        self.assertEqual(queries[2], {"qname": target_host, "qtype": "A", "timestamp": 1793205291.347484})

        # Validate responses
        responses = dns_obs["responses"]
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0], {"qname": target_host, "qtype": "65", "address": "", "timestamp": 1793205291.350512})
        self.assertEqual(responses[1], {"qname": target_host, "qtype": "AAAA", "address": "2001:db8:2::10", "timestamp": 1793205291.352642})
        self.assertEqual(responses[2], {"qname": target_host, "qtype": "A", "address": "10.0.2.10", "timestamp": 1793205291.355056})

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dissect_pcap_dns_numeric_flags_1_and_0(self, mock_run, mock_which):
        """Verifies dissect_pcap correctly parses '1' and '0' representation for dns.flags.response."""
        pcap_file = self.temp_dir / "test_num.pcap"
        pcap_file.touch()

        target_host = "trial-123.he.test"
        tshark_lines = [
            f"100.0\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t65\t0\t\t\t",
            f"100.1\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t28\t0\t\t\t",
            f"100.2\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t1\t0\t\t\t",
            f"100.3\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t65\t1\t\t\t",
            f"100.4\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t28\t1\t\t2001:db8:2::10\t",
            f"100.5\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t1\t1\t10.0.2.10\t\t",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(tshark_lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname=target_host)
        dns_obs = dissection["dns"]

        self.assertEqual(len(dns_obs["queries"]), 3)
        self.assertEqual(len(dns_obs["responses"]), 3)
        self.assertEqual(dns_obs["responses"][0]["qtype"], "65")
        self.assertEqual(dns_obs["responses"][0]["address"], "")
        self.assertEqual(dns_obs["responses"][1]["qtype"], "AAAA")
        self.assertEqual(dns_obs["responses"][1]["address"], "2001:db8:2::10")
        self.assertEqual(dns_obs["responses"][2]["qtype"], "A")
        self.assertEqual(dns_obs["responses"][2]["address"], "10.0.2.10")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dissect_pcap_dns_hostname_filtering_preserves_target_only(self, mock_run, mock_which):
        """Verifies hostname filtering ignores unrelated DNS traffic while retaining target hostname events."""
        pcap_file = self.temp_dir / "filter.pcap"
        pcap_file.touch()

        target_host = "trial-xyz.he.test"
        tshark_lines = [
            # Background traffic from browser
            "10.0\t10.0.1.2\t10.0.1.1\t\t\t\t\t\tclients2.google.com\t65\tFalse\t\t\t",
            "10.1\t10.0.1.1\t10.0.1.2\t\t\t\t\t\tclients2.google.com\t65\tTrue\t\t\t",
            "10.2\t10.0.1.2\t10.0.1.1\t\t\t\t\t\twww.gstatic.com\t1\tFalse\t\t\t",
            "10.3\t10.0.1.1\t10.0.1.2\t\t\t\t\t\twww.gstatic.com\t1\tTrue\t142.250.80.35\t\t",
            # Target hostname traffic
            f"10.4\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t65\tFalse\t\t\t",
            f"10.5\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t65\tTrue\t\t\t",
            f"10.6\t10.0.1.2\t10.0.1.1\t\t\t\t\t\t{target_host}\t1\tFalse\t\t\t",
            f"10.7\t10.0.1.1\t10.0.1.2\t\t\t\t\t\t{target_host}\t1\tTrue\t10.0.2.10\t\t",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(tshark_lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname=target_host)
        queries = dissection["dns"]["queries"]
        responses = dissection["dns"]["responses"]

        self.assertEqual(len(queries), 2)
        self.assertTrue(all(q["qname"] == target_host for q in queries))
        self.assertEqual(len(responses), 2)
        self.assertTrue(all(r["qname"] == target_host for r in responses))

    def test_dissect_pcap_with_recorded_trial_evidence_pcap(self):
        """Verifies dissect_pcap against the recorded trial PCAP from trial-20261028163450-0ee0c712."""
        evidence_pcap = Path("lab/trials/trial-20261028163450-0ee0c712/capture.pcap")
        if not evidence_pcap.is_file():
            self.skipTest(f"Evidence PCAP not found: {evidence_pcap}")
        if not shutil.which("tshark"):
            self.skipTest("tshark binary not available in environment")

        target_host = "trial-20261028163450-0ee0c712.he.test"
        dissection = run_trial.dissect_pcap(evidence_pcap, target_hostname=target_host)

        queries = dissection["dns"]["queries"]
        responses = dissection["dns"]["responses"]

        # Exactly 3 target queries (types 65, AAAA, A)
        self.assertEqual(len(queries), 3)
        self.assertEqual([q["qtype"] for q in queries], ["65", "AAAA", "A"])

        # Exactly 3 target responses (types 65, AAAA, A)
        self.assertEqual(len(responses), 3)
        self.assertEqual([r["qtype"] for r in responses], ["65", "AAAA", "A"])

        # Responses contain correct addresses
        resp_65 = responses[0]
        self.assertEqual(resp_65["qtype"], "65")
        self.assertEqual(resp_65["address"], "")
        self.assertAlmostEqual(resp_65["timestamp"], 1793205291.350512, places=4)

        resp_aaaa = responses[1]
        self.assertEqual(resp_aaaa["qtype"], "AAAA")
        self.assertEqual(resp_aaaa["address"], "2001:db8:2::10")
        self.assertAlmostEqual(resp_aaaa["timestamp"], 1793205291.352642, places=4)

        resp_a = responses[2]
        self.assertEqual(resp_a["qtype"], "A")
        self.assertEqual(resp_a["address"], "10.0.2.10")
        self.assertAlmostEqual(resp_a["timestamp"], 1793205291.355056, places=4)


class TestTcpdumpDropStatisticsAndCaptureLoss(unittest.TestCase):
    """Tests for tcpdump drop statistics parsing and capture loss classification."""

    def test_parse_tcpdump_drop_statistics_with_kernel_drops(self):
        log_text = (
            "tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes\n"
            "166 packets captured\n"
            "168 packets received by filter\n"
            "2 packets dropped by kernel\n"
        )
        stats = run_trial.parse_tcpdump_drop_statistics(log_text)
        self.assertEqual(stats["packets_captured"], 166)
        self.assertEqual(stats["packets_received_by_filter"], 168)
        self.assertEqual(stats["packets_dropped_by_kernel"], 2)
        self.assertEqual(stats["packets_dropped_by_interface"], 0)
        self.assertEqual(stats["total_packets_dropped"], 2)
        self.assertTrue(stats["capture_loss"])
        self.assertIn("Capture loss detected", stats["capture_loss_message"])
        self.assertIn("2 dropped by kernel", stats["capture_loss_message"])

    def test_parse_tcpdump_drop_statistics_zero_drops(self):
        log_text = (
            "tcpdump: listening on any, link-type LINUX_SLL2\n"
            "100 packets captured\n"
            "100 packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        stats = run_trial.parse_tcpdump_drop_statistics(log_text)
        self.assertEqual(stats["packets_captured"], 100)
        self.assertEqual(stats["packets_received_by_filter"], 100)
        self.assertEqual(stats["packets_dropped_by_kernel"], 0)
        self.assertEqual(stats["total_packets_dropped"], 0)
        self.assertFalse(stats["capture_loss"])
        self.assertIsNone(stats["capture_loss_message"])

    def test_parse_tcpdump_drop_statistics_interface_drops(self):
        log_text = (
            "50 packets captured\n"
            "55 packets received by filter\n"
            "0 packets dropped by kernel\n"
            "5 packets dropped by interface\n"
        )
        stats = run_trial.parse_tcpdump_drop_statistics(log_text)
        self.assertEqual(stats["packets_dropped_by_interface"], 5)
        self.assertEqual(stats["total_packets_dropped"], 5)
        self.assertTrue(stats["capture_loss"])

    def test_classify_fallback_marks_inconclusive_when_capture_loss_is_true(self):
        """
        PS-028 Invariant:
        When capture loss is detected (dropped packets), absence of an IPv4 attempt
        must NOT produce a conclusive DIRECT_IPV6 classification. It must be INCONCLUSIVE.
        """
        dissection = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 1000.0,
                "syn_ack_received": True,
                "syn_ack_time": 1000.03,
                "rst_received": False,
                "connection_established": True,
                "http_observed": True,
            },
            "ipv4": {
                "syn_count": 0,
                "first_syn_time": None,
                "syn_ack_received": False,
                "syn_ack_time": None,
                "rst_received": False,
                "connection_established": False,
                "http_observed": False,
            },
            "connection_attempt_delay_ms": None,
            "connection_setup_time_ms": 30.0,
            "http_status_code": 200,
            "http_response_family": "IPv6",
        }
        http_outcome = {"success": True, "winning_address_family": "IPv6"}

        # Case A: With capture loss -> INCONCLUSIVE
        res_loss = run_trial.classify_fallback(
            dissection=dissection,
            http_outcome=http_outcome,
            pcap_valid=True,
            capture_loss=True,
            capture_loss_message="2 packet(s) dropped by kernel"
        )
        self.assertEqual(res_loss["classification"], "INCONCLUSIVE")
        self.assertFalse(res_loss["fallback_occurred"])
        self.assertIn("Capture loss detected", res_loss["reason"])

        # Case B: Without capture loss -> DIRECT_IPV6
        res_clean = run_trial.classify_fallback(
            dissection=dissection,
            http_outcome=http_outcome,
            pcap_valid=True,
            capture_loss=False
        )
        self.assertEqual(res_clean["classification"], "DIRECT_IPV6")
        self.assertFalse(res_clean["fallback_occurred"])


class TestChromiumNetLogExtraction(unittest.TestCase):
    """Tests for extracting HTTP status and connection telemetry from Chromium NetLog."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_netlog_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parse_chromium_netlog_extracts_http_200_and_ipv6(self):
        netlog_path = self.temp_dir / "netlog.json"
        netlog_data = {
            "constants": {
                "logEventTypes": {
                    "URL_REQUEST_START_JOB": 1,
                    "TCP_CONNECT": 2,
                    "HTTP_TRANSACTION_READ_RESPONSE_HEADERS": 3
                }
            },
            "events": [
                {
                    "source": {"id": 101},
                    "type": 1,
                    "params": {"url": "http://trial-xyz.he.test/"}
                },
                {
                    "source": {"id": 102},
                    "type": 2,
                    "params": {"remote_address": "[2001:db8:2::10]:80"}
                },
                {
                    "source": {"id": 101},
                    "type": 3,
                    "params": {
                        "headers": [
                            "HTTP/1.1 200 OK",
                            "Content-Type: text/html",
                            "Server: nginx"
                        ]
                    }
                }
            ]
        }
        netlog_path.write_text(json.dumps(netlog_data), encoding="utf-8")

        res = run_trial.parse_chromium_netlog(netlog_path, target_url="http://trial-xyz.he.test/")
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["winning_family"], "IPv6")
        self.assertEqual(res["remote_address"], "[2001:db8:2::10]:80")

    def test_parse_chromium_netlog_extracts_http_404_response(self):
        netlog_path = self.temp_dir / "netlog.json"
        netlog_data = {
            "constants": {
                "logEventTypes": {
                    "URL_REQUEST_START_JOB": 1,
                    "TCP_CONNECT": 2,
                    "HTTP_TRANSACTION_READ_RESPONSE_HEADERS": 3
                }
            },
            "events": [
                {
                    "source": {"id": 201},
                    "type": 1,
                    "params": {"url": "http://trial-xyz.he.test/favicon.ico"}
                },
                {
                    "source": {"id": 202},
                    "type": 2,
                    "params": {"remote_address": "10.0.2.10:80"}
                },
                {
                    "source": {"id": 201},
                    "type": 3,
                    "params": {
                        "headers": [
                            "HTTP/1.1 404 Not Found",
                            "Content-Type: text/html"
                        ]
                    }
                }
            ]
        }
        netlog_path.write_text(json.dumps(netlog_data), encoding="utf-8")

        res = run_trial.parse_chromium_netlog(netlog_path, target_url="http://trial-xyz.he.test/favicon.ico")
        self.assertEqual(res["status_code"], 404)
        self.assertEqual(res["winning_family"], "IPv4")

    def test_parse_chromium_netlog_handles_missing_file_gracefully(self):
        missing_path = self.temp_dir / "nonexistent.json"
        res = run_trial.parse_chromium_netlog(missing_path)
        self.assertIsNone(res["status_code"])
        self.assertIsNone(res["winning_family"])


class TestBrowserLaunchEnvironmentAndPreflight(unittest.TestCase):
    """
    Focused tests for Chrome unprivileged launch environment,
    effective UID/GID privilege dropping, path writability verification,
    capture readiness confirmation, and preflight failure reporting.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_launch_test_"))
        self.lock_file = self.temp_dir / ".test.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_browser_uid_gid_never_returns_root(self):
        """get_browser_uid_gid must return an unprivileged UID/GID and never root (UID 0)."""
        uid, gid = run_trial.get_browser_uid_gid()
        self.assertNotEqual(uid, 0, "Browser UID must never be 0 (root)")
        self.assertNotEqual(gid, 0, "Browser GID must never be 0 (root)")

    @patch.dict(os.environ, {"SUDO_UID": "1001", "SUDO_GID": "1001"}, clear=False)
    @patch("os.getuid", return_value=0)
    @patch("os.geteuid", return_value=0)
    def test_get_browser_uid_gid_preserves_sudo_invoking_identity(self, mock_euid, mock_uid):
        """When running under sudo (UID 0), get_browser_uid_gid extracts the invoking user's UID/GID."""
        uid, gid = run_trial.get_browser_uid_gid()
        self.assertEqual(uid, 1001)
        self.assertEqual(gid, 1001)

    def test_get_browser_env_sets_unprivileged_identity_and_xdg_paths(self):
        """
        get_browser_env must set HOME to user home, consistent USER/LOGNAME,
        and XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME without /root leaks.
        """
        env = run_trial.get_browser_env(target_uid=1000, target_gid=1000)
        self.assertEqual(env["USER"], "indrani")
        self.assertEqual(env["LOGNAME"], "indrani")
        self.assertEqual(env["HOME"], "/home/indrani")
        self.assertEqual(env["XDG_CONFIG_HOME"], "/home/indrani/.config")
        self.assertEqual(env["XDG_CACHE_HOME"], "/home/indrani/.cache")
        self.assertEqual(env["XDG_DATA_HOME"], "/home/indrani/.local/share")

        # Crucial PS-028 requirement: No inappropriate /root paths in browser environment
        for k, v in env.items():
            self.assertNotIn("/root", v, f"Environment variable {k}={v} must not contain /root")

    def test_get_browser_env_refuses_root_uid(self):
        """get_browser_env must refuse target_uid=0 and raise BrowserPreflightError."""
        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.get_browser_env(target_uid=0, target_gid=0)
        self.assertIn("root user", str(ctx.exception).lower())

    def test_get_browser_env_xdg_runtime_dir_included_only_if_owned_by_user(self):
        """XDG_RUNTIME_DIR is included only if a valid directory exists and is owned by target_uid."""
        mock_user_dir = self.temp_dir / "user_1000"
        mock_user_dir.mkdir(mode=0o700)
        mock_st_user = MagicMock()
        mock_st_user.st_uid = 1000
        mock_st_user.st_mode = stat.S_IFDIR | 0o700

        with patch.object(Path, "stat", return_value=mock_st_user):
            env_with_valid = run_trial.get_browser_env(
                target_uid=1000,
                target_gid=1000,
                base_env={"XDG_RUNTIME_DIR": str(mock_user_dir)}
            )
            self.assertEqual(env_with_valid.get("XDG_RUNTIME_DIR"), str(mock_user_dir))

        mock_st_root = MagicMock()
        mock_st_root.st_uid = 0
        mock_st_root.st_mode = stat.S_IFDIR | 0o700

        with patch.object(Path, "stat", return_value=mock_st_root):
            env_with_root_runtime = run_trial.get_browser_env(
                target_uid=1000,
                target_gid=1000,
                base_env={"XDG_RUNTIME_DIR": "/run/user/0"}
            )
            self.assertNotIn("XDG_RUNTIME_DIR", env_with_root_runtime)

    def test_get_browser_env_rejects_inappropriate_root_paths_in_base_env(self):
        """get_browser_env rejects leaked root paths and cleans environment."""
        tainted_base = {
            "HOME": "/root",
            "USER": "root",
            "LOGNAME": "root",
            "XDG_CONFIG_HOME": "/root/.config",
            "CUSTOM_PATH": "/root/something"
        }
        env = run_trial.get_browser_env(target_uid=1000, target_gid=1000, base_env=tainted_base)
        self.assertEqual(env["HOME"], "/home/indrani")
        self.assertEqual(env["USER"], "indrani")
        for k, v in env.items():
            self.assertNotIn("/root", v)

    def test_verify_browser_paths_writable_success(self):
        """verify_browser_paths_writable succeeds when profile and crashpad dirs are writable."""
        profile = self.temp_dir / "profile"
        mock_env = {
            "HOME": str(self.temp_dir),
            "XDG_CONFIG_HOME": str(self.temp_dir / ".config"),
            "XDG_DATA_HOME": str(self.temp_dir / ".local" / "share")
        }
        paths = run_trial.verify_browser_paths_writable(
            profile_dir=profile,
            target_uid=os.getuid(),
            target_gid=os.getgid(),
            browser_name="google-chrome",
            env=mock_env
        )
        self.assertTrue(paths["profile_dir"].is_dir())
        self.assertTrue(paths["crashpad_dir"].is_dir())

    def test_verify_browser_paths_writable_fails_on_unwritable_profile(self):
        """verify_browser_paths_writable raises BrowserPreflightError when profile is not writable."""
        unwritable_parent = self.temp_dir / "ro_dir"
        unwritable_parent.mkdir()
        unwritable_parent.chmod(0o500)
        profile = unwritable_parent / "subprofile"

        try:
            with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
                run_trial.verify_browser_paths_writable(
                    profile_dir=profile,
                    target_uid=os.getuid(),
                    target_gid=os.getgid()
                )
            self.assertIn("profile directory", str(ctx.exception).lower())
        finally:
            unwritable_parent.chmod(0o700)

    @patch("subprocess.run")
    def test_run_browser_executes_with_unprivileged_command_and_clean_env(self, mock_run):
        """
        run_browser drops privileges via setpriv or sudo -u, passes env -i with unprivileged variables,
        and contains no /root paths.
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "<html><body>Clean DOM</body></html>"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "chrome_profile"
        profile.mkdir()

        res = run_trial.run_browser(
            browser_name="google-chrome",
            browser_path="/usr/bin/google-chrome",
            target_url="http://trial-env-test.he.test/",
            profile_dir=profile
        )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)

        self.assertTrue(
            "--reuid=1000" in cmd_str or "sudo -u" in cmd_str,
            f"Command must drop privileges to unprivileged UID: {cmd_str}"
        )
        self.assertIn("env", cmd)
        self.assertIn("-i", cmd)
        self.assertIn("HOME=/home/indrani", cmd_str)
        self.assertIn("USER=indrani", cmd_str)
        self.assertIn("XDG_CONFIG_HOME=/home/indrani/.config", cmd_str)
        self.assertNotIn("/root", cmd_str)
        self.assertEqual(res["exit_code"], 0)

    @patch("subprocess.run")
    def test_run_browser_raises_preflight_on_startup_crash(self, mock_run):
        """
        When Chrome crashes on startup (exit code -5 or permission denied / crashpad error),
        run_browser raises BrowserPreflightError rather than returning network failure.
        """
        mock_proc = MagicMock()
        mock_proc.returncode = -5
        mock_proc.stdout = ""
        mock_proc.stderr = (
            "mkdir: cannot create directory ‘/root’: Permission denied\n"
            "chrome_crashpad_handler: --database is required\n"
        )
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "crash_profile"
        profile.mkdir()

        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.run_browser(
                browser_name="google-chrome",
                browser_path="/usr/bin/google-chrome",
                target_url="http://trial-crash.he.test/",
                profile_dir=profile
            )
        self.assertTrue(
            "signal 5" in str(ctx.exception) or "launch environment error" in str(ctx.exception)
        )

    def test_confirm_capture_ready_detects_listening(self):
        """confirm_capture_ready returns True when 'listening on' is logged."""
        log_file = self.temp_dir / "tcpdump.log"
        log_file.write_text("tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes\n")
        handle = {"parent_pid": os.getpid()}

        ready = run_trial.confirm_capture_ready(handle, log_file, timeout=1.0)
        self.assertTrue(ready)

    def test_confirm_capture_ready_raises_when_not_listening(self):
        """confirm_capture_ready raises TrialExecutionError when 'listening on' is missing."""
        log_file = self.temp_dir / "tcpdump.log"
        log_file.write_text("tcpdump: syntax error\n")
        handle = {"parent_pid": os.getpid()}

        with patch("lab.run_trial._is_pid_alive", return_value=True):
            with self.assertRaises(run_trial.TrialExecutionError) as ctx:
                run_trial.confirm_capture_ready(handle, log_file, timeout=0.1)
            self.assertIn("not confirmed", str(ctx.exception).lower())

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.run_trial.verify_browser_paths_writable")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_run_trial_browser_preflight_failure_aborts_without_network_result(
        self, mock_base, mock_clear, mock_verify, mock_ready
    ):
        """
        Task 5:
        A browser preflight failure is reported as a launch failure rather than a network result.
        Must raise BrowserPreflightError, must NOT generate zero-packet network result,
        and must guarantee profile cleanup and lock release.
        """
        mock_ready.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "google-chrome", "path": "/usr/bin/google-chrome", "valid": True}}
        }
        mock_verify.side_effect = run_trial.BrowserPreflightError(
            "Crashpad database path '/home/indrani/.config/google-chrome/Crash Reports' is not writable"
        )

        trial_dir = self.temp_dir / "preflight_fail_trial"
        trial_dir.mkdir(parents=True, exist_ok=True)

        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.run_trial(
                scenario_id="S0",
                browser_pref="google-chrome",
                is_simulation=False,
                skip_baseline_check=True,
                lock_file=self.lock_file,
                output_dir=trial_dir
            )

        self.assertIn("is not writable", str(ctx.exception))
        result_json = trial_dir / "result.json"
        self.assertFalse(result_json.exists(), "Preflight failure must not produce a result.json with network results")
        self.assertFalse(concurrency.is_lock_held_by_current_thread(self.lock_file))


class TestCaptureFilterBufferAndDropAccountingRegression(unittest.TestCase):
    """
    Regression Test Suite for Task 1, 2, 3, 4, 5:
    - Narrow capture filter preserving required evidence (DNS 10.0.1.1:53, TCP 80 10.0.2.10 and 2001:db8:2::10).
    - Capture buffer configuration (-B 8192) and client interface selection (ps028-cl-rt).
    - Browser background activity suppression flags without DNS/network bypassing.
    - Explicit kernel-drop and interface-drop accounting.
    - Loss-aware classification preventing conclusive claims on packet drops.
    - NetLog evidence preservation surviving profile cleanup.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_filter_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_default_bpf_filter_syntax_and_targets(self):
        """BPF filter compiles with tcpdump and strictly targets required lab endpoints."""
        bpf = run_trial.DEFAULT_BPF_FILTER
        self.assertIn("10.0.1.1", bpf)
        self.assertIn("port 53", bpf)
        self.assertIn("10.0.2.10", bpf)
        self.assertIn("2001:db8:2::10", bpf)
        self.assertIn("tcp port 80", bpf)

        # Validate with tcpdump -d (libpcap BPF compiler)
        res = subprocess.run(
            ["tcpdump", "-d", bpf],
            capture_output=True,
            text=True
        )
        self.assertEqual(res.returncode, 0, f"BPF filter failed to compile: {res.stderr}")
        self.assertIn("ret", res.stdout)

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_start_packet_capture_includes_buffer_interface_and_filter(self, mock_euid, mock_popen):
        """Verifies start_packet_capture passes -i ps028-cl-rt, -B 8192, and narrow BPF filter."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 22222

        pcap_path = self.temp_dir / "capture.pcap"
        log_file = self.temp_dir / "tcpdump.log"

        def _popen_side(*args, **kwargs):
            log_file.write_text("tcpdump: listening on ps028-cl-rt, link-type EN10MB\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side

        proc = run_trial.start_packet_capture(
            output_pcap=pcap_path,
            log_file=log_file,
            netns="ps028-cl",
            is_simulation=False
        )
        self.assertIsNotNone(proc)
        cmd_called = mock_popen.call_args[0][0]

        self.assertIn("-i", cmd_called)
        self.assertIn("ps028-cl-rt", cmd_called)
        self.assertIn("-B", cmd_called)
        self.assertIn("8192", cmd_called)
        self.assertIn("--immediate-mode", cmd_called)
        self.assertIn("-U", cmd_called)
        self.assertIn(run_trial.DEFAULT_BPF_FILTER, cmd_called)
        proc._ps028_log_fp.close()

    @patch("lab.privileged_helper.run_helper_action")
    @patch("os.geteuid", return_value=1000)
    def test_start_packet_capture_unprivileged_passes_filter_and_buffer(self, mock_euid, mock_helper):
        """When unprivileged, start_packet_capture passes --filter and --buffer-size-kb to helper."""
        pcap_path = self.temp_dir / "capture.pcap"
        log_file = self.temp_dir / "tcpdump.log"
        mock_helper.return_value = {
            "status": "OK",
            "parent_pid": 33333,
            "tcpdump_pid": 33334,
            "pcap_path": str(pcap_path),
            "log_path": str(log_file),
            "interface": "ps028-cl-rt",
            "filter": run_trial.DEFAULT_BPF_FILTER,
            "buffer_size_kb": 8192
        }

        proc = run_trial.start_packet_capture(
            output_pcap=pcap_path,
            log_file=log_file,
            netns="ps028-cl",
            is_simulation=False
        )
        self.assertEqual(proc.pid, 33333)
        mock_helper.assert_called_once()
        extra_args = mock_helper.call_args[1].get("extra_args")
        self.assertIn("--interface", extra_args)
        self.assertIn("ps028-cl-rt", extra_args)
        self.assertIn("--filter", extra_args)
        self.assertIn(run_trial.DEFAULT_BPF_FILTER, extra_args)
        self.assertIn("--buffer-size-kb", extra_args)
        self.assertIn("8192", extra_args)

    @patch("subprocess.run")
    def test_run_browser_disables_background_traffic_without_bypassing_network(self, mock_run):
        """
        run_browser configures flags that disable irrelevant background requests
        while strictly preserving genuine DNS/network path (no host-resolver rules or curl).
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "<html>OK</html>"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "prof"
        profile.mkdir()

        res = run_trial.run_browser(
            browser_name="google-chrome",
            browser_path="/usr/bin/google-chrome",
            target_url="http://trial-test.he.test/",
            profile_dir=profile
        )

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)

        # Background suppression flags
        self.assertIn("--disable-component-update", cmd_str)
        self.assertIn("--disable-domain-reliability", cmd_str)
        self.assertIn("--disable-client-side-phishing-detection", cmd_str)
        self.assertIn("--safebrowsing-disable-auto-update", cmd_str)
        self.assertIn("--disable-features=OptimizationHints,Translate", cmd_str)
        self.assertIn("--disable-breakpad", cmd_str)
        self.assertIn("--disable-background-timer-throttling", cmd_str)

        # Invariants: No resolver bypass, no curl
        self.assertNotIn("--host-resolver-rules", cmd_str)
        self.assertNotIn("curl", cmd_str)
        self.assertEqual(cmd[-1], "http://trial-test.he.test/")

    def test_parse_tcpdump_drop_statistics_exact_trial_kernel_drops(self):
        """
        Verifies drop accounting on the exact output observed in trial-20261029185347-28c5e7cb:
        124 captured, 138 received by filter, 14 dropped by kernel.
        """
        log_text = (
            "tcpdump: data link type LINUX_SLL2\n"
            "tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes\n"
            "124 packets captured\n"
            "138 packets received by filter\n"
            "14 packets dropped by kernel\n"
        )
        stats = run_trial.parse_tcpdump_drop_statistics(log_text)
        self.assertEqual(stats["packets_captured"], 124)
        self.assertEqual(stats["packets_received_by_filter"], 138)
        self.assertEqual(stats["packets_dropped_by_kernel"], 14)
        self.assertEqual(stats["packets_dropped_by_interface"], 0)
        self.assertEqual(stats["total_packets_dropped"], 14)
        self.assertTrue(stats["capture_loss"])
        self.assertIn("14 packet(s) lost", stats["capture_loss_message"])
        self.assertIn("14 dropped by kernel", stats["capture_loss_message"])

    def test_parse_tcpdump_drop_statistics_discrepancy_accounting(self):
        """When captured < received without explicit drop line, capture loss is detected."""
        log_text = (
            "40 packets captured\n"
            "50 packets received by filter\n"
        )
        stats = run_trial.parse_tcpdump_drop_statistics(log_text)
        self.assertEqual(stats["packets_captured"], 40)
        self.assertEqual(stats["packets_received_by_filter"], 50)
        self.assertEqual(stats["total_packets_dropped"], 10)
        self.assertTrue(stats["capture_loss"])

    def test_classify_fallback_prevents_conclusive_direct_ipv4_on_loss(self):
        """Capture loss prevents conclusive DIRECT_IPV4 claims when IPv6 attempts are unobserved."""
        dissection = {
            "ipv6": {"syn_count": 0, "first_syn_time": None, "syn_ack_received": False, "syn_ack_time": None, "rst_received": False, "connection_established": False, "http_observed": False},
            "ipv4": {"syn_count": 1, "first_syn_time": 100.0, "syn_ack_received": True, "syn_ack_time": 100.02, "rst_received": False, "connection_established": True, "http_observed": True},
            "connection_attempt_delay_ms": None,
            "connection_setup_time_ms": 20.0,
            "http_status_code": 200,
            "http_response_family": "IPv4"
        }
        res = run_trial.classify_fallback(
            dissection=dissection,
            http_outcome={"success": True, "winning_address_family": "IPv4"},
            pcap_valid=True,
            capture_loss=True,
            capture_loss_message="14 dropped by kernel"
        )
        self.assertEqual(res["classification"], "INCONCLUSIVE")
        self.assertIn("Capture loss detected", res["reason"])

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.run_trial.verify_browser_paths_writable")
    @patch("lab.impair.apply_scenario")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.stop_packet_capture", return_value=True)
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.validate_pcap_file")
    def test_netlog_preserved_in_trial_dir_survives_profile_cleanup(
        self, mock_val_pcap, mock_browser, mock_stop_cap, mock_start_cap,
        mock_baseline, mock_clear, mock_apply, mock_verify, mock_readiness
    ):
        """
        Task 5:
        Ensures NetLog is copied to trial_dir / 'netlog.json' and survives profile directory cleanup.
        evidence_paths['browser_netlog'] must point to the persistent file in trial_dir.
        """
        mock_readiness.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "google-chrome", "path": "/usr/bin/google-chrome", "valid": True}}
        }
        mock_val_pcap.return_value = (True, "aabbcc", 1024, 15, "Valid PCAP")

        trial_dir = self.temp_dir / "trial_netlog_preservation"
        trial_dir.mkdir(parents=True, exist_ok=True)

        def _mock_run_browser(*args, **kwargs):
            pdir = kwargs.get("profile_dir")
            netlog = pdir / "netlog.json"
            netlog.write_text('{"constants": {}, "events": [{"type": 1}]}', encoding="utf-8")
            return {
                "name": "google-chrome",
                "executable": "/usr/bin/google-chrome",
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 500.0,
                "stdout": "OK",
                "stderr": "",
                "http_status": 200,
                "success": True,
                "winning_family": "IPv6",
                "netlog_path": str(netlog)
            }

        mock_browser.side_effect = _mock_run_browser

        res = run_trial.run_trial(
            scenario_id="S0",
            browser_pref="google-chrome",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        persistent_netlog = trial_dir / "netlog.json"
        self.assertTrue(persistent_netlog.is_file(), "NetLog evidence must exist in trial directory")
        self.assertEqual(res["evidence_paths"]["browser_netlog"], str(persistent_netlog))
        self.assertTrue(res["browser"]["profile_cleaned"])


class TestFirefoxSupportRegression(unittest.TestCase):
    """
    Focused regression and compliance tests for standalone Firefox runner:
    1. Runtime discovery & non-Snap qualification.
    2. Command construction (Firefox flags vs Chrome flag exclusion).
    3. Execution environment (clean environment, unprivileged UID, MOZ_LOG, no /root).
    4. Telemetry parsing & status/winning-family instrumentation.
    5. Evidence preservation, profile cleanup, and lock safety.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_firefox_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_firefox_discovery_with_explicit_standalone_path(self):
        """Verifies explicit standalone Firefox path is discovered and qualified."""
        with patch("lab.run_trial._query_browser_version", return_value="Mozilla Firefox 159.0"):
            bname, bpath, bver = run_trial.find_browser_runtime(
                preferred="/home/indrani/opt/firefox-measurement/firefox"
            )
            self.assertEqual(bname, "firefox")
            self.assertEqual(bpath, "/home/indrani/opt/firefox-measurement/firefox")
            self.assertEqual(bver, "Mozilla Firefox 159.0")

    def test_firefox_standalone_is_not_detected_as_snap(self):
        """Standalone Firefox binary must not be classified as a Snap-backed package."""
        self.assertFalse(run_trial.is_snap_browser("/home/indrani/opt/firefox-measurement/firefox"))

    def test_firefox_snap_binary_is_detected_as_snap(self):
        """Standard Ubuntu Snap binary at /snap/bin/firefox must be identified as Snap."""
        self.assertTrue(run_trial.is_snap_browser("/snap/bin/firefox"))

    def test_firefox_command_construction_and_flags(self):
        """
        Firefox command must include headless, profile, no-remote, new-instance,
        and strictly omit Chrome-only flags.
        """
        profile_dir = self.temp_dir / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        captured_cmd = []

        def mock_subprocess_run(cmd, **kwargs):
            nonlocal captured_cmd
            if isinstance(cmd, list) and not any(c == "pkill" for c in cmd):
                captured_cmd = list(cmd)
                log_file = profile_dir / "moz_telemetry.log"
                log_file.write_text("nsHttpTransaction [HTTP/1.1 200 OK]\n", encoding="utf-8")
            res = MagicMock()
            res.returncode = 0
            res.stdout = "OK"
            res.stderr = ""
            return res

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch("lab.run_trial.get_browser_uid_gid", return_value=(1000, 1000)):
            run_trial.run_browser(
                browser_name="firefox",
                browser_path="/home/indrani/opt/firefox-measurement/firefox",
                target_url="http://trial-test.he.test/",
                profile_dir=profile_dir,
                timeout=5.0,
                is_simulation=False
            )

        cmd_str = " ".join(captured_cmd)
        self.assertIn("--headless", captured_cmd)
        self.assertIn("--profile", captured_cmd)
        self.assertIn(str(profile_dir.resolve()), captured_cmd)
        self.assertIn("--no-remote", captured_cmd)
        self.assertIn("--new-instance", captured_cmd)
        self.assertEqual(captured_cmd[-1], "http://trial-test.he.test/")

        # Strictly omit Chrome-only flags
        self.assertNotIn("--dump-dom", cmd_str)
        self.assertNotIn("--user-data-dir", cmd_str)
        self.assertNotIn("--no-sandbox", cmd_str)
        self.assertNotIn("--disable-gpu", cmd_str)
        self.assertNotIn("--log-net-log", cmd_str)
        self.assertNotIn("--disable-background-networking", cmd_str)
        self.assertNotIn("--safebrowsing-disable-auto-update", cmd_str)
        self.assertNotIn("launch-snap-browser", cmd_str)

    def test_firefox_execution_environment(self):
        """
        Browser environment must define MOZ_LOG, MOZ_LOG_FILE, valid XDG dirs,
        and not leak root directories.
        """
        profile_dir = self.temp_dir / "profile"
        profile_dir.mkdir(parents=True, exist_ok=True)
        captured_cmd = []
        captured_env = {}

        def mock_subprocess_run(cmd, **kwargs):
            nonlocal captured_cmd, captured_env
            if isinstance(cmd, list) and not any(c == "pkill" for c in cmd):
                captured_cmd = list(cmd)
                captured_env = dict(kwargs.get("env") or {})
                log_file = profile_dir / "moz_telemetry.log"
                log_file.write_text("nsHttpTransaction [HTTP/1.1 200 OK]\n", encoding="utf-8")
            res = MagicMock()
            res.returncode = 0
            res.stdout = ""
            res.stderr = ""
            return res

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch("lab.run_trial.get_browser_uid_gid", return_value=(1000, 1000)):
            run_trial.run_browser(
                browser_name="firefox",
                browser_path="/home/indrani/opt/firefox-measurement/firefox",
                target_url="http://trial-test.he.test/",
                profile_dir=profile_dir,
                timeout=5.0,
                is_simulation=False
            )

        env_args = [arg for arg in captured_cmd if "=" in arg]
        env_dict = dict(arg.split("=", 1) for arg in env_args if not arg.startswith("--"))
        env_dict.update(captured_env)

        self.assertIn("MOZ_LOG", env_dict)
        self.assertIn("nsHttp:5", env_dict["MOZ_LOG"])
        self.assertIn("nsSocketTransport:5", env_dict["MOZ_LOG"])
        self.assertIn("MOZ_LOG_FILE", env_dict)
        self.assertTrue(env_dict["MOZ_LOG_FILE"].endswith("moz_telemetry.log"))
        self.assertNotIn("/root", env_dict.get("HOME", ""))
        self.assertNotIn("/root", env_dict.get("XDG_CONFIG_HOME", ""))

        # Check user.js generated in profile
        user_js = profile_dir / "user.js"
        self.assertTrue(user_js.is_file(), "user.js must be created in profile_dir")
        content = user_js.read_text(encoding="utf-8")
        self.assertIn("app.update.auto", content)
        self.assertIn("network.dns.disablePrefetch", content)

    def test_parse_firefox_telemetry_ipv6_success(self):
        """Telemetry log with IPv6 connection records HTTP 200 and IPv6 winning family."""
        log_dir = self.temp_dir / "moz_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "moz_telemetry.log.main.1234"
        log_file.write_text(
            "2026-10-29 20:00:00.000000 UTC - [Parent 1234: Socket Thread]: D/nsSocketTransport trying address: 2001:db8:2::10\n"
            "2026-10-29 20:00:00.015000 UTC - [Parent 1234: Main Thread]: V/nsHttp ConnectionEntry::RecordIPFamilyPreference af=10\n"
            "2026-10-29 20:00:00.020000 UTC - [Parent 1234: Main Thread]: V/nsHttp nsHttpTransaction 0x7f1 [HTTP/1.1 200 OK]\n",
            encoding="utf-8"
        )
        parsed = run_trial.parse_firefox_telemetry(log_dir, target_url="http://trial-123.he.test/")
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["winning_family"], "IPv6")
        self.assertEqual(parsed["remote_address"], "2001:db8:2::10")

    def test_parse_firefox_telemetry_ipv4_fallback(self):
        """Telemetry log with IPv4 fallback records HTTP 200 and IPv4 winning family."""
        log_dir = self.temp_dir / "moz_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "moz_telemetry.log"
        log_file.write_text(
            "2026-10-29 20:00:00.000000 UTC - D/nsSocketTransport trying address: 2001:db8:2::10\n"
            "2026-10-29 20:00:00.250000 UTC - D/nsSocketTransport trying address: 10.0.2.10\n"
            "2026-10-29 20:00:00.270000 UTC - V/nsHttp ConnectionEntry::RecordIPFamilyPreference af=2\n"
            "2026-10-29 20:00:00.280000 UTC - V/nsHttp nsHttpResponseHead [HTTP/1.1 200 OK]\n",
            encoding="utf-8"
        )
        parsed = run_trial.parse_firefox_telemetry(log_file, target_url="http://trial-123.he.test/")
        self.assertEqual(parsed["status_code"], 200)
        self.assertEqual(parsed["winning_family"], "IPv4")
        self.assertEqual(parsed["remote_address"], "10.0.2.10")

    def test_parse_firefox_telemetry_http_error(self):
        """Telemetry log with 404 or 500 status code is accurately parsed."""
        log_file = self.temp_dir / "error.log"
        log_file.write_text(
            "V/nsHttp nsHttpTransaction 0x123 [HTTP/1.1 404 handled]\n",
            encoding="utf-8"
        )
        parsed = run_trial.parse_firefox_telemetry(log_file)
        # Check that regex captures 404
        log_file.write_text(
            "V/nsHttp nsHttpTransaction 0x123 [HTTP/1.1 404 Not Found]\n",
            encoding="utf-8"
        )
        parsed = run_trial.parse_firefox_telemetry(log_file)
        self.assertEqual(parsed["status_code"], 404)

    def test_parse_firefox_telemetry_empty_or_corrupt(self):
        """Empty or non-existent telemetry logs return None status and None family."""
        missing = self.temp_dir / "nonexistent.log"
        parsed = run_trial.parse_firefox_telemetry(missing)
        self.assertIsNone(parsed["status_code"])
        self.assertIsNone(parsed["winning_family"])

    @patch("lab.run_trial.validate_lab_readiness")
    @patch("lab.run_trial.verify_browser_paths_writable")
    @patch("lab.impair.apply_scenario")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.start_packet_capture")
    @patch("lab.run_trial.stop_packet_capture", return_value=True)
    @patch("lab.run_trial.run_browser")
    @patch("lab.run_trial.validate_pcap_file")
    def test_firefox_evidence_preservation_and_profile_cleanup(
        self, mock_val_pcap, mock_browser, mock_stop_cap, mock_start_cap,
        mock_baseline, mock_clear, mock_apply, mock_verify, mock_readiness
    ):
        """
        Telemetry log is copied to trial_dir / 'browser_telemetry.log'
        and profile directory is cleaned up.
        """
        mock_readiness.return_value = {
            "status": "PASS",
            "checks": {"browser": {"name": "firefox", "path": "/home/indrani/opt/firefox-measurement/firefox", "valid": True}}
        }
        mock_val_pcap.return_value = (True, "aabbcc", 1024, 15, "Valid PCAP")

        trial_dir = self.temp_dir / "trial_firefox_preservation"
        trial_dir.mkdir(parents=True, exist_ok=True)

        def _mock_run_browser(*args, **kwargs):
            pdir = kwargs.get("profile_dir")
            telem = pdir / "moz_telemetry.log"
            telem.write_text("nsHttpTransaction [HTTP/1.1 200 OK]\n", encoding="utf-8")
            return {
                "name": "firefox",
                "executable": "/home/indrani/opt/firefox-measurement/firefox",
                "exit_code": 0,
                "timed_out": False,
                "duration_ms": 1200.0,
                "stdout": "",
                "stderr": "",
                "http_status": 200,
                "success": True,
                "winning_family": "IPv6",
                "telemetry_path": str(telem)
            }

        mock_browser.side_effect = _mock_run_browser

        res = run_trial.run_trial(
            scenario_id="S0",
            browser_pref="/home/indrani/opt/firefox-measurement/firefox",
            is_simulation=False,
            skip_baseline_check=True,
            lock_file=self.lock_file,
            output_dir=trial_dir
        )

        persistent_telemetry = trial_dir / "browser_telemetry.log"
        self.assertTrue(persistent_telemetry.is_file(), "Telemetry evidence must exist in trial directory")
        self.assertEqual(res["evidence_paths"]["browser_telemetry"], str(persistent_telemetry))
        self.assertTrue(res["browser"]["profile_cleaned"])
        self.assertTrue(res["cleanup_status"]["lock_released"])

    def test_firefox_launch_failure_reported_as_preflight_error(self):
        """Failed browser discovery or preflight is reported as preflight failure, not network result."""
        with patch("lab.run_trial.validate_lab_readiness") as mock_readiness:
            mock_readiness.return_value = {
                "status": "FAIL",
                "errors": ["Browser runtime '/nonexistent/firefox' does not exist or is not executable"],
                "checks": {"browser": {"valid": False}}
            }
            with self.assertRaises(run_trial.BrowserPreflightError):
                run_trial.run_trial(
                    scenario_id="S0",
                    browser_pref="/nonexistent/firefox",
                    is_simulation=False,
                    lock_file=self.lock_file
                )


if __name__ == "__main__":
    unittest.main()
