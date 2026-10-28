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

    @patch("subprocess.Popen")
    def test_start_packet_capture_includes_immediate_mode_and_readiness(self, mock_popen):
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

    @patch("subprocess.Popen")
    @patch("lab.run_trial.stop_packet_capture")
    def test_start_packet_capture_fails_and_cleans_up_on_readiness_timeout(self, mock_stop, mock_popen):
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

    @patch("subprocess.Popen")
    def test_start_packet_capture_fails_when_tcpdump_terminates_prematurely(self, mock_popen):
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


if __name__ == "__main__":
    unittest.main()
