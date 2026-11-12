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

import hashlib
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

from dataclasses import FrozenInstanceError
import pwd
import lab.concurrency as concurrency
import lab.dns_server as dns_server
import lab.identity as identity
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
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
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
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "DIRECT_IPV6")

    def test_direct_ipv6_when_both_attempted_but_ipv6_wins_navigation(self):
        """
        When both IPv6 and IPv4 connections are established but IPv6 won HTTP navigation
        (e.g., post-navigation favicon or speculative preconnect over IPv4),
        classification MUST report DIRECT_IPV6 and fallback_occurred=False.
        """
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": False, "first_syn_time": 10.3},
            "connection_attempt_delay_ms": 300.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "DIRECT_IPV6")
        self.assertIn("won HTTP navigation", res["reason"])
        self.assertIn("Connection Attempt Delay: 300.0ms", res["reason"])

    def test_direct_ipv6_when_both_attempted_and_main_flow_correlated_to_ipv6(self):
        """
        Regression test for S5 flow correlation:
        When main_http_flow confirms the primary GET / request was served over IPv6,
        even if an ancillary connection occurred on IPv4, classification must be DIRECT_IPV6.
        """
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.301},
            "connection_attempt_delay_ms": 301.0,
            "main_http_flow": {
                "stream_id": "2",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "DIRECT_IPV6")
        self.assertIn("Main GET / request correlated to IPv6 TCP flow", res["reason"])
        self.assertIn("Connection Attempt Delay: 301.0ms", res["reason"])

    def test_direct_ipv6_when_secondary_ipv4_attempt_fails_to_establish(self):
        """
        When primary IPv6 establishes and wins, and secondary IPv4 attempt is made
        but fails to establish, classification must be DIRECT_IPV6.
        """
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.25},
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "1",
                "family": "IPv6",
                "status_code": 200,
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(res["fallback_occurred"])
        self.assertEqual(res["classification"], "DIRECT_IPV6")
        self.assertIn("Secondary IPv4 connection attempt did not establish", res["reason"])

    def test_do_not_infer_fallback_from_http_200_alone_when_ipv6_not_attempted(self):
        """
        CRITICAL PS-028 REQUIREMENT:
        HTTP 200 on IPv4 without prior IPv6 attempt MUST NOT be classified as fallback!
        It must report DIRECT_IPV4 and fallback_occurred=False.
        """
        dissection = {
            "ipv6": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
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
        """Verifies dissect_pcap extracts HTTP status code (200) from raw data as diagnostic only."""
        pcap_file = self.temp_dir / "http.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        http_data = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 12\r\n\r\nHello World!"
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(http_data), len(http_data))
        pcap_file.write_bytes(header + pkt_hdr + http_data)

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname="trial-1.he.test")
        # Diagnostic raw PCAP code is extracted, but uncorrelated raw byte signature
        # does not populate authoritative primary-navigation status or main HTTP flow.
        self.assertEqual(dissection["diagnostic_raw_pcap_http_code"], 200)
        self.assertIsNone(dissection["http_status_code"])
        self.assertIsNone(dissection["main_http_flow"]["status_code"])
        self.assertFalse(dissection["main_http_flow"]["correlated"])

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

        target_host = "trial-dns-parser-fixture.he.test"
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
        """
        Integration test verifying validate_pcap_file and dissect_pcap against the authentic,
        Git-tracked October 29 S6 recorded trial capture: trial-20261029215022-d5cc11cb.
        """
        self.assertIsNotNone(
            shutil.which("tshark"),
            "tshark is a required integration-test dependency for dissecting PCAP files"
        )

        trial_id = "trial-20261029215022-d5cc11cb"
        trial_dir = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01" / "trials" / trial_id
        evidence_pcap = trial_dir / "capture.pcap"
        evidence_json = trial_dir / "result.json"

        self.assertTrue(evidence_pcap.is_file(), f"Authentic S6 capture PCAP missing: {evidence_pcap}")
        self.assertTrue(evidence_json.is_file(), f"Authentic S6 result JSON missing: {evidence_json}")

        expected_trial_id = "trial-20261029215022-d5cc11cb"
        expected_hostname = "trial-20261029215022-d5cc11cb.he.test"
        expected_sha256 = "75eeda0399bfccc5c8d0c51840d12366a4b48d80e09298f0e62b5dcb40d889c3"
        expected_packet_count = 168

        # 1. Load actual result.json and verify recorded metadata
        with open(evidence_json, "r", encoding="utf-8") as f:
            result_data = json.load(f)

        self.assertEqual(result_data.get("trial_id"), expected_trial_id)
        self.assertEqual(result_data.get("hostname"), expected_hostname)
        self.assertEqual(result_data.get("scenario_id"), "S6")

        capture_meta = result_data.get("capture_metadata", {})
        self.assertTrue(capture_meta.get("pcap_valid"), "capture_metadata indicates PCAP is not valid")
        self.assertEqual(capture_meta.get("pcap_sha256"), expected_sha256)
        self.assertEqual(capture_meta.get("packet_count"), expected_packet_count)

        actual_disk_sha256 = hashlib.sha256(evidence_pcap.read_bytes()).hexdigest()
        self.assertEqual(actual_disk_sha256, expected_sha256)
        self.assertEqual(capture_meta.get("pcap_sha256"), actual_disk_sha256)

        # 2. Independently validate actual PCAP using run_trial.validate_pcap_file (min_packets=1)
        is_valid, val_sha256, val_size, val_packet_count, val_msg = run_trial.validate_pcap_file(
            evidence_pcap, min_packets=1
        )
        self.assertTrue(is_valid, f"PCAP validation failed: {val_msg}")
        self.assertEqual(val_packet_count, expected_packet_count)
        self.assertEqual(val_sha256, expected_sha256)

        # 3. Dissect authentic PCAP using real tshark
        dissection = run_trial.dissect_pcap(evidence_pcap, target_hostname=expected_hostname)

        # 4. Assert DNS query and response evidence
        dns_obs = dissection["dns"]
        queries = dns_obs["queries"]
        responses = dns_obs["responses"]

        # Target hostname correctly filtered
        self.assertEqual(len(queries), 3)
        self.assertTrue(all(q["qname"] == expected_hostname for q in queries))
        self.assertEqual(len(responses), 3)
        self.assertTrue(all(r["qname"] == expected_hostname for r in responses))

        # Query types include 65, AAAA, and A
        query_types = [q["qtype"] for q in queries]
        self.assertIn("65", query_types)
        self.assertIn("AAAA", query_types)
        self.assertIn("A", query_types)

        # Response types include 65, A, and AAAA
        response_types = [r["qtype"] for r in responses]
        self.assertIn("65", response_types)
        self.assertIn("A", response_types)
        self.assertIn("AAAA", response_types)

        # Type 65 response has no address
        resp_65 = [r for r in responses if r["qtype"] == "65"][0]
        self.assertEqual(resp_65["address"], "")

        # Positive A and AAAA responses contain expected addresses
        resp_a = [r for r in responses if r["qtype"] == "A"][0]
        self.assertEqual(resp_a["address"], "10.0.2.10")

        resp_aaaa = [r for r in responses if r["qtype"] == "AAAA"][0]
        self.assertEqual(resp_aaaa["address"], "2001:db8:2::10")

        # A-to-AAAA interval is approximately 496.544 ms, allowing small floating-point tolerance
        a_to_aaaa_interval_ms = (resp_aaaa["timestamp"] - resp_a["timestamp"]) * 1000.0
        self.assertAlmostEqual(a_to_aaaa_interval_ms, 496.544, places=2)

        # 5. Assert TCP and HTTP evidence
        # IPv4 has zero SYNs, no first SYN timestamp, and no connection established
        ipv4_obs = dissection["ipv4"]
        self.assertEqual(ipv4_obs["syn_count"], 0)
        self.assertIsNone(ipv4_obs["first_syn_time"])
        self.assertFalse(ipv4_obs["connection_established"])

        # IPv6 connection established and SYN-ACK observed
        ipv6_obs = dissection["ipv6"]
        self.assertTrue(ipv6_obs["connection_established"])
        self.assertTrue(ipv6_obs["syn_ack_received"])

        # IPv6 first SYN follows positive AAAA response by approximately 2.928 ms
        self.assertIsNotNone(ipv6_obs["first_syn_time"])
        v6_syn_delay_ms = (ipv6_obs["first_syn_time"] - resp_aaaa["timestamp"]) * 1000.0
        self.assertAlmostEqual(v6_syn_delay_ms, 2.928, places=2)

        # Main HTTP flow correlated
        main_flow = dissection.get("main_http_flow")
        self.assertIsNotNone(main_flow)
        self.assertTrue(main_flow.get("correlated"))

        # Main request is GET /
        self.assertEqual(main_flow.get("request"), ("GET", "/"))

        # Status is 200 and family is IPv6
        self.assertEqual(main_flow.get("status_code"), 200)
        self.assertEqual(main_flow.get("family"), "IPv6")
        self.assertEqual(dissection.get("http_status_code"), 200)
        self.assertEqual(dissection.get("http_response_family"), "IPv6")

        # Handshake completion evidence
        self.assertTrue(ipv6_obs["tcp_handshake_completed"])
        self.assertFalse(ipv4_obs["tcp_handshake_completed"])
        self.assertTrue(main_flow.get("tcp_handshake_completed"))

        # Per-stream handshake and request verification
        tcp_streams = dissection.get("tcp_streams", {})
        self.assertIn("0", tcp_streams)
        self.assertIn("1", tcp_streams)

        # Stream 0: primary navigation flow (GET /)
        s0 = tcp_streams["0"]
        self.assertEqual(s0["syn_frame"], 137)
        self.assertEqual(s0["syn_ack_frame"], 139)
        self.assertEqual(s0["final_ack_frame"], 140)
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertTrue(s0["main_get"])
        self.assertEqual(s0["first_request"], ("GET", "/"))
        self.assertEqual(s0["response_code"], 200)

        # Stream 1: ancillary request (GET /favicon.ico)
        s1 = tcp_streams["1"]
        self.assertEqual(s1["syn_frame"], 138)
        self.assertEqual(s1["syn_ack_frame"], 141)
        self.assertEqual(s1["final_ack_frame"], 142)
        self.assertTrue(s1["tcp_handshake_completed"])
        self.assertEqual(s1["handshake_state"], "CLOSED_BY_CLIENT_ABORT")
        self.assertTrue(s1["client_rst_sent"])
        self.assertFalse(s1["server_rst_received"])
        self.assertFalse(s1["rst_received"])
        self.assertFalse(s1["main_get"])
        self.assertEqual(s1["first_request"], ("GET", "/favicon.ico"))
        self.assertEqual(s1["response_code"], 404)


class TestDissectPcapFlowCorrelationRegression(unittest.TestCase):
    """
    Offline regression tests for correlating the main GET / HTTP request and TCP flow:
    - Distinguishes main GET / request flow from ancillary requests (/favicon.ico).
    - Accurately attributes winning address family to the primary navigation stream.
    - Preserves fallback behavior when primary IPv6 is unestablished and IPv4 serves GET /.
    - Works offline using synthetic tshark field streams.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_flow_corr_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dissect_pcap_correlates_main_get_over_ipv6_with_ancillary_ipv4_favicon(self, mock_run, mock_which):
        """
        Verifies dissect_pcap correlates main GET / on IPv6 (stream 1, code 200)
        and distinguishes it from an ancillary GET /favicon.ico on IPv4 (stream 2, code 404).
        Both streams complete a full 3-way handshake.
        """
        pcap_file = self.temp_dir / "s5_ancillary.pcap"
        pcap_file.touch()

        target_host = "trial-s5.he.test"
        # 20 fields:
        # frame.time_epoch, ip.src, ip.dst, ip6.src, ip6.dst, tcp.flags,
        # tcp.srcport, tcp.dstport, dns.qry.name, dns.qry.type, dns.flags.response,
        # dns.a, dns.aaaa, http.response.code, tcp.stream, http.request.method, http.request.uri,
        # tcp.seq_raw, tcp.ack_raw, frame.number
        tshark_lines = [
            # Stream 1: IPv6 SYN, SYN-ACK, client final ACK (handshake completed)
            f"10.00\t\t\t2001:db8:1::2\t2001:db8:2::10\t0x0002\t32800\t80\t\t\t\t\t\t\t1\t\t\t1000\t0\t1\t0\t\t",
            f"10.02\t\t\t2001:db8:2::10\t2001:db8:1::2\t0x0012\t80\t32800\t\t\t\t\t\t\t1\t\t\t5000\t1001\t2\t0\t\t",
            f"10.025\t\t\t2001:db8:1::2\t2001:db8:2::10\t0x0010\t32800\t80\t\t\t\t\t\t\t1\t\t\t1001\t5001\t3\t0\t\t",
            # Stream 1: IPv6 GET / and 200 OK
            f"10.03\t\t\t2001:db8:1::2\t2001:db8:2::10\t0x0018\t32800\t80\t\t\t\t\t\t\t1\tGET\t/\t1001\t5001\t4\t50\t5\t",
            f"10.05\t\t\t2001:db8:2::10\t2001:db8:1::2\t0x0018\t80\t32800\t\t\t\t\t\t200\t1\t\t\t5001\t1080\t5\t200\t\t4",
            # Stream 2: IPv4 SYN, SYN-ACK, client final ACK (speculative / ancillary)
            f"10.31\t10.0.1.2\t10.0.2.10\t\t\t0x0002\t52132\t80\t\t\t\t\t\t\t2\t\t\t2000\t0\t6\t0\t\t",
            f"10.33\t10.0.2.10\t10.0.1.2\t\t\t0x0012\t80\t52132\t\t\t\t\t\t\t2\t\t\t6000\t2001\t7\t0\t\t",
            f"10.34\t10.0.1.2\t10.0.2.10\t\t\t0x0010\t52132\t80\t\t\t\t\t\t\t2\t\t\t2001\t6001\t8\t0\t\t",
            # Stream 2: IPv4 GET /favicon.ico and 404 Not Found
            f"10.35\t10.0.1.2\t10.0.2.10\t\t\t0x0018\t52132\t80\t\t\t\t\t\t\t2\tGET\t/favicon.ico\t2001\t6001\t9\t50\t10\t",
            f"10.37\t10.0.2.10\t10.0.1.2\t\t\t0x0018\t80\t52132\t\t\t\t\t\t404\t2\t\t\t6001\t2150\t10\t150\t\t9",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(tshark_lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname=target_host)

        # Primary navigation attributes must come from Stream 1 (IPv6, 200 OK)
        self.assertEqual(dissection["http_status_code"], 200)
        self.assertEqual(dissection["http_response_family"], "IPv6")
        flow = dissection["main_http_flow"]
        self.assertTrue(flow["correlated"])
        self.assertEqual(flow["stream_id"], "1")
        self.assertEqual(flow["family"], "IPv6")
        self.assertEqual(flow["status_code"], 200)
        self.assertEqual(flow["request"], ("GET", "/"))
        self.assertTrue(flow["tcp_handshake_completed"])

        # Both connections observed in network observations
        self.assertTrue(dissection["ipv6"]["connection_established"])
        self.assertTrue(dissection["ipv6"]["tcp_handshake_completed"])
        self.assertTrue(dissection["ipv4"]["connection_established"])
        self.assertTrue(dissection["ipv4"]["tcp_handshake_completed"])
        self.assertAlmostEqual(dissection["connection_attempt_delay_ms"], 310.0, delta=1.0)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dissect_pcap_correlates_main_get_over_ipv4_in_fallback_scenario(self, mock_run, mock_which):
        """
        Verifies dissect_pcap correlates main GET / on IPv4 (stream 2, code 200)
        when IPv6 attempt fails (stream 1 SYN blackholed).
        """
        pcap_file = self.temp_dir / "s1_fallback.pcap"
        pcap_file.touch()

        target_host = "trial-s1.he.test"
        tshark_lines = [
            # Stream 1: IPv6 SYN only (blackholed)
            f"10.00\t\t\t2001:db8:1::2\t2001:db8:2::10\t0x0002\t32800\t80\t\t\t\t\t\t\t1\t\t\t1000\t0\t1\t0\t\t",
            # Stream 2: IPv4 SYN, SYN-ACK, client final ACK after CAD
            f"10.30\t10.0.1.2\t10.0.2.10\t\t\t0x0002\t52132\t80\t\t\t\t\t\t\t2\t\t\t2000\t0\t2\t0\t\t",
            f"10.32\t10.0.2.10\t10.0.1.2\t\t\t0x0012\t80\t52132\t\t\t\t\t\t\t2\t\t\t6000\t2001\t3\t0\t\t",
            f"10.325\t10.0.1.2\t10.0.2.10\t\t\t0x0010\t52132\t80\t\t\t\t\t\t\t2\t\t\t2001\t6001\t4\t0\t\t",
            # Stream 2: IPv4 GET / and 200 OK
            f"10.33\t10.0.1.2\t10.0.2.10\t\t\t0x0018\t52132\t80\t\t\t\t\t\t\t2\tGET\t/\t2001\t6001\t5\t50\t6\t",
            f"10.35\t10.0.2.10\t10.0.1.2\t\t\t0x0018\t80\t52132\t\t\t\t\t\t200\t2\t\t\t6001\t2100\t6\t200\t\t5",
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(tshark_lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname=target_host)

        self.assertEqual(dissection["http_status_code"], 200)
        self.assertEqual(dissection["http_response_family"], "IPv4")
        flow = dissection["main_http_flow"]
        self.assertTrue(flow["correlated"])
        self.assertEqual(flow["stream_id"], "2")
        self.assertEqual(flow["family"], "IPv4")
        self.assertEqual(flow["status_code"], 200)
        self.assertEqual(flow["request"], ("GET", "/"))
        self.assertTrue(flow["tcp_handshake_completed"])
        self.assertTrue(dissection["ipv4"]["connection_established"])
        self.assertTrue(dissection["ipv4"]["tcp_handshake_completed"])
        self.assertFalse(dissection["ipv6"]["connection_established"])
        self.assertFalse(dissection["ipv6"]["tcp_handshake_completed"])

        # Verify fallback classification with this dissection
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}
        cls_res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertTrue(cls_res["fallback_occurred"])
        self.assertEqual(cls_res["classification"], "IPV6_TO_IPV4_FALLBACK")
        flow = dissection["main_http_flow"]
        self.assertTrue(flow["correlated"])
        self.assertEqual(flow["stream_id"], "2")
        self.assertEqual(flow["family"], "IPv4")
        self.assertEqual(flow["status_code"], 200)
        self.assertEqual(flow["request"], ("GET", "/"))

        # Verify fallback classification with this dissection
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}
        cls_res = run_trial.classify_fallback(dissection, http_outcome)
        self.assertTrue(cls_res["fallback_occurred"])
        self.assertEqual(cls_res["classification"], "IPV6_TO_IPV4_FALLBACK")


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
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
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

    @patch("os.getuid", return_value=0)
    @patch("os.geteuid", return_value=0)
    def test_get_browser_uid_gid_preserves_sudo_invoking_identity(self, mock_euid, mock_uid):
        """When running under sudo (UID 0), get_browser_uid_gid extracts the invoking user's UID/GID."""
        mock_pw = pwd.struct_passwd((
            "sudo_user", "x", 1001, 1001, "Sudo User", "/home/sudo_user", "/bin/bash"
        ))
        with patch.dict(os.environ, {"SUDO_UID": "1001", "SUDO_GID": "1001", "SUDO_USER": "sudo_user"}, clear=False), \
             patch("pwd.getpwuid", return_value=mock_pw):
            uid, gid = run_trial.get_browser_uid_gid()
            self.assertEqual(uid, 1001)
            self.assertEqual(gid, 1001)

    def test_get_browser_env_sets_unprivileged_identity_and_xdg_paths(self):
        """
        get_browser_env must set HOME to user home, consistent USER/LOGNAME,
        and XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_DATA_HOME without /root leaks.
        """
        synth_user = "synth_browser_user"
        synth_uid = 24001
        synth_gid = 24001
        synth_home = "/tmp/ps028-test-home/synth_browser_user"
        mock_pw = pwd.struct_passwd((
            synth_user, "x", synth_uid, synth_gid, "Synth Browser User", synth_home, "/bin/bash"
        ))
        with patch("pwd.getpwuid", return_value=mock_pw):
            env = run_trial.get_browser_env(target_uid=synth_uid, target_gid=synth_gid)
            self.assertEqual(env["USER"], synth_user)
            self.assertEqual(env["LOGNAME"], synth_user)
            self.assertEqual(env["HOME"], synth_home)
            self.assertEqual(env["SHELL"], "/bin/bash")
            self.assertEqual(env["XDG_CONFIG_HOME"], f"{synth_home}/.config")
            self.assertEqual(env["XDG_CACHE_HOME"], f"{synth_home}/.cache")
            self.assertEqual(env["XDG_DATA_HOME"], f"{synth_home}/.local/share")

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
        synth_user = "synth_browser_user"
        synth_uid = 24001
        synth_gid = 24001
        synth_home = "/tmp/ps028-test-home/synth_browser_user"
        mock_pw = pwd.struct_passwd((
            synth_user, "x", synth_uid, synth_gid, "Synth Browser User", synth_home, "/bin/bash"
        ))
        with patch("pwd.getpwuid", return_value=mock_pw):
            env = run_trial.get_browser_env(target_uid=synth_uid, target_gid=synth_gid, base_env=tainted_base)
            self.assertEqual(env["HOME"], synth_home)
            self.assertEqual(env["USER"], synth_user)
            for k, v in env.items():
                self.assertNotIn("/root", v)

    def test_sanitize_browser_path_filters_wsl_and_preserves_linux_mounts(self):
        """sanitize_browser_path removes Windows WSL mounts but preserves valid Linux mounts."""
        raw = "/mnt/c/Windows/System32:/mnt/d/tools:/mnt/c:/mnt/storage/bin:/mnt/data/tools"
        sanitized = run_trial.sanitize_browser_path(raw)
        entries = sanitized.split(":")
        # WSL drive paths removed
        self.assertNotIn("/mnt/c/Windows/System32", entries)
        self.assertNotIn("/mnt/d/tools", entries)
        self.assertNotIn("/mnt/c", entries)
        # Legitimate Linux mounts preserved
        self.assertIn("/mnt/storage/bin", entries)
        self.assertIn("/mnt/data/tools", entries)
        # Order of valid entries preserved
        self.assertLess(entries.index("/mnt/storage/bin"), entries.index("/mnt/data/tools"))

    def test_sanitize_browser_path_preserves_order_and_deduplicates(self):
        """sanitize_browser_path maintains order and removes duplicate directories."""
        raw = "/opt/first:/usr/bin:/opt/second:/opt/first:/usr/bin"
        sanitized = run_trial.sanitize_browser_path(raw)
        entries = sanitized.split(":")
        self.assertEqual(entries[0], "/opt/first")
        self.assertEqual(entries[1], "/usr/bin")
        self.assertEqual(entries[2], "/opt/second")
        # Deduplication check
        self.assertEqual(entries.count("/opt/first"), 1)
        self.assertEqual(entries.count("/usr/bin"), 1)

    def test_sanitize_browser_path_rejects_relative_and_empty_entries(self):
        """sanitize_browser_path ignores relative paths and empty or whitespace-only entries."""
        raw = "::relative/dir: :   :/opt/valid/bin::./another/relative:"
        sanitized = run_trial.sanitize_browser_path(raw)
        entries = sanitized.split(":")
        self.assertIn("/opt/valid/bin", entries)
        self.assertNotIn("relative/dir", entries)
        self.assertNotIn("./another/relative", entries)
        self.assertNotIn("", entries)
        self.assertNotIn(" ", entries)

    def test_sanitize_browser_path_ensures_all_standard_system_directories(self):
        """sanitize_browser_path guarantees presence of standard Linux system directories."""
        sanitized = run_trial.sanitize_browser_path("")
        expected = [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ]
        self.assertEqual(sanitized.split(":"), expected)

        # None input also provides standard directories
        self.assertEqual(run_trial.sanitize_browser_path(None).split(":"), expected)

    def test_get_browser_env_sanitizes_path_and_enforces_identity_invariants(self):
        """get_browser_env applies path sanitization, resolves target identity, and strictly forbids root."""
        wsl_tainted_env = {
            "PATH": "/mnt/c/Windows:/opt/custom/bin:/mnt/storage/bin:/mnt/d/app::relative/bin",
            "HOME": "/root",
            "USER": "root",
            "LOGNAME": "root"
        }
        synth_user = "synth_browser_user"
        synth_uid = 24001
        synth_gid = 24001
        synth_home = "/tmp/ps028-test-home/synth_browser_user"
        mock_pw = pwd.struct_passwd((
            synth_user, "x", synth_uid, synth_gid, "Synth Browser User", synth_home, "/bin/bash"
        ))
        with patch("pwd.getpwuid", return_value=mock_pw):
            env = run_trial.get_browser_env(
                target_uid=synth_uid,
                target_gid=synth_gid,
                base_env=wsl_tainted_env
            )
            # PATH sanitization in get_browser_env
            path_entries = env["PATH"].split(":")
            self.assertNotIn("/mnt/c/Windows", path_entries)
            self.assertNotIn("/mnt/d/app", path_entries)
            self.assertNotIn("relative/bin", path_entries)
            self.assertIn("/opt/custom/bin", path_entries)
            self.assertIn("/mnt/storage/bin", path_entries)
            self.assertIn("/usr/bin", path_entries)
            self.assertIn("/bin", path_entries)

            # Security invariants: identity resolved, no root leaks
            self.assertEqual(env["USER"], synth_user)
            self.assertEqual(env["LOGNAME"], synth_user)
            self.assertEqual(env["HOME"], synth_home)
            for k, v in env.items():
                self.assertNotIn("/root", v, f"Environment variable {k}={v} must not contain /root")

        # Refusal of root target UID
        with self.assertRaises(run_trial.BrowserPreflightError):
            run_trial.get_browser_env(target_uid=0, target_gid=0)

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
    def test_run_browser_constructs_unprivileged_command_and_clean_env(self, mock_run):
        """
        run_browser constructs unprivileged setpriv/sudo command tokens, passes env -i with unprivileged variables,
        and contains no /root paths (verifies command construction and clean environment, not live execution).
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "<html><body>Clean DOM</body></html>"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "chrome_profile"
        profile.mkdir()

        synth_user = "synth_browser_user"
        synth_uid = 24001
        synth_gid = 24001
        synth_home = "/tmp/ps028-test-home/synth_browser_user"
        mock_pw = pwd.struct_passwd((
            synth_user, "x", synth_uid, synth_gid, "Synth Browser User", synth_home, "/bin/bash"
        ))

        with patch("os.getuid", return_value=synth_uid), \
             patch("os.geteuid", return_value=synth_uid), \
             patch("pwd.getpwuid", return_value=mock_pw):
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
            f"--reuid={synth_uid}" in cmd_str or f"sudo -u {synth_user}" in cmd_str,
            f"Command must drop privileges to unprivileged UID: {cmd_str}"
        )
        self.assertIn("env", cmd)
        self.assertIn("-i", cmd)
        self.assertIn(f"HOME={synth_home}", cmd_str)
        self.assertIn(f"USER={synth_user}", cmd_str)
        self.assertIn(f"XDG_CONFIG_HOME={synth_home}/.config", cmd_str)
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
            f"Crashpad database path '{self.temp_dir}/.config/google-chrome/Crash Reports' is not writable"
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
            "http_response_family": "IPv4",
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
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

    def test_firefox_discovery_with_synthetic_standalone_executable(self):
        """Verifies explicit standalone Firefox executable path is discovered and qualified via synthetic fixture."""
        fake_firefox = self.temp_dir / "opt" / "firefox-measurement" / "firefox"
        fake_firefox.parent.mkdir(parents=True, exist_ok=True)
        fake_firefox.write_text("#!/bin/sh\necho 'Mozilla Firefox 159.0'\n", encoding="utf-8")
        fake_firefox.chmod(0o755)

        with patch("lab.run_trial._query_browser_version", return_value="Mozilla Firefox 159.0"):
            bname, bpath, bver = run_trial.find_browser_runtime(
                preferred=str(fake_firefox)
            )
            self.assertEqual(bname, "firefox")
            self.assertEqual(bpath, str(fake_firefox.resolve()))
            self.assertEqual(bver, "Mozilla Firefox 159.0")

    def test_firefox_standalone_is_not_detected_as_snap(self):
        """Standalone Firefox binary must not be classified as a Snap-backed package."""
        self.assertFalse(run_trial.is_snap_browser("/opt/firefox-measurement/firefox"))

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
                browser_path="/opt/firefox-measurement/firefox",
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
                browser_path="/opt/firefox-measurement/firefox",
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
            "checks": {"browser": {"name": "firefox", "path": "/opt/firefox-measurement/firefox", "valid": True}}
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
                "executable": "/opt/firefox-measurement/firefox",
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
            browser_pref="/opt/firefox-measurement/firefox",
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



class TestUnifiedIdentityResolution(unittest.TestCase):
    """
    Dedicated regression test suite for lab.identity Linux user resolution.
    Strictly verifies:
    - Authoritative identity extraction from pwd database.
    - Sudo environment metadata cross-checking and contradiction rejection.
    - Protection against root browser identity and privilege leaks.
    - Deterministic execution using synthetic passwd records (never assumes UID 1000).
    """

    def _make_passwd_record(
        self,
        name: str = "synthuser",
        uid: int = 25001,
        gid: int = 25001,
        dir_path: str = "/home/synthuser",
        shell: str = "/bin/bash"
    ) -> pwd.struct_passwd:
        return pwd.struct_passwd((name, "x", uid, gid, "Synthetic User", dir_path, shell))

    def test_01_normal_user_identity_resolution(self):
        """1. Normal user execution resolves real UID from os.getuid() and matching passwd record."""
        mock_pw = self._make_passwd_record(uid=25001, name="synthuser", gid=25001, dir_path="/home/synthuser")
        with patch("os.getuid", return_value=25001), \
             patch("os.geteuid", return_value=25001), \
             patch("pwd.getpwuid", return_value=mock_pw):
            ident = identity.resolve_invoking_identity(env={})
            self.assertEqual(ident.uid, 25001)
            self.assertEqual(ident.gid, 25001)
            self.assertEqual(ident.username, "synthuser")
            self.assertEqual(ident.home_dir, Path("/home/synthuser"))
            self.assertEqual(ident.shell, "/bin/bash")

    def test_02_normal_user_with_non_1000_uid(self):
        """2. Normal user with arbitrary non-1000 UID resolves cleanly without defaulting to 1000."""
        mock_pw = self._make_passwd_record(uid=34567, name="altuser", gid=34567, dir_path="/home/altuser", shell="/bin/zsh")
        with patch("os.getuid", return_value=34567), \
             patch("os.geteuid", return_value=34567), \
             patch("pwd.getpwuid", return_value=mock_pw):
            ident = identity.resolve_invoking_identity(env={})
            self.assertEqual(ident.uid, 34567)
            self.assertEqual(ident.gid, 34567)
            self.assertEqual(ident.username, "altuser")
            self.assertEqual(ident.home_dir, Path("/home/altuser"))

    def test_03_valid_sudo_identity_resolution(self):
        """3. Root execution with valid SUDO_UID, SUDO_USER, and SUDO_GID resolves invoking identity."""
        mock_pw = self._make_passwd_record(uid=25001, name="synthuser", gid=25001, dir_path="/home/synthuser")
        fake_env = {
            "SUDO_UID": "25001",
            "SUDO_USER": "synthuser",
            "SUDO_GID": "25001"
        }
        with patch("os.getuid", return_value=0), \
             patch("os.geteuid", return_value=0), \
             patch("pwd.getpwuid", return_value=mock_pw):
            ident = identity.resolve_invoking_identity(env=fake_env)
            self.assertEqual(ident.uid, 25001)
            self.assertEqual(ident.gid, 25001)
            self.assertEqual(ident.username, "synthuser")
            self.assertEqual(ident.home_dir, Path("/home/synthuser"))

    def test_04_sudo_uid_and_sudo_user_mismatch_rejection(self):
        """4. Sudo metadata with contradictory SUDO_UID and SUDO_USER must be rejected."""
        mock_pw = self._make_passwd_record(uid=25001, name="synthuser")
        fake_env = {
            "SUDO_UID": "25001",
            "SUDO_USER": "imposter_user"
        }
        with patch("os.getuid", return_value=0), \
             patch("pwd.getpwuid", return_value=mock_pw):
            with self.assertRaises(identity.IdentityResolutionError) as ctx:
                identity.resolve_invoking_identity(env=fake_env)
            self.assertIn("Contradictory SUDO_USER", str(ctx.exception))

    def test_05_sudo_gid_mismatch_rejection(self):
        """5. Sudo metadata with contradictory SUDO_GID must be rejected."""
        mock_pw = self._make_passwd_record(uid=25001, gid=25001)
        fake_env = {
            "SUDO_UID": "25001",
            "SUDO_GID": "99999"
        }
        with patch("os.getuid", return_value=0), \
             patch("pwd.getpwuid", return_value=mock_pw):
            with self.assertRaises(identity.IdentityResolutionError) as ctx:
                identity.resolve_invoking_identity(env=fake_env)
            self.assertIn("Contradictory SUDO_GID", str(ctx.exception))

    def test_06_malformed_sudo_uid_rejection(self):
        """6. Malformed non-integer or float SUDO_UID values must fail closed."""
        with patch("os.getuid", return_value=0):
            with self.assertRaises(identity.IdentityResolutionError):
                identity.resolve_invoking_identity(env={"SUDO_UID": "not_an_int"})
            with self.assertRaises(identity.IdentityResolutionError):
                identity.resolve_invoking_identity(env={"SUDO_UID": "1000.5"})
            with self.assertRaises(identity.IdentityResolutionError):
                identity.resolve_invoking_identity(env={"SUDO_UID": ""})

    def test_07_malformed_sudo_gid_rejection(self):
        """7. Malformed non-integer SUDO_GID values must fail closed."""
        mock_pw = self._make_passwd_record(uid=25001)
        with patch("os.getuid", return_value=0), \
             patch("pwd.getpwuid", return_value=mock_pw):
            with self.assertRaises(identity.IdentityResolutionError):
                identity.resolve_invoking_identity(env={"SUDO_UID": "25001", "SUDO_GID": "bad_gid"})
            with self.assertRaises(identity.IdentityResolutionError):
                identity.resolve_invoking_identity(env={"SUDO_UID": "25001", "SUDO_GID": ""})

    def test_08_missing_passwd_record_rejection(self):
        """8. Missing passwd database records must raise IdentityResolutionError."""
        with patch("pwd.getpwuid", side_effect=KeyError("UID 25001 not found")):
            with self.assertRaises(identity.IdentityResolutionError) as ctx:
                identity.resolve_user_by_uid(25001)
            self.assertIn("not found in passwd database", str(ctx.exception))

        with patch("pwd.getpwnam", side_effect=KeyError("User not found")):
            with self.assertRaises(identity.IdentityResolutionError) as ctx:
                identity.resolve_user_by_name("nonexistent_user")
            self.assertIn("not found in passwd database", str(ctx.exception))

    def test_09_root_identity_rejection(self):
        """9. Root identity (UID 0) must be strictly rejected as unprivileged identity."""
        with self.assertRaises(identity.IdentityResolutionError) as ctx1:
            identity.resolve_user_by_uid(0)
        self.assertIn("greater than zero", str(ctx1.exception))

        mock_root_pw = pwd.struct_passwd(("root", "x", 0, 0, "root", "/root", "/bin/bash"))
        with patch("pwd.getpwnam", return_value=mock_root_pw):
            with self.assertRaises(identity.IdentityResolutionError) as ctx2:
                identity.resolve_user_by_name("root")
            self.assertIn("root", str(ctx2.exception).lower())

        with patch("os.getuid", return_value=0):
            with self.assertRaises(identity.IdentityResolutionError) as ctx3:
                identity.resolve_invoking_identity(env={"SUDO_UID": "0"})
            self.assertIn("root", str(ctx3.exception).lower())

    def test_10_root_execution_without_sudo_uid_rejection(self):
        """10. Root execution without SUDO_UID (or relying on SUDO_USER alone) must be rejected."""
        with patch("os.getuid", return_value=0):
            # No sudo metadata at all
            with self.assertRaises(identity.IdentityResolutionError) as ctx1:
                identity.resolve_invoking_identity(env={})
            self.assertIn("Root execution requires a valid SUDO_UID", str(ctx1.exception))

            # SUDO_USER present, but SUDO_UID missing: must NOT trust SUDO_USER alone
            with self.assertRaises(identity.IdentityResolutionError) as ctx2:
                identity.resolve_invoking_identity(env={"SUDO_USER": "synthuser"})
            self.assertIn("Root execution requires a valid SUDO_UID", str(ctx2.exception))

    def test_11_invalid_or_relative_home_directory_rejection(self):
        """11. Relative or empty home directory paths in passwd database must be rejected."""
        mock_pw_rel = self._make_passwd_record(dir_path="relative/path/home")
        with patch("pwd.getpwuid", return_value=mock_pw_rel):
            with self.assertRaises(identity.IdentityResolutionError) as ctx1:
                identity.resolve_user_by_uid(25001)
            self.assertIn("absolute path", str(ctx1.exception))

        mock_pw_empty = self._make_passwd_record(dir_path="")
        with patch("pwd.getpwuid", return_value=mock_pw_empty):
            with self.assertRaises(identity.IdentityResolutionError) as ctx2:
                identity.resolve_user_by_uid(25001)
            self.assertIn("absolute path", str(ctx2.exception))

    def test_12_frozen_user_identity_immutability(self):
        """12. UserIdentity must be frozen and strictly immutable against in-place modification."""
        ident = identity.UserIdentity(
            uid=25001,
            gid=25001,
            username="synthuser",
            home_dir=Path("/home/synthuser"),
            shell="/bin/bash"
        )
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            ident.uid = 1000
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            ident.username = "modified"
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            ident.home_dir = Path("/tmp")

    def test_13_correct_resolution_of_actual_passwd_home_directory(self):
        """13. Home directory must resolve from passwd record and never be synthesized as /home/username."""
        custom_home = "/srv/isolated/measurements/synthuser"
        mock_pw = self._make_passwd_record(uid=25001, dir_path=custom_home)
        with patch("pwd.getpwuid", return_value=mock_pw):
            ident = identity.resolve_user_by_uid(25001)
            self.assertEqual(ident.home_dir, Path(custom_home))
            self.assertNotEqual(ident.home_dir, Path("/home/synthuser"))

    def test_14_real_uid_remains_authoritative_when_effective_uid_is_root(self):
        """14. Where os.getuid() is nonzero but os.geteuid() is zero, real UID remains invoking identity."""
        mock_pw = self._make_passwd_record(uid=25001, name="synthuser")
        with patch("os.getuid", return_value=25001), \
             patch("os.geteuid", return_value=0), \
             patch("pwd.getpwuid", return_value=mock_pw):
            # Without sudo env: real UID 25001 is used
            ident = identity.resolve_invoking_identity(env={})
            self.assertEqual(ident.uid, 25001)
            self.assertEqual(ident.username, "synthuser")

            # With matching sudo metadata: succeeds
            ident_sudo = identity.resolve_invoking_identity(env={"SUDO_UID": "25001", "SUDO_USER": "synthuser"})
            self.assertEqual(ident_sudo.uid, 25001)

            # With contradictory sudo metadata: rejects
            with self.assertRaises(identity.IdentityResolutionError) as ctx:
                identity.resolve_invoking_identity(env={"SUDO_UID": "99999"})
            self.assertIn("Contradictory SUDO_UID", str(ctx.exception))

    def test_15_passwd_oserror_chained_as_identity_resolution_error(self):
        """15. OSError raised during passwd lookup must be chained as IdentityResolutionError."""
        os_err = OSError("Simulated passwd database I/O read failure")
        with patch("pwd.getpwuid", side_effect=os_err):
            with self.assertRaises(identity.IdentityResolutionError) as ctx1:
                identity.resolve_user_by_uid(25001)
            self.assertIn("Operating system error", str(ctx1.exception))
            self.assertIs(ctx1.exception.__cause__, os_err)

        with patch("pwd.getpwnam", side_effect=os_err):
            with self.assertRaises(identity.IdentityResolutionError) as ctx2:
                identity.resolve_user_by_name("synthuser")
            self.assertIn("Operating system error", str(ctx2.exception))
            self.assertIs(ctx2.exception.__cause__, os_err)

    def test_16_empty_passwd_shell_defaults_to_posix_sh(self):
        """16. Empty passwd shell field defaults to the conventional Linux system-shell path."""
        # UID-based resolution with empty string shell
        mock_pw_empty = self._make_passwd_record(uid=25001, shell="")
        with patch("pwd.getpwuid", return_value=mock_pw_empty):
            ident = identity.resolve_user_by_uid(25001)
            self.assertEqual(ident.shell, "/bin/sh")

        # UID-based resolution with whitespace-only shell
        mock_pw_space = self._make_passwd_record(uid=25001, shell="   ")
        with patch("pwd.getpwuid", return_value=mock_pw_space):
            ident = identity.resolve_user_by_uid(25001)
            self.assertEqual(ident.shell, "/bin/sh")

        # Name-based resolution with empty string shell
        mock_pw_name_empty = self._make_passwd_record(name="synthuser", shell="")
        with patch("pwd.getpwnam", return_value=mock_pw_name_empty):
            ident_name_empty = identity.resolve_user_by_name("synthuser")
            self.assertEqual(ident_name_empty.shell, "/bin/sh")

        # Name-based resolution with whitespace-only shell
        mock_pw_name_space = self._make_passwd_record(name="synthuser", shell="   ")
        with patch("pwd.getpwnam", return_value=mock_pw_name_space):
            ident_name_space = identity.resolve_user_by_name("synthuser")
            self.assertEqual(ident_name_space.shell, "/bin/sh")


class TestTCPHandshakeVerificationRegression(unittest.TestCase):
    """
    Deterministic regression unit tests for TCP Three-Way Handshake Verification:
    E1. Client SYN without server SYN-ACK: handshake incomplete.
    E2. Valid SYN-ACK without client final ACK: handshake incomplete.
    E3. Client ACK with incorrect acknowledgement number: handshake incomplete.
    E4. ACK from the wrong direction: handshake incomplete.
    E5. ACK from another TCP stream: handshake incomplete.
    E6. Correct SYN -> matching SYN-ACK -> matching client ACK: handshake completed (with 32-bit wraparound).
    E7. IPv4 and IPv6 independent handshake tracking.
    E8. Two independent TCP streams: completion of ancillary stream not assigned to primary HTTP stream.
    E9. Retransmitted SYN or SYN-ACK does not create false completion.
    E10. Fallback classification does not treat a SYN-ACK alone as successful connection evidence.

    Synthetic fixtures are deterministic unit tests and do not constitute live network evidence.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_tcp_handshake_"))
        self.pcap_file = self.temp_dir / "test.pcap"
        self.pcap_file.touch()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_tshark_line(
        self,
        t_epoch: float = 10.0,
        ip_src: str = "",
        ip_dst: str = "",
        ip6_src: str = "",
        ip6_dst: str = "",
        flags: str = "0x0002",
        sport: int = 50000,
        dport: int = 80,
        dns_qname: str = "",
        dns_qtype: str = "",
        dns_resp: str = "",
        dns_a: str = "",
        dns_aaaa: str = "",
        http_code: str = "",
        stream: str = "0",
        http_method: str = "",
        http_uri: str = "",
        seq_raw: int = 1000,
        ack_raw: int = 0,
        frame_num: int = 1,
        tcp_len: int = 0,
        http_response_in: str = "",
        http_request_in: str = "",
    ) -> str:
        return (
            f"{t_epoch}\t{ip_src}\t{ip_dst}\t{ip6_src}\t{ip6_dst}\t{flags}\t"
            f"{sport}\t{dport}\t{dns_qname}\t{dns_qtype}\t{dns_resp}\t{dns_a}\t{dns_aaaa}\t"
            f"{http_code}\t{stream}\t{http_method}\t{http_uri}\t{seq_raw}\t{ack_raw}\t{frame_num}\t{tcp_len}\t"
            f"{http_response_in}\t{http_request_in}"
        )

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e1_client_syn_without_server_synack_incomplete(self, mock_run, mock_which):
        """E1. Client SYN without server SYN-ACK: handshake incomplete."""
        lines = [
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            )
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertEqual(v6["syn_count"], 1)
        self.assertEqual(v6["first_syn_time"], 10.00)
        self.assertFalse(v6["syn_ack_received"])
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])

        stream0 = dissection["tcp_streams"]["0"]
        self.assertEqual(stream0["handshake_state"], "SYN_SENT")
        self.assertFalse(stream0["tcp_handshake_completed"])
        self.assertFalse(stream0["syn_ack_received"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e2_valid_synack_without_client_final_ack_incomplete(self, mock_run, mock_which):
        """E2. Valid SYN-ACK without client final ACK: handshake incomplete."""
        lines = [
            # Client SYN
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            # Server SYN-ACK
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertEqual(v6["syn_count"], 1)
        self.assertTrue(v6["syn_ack_received"])
        self.assertEqual(v6["syn_ack_time"], 10.02)
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])

        stream0 = dissection["tcp_streams"]["0"]
        self.assertTrue(stream0["syn_ack_received"])
        self.assertFalse(stream0["tcp_handshake_completed"])
        self.assertEqual(stream0["handshake_state"], "SYNACK_RCVD")
        self.assertIsNone(stream0["final_ack_frame"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e3_client_ack_with_incorrect_ack_number_incomplete(self, mock_run, mock_which):
        """E3. Client ACK with incorrect acknowledgement number: handshake incomplete."""
        lines = [
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            # Client ACK with invalid ack_raw (9999 instead of 5001)
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1001,
                ack_raw=9999,
                frame_num=3,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["syn_ack_received"])
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])

        stream0 = dissection["tcp_streams"]["0"]
        self.assertFalse(stream0["tcp_handshake_completed"])
        self.assertEqual(stream0["handshake_state"], "SYNACK_RCVD")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e4_ack_from_wrong_direction_incomplete(self, mock_run, mock_which):
        """E4. ACK from the wrong direction: handshake incomplete."""
        lines = [
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            # Server sends ACK to client (wrong direction)
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0010",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5001,
                ack_raw=1001,
                frame_num=3,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])
        self.assertFalse(dissection["tcp_streams"]["0"]["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e5_ack_from_another_tcp_stream_incomplete(self, mock_run, mock_which):
        """E5. ACK from another TCP stream: handshake incomplete."""
        lines = [
            # Stream 0: SYN and SYN-ACK
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            # Stream 1: Client ACK attempting to acknowledge Stream 0
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50002,
                dport=80,
                stream="1",
                seq_raw=2000,
                ack_raw=5001,
                frame_num=3,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        self.assertFalse(dissection["ipv6"]["tcp_handshake_completed"])
        self.assertFalse(dissection["ipv6"]["connection_established"])
        self.assertFalse(dissection["tcp_streams"]["0"]["tcp_handshake_completed"])
        self.assertFalse(dissection["tcp_streams"]["1"]["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e6_correct_three_way_handshake_and_32bit_wraparound(self, mock_run, mock_which):
        """E6. Correct SYN -> matching SYN-ACK -> matching client ACK completes handshake, including 32-bit wraparound."""
        # 6a: Standard sequence numbers
        lines_std = [
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=100000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=200000,
                ack_raw=100001,
                frame_num=2,
            ),
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=100001,
                ack_raw=200001,
                frame_num=3,
            ),
        ]
        mock_proc_std = MagicMock()
        mock_proc_std.stdout = "\n".join(lines_std) + "\n"
        mock_run.return_value = mock_proc_std

        dissection_std = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6_std = dissection_std["ipv6"]
        self.assertTrue(v6_std["syn_ack_received"])
        self.assertTrue(v6_std["tcp_handshake_completed"])
        self.assertTrue(v6_std["connection_established"])
        s0_std = dissection_std["tcp_streams"]["0"]
        self.assertTrue(s0_std["tcp_handshake_completed"])
        self.assertEqual(s0_std["handshake_state"], "ESTABLISHED")
        self.assertEqual(s0_std["final_ack_frame"], 3)

        # 6b: 32-bit sequence wraparound (ISN = 0xFFFFFFFF, +1 wraps to 0)
        lines_wrap = [
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=4294967295,  # 0xFFFFFFFF
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=4294967295,  # 0xFFFFFFFF
                ack_raw=0,  # Wrapped (4294967295 + 1) & 0xFFFFFFFF == 0
                frame_num=2,
            ),
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=0,
                ack_raw=0,  # Wrapped (4294967295 + 1) & 0xFFFFFFFF == 0
                frame_num=3,
            ),
        ]
        mock_proc_wrap = MagicMock()
        mock_proc_wrap.stdout = "\n".join(lines_wrap) + "\n"
        mock_run.return_value = mock_proc_wrap

        dissection_wrap = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6_wrap = dissection_wrap["ipv6"]
        self.assertTrue(v6_wrap["tcp_handshake_completed"])
        self.assertTrue(v6_wrap["connection_established"])
        self.assertTrue(dissection_wrap["tcp_streams"]["0"]["tcp_handshake_completed"])
        self.assertEqual(dissection_wrap["tcp_streams"]["0"]["handshake_state"], "ESTABLISHED")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e7_ipv4_and_ipv6_independent_handshake_tracking(self, mock_run, mock_which):
        """E7. IPv4 and IPv6 handshake states are tracked independently."""
        lines = [
            # Stream 0 (IPv6): Full completed 3-way handshake
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1001,
                ack_raw=5001,
                frame_num=3,
            ),
            # Stream 1 (IPv4): SYN and SYN-ACK only (handshake NOT completed)
            self._make_tshark_line(
                t_epoch=10.30,
                ip_src="10.0.1.2",
                ip_dst=run_trial.SERVER_IPV4,
                flags="0x0002",
                sport=50001,
                dport=80,
                stream="1",
                seq_raw=3000,
                ack_raw=0,
                frame_num=4,
            ),
            self._make_tshark_line(
                t_epoch=10.32,
                ip_src=run_trial.SERVER_IPV4,
                ip_dst="10.0.1.2",
                flags="0x0012",
                sport=80,
                dport=50001,
                stream="1",
                seq_raw=7000,
                ack_raw=3001,
                frame_num=5,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")

        # IPv6: Completed
        v6 = dissection["ipv6"]
        self.assertEqual(v6["syn_count"], 1)
        self.assertTrue(v6["syn_ack_received"])
        self.assertTrue(v6["tcp_handshake_completed"])
        self.assertTrue(v6["connection_established"])

        # IPv4: Incomplete
        v4 = dissection["ipv4"]
        self.assertEqual(v4["syn_count"], 1)
        self.assertTrue(v4["syn_ack_received"])
        self.assertFalse(v4["tcp_handshake_completed"])
        self.assertFalse(v4["connection_established"])

        self.assertTrue(dissection["tcp_streams"]["0"]["tcp_handshake_completed"])
        self.assertFalse(dissection["tcp_streams"]["1"]["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e8_ancillary_stream_completion_not_assigned_to_primary_http_stream(self, mock_run, mock_which):
        """E8. Two independent TCP streams: completion of an ancillary stream is not assigned to primary HTTP stream."""
        lines = [
            # Stream 0: Primary navigation GET /, but client never acknowledged server SYN-ACK
            # (e.g. ack_raw is 0 / unacknowledged or final ACK never transmitted)
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            self._make_tshark_line(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0018",
                sport=50000,
                dport=80,
                stream="0",
                http_method="GET",
                http_uri="/",
                seq_raw=1001,
                ack_raw=9999,  # Incorrect ack_raw: server ISN 5000 never acknowledged
                frame_num=3,
            ),
            # Stream 1: Ancillary GET /favicon.ico, completes full 3-way handshake and returns 404
            self._make_tshark_line(
                t_epoch=10.10,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50002,
                dport=80,
                stream="1",
                seq_raw=2000,
                ack_raw=0,
                frame_num=4,
            ),
            self._make_tshark_line(
                t_epoch=10.12,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50002,
                stream="1",
                seq_raw=6000,
                ack_raw=2001,
                frame_num=5,
            ),
            self._make_tshark_line(
                t_epoch=10.13,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50002,
                dport=80,
                stream="1",
                seq_raw=2001,
                ack_raw=6001,
                frame_num=6,
            ),
            self._make_tshark_line(
                t_epoch=10.14,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0018",
                sport=50002,
                dport=80,
                stream="1",
                http_method="GET",
                http_uri="/favicon.ico",
                seq_raw=2001,
                ack_raw=6001,
                frame_num=7,
            ),
            self._make_tshark_line(
                t_epoch=10.15,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0018",
                sport=80,
                dport=50002,
                stream="1",
                http_code="404",
                seq_raw=6001,
                ack_raw=2150,
                frame_num=8,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        main_flow = dissection["main_http_flow"]
        self.assertTrue(main_flow["correlated"])
        self.assertEqual(main_flow["stream_id"], "0")
        self.assertEqual(main_flow["request"], ("GET", "/"))
        self.assertFalse(main_flow["tcp_handshake_completed"])

        s1 = dissection["tcp_streams"]["1"]
        self.assertTrue(s1["tcp_handshake_completed"])
        self.assertFalse(s1["main_get"])
        self.assertEqual(s1["first_request"], ("GET", "/favicon.ico"))
        self.assertEqual(s1["response_code"], 404)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_e9_retransmitted_syn_or_synack_no_false_completion(self, mock_run, mock_which):
        """E9. Retransmitted SYN or SYN-ACK does not create false completion."""
        lines = [
            # Initial SYN
            self._make_tshark_line(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            # Retransmitted SYN
            self._make_tshark_line(
                t_epoch=11.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=2,
            ),
            # Server SYN-ACK
            self._make_tshark_line(
                t_epoch=11.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=3,
            ),
            # Server retransmitted SYN-ACK
            self._make_tshark_line(
                t_epoch=12.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=4,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertEqual(v6["syn_count"], 2)
        self.assertTrue(v6["syn_ack_received"])
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])

        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "SYNACK_RCVD")

    def test_e10_fallback_classification_synack_alone_not_connection_evidence(self):
        """E10. Fallback classification does not treat SYN-ACK alone as successful connection evidence."""
        # Baseline mock dissection where IPv4 received SYN-ACK but never completed handshake
        dissection_incomplete = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": False,
                "syn_ack_time": None,
                "rst_received": False,
                "tcp_handshake_completed": False,
                "connection_established": False,
                "http_observed": False,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "rst_received": False,
                "tcp_handshake_completed": False,
                "connection_established": False,
                "http_observed": False,
            },
            "connection_attempt_delay_ms": 250.0,
            "connection_setup_time_ms": 20.0,
            "http_status_code": None,
            "http_response_family": None,
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

        # Subcase 10a: HTTP failed, SYN-ACK received without final client ACK -> CONNECTION_FAILED, NOT fallback
        outcome_failed = {"status_code": None, "success": False, "winning_address_family": None}
        cls_a = run_trial.classify_fallback(dissection_incomplete, outcome_failed)
        self.assertFalse(cls_a["fallback_occurred"])
        self.assertEqual(cls_a["classification"], "CONNECTION_FAILED")
        self.assertFalse(cls_a["ipv4_success"])
        self.assertFalse(cls_a["ipv6_success"])

        # Subcase 10b: HTTP reported apparent success, but no completed handshake -> INCONCLUSIVE, NOT fallback
        outcome_synth_success = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}
        cls_b = run_trial.classify_fallback(dissection_incomplete, outcome_synth_success)
        self.assertFalse(cls_b["fallback_occurred"])
        self.assertEqual(cls_b["classification"], "INCONCLUSIVE")

        # Subcase 10c: IPv4 ancillary HTTP response (404 favicon) does not make failed navigation into fallback
        dissection_ancillary = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": False,
                "syn_ack_time": None,
                "rst_received": False,
                "tcp_handshake_completed": False,
                "connection_established": False,
                "http_observed": False,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "connection_attempt_delay_ms": 250.0,
            "connection_setup_time_ms": 20.0,
            "http_status_code": 404,
            "http_response_family": "IPv4",
            "main_http_flow": {
                "stream_id": "1",
                "family": "IPv4",
                "status_code": 404,
                "request": ("GET", "/favicon.ico"),
                "correlated": True,
                "tcp_handshake_completed": True,
            },
            "tcp_streams": {},
        }
        outcome_nav_failed = {"status_code": None, "success": False, "winning_address_family": None}
        cls_c = run_trial.classify_fallback(dissection_ancillary, outcome_nav_failed)
        self.assertFalse(cls_c["fallback_occurred"])
        self.assertEqual(cls_c["classification"], "CONNECTION_FAILED")

    # --------------------------------------------------------------------------
    # Deterministic Requirements 1-17 Tests (Phase 2B Evidence Integrity)
    # --------------------------------------------------------------------------

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_1_correct_final_ack_seq_and_ack(self, mock_run, mock_which):
        """1. Correct final ACK SEQ and ACK values completes handshake."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=100000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=200000, ack_raw=100001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=100001, ack_raw=200001, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["syn_ack_received"])
        self.assertTrue(v6["tcp_handshake_completed"])
        self.assertTrue(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertEqual(s0["final_ack_frame"], 3)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_2_incorrect_final_ack_seq_with_correct_ack_fails(self, mock_run, mock_which):
        """2. Incorrect final ACK SEQ with correct ACK fails to complete handshake."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=100000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=200000, ack_raw=100001, frame_num=2, tcp_len=0),
            # Client final ACK has incorrect seq_raw (100999 instead of 100001)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=100999, ack_raw=200001, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["syn_ack_received"])
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertNotEqual(s0["handshake_state"], "ESTABLISHED")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_3_incorrect_final_ack_ack_with_correct_seq_fails(self, mock_run, mock_which):
        """3. Incorrect final ACK ACK with correct SEQ fails to complete handshake."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=100000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=200000, ack_raw=100001, frame_num=2, tcp_len=0),
            # Client final ACK has incorrect ack_raw (209999 instead of 200001)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=100001, ack_raw=209999, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertNotEqual(s0["handshake_state"], "ESTABLISHED")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_4_valid_sequence_number_wraparound(self, mock_run, mock_which):
        """4. Valid sequence-number wraparound correctly verifies handshake across 2^32 boundary."""
        # Client ISN = 0xFFFFFFFF (4294967295) -> wraps to 0
        # Server ISN = 0xFFFFFFFE (4294967294) -> wraps to 0xFFFFFFFF
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=4294967295, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=4294967294, ack_raw=0, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=0, ack_raw=4294967295, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["tcp_handshake_completed"])
        self.assertTrue(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_5_consistent_syn_ack_retransmission(self, mock_run, mock_which):
        """5. Consistent SYN-ACK retransmission preserves stream state and completes upon final ACK."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            # Retransmitted SYN-ACK with identical server ISN
            self._make_tshark_line(t_epoch=11.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=3, tcp_len=0),
            # Final client ACK
            self._make_tshark_line(t_epoch=11.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["tcp_handshake_completed"])
        self.assertTrue(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_6_conflicting_syn_ack_server_isn_rejected(self, mock_run, mock_which):
        """6. Conflicting SYN-ACK server ISN is rejected and does not overwrite recorded server ISN."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            # Conflicting SYN-ACK with differing server ISN (7000 != 5000)
            self._make_tshark_line(t_epoch=11.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=7000, ack_raw=1001, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertEqual(s0["server_isn"], 5000, "Server ISN must never be overwritten with conflicting value")
        self.assertEqual(s0["handshake_state"], "INVALID")
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertFalse(dissection["ipv6"]["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_7_client_to_server_rst_observation_and_state(self, mock_run, mock_which):
        """7. Client-to-server RST documents client abort without misrepresenting as server RST."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            # Client sends RST to server (client cancellation / abort)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0004", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=0, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["client_rst_sent"])
        self.assertFalse(v6["server_rst_received"])
        self.assertFalse(v6["rst_received"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["client_rst_sent"])
        self.assertFalse(s0["server_rst_received"])
        self.assertEqual(s0["handshake_state"], "CLIENT_ABORT")
        self.assertFalse(s0["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_8_server_to_client_rst_observation_and_validation(self, mock_run, mock_which):
        """8. Server-to-client RST observation and validation per RFC 9293."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Server sends valid RST acknowledging client SYN (flags 0x0014, ack = 1001)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1001, frame_num=2, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["server_rst_received"])
        self.assertTrue(v6["rst_received"])
        self.assertFalse(v6["client_rst_sent"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["server_rst_received"])
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "RESET")
        self.assertFalse(s0["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_9_rst_after_completed_handshake_preserves_historical_completion(self, mock_run, mock_which):
        """9. RST after a successfully completed handshake preserves historical completion."""
        lines = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Handshake completed. Later, server sends RST
            self._make_tshark_line(t_epoch=10.10, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertTrue(v6["server_rst_received"])
        self.assertTrue(v6["rst_received"])
        self.assertTrue(v6["tcp_handshake_completed"], "Historical handshake completion must be preserved")
        self.assertTrue(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_RESET")

    def test_10_ancillary_favicon_404_does_not_establish_primary_navigation(self):
        """10. Ancillary favicon 404 does not establish primary navigation success."""
        dissection = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": False,
                "syn_ack_time": None,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": False,
                "connection_established": False,
                "http_observed": False,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "1",
                "family": "IPv4",
                "status_code": 404,
                "request": ("GET", "/favicon.ico"),
                "correlated": False,
                "tcp_handshake_completed": True,
            },
            "tcp_streams": {},
        }
        outcome = {"status_code": None, "success": False, "winning_address_family": None}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "CONNECTION_FAILED")
        self.assertFalse(cls["ipv4_success"])
        self.assertFalse(cls["ipv6_success"])

    def test_11_ancillary_flow_completed_handshake_does_not_establish_primary_navigation(self):
        """11. An ancillary flow with a completed handshake does not establish primary navigation success."""
        dissection = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": False,
                "syn_ack_time": None,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": False,
                "connection_established": False,
                "http_observed": False,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": None,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": False,
            },
            "tcp_streams": {},
        }
        outcome = {"status_code": None, "success": False, "winning_address_family": None}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "CONNECTION_FAILED")
        self.assertFalse(cls["ipv4_success"])

    def test_12_correlated_ipv6_primary_navigation_not_displaced_by_ancillary_ipv4(self):
        """12. Correlated IPv6 primary navigation is not displaced by an ancillary IPv4 response."""
        dissection = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": True,
                "syn_ack_time": 10.02,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            },
            "tcp_streams": {},
        }
        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "DIRECT_IPV6")
        self.assertTrue(cls["ipv6_success"])
        self.assertFalse(cls["ipv4_success"])

    def test_13_browser_ipv4_vs_correlated_pcap_ipv6_produces_inconclusive(self):
        """13. Browser IPv4 versus correlated PCAP IPv6 produces INCONCLUSIVE."""
        dissection = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": True,
                "syn_ack_time": 10.02,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            },
            "tcp_streams": {},
        }
        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "INCONCLUSIVE")
        self.assertIn("Contradictory evidence", cls["reason"])
        self.assertIn("IPv4", cls["reason"])
        self.assertIn("IPv6", cls["reason"])

    def test_14_browser_ipv6_vs_correlated_pcap_ipv4_produces_inconclusive(self):
        """14. Browser IPv6 versus correlated PCAP IPv4 produces INCONCLUSIVE."""
        dissection = {
            "ipv6": {
                "syn_count": 1,
                "first_syn_time": 10.00,
                "syn_ack_received": False,
                "syn_ack_time": None,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": False,
                "connection_established": False,
                "http_observed": False,
            },
            "ipv4": {
                "syn_count": 1,
                "first_syn_time": 10.25,
                "syn_ack_received": True,
                "syn_ack_time": 10.27,
                "server_rst_received": False,
                "client_rst_sent": False,
                "rst_received": False,
                "tcp_handshake_completed": True,
                "connection_established": True,
                "http_observed": True,
            },
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "1",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            },
            "tcp_streams": {},
        }
        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "INCONCLUSIVE")
        self.assertIn("Contradictory evidence", cls["reason"])
        self.assertIn("IPv6", cls["reason"])
        self.assertIn("IPv4", cls["reason"])

    def test_15_uncorrelated_raw_pcap_http_signatures_do_not_establish_authoritative_http_success(self):
        """15. Uncorrelated raw PCAP HTTP status signatures do not establish authoritative HTTP success."""
        pcap_file = self.temp_dir / "raw_sig.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        http_data = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 12\r\n\r\nHello World!"
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, len(http_data), len(http_data))
        pcap_file.write_bytes(header + pkt_hdr + http_data)

        dissection = run_trial.dissect_pcap(pcap_file, target_hostname="trial.he.test")
        self.assertEqual(dissection["diagnostic_raw_pcap_http_code"], 200)
        self.assertIsNone(dissection["http_status_code"])
        self.assertIsNone(dissection["main_http_flow"]["status_code"])
        self.assertFalse(dissection["main_http_flow"]["correlated"])

        outcome = {"status_code": None, "success": False, "winning_address_family": None}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "CONNECTION_FAILED")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_16_incomplete_midstream_captures_not_falsely_verified(self, mock_run, mock_which):
        """16. Incomplete/midstream captures are not falsely reported as verified or malformed handshakes."""
        lines = [
            # Stream starts midstream with ACK and data without prior SYN or SYN-ACK
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=5000, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1000, frame_num=2, tcp_len=100),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        self.assertFalse(v6["tcp_handshake_completed"])
        self.assertFalse(v6["connection_established"])
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "MIDSTREAM")
        self.assertIn("MIDSTREAM_TRAFFIC_OBSERVED", s0["anomalies"])

    def test_17_existing_valid_recorded_pcap_regression_verified(self):
        """17. Existing valid recorded-PCAP regression continues to work against authentic October 29 trial."""
        authentic_pcap = REPO_ROOT / "lab/campaigns/ps028-a10-live-20261030-01/trials/trial-20261029215022-d5cc11cb/capture.pcap"
        self.assertTrue(authentic_pcap.is_file(), f"Authentic PCAP must exist at {authentic_pcap}")

        pcap_valid, sha256_hash, pcap_size, pkt_count, pcap_msg = run_trial.validate_pcap_file(authentic_pcap)
        self.assertTrue(pcap_valid)
        self.assertEqual(sha256_hash, "75eeda0399bfccc5c8d0c51840d12366a4b48d80e09298f0e62b5dcb40d889c3")
        self.assertEqual(pkt_count, 168)

        dissection = run_trial.dissect_pcap(authentic_pcap, "trial-20261029215022-d5cc11cb.he.test")
        v6 = dissection["ipv6"]
        v4 = dissection["ipv4"]
        self.assertTrue(v6["tcp_handshake_completed"])
        self.assertTrue(v6["connection_established"])
        self.assertEqual(v4["syn_count"], 0)
        self.assertFalse(v4["tcp_handshake_completed"])
        self.assertEqual(dissection["http_status_code"], 200)
        self.assertEqual(dissection["http_response_family"], "IPv6")
        self.assertTrue(dissection["main_http_flow"]["correlated"])
        self.assertEqual(dissection["main_http_flow"]["family"], "IPv6")
        self.assertTrue(dissection["main_http_flow"]["tcp_handshake_completed"])

        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}
        cls = run_trial.classify_fallback(dissection, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "DIRECT_IPV6")
        self.assertTrue(cls["ipv6_success"])
        self.assertFalse(cls["ipv4_success"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_18_unvalidated_server_rst_does_not_terminate_stream(self, mock_run, mock_which):
        """18. Unvalidated server RST does not terminate a stream."""
        lines = [
            # Stream 0: Completed handshake
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=2001, frame_num=3, tcp_len=0),
            # Server sends unvalidated RST with invalid seq (e.g. 999999 instead of expected 2001)
            self._make_tshark_line(t_epoch=10.05, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=999999, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        s0 = dissection["tcp_streams"]["0"]

        self.assertTrue(s0["server_rst_received"])
        self.assertFalse(s0["server_rst_validated"])
        # Crucial: Unvalidated server RST must NOT terminate the stream into RESET or CLOSED_BY_RESET
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertTrue(v6["tcp_handshake_completed"])
        self.assertTrue(v6["connection_established"])
        self.assertTrue(any("UNVALIDATED_SERVER_RST" in a for a in s0["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_19_client_rst_observation_not_treated_as_server_reset(self, mock_run, mock_which):
        """19. Client RST observation is not treated as proof of successful server reset."""
        lines = [
            # Handshake completed
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=2001, frame_num=3, tcp_len=0),
            # Client emits RST to server
            self._make_tshark_line(t_epoch=10.05, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0004", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        v6 = dissection["ipv6"]
        s0 = dissection["tcp_streams"]["0"]

        self.assertTrue(s0["client_rst_sent"])
        self.assertFalse(s0["server_rst_received"])
        self.assertFalse(s0["rst_received"])
        self.assertFalse(v6["server_rst_received"])
        self.assertFalse(v6["rst_received"])
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertTrue(v6["tcp_handshake_completed"])
        # Stream documents client abort without asserting server accepted reset
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_CLIENT_ABORT")

    def test_20_missing_correlated_pcap_response_status_cannot_be_filled_by_browser_status(self):
        """20. Missing correlated PCAP response status cannot be filled by browser HTTP status."""
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": False, "first_syn_time": 10.25},
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": None,  # Missing response status in PCAP!
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        # Browser claims success with HTTP 200
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        cls = run_trial.classify_fallback(dissection, http_outcome)
        # Cannot substitute browser HTTP status for missing packet-correlated response
        self.assertFalse(cls["ipv4_success"])
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "INCONCLUSIVE")

    def test_21_uncorrelated_response_family_cannot_trigger_contradiction(self):
        """21. Uncorrelated response family cannot trigger contradiction."""
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "diagnostic_fallback_http_code": 200,
            "diagnostic_fallback_http_family": "IPv4",
            "main_http_flow": {
                "stream_id": None,
                "family": None,
                "status_code": None,
                "request": None,
                "correlated": False,  # Not correlated to primary navigation!
                "tcp_handshake_completed": False,
            }
        }
        # Browser says IPv6 won navigation
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        cls = run_trial.classify_fallback(dissection, http_outcome)
        # Must not produce a contradiction when PCAP flow is uncorrelated
        self.assertNotIn("Contradictory evidence", cls["reason"])
        # Per F-34: Uncorrelated packet evidence cannot prove navigation; packet classification is INCONCLUSIVE
        self.assertEqual(cls["classification"], "INCONCLUSIVE")
        self.assertIsNotNone(cls.get("telemetry_diagnostic_conclusion"))
        self.assertIn("IPv6", cls["telemetry_diagnostic_conclusion"])

    def test_22_family_aggregate_cannot_substitute_for_primary_stream_handshake(self):
        """22. Family aggregate cannot substitute for primary stream handshake."""
        dissection = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {
                "syn_count": 2,
                "connection_established": True,  # Family aggregate True due to stream 1
                "http_observed": True,
                "first_syn_time": 10.25
            },
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",  # Stream 0 carried GET / but did NOT complete handshake
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": False,  # Crucial: Primary stream handshake incomplete!
            }
        }
        http_outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        cls = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(cls["ipv4_success"])
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "INCONCLUSIVE")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_23_stylesheet_or_script_get_cannot_become_primary_navigation(self, mock_run, mock_which):
        """23. A GET for a stylesheet or script cannot become the primary navigation."""
        lines = [
            # Stream 0: Completed handshake
            self._make_tshark_line(t_epoch=10.00, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=2001, frame_num=3, tcp_len=0),
            # Request for stylesheet (not root / or /index.html)
            self._make_tshark_line(t_epoch=10.04, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/style.css", stream="0", seq_raw=1001, ack_raw=2001, frame_num=4, tcp_len=50),
            self._make_tshark_line(t_epoch=10.05, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=50000, http_code="200", stream="0", seq_raw=2001, ack_raw=1051, frame_num=5, tcp_len=200),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["main_get"])
        self.assertIsNone(s0["main_response_code"])
        self.assertFalse(dissection["main_http_flow"]["correlated"])
        self.assertIsNone(dissection["http_status_code"])
        self.assertIsNone(dissection["main_http_flow"]["status_code"])
        self.assertEqual(dissection["diagnostic_fallback_http_code"], 200)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_24_favicon_response_preceding_root_request_not_used_as_root_response(self, mock_run, mock_which):
        """24. A favicon response preceding a root request on a persistent connection cannot be used as root response."""
        lines = [
            # Handshake
            self._make_tshark_line(t_epoch=10.00, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=2001, frame_num=3, tcp_len=0),
            # Request 0: GET /favicon.ico -> Response 0: 404 Not Found
            self._make_tshark_line(t_epoch=10.04, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/favicon.ico", stream="0", seq_raw=1001, ack_raw=2001, frame_num=4, tcp_len=50),
            self._make_tshark_line(t_epoch=10.05, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=50000, http_code="404", stream="0", seq_raw=2001, ack_raw=1051, frame_num=5, tcp_len=150),
            # Request 1: GET / (primary navigation, but server never responds before capture ends)
            self._make_tshark_line(t_epoch=10.06, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/", stream="0", seq_raw=1051, ack_raw=2151, frame_num=6, tcp_len=40),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["main_get"])
        # The 404 was for /favicon.ico (request index 0), NOT for GET / (request index 1)
        self.assertIsNone(s0["main_response_code"])
        self.assertIsNone(dissection["http_status_code"])
        self.assertTrue(dissection["main_http_flow"]["correlated"])
        self.assertIsNone(dissection["main_http_flow"]["status_code"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_25_uncorrelated_http_status_cannot_promote_http_outcome_success(self, mock_run, mock_which):
        """25. Uncorrelated HTTP status cannot promote http_outcome.success."""
        lines = [
            # Only ancillary stylesheet request is present
            self._make_tshark_line(t_epoch=10.00, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=2001, frame_num=3, tcp_len=0),
            self._make_tshark_line(t_epoch=10.04, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/app.js", stream="0", seq_raw=1001, ack_raw=2001, frame_num=4, tcp_len=50),
            self._make_tshark_line(t_epoch=10.05, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=50000, http_code="200", stream="0", seq_raw=2001, ack_raw=1051, frame_num=5, tcp_len=200),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        self.assertFalse(dissection["main_http_flow"]["correlated"])
        self.assertIsNone(dissection["http_status_code"])

        # Browser navigation failed
        http_outcome = {
            "status_code": None,
            "success": False,
            "winning_address_family": None,
            "winning_ip": None
        }

        # Update HTTP outcome using production helper from run_trial (F-33)
        http_outcome = run_trial.update_http_outcome_from_dissection(http_outcome, dissection)

        # Uncorrelated 200 in capture cannot promote http_outcome.success to True!
        self.assertFalse(http_outcome["success"])
        self.assertIsNone(http_outcome["status_code"])

        cls = run_trial.classify_fallback(dissection, http_outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertNotEqual(cls["classification"], "IPV6_TO_IPV4_FALLBACK")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_26_conflicting_retransmitted_syn_payload_lengths_detected(self, mock_run, mock_which):
        """26. Conflicting retransmitted SYN payload lengths are detected."""
        lines = [
            # Initial SYN with payload length 0
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Retransmitted SYN with identical seq but conflicting payload length 50
            self._make_tshark_line(t_epoch=10.02, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=2, tcp_len=50),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertEqual(s0["handshake_state"], "INVALID")
        self.assertTrue(any("CONFLICTING_SYN_PAYLOAD_LEN" in a for a in s0["anomalies"]))
        # Original syn_data_len must NOT be overwritten
        self.assertEqual(s0["syn_data_len"], 0)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_27_conflicting_retransmitted_synack_payload_lengths_detected(self, mock_run, mock_which):
        """27. Conflicting retransmitted SYN-ACK payload lengths are detected."""
        lines = [
            # Initial SYN
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Initial SYN-ACK with payload length 0
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            # Retransmitted SYN-ACK with identical seq but conflicting payload length 30
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=3, tcp_len=30),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertEqual(s0["handshake_state"], "INVALID")
        self.assertTrue(any("CONFLICTING_SYNACK_PAYLOAD_LEN" in a for a in s0["anomalies"]))
        # Original server_syn_data_len must NOT be overwritten
        self.assertEqual(s0["server_syn_data_len"], 0)

    def test_28_distinguish_ipv6_first_then_ipv4_from_ipv4_first_then_ipv6(self):
        """28. IPv6-first then IPv4 is distinguishable from IPv4-first then IPv6."""
        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        # Case A: IPv6 SYN at 10.0, IPv4 SYN at 10.25 (v6_syn <= v4_syn: standard fallback chronology)
        dissection_v6_first = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.25},
            "connection_attempt_delay_ms": 250.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        cls_a = run_trial.classify_fallback(dissection_v6_first, outcome)
        self.assertTrue(cls_a["fallback_occurred"])
        self.assertEqual(cls_a["classification"], "IPV6_TO_IPV4_FALLBACK")

        # Case B: IPv4 SYN at 10.0, IPv6 SYN at 10.25 (v4_syn < v6_syn: reversed chronology, not fallback!)
        dissection_v4_first = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.25},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "connection_attempt_delay_ms": None,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        cls_b = run_trial.classify_fallback(dissection_v4_first, outcome)
        self.assertFalse(cls_b["fallback_occurred"])
        self.assertEqual(cls_b["classification"], "DIRECT_IPV4")
        self.assertIn("preceded IPv6 attempt", cls_b["reason"])

        # Case C: Both attempted, but first_syn_time missing -> INCONCLUSIVE
        dissection_no_timing = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": None},
            "connection_attempt_delay_ms": None,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        cls_c = run_trial.classify_fallback(dissection_no_timing, outcome)
        self.assertFalse(cls_c["fallback_occurred"])
        self.assertEqual(cls_c["classification"], "INCONCLUSIVE")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_29_syn_sent_rst_validation_requires_ack_acknowledging_syn(self, mock_run, mock_which):
        """29. RFC 9293 §3.5.3: In SYN-SENT, RST is acceptable ONLY IF ACK acknowledges the SYN."""
        # Case A: RST without ACK, SEQ equal to client_isn -> unvalidated, state remains SYN_SENT
        lines_no_ack = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Server RST without ACK (flags 0x0004), raw_seq == client_isn (1000)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=1000, ack_raw=0, frame_num=2, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines_no_ack) + "\n"
        mock_run.return_value = mock_proc

        dissection_a = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_a = dissection_a["tcp_streams"]["0"]
        self.assertTrue(s0_a["server_rst_received"])
        self.assertFalse(s0_a["server_rst_validated"])
        self.assertEqual(s0_a["handshake_state"], "SYN_SENT")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_IN_SYN_SENT" in a for a in s0_a["anomalies"]))

        # Case B: RST with ACK acknowledging SYN (ack_raw == 1001) -> validated, state transitions to RESET
        lines_ack_valid = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Server RST+ACK (flags 0x0014), raw_ack == 1001
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1001, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_ack_valid) + "\n"
        dissection_b = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_b = dissection_b["tcp_streams"]["0"]
        self.assertTrue(s0_b["server_rst_received"])
        self.assertTrue(s0_b["server_rst_validated"])
        self.assertEqual(s0_b["handshake_state"], "RESET")

        # Case C: RST with incorrect ACK (ack_raw == 9999) -> unvalidated, state remains SYN_SENT
        lines_ack_invalid = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Server RST+ACK (flags 0x0014), raw_ack == 9999 (incorrect)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=9999, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_ack_invalid) + "\n"
        dissection_c = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_c = dissection_c["tcp_streams"]["0"]
        self.assertTrue(s0_c["server_rst_received"])
        self.assertFalse(s0_c["server_rst_validated"])
        self.assertEqual(s0_c["handshake_state"], "SYN_SENT")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_IN_SYN_SENT" in a for a in s0_c["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_30_synchronized_state_rst_validation_sequence_scenarios(self, mock_run, mock_which):
        """30. RFC 5961 / RFC 9293 sequence-aware progression and exact-RCV.NXT RST validation."""
        mock_proc = MagicMock()
        mock_run.return_value = mock_proc

        # Scenario 1: SYN payload (client SYN with 20 bytes payload)
        # Server SYN-ACK acknowledges ISN + 1 + 20 = 1021
        # Client final ACK acknowledges server ISN + 1 = 5001
        lines_syn_payload = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=20),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1021, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1021, ack_raw=5001, frame_num=3, tcp_len=0),
            # Server RST matching exact RCV.NXT (5001)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_syn_payload) + "\n"
        d1 = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s1 = d1["tcp_streams"]["0"]
        self.assertTrue(s1["tcp_handshake_completed"])
        self.assertTrue(s1["server_rst_validated"])
        self.assertEqual(s1["handshake_state"], "CLOSED_BY_RESET")

        # Scenario 2: Server SYN-ACK with 15 bytes payload
        # Base RCV.NXT = server_isn (5000) + 1 + 15 = 5016
        lines_synack_payload = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=15),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5016, frame_num=3, tcp_len=0),
            # Valid server RST at 5016
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5016, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_synack_payload) + "\n"
        d2 = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s2 = d2["tcp_streams"]["0"]
        self.assertTrue(s2["tcp_handshake_completed"])
        self.assertTrue(s2["server_rst_validated"])
        self.assertEqual(s2["handshake_state"], "CLOSED_BY_RESET")

        # Scenario 3: Duplicated data segments do not advance RCV.NXT twice
        lines_dup_data = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Server sends 100 bytes at seq 5001
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=1001, frame_num=4, tcp_len=100),
            # Duplicate retransmission of 100 bytes at seq 5001
            self._make_tshark_line(t_epoch=10.05, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=1001, frame_num=5, tcp_len=100),
            # RST with seq 5101 (expected contiguous progression) -> valid!
            self._make_tshark_line(t_epoch=10.06, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5101, ack_raw=0, frame_num=6, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_dup_data) + "\n"
        d3 = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s3 = d3["tcp_streams"]["0"]
        self.assertTrue(s3["server_rst_validated"])
        self.assertEqual(s3["handshake_state"], "CLOSED_BY_RESET")

        # Scenario 4: Out-of-order data segments leave gap, filled later
        lines_ooo = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Out-of-order segment: seq 5101..5201 (gap at 5001..5101)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", sport=80, dport=50000, stream="0", seq_raw=5101, ack_raw=1001, frame_num=4, tcp_len=100),
            # Server RST at 5201 arrives BEFORE gap is filled -> UNVALIDATED because RCV.NXT is still 5001!
            self._make_tshark_line(t_epoch=10.05, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5201, ack_raw=0, frame_num=5, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_ooo) + "\n"
        d4 = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s4 = d4["tcp_streams"]["0"]
        self.assertFalse(s4["server_rst_validated"])
        self.assertEqual(s4["handshake_state"], "ESTABLISHED")

        # Scenario 5: FIN segment advances RCV.NXT by +1
        lines_fin = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Server sends FIN+ACK with 0 payload at seq 5001 (flags 0x0011)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0011", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=1001, frame_num=4, tcp_len=0),
            # Server RST at 5002 (credited +1 for FIN) -> valid!
            self._make_tshark_line(t_epoch=10.05, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5002, ack_raw=0, frame_num=5, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_fin) + "\n"
        d5 = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s5 = d5["tcp_streams"]["0"]
        self.assertTrue(s5["server_rst_validated"])
        self.assertEqual(s5["handshake_state"], "CLOSED_BY_RESET")

        # Scenario 6: Insufficient evidence (server ISN missing) -> unvalidated, state preserved, anomaly logged
        lines_missing_isn = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # RST in SYN_SENT with no ACK
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=0, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_missing_isn) + "\n"
        d6 = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s6 = d6["tcp_streams"]["0"]
        self.assertFalse(s6["server_rst_validated"])
        self.assertEqual(s6["handshake_state"], "SYN_SENT")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_31_http_frame_reference_correlation_avoids_misattributing_subsequent_responses(self, mock_run, mock_which):
        """31. Frame-reference correlation: JavaScript 200 is NEVER assigned to root GET /."""
        lines = [
            # Handshake
            self._make_tshark_line(t_epoch=10.00, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=2000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=2001, frame_num=3, tcp_len=0),
            # Request 0: GET /favicon.ico (Frame 4) -> Response 0: 404 (Frame 5)
            self._make_tshark_line(t_epoch=10.04, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/favicon.ico", stream="0", seq_raw=1001, ack_raw=2001, frame_num=4, tcp_len=50, http_response_in="5", http_request_in=""),
            self._make_tshark_line(t_epoch=10.05, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=50000, http_code="404", stream="0", seq_raw=2001, ack_raw=1051, frame_num=5, tcp_len=150, http_response_in="", http_request_in="4"),
            # Request 1: GET / (Frame 6, root navigation, but server never responds)
            self._make_tshark_line(t_epoch=10.06, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/", stream="0", seq_raw=1051, ack_raw=2151, frame_num=6, tcp_len=40, http_response_in="", http_request_in=""),
            # Request 2: GET /app.js (Frame 7) -> Response 2: 200 OK (Frame 8)
            self._make_tshark_line(t_epoch=10.07, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=50000, dport=80, http_method="GET", http_uri="/app.js", stream="0", seq_raw=1091, ack_raw=2151, frame_num=7, tcp_len=45, http_response_in="8", http_request_in=""),
            self._make_tshark_line(t_epoch=10.08, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=50000, http_code="200", stream="0", seq_raw=2151, ack_raw=1136, frame_num=8, tcp_len=500, http_response_in="", http_request_in="7"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["main_get"])
        # Crucial PS-028 invariant: JavaScript 200 must NEVER be assigned to GET /
        self.assertIsNone(s0["main_response_code"])
        self.assertIsNone(dissection["http_status_code"])
        self.assertIsNone(dissection["main_http_flow"]["status_code"])

    def test_32_strict_fallback_chronology_with_identical_timestamps(self):
        """32. Strict fallback chronology: identical timestamps resolved by capture frame numbers."""
        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv4"}

        # Case A: Identical timestamps (10.0s), IPv6 frame 1 < IPv4 frame 2 -> IPV6_TO_IPV4_FALLBACK
        dissection_v6_first = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0, "first_syn_frame": 1},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0, "first_syn_frame": 2},
            "connection_attempt_delay_ms": 0.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        cls_a = run_trial.classify_fallback(dissection_v6_first, outcome)
        self.assertTrue(cls_a["fallback_occurred"])
        self.assertEqual(cls_a["classification"], "IPV6_TO_IPV4_FALLBACK")
        self.assertIn("resolved by capture frame sequence", cls_a["reason"])

        # Case B: Identical timestamps (10.0s), IPv4 frame 1 < IPv6 frame 2 -> DIRECT_IPV4 (reversed order)
        dissection_v4_first = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0, "first_syn_frame": 2},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0, "first_syn_frame": 1},
            "connection_attempt_delay_ms": None,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        cls_b = run_trial.classify_fallback(dissection_v4_first, outcome)
        self.assertFalse(cls_b["fallback_occurred"])
        self.assertEqual(cls_b["classification"], "DIRECT_IPV4")
        self.assertIn("preceded IPv6 attempt by capture frame sequence", cls_b["reason"])

        # Case C: Identical timestamps (10.0s), but missing frame numbers -> INCONCLUSIVE
        dissection_no_frames = {
            "ipv6": {"syn_count": 1, "connection_established": False, "http_observed": False, "first_syn_time": 10.0, "first_syn_frame": None},
            "ipv4": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0, "first_syn_frame": None},
            "connection_attempt_delay_ms": 0.0,
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        cls_c = run_trial.classify_fallback(dissection_no_frames, outcome)
        self.assertFalse(cls_c["fallback_occurred"])
        self.assertEqual(cls_c["classification"], "INCONCLUSIVE")
        self.assertIn("missing capture frame numbers", cls_c["reason"])

    def test_33_update_http_outcome_from_dissection(self):
        """33. Exercise production update_http_outcome_from_dissection helper directly."""
        # Case A: Correlated dissection with 200 OK
        corr_dissection = {
            "http_status_code": 200,
            "http_response_family": "IPv6",
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "status_code": 200,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        outcome_a = {"status_code": None, "success": False, "winning_address_family": None, "winning_ip": None}
        updated_a = run_trial.update_http_outcome_from_dissection(outcome_a, corr_dissection)
        self.assertEqual(updated_a["status_code"], 200)
        self.assertTrue(updated_a["success"])
        self.assertEqual(updated_a["winning_address_family"], "IPv6")
        self.assertEqual(updated_a["winning_ip"], run_trial.SERVER_IPV6)

        # Case B: Correlated dissection with 404
        corr_dissection_404 = {
            "http_status_code": 404,
            "http_response_family": "IPv4",
            "main_http_flow": {
                "stream_id": "0",
                "family": "IPv4",
                "status_code": 404,
                "request": ("GET", "/"),
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        outcome_b = {"status_code": None, "success": False, "winning_address_family": None, "winning_ip": None}
        updated_b = run_trial.update_http_outcome_from_dissection(outcome_b, corr_dissection_404)
        self.assertEqual(updated_b["status_code"], 404)
        self.assertFalse(updated_b["success"])
        self.assertEqual(updated_b["winning_address_family"], "IPv4")

        # Case C: Uncorrelated dissection with ancillary 200 cannot promote failed navigation
        uncorr_dissection = {
            "http_status_code": None,
            "http_response_family": None,
            "main_http_flow": {
                "stream_id": None,
                "family": None,
                "status_code": None,
                "request": None,
                "correlated": False,
                "tcp_handshake_completed": False,
            }
        }
        outcome_c = {"status_code": None, "success": False, "winning_address_family": None, "winning_ip": None}
        updated_c = run_trial.update_http_outcome_from_dissection(outcome_c, uncorr_dissection, is_simulation=False)
        self.assertIsNone(updated_c["status_code"])
        self.assertFalse(updated_c["success"])

        # Case D: Uncorrelated dissection with browser-corroborated success
        outcome_d = {"status_code": 200, "success": True, "winning_address_family": None, "winning_ip": None}
        browser_res = {"winning_family": "IPv4"}
        updated_d = run_trial.update_http_outcome_from_dissection(outcome_d, uncorr_dissection, browser_result=browser_res)
        self.assertEqual(updated_d["status_code"], 200)
        self.assertTrue(updated_d["success"])
        self.assertEqual(updated_d["winning_address_family"], "IPv4")
        self.assertEqual(updated_d["winning_ip"], run_trial.SERVER_IPV4)

    def test_34_uncorrelated_evidence_policy_forces_inconclusive_with_telemetry_diagnostic(self):
        """34. F-34: Uncorrelated packet evidence cannot prove navigation; forces INCONCLUSIVE with diagnostic."""
        dissection_uncorr = {
            "ipv6": {"syn_count": 1, "connection_established": True, "http_observed": True, "first_syn_time": 10.0},
            "ipv4": {"syn_count": 0, "connection_established": False, "http_observed": False, "first_syn_time": None},
            "connection_attempt_delay_ms": None,
            "main_http_flow": {
                "stream_id": None,
                "family": None,
                "status_code": None,
                "request": None,
                "correlated": False,
                "tcp_handshake_completed": False,
            }
        }
        outcome = {"status_code": 200, "success": True, "winning_address_family": "IPv6"}

        cls = run_trial.classify_fallback(dissection_uncorr, outcome)
        self.assertFalse(cls["fallback_occurred"])
        self.assertEqual(cls["classification"], "INCONCLUSIVE")
        self.assertIn("uncorrelated", cls["reason"].lower())
        self.assertIsNotNone(cls.get("telemetry_diagnostic_conclusion"))
        self.assertIn("Browser reported navigation success on IPv6", cls["telemetry_diagnostic_conclusion"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_35_tfo_accepted_syn_data(self, mock_run, mock_which):
        """35. F-35: TCP Fast Open server accepts client SYN payload and acknowledges it."""
        lines = [
            # Frame 1: Client SYN carrying 40 bytes data (seq 1000..1040)
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=40),
            # Frame 2: Server SYN-ACK acknowledging SYN + 40 bytes (ack_raw == 1041)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1041, frame_num=2, tcp_len=0),
            # Frame 3: Client final ACK at seq 1041 acknowledging server ISN+1 (5001)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1041, ack_raw=5001, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertEqual(s0["syn_data_len"], 40)
        self.assertEqual(s0["syn_data_accepted"], 40)
        self.assertEqual(s0["server_ack_received"], 1041)
        self.assertEqual(s0["final_ack_frame"], 3)
        self.assertTrue(dissection["ipv6"]["connection_established"])
        self.assertTrue(dissection["ipv6"]["tcp_handshake_completed"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_36_tfo_rejected_syn_data_followed_by_retransmission_in_first_ack(self, mock_run, mock_which):
        """36. F-35: TCP Fast Open server rejects SYN data (ACKs only SYN); client retransmits in first ACK."""
        lines = [
            # Frame 1: Client SYN carrying 40 bytes data (seq 1000..1040)
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=40),
            # Frame 2: Server SYN-ACK rejecting data, acknowledging only SYN (ack_raw == 1001)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            # Frame 3: Client final ACK at seq 1001 retransmitting 40 bytes payload, acknowledging server ISN+1 (5001)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=40),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertEqual(s0["syn_data_len"], 40)
        self.assertEqual(s0["syn_data_accepted"], 0)
        self.assertEqual(s0["server_ack_received"], 1001)
        self.assertEqual(s0["final_ack_frame"], 3)
        self.assertEqual(s0["final_ack_data_len"], 40)
        self.assertTrue(dissection["ipv6"]["connection_established"])
        self.assertEqual(len(s0["anomalies"]), 0)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_37_client_bare_syn_retransmission_after_original_data_bearing_syn(self, mock_run, mock_which):
        """37. F-36 / F-41: Zero-payload SYN retry with identical ISN preserves sequence history."""
        lines = [
            # Frame 1: Original client SYN with 50 bytes data
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=50),
            # Frame 2: Zero-payload SYN retry (RFC 7413): same ISN 1000, tcp_len == 0
            self._make_tshark_line(t_epoch=10.02, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=2, tcp_len=0),
            # Frame 3: Server SYN-ACK acknowledging SYN (ack_raw == 1001)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=3, tcp_len=0),
            # Frame 4: Client final ACK at seq 1001
            self._make_tshark_line(t_epoch=10.05, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        # Original syn_data_len must NOT be overwritten with 0
        self.assertEqual(s0["syn_data_len"], 50)
        self.assertTrue(s0["zero_payload_syn_retry"])
        self.assertTrue(s0["bare_syn_retry"])
        self.assertEqual(s0["final_ack_frame"], 4)
        self.assertTrue(dissection["ipv6"]["connection_established"])
        self.assertFalse(any("CONFLICTING_SYN_PAYLOAD_LEN" in a for a in s0["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_38_server_no_data_synack_retransmission_following_original_data_bearing_synack(self, mock_run, mock_which):
        """38. F-37 / F-41: Zero-payload SYN-ACK retransmission preserves ISN; client ACK determines sequence space."""
        lines = [
            # Frame 1: Client SYN
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Frame 2: Original server SYN-ACK carrying 30 bytes data
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=30),
            # Frame 3: Retransmitted zero-payload SYN-ACK (RFC 7413): same ISN 5000, tcp_len == 0
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=3, tcp_len=0),
            # Frame 4: Client ACK acknowledging bare SYN-ACK only (ack_raw == 5001, not 5031)
            self._make_tshark_line(t_epoch=10.05, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=4, tcp_len=0),
            # Frame 5: Server sends RST at seq 5001
            self._make_tshark_line(t_epoch=10.06, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=0, frame_num=5, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        # Original server_syn_data_len preserved
        self.assertEqual(s0["server_syn_data_len"], 30)
        # Client ACK determined that 0 bytes of SYN-ACK data were accepted
        self.assertEqual(s0["server_syn_data_len_accepted"], 0)
        self.assertTrue(s0["zero_payload_synack_retry"])
        self.assertEqual(len(s0["syn_ack_variants"]), 2)
        # RST at 5001 is validated because RCV.NXT was computed from accepted client sequence space
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_RESET")
        self.assertFalse(any("CONFLICTING_SYNACK_PAYLOAD_LEN" in a for a in s0["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_39_syn_and_synack_sequence_number_wraparound(self, mock_run, mock_which):
        """39. F-35: 32-bit serial arithmetic wraparound for SYN and SYN-ACK sequence space."""
        # Client ISN near 2^32 - 1: 0xFFFFFFE0 (4294967264), with syn_data_len = 35
        # Expected server ACK: (0xFFFFFFE0 + 1 + 35) & 0xFFFFFFFF = 4
        # Server ISN near 2^32 - 1: 0xFFFFFFF0 (4294967280), with server_syn_data_len = 20
        # Expected client ACK: (0xFFFFFFF0 + 1 + 20) & 0xFFFFFFFF = 5
        client_isn = 0xFFFFFFE0
        server_isn = 0xFFFFFFF0
        lines = [
            # Frame 1: Client SYN across 2^32 boundary
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=client_isn, ack_raw=0, frame_num=1, tcp_len=35),
            # Frame 2: Server SYN-ACK acknowledging full 35 bytes at ack 4, offering 20 bytes data
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=server_isn, ack_raw=4, frame_num=2, tcp_len=20),
            # Frame 3: Client final ACK at seq 4 acknowledging full 20 bytes at ack 5
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=4, ack_raw=5, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertEqual(s0["syn_data_accepted"], 35)
        self.assertEqual(s0["server_syn_data_len_accepted"], 20)
        self.assertEqual(s0["final_ack_frame"], 3)
        self.assertTrue(dissection["ipv6"]["connection_established"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_40_rst_with_payload_must_not_contribute_to_its_own_rcv_nxt_validation(self, mock_run, mock_which):
        """40. F-38: RST with payload must not advance its own RCV.NXT validation basis."""
        mock_proc = MagicMock()
        mock_run.return_value = mock_proc

        # Part A: Valid RST carrying payload
        # Handshake established: server ISN 5000 + 1 = 5001. Contiguous RCV.NXT is 5001.
        # Server sends RST with seq 5001 and tcp_len 100.
        # The RST segment itself must NOT advance RCV.NXT to 5101 before validation.
        lines_valid_rst_with_payload = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Server RST carrying 100 bytes payload at seq 5001
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=0, frame_num=4, tcp_len=100),
        ]
        mock_proc.stdout = "\n".join(lines_valid_rst_with_payload) + "\n"
        d_valid = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_valid = d_valid["tcp_streams"]["0"]
        self.assertTrue(s0_valid["tcp_handshake_completed"])
        # Expected sequence was 5001, matched 5001
        self.assertTrue(s0_valid["server_rst_validated"])
        self.assertEqual(s0_valid["handshake_state"], "CLOSED_BY_RESET")
        # Ensure RST was not appended to server_segments
        self.assertEqual(len(s0_valid["server_segments"]), 0)

        # Part B: Invalid RST carrying payload
        # Server sends RST with seq 5101 and tcp_len 100.
        # If the RST payload were appended before validation, RCV.NXT could be corrupted.
        # It must NOT match RCV.NXT 5001.
        lines_invalid_rst_with_payload = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Invalid RST carrying 100 bytes payload at seq 5101 (expected 5001)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5101, ack_raw=0, frame_num=4, tcp_len=100),
        ]
        mock_proc.stdout = "\n".join(lines_invalid_rst_with_payload) + "\n"
        d_invalid = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_invalid = d_invalid["tcp_streams"]["0"]
        self.assertTrue(s0_invalid["tcp_handshake_completed"])
        self.assertFalse(s0_invalid["server_rst_validated"])
        self.assertEqual(s0_invalid["handshake_state"], "ESTABLISHED")
        self.assertEqual(len(s0_invalid["server_segments"]), 0)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_41_syn_sent_rst_acceptable_ack_semantics(self, mock_run, mock_which):
        """41. F-39: In SYN-SENT, RST is acceptable if SND.UNA < SEG.ACK <= SND.NXT."""
        mock_proc = MagicMock()
        mock_run.return_value = mock_proc

        # Client SYN with 50 bytes data (seq 1000..1050). SND.UNA = 1000, SND.NXT = 1051.
        # Acceptable ACK range: [1001, 1051].

        # Case A: ACK equal to ISN + 1 (1001)
        lines_a = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1001, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_a) + "\n"
        da = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sa = da["tcp_streams"]["0"]
        self.assertTrue(sa["server_rst_validated"])
        self.assertEqual(sa["handshake_state"], "RESET")

        # Case B: ACK equal to ISN + 1 + syn_data_len (1051)
        lines_b = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1051, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_b) + "\n"
        db = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sb = db["tcp_streams"]["0"]
        self.assertTrue(sb["server_rst_validated"])
        self.assertEqual(sb["handshake_state"], "RESET")

        # Case C: ACK strictly between 1001 and 1051 (1025)
        lines_c = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1025, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_c) + "\n"
        dc = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sc = dc["tcp_streams"]["0"]
        self.assertTrue(sc["server_rst_validated"])
        self.assertEqual(sc["handshake_state"], "RESET")

        # Case D: 32-bit wraparound (client ISN == 0xFFFFFFFF, syn_data_len == 50)
        # Acceptable ACK range: [0, 50]
        lines_d = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=0xFFFFFFFF, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=25, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_d) + "\n"
        dd = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sd = dd["tcp_streams"]["0"]
        self.assertTrue(sd["server_rst_validated"])
        self.assertEqual(sd["handshake_state"], "RESET")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_42_syn_sent_rst_unacceptable_ack_semantics(self, mock_run, mock_which):
        """42. F-39: In SYN-SENT, RST remains unvalidated if ACK is outside acceptable range."""
        mock_proc = MagicMock()
        mock_run.return_value = mock_proc

        # Client SYN with 50 bytes data (seq 1000..1050). Acceptable ACK range: [1001, 1051].

        # Case A: ACK outside acceptable range (1052 > SND.NXT)
        lines_a = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1052, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_a) + "\n"
        da = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sa = da["tcp_streams"]["0"]
        self.assertTrue(sa["server_rst_received"])
        self.assertFalse(sa["server_rst_validated"])
        self.assertEqual(sa["handshake_state"], "SYN_SENT")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_IN_SYN_SENT" in a for a in sa["anomalies"]))

        # Case B: ACK outside acceptable range (1000 does not acknowledge SYN, SND.UNA)
        lines_b = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=1000, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_b) + "\n"
        db = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sb = db["tcp_streams"]["0"]
        self.assertTrue(sb["server_rst_received"])
        self.assertFalse(sb["server_rst_validated"])
        self.assertEqual(sb["handshake_state"], "SYN_SENT")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_IN_SYN_SENT" in a for a in sb["anomalies"]))

        # Case C: 32-bit wraparound outside range (client ISN == 0xFFFFFFFF, syn_data_len == 50 -> range [0, 50], ACK = 51)
        lines_c = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=0xFFFFFFFF, ack_raw=0, frame_num=1, tcp_len=50),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", sport=80, dport=50000, stream="0", seq_raw=0, ack_raw=51, frame_num=2, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_c) + "\n"
        dc = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        sc = dc["tcp_streams"]["0"]
        self.assertTrue(sc["server_rst_received"])
        self.assertFalse(sc["server_rst_validated"])
        self.assertEqual(sc["handshake_state"], "SYN_SENT")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_IN_SYN_SENT" in a for a in sc["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_43_f40_data_bearing_synack_followed_by_rst_before_final_ack_unvalidated(self, mock_run, mock_which):
        """43. F-40: In SYNACK_RCVD with data-bearing SYN-ACK, RST before client final ACK is unvalidated."""
        lines = [
            # Frame 1: Client SYN
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Frame 2: Server SYN-ACK carrying 30 bytes data
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=30),
            # Frame 3: Server RST before client final ACK arrives
            self._make_tshark_line(t_epoch=10.03, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5031, ack_raw=0, frame_num=3, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        # Client final ACK has not arrived, so accepted sequence space cannot be established
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertTrue(s0["server_rst_received"])
        self.assertFalse(s0["server_rst_validated"])
        # State remains preserved as SYNACK_RCVD
        self.assertEqual(s0["handshake_state"], "SYNACK_RCVD")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_INSUFFICIENT_EVIDENCE" in a for a in s0["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_44_f40_zero_payload_synack_followed_by_rst_before_final_ack_validated_where_sufficient(self, mock_run, mock_which):
        """44. F-40: In SYNACK_RCVD with zero-payload SYN-ACK, RST before client final ACK validated using server ISN+1 base."""
        mock_proc = MagicMock()
        mock_run.return_value = mock_proc

        # Case A: Matching sequence (server_isn + 1 = 5001)
        lines_matching = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=0, frame_num=3, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_matching) + "\n"
        d_match = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_match = d_match["tcp_streams"]["0"]
        self.assertTrue(s0_match["server_rst_received"])
        self.assertTrue(s0_match["server_rst_validated"])
        self.assertEqual(s0_match["handshake_state"], "RESET")

        # Case B: Mismatching sequence (9999 != 5001)
        lines_mismatch = [
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=0),
            self._make_tshark_line(t_epoch=10.03, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=9999, ack_raw=0, frame_num=3, tcp_len=0),
        ]
        mock_proc.stdout = "\n".join(lines_mismatch) + "\n"
        d_mismatch = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0_mismatch = d_mismatch["tcp_streams"]["0"]
        self.assertTrue(s0_mismatch["server_rst_received"])
        self.assertFalse(s0_mismatch["server_rst_validated"])
        self.assertEqual(s0_mismatch["handshake_state"], "SYNACK_RCVD")
        self.assertTrue(any("UNVALIDATED_SERVER_RST_IN_SYNACK_RCVD" in a for a in s0_mismatch["anomalies"]))

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_45_f40_data_bearing_synack_client_ack_zero_bytes_rcv_nxt_uses_syn_only_position(self, mock_run, mock_which):
        """45. F-40: Data-bearing SYN-ACK followed by client ACK of 0 data bytes: RCV.NXT uses SYN-only position."""
        lines = [
            # Frame 1: Client SYN
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Frame 2: Server SYN-ACK with 30 bytes data
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=30),
            # Frame 3: Client final ACK acknowledging 0 bytes of SYN-ACK data (ack_raw == 5001)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5001, frame_num=3, tcp_len=0),
            # Frame 4: Server RST at 5001 (SYN-only position)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5001, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["server_syn_data_len_accepted"], 0)
        self.assertEqual(run_trial._compute_rcv_nxt(s0), 5001)
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_RESET")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_46_f40_data_bearing_synack_client_ack_all_bytes_rcv_nxt_uses_full_position(self, mock_run, mock_which):
        """46. F-40: Data-bearing SYN-ACK followed by client ACK of all bytes: RCV.NXT uses full sequence position."""
        lines = [
            # Frame 1: Client SYN
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Frame 2: Server SYN-ACK with 30 bytes data
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=30),
            # Frame 3: Client final ACK acknowledging all 30 bytes of SYN-ACK data (ack_raw == 5031)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5031, frame_num=3, tcp_len=0),
            # Frame 4: Server RST at 5031 (full position)
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5031, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["server_syn_data_len_accepted"], 30)
        self.assertEqual(run_trial._compute_rcv_nxt(s0), 5031)
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_RESET")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_47_f42_partial_acknowledgement_client_syn_data_completed_handshake(self, mock_run, mock_which):
        """47. F-42: Partial acknowledgement of client SYN data in completed handshake."""
        lines = [
            # Frame 1: Client SYN with 40 bytes data (seq 1000..1040)
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=40),
            # Frame 2: Server SYN-ACK acknowledging 20 bytes (ack_raw == 1021)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1021, frame_num=2, tcp_len=0),
            # Frame 3: Client first ACK at seq 1021 with 20 bytes retransmitted payload, acknowledging server ISN+1 (5001)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1021, ack_raw=5001, frame_num=3, tcp_len=20),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        self.assertEqual(s0["syn_data_accepted"], 20)
        self.assertEqual(s0["server_ack_received"], 1021)
        self.assertEqual(s0["final_ack_data_len"], 20)
        self.assertEqual(s0["syn_data_len"], 40)
        self.assertTrue(dissection["ipv6"]["connection_established"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_48_f42_partial_acknowledgement_server_synack_data_rcv_nxt_basis(self, mock_run, mock_which):
        """48. F-42: Partial acknowledgement of server SYN-ACK data grounds _compute_rcv_nxt() base."""
        lines = [
            # Frame 1: Client SYN
            self._make_tshark_line(t_epoch=10.00, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="0", seq_raw=1000, ack_raw=0, frame_num=1, tcp_len=0),
            # Frame 2: Server SYN-ACK with 50 bytes data (seq 5000..5050)
            self._make_tshark_line(t_epoch=10.02, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="0", seq_raw=5000, ack_raw=1001, frame_num=2, tcp_len=50),
            # Frame 3: Client final ACK partially acknowledging 25 bytes of SYN-ACK data (ack_raw == 5026)
            self._make_tshark_line(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="0", seq_raw=1001, ack_raw=5026, frame_num=3, tcp_len=0),
            # Frame 4: Server RST at seq 5026
            self._make_tshark_line(t_epoch=10.04, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", sport=80, dport=50000, stream="0", seq_raw=5026, ack_raw=0, frame_num=4, tcp_len=0),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["server_syn_data_len"], 50)
        self.assertEqual(s0["server_syn_data_len_accepted"], 25)
        # _compute_rcv_nxt starts strictly from acknowledged length: 5000 + 1 + 25 = 5026
        self.assertEqual(run_trial._compute_rcv_nxt(s0), 5026)
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_RESET")


class TestPhaseC1HandshakeAndFlowCorrelationRegression(unittest.TestCase):
    """
    Milestone 2 Batch C1 Regression Tests:
    - SYN-only incomplete handshake (null preservation)
    - Missing final ACK (null preservation with INDETERMINATE_NO_FINAL_ACK)
    - Valid 3-way handshake completion (RFC 9293 §3.5 t_connect_ms and Amendment A3 t_setup_total_ms)
    - Retransmitted SYN invariance (initial SYN timestamp not advanced)
    - Ancillary stream isolation (root document / or /index.html exclusively decides primary flow)
    - Exact QNAME matching (normalized exact match vs loose substring)
    - Duplicate dns.id handling via FIFO transaction queue
    - Type 65 (HTTPS/SVCB) query isolation from A/AAAA distributions
    - DNS query / last-positive-response to first payload latency metrics
    - Schema 1.1.0 and compact primary_flow emission
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_c1_regress_"))
        self.pcap_file = self.temp_dir / "test.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.pcap_file.write_bytes(header)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_tshark_line_c1(
        self,
        t_epoch: float = 10.0,
        ip_src: str = "",
        ip_dst: str = "",
        ip6_src: str = "",
        ip6_dst: str = "",
        flags: str = "0x0002",
        sport: int = 50000,
        dport: int = 80,
        dns_qname: str = "",
        dns_qtype: str = "",
        dns_resp: str = "",
        dns_a: str = "",
        dns_aaaa: str = "",
        http_code: str = "",
        stream: str = "0",
        http_method: str = "",
        http_uri: str = "",
        seq_raw: int = 1000,
        ack_raw: int = 0,
        frame_num: int = 1,
        tcp_len: int = 0,
        http_response_in: str = "",
        http_request_in: str = "",
        dns_id: str = "",
        dns_rcode: str = "",
        udp_sport: str = "",
        udp_dport: str = "",
        dns_ancount: str = "",
        dns_resp_name: str = "",
    ) -> str:
        fields = [
            str(t_epoch), ip_src, ip_dst, ip6_src, ip6_dst, flags,
            str(sport), str(dport), dns_qname, dns_qtype, dns_resp, dns_a, dns_aaaa,
            http_code, stream, http_method, http_uri, str(seq_raw), str(ack_raw),
            str(frame_num), str(tcp_len), http_response_in, http_request_in,
            dns_id, dns_rcode, udp_sport, udp_dport, dns_ancount, dns_resp_name
        ]
        return "\t".join(fields)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_handshake_syn_only_preserves_explicit_nulls(self, mock_run, mock_which):
        """SYN-only: Incomplete handshake retains explicit nulls with canonical reason codes."""
        lines = [
            self._make_tshark_line_c1(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            )
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertIsNone(s0["t_connect_ms"])
        self.assertIsNone(s0["t_setup_total_ms"])
        self.assertIsNone(s0["syn_to_synack_ms"])
        self.assertEqual(s0["null_reasons"]["syn_to_synack_ms"], "INDETERMINATE_NO_SYNACK")
        self.assertEqual(s0["null_reasons"]["t_connect_ms"], "INDETERMINATE_NO_SYNACK")
        self.assertEqual(s0["null_reasons"]["t_setup_total_ms"], "INDETERMINATE_NO_SYNACK")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_handshake_missing_final_ack_preserves_explicit_null(self, mock_run, mock_which):
        """Missing final ACK: syn_to_synack_ms calculated, but t_connect_ms remains null."""
        lines = [
            self._make_tshark_line_c1(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line_c1(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertAlmostEqual(s0["syn_to_synack_ms"], 20.0, places=2)
        self.assertIsNone(s0["t_connect_ms"])
        self.assertIsNone(s0["t_setup_total_ms"])
        self.assertEqual(s0["null_reasons"]["t_connect_ms"], "INDETERMINATE_NO_FINAL_ACK")
        self.assertEqual(s0["null_reasons"]["t_setup_total_ms"], "INDETERMINATE_NO_FINAL_ACK")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_handshake_valid_three_way_completion(self, mock_run, mock_which):
        """Completed 3-way handshake: t_connect_ms, t_setup_total_ms, and syn_to_synack_ms all populated."""
        lines = [
            self._make_tshark_line_c1(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line_c1(
                t_epoch=10.025,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            self._make_tshark_line_c1(
                t_epoch=10.030,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1001,
                ack_raw=5001,
                frame_num=3,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertAlmostEqual(s0["syn_to_synack_ms"], 25.0, places=2)
        self.assertAlmostEqual(s0["t_connect_ms"], 30.0, places=2)
        self.assertAlmostEqual(s0["t_setup_total_ms"], 30.0, places=2)
        self.assertNotIn("t_connect_ms", s0["null_reasons"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_handshake_wrong_ack_seq_ignored(self, mock_run, mock_which):
        """ACK with unexpected sequence does NOT complete handshake."""
        lines = [
            self._make_tshark_line_c1(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            self._make_tshark_line_c1(
                t_epoch=10.02,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=2,
            ),
            self._make_tshark_line_c1(
                t_epoch=10.03,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1001,
                ack_raw=9999,  # Mismatched ACK sequence
                frame_num=3,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["tcp_handshake_completed"])
        self.assertIsNone(s0["t_connect_ms"])
        self.assertEqual(s0["null_reasons"]["t_connect_ms"], "INDETERMINATE_NO_FINAL_ACK")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_retransmitted_syn_invariance(self, mock_run, mock_which):
        """Retransmitted SYN increments retransmitted_syn_count without advancing initial SYN timestamp."""
        lines = [
            # Frame 1: Initial SYN at t=10.00
            self._make_tshark_line_c1(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
            # Frame 2: Retransmitted SYN at t=10.50
            self._make_tshark_line_c1(
                t_epoch=10.50,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=2,
            ),
            # Frame 3: Server SYN-ACK at t=10.52
            self._make_tshark_line_c1(
                t_epoch=10.52,
                ip6_src=run_trial.SERVER_IPV6,
                ip6_dst="2001:db8:1::2",
                flags="0x0012",
                sport=80,
                dport=50000,
                stream="0",
                seq_raw=5000,
                ack_raw=1001,
                frame_num=3,
            ),
            # Frame 4: Client final ACK at t=10.54
            self._make_tshark_line_c1(
                t_epoch=10.54,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0010",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1001,
                ack_raw=5001,
                frame_num=4,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["retransmitted_syn_count"], 1)
        # RFC 9293 §3.5: t_connect_ms measured strictly from initial SYN (10.00)
        self.assertAlmostEqual(s0["t_connect_ms"], 540.0, places=2)
        self.assertAlmostEqual(s0["syn_to_synack_ms"], 520.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_ancillary_stream_isolation_favors_root_document(self, mock_run, mock_which):
        """Stream carrying root document (GET /) exclusively decides primary flow over ancillary streams."""
        lines = [
            # Stream 0: Ancillary /favicon.ico request
            self._make_tshark_line_c1(t_epoch=10.00, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=40000, dport=80, stream="0", seq_raw=100, ack_raw=0, frame_num=1),
            self._make_tshark_line_c1(t_epoch=10.01, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=40000, stream="0", seq_raw=500, ack_raw=101, frame_num=2),
            self._make_tshark_line_c1(t_epoch=10.015, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=40000, dport=80, stream="0", seq_raw=101, ack_raw=501, frame_num=3),
            self._make_tshark_line_c1(t_epoch=10.016, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=40000, dport=80, stream="0", seq_raw=101, ack_raw=501, frame_num=4, tcp_len=50, http_method="GET", http_uri="/favicon.ico", http_response_in="5"),
            self._make_tshark_line_c1(t_epoch=10.02, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=40000, stream="0", seq_raw=501, ack_raw=151, frame_num=5, tcp_len=100, http_code="404", http_request_in="4"),

            # Stream 1: Primary root document request (GET /)
            self._make_tshark_line_c1(t_epoch=10.03, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="1", seq_raw=1000, ack_raw=0, frame_num=6),
            self._make_tshark_line_c1(t_epoch=10.05, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="1", seq_raw=5000, ack_raw=1001, frame_num=7),
            self._make_tshark_line_c1(t_epoch=10.055, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="1", seq_raw=1001, ack_raw=5001, frame_num=8),
            self._make_tshark_line_c1(t_epoch=10.056, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", sport=50000, dport=80, stream="1", seq_raw=1001, ack_raw=5001, frame_num=9, tcp_len=50, http_method="GET", http_uri="/", http_response_in="10"),
            self._make_tshark_line_c1(t_epoch=10.07, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", sport=80, dport=50000, stream="1", seq_raw=5001, ack_raw=1051, frame_num=10, tcp_len=200, http_code="200", http_request_in="9"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        self.assertEqual(dissection["main_http_flow"]["stream_id"], "1")
        self.assertEqual(dissection["main_http_flow"]["http_uri"], "/")
        self.assertEqual(dissection["main_http_flow"]["status_code"], 200)
        self.assertEqual(dissection["primary_flow"]["stream_id"], "1")
        self.assertEqual(dissection["primary_flow"]["family"], "IPv6")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_exact_qname_matching_vs_substring(self, mock_run, mock_which):
        """Exact normalized QNAME matching prevents subdomains or similar strings from matching target hostname."""
        lines = [
            # Subdomain query/response: should be ignored by exact matching
            self._make_tshark_line_c1(t_epoch=10.00, dns_qname="sub.trial.he.test", dns_qtype="1", dns_id="0x0001", udp_sport="53000", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.01, dns_qname="sub.trial.he.test", dns_qtype="1", dns_resp="1", dns_a="10.0.1.99", dns_id="0x0001", udp_sport="53", udp_dport="53000"),
            # Exact target query/response
            self._make_tshark_line_c1(t_epoch=10.02, dns_qname="trial.he.test.", dns_qtype="1", dns_id="0x0002", udp_sport="53001", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.03, dns_qname="trial.he.test.", dns_qtype="1", dns_resp="1", dns_a="10.0.2.10", dns_id="0x0002", udp_sport="53", udp_dport="53001"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        # Legacy queries array should only contain the matched query
        queries = dissection["dns"]["queries"]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0]["qname"].rstrip("."), "trial.he.test")
        responses = dissection["dns"]["responses"]
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["address"], "10.0.2.10")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_duplicate_dns_id_fifo_pairing(self, mock_run, mock_which):
        """Sequential DNS queries reusing the same transaction ID pair cleanly via FIFO queue."""
        lines = [
            # Tx 1: query and response
            self._make_tshark_line_c1(t_epoch=10.00, dns_qname="trial.he.test", dns_qtype="1", dns_id="0x1234", udp_sport="50000", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.02, dns_qname="trial.he.test", dns_qtype="1", dns_resp="1", dns_a="10.0.2.10", dns_id="0x1234", udp_sport="53", udp_dport="50000"),
            # Tx 2: query and response reusing 0x1234
            self._make_tshark_line_c1(t_epoch=10.05, dns_qname="trial.he.test", dns_qtype="1", dns_id="0x1234", udp_sport="50001", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.08, dns_qname="trial.he.test", dns_qtype="1", dns_resp="1", dns_a="10.0.2.10", dns_id="0x1234", udp_sport="53", udp_dport="50001"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        txs = dissection["dns_transactions"]
        self.assertEqual(len(txs), 2)
        self.assertAlmostEqual(txs[0]["duration_ms"], 20.0, places=2)
        self.assertAlmostEqual(txs[1]["duration_ms"], 30.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_type_65_https_svcb_isolation(self, mock_run, mock_which):
        """Type 65 (HTTPS/SVCB) queries are routed to https_svcb_queries and excluded from A/AAAA distributions."""
        lines = [
            # Type 65 query/response
            self._make_tshark_line_c1(t_epoch=10.00, dns_qname="trial.he.test", dns_qtype="65", dns_id="0x6565", udp_sport="50000", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.01, dns_qname="trial.he.test", dns_qtype="65", dns_resp="1", dns_id="0x6565", udp_sport="53", udp_dport="50000"),
            # Type 1 (A) query/response
            self._make_tshark_line_c1(t_epoch=10.00, dns_qname="trial.he.test", dns_qtype="1", dns_id="0x0001", udp_sport="50001", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.025, dns_qname="trial.he.test", dns_qtype="1", dns_resp="1", dns_a="10.0.2.10", dns_id="0x0001", udp_sport="53", udp_dport="50001"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        self.assertEqual(len(dissection["https_svcb_queries"]), 1)
        self.assertEqual(dissection["https_svcb_queries"][0]["qtype"], "HTTPS")
        self.assertAlmostEqual(dissection["dns_metrics"]["dns_latency_a_ms"], 25.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_dns_first_payload_latency_metrics(self, mock_run, mock_which):
        """Extracts dns_query_to_first_payload_ms and dns_last_positive_response_to_first_payload_ms."""
        lines = [
            # DNS query and response
            self._make_tshark_line_c1(t_epoch=10.00, dns_qname="trial.he.test", dns_qtype="1", dns_id="0x0001", udp_sport="50000", udp_dport="53"),
            self._make_tshark_line_c1(t_epoch=10.02, dns_qname="trial.he.test", dns_qtype="1", dns_resp="1", dns_a="10.0.2.10", dns_id="0x0001", udp_sport="53", udp_dport="50000"),
            # TCP Handshake on stream 0
            self._make_tshark_line_c1(t_epoch=10.03, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=40000, dport=80, stream="0", seq_raw=100, ack_raw=0, frame_num=3),
            self._make_tshark_line_c1(t_epoch=10.04, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=40000, stream="0", seq_raw=500, ack_raw=101, frame_num=4),
            self._make_tshark_line_c1(t_epoch=10.045, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=40000, dport=80, stream="0", seq_raw=101, ack_raw=501, frame_num=5),
            # HTTP Request and Response
            self._make_tshark_line_c1(t_epoch=10.05, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=40000, dport=80, stream="0", seq_raw=101, ack_raw=501, frame_num=6, tcp_len=50, http_method="GET", http_uri="/", http_response_in="7"),
            self._make_tshark_line_c1(t_epoch=10.08, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=40000, stream="0", seq_raw=501, ack_raw=151, frame_num=7, tcp_len=200, http_code="200", http_request_in="6"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        metrics = dissection["metrics"]
        self.assertAlmostEqual(metrics["dns_query_to_first_payload_ms"], 80.0, places=2)
        self.assertAlmostEqual(metrics["dns_last_positive_response_to_first_payload_ms"], 60.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_schema_1_1_0_structure_emission(self, mock_run, mock_which):
        """dissect_pcap emits schema 1.1.0 and compact primary_flow evidence object."""
        lines = [
            self._make_tshark_line_c1(
                t_epoch=10.00,
                ip6_src="2001:db8:1::2",
                ip6_dst=run_trial.SERVER_IPV6,
                flags="0x0002",
                sport=50000,
                dport=80,
                stream="0",
                seq_raw=1000,
                ack_raw=0,
                frame_num=1,
            ),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        self.assertEqual(dissection["schema_version"], "1.1.0")
        self.assertIn("primary_flow", dissection)
        self.assertIn("dns_transactions", dissection)
        self.assertIn("https_svcb_queries", dissection)
        self.assertIn("metrics", dissection)


if __name__ == "__main__":
    unittest.main()

