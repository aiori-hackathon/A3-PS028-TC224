"""
PS-028 Tier 5: Adversarial Fault Injection & Robustness Test Suite
Independent Adversarial Challenger Track (Batch C5 Verification)

Evaluates fail-closed semantics, boundary violations, and lifecycle invariants:
1. Adversarial DNS Reload Protocol Fault Injections (Stage 1 to Stage 5):
   - Corrupted PID representations (alphanumeric, binary zeros, negative values, PID 0, PID 1, empty)
   - Missing or non-existent PID files
   - Stale/dead process PIDs
   - Process cmdline authentication mismatches (/proc/{pid}/cmdline)
   - SIGHUP signal delivery failures (process termination, permission denial)
   - Log confirmation failures (server configuration rejections, syntax errors)
   - Stale log offset isolation (preventing false-positive confirmations from earlier reloads)
   - Timeout and missing log file handling
   - Active DNS query delay violations (lower/upper tolerance bounds, error rcodes, IP mismatches, empty answers)
   - Fail-closed exception typing: all errors MUST inherit from DNSReloadError
   - High-level API fail-closed preservation (apply_dns_delays, restore_dns_baseline retaining .impair_bak)

2. Lifecycle & Evidence Bundle Failure Invariant:
   - Mid-run scenario crash: verification that self_test_bundle.json, self_test_summary.csv,
     and self_test_summary.csv.provenance.json are STILL generated with status FAIL and diagnostic errors
   - Immediate scenario crash (S0): verifying graceful bundle writing on step 1 failure
   - Diagnostic lifecycle capture: verifying cleanup and baseline error propagation into metadata

Normative references: Problem Statement PS-028, Amendment A11, Amendment A13, Rule R11
"""

import hashlib
import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.impair as impair
import lab.self_test_scenarios as sts


class TestAdversarialDNSReloadFaultInjections(unittest.TestCase):
    """
    Adversarial stress-testing of the 5-stage DNS reload protocol (`impair.reload_dns_server`).
    Asserts that every fault injection triggers a fail-closed response with a typed exception
    inheriting from DNSReloadError.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_adv_dns_test_"))
        self.pid_file = self.temp_dir / "dns.pid"
        self.log_file = self.temp_dir / "dns.log"
        self.config_file = self.temp_dir / "dns_config.json"

        # Baseline config template from actual project DNS config file
        with open(impair.DNS_CONFIG_FILE, "r", encoding="utf-8") as f:
            self.baseline_config = json.load(f)
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(self.baseline_config, f, indent=2)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _mock_dns_server_proc_cmdline(self):
        """Helper to return a mock open for a valid dns_server.py process cmdline."""
        mock_cmd = MagicMock()
        mock_cmd.__enter__.return_value = mock_cmd
        mock_cmd.read.return_value = b"python3\x00/home/ps028/lab/dns_server.py\x00--config\x00"
        return mock_cmd

    # --------------------------------------------------------------------------
    # 1. PID File Fault Injections (Stage 1 -> DNSPIDError)
    # --------------------------------------------------------------------------

    def test_reload_adversarial_pid_corrupted_alphanumeric(self):
        """Fault: Alphanumeric corrupted string in PID file -> DNSPIDError."""
        for corrupt_val in ["corrupted_pid_123\n", "abc-999", "pid:4567\n", "12a34"]:
            self.pid_file.write_text(corrupt_val, encoding="utf-8")
            with self.assertRaises(impair.DNSPIDError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("Invalid DNS PID", str(ctx.exception))

    def test_reload_adversarial_pid_corrupted_binary_nulls(self):
        """Fault: Binary zeros / null bytes in PID file -> DNSPIDError."""
        bad_payloads = [
            b"\x00\x00\x00\x00",
            b"\x001234\x00",
            b"9876\x00\x00\n",
            b"\xff\xfe\x00\x00"
        ]
        for payload in bad_payloads:
            self.pid_file.write_bytes(payload)
            with self.assertRaises(impair.DNSPIDError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)

    def test_reload_adversarial_pid_illegal_boundary_values(self):
        """Fault: Negative values, 0, or 1 (system init) in PID file -> DNSPIDError."""
        illegal_pids = ["-1", "-9999", "0", "1"]
        for bad_pid in illegal_pids:
            self.pid_file.write_text(f"{bad_pid}\n", encoding="utf-8")
            with self.assertRaises(impair.DNSPIDError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("must be a user process > 1", str(ctx.exception))

    def test_reload_adversarial_pid_floating_point_or_special_strings(self):
        """Fault: Floating point numbers or special tokens in PID file -> DNSPIDError."""
        special_strings = ["1234.56\n", "NaN\n", "Infinity\n", "-inf\n", "1e5\n"]
        for val in special_strings:
            self.pid_file.write_text(val, encoding="utf-8")
            with self.assertRaises(impair.DNSPIDError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)

    def test_reload_adversarial_pid_empty_or_whitespace_file(self):
        """Fault: Empty or whitespace-only PID file -> DNSPIDError."""
        for ws in ["", "   ", "\n", "\t\t\n", "\r\n"]:
            self.pid_file.write_text(ws, encoding="utf-8")
            with self.assertRaises(impair.DNSPIDError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)

    def test_reload_adversarial_pid_missing_or_directory(self):
        """Fault: Missing PID file or PID file is a directory -> DNSPIDError."""
        # Non-existent file
        if self.pid_file.exists():
            self.pid_file.unlink()
        with self.assertRaises(impair.DNSPIDError) as ctx:
            impair.reload_dns_server(
                pid_file=self.pid_file,
                log_file=self.log_file,
                config_file=self.config_file
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("does not exist", str(ctx.exception))

        # PID file is a directory
        self.pid_file.mkdir()
        with self.assertRaises(impair.DNSPIDError) as ctx:
            impair.reload_dns_server(
                pid_file=self.pid_file,
                log_file=self.log_file,
                config_file=self.config_file
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.pid_file.rmdir()

    @patch("os.kill")
    def test_reload_adversarial_pid_dead_process(self, mock_kill):
        """Fault: PID file contains PID of non-existent process -> DNSPIDError."""
        mock_kill.side_effect = ProcessLookupError("No such process")
        self.pid_file.write_text("987654\n", encoding="utf-8")
        with self.assertRaises(impair.DNSPIDError) as ctx:
            impair.reload_dns_server(
                pid_file=self.pid_file,
                log_file=self.log_file,
                config_file=self.config_file
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("not running", str(ctx.exception))

    @patch("os.kill")
    def test_reload_adversarial_pid_cmdline_mismatch_hijack_prevention(self, mock_kill):
        """Fault: PID belongs to an unrelated process (e.g., bash, nginx, python runner) -> DNSPIDError."""
        mock_kill.return_value = None
        self.pid_file.write_text("12345\n", encoding="utf-8")

        unrelated_cmdlines = [
            b"/bin/bash\x00-i\x00",
            b"nginx:\x00worker process\x00",
            b"python3\x00lab/run_trial.py\x00--scenario\x00S0\x00",
            b"/usr/sbin/systemd\x00--user\x00",
            b""
        ]

        for raw_cmd in unrelated_cmdlines:
            mock_cmd = MagicMock()
            mock_cmd.__enter__.return_value = mock_cmd
            mock_cmd.read.return_value = raw_cmd

            real_open = open
            def custom_open(path, *args, **kwargs):
                if str(path).startswith("/proc/"):
                    return mock_cmd
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=custom_open):
                with self.assertRaises(impair.DNSPIDError) as ctx:
                    impair.reload_dns_server(
                        pid_file=self.pid_file,
                        log_file=self.log_file,
                        config_file=self.config_file
                    )
                self.assertIsInstance(ctx.exception, impair.DNSReloadError)
                self.assertIn("does not match dns_server.py", str(ctx.exception))

    @patch("os.kill")
    def test_reload_adversarial_pid_cmdline_permission_denial(self, mock_kill):
        """Fault: Permission denied inspecting /proc/{pid}/cmdline -> DNSPIDError."""
        mock_kill.return_value = None
        self.pid_file.write_text("12345\n", encoding="utf-8")

        real_open = open
        def custom_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                raise PermissionError("EACCES: Access denied to /proc/12345/cmdline")
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            with self.assertRaises(impair.DNSPIDError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("Permission denied", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 2. Signal Delivery Fault Injections (Stage 3 -> DNSSignalError)
    # --------------------------------------------------------------------------

    @patch("os.kill")
    def test_reload_adversarial_signal_process_dies_mid_reload(self, mock_kill):
        """Fault: DNS process is alive in Stage 1 but terminates before Stage 3 SIGHUP -> DNSSignalError."""
        def kill_side_effect(pid, sig):
            if sig == 0:
                return None  # Stage 1 liveness succeeds
            if sig == signal.SIGHUP:
                raise ProcessLookupError("Process disappeared")
            return None

        mock_kill.side_effect = kill_side_effect
        self.pid_file.write_text("12345\n", encoding="utf-8")
        mock_cmd = self._mock_dns_server_proc_cmdline()

        real_open = open
        def custom_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                return mock_cmd
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            with self.assertRaises(impair.DNSSignalError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("died before SIGHUP delivery", str(ctx.exception))

    @patch("os.kill")
    def test_reload_adversarial_signal_permission_denied(self, mock_kill):
        """Fault: PermissionError delivering SIGHUP signal -> DNSSignalError."""
        def kill_side_effect(pid, sig):
            if sig == 0:
                return None
            if sig == signal.SIGHUP:
                raise PermissionError("EPERM: Operation not permitted")
            return None

        mock_kill.side_effect = kill_side_effect
        self.pid_file.write_text("12345\n", encoding="utf-8")
        mock_cmd = self._mock_dns_server_proc_cmdline()

        real_open = open
        def custom_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                return mock_cmd
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            with self.assertRaises(impair.DNSSignalError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("Permission denied sending SIGHUP", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 3. Log Confirmation & Stale Offset Injections (Stage 4 -> DNSConfigurationRejectedError / DNSConfirmationTimeoutError)
    # --------------------------------------------------------------------------

    @patch("os.kill")
    def test_reload_adversarial_log_server_rejects_configuration(self, mock_kill):
        """Fault: DNS Server logs explicit rejection on reload -> DNSConfigurationRejectedError."""
        rejection_messages = [
            "SIGHUP config reload rejected: Schema violation: missing required field 'rules'",
            "SIGHUP config reload rejected: Invalid delay value negative: -50",
            "SIGHUP config reload rejected: rcode must be NOERROR"
        ]

        for msg in rejection_messages:
            mock_kill.return_value = None
            self.pid_file.write_text("12345\n", encoding="utf-8")

            def kill_side_effect(pid, sig):
                if sig == signal.SIGHUP:
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        f.write(f"[2026-11-12T06:30:00.000Z] [ERROR] {msg}\n")
                return None

            mock_kill.side_effect = kill_side_effect
            mock_cmd = self._mock_dns_server_proc_cmdline()

            real_open = open
            def custom_open(path, *args, **kwargs):
                if str(path).startswith("/proc/"):
                    return mock_cmd
                return real_open(path, *args, **kwargs)

            with patch("builtins.open", side_effect=custom_open):
                with self.assertRaises(impair.DNSConfigurationRejectedError) as ctx:
                    impair.reload_dns_server(
                        pid_file=self.pid_file,
                        log_file=self.log_file,
                        config_file=self.config_file,
                        timeout=0.1,
                        verify_active_delays=False
                    )
                self.assertIsInstance(ctx.exception, impair.DNSReloadError)
                self.assertIn("rejected", str(ctx.exception).lower())

    @patch("os.kill")
    def test_reload_adversarial_log_stale_offset_prevents_false_positive(self, mock_kill):
        """
        Adversarial Isolation Test:
        dns.log already contains multiple previous 'SIGHUP config reload applied successfully' lines.
        No new confirmation is written after SIGHUP.
        The reload MUST NOT match the old log entries; it must timeout and raise DNSConfirmationTimeoutError.
        """
        mock_kill.return_value = None
        self.pid_file.write_text("12345\n", encoding="utf-8")

        # Seed pre-existing successful reload lines in log
        stale_content = (
            "[2026-11-12T05:00:00.000Z] [INFO] Server started\n"
            "[2026-11-12T05:10:00.000Z] [INFO] SIGHUP config reload applied successfully: rules={'A': 0}\n"
            "[2026-11-12T05:20:00.000Z] [INFO] SIGHUP config reload applied successfully: rules={'AAAA': 500}\n"
        )
        self.log_file.write_text(stale_content, encoding="utf-8")

        mock_cmd = self._mock_dns_server_proc_cmdline()
        real_open = open
        def custom_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                return mock_cmd
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            with self.assertRaises(impair.DNSConfirmationTimeoutError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file,
                    timeout=0.08,
                    verify_active_delays=False
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("Timed out", str(ctx.exception))

    @patch("os.kill")
    def test_reload_adversarial_log_stale_offset_with_unrelated_log_growth(self, mock_kill):
        """
        Adversarial Isolation Test:
        dns.log contains older reload lines, and during reload, unrelated logs are written (log file grows).
        Because no NEW reload confirmation appears, reload_dns_server must time out.
        """
        self.pid_file.write_text("12345\n", encoding="utf-8")
        self.log_file.write_text("[2026-11-12T05:00:00.000Z] SIGHUP config reload applied successfully: rules={}\n")

        def kill_side_effect(pid, sig):
            if sig == signal.SIGHUP:
                # Append unrelated query traffic logs after offset
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write("[2026-11-12T06:00:00.000Z] [INFO] Handled query for example.com IN A\n")
                    f.write("[2026-11-12T06:00:01.000Z] [INFO] Handled query for example.com IN AAAA\n")
            return None

        mock_kill.side_effect = kill_side_effect
        mock_cmd = self._mock_dns_server_proc_cmdline()

        real_open = open
        def custom_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                return mock_cmd
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            with self.assertRaises(impair.DNSConfirmationTimeoutError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file,
                    timeout=0.08,
                    verify_active_delays=False
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("Timed out", str(ctx.exception))

    @patch("os.kill")
    def test_reload_adversarial_log_missing_file_timeout(self, mock_kill):
        """Fault: dns.log does not exist at all during reload -> times out with DNSConfirmationTimeoutError."""
        mock_kill.return_value = None
        self.pid_file.write_text("12345\n", encoding="utf-8")
        if self.log_file.exists():
            self.log_file.unlink()

        mock_cmd = self._mock_dns_server_proc_cmdline()
        real_open = open
        def custom_open(path, *args, **kwargs):
            if str(path).startswith("/proc/"):
                return mock_cmd
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            with self.assertRaises(impair.DNSConfirmationTimeoutError) as ctx:
                impair.reload_dns_server(
                    pid_file=self.pid_file,
                    log_file=self.log_file,
                    config_file=self.config_file,
                    timeout=0.08,
                    verify_active_delays=False
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("Timed out", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 4. Active Query Delay & Response Fault Injections (Stage 5 -> DNSDelayVerificationError)
    # --------------------------------------------------------------------------

    @patch("dns.query.udp")
    @patch("time.time")
    def test_reload_adversarial_active_delay_too_fast(self, mock_time, mock_query):
        """Fault: Observed delay 450ms is below tolerance floor 475ms (for 500ms ± 25ms) -> DNSDelayVerificationError."""
        mock_time.side_effect = [100.0, 100.450]
        resp = MagicMock()
        import dns.rcode
        resp.rcode.return_value = dns.rcode.NOERROR
        rr = MagicMock()
        rr.address = "2001:db8:2::10"
        resp.answer = [[rr]]
        mock_query.return_value = resp

        with self.assertRaises(impair.DNSDelayVerificationError) as ctx:
            impair.verify_active_dns_delay(
                expected_delay_ms=500,
                qtype="AAAA",
                expected_addr="2001:db8:2::10",
                tolerance_ms=25.0
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("outside expected 500ms ± 25.0ms", str(ctx.exception))

    @patch("dns.query.udp")
    @patch("time.time")
    def test_reload_adversarial_active_delay_too_slow(self, mock_time, mock_query):
        """Fault: Observed delay 550ms exceeds tolerance ceiling 525ms (for 500ms ± 25ms) -> DNSDelayVerificationError."""
        mock_time.side_effect = [100.0, 100.550]
        resp = MagicMock()
        import dns.rcode
        resp.rcode.return_value = dns.rcode.NOERROR
        rr = MagicMock()
        rr.address = "2001:db8:2::10"
        resp.answer = [[rr]]
        mock_query.return_value = resp

        with self.assertRaises(impair.DNSDelayVerificationError) as ctx:
            impair.verify_active_dns_delay(
                expected_delay_ms=500,
                qtype="AAAA",
                expected_addr="2001:db8:2::10",
                tolerance_ms=25.0
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("outside expected 500ms ± 25.0ms", str(ctx.exception))

    @patch("dns.query.udp")
    @patch("time.time")
    def test_reload_adversarial_active_delay_error_rcodes(self, mock_time, mock_query):
        """Fault: DNS response returns error rcode (SERVFAIL, REFUSED, NXDOMAIN) -> DNSDelayVerificationError."""
        import dns.rcode
        for bad_code in [dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.NXDOMAIN]:
            mock_time.side_effect = [100.0, 100.010]
            resp = MagicMock()
            resp.rcode.return_value = bad_code
            mock_query.return_value = resp

            with self.assertRaises(impair.DNSDelayVerificationError) as ctx:
                impair.verify_active_dns_delay(
                    expected_delay_ms=0,
                    qtype="A",
                    expected_addr="10.0.2.10",
                    tolerance_ms=25.0
                )
            self.assertIsInstance(ctx.exception, impair.DNSReloadError)
            self.assertIn("error rcode", str(ctx.exception))

    @patch("dns.query.udp")
    @patch("time.time")
    def test_reload_adversarial_active_delay_address_mismatch(self, mock_time, mock_query):
        """Fault: DNS response contains wrong IP address in answer section -> DNSDelayVerificationError."""
        mock_time.side_effect = [100.0, 100.010]
        resp = MagicMock()
        import dns.rcode
        resp.rcode.return_value = dns.rcode.NOERROR
        rr = MagicMock()
        rr.address = "192.0.2.99"  # Mismatch against expected 10.0.2.10
        resp.answer = [[rr]]
        mock_query.return_value = resp

        with self.assertRaises(impair.DNSDelayVerificationError) as ctx:
            impair.verify_active_dns_delay(
                expected_delay_ms=0,
                qtype="A",
                expected_addr="10.0.2.10",
                tolerance_ms=25.0
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("did not return expected address", str(ctx.exception))

    @patch("dns.query.udp")
    @patch("time.time")
    def test_reload_adversarial_active_delay_empty_answers(self, mock_time, mock_query):
        """Fault: DNS response returns NOERROR but empty answer section -> DNSDelayVerificationError."""
        mock_time.side_effect = [100.0, 100.010]
        resp = MagicMock()
        import dns.rcode
        resp.rcode.return_value = dns.rcode.NOERROR
        resp.answer = []
        mock_query.return_value = resp

        with self.assertRaises(impair.DNSDelayVerificationError) as ctx:
            impair.verify_active_dns_delay(
                expected_delay_ms=0,
                qtype="A",
                expected_addr="10.0.2.10",
                tolerance_ms=25.0
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("did not return expected address", str(ctx.exception))

    @patch("dns.query.udp")
    def test_reload_adversarial_active_delay_network_socket_exception(self, mock_query):
        """Fault: Network timeout or socket exception during active query -> DNSDelayVerificationError."""
        import dns.exception
        mock_query.side_effect = dns.exception.Timeout("Query timed out")

        with self.assertRaises(impair.DNSDelayVerificationError) as ctx:
            impair.verify_active_dns_delay(
                expected_delay_ms=0,
                qtype="A",
                expected_addr="10.0.2.10",
                tolerance_ms=25.0
            )
        self.assertIsInstance(ctx.exception, impair.DNSReloadError)
        self.assertIn("Active DNS query failed", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 5. High-Level Fail-Closed Invariants (apply_dns_delays / restore_dns_baseline)
    # --------------------------------------------------------------------------

    @patch("lab.impair.reload_dns_server")
    def test_apply_dns_delays_fail_closed_propagation(self, mock_reload):
        """Verification that apply_dns_delays propagates any DNSReloadError and fails closed."""
        mock_reload.side_effect = impair.DNSConfigurationRejectedError("Config rejected by server")

        with patch.object(impair, "DNS_CONFIG_FILE", self.config_file), \
             patch.object(impair, "DNS_BACKUP_A4", self.temp_dir / "a4.bak"), \
             patch.object(impair, "DNS_BACKUP_A3", self.temp_dir / "a3.bak"), \
             patch("lab.impair.is_root", return_value=True):
            with self.assertRaises(impair.DNSReloadError) as ctx:
                impair.apply_dns_delays(a_delay_ms=0, aaaa_delay_ms=500, dry_run=False)
            self.assertIsInstance(ctx.exception, impair.DNSConfigurationRejectedError)

    @patch("lab.impair.reload_dns_server")
    def test_restore_dns_baseline_retains_backup_on_reload_failure(self, mock_reload):
        """Verification that restore_dns_baseline retains .impair_bak when reload fails closed."""
        mock_reload.side_effect = impair.DNSConfirmationTimeoutError("Timeout confirming baseline")
        bak_file = self.temp_dir / "dns_backup_a4.json"
        bak_file.write_text(json.dumps(self.baseline_config), encoding="utf-8")

        with patch.object(impair, "DNS_CONFIG_FILE", self.config_file), \
             patch.object(impair, "DNS_BACKUP_A4", bak_file), \
             patch.object(impair, "DNS_BACKUP_A3", self.temp_dir / "a3.bak"), \
             patch("lab.impair.is_root", return_value=True):
            with self.assertRaises(impair.DNSReloadError) as ctx:
                impair.restore_dns_baseline(
                    dry_run=False,
                    config_file=self.config_file,
                    backup_file_a4=bak_file,
                    lock_file=self.temp_dir / ".dns.lock"
                )
            self.assertIsInstance(ctx.exception, impair.DNSConfirmationTimeoutError)
            self.assertTrue(bak_file.exists(), "Backup file MUST be retained when reload fails")


class TestAdversarialEvidenceBundleLifecycle(unittest.TestCase):
    """
    Adversarial verification of the machine-readable evidence bundle lifecycle
    under mid-run and immediate scenario failures.
    Asserts that `self_test_bundle.json` and `self_test_summary.csv` are ALWAYS written
    with status: FAIL, exact error details, and Amendment A13 compliance.
    """

    def setUp(self):
        self.evidence_dir = Path(tempfile.mkdtemp(prefix="ps028_adv_bundle_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.evidence_dir, ignore_errors=True)

    def test_evidence_bundle_failure_invariant_mid_run_crash(self):
        """
        Adversarial Stress Test:
        Scenarios S0 and S1 execute and succeed.
        Scenario S2 crashes with an unhandled ImpairmentError.
        Verify:
        1. run_all_self_tests_with_bundle re-raises the failure exception (fail-closed)
        2. self_test_bundle.json is written with overall_status='FAIL'
        3. Bundle contains S0 (PASS), S1 (PASS), and S2 (FAIL with error message)
        4. self_test_summary.csv is written with 3 data rows (S0, S1, S2)
        5. S2 CSV row contains 'FAIL' and diagnostic error text
        6. CSV contains ZERO timestamp strings (Amendment A13)
        7. Sibling self_test_summary.csv.provenance.json is written with matching SHA-256 and row count
        """
        def mock_scenario_runner(scenario_id, **kwargs):
            if scenario_id == "S0":
                return {
                    "scenario": "S0",
                    "post_baseline_verified": True,
                    "details": {"key_metric_name": "ipv4_rtt_ms", "key_metric_value": 20.1}
                }
            elif scenario_id == "S1":
                return {
                    "scenario": "S1",
                    "post_baseline_verified": True,
                    "details": {"key_metric_name": "ipv6_tcp_outcome", "key_metric_value": "timeout"}
                }
            elif scenario_id == "S2":
                raise impair.ImpairmentError("Adversarial kernel nftables reject injection failure in S2")
            else:
                raise RuntimeError(f"Unexpected scenario {scenario_id}")

        with patch("lab.self_test_scenarios.run_scenario_self_test", side_effect=mock_scenario_runner):
            with self.assertRaises(impair.ImpairmentError) as ctx:
                sts.run_all_self_tests_with_bundle(
                    scenarios=["S0", "S1", "S2", "S3", "S4"],
                    dry_run=True,
                    output_dir=self.evidence_dir
                )
            self.assertIn("Adversarial kernel nftables reject injection failure in S2", str(ctx.exception))

        # Check artifact files exist
        bundle_json_file = self.evidence_dir / "self_test_bundle.json"
        summary_csv_file = self.evidence_dir / "self_test_summary.csv"
        provenance_json_file = self.evidence_dir / "self_test_summary.csv.provenance.json"

        self.assertTrue(bundle_json_file.is_file(), "self_test_bundle.json MUST exist on failure")
        self.assertTrue(summary_csv_file.is_file(), "self_test_summary.csv MUST exist on failure")
        self.assertTrue(provenance_json_file.is_file(), "provenance sidecar MUST exist on failure")

        # 1. Inspect self_test_bundle.json
        with open(bundle_json_file, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)

        self.assertEqual(bundle_data.get("overall_status"), "FAIL")
        self.assertEqual(bundle_data.get("execution_mode"), "SIMULATION")
        scenarios = bundle_data.get("scenarios", [])
        self.assertEqual(len(scenarios), 3, "Exactly 3 scenarios attempted before termination")

        self.assertEqual(scenarios[0]["scenario_id"], "S0")
        self.assertEqual(scenarios[0]["status"], "PASS")

        self.assertEqual(scenarios[1]["scenario_id"], "S1")
        self.assertEqual(scenarios[1]["status"], "PASS")

        self.assertEqual(scenarios[2]["scenario_id"], "S2")
        self.assertEqual(scenarios[2]["status"], "FAIL")
        self.assertIn("Adversarial kernel nftables reject injection failure in S2", scenarios[2]["error"])

        # 2. Inspect self_test_summary.csv
        csv_lines = summary_csv_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(csv_lines), 4, "CSV should have 1 header row + 3 scenario rows")
        header = csv_lines[0].split(",")
        self.assertIn("scenario_id", header)
        self.assertIn("status", header)
        self.assertIn("error", header)

        # Ensure no generation timestamps exist in CSV rows (Amendment A13)
        for line in csv_lines:
            self.assertNotIn("2026-", line, "CSV data MUST NOT contain ISO timestamps (Amendment A13)")
            self.assertNotIn("T0", line, "CSV data MUST NOT contain ISO timestamps")

        s2_row = csv_lines[3]
        self.assertTrue(s2_row.startswith("S2,SIMULATION,FAIL,"))
        self.assertIn("Adversarial kernel nftables reject injection failure in S2", s2_row)

        # 3. Inspect provenance sidecar
        with open(provenance_json_file, "r", encoding="utf-8") as f:
            prov_data = json.load(f)

        self.assertEqual(prov_data.get("row_count"), 3)
        self.assertEqual(prov_data.get("execution_mode"), "SIMULATION")
        computed_sha256 = hashlib.sha256(summary_csv_file.read_bytes()).hexdigest()
        self.assertEqual(prov_data.get("sha256"), computed_sha256)

    def test_evidence_bundle_failure_invariant_first_scenario_crash(self):
        """
        Adversarial Stress Test:
        Scenario S0 crashes immediately on the first attempt with RuntimeError.
        Verify that evidence bundle and CSV are still written with 1 failed scenario.
        """
        with patch("lab.self_test_scenarios.run_scenario_self_test") as mock_run:
            mock_run.side_effect = RuntimeError("Catastrophic initial environment crash in S0")

            with self.assertRaises(RuntimeError) as ctx:
                sts.run_all_self_tests_with_bundle(
                    scenarios=["S0", "S1"],
                    dry_run=True,
                    output_dir=self.evidence_dir
                )
            self.assertIn("Catastrophic initial environment crash in S0", str(ctx.exception))

        bundle_json_file = self.evidence_dir / "self_test_bundle.json"
        summary_csv_file = self.evidence_dir / "self_test_summary.csv"
        provenance_json_file = self.evidence_dir / "self_test_summary.csv.provenance.json"

        self.assertTrue(bundle_json_file.is_file())
        self.assertTrue(summary_csv_file.is_file())
        self.assertTrue(provenance_json_file.is_file())

        with open(bundle_json_file, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)

        self.assertEqual(bundle_data["overall_status"], "FAIL")
        self.assertEqual(len(bundle_data["scenarios"]), 1)
        self.assertEqual(bundle_data["scenarios"][0]["status"], "FAIL")
        self.assertIn("Catastrophic initial environment crash in S0", bundle_data["scenarios"][0]["error"])

    def test_evidence_bundle_custom_lifecycle_exception_diagnostics(self):
        """
        Adversarial Stress Test:
        Scenario fails with custom cleanup and baseline diagnostic errors attached to exception.
        Verify that bundle lifecycle_guarantees captures these specific error strings.
        """
        class CustomImpairmentFailure(impair.ImpairmentError):
            def __init__(self, msg, cleanup_err, baseline_err):
                super().__init__(msg)
                self.cleanup_error = cleanup_err
                self.baseline_error = baseline_err

        with patch("lab.self_test_scenarios.run_scenario_self_test") as mock_run:
            mock_run.side_effect = CustomImpairmentFailure(
                "Primary scenario failure",
                cleanup_err="Cleanup tc netem qdisc delete failed: device busy",
                baseline_err="Baseline DNS AAAA delay 500ms leaked into post-check"
            )

            with self.assertRaises(CustomImpairmentFailure):
                sts.run_all_self_tests_with_bundle(
                    scenarios=["S0"],
                    dry_run=True,
                    output_dir=self.evidence_dir
                )

        bundle_json_file = self.evidence_dir / "self_test_bundle.json"
        with open(bundle_json_file, "r", encoding="utf-8") as f:
            bundle_data = json.load(f)

        lg = bundle_data.get("lifecycle_guarantees", {})
        self.assertEqual(lg.get("cleanups_attempted"), 1)
        self.assertEqual(lg.get("cleanups_succeeded"), 0)
        self.assertIn("Cleanup tc netem qdisc delete failed: device busy", lg.get("cleanup_exceptions", []))
        self.assertEqual(lg.get("baseline_failures"), 1)
        self.assertIn("Baseline DNS AAAA delay 500ms leaked into post-check", lg.get("baseline_exceptions", []))


if __name__ == "__main__":
    unittest.main()
