#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Automated Tests for Impairment Controller
Work Package A4: Test Suite for lab/impair.py and lab/scenarios.yaml

Executes comprehensive unprivileged unit tests:
- Scenarios YAML structure, types, delays, and exact rule schemas (S0 - S6)
- Project-owned nftables rule generation and anti-flush safety
- tc netem qdisc command generation and baseline delay preservation
- DNS lock coordination, atomic config updates, and A3 backup safety
- Controller lifecycle (apply, clear, rollback, state tracking, self-test)
- CLI argument parsing and dry-run execution
"""

import fcntl
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

import lab.impair as impair

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SCENARIOS_YAML = SCRIPT_DIR / "scenarios.yaml"


class TestScenariosYAML(unittest.TestCase):
    """Validate scenarios.yaml syntax, completeness, and Study Guide specifications."""

    def setUp(self):
        self.assertTrue(SCENARIOS_YAML.is_file(), "scenarios.yaml must exist in lab directory")
        with open(SCENARIOS_YAML, "r", encoding="utf-8") as f:
            self.data = yaml.safe_load(f)

    def test_root_structure(self):
        """Configuration must define lab topology metadata and all 7 scenarios."""
        self.assertIn("version", self.data)
        self.assertIn("lab", self.data)
        self.assertIn("scenarios", self.data)

        lab_cfg = self.data["lab"]
        self.assertEqual(lab_cfg["namespaces"]["router"], "ps028-rt")
        self.assertEqual(lab_cfg["namespaces"]["client"], "ps028-cl")
        self.assertEqual(lab_cfg["namespaces"]["server"], "ps028-sv")
        self.assertEqual(lab_cfg["nftables"]["table"], "ps028_impair")
        self.assertEqual(lab_cfg["nftables"]["family"], "inet")

    def test_all_seven_scenarios_exist(self):
        """All seven Study Guide scenarios S0 through S6 must be defined."""
        scenarios = self.data["scenarios"]
        expected = {"S0", "S1", "S2", "S3", "S4", "S5", "S6"}
        self.assertEqual(set(scenarios.keys()), expected)

    def test_s0_healthy_baseline(self):
        """S0 must represent healthy baseline: ~20ms RTT, 0ms DNS delays, no nft rules."""
        s0 = self.data["scenarios"]["S0"]
        self.assertEqual(s0["name"], "healthy_baseline")
        self.assertEqual(s0["type"], "baseline")
        self.assertEqual(s0["dns"]["A_delay_ms"], 0)
        self.assertEqual(s0["dns"]["AAAA_delay_ms"], 0)
        self.assertEqual(s0["nftables"], [])

        delays = s0["network"]["delays"]
        for iface in ("ps028-rt-sv4", "ps028-sv-rt4", "ps028-rt-sv6", "ps028-sv-rt6"):
            self.assertEqual(delays[iface], "10ms")

    def test_s1_ipv6_syn_blackhole(self):
        """S1 must silently drop IPv6 TCP SYN packets client-to-server."""
        s1 = self.data["scenarios"]["S1"]
        self.assertEqual(s1["name"], "ipv6_syn_blackhole")
        self.assertEqual(s1["type"], "nftables")
        self.assertEqual(len(s1["nftables"]), 1)
        rule = s1["nftables"][0]
        self.assertIn("tcp flags syn / syn,ack drop", rule)
        self.assertIn("oifname \"ps028-rt-sv6\"", rule)
        self.assertIn("2001:db8:2::10", rule)

    def test_s2_ipv6_tcp_rst(self):
        """S2 must actively reject IPv6 TCP SYN packets with TCP RST."""
        s2 = self.data["scenarios"]["S2"]
        self.assertEqual(s2["name"], "ipv6_tcp_rst")
        self.assertEqual(s2["type"], "nftables")
        self.assertEqual(len(s2["nftables"]), 1)
        rule = s2["nftables"][0]
        self.assertIn("tcp flags syn / syn,ack reject with tcp reset", rule)
        self.assertIn("oifname \"ps028-rt-sv6\"", rule)
        self.assertIn("2001:db8:2::10", rule)

    def test_s3_ipv6_rtt_150ms(self):
        """S3 must specify 150ms total IPv6 RTT (75ms symmetric delay on each end)."""
        s3 = self.data["scenarios"]["S3"]
        self.assertEqual(s3["name"], "ipv6_rtt_150ms")
        self.assertEqual(s3["type"], "netem")
        self.assertEqual(s3["network"]["ipv6_rtt_ms"], 150)
        delays = s3["network"]["delays"]
        self.assertEqual(delays["ps028-rt-sv6"], "75ms")
        self.assertEqual(delays["ps028-sv-rt6"], "75ms")
        self.assertEqual(delays["ps028-rt-sv4"], "10ms")
        self.assertEqual(delays["ps028-sv-rt4"], "10ms")

    def test_s4_ipv6_rtt_600ms(self):
        """S4 must specify 600ms total IPv6 RTT (300ms symmetric delay on each end)."""
        s4 = self.data["scenarios"]["S4"]
        self.assertEqual(s4["name"], "ipv6_rtt_600ms")
        self.assertEqual(s4["type"], "netem")
        self.assertEqual(s4["network"]["ipv6_rtt_ms"], 600)
        delays = s4["network"]["delays"]
        self.assertEqual(delays["ps028-rt-sv6"], "300ms")
        self.assertEqual(delays["ps028-sv-rt6"], "300ms")
        self.assertEqual(delays["ps028-rt-sv4"], "10ms")
        self.assertEqual(delays["ps028-sv-rt4"], "10ms")

    def test_s5_ipv6_syn_loss_50pct(self):
        """S5 must drop ~50% IPv6 TCP SYN packets in client-to-server direction only."""
        s5 = self.data["scenarios"]["S5"]
        self.assertEqual(s5["name"], "ipv6_syn_loss_50pct")
        self.assertEqual(s5["type"], "nftables")
        self.assertEqual(len(s5["nftables"]), 1)
        rule = s5["nftables"][0]
        self.assertIn("oifname \"ps028-rt-sv6\"", rule)
        self.assertIn("tcp flags syn / syn,ack", rule)
        self.assertIn("numgen random mod 100 < 50 drop", rule)

    def test_s6_delay_aaaa_500ms(self):
        """S6 must delay AAAA responses by 500ms while A remains immediate (0ms)."""
        s6 = self.data["scenarios"]["S6"]
        self.assertEqual(s6["name"], "delay_aaaa_500ms")
        self.assertEqual(s6["type"], "dns")
        self.assertEqual(s6["dns"]["A_delay_ms"], 0)
        self.assertEqual(s6["dns"]["AAAA_delay_ms"], 500)


class TestNFTablesManagement(unittest.TestCase):
    """Test nftables script generation and anti-flush safety guarantees."""

    @patch("lab.impair.execute_netns_cmd")
    def test_apply_nftables_rules_generation(self, mock_cmd):
        mock_cmd.return_value = (0, "", "")
        rules = ['oifname "ps028-rt-sv6" ip6 daddr 2001:db8:2::10 tcp flags syn / syn,ack drop']

        with patch("lab.impair.is_root", return_value=True):
            impair.apply_nftables_rules(rules, dry_run=False)

        # Ensure delete table was called first, then add table script
        self.assertEqual(mock_cmd.call_count, 2)
        first_call = mock_cmd.call_args_list[0]
        second_call = mock_cmd.call_args_list[1]

        self.assertEqual(first_call[0][0], "ps028-rt")
        self.assertEqual(first_call[0][1], ["nft", "delete", "table", "inet", "ps028_impair"])

        self.assertEqual(second_call[0][0], "ps028-rt")
        self.assertEqual(second_call[0][1], ["nft", "-f", "-"])
        script_sent = second_call[1]["stdin_data"]

        # Check script structure
        self.assertIn("add table inet ps028_impair", script_sent)
        self.assertIn("add chain inet ps028_impair forward { type filter hook forward priority 0; policy accept; }", script_sent)
        self.assertIn(rules[0], script_sent)

        # STRICT SAFETY: Ensure 'flush ruleset' is NEVER sent
        self.assertNotIn("flush ruleset", script_sent)
        self.assertNotIn("flush table", script_sent)

    @patch("lab.impair.execute_netns_cmd")
    def test_clear_nftables_only_deletes_project_table(self, mock_cmd):
        mock_cmd.return_value = (0, "", "")
        with patch("lab.impair.is_root", return_value=True):
            impair.clear_nftables_rules(dry_run=False)

        mock_cmd.assert_called_once_with(
            "ps028-rt",
            ["nft", "delete", "table", "inet", "ps028_impair"],
            dry_run=False,
            check=False
        )


class TestNetemManagement(unittest.TestCase):
    """Test tc netem command generation and baseline delay preservation."""

    @patch("lab.impair.execute_netns_cmd")
    def test_apply_netem_delays(self, mock_cmd):
        mock_cmd.return_value = (0, "", "")
        delays = {
            "ps028-rt-sv4": "10ms",
            "ps028-sv-rt4": "10ms",
            "ps028-rt-sv6": "75ms",
            "ps028-sv-rt6": "75ms",
        }

        with patch("lab.impair.is_root", return_value=True):
            impair.apply_netem_delays(delays, dry_run=False)

        self.assertEqual(mock_cmd.call_count, 4)
        calls = {call[0][1][4]: (call[0][0], call[0][1][8]) for call in mock_cmd.call_args_list}
        self.assertEqual(calls["ps028-rt-sv4"], ("ps028-rt", "10ms"))
        self.assertEqual(calls["ps028-sv-rt4"], ("ps028-sv", "10ms"))
        self.assertEqual(calls["ps028-rt-sv6"], ("ps028-rt", "75ms"))
        self.assertEqual(calls["ps028-sv-rt6"], ("ps028-sv", "75ms"))

        # STRICT SAFETY: Verify 'replace' is used, never 'del'
        for call in mock_cmd.call_args_list:
            cmd = call[0][1]
            self.assertEqual(cmd[2], "replace")
            self.assertNotIn("del", cmd)

    @patch("lab.impair.execute_netns_cmd")
    def test_restore_baseline_delays(self, mock_cmd):
        mock_cmd.return_value = (0, "", "")
        with patch("lab.impair.is_root", return_value=True):
            impair.restore_baseline_delays(dry_run=False)

        self.assertEqual(mock_cmd.call_count, 4)
        for call in mock_cmd.call_args_list:
            cmd = call[0][1]
            self.assertEqual(cmd[8], "10ms")


class TestDNSCoordinationAndSafety(unittest.TestCase):
    """Test .verify_dns.lock coordination, safe backups, and A3 non-interference."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ps028_dns_test_")
        self.test_dir = Path(self.temp_dir)

        self.lock_file = self.test_dir / ".verify_dns.lock"
        self.dns_config = self.test_dir / "dns_config.json"
        self.dns_bak_a3 = self.test_dir / "dns_config.json.bak"
        self.dns_bak_a4 = self.test_dir / "dns_config.json.impair_bak"
        self.dns_pid = self.test_dir / "dns.pid"

        self.baseline_content = {
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
        }
        with open(self.dns_config, "w", encoding="utf-8") as f:
            json.dump(self.baseline_content, f, indent=2)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_lock_acquisition_success(self):
        """Uncontended lock must be acquired and released cleanly."""
        with impair.acquire_dns_lock(timeout=1.0, lock_path=self.lock_file):
            self.assertTrue(self.lock_file.exists())

    def test_lock_contention_failure_without_bypass(self):
        """When lock is held by another process, acquisition must fail without bypassing."""
        # Hold lock exclusively in external fd
        fd = os.open(str(self.lock_file), os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

        try:
            with self.assertRaises(impair.LockAcquisitionError):
                with impair.acquire_dns_lock(timeout=0.2, lock_path=self.lock_file):
                    pass
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_refuse_if_a3_backup_exists(self):
        """Applying S6 DNS delays must refuse to run if A3's dns_config.json.bak exists."""
        self.dns_bak_a3.write_text("dummy A3 backup content", encoding="utf-8")

        with patch("lab.impair.is_root", return_value=True):
            with self.assertRaises(impair.ImpairmentError) as ctx:
                impair.apply_dns_delays(
                    a_delay_ms=0,
                    aaaa_delay_ms=500,
                    dry_run=False,
                    config_file=self.dns_config,
                    backup_file_a3=self.dns_bak_a3,
                    backup_file_a4=self.dns_bak_a4,
                    lock_file=self.lock_file
                )

            self.assertIn("Existing A3 backup detected", str(ctx.exception))
            # Verify A3 backup was NOT overwritten
            self.assertEqual(self.dns_bak_a3.read_text(encoding="utf-8"), "dummy A3 backup content")

    def test_s6_backup_creation_and_restoration(self):
        """Applying S6 must preserve clean baseline in impair_bak and restore cleanly."""
        with patch("lab.impair.is_root", return_value=True), \
             patch("lab.impair.reload_dns_server") as mock_reload:

            # 1. Apply S6 delays (0ms A, 500ms AAAA)
            impair.apply_dns_delays(
                a_delay_ms=0,
                aaaa_delay_ms=500,
                dry_run=False,
                config_file=self.dns_config,
                backup_file_a3=self.dns_bak_a3,
                backup_file_a4=self.dns_bak_a4,
                lock_file=self.lock_file
            )

            # A4 backup must exist
            self.assertTrue(self.dns_bak_a4.exists())
            with open(self.dns_bak_a4, "r", encoding="utf-8") as f:
                bak_data = json.load(f)
            self.assertEqual(bak_data["rules"]["AAAA"]["delay_ms"], 0)

            # Active config must be updated
            with open(self.dns_config, "r", encoding="utf-8") as f:
                curr_data = json.load(f)
            self.assertEqual(curr_data["rules"]["AAAA"]["delay_ms"], 500)
            self.assertEqual(curr_data["rules"]["A"]["delay_ms"], 0)
            mock_reload.assert_called_once()

            # 2. Restore baseline
            mock_reload.reset_mock()
            impair.restore_dns_baseline(
                dry_run=False,
                config_file=self.dns_config,
                backup_file_a4=self.dns_bak_a4,
                lock_file=self.lock_file
            )

            # Active config must be back to 0ms
            with open(self.dns_config, "r", encoding="utf-8") as f:
                restored_data = json.load(f)
            self.assertEqual(restored_data["rules"]["AAAA"]["delay_ms"], 0)
            self.assertEqual(restored_data["rules"]["A"]["delay_ms"], 0)

            # A4 backup must be removed
            self.assertFalse(self.dns_bak_a4.exists())
            mock_reload.assert_called_once()


class TestControllerLifecycle(unittest.TestCase):
    """Test full controller lifecycle: apply, clear, state recording, rollback."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ps028_ctrl_test_")
        self.state_file = Path(self.temp_dir) / ".impair_state.json"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.impair.apply_netem_delays")
    @patch("lab.impair.apply_nftables_rules")
    @patch("lab.impair.clear_nftables_rules")
    @patch("lab.impair.restore_baseline_delays")
    @patch("lab.impair.restore_dns_baseline")
    def test_apply_s1_and_clear(
        self, mock_dns_res, mock_del_res, mock_nft_clr, mock_nft_app, mock_netem_app
    ):
        with patch.object(impair, "STATE_FILE", self.state_file), \
             patch("lab.impair.is_root", return_value=True):

            # Apply S1
            impair.apply_scenario("S1", scenarios_path=SCENARIOS_YAML, dry_run=False)

            # Verify nftables rule applied
            mock_nft_app.assert_called_once()
            rule_arg = mock_nft_app.call_args[0][0][0]
            self.assertIn("tcp flags syn / syn,ack drop", rule_arg)

            # Verify state recorded
            self.assertTrue(self.state_file.exists())
            with open(self.state_file, "r") as f:
                st = json.load(f)
            self.assertEqual(st["active_scenario"], "S1")

            # Clear
            impair.clear_impairments(dry_run=False)
            mock_nft_clr.assert_called()
            mock_del_res.assert_called()
            mock_dns_res.assert_called()
            self.assertFalse(self.state_file.exists())

    @patch("lab.impair.apply_netem_delays")
    @patch("lab.impair.apply_nftables_rules")
    @patch("lab.impair.clear_nftables_rules")
    @patch("lab.impair.restore_baseline_delays")
    @patch("lab.impair.restore_dns_baseline")
    def test_apply_failure_triggers_automatic_rollback(
        self, mock_dns_res, mock_del_res, mock_nft_clr, mock_nft_app, mock_netem_app
    ):
        mock_nft_app.side_effect = RuntimeError("Simulated nftables kernel failure")

        with patch.object(impair, "STATE_FILE", self.state_file), \
             patch("lab.impair.is_root", return_value=True):

            with self.assertRaises(RuntimeError):
                impair.apply_scenario("S1", scenarios_path=SCENARIOS_YAML, dry_run=False)

            # Clear impairments must have been called during rollback
            self.assertTrue(mock_del_res.called)
            self.assertTrue(mock_nft_clr.called)
            self.assertFalse(self.state_file.exists())


class TestSelfTestBaseline(unittest.TestCase):
    """Test self-test-baseline validation logic."""

    def test_self_test_baseline_unprivileged(self):
        """Unprivileged self-test-baseline validates files and reports status."""
        result = impair.self_test_baseline(dry_run=True)
        self.assertTrue(result)


class TestCLIOptions(unittest.TestCase):
    """Test CLI argument parsing and dry-run execution."""

    def test_parser_subcommands(self):
        parser = impair.build_parser()

        args1 = parser.parse_args(["apply", "S3"])
        self.assertEqual(args1.command, "apply")
        self.assertEqual(args1.scenario, "S3")

        args2 = parser.parse_args(["clear"])
        self.assertEqual(args2.command, "clear")

        args3 = parser.parse_args(["self-test-baseline"])
        self.assertEqual(args3.command, "self-test-baseline")

        args4 = parser.parse_args(["status"])
        self.assertEqual(args4.command, "status")

        args5 = parser.parse_args(["list"])
        self.assertEqual(args5.command, "list")

        args6 = parser.parse_args(["test-scenarios", "--scenario", "S1", "--dry-run"])
        self.assertEqual(args6.command, "test-scenarios")
        self.assertEqual(args6.scenario, "S1")
        self.assertTrue(args6.dry_run)

        args7 = parser.parse_args(["self-test-scenarios", "--scenarios", "S0,S2", "--json"])
        self.assertEqual(args7.command, "self-test-scenarios")
        self.assertEqual(args7.scenarios, "S0,S2")
        self.assertTrue(args7.json)

    def test_dry_run_flag_positions(self):
        parser = impair.build_parser()

        # Flag after subcommand
        args_after = parser.parse_args(["apply", "S2", "--dry-run"])
        self.assertTrue(args_after.dry_run)

        # Flag before subcommand
        args_before = parser.parse_args(["--dry-run", "apply", "S2"])
        self.assertTrue(args_before.dry_run)


if __name__ == "__main__":
    unittest.main()
