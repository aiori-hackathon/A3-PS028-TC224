#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Automated Unit Tests for Scenario Self-Test Harness
Work Package A5: Automated Test Suite for lab/self_test_scenarios.py and lab/impair.py

Executes comprehensive unprivileged unit tests:
  - S0-S6 verifier behavior (success, failure, bounds checks, schema)
  - Strict lifecycle guarantees: apply -> verify -> clear -> self-test-baseline
  - Fault tolerance: cleanup and baseline verification are guaranteed even on test failures
  - Network measurement parser accuracy (ping RTT, dig DNS timing, curl HTTP, TCP probe, SYN loss)
  - CLI argument parsing for test-scenarios and self-test-scenarios in both modules
  - Unprivileged dry-run execution
"""

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, call, patch

import lab.impair as impair
import lab.self_test_scenarios as sts

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


class TestNetworkProbeParsing(unittest.TestCase):
    """Test stdout/stderr parsing and calculation in network measurement probes."""

    @patch("lab.impair.execute_netns_cmd")
    def test_measure_ping_rtt_parsing_success(self, mock_cmd):
        ping_stdout = (
            "PING 10.0.2.10 (10.0.2.10) 56(84) bytes of data.\n"
            "64 bytes from 10.0.2.10: icmp_seq=1 ttl=63 time=20.1 ms\n"
            "64 bytes from 10.0.2.10: icmp_seq=2 ttl=63 time=20.3 ms\n"
            "\n"
            "--- 10.0.2.10 ping statistics ---\n"
            "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n"
            "rtt min/avg/max/mdev = 19.821/20.200/20.579/0.379 ms\n"
        )
        mock_cmd.return_value = (0, ping_stdout, "")

        rtt = sts.measure_ping_rtt("10.0.2.10", is_ipv6=False, dry_run=False)
        self.assertAlmostEqual(rtt, 20.200, places=3)
        mock_cmd.assert_called_once()
        cmd_sent = mock_cmd.call_args[0][1]
        self.assertEqual(cmd_sent[0], "ping")
        self.assertNotIn("-6", cmd_sent)

    @patch("lab.impair.execute_netns_cmd")
    def test_measure_ping_rtt_ipv6_flag(self, mock_cmd):
        ping_stdout = "rtt min/avg/max/mdev = 149.8/150.2/150.6/0.4 ms\n"
        mock_cmd.return_value = (0, ping_stdout, "")

        rtt = sts.measure_ping_rtt("2001:db8:2::10", is_ipv6=True, dry_run=False)
        self.assertAlmostEqual(rtt, 150.2, places=1)
        cmd_sent = mock_cmd.call_args[0][1]
        self.assertIn("-6", cmd_sent)

    @patch("lab.impair.execute_netns_cmd")
    def test_measure_ping_rtt_realistic_ipv6_s3_output(self, mock_cmd):
        """Regression test: verify parsing of realistic Linux iputils ping output for S3 (150ms target)."""
        ping_stdout = (
            "PING 2001:db8:2::10(2001:db8:2::10) 56 data bytes\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=1 ttl=64 time=150 ms\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=2 ttl=64 time=150 ms\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=3 ttl=64 time=150 ms\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=4 ttl=64 time=150 ms\n"
            "\n"
            "--- 2001:db8:2::10 ping statistics ---\n"
            "4 packets transmitted, 4 received, 0% packet loss, time 601ms\n"
            "rtt min/avg/max/mdev = 150.112/150.309/150.512/0.145 ms\n"
        )
        mock_cmd.return_value = (0, ping_stdout, "")

        rtt = sts.measure_ping_rtt("2001:db8:2::10", is_ipv6=True, count=4, timeout=3.0, interval=0.2, dry_run=False)
        self.assertAlmostEqual(rtt, 150.309, places=3)
        # Verify RTT is within S3 acceptance range [135, 175]ms
        self.assertTrue(sts.S3_IPV6_RTT_MIN <= rtt <= sts.S3_IPV6_RTT_MAX)
        # Verify RTT is parsed once and NOT doubled to ~300.6ms or 301.00ms
        self.assertNotAlmostEqual(rtt, 301.00, delta=10.0)

    @patch("lab.impair.execute_netns_cmd")
    def test_measure_ping_rtt_realistic_ipv6_s4_output(self, mock_cmd):
        """Regression test: verify parsing of realistic Linux iputils ping output for S4 (600ms target)."""
        ping_stdout = (
            "PING 2001:db8:2::10(2001:db8:2::10) 56 data bytes\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=1 ttl=64 time=600 ms\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=2 ttl=64 time=601 ms\n"
            "64 bytes from 2001:db8:2::10: icmp_seq=3 ttl=64 time=600 ms\n"
            "\n"
            "--- 2001:db8:2::10 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 1201ms\n"
            "rtt min/avg/max/mdev = 598.214/600.412/602.810/1.120 ms\n"
        )
        mock_cmd.return_value = (0, ping_stdout, "")

        rtt = sts.measure_ping_rtt("2001:db8:2::10", is_ipv6=True, count=3, timeout=4.0, interval=0.5, dry_run=False)
        self.assertAlmostEqual(rtt, 600.412, places=3)
        # Verify RTT is within S4 acceptance range [550, 660]ms
        self.assertTrue(sts.S4_IPV6_RTT_MIN <= rtt <= sts.S4_IPV6_RTT_MAX)
        # Verify RTT is parsed once and NOT doubled to ~1200ms
        self.assertNotAlmostEqual(rtt, 1200.0, delta=50.0)

    @patch("lab.impair.execute_netns_cmd")
    def test_measure_ping_rtt_round_trip_format_compatibility(self, mock_cmd):
        """Verify compatibility with 'round-trip min/avg/max/stddev' summary line."""
        ping_stdout = (
            "--- 2001:db8:2::10 ping statistics ---\n"
            "4 packets transmitted, 4 received, 0% packet loss, time 602ms\n"
            "round-trip min/avg/max/stddev = 149.900/150.309/150.700/0.250 ms\n"
        )
        mock_cmd.return_value = (0, ping_stdout, "")
        rtt = sts.measure_ping_rtt("2001:db8:2::10", is_ipv6=True, dry_run=False)
        self.assertAlmostEqual(rtt, 150.309, places=3)

    @patch("lab.impair.execute_netns_cmd")
    def test_measure_ping_rtt_failure_raises(self, mock_cmd):
        mock_cmd.return_value = (1, "", "Destination Host Unreachable")
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.measure_ping_rtt("10.0.2.10", dry_run=False)
        self.assertIn("Destination Host Unreachable", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_query_dns_with_timing_parsing_a_and_aaaa(self, mock_cmd):
        # A record output
        dig_stdout_a = (
            ";; Got answer:\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
            "he.test.\t\t1\tIN\tA\t10.0.2.10\n"
            "\n"
            ";; Query time: 1 msec\n"
        )
        mock_cmd.return_value = (0, dig_stdout_a, "")
        addr, elapsed = sts.query_dns_with_timing("A", dry_run=False)
        self.assertEqual(addr, "10.0.2.10")
        self.assertEqual(elapsed, 1.0)
        cmd_sent = mock_cmd.call_args[0][1]
        self.assertIn("+stats", cmd_sent)

        # AAAA record output
        dig_stdout_aaaa = (
            ";; Got answer:\n"
            "he.test.\t\t1\tIN\tAAAA\t2001:db8:2::10\n"
            ";; Query time: 501 msec\n"
        )
        mock_cmd.return_value = (0, dig_stdout_aaaa, "")
        addr, elapsed = sts.query_dns_with_timing("AAAA", dry_run=False)
        self.assertEqual(addr, "2001:db8:2::10")
        self.assertEqual(elapsed, 501.0)

    @patch("lab.impair.execute_netns_cmd")
    def test_query_dns_with_timing_normal_query_time(self, mock_cmd):
        """Verify parsing a normal query-time line from dig stdout."""
        dig_stdout = (
            ";; Got answer:\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
            "he.test.\t\t1\tIN\tA\t10.0.2.10\n"
            "\n"
            ";; Query time: 12 msec\n"
            ";; SERVER: 10.0.2.10#53(10.0.2.10)\n"
        )
        mock_cmd.return_value = (0, dig_stdout, "")
        addr, elapsed = sts.query_dns_with_timing("A", dry_run=False)
        self.assertEqual(addr, "10.0.2.10")
        self.assertEqual(elapsed, 12.0)

    @patch("lab.impair.execute_netns_cmd")
    def test_query_dns_with_timing_zero_milliseconds(self, mock_cmd):
        """Verify parsing zero milliseconds (0 msec) resolution duration."""
        dig_stdout = (
            ";; Got answer:\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
            "he.test.\t\t1\tIN\tA\t10.0.2.10\n"
            "\n"
            ";; Query time: 0 msec\n"
        )
        mock_cmd.return_value = (0, dig_stdout, "")
        addr, elapsed = sts.query_dns_with_timing("A", dry_run=False)
        self.assertEqual(addr, "10.0.2.10")
        self.assertEqual(elapsed, 0.0)

    @patch("lab.impair.execute_netns_cmd")
    def test_query_dns_with_timing_missing_query_time_raises(self, mock_cmd):
        """Verify ImpairmentError is raised if query-time line is missing from dig stdout."""
        dig_stdout = (
            ";; Got answer:\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
            "he.test.\t\t1\tIN\tA\t10.0.2.10\n"
        )
        mock_cmd.return_value = (0, dig_stdout, "")
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.query_dns_with_timing("A", dry_run=False)
        self.assertIn("Missing query time", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_query_dns_with_timing_malformed_query_time_raises(self, mock_cmd):
        """Verify ImpairmentError is raised if query-time field is malformed."""
        malformed_samples = [
            ";; Query time: not_a_number msec\n",
            ";; Query time: msec\n",
            ";; Query time: 10 sec\n",
            ";; Query time: -5 msec\n",
            ";; Query time:\n",
        ]
        for sample in malformed_samples:
            dig_stdout = (
                ";; Got answer:\n"
                ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345\n"
                "he.test.\t\t1\tIN\tA\t10.0.2.10\n"
                f"{sample}"
            )
            mock_cmd.return_value = (0, dig_stdout, "")
            with self.subTest(sample=sample):
                with self.assertRaises(impair.ImpairmentError) as ctx:
                    sts.query_dns_with_timing("A", dry_run=False)
                self.assertIn("Malformed query time", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_probe_http_status_parsing(self, mock_cmd):
        mock_cmd.return_value = (0, "200\n", "")
        code, elapsed = sts.probe_http("http://10.0.2.10/", dry_run=False)
        self.assertEqual(code, 200)

        mock_cmd.return_value = (0, "404\n", "")
        code, elapsed = sts.probe_http("http://10.0.2.10/missing", dry_run=False)
        self.assertEqual(code, 404)

    @patch("lab.impair.execute_netns_cmd")
    def test_probe_tcp_connect_outcomes(self, mock_cmd):
        mock_cmd.return_value = (0, "connected,0.0210\n", "")
        outcome, el = sts.probe_tcp_connect("10.0.2.10", port=80, dry_run=False)
        self.assertEqual(outcome, "connected")
        self.assertAlmostEqual(el, 0.021, places=3)

        mock_cmd.return_value = (0, "timeout,2.0005\n", "")
        outcome, el = sts.probe_tcp_connect("2001:db8:2::10", port=80, dry_run=False)
        self.assertEqual(outcome, "timeout")
        self.assertAlmostEqual(el, 2.0005, places=3)

        mock_cmd.return_value = (0, "refused,0.0035\n", "")
        outcome, el = sts.probe_tcp_connect("2001:db8:2::10", port=80, dry_run=False)
        self.assertEqual(outcome, "refused")
        self.assertAlmostEqual(el, 0.0035, places=3)

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_nftables_counters_json(self, mock_cmd):
        nft_json = {
            "nftables": [
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_total", "packets": 50, "bytes": 4000}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_dropped", "packets": 24, "bytes": 1920}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_not_dropped", "packets": 26, "bytes": 2080}},
            ]
        }
        mock_cmd.return_value = (0, json.dumps(nft_json), "")
        counters = sts.read_s5_nftables_counters(dry_run=False)
        self.assertEqual(counters["syn_total"], 50)
        self.assertEqual(counters["syn_dropped"], 24)
        self.assertEqual(counters["syn_not_dropped"], 26)

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_nftables_counters_text_fallback(self, mock_cmd):
        text_output = (
            "table inet ps028_impair {\n"
            "    counter syn_total {\n"
            "        packets 50 bytes 4000\n"
            "    }\n"
            "    counter syn_dropped {\n"
            "        packets 24 bytes 1920\n"
            "    }\n"
            "    counter syn_not_dropped {\n"
            "        packets 26 bytes 2080\n"
            "    }\n"
            "}\n"
        )
        mock_cmd.side_effect = [(1, "", "JSON not supported"), (0, text_output, "")]
        counters = sts.read_s5_nftables_counters(dry_run=False)
        self.assertEqual(counters["syn_total"], 50)
        self.assertEqual(counters["syn_dropped"], 24)
        self.assertEqual(counters["syn_not_dropped"], 26)

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_nftables_counters_missing_counter_raises(self, mock_cmd):
        """Regression test: raise ImpairmentError if any required named counter is missing from both formats."""
        json_missing = {
            "nftables": [
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_total", "packets": 50}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_dropped", "packets": 25}},
            ]
        }
        text_missing = (
            "table inet ps028_impair {\n"
            "    counter syn_total { packets 50 bytes 4000 }\n"
            "    counter syn_dropped { packets 25 bytes 2000 }\n"
            "}\n"
        )
        mock_cmd.side_effect = [(0, json.dumps(json_missing), ""), (0, text_missing, "")]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.read_s5_nftables_counters(dry_run=False)
        self.assertIn("syn_not_dropped", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_nftables_counters_malformed_raises(self, mock_cmd):
        """Regression test: raise ImpairmentError if counters are malformed in both formats."""
        json_malformed = {
            "nftables": [
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_total", "packets": "corrupt"}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_dropped", "packets": 25}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_not_dropped", "packets": 25}},
            ]
        }
        text_malformed = (
            "table inet ps028_impair {\n"
            "    counter syn_total { packets not_a_number bytes 4000 }\n"
            "    counter syn_dropped { packets 25 bytes 2000 }\n"
            "    counter syn_not_dropped { packets 25 bytes 2000 }\n"
            "}\n"
        )
        mock_cmd.side_effect = [(0, json.dumps(json_malformed), ""), (0, text_malformed, "")]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.read_s5_nftables_counters(dry_run=False)
        self.assertIn("Unable to read required S5 nftables counters", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_nftables_counters_both_formats_command_failure_raises(self, mock_cmd):
        """Regression test: raise ImpairmentError if both format commands fail."""
        mock_cmd.side_effect = [(1, "", "nft JSON error"), (1, "", "nft text error")]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.read_s5_nftables_counters(dry_run=False)
        self.assertIn("Unable to read required S5 nftables counters", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_nftables_counters_malformed_json_falls_back_to_valid_text(self, mock_cmd):
        """Regression test: malformed JSON format cleanly falls back to text format."""
        text_valid = (
            "table inet ps028_impair {\n"
            "    counter syn_total { packets 50 bytes 4000 }\n"
            "    counter syn_dropped { packets 24 bytes 1920 }\n"
            "    counter syn_not_dropped { packets 26 bytes 2080 }\n"
            "}\n"
        )
        mock_cmd.side_effect = [(0, "invalid json {[[", ""), (0, text_valid, "")]
        counters = sts.read_s5_nftables_counters(dry_run=False)
        self.assertEqual(counters["syn_total"], 50)
        self.assertEqual(counters["syn_dropped"], 24)
        self.assertEqual(counters["syn_not_dropped"], 26)

    @patch("lab.impair.execute_netns_cmd")
    @patch("lab.impair.require_root")
    def test_setup_s5_nftables_counters_consistent_filters(self, mock_root, mock_cmd):
        """Regression test: verify consistent filters (client IP, server IP, dport, SYN flags, oifname) on all 3 counters."""
        mock_cmd.return_value = (0, "", "")
        sts.setup_s5_nftables_counters(
            port=80,
            target_ip="2001:db8:2::10",
            client_ip="2001:db8:1::2",
            oifname="ps028-rt-sv6",
            dry_run=False
        )
        mock_cmd.assert_called_once()
        stdin_data = mock_cmd.call_args[1].get("stdin_data", "")
        expected_filter = (
            'oifname "ps028-rt-sv6" ip6 saddr 2001:db8:1::2 ip6 daddr 2001:db8:2::10 '
            'tcp dport 80 tcp flags syn / syn,ack'
        )
        lines = stdin_data.strip().splitlines()
        rule_lines = [l for l in lines if l.startswith("add rule")]
        self.assertEqual(len(rule_lines), 3)
        for rline in rule_lines:
            self.assertIn(expected_filter, rline)
        self.assertIn('counter name "syn_total"', rule_lines[0])
        self.assertIn('numgen random mod 100 < 50 counter name "syn_dropped" drop', rule_lines[1])
        self.assertIn('counter name "syn_not_dropped"', rule_lines[2])

    @patch("lab.self_test_scenarios.read_s5_nftables_counters")
    @patch("lab.self_test_scenarios.setup_s5_nftables_counters")
    @patch("lab.impair.execute_netns_cmd")
    @patch("lab.impair.require_root")
    def test_measure_syn_loss_live_with_nftables_evidence(self, mock_root, mock_cmd, mock_setup, mock_counters):
        mock_counters.side_effect = [
            {"syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
            {"syn_total": 50, "syn_dropped": 24, "syn_not_dropped": 26},
        ]

        def mock_cmd_compile_and_run(netns, cmd, **kwargs):
            if len(cmd) >= 3 and cmd[0] == "python3" and cmd[1] == "-c":
                compile(cmd[2], "<string>", "exec")
            return (0, "PROBES_DONE\n", "")

        mock_cmd.side_effect = mock_cmd_compile_and_run

        res = sts.measure_syn_loss("2001:db8:2::10", port=80, total_probes=50, dry_run=False)
        self.assertEqual(res["total_syn_count"], 50)
        self.assertEqual(res["dropped_packets"], 24)
        self.assertEqual(res["accepted_packets"], 26)
        self.assertEqual(res["not_dropped_packets"], 26)
        self.assertEqual(res["observed_loss_pct"], 48.0)
        self.assertEqual(res["extra_syn_packets"], 0)
        self.assertNotIn("retransmitted_packets", res)
        self.assertEqual(res["measurement_method"], "nftables_counters")
        self.assertEqual(res["evidence"]["source"], "nftables")
        self.assertEqual(res["evidence"]["counters"]["syn_total"], 50)

    @patch("lab.self_test_scenarios.read_s5_nftables_counters")
    @patch("lab.self_test_scenarios.setup_s5_nftables_counters")
    @patch("lab.impair.execute_netns_cmd")
    @patch("lab.impair.require_root")
    def test_measure_syn_loss_compiles_actual_generated_script_before_execution(
        self, mock_root, mock_cmd, mock_setup, mock_counters
    ):
        """
        Regression test: Verify that the actual generated probe script passed to
        execute_netns_cmd compiles with Python's compile() before execution.
        A test that only mocks the probe's subprocess result is insufficient.
        """
        mock_counters.side_effect = [
            {"syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
            {"syn_total": 50, "syn_dropped": 25, "syn_not_dropped": 25},
        ]

        compiled_code_objects = []

        def inspect_and_compile(netns, cmd, **kwargs):
            self.assertEqual(netns, sts.CLIENT_NETNS)
            self.assertEqual(cmd[0], "python3")
            self.assertEqual(cmd[1], "-c")
            generated_script = cmd[2]
            # Compile the actual generated script before execution
            code_obj = compile(generated_script, "<ps028_s5_probe>", "exec")
            compiled_code_objects.append(code_obj)
            return (0, "PROBES_DONE\n", "")

        mock_cmd.side_effect = inspect_and_compile

        res = sts.measure_syn_loss("2001:db8:2::10", port=80, total_probes=50, dry_run=False)

        self.assertEqual(len(compiled_code_objects), 1, "Expected exactly one probe script to be compiled")
        self.assertIsNotNone(compiled_code_objects[0])
        self.assertEqual(res["total_syn_count"], 50)
        self.assertEqual(res["dropped_packets"], 25)
        self.assertEqual(res["not_dropped_packets"], 25)

    def test_build_s5_probe_script_syntax_and_socket_lifecycle(self):
        """
        Regression test: Verify build_s5_probe_script compiles cleanly with compile()
        and defines reliable socket closing in try/finally even if connect() times out
        or raises an OSError.
        """
        script = sts.build_s5_probe_script()
        code_obj = compile(script, "<s5_probe_script>", "exec")
        self.assertIsNotNone(code_obj)
        # Check proper structure for socket closing and error handling
        self.assertIn("try:", script)
        self.assertIn("s.connect((ip, port))", script)
        self.assertIn("except (socket.timeout, TimeoutError, OSError):", script)
        self.assertIn("finally:", script)
        self.assertIn("s.close()", script)

    def test_s5_probe_script_detects_malformed_syntax_error(self):
        """
        Regression test: Verify compile() catches the malformed unindented finally
        syntax error that caused probe execution failures in live runs.
        """
        malformed_script = (
            "import socket, sys\n"
            "def probe_one(idx):\n"
            "    s = socket.socket()\n"
            "    try:\n"
            "        s.connect(('127.0.0.1', 80))\n"
            "    except Exception:\n"
            "        pass\n"
            "finally:\n"
            "        s.close()\n"
        )
        with self.assertRaises(SyntaxError) as ctx:
            compile(malformed_script, "<string>", "exec")
        self.assertIn("invalid syntax", ctx.exception.msg)
        self.assertIn("finally", ctx.exception.text)

    @patch("lab.self_test_scenarios.read_s5_nftables_counters")
    @patch("lab.self_test_scenarios.setup_s5_nftables_counters")
    @patch("lab.impair.execute_netns_cmd")
    @patch("lab.impair.require_root")
    def test_measure_syn_loss_infers_extra_syn_packets(self, mock_root, mock_cmd, mock_setup, mock_counters):
        """Verify measurement infers extra SYN packets: total packets > initial probe attempts."""
        mock_counters.side_effect = [
            {"syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
            {"syn_total": 60, "syn_dropped": 30, "syn_not_dropped": 30},
        ]
        mock_cmd.return_value = (0, "PROBES_DONE\n", "")

        res = sts.measure_syn_loss("2001:db8:2::10", port=80, total_probes=50, dry_run=False)
        self.assertEqual(res["total_syn_count"], 60)
        self.assertEqual(res["initial_probes"], 50)
        self.assertEqual(res["extra_syn_packets"], 10)
        self.assertNotIn("retransmitted_packets", res)
        self.assertEqual(res["dropped_packets"], 30)
        self.assertEqual(res["not_dropped_packets"], 30)
        self.assertEqual(res["accepted_packets"], 30)
        self.assertEqual(res["observed_loss_pct"], 50.0)
        self.assertEqual(res["total_syn_count"], res["dropped_packets"] + res["not_dropped_packets"])

    @patch("lab.self_test_scenarios.read_s5_nftables_counters")
    @patch("lab.self_test_scenarios.setup_s5_nftables_counters")
    @patch("lab.impair.execute_netns_cmd")
    @patch("lab.impair.require_root")
    def test_measure_syn_loss_counter_mismatch_fails_without_overwriting(self, mock_root, mock_cmd, mock_setup, mock_counters):
        """Regression test: fail if total_syn_count != dropped + not_dropped; never overwrite raw counters."""
        mock_counters.side_effect = [
            {"syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
            {"syn_total": 50, "syn_dropped": 20, "syn_not_dropped": 25},  # 20 + 25 = 45 != 50!
        ]
        mock_cmd.return_value = (0, "PROBES_DONE\n", "")

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.measure_syn_loss("2001:db8:2::10", port=80, total_probes=50, dry_run=False)
        self.assertIn("S5 Counter accounting mismatch", str(ctx.exception))
        self.assertIn("50", str(ctx.exception))
        self.assertIn("20", str(ctx.exception))
        self.assertIn("25", str(ctx.exception))

    @patch("lab.impair.log_info")
    def test_measure_syn_loss_dry_run_evidence_and_terminology(self, mock_log):
        """Regression test: dry-run marks measurement_method='dry_run_simulation', evidence.source='simulation',
        uses extra_syn_packets terminology, and logs simulated counts."""
        res = sts.measure_syn_loss(total_probes=50, dry_run=True, simulated_loss_pct=50.0)
        self.assertEqual(res["measurement_method"], "dry_run_simulation")
        self.assertEqual(res["evidence"]["source"], "simulation")
        self.assertIn("extra_syn_packets", res)
        self.assertNotIn("retransmitted_packets", res)
        self.assertEqual(res["extra_syn_packets"], 0)
        self.assertEqual(res["total_syn_count"], 50)
        self.assertEqual(res["dropped_packets"], 25)
        self.assertEqual(res["not_dropped_packets"], 25)

        # Verify log message clearly identifies simulated counts
        mock_log.assert_called()
        log_msgs = [c[0][0] for c in mock_log.call_args_list]
        s5_log = next(m for m in log_msgs if "[DRY-RUN] S5 SYN Loss" in m)
        self.assertIn("simulated counts", s5_log)
        self.assertIn("simulated_total=50", s5_log)
        self.assertNotIn("evidence: project nftables counters", s5_log)

    def test_measure_syn_loss_dry_run_consistency(self):
        """Regression test: verify S5 dry-run derives loss percentage from dropped/total*100 and accepted=total-dropped."""
        # Case 1: total_probes = 20 with simulated 48% target
        res20 = sts.measure_syn_loss(total_probes=20, dry_run=True, simulated_loss_pct=48.0)
        self.assertEqual(res20["total_syn_count"], 20)
        self.assertEqual(res20["dropped_packets"], 10)
        self.assertEqual(res20["accepted_packets"], 10)
        self.assertEqual(res20["accepted_packets"], res20["total_syn_count"] - res20["dropped_packets"])
        self.assertEqual(res20["measurement_method"], "dry_run_simulation")
        self.assertEqual(res20["evidence"]["source"], "simulation")
        self.assertEqual(res20["extra_syn_packets"], 0)
        self.assertNotIn("retransmitted_packets", res20)
        # Crucial: 10/20 is 50%, not 48.0%
        self.assertEqual(res20["observed_loss_pct"], 50.0)
        self.assertEqual(
            res20["observed_loss_pct"],
            (res20["dropped_packets"] / res20["total_syn_count"]) * 100.0
        )

        # Case 2: total_probes = 50 with simulated 48% target (24/50 = 48.0%)
        res50 = sts.measure_syn_loss(total_probes=50, dry_run=True, simulated_loss_pct=48.0)
        self.assertEqual(res50["total_syn_count"], 50)
        self.assertEqual(res50["dropped_packets"], 24)
        self.assertEqual(res50["accepted_packets"], 26)
        self.assertEqual(res50["accepted_packets"], res50["total_syn_count"] - res50["dropped_packets"])
        self.assertEqual(res50["observed_loss_pct"], 48.0)
        self.assertEqual(
            res50["observed_loss_pct"],
            (res50["dropped_packets"] / res50["total_syn_count"]) * 100.0
        )

        # Case 3: total_probes = 25 with simulated 48% target (12/25 = 48.0%)
        res25 = sts.measure_syn_loss(total_probes=25, dry_run=True, simulated_loss_pct=48.0)
        self.assertEqual(res25["total_syn_count"], 25)
        self.assertEqual(res25["dropped_packets"], 12)
        self.assertEqual(res25["accepted_packets"], 13)
        self.assertEqual(res25["accepted_packets"], res25["total_syn_count"] - res25["dropped_packets"])
        self.assertEqual(res25["observed_loss_pct"], 48.0)
        self.assertEqual(
            res25["observed_loss_pct"],
            (res25["dropped_packets"] / res25["total_syn_count"]) * 100.0
        )

        # Case 4: default simulated_loss_pct (nominal 50%)
        res_def = sts.measure_syn_loss(total_probes=30, dry_run=True)
        self.assertEqual(res_def["total_syn_count"], 30)
        self.assertEqual(res_def["dropped_packets"], 15)
        self.assertEqual(res_def["accepted_packets"], 15)
        self.assertEqual(res_def["observed_loss_pct"], 50.0)
        self.assertEqual(
            res_def["observed_loss_pct"],
            (res_def["dropped_packets"] / res_def["total_syn_count"]) * 100.0
        )


class TestScenarioVerifiers(unittest.TestCase):
    """Test scenario verification functions under expected conditions and fault injections."""

    @patch("lab.self_test_scenarios.probe_http")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    @patch("lab.self_test_scenarios.query_dns_with_timing")
    def test_verify_s0_success(self, mock_dns, mock_ping, mock_http):
        mock_dns.side_effect = [("10.0.2.10", 3.0), ("2001:db8:2::10", 3.5)]
        mock_ping.side_effect = [20.1, 20.2]
        mock_http.side_effect = [(200, 20.0), (200, 20.0), (200, 20.0)]

        res = sts.verify_s0(dry_run=False)
        self.assertEqual(res["dns_a"], "10.0.2.10")
        self.assertEqual(res["dns_aaaa"], "2001:db8:2::10")
        self.assertAlmostEqual(res["ipv4_rtt_ms"], 20.1)
        self.assertAlmostEqual(res["ipv6_rtt_ms"], 20.2)
        self.assertEqual(res["http_ipv4_status"], 200)
        self.assertEqual(res["http_ipv6_status"], 200)
        self.assertEqual(res["http_domain_status"], 200)

    @patch("lab.self_test_scenarios.query_dns_with_timing")
    def test_verify_s0_dns_failure(self, mock_dns):
        # AAAA record returns wrong address
        mock_dns.side_effect = [("10.0.2.10", 3.0), ("2001:db8:9::99", 3.5)]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s0(dry_run=False)
        self.assertIn("S0 DNS AAAA returned", str(ctx.exception))

    @patch("lab.self_test_scenarios.probe_http")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    @patch("lab.self_test_scenarios.query_dns_with_timing")
    def test_verify_s0_latency_out_of_bounds(self, mock_dns, mock_ping, mock_http):
        mock_dns.side_effect = [("10.0.2.10", 3.0), ("2001:db8:2::10", 3.5)]
        mock_ping.side_effect = [55.0, 20.2]  # IPv4 RTT 55ms deviates from baseline
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s0(dry_run=False)
        self.assertIn("out of baseline range", str(ctx.exception))

    @patch("lab.self_test_scenarios.probe_tcp_connect")
    @patch("lab.self_test_scenarios.probe_http")
    def test_verify_s1_ipv4_succeeds_ipv6_times_out(self, mock_http, mock_tcp):
        mock_http.return_value = (200, 20.0)
        mock_tcp.return_value = ("timeout", 1.50)

        res = sts.verify_s1(dry_run=False)
        self.assertEqual(res["ipv4_http_status"], 200)
        self.assertEqual(res["ipv6_tcp_outcome"], "timeout")

    @patch("lab.self_test_scenarios.probe_tcp_connect")
    @patch("lab.self_test_scenarios.probe_http")
    def test_verify_s1_failure_if_ipv6_connects(self, mock_http, mock_tcp):
        mock_http.return_value = (200, 20.0)
        mock_tcp.return_value = ("connected", 0.02)  # Should have timed out!

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s1(dry_run=False)
        self.assertIn("did not time out", str(ctx.exception))

    @patch("lab.self_test_scenarios.probe_tcp_connect")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    @patch("lab.self_test_scenarios.probe_http")
    def test_verify_s2_ipv4_succeeds_ipv6_rst(self, mock_http, mock_ping, mock_tcp):
        mock_http.return_value = (200, 20.0)
        mock_ping.return_value = 20.1
        mock_tcp.return_value = ("refused", 0.005)

        res = sts.verify_s2(dry_run=False)
        self.assertEqual(res["ipv4_http_status"], 200)
        self.assertEqual(res["ipv6_tcp_outcome"], "refused")
        self.assertAlmostEqual(res["ipv4_rtt_ms"], 20.1)

    @patch("lab.self_test_scenarios.probe_tcp_connect")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    @patch("lab.self_test_scenarios.probe_http")
    def test_verify_s2_failure_if_timed_out_instead_of_rst(self, mock_http, mock_ping, mock_tcp):
        mock_http.return_value = (200, 20.0)
        mock_ping.return_value = 20.1
        mock_tcp.return_value = ("timeout", 2.0)  # Should have been RST refused!

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s2(dry_run=False)
        self.assertIn("did not receive TCP RST", str(ctx.exception))

    @patch("lab.self_test_scenarios.probe_http")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s3_150ms_rtt(self, mock_ping, mock_http):
        mock_ping.side_effect = [20.2, 150.3]  # IPv4 baseline 20ms, IPv6 150ms
        mock_http.side_effect = [(200, 20.0), (200, 150.0)]

        res = sts.verify_s3(dry_run=False)
        self.assertAlmostEqual(res["ipv4_rtt_ms"], 20.2)
        self.assertAlmostEqual(res["ipv6_rtt_ms"], 150.3)
        self.assertEqual(res["http_ipv4_status"], 200)
        self.assertEqual(res["http_ipv6_status"], 200)

    @patch("lab.self_test_scenarios.probe_http")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s3_live_ping_evidence_success(self, mock_ping, mock_http):
        """Verify S3 passes when ping measures 150.309ms (real live evidence) and 20.229ms IPv4."""
        mock_ping.side_effect = [20.229, 150.309]
        mock_http.side_effect = [(200, 20.0), (200, 150.0)]

        res = sts.verify_s3(dry_run=False)
        self.assertAlmostEqual(res["ipv4_rtt_ms"], 20.229)
        self.assertAlmostEqual(res["ipv6_rtt_ms"], 150.309)
        self.assertEqual(res["http_ipv4_status"], 200)
        self.assertEqual(res["http_ipv6_status"], 200)

    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s3_faulty_measurement_301ms_fails(self, mock_ping):
        """Regression test: S3 must reject the faulty ~2x measurement (301.00ms) from evidence."""
        mock_ping.side_effect = [20.229, 301.00]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s3(dry_run=False)
        self.assertIn("S3 IPv6 RTT out of 150ms target range", str(ctx.exception))
        self.assertIn("got 301.00ms", str(ctx.exception))

    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s3_faulty_doubled_measurement_fails(self, mock_ping):
        """Regression test: S3 must reject 2x doubled live ping value (300.62ms)."""
        mock_ping.side_effect = [20.229, 150.309 * 2]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s3(dry_run=False)
        self.assertIn("S3 IPv6 RTT out of 150ms target range", str(ctx.exception))

    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s3_failure_if_rtt_wrong(self, mock_ping):
        mock_ping.side_effect = [20.2, 20.1]  # IPv6 delay not applied!
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s3(dry_run=False)
        self.assertIn("S3 IPv6 RTT out of 150ms target range", str(ctx.exception))

    @patch("lab.self_test_scenarios.probe_http")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s4_600ms_rtt(self, mock_ping, mock_http):
        mock_ping.side_effect = [20.2, 600.4]  # IPv4 baseline 20ms, IPv6 600ms
        mock_http.side_effect = [(200, 20.0), (200, 600.0)]

        res = sts.verify_s4(dry_run=False)
        self.assertAlmostEqual(res["ipv4_rtt_ms"], 20.2)
        self.assertAlmostEqual(res["ipv6_rtt_ms"], 600.4)
        self.assertEqual(res["http_ipv4_status"], 200)
        self.assertEqual(res["http_ipv6_status"], 200)

    @patch("lab.self_test_scenarios.probe_http")
    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s4_realistic_live_ping_evidence_success(self, mock_ping, mock_http):
        """Verify S4 passes when ping measures realistic 600.412ms and 20.229ms IPv4."""
        mock_ping.side_effect = [20.229, 600.412]
        mock_http.side_effect = [(200, 20.0), (200, 600.0)]

        res = sts.verify_s4(dry_run=False)
        self.assertAlmostEqual(res["ipv4_rtt_ms"], 20.229)
        self.assertAlmostEqual(res["ipv6_rtt_ms"], 600.412)
        self.assertEqual(res["http_ipv4_status"], 200)
        self.assertEqual(res["http_ipv6_status"], 200)

    @patch("lab.self_test_scenarios.measure_ping_rtt")
    def test_verify_s4_faulty_measurement_fails(self, mock_ping):
        """Regression test: S4 must reject faulty/doubled measurement (~1200ms) or baseline (~20ms)."""
        mock_ping.side_effect = [20.2, 1200.0]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s4(dry_run=False)
        self.assertIn("S4 IPv6 RTT out of 600ms target range", str(ctx.exception))

        mock_ping.side_effect = [20.2, 300.0]  # One-way delay without return leg
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s4(dry_run=False)
        self.assertIn("S4 IPv6 RTT out of 600ms target range", str(ctx.exception))

    @patch("lab.self_test_scenarios.measure_syn_loss")
    def test_verify_s5_syn_loss_variation_success(self, mock_syn):
        mock_syn.return_value = {
            "total_syn_count": 50,
            "dropped_packets": 24,
            "accepted_packets": 26,
            "observed_loss_pct": 48.0
        }
        res = sts.verify_s5(probe_count=50, dry_run=False)
        self.assertEqual(res["total_syn_count"], 50)
        self.assertEqual(res["dropped_packets"], 24)
        self.assertEqual(res["accepted_packets"], 26)
        self.assertEqual(res["observed_loss_pct"], 48.0)

    @patch("lab.self_test_scenarios.measure_syn_loss")
    def test_verify_s5_zero_loss_failure(self, mock_syn):
        # 0% loss violates expected ~50% random loss
        mock_syn.return_value = {
            "total_syn_count": 50,
            "dropped_packets": 0,
            "accepted_packets": 50,
            "observed_loss_pct": 0.0
        }
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s5(probe_count=50, dry_run=False)
        self.assertIn("outside acceptable random variation", str(ctx.exception))

    def test_verify_s5_dry_run_consistency(self):
        """Regression test: verify_s5 in dry-run mode returns consistent counts and percentages."""
        # Test with probe_count=20 (previously reported total=20, dropped=10, accepted=10, loss=48.0%)
        res20 = sts.verify_s5(probe_count=20, dry_run=True)
        self.assertEqual(res20["total_syn_count"], 20)
        self.assertEqual(res20["dropped_packets"], 10)
        self.assertEqual(res20["accepted_packets"], 10)
        self.assertEqual(res20["accepted_packets"], res20["total_syn_count"] - res20["dropped_packets"])
        self.assertEqual(res20["observed_loss_pct"], 50.0)
        self.assertEqual(
            res20["observed_loss_pct"],
            (res20["dropped_packets"] / res20["total_syn_count"]) * 100.0
        )

        # Test with default probe_count=50 (24/50 = 48.0%)
        res50 = sts.verify_s5(probe_count=50, dry_run=True)
        self.assertEqual(res50["total_syn_count"], 50)
        self.assertEqual(res50["dropped_packets"], 24)
        self.assertEqual(res50["accepted_packets"], 26)
        self.assertEqual(res50["accepted_packets"], res50["total_syn_count"] - res50["dropped_packets"])
        self.assertEqual(res50["observed_loss_pct"], 48.0)
        self.assertEqual(
            res50["observed_loss_pct"],
            (res50["dropped_packets"] / res50["total_syn_count"]) * 100.0
        )

    @patch("lab.self_test_scenarios.measure_syn_loss")
    def test_verify_s5_inconsistent_percentage_accounting_error(self, mock_syn):
        """Regression test: verify_s5 rejects inconsistent counts and percentages (e.g. 10/20 reporting 48%)."""
        mock_syn.return_value = {
            "total_syn_count": 20,
            "dropped_packets": 10,
            "accepted_packets": 10,
            "observed_loss_pct": 48.0  # Inconsistent: 10/20 is 50%, not 48%
        }
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s5(probe_count=20, dry_run=False)
        self.assertIn("inconsistent", str(ctx.exception).lower())

    @patch("lab.self_test_scenarios.query_dns_with_timing")
    def test_verify_s6_a_immediate_aaaa_delayed_500ms(self, mock_dns):
        mock_dns.side_effect = [
            ("10.0.2.10", 3.2),        # A resolves immediately
            ("2001:db8:2::10", 508.5)   # AAAA delayed ~500ms
        ]
        res = sts.verify_s6(dry_run=False)
        self.assertEqual(res["a_address"], "10.0.2.10")
        self.assertEqual(res["aaaa_address"], "2001:db8:2::10")
        self.assertAlmostEqual(res["a_delay_ms"], 3.2)
        self.assertAlmostEqual(res["aaaa_delay_ms"], 508.5)
        self.assertAlmostEqual(res["observed_delay_delta_ms"], 505.3, places=1)

    @patch("lab.self_test_scenarios.query_dns_with_timing")
    def test_verify_s6_failure_if_aaaa_not_delayed(self, mock_dns):
        mock_dns.side_effect = [
            ("10.0.2.10", 3.2),
            ("2001:db8:2::10", 5.0)  # Delay not applied!
        ]
        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.verify_s6(dry_run=False)
        self.assertIn("outside expected ~500ms window", str(ctx.exception))


class TestHarnessLifecycleAndSafety(unittest.TestCase):
    """Test mandatory lifecycle: apply -> verify -> clear -> self-test-baseline."""

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_sequence_on_success(self, mock_apply, mock_clear, mock_baseline, mock_verify):
        mock_verify.return_value = {"status": "ok"}
        mock_baseline.return_value = True

        res = sts.run_scenario_self_test("S1", dry_run=False)

        # 1. apply_scenario must be called first
        mock_apply.assert_called_once_with("S1", scenarios_path=impair.DEFAULT_SCENARIOS_PATH, dry_run=False)
        # 2. verify must be called
        mock_verify.assert_called_once_with(dry_run=False)
        # 3. clear_impairments must be called in finally
        mock_clear.assert_called_once_with(dry_run=False)
        # 4. self_test_baseline must be called in finally
        mock_baseline.assert_called_once_with(dry_run=False)
        self.assertTrue(res["passed"])
        self.assertTrue(res["post_baseline_verified"])

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_cleans_up_even_when_verification_fails(self, mock_apply, mock_clear, mock_baseline, mock_verify):
        mock_verify.side_effect = impair.ImpairmentError("Simulated scenario check failure")
        mock_baseline.return_value = True

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.run_scenario_self_test("S1", dry_run=False)

        self.assertIn("Simulated scenario check failure", str(ctx.exception))
        # STRICT SAFETY: Ensure cleanup and baseline verification were STILL called
        mock_clear.assert_called_once_with(dry_run=False)
        mock_baseline.assert_called_once_with(dry_run=False)

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_raises_if_post_baseline_check_fails(self, mock_apply, mock_clear, mock_baseline, mock_verify):
        mock_verify.return_value = {"status": "ok"}
        mock_baseline.return_value = False  # Baseline check failed!

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.run_scenario_self_test("S1", dry_run=False)

        self.assertIn("Baseline self-test failed following scenario S1", str(ctx.exception))

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_cleanup_failure_not_suppressed_when_baseline_passes(
        self, mock_apply, mock_clear, mock_baseline, mock_verify
    ):
        """Cleanup failure must NOT be suppressed even when post-scenario baseline check passes."""
        mock_verify.return_value = {"status": "ok"}
        mock_clear.side_effect = impair.ImpairmentError("Simulated cleanup lock failure")
        mock_baseline.return_value = True

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.run_scenario_self_test("S1", dry_run=False)

        self.assertIn("Cleanup error", str(ctx.exception))
        self.assertIn("Simulated cleanup lock failure", str(ctx.exception))
        # STRICT SAFETY: Baseline verification must still be attempted
        mock_baseline.assert_called_once_with(dry_run=False)

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_baseline_check_exception_handled_and_raised(
        self, mock_apply, mock_clear, mock_baseline, mock_verify
    ):
        """Exceptions raised during baseline check must be handled and preserved."""
        mock_verify.return_value = {"status": "ok"}
        mock_baseline.side_effect = RuntimeError("Baseline verification probe crashed")

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.run_scenario_self_test("S1", dry_run=False)

        self.assertIn("Baseline error", str(ctx.exception))
        self.assertIn("Baseline verification probe crashed", str(ctx.exception))
        mock_clear.assert_called_once_with(dry_run=False)

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_combined_verification_and_cleanup_failure(
        self, mock_apply, mock_clear, mock_baseline, mock_verify
    ):
        """Preserve both scenario verification error and cleanup error."""
        mock_verify.side_effect = impair.ImpairmentError("Original verification check failed")
        mock_clear.side_effect = impair.ImpairmentError("Simulated cleanup lock failure")
        mock_baseline.return_value = True

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.run_scenario_self_test("S1", dry_run=False)

        exc_msg = str(ctx.exception)
        self.assertIn("Scenario verification error", exc_msg)
        self.assertIn("Original verification check failed", exc_msg)
        self.assertIn("Cleanup error", exc_msg)
        self.assertIn("Simulated cleanup lock failure", exc_msg)
        mock_baseline.assert_called_once_with(dry_run=False)

    @patch("lab.self_test_scenarios.verify_s1")
    @patch("lab.impair.self_test_baseline")
    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.apply_scenario")
    def test_lifecycle_combined_verification_cleanup_and_baseline_failure(
        self, mock_apply, mock_clear, mock_baseline, mock_verify
    ):
        """Preserve scenario verification error, cleanup error, and baseline check failure."""
        mock_verify.side_effect = impair.ImpairmentError("Original verification check failed")
        mock_clear.side_effect = impair.ImpairmentError("Simulated cleanup lock failure")
        mock_baseline.side_effect = RuntimeError("Baseline check probe crashed")

        with self.assertRaises(impair.ImpairmentError) as ctx:
            sts.run_scenario_self_test("S1", dry_run=False)

        exc_msg = str(ctx.exception)
        self.assertIn("Scenario verification error", exc_msg)
        self.assertIn("Original verification check failed", exc_msg)
        self.assertIn("Cleanup error", exc_msg)
        self.assertIn("Simulated cleanup lock failure", exc_msg)
        self.assertIn("Baseline error", exc_msg)
        self.assertIn("Baseline check probe crashed", exc_msg)

    def test_dry_run_run_all_self_tests(self):
        """Executing run_all_self_tests in dry-run mode completes all 7 scenarios successfully."""
        results = sts.run_all_self_tests(dry_run=True, probe_count=20)
        self.assertEqual(len(results), 7)
        expected_scenarios = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
        self.assertEqual([r["scenario"] for r in results], expected_scenarios)
        for r in results:
            self.assertTrue(r["passed"])
            self.assertTrue(r["post_baseline_verified"])

        # Regression check: verify S5 result details maintain exact count and percentage consistency
        s5_res = next(r for r in results if r["scenario"] == "S5")
        s5_details = s5_res["details"]
        self.assertEqual(s5_details["total_syn_count"], 20)
        self.assertEqual(s5_details["dropped_packets"], 10)
        self.assertEqual(s5_details["accepted_packets"], 10)
        self.assertEqual(
            s5_details["accepted_packets"],
            s5_details["total_syn_count"] - s5_details["dropped_packets"]
        )
        self.assertEqual(s5_details["observed_loss_pct"], 50.0)
        self.assertEqual(
            s5_details["observed_loss_pct"],
            (s5_details["dropped_packets"] / s5_details["total_syn_count"]) * 100.0
        )
        self.assertEqual(s5_details["measurement_method"], "dry_run_simulation")
        self.assertEqual(s5_details["evidence"]["source"], "simulation")
        self.assertEqual(s5_details["extra_syn_packets"], 0)
        self.assertNotIn("retransmitted_packets", s5_details)


class TestHarnessCLIAndIntegration(unittest.TestCase):
    """Test CLI argument parsing and module integration."""

    def test_sts_parser_options(self):
        parser = sts.build_parser()

        args1 = parser.parse_args(["--scenario", "S2", "--dry-run"])
        self.assertEqual(args1.scenario, "S2")
        self.assertTrue(args1.dry_run)

        args2 = parser.parse_args(["--scenarios", "S0,S1,S5", "--probes", "40", "--json"])
        self.assertEqual(args2.scenarios, "S0,S1,S5")
        self.assertEqual(args2.probes, 40)
        self.assertTrue(args2.json)

    def test_impair_parser_test_scenarios_subcommands(self):
        parser = impair.build_parser()

        args1 = parser.parse_args(["test-scenarios", "--scenario", "S3", "--dry-run"])
        self.assertEqual(args1.command, "test-scenarios")
        self.assertEqual(args1.scenario, "S3")
        self.assertTrue(args1.dry_run)

        args2 = parser.parse_args(["self-test-scenarios", "--scenarios", "S4,S6", "--json"])
        self.assertEqual(args2.command, "self-test-scenarios")
        self.assertEqual(args2.scenarios, "S4,S6")
        self.assertTrue(args2.json)


class TestProbeCountValidation(unittest.TestCase):
    """Test validation of probe counts across public functions, CLI, and harness."""

    def test_validate_probe_count_valid(self):
        self.assertEqual(sts.validate_probe_count(1), 1)
        self.assertEqual(sts.validate_probe_count(50), 50)
        self.assertEqual(sts.validate_probe_count(100), 100)

    def test_validate_probe_count_invalid_values(self):
        for invalid in [0, -1, -50, "50", None, False, True, 3.14]:
            with self.assertRaises(impair.ImpairmentError):
                sts.validate_probe_count(invalid)

    @patch("lab.impair.apply_scenario")
    def test_run_scenario_self_test_rejects_invalid_probes_without_applying(self, mock_apply):
        """Reject probe_count <= 0 before applying any scenario."""
        for invalid_count in [0, -1, -100]:
            with self.assertRaises(impair.ImpairmentError):
                sts.run_scenario_self_test("S5", probe_count=invalid_count, dry_run=False)
            mock_apply.assert_not_called()

    @patch("lab.impair.apply_scenario")
    def test_run_all_self_tests_rejects_invalid_probes_without_applying(self, mock_apply):
        """Reject probe_count <= 0 in run_all_self_tests before applying any scenario."""
        for invalid_count in [0, -5]:
            with self.assertRaises(impair.ImpairmentError):
                sts.run_all_self_tests(scenarios=["S5"], probe_count=invalid_count, dry_run=False)
            mock_apply.assert_not_called()

    def test_verify_s5_rejects_invalid_probes(self):
        for invalid_count in [0, -1, -20]:
            with self.assertRaises(impair.ImpairmentError):
                sts.verify_s5(probe_count=invalid_count, dry_run=True)

    def test_measure_syn_loss_rejects_invalid_probes(self):
        for invalid_count in [0, -1, -10]:
            with self.assertRaises(impair.ImpairmentError):
                sts.measure_syn_loss(total_probes=invalid_count, dry_run=True)

    def test_cli_probes_rejection_in_sts(self):
        parser = sts.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--probes", "0"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["--probes", "-10"])

    def test_cli_probes_rejection_in_impair(self):
        parser = impair.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["test-scenarios", "--probes", "0"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["test-scenarios", "--probes", "-5"])


if __name__ == "__main__":
    unittest.main()
