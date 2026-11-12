#!/usr/bin/env python3
"""
Comprehensive Adversarial Challenge Suite for Milestone 2 Batch C1:
- Handshake & Timing Latency Metrics (t_connect_ms, t_setup_total_ms, syn_to_synack_ms)
- Retransmission Invariance (SYN, SYN-ACK, final ACK)
- RST Handling & Sequence Space Invariance (RFC 5961 / RFC 9293)
- NetLog / PCAP Alignment & Directed Acyclic Graph Traversal
- Primary Flow Correlation & Ancillary Flow Isolation
- DNS Transaction Extraction & HTTPS/SVCB Isolation
- Schema 1.0.0 / 1.1.0 Compatibility & Fail-Closed Enforcement
- Deep Numeric Type Enforcement & Boolean Coercion Prevention
"""

import copy
import json
import math
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import lab.run_trial as run_trial
import lab.analyze as analyze


class TestC1AdversarialChallenge(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_c1_adv_"))
        self.pcap_file = self.temp_dir / "test.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.pcap_file.write_bytes(header)

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
        sport: Optional[int] = None,
        dport: Optional[int] = None,
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
        # Default sport and dport based on direction to/from server
        if sport is None and dport is None:
            if ip6_src == run_trial.SERVER_IPV6 or ip_src == run_trial.SERVER_IPV4:
                sport = 80
                dport = 50000
            else:
                sport = 50000
                dport = 80
        elif sport is None:
            sport = 50000
        elif dport is None:
            dport = 80

        fields = [
            str(t_epoch), ip_src, ip_dst, ip6_src, ip6_dst, flags,
            str(sport), str(dport), dns_qname, dns_qtype, dns_resp, dns_a, dns_aaaa,
            http_code, stream, http_method, http_uri, str(seq_raw), str(ack_raw),
            str(frame_num), str(tcp_len), http_response_in, http_request_in,
            dns_id, dns_rcode, udp_sport, udp_dport, dns_ancount, dns_resp_name
        ]
        return "\t".join(fields)

    # =========================================================================
    # SUITE 1: Handshake Timing Metrics & Retransmission Invariance
    # =========================================================================

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_1_1_clean_handshake_timing(self, mock_run, mock_which):
        """Clean 3-way handshake calculates t_connect_ms, syn_to_synack_ms, t_setup_total_ms."""
        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            self._make_tshark_line(t_epoch=10.025, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=2),
            self._make_tshark_line(t_epoch=10.035, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=1001, ack_raw=5001, frame_num=3),
            self._make_tshark_line(t_epoch=10.036, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", stream="0", seq_raw=1001, ack_raw=5001, frame_num=4, tcp_len=50, http_method="GET", http_uri="/", http_response_in="5"),
            self._make_tshark_line(t_epoch=10.050, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", stream="0", seq_raw=5001, ack_raw=1051, frame_num=5, tcp_len=100, http_code="200", http_request_in="4"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        metrics = dissection["metrics"]
        self.assertAlmostEqual(metrics["t_connect_ms"], 35.0, places=2)
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 25.0, places=2)
        self.assertAlmostEqual(metrics["t_setup_total_ms"], 35.0, places=2)
        self.assertEqual(metrics["retransmitted_syn_count_ipv6"], 0)
        self.assertEqual(metrics["retransmitted_syn_count_ipv4"], 0)
        self.assertNotIn("t_connect_ms", metrics["null_reasons"])

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_1_2_syn_retransmission_invariance(self, mock_run, mock_which):
        """Retransmitted SYNs increment retry count but strictly lock initial SYN timestamp."""
        lines = [
            # Initial SYN at t=10.000
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            # Retransmission 1 at t=10.500
            self._make_tshark_line(t_epoch=10.500, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=2),
            # Retransmission 2 at t=11.200
            self._make_tshark_line(t_epoch=11.200, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=3),
            # Server SYN-ACK at t=11.230
            self._make_tshark_line(t_epoch=11.230, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=4),
            # Client final ACK at t=11.240
            self._make_tshark_line(t_epoch=11.240, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=1001, ack_raw=5001, frame_num=5),
            # HTTP request & response
            self._make_tshark_line(t_epoch=11.241, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", stream="0", seq_raw=1001, ack_raw=5001, frame_num=6, tcp_len=50, http_method="GET", http_uri="/", http_response_in="7"),
            self._make_tshark_line(t_epoch=11.250, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", stream="0", seq_raw=5001, ack_raw=1051, frame_num=7, tcp_len=100, http_code="200", http_request_in="6"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertEqual(s0["retransmitted_syn_count"], 2)
        self.assertEqual(s0["syn_time"], 10.000)
        metrics = dissection["metrics"]
        self.assertEqual(metrics["retransmitted_syn_count_ipv6"], 2)
        self.assertAlmostEqual(metrics["t_connect_ms"], 1240.0, places=2)
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 1230.0, places=2)
        self.assertAlmostEqual(metrics["t_setup_total_ms"], 1240.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_1_3_retransmitted_synack_and_final_ack_invariance(self, mock_run, mock_which):
        """Retransmitted SYN-ACK and duplicate final ACK do not advance initial timestamps."""
        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            # Initial SYN-ACK at t=10.030
            self._make_tshark_line(t_epoch=10.030, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=2),
            # Retransmitted SYN-ACK at t=10.070
            self._make_tshark_line(t_epoch=10.070, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=3),
            # Initial final ACK at t=10.080
            self._make_tshark_line(t_epoch=10.080, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=1001, ack_raw=5001, frame_num=4),
            # Duplicate final ACK at t=10.090
            self._make_tshark_line(t_epoch=10.090, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=1001, ack_raw=5001, frame_num=5),
            # HTTP request & response
            self._make_tshark_line(t_epoch=10.091, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", stream="0", seq_raw=1001, ack_raw=5001, frame_num=6, tcp_len=50, http_method="GET", http_uri="/", http_response_in="7"),
            self._make_tshark_line(t_epoch=10.100, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", stream="0", seq_raw=5001, ack_raw=1051, frame_num=7, tcp_len=100, http_code="200", http_request_in="6"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertEqual(s0["syn_ack_time"], 10.030)
        self.assertEqual(s0["final_ack_time"], 10.080)
        metrics = dissection["metrics"]
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 30.0, places=2)
        self.assertAlmostEqual(metrics["t_connect_ms"], 80.0, places=2)
        self.assertAlmostEqual(metrics["t_setup_total_ms"], 80.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_1_4_fallback_t_setup_total_vs_t_connect(self, mock_run, mock_which):
        """In fallback scenario S1, t_connect_ms reflects winning IPv4 flow, while t_setup_total_ms spans from initial IPv6 SYN."""
        lines = [
            # Stream 0: IPv6 initial SYN at t=10.000, retry at t=10.500 (blackholed)
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            self._make_tshark_line(t_epoch=10.500, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=2),

            # Stream 1: IPv4 fallback attempt at t=10.250 (CAD = 250ms)
            self._make_tshark_line(t_epoch=10.250, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=40000, dport=80, stream="1", seq_raw=2000, frame_num=3),
            self._make_tshark_line(t_epoch=10.270, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=40000, stream="1", seq_raw=6000, ack_raw=2001, frame_num=4),
            self._make_tshark_line(t_epoch=10.285, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=40000, dport=80, stream="1", seq_raw=2001, ack_raw=6001, frame_num=5),
            # HTTP on Stream 1
            self._make_tshark_line(t_epoch=10.286, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=40000, dport=80, stream="1", seq_raw=2001, ack_raw=6001, frame_num=6, tcp_len=50, http_method="GET", http_uri="/", http_response_in="7"),
            self._make_tshark_line(t_epoch=10.300, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=40000, stream="1", seq_raw=6001, ack_raw=2051, frame_num=7, tcp_len=100, http_code="200", http_request_in="6"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        metrics = dissection["metrics"]
        self.assertEqual(dissection["primary_flow"]["stream_id"], "1")
        self.assertEqual(dissection["primary_flow"]["family"], "IPv4")
        self.assertAlmostEqual(metrics["connection_attempt_delay_ms"], 250.0, places=2)
        # t_connect_ms on stream 1: 10.285 - 10.250 = 35.0ms
        self.assertAlmostEqual(metrics["t_connect_ms"], 35.0, places=2)
        # t_setup_total_ms: 10.285 - 10.000 = 285.0ms
        self.assertAlmostEqual(metrics["t_setup_total_ms"], 285.0, places=2)
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 20.0, places=2)
        self.assertEqual(metrics["retransmitted_syn_count_ipv6"], 1)
        self.assertEqual(metrics["retransmitted_syn_count_ipv4"], 0)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_1_5_missing_final_ack_null_preservation(self, mock_run, mock_which):
        """Incomplete handshake missing final ACK retains explicit nulls and does NOT coerce to 0."""
        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            self._make_tshark_line(t_epoch=10.025, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=2),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        metrics = dissection["metrics"]
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 25.0, places=2)
        self.assertIsNone(metrics["t_connect_ms"])
        self.assertIsNone(metrics["t_setup_total_ms"])
        self.assertEqual(metrics["null_reasons"]["t_connect_ms"], "INDETERMINATE_NO_FINAL_ACK")
        self.assertEqual(metrics["null_reasons"]["t_setup_total_ms"], "INDETERMINATE_NO_FINAL_ACK")

    # =========================================================================
    # SUITE 2: RST Handling Boundary Conditions
    # =========================================================================

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_2_1_server_rst_valid_in_syn_sent(self, mock_run, mock_which):
        """Server RST with matching ACK in SYN_SENT correctly sets state RESET and null reason INDETERMINATE_CONN_RESET."""
        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            # Valid server RST: ACK bit set, ack_raw == 1001
            self._make_tshark_line(t_epoch=10.005, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0014", stream="0", seq_raw=0, ack_raw=1001, frame_num=2),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["server_rst_received"])
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "RESET")
        self.assertFalse(s0["tcp_handshake_completed"])
        metrics = dissection["metrics"]
        self.assertIsNone(metrics["t_connect_ms"])
        self.assertIsNone(metrics["syn_to_synack_ms"])
        self.assertEqual(metrics["null_reasons"]["t_connect_ms"], "INDETERMINATE_CONN_RESET")
        self.assertEqual(metrics["null_reasons"]["syn_to_synack_ms"], "INDETERMINATE_CONN_RESET")

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_2_2_server_rst_unvalidated_in_syn_sent_does_not_abort(self, mock_run, mock_which):
        """Server RST without valid ACK in SYN_SENT is marked unvalidated; genuine SYN-ACK still completes connection."""
        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            # Unvalidated RST: No ACK flag (flags=0x0004), raw_ack=0
            self._make_tshark_line(t_epoch=10.005, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", stream="0", seq_raw=0, ack_raw=0, frame_num=2),
            # Genuine SYN-ACK arrives
            self._make_tshark_line(t_epoch=10.020, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=3),
            # Client final ACK completes handshake
            self._make_tshark_line(t_epoch=10.030, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=1001, ack_raw=5001, frame_num=4),
            # HTTP request & response
            self._make_tshark_line(t_epoch=10.031, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", stream="0", seq_raw=1001, ack_raw=5001, frame_num=5, tcp_len=50, http_method="GET", http_uri="/", http_response_in="6"),
            self._make_tshark_line(t_epoch=10.040, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", stream="0", seq_raw=5001, ack_raw=1051, frame_num=6, tcp_len=100, http_code="200", http_request_in="5"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertFalse(s0["server_rst_validated"])
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        metrics = dissection["metrics"]
        self.assertAlmostEqual(metrics["t_connect_ms"], 30.0, places=2)
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 20.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_2_3_server_rst_after_handshake_preserves_historical_completion(self, mock_run, mock_which):
        """Server RST arriving after ESTABLISHED closes connection but preserves historical handshake completion."""
        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=1000, frame_num=1),
            self._make_tshark_line(t_epoch=10.020, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=5000, ack_raw=1001, frame_num=2),
            self._make_tshark_line(t_epoch=10.030, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=1001, ack_raw=5001, frame_num=3),
            # Valid Server RST at seq 5001 (matching RCV.NXT)
            self._make_tshark_line(t_epoch=10.050, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0004", stream="0", seq_raw=5001, ack_raw=0, frame_num=4),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertTrue(s0["server_rst_validated"])
        self.assertEqual(s0["handshake_state"], "CLOSED_BY_RESET")
        self.assertAlmostEqual(s0["t_connect_ms"], 30.0, places=2)

    # =========================================================================
    # SUITE 3: NetLog / PCAP Alignment
    # =========================================================================

    def test_3_1_netlog_graph_traversal_isolates_navigation_socket(self):
        """NetLog directed acyclic graph traversal isolates target socket from unrelated background sockets."""
        netlog_data = {
            "constants": {
                "logEventTypes": {
                    "URL_REQUEST_START_JOB": 1,
                    "TCP_CONNECT": 2,
                    "HTTP_TRANSACTION_READ_RESPONSE_HEADERS": 3
                }
            },
            "events": [
                # Unrelated background URL request (id 10) -> socket (id 100) on IPv4
                {"type": 1, "source": {"id": 10}, "params": {"url": "https://accounts.google.com/check"}},
                {"type": 2, "source": {"id": 100}, "params": {"remote_address": "142.250.190.46:443", "source_dependency": {"id": 10}}},

                # Target navigation URL request (id 20) -> socket (id 200) on IPv6
                {"type": 1, "source": {"id": 20}, "params": {"url": "http://trial.he.test/"}},
                {"type": 2, "source": {"id": 200}, "params": {"remote_address": "[2001:db8:2::10]:80", "source_dependency": {"id": 20}}},
                {"type": 3, "source": {"id": 20}, "params": {"headers": ["HTTP/1.1 200 OK"]}},

                # Another background socket that finishes LATER (id 300) on IPv4
                {"type": 2, "source": {"id": 300}, "params": {"remote_address": "10.0.2.10:80", "source_dependency": {"id": 999}}},
            ]
        }
        netlog_path = self.temp_dir / "netlog.json"
        netlog_path.write_text(json.dumps(netlog_data), encoding="utf-8")

        res = run_trial.parse_chromium_netlog(netlog_path, target_url="http://trial.he.test/")
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["winning_family"], "IPv6")
        self.assertEqual(res["remote_address"], "[2001:db8:2::10]:80")
        self.assertTrue(res["telemetry_valid"])

    def test_3_2_pcap_primary_flow_strictly_overrides_divergent_netlog(self):
        """PCAP correlated primary flow strictly overrides conflicting browser telemetry."""
        http_outcome = {
            "status_code": 200,
            "success": True,
            "winning_address_family": "IPv6",
            "winning_ip": run_trial.SERVER_IPV6,
        }
        browser_result = {
            "winning_family": "IPv6",
            "http_status": 200,
        }
        dissection = {
            "http_status_code": 200,
            "http_response_family": "IPv4",
            "main_http_flow": {
                "stream_id": "1",
                "family": "IPv4",
                "status_code": 200,
                "correlated": True,
                "tcp_handshake_completed": True,
            }
        }
        updated = run_trial.update_http_outcome_from_dissection(
            http_outcome=copy.deepcopy(http_outcome),
            dissection=dissection,
            browser_result=browser_result,
            is_simulation=False
        )
        self.assertEqual(updated["winning_address_family"], "IPv4")
        self.assertEqual(updated["winning_ip"], run_trial.SERVER_IPV4)
        self.assertTrue(updated["success"])

    # =========================================================================
    # SUITE 4: Boundary Edge Cases (Mathematical, Float, Zero, Schema)
    # =========================================================================

    def test_4_1_validate_trial_record_rejection_of_booleans_and_strings(self):
        """Validates that boolean and non-numeric string values fail closed as CORRUPTED_RECORD."""
        base_record = {
            "schema_version": "1.1.0",
            "trial_id": "trial-test",
            "scenario_id": "S0",
            "is_simulation": False,
            "execution_mode": "LIVE",
            "cleanup_status": {"scenario_restored": True, "baseline_verified": True, "errors": []},
            "capture_metadata": {"pcap_valid": True, "packet_count": 50},
            "network_observations": {"classification": "DIRECT_IPV6", "classification_reason": "ok"},
            "metrics": {
                "t_connect_ms": 20.5,
                "t_setup_total_ms": 20.5,
                "syn_to_synack_ms": 20.0,
            },
            "primary_flow": {"stream_id": "0", "t_connect_ms": 20.5},
            "http_outcome": {"status_code": 200, "success": True},
            "browser": {"duration_ms": 150.0},
        }

        # 1. Valid record passes
        cat, reason = analyze.validate_trial_record(base_record, Path("dummy.json"))
        self.assertEqual(cat, "VALID_LIVE")
        self.assertIsNone(reason)

        # 2. Boolean in t_connect_ms fails closed
        rec_bool = copy.deepcopy(base_record)
        rec_bool["metrics"]["t_connect_ms"] = True
        cat, reason = analyze.validate_trial_record(rec_bool, Path("dummy.json"))
        self.assertEqual(cat, "CORRUPTED_RECORD")
        self.assertIn("bool", reason)

        # 3. String in syn_to_synack_ms fails closed
        rec_str = copy.deepcopy(base_record)
        rec_str["metrics"]["syn_to_synack_ms"] = "twenty"
        cat, reason = analyze.validate_trial_record(rec_str, Path("dummy.json"))
        self.assertEqual(cat, "CORRUPTED_RECORD")
        self.assertIn("str", reason)

        # 4. NaN / Inf fails closed
        rec_nan = copy.deepcopy(base_record)
        rec_nan["metrics"]["t_connect_ms"] = float("nan")
        cat, reason = analyze.validate_trial_record(rec_nan, Path("dummy.json"))
        self.assertEqual(cat, "CORRUPTED_RECORD")

        # 5. Boolean in packet_count fails closed
        rec_pc_bool = copy.deepcopy(base_record)
        rec_pc_bool["capture_metadata"]["packet_count"] = True
        cat, reason = analyze.validate_trial_record(rec_pc_bool, Path("dummy.json"))
        self.assertEqual(cat, "CORRUPTED_RECORD")

        # 6. Negative packet_count fails as MEASUREMENT_FAILURE
        rec_pc_neg = copy.deepcopy(base_record)
        rec_pc_neg["capture_metadata"]["packet_count"] = 0
        cat, reason = analyze.validate_trial_record(rec_pc_neg, Path("dummy.json"))
        self.assertEqual(cat, "MEASUREMENT_FAILURE")

    def test_4_2_loader_fault_isolation_on_corrupt_files(self):
        """load_trials_from_directory isolates corrupt files and completes scan."""
        campaign_dir = self.temp_dir / "campaign"
        campaign_dir.mkdir()

        # Trial 1: Valid
        t1_dir = campaign_dir / "trial_valid"
        t1_dir.mkdir()
        valid_data = {
            "schema_version": "1.1.0",
            "trial_id": "trial-valid",
            "scenario_id": "S0",
            "cleanup_status": {"scenario_restored": True, "baseline_verified": True, "errors": []},
            "capture_metadata": {"pcap_valid": True, "packet_count": 20},
            "network_observations": {"classification": "DIRECT_IPV6", "classification_reason": "ok"},
            "metrics": {"t_connect_ms": 25.0, "syn_to_synack_ms": 20.0},
            "http_outcome": {"status_code": 200, "success": True},
        }
        (t1_dir / "result.json").write_text(json.dumps(valid_data), encoding="utf-8")

        # Trial 2: Corrupted syntax
        t2_dir = campaign_dir / "trial_corrupt_syntax"
        t2_dir.mkdir()
        (t2_dir / "result.json").write_text("{malformed: json", encoding="utf-8")

        # Trial 3: Corrupted boolean metric bypass
        t3_dir = campaign_dir / "trial_corrupt_metric"
        t3_dir.mkdir()
        corrupt_metric_data = copy.deepcopy(valid_data)
        corrupt_metric_data["trial_id"] = "trial-corrupt-metric"
        corrupt_metric_data["metrics"]["t_connect_ms"] = True
        (t3_dir / "result.json").write_text(json.dumps(corrupt_metric_data), encoding="utf-8")

        trials = analyze.load_trials_from_directory(campaign_dir)
        self.assertEqual(len(trials), 3)

        valid_trials = [t for t in trials if t.validity_category == "VALID_LIVE"]
        corrupt_trials = [t for t in trials if t.validity_category == "CORRUPTED_RECORD"]

        self.assertEqual(len(valid_trials), 1)
        self.assertEqual(len(corrupt_trials), 2)
        # Ensure boolean True was NOT coerced to 1.0!
        for ct in corrupt_trials:
            if ct.trial_id == "trial-corrupt-metric":
                self.assertNotEqual(ct.t_connect_ms, 1.0)

    def test_4_3_schema_version_compatibility(self):
        """Schema 1.0.0 and 1.1.0 accepted; other versions fail closed as CORRUPTED_RECORD."""
        base_record = {
            "schema_version": "1.1.0",
            "trial_id": "trial-test",
            "scenario_id": "S0",
            "cleanup_status": {"scenario_restored": True, "baseline_verified": True, "errors": []},
            "capture_metadata": {"pcap_valid": True, "packet_count": 50},
            "network_observations": {"classification": "DIRECT_IPV6", "classification_reason": "ok"},
            "metrics": {"t_connect_ms": 20.5},
            "http_outcome": {"status_code": 200, "success": True},
        }

        # 1.1.0 passes
        c11, _ = analyze.validate_trial_record(base_record, Path("dummy.json"))
        self.assertEqual(c11, "VALID_LIVE")

        # 1.0.0 passes
        rec_100 = copy.deepcopy(base_record)
        rec_100["schema_version"] = "1.0.0"
        c10, _ = analyze.validate_trial_record(rec_100, Path("dummy.json"))
        self.assertEqual(c10, "VALID_LIVE")

        # 1.2.0 fails closed
        rec_120 = copy.deepcopy(base_record)
        rec_120["schema_version"] = "1.2.0"
        c12, r12 = analyze.validate_trial_record(rec_120, Path("dummy.json"))
        self.assertEqual(c12, "CORRUPTED_RECORD")
        self.assertIn("1.2.0", r12)

        # non-string fails closed
        rec_num = copy.deepcopy(base_record)
        rec_num["schema_version"] = 1.1
        c_num, _ = analyze.validate_trial_record(rec_num, Path("dummy.json"))
        self.assertEqual(c_num, "CORRUPTED_RECORD")

    def test_4_4_deep_field_rejection_all_numeric_fields(self):
        """Verifies that EVERY field in NUMERIC_METRIC_FIELDS strictly rejects booleans, strings, and collections."""
        base_record = {
            "schema_version": "1.1.0",
            "trial_id": "trial-test",
            "scenario_id": "S0",
            "cleanup_status": {"scenario_restored": True, "baseline_verified": True, "errors": []},
            "capture_metadata": {"pcap_valid": True, "packet_count": 50},
            "network_observations": {"classification": "DIRECT_IPV6", "classification_reason": "ok"},
            "metrics": {},
            "http_outcome": {"status_code": 200, "success": True},
        }

        for field in analyze.NUMERIC_METRIC_FIELDS:
            # 1. Test True
            rec_true = copy.deepcopy(base_record)
            rec_true["metrics"][field] = True
            cat, reason = analyze.validate_trial_record(rec_true, Path("dummy.json"))
            self.assertEqual(cat, "CORRUPTED_RECORD", f"Field {field}=True must fail closed as CORRUPTED_RECORD")

            # 2. Test False
            rec_false = copy.deepcopy(base_record)
            rec_false["metrics"][field] = False
            cat, reason = analyze.validate_trial_record(rec_false, Path("dummy.json"))
            self.assertEqual(cat, "CORRUPTED_RECORD", f"Field {field}=False must fail closed as CORRUPTED_RECORD")

            # 3. Test string
            rec_str = copy.deepcopy(base_record)
            rec_str["metrics"][field] = "invalid_string"
            cat, reason = analyze.validate_trial_record(rec_str, Path("dummy.json"))
            self.assertEqual(cat, "CORRUPTED_RECORD", f"Field {field}='str' must fail closed as CORRUPTED_RECORD")

            # 4. Test dict
            rec_dict = copy.deepcopy(base_record)
            rec_dict["metrics"][field] = {"nested": 123}
            cat, reason = analyze.validate_trial_record(rec_dict, Path("dummy.json"))
            self.assertEqual(cat, "CORRUPTED_RECORD", f"Field {field}={{...}} must fail closed as CORRUPTED_RECORD")

            # 5. In primary_flow section
            rec_pf = copy.deepcopy(base_record)
            rec_pf["primary_flow"] = {field: True}
            cat, reason = analyze.validate_trial_record(rec_pf, Path("dummy.json"))
            self.assertEqual(cat, "CORRUPTED_RECORD", f"primary_flow.{field}=True must fail closed as CORRUPTED_RECORD")

    # =========================================================================
    # SUITE 5: 32-bit Wraparound & Flow Hierarchy
    # =========================================================================

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_5_1_sequence_32bit_wraparound_handshake(self, mock_run, mock_which):
        """Handshake sequence numbers wrapping around 2^32 boundary are validated correctly."""
        client_isn = 0xFFFFFFF0
        server_isn = 0xFFFFFFFA
        # SYN-ACK acknowledges client_isn + 1 = 0xFFFFFFF1
        synack_ack = 0xFFFFFFF1
        # Client final ACK acknowledges server_isn + 1 = (0xFFFFFFFA + 1) = 0xFFFFFFFB
        final_ack_ack = (server_isn + 1) & 0xFFFFFFFF

        lines = [
            self._make_tshark_line(t_epoch=10.000, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", stream="0", seq_raw=client_isn, frame_num=1),
            self._make_tshark_line(t_epoch=10.020, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", stream="0", seq_raw=server_isn, ack_raw=synack_ack, frame_num=2),
            self._make_tshark_line(t_epoch=10.030, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", stream="0", seq_raw=synack_ack, ack_raw=final_ack_ack, frame_num=3),
            self._make_tshark_line(t_epoch=10.031, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", stream="0", seq_raw=synack_ack, ack_raw=final_ack_ack, frame_num=4, tcp_len=50, http_method="GET", http_uri="/", http_response_in="5"),
            self._make_tshark_line(t_epoch=10.040, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", stream="0", seq_raw=final_ack_ack, ack_raw=((synack_ack + 50) & 0xFFFFFFFF), frame_num=5, tcp_len=100, http_code="200", http_request_in="4"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        s0 = dissection["tcp_streams"]["0"]
        self.assertTrue(s0["tcp_handshake_completed"])
        self.assertEqual(s0["handshake_state"], "ESTABLISHED")
        metrics = dissection["metrics"]
        self.assertAlmostEqual(metrics["t_connect_ms"], 30.0, places=2)
        self.assertAlmostEqual(metrics["syn_to_synack_ms"], 20.0, places=2)

    @patch("shutil.which", return_value="/usr/bin/tshark")
    @patch("subprocess.run")
    def test_5_2_root_document_uri_selection_hierarchy(self, mock_run, mock_which):
        """Verifies that /index.html and / win primary flow over non-root ancillary URIs."""
        lines = [
            # Stream 0: /favicon.ico on IPv4 (200 OK)
            self._make_tshark_line(t_epoch=10.000, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0002", sport=40000, dport=80, stream="0", seq_raw=100, frame_num=1),
            self._make_tshark_line(t_epoch=10.010, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0012", sport=80, dport=40000, stream="0", seq_raw=500, ack_raw=101, frame_num=2),
            self._make_tshark_line(t_epoch=10.015, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0010", sport=40000, dport=80, stream="0", seq_raw=101, ack_raw=501, frame_num=3),
            self._make_tshark_line(t_epoch=10.016, ip_src="10.0.1.2", ip_dst=run_trial.SERVER_IPV4, flags="0x0018", sport=40000, dport=80, stream="0", seq_raw=101, ack_raw=501, frame_num=4, tcp_len=50, http_method="GET", http_uri="/favicon.ico", http_response_in="5"),
            self._make_tshark_line(t_epoch=10.020, ip_src=run_trial.SERVER_IPV4, ip_dst="10.0.1.2", flags="0x0018", sport=80, dport=40000, stream="0", seq_raw=501, ack_raw=151, frame_num=5, tcp_len=100, http_code="200", http_request_in="4"),

            # Stream 1: /index.html on IPv6 (200 OK)
            self._make_tshark_line(t_epoch=10.030, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0002", sport=50000, dport=80, stream="1", seq_raw=1000, frame_num=6),
            self._make_tshark_line(t_epoch=10.040, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0012", sport=80, dport=50000, stream="1", seq_raw=5000, ack_raw=1001, frame_num=7),
            self._make_tshark_line(t_epoch=10.045, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0010", sport=50000, dport=80, stream="1", seq_raw=1001, ack_raw=5001, frame_num=8),
            self._make_tshark_line(t_epoch=10.046, ip6_src="2001:db8:1::2", ip6_dst=run_trial.SERVER_IPV6, flags="0x0018", sport=50000, dport=80, stream="1", seq_raw=1001, ack_raw=5001, frame_num=9, tcp_len=50, http_method="GET", http_uri="/index.html", http_response_in="10"),
            self._make_tshark_line(t_epoch=10.050, ip6_src=run_trial.SERVER_IPV6, ip6_dst="2001:db8:1::2", flags="0x0018", sport=80, dport=50000, stream="1", seq_raw=5001, ack_raw=1051, frame_num=10, tcp_len=200, http_code="200", http_request_in="9"),
        ]
        mock_proc = MagicMock()
        mock_proc.stdout = "\n".join(lines) + "\n"
        mock_run.return_value = mock_proc

        dissection = run_trial.dissect_pcap(self.pcap_file, "trial.he.test")
        self.assertEqual(dissection["main_http_flow"]["stream_id"], "1")
        self.assertEqual(dissection["main_http_flow"]["family"], "IPv6")
        self.assertEqual(dissection["primary_flow"]["stream_id"], "1")
        self.assertEqual(dissection["primary_flow"]["winning_family"], "ipv6")


if __name__ == "__main__":
    unittest.main()
