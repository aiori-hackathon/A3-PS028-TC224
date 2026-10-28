#!/usr/bin/env python3
"""
PS-028 Controlled DNS Server: Wildcard DNS & Regression Test Suite
Work Package A6: PS-028 Lab Hardening

Tests:
- Validation of he.test and valid trial-<id>.he.test domain patterns
- Return of controlled A and AAAA addresses
- Preservation of requested hostname in answer RRsets and query logs
- NXDOMAIN responses for invalid/unsupported names
- Live UDP and TCP query resolution and log verification on unprivileged ports
"""

import asyncio
import json
from pathlib import Path
import shutil
import socket
import tempfile
import threading
import time
import unittest

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

import lab.dns_server as dns_server

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_CONFIG = SCRIPT_DIR / "dns_config.json"


class TestWildcardHostnameValidation(unittest.TestCase):
    """Unit tests for domain and trial-<id> hostname validation."""

    def test_apex_zone_matches(self):
        self.assertTrue(dns_server.is_supported_hostname("he.test.", "he.test."))
        self.assertTrue(dns_server.is_supported_hostname("he.test", "he.test."))
        self.assertTrue(dns_server.is_supported_hostname("HE.TEST.", "he.test."))

    def test_valid_trial_hostnames(self):
        valid_cases = [
            "trial-1.he.test.",
            "trial-0.he.test.",
            "trial-42.he.test.",
            "trial-001.he.test.",
            "trial-abc.he.test.",
            "trial-test-run-1.he.test.",
            "trial-client_a.he.test.",
            "trial-uuid-1234-5678.he.test.",
            "TRIAL-1.he.test.",
            "Trial-99.HE.TEST.",
        ]
        for name in valid_cases:
            with self.subTest(name=name):
                self.assertTrue(
                    dns_server.is_supported_hostname(name.lower(), "he.test."),
                    f"Expected {name} to be supported"
                )

    def test_unsupported_or_malformed_hostnames(self):
        invalid_cases = [
            "trial-.he.test.",          # Empty ID
            "trial.he.test.",           # Missing hyphen and ID
            "trial-.he.test",           # Empty ID, no trailing dot
            "trial_1.he.test.",         # Underscore instead of hyphen after trial
            "other.he.test.",           # Arbitrary subdomain
            "www.he.test.",             # www subdomain
            "sub.trial-1.he.test.",     # Multi-level subdomain
            "trial-1.sub.he.test.",     # Multi-level subdomain
            "trial-1.other.test.",      # Different zone
            "google.com.",              # External zone
            "he.test.org.",             # Suffix mismatch
            "",                         # Empty string
            "trial-1@test.he.test.",    # Invalid characters
        ]
        for name in invalid_cases:
            with self.subTest(name=name):
                self.assertFalse(
                    dns_server.is_supported_hostname(name.lower(), "he.test."),
                    f"Expected {name} to be rejected (NXDOMAIN)"
                )


class TestDNSResponseBuilding(unittest.TestCase):
    """Unit tests for response building, address return, and name preservation."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_dns_test_"))
        self.config_path = self.temp_dir / "dns_config.json"
        self.log_path = self.temp_dir / "dns.log"
        self.pid_path = self.temp_dir / "dns.pid"

        with open(DEFAULT_CONFIG, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        self.server = dns_server.ControlledDNSServer(
            bind_ip="127.0.0.1",
            port=15353,
            config_path=self.config_path,
            log_file=self.log_path,
            pid_file=self.pid_path
        )
        self.server.load_configuration()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_apex_a_record(self):
        query = dns.message.make_query("he.test.", "A")
        wire, qname, qtype, rcode_str, delay_s = self.server.build_response(query)
        resp = dns.message.from_wire(wire)

        self.assertEqual(rcode_str, "NOERROR")
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(resp.answer), 1)
        self.assertEqual(resp.answer[0].name.to_text(), "he.test.")
        self.assertEqual(resp.answer[0][0].address, "10.0.2.10")
        self.assertEqual(delay_s, 0.0)

    def test_apex_aaaa_record(self):
        query = dns.message.make_query("he.test.", "AAAA")
        wire, qname, qtype, rcode_str, delay_s = self.server.build_response(query)
        resp = dns.message.from_wire(wire)

        self.assertEqual(rcode_str, "NOERROR")
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(resp.answer), 1)
        self.assertEqual(resp.answer[0].name.to_text(), "he.test.")
        self.assertEqual(resp.answer[0][0].address, "2001:db8:2::10")

    def test_trial_hostname_preserves_requested_name_in_a_answer(self):
        query = dns.message.make_query("trial-42.he.test.", "A")
        wire, qname, qtype, rcode_str, delay_s = self.server.build_response(query)
        resp = dns.message.from_wire(wire)

        self.assertEqual(rcode_str, "NOERROR")
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(qname, "trial-42.he.test.")
        self.assertEqual(len(resp.answer), 1)
        # CRITICAL: Name in answer RRset must match requested trial hostname, NOT apex he.test.
        self.assertEqual(resp.answer[0].name.to_text(), "trial-42.he.test.")
        self.assertEqual(resp.answer[0][0].address, "10.0.2.10")

    def test_trial_hostname_preserves_requested_name_in_aaaa_answer(self):
        query = dns.message.make_query("trial-client-01.he.test.", "AAAA")
        wire, qname, qtype, rcode_str, delay_s = self.server.build_response(query)
        resp = dns.message.from_wire(wire)

        self.assertEqual(rcode_str, "NOERROR")
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(qname, "trial-client-01.he.test.")
        self.assertEqual(len(resp.answer), 1)
        self.assertEqual(resp.answer[0].name.to_text(), "trial-client-01.he.test.")
        self.assertEqual(resp.answer[0][0].address, "2001:db8:2::10")

    def test_unsupported_name_returns_nxdomain(self):
        unsupported = [
            "unknown.he.test.",
            "trial-.he.test.",
            "trial.he.test.",
            "example.org.",
            "bad-trial-1.he.test.",
        ]
        for name in unsupported:
            with self.subTest(name=name):
                query = dns.message.make_query(name, "A")
                wire, qname, qtype, rcode_str, delay_s = self.server.build_response(query)
                resp = dns.message.from_wire(wire)

                self.assertEqual(rcode_str, "NXDOMAIN")
                self.assertEqual(resp.rcode(), dns.rcode.NXDOMAIN)
                self.assertEqual(len(resp.answer), 0)
                self.assertEqual(qname, name)

    def test_unsupported_record_type_returns_nodata(self):
        query = dns.message.make_query("trial-1.he.test.", "TXT")
        wire, qname, qtype, rcode_str, delay_s = self.server.build_response(query)
        resp = dns.message.from_wire(wire)

        self.assertEqual(rcode_str, "NOERROR")
        self.assertEqual(resp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(resp.answer), 0)

    def test_empty_question_returns_formerr(self):
        msg = dns.message.Message()
        wire, qname, qtype, rcode_str, delay_s = self.server.build_response(msg)
        resp = dns.message.from_wire(wire)
        self.assertEqual(resp.rcode(), dns.rcode.FORMERR)


class TestLiveDNSQueries(unittest.TestCase):
    """Live UDP/TCP queries against unprivileged ControlledDNSServer process."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_dns_live_"))
        cls.config_path = cls.temp_dir / "dns_config.json"
        cls.log_path = cls.temp_dir / "dns.log"
        cls.pid_path = cls.temp_dir / "dns.pid"

        # Find an open port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        with open(DEFAULT_CONFIG, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        with open(cls.config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        import subprocess
        import sys
        cls.proc = subprocess.Popen([
            sys.executable,
            str(SCRIPT_DIR / "dns_server.py"),
            "--bind", "127.0.0.1",
            "--port", str(cls.port),
            "--config", str(cls.config_path),
            "--log-file", str(cls.log_path),
            "--pid-file", str(cls.pid_path),
        ])

        # Wait until port is listening
        t0 = time.time()
        ready = False
        while time.time() - t0 < 3.0:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            cls.proc.terminate()
            raise RuntimeError(f"ControlledDNSServer failed to start on port {cls.port}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "proc") and cls.proc:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_live_resolution_and_log_preservation(self):
        # 1. UDP A query for trial hostname
        q_a = dns.message.make_query("trial-10.he.test", "A")
        resp_a = dns.query.udp(q_a, "127.0.0.1", port=self.port, timeout=2.0)
        self.assertEqual(resp_a.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(resp_a.answer), 1)
        self.assertEqual(resp_a.answer[0].name.to_text(), "trial-10.he.test.")
        self.assertEqual(resp_a.answer[0][0].address, "10.0.2.10")

        # 2. UDP AAAA query for trial hostname
        q_aaaa = dns.message.make_query("trial-10.he.test", "AAAA")
        resp_aaaa = dns.query.udp(q_aaaa, "127.0.0.1", port=self.port, timeout=2.0)
        self.assertEqual(resp_aaaa.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(resp_aaaa.answer), 1)
        self.assertEqual(resp_aaaa.answer[0].name.to_text(), "trial-10.he.test.")
        self.assertEqual(resp_aaaa.answer[0][0].address, "2001:db8:2::10")

        # 3. TCP query
        q_tcp = dns.message.make_query("trial-tcp.he.test", "A")
        resp_tcp = dns.query.tcp(q_tcp, "127.0.0.1", port=self.port, timeout=2.0)
        self.assertEqual(resp_tcp.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(resp_tcp.answer), 1)
        self.assertEqual(resp_tcp.answer[0].name.to_text(), "trial-tcp.he.test.")
        self.assertEqual(resp_tcp.answer[0][0].address, "10.0.2.10")

        # 4. NXDOMAIN query
        q_nx = dns.message.make_query("unsupported.he.test", "A")
        resp_nx = dns.query.udp(q_nx, "127.0.0.1", port=self.port, timeout=2.0)
        self.assertEqual(resp_nx.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(len(resp_nx.answer), 0)

        # 5. Verify query logs preserve requested hostnames
        time.sleep(0.1)
        self.assertTrue(self.log_path.exists())
        with open(self.log_path, "r", encoding="utf-8") as f:
            logs = f.read()

        self.assertIn("qname=trial-10.he.test. qtype=A rcode=NOERROR", logs)
        self.assertIn("qname=trial-10.he.test. qtype=AAAA rcode=NOERROR", logs)
        self.assertIn("qname=trial-tcp.he.test. qtype=A rcode=NOERROR", logs)
        self.assertIn("qname=unsupported.he.test. qtype=A rcode=NXDOMAIN", logs)


if __name__ == "__main__":
    unittest.main()
