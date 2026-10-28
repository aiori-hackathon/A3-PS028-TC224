#!/usr/bin/env python3
"""
PS-028 HTTP Isolation and Nginx Configuration Tests
Work Package A6: PS-028 Lab Hardening

Tests:
- Verification of keepalive_timeout 0 in lab/nginx.conf
- Live HTTP 200 verification over IPv4 and IPv6
- Fresh connection verification (Connection: close, socket EOF after each request)
"""

import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
NGINX_CONF = SCRIPT_DIR / "nginx.conf"
WWW_INDEX = SCRIPT_DIR / "www" / "index.html"


class TestNginxConfiguration(unittest.TestCase):
    """Static analysis and syntax verification of lab/nginx.conf."""

    def test_keepalive_timeout_is_zero(self):
        """Verify keepalive_timeout 0 is configured for HTTP isolation."""
        self.assertTrue(NGINX_CONF.is_file(), f"Missing {NGINX_CONF}")
        content = NGINX_CONF.read_text(encoding="utf-8")

        # Match 'keepalive_timeout 0;' directive
        match = re.search(r"\bkeepalive_timeout\s+0\s*;", content)
        self.assertIsNotNone(
            match,
            "lab/nginx.conf must contain 'keepalive_timeout 0;' to enforce connection isolation"
        )

        # Ensure no other keepalive_timeout directive overrides it
        all_matches = re.findall(r"\bkeepalive_timeout\s+([^;]+);", content)
        self.assertEqual(
            all_matches, ["0"],
            f"Expected only 'keepalive_timeout 0;', found: {all_matches}"
        )


class TestLiveHTTPIsolation(unittest.TestCase):
    """Live verification of HTTP 200 over IPv4/IPv6 and connection closing."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_nginx_test_"))
        cls.pid_file = cls.temp_dir / "nginx.pid"
        cls.access_log = cls.temp_dir / "access.log"
        cls.error_log = cls.temp_dir / "error.log"

        # Find an open port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        # Generate isolated unprivileged Nginx test configuration
        cls.test_conf = cls.temp_dir / "nginx_test.conf"
        cls.test_conf.write_text(f"""
worker_processes 1;
pid {cls.pid_file};
error_log {cls.error_log} info;

events {{
    worker_connections 64;
}}

http {{
    access_log {cls.access_log};
    sendfile on;
    keepalive_timeout 0;

    server {{
        listen 127.0.0.1:{cls.port};
        listen [::1]:{cls.port};
        server_name _;

        root {SCRIPT_DIR / "www"};
        index index.html;

        location / {{
            try_files $uri $uri/ =404;
        }}
    }}
}}
""", encoding="utf-8")

        # Start Nginx
        cls.proc = subprocess.Popen([
            "nginx",
            "-c", str(cls.test_conf),
            "-p", str(REPO_ROOT),
        ])

        # Wait until port is open
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
            cls.tearDownClass()
            raise RuntimeError(f"Nginx test instance failed to bind port {cls.port}")

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["nginx", "-c", str(cls.test_conf), "-s", "stop"], check=False)
        time.sleep(0.1)
        if cls.temp_dir.exists():
            import shutil
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_ipv4_http_200_and_connection_close(self):
        """Verify IPv4 returns 200 OK and closes the TCP connection immediately."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", self.port))
        try:
            req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            s.sendall(req)

            resp_bytes = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_bytes += chunk

            resp_text = resp_bytes.decode("utf-8", errors="replace")
            self.assertIn("HTTP/1.1 200 OK", resp_text)
            self.assertIn("Connection: close", resp_text)
            self.assertIn("PS-028 Happy Eyeballs", resp_text)

            # Confirm socket is closed by server (recv returns b"")
            extra = s.recv(1024)
            self.assertEqual(extra, b"")
        finally:
            s.close()

    def test_ipv6_http_200_and_connection_close(self):
        """Verify IPv6 returns 200 OK and closes the TCP connection immediately."""
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("::1", self.port))
        try:
            req = b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n"
            s.sendall(req)

            resp_bytes = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_bytes += chunk

            resp_text = resp_bytes.decode("utf-8", errors="replace")
            self.assertIn("HTTP/1.1 200 OK", resp_text)
            self.assertIn("Connection: close", resp_text)
            self.assertIn("PS-028 Happy Eyeballs", resp_text)

            # Confirm socket is closed by server
            extra = s.recv(1024)
            self.assertEqual(extra, b"")
        finally:
            s.close()

    def test_fresh_connection_between_consecutive_requests(self):
        """Verify consecutive requests require establishing fresh connections."""
        for attempt in range(3):
            with self.subTest(attempt=attempt):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(("127.0.0.1", self.port))
                try:
                    s.sendall(b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                    data = s.recv(4096).decode("utf-8", errors="replace")
                    self.assertIn("HTTP/1.1 200 OK", data)
                    self.assertIn("Connection: close", data)
                finally:
                    s.close()


if __name__ == "__main__":
    unittest.main()
