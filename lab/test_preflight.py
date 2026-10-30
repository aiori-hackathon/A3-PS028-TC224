#!/usr/bin/env python3
"""
PS-028 Non-Destructive Dependency Preflight: Test Suite
Work Package A6: PS-028 Lab Hardening

Tests:
- Manifest parsing and completeness
- Successful clean-pass verification in healthy environment
- Accurate detection and reporting of missing binaries
- Accurate detection and reporting of missing/mismatched packages
- Accurate detection and reporting of Python version discrepancies
- Configuration integrity and syntax verification
"""

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import lab.preflight as preflight

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


class TestPreflightExecution(unittest.TestCase):
    """Test non-destructive dependency preflight checks."""

    def test_run_preflight_passes_on_current_system(self):
        """Live preflight check on healthy system must return status PASS."""
        report = preflight.run_preflight()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["failures"]["missing_required_binaries"]), 0)
        self.assertEqual(len(report["failures"]["missing_packages"]), 0)
        self.assertEqual(len(report["failures"]["missing_python"]), 0)
        self.assertEqual(len(report["failures"]["invalid_configs"]), 0)

    def test_manifest_contains_all_study_guide_categories(self):
        """Manifest must include networking, DNS, nftables, Python, Nginx, and capture tools."""
        manifest = preflight.parse_system_packages_manifest()

        # Networking
        for pkg in ("iproute2", "iputils-ping", "procps", "curl", "bc"):
            self.assertIn(pkg, manifest, f"Missing networking package: {pkg}")

        # DNS
        for pkg in ("bind9-dnsutils", "python3-dnspython"):
            self.assertIn(pkg, manifest, f"Missing DNS package: {pkg}")

        # nftables
        self.assertIn("nftables", manifest, "Missing nftables package")

        # Nginx
        self.assertIn("nginx", manifest, "Missing nginx package")

        # Python
        for pkg in ("python3", "python3-yaml"):
            self.assertIn(pkg, manifest, f"Missing Python package: {pkg}")

        # Capture tools
        self.assertIn("tcpdump", manifest, "Missing capture tool: tcpdump")
        self.assertIn("tshark", manifest, "Missing capture tool: tshark")

    @patch("shutil.which")
    def test_missing_required_binary_fails_preflight(self, mock_which):
        """Simulate missing 'nft' binary -> must report FAIL and list missing binary."""
        def fake_which(cmd):
            if cmd == "nft":
                return None
            return f"/usr/bin/{cmd}"

        mock_which.side_effect = fake_which
        binaries = preflight.check_binaries()
        nft_entry = next(b for b in binaries if b["command"] == "nft")
        self.assertFalse(nft_entry["found"])

        with patch("lab.preflight.check_binaries", return_value=binaries):
            report = preflight.run_preflight()
            self.assertEqual(report["status"], "FAIL")
            self.assertIn("nft", report["failures"]["missing_required_binaries"])

    @patch("lab.preflight.check_system_packages")
    def test_missing_system_package_fails_preflight(self, mock_check_pkgs):
        """Simulate uninstalled package -> must report FAIL."""
        mock_check_pkgs.return_value = [
            {"package": "nftables", "expected_version": "1.0.9", "actual_version": None, "installed": False, "version_match": False}
        ]
        report = preflight.run_preflight()
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("nftables", report["failures"]["missing_packages"])

    @patch("lab.preflight.check_python_dependencies")
    def test_python_version_mismatch_fails_preflight(self, mock_py_deps):
        """Simulate dnspython version mismatch -> must report FAIL."""
        mock_py_deps.return_value = [
            {"module": "dns", "package": "python3-dnspython", "installed": True, "version": "2.5.0", "expected_version": "2.6.1", "version_match": False}
        ]
        report = preflight.run_preflight()
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("dns", report["failures"]["missing_python"])

    def test_invalid_nginx_conf_fails_preflight(self):
        """Simulate nginx.conf with missing keepalive_timeout 0 -> must report invalid config."""
        temp_dir = Path(tempfile.mkdtemp(prefix="ps028_preflight_test_"))
        try:
            bad_conf = temp_dir / "nginx.conf"
            bad_conf.write_text("worker_processes 1;\nkeepalive_timeout 65;\n", encoding="utf-8")

            with patch.object(preflight, "NGINX_CONF", bad_conf):
                configs = preflight.check_configuration_files()
                ngx_entry = next(c for c in configs if "nginx.conf" in c["file"])
                self.assertFalse(ngx_entry["valid"])
                self.assertIn("keepalive_timeout 0", ngx_entry["error"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
