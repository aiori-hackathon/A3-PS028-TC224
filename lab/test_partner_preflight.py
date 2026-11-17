#!/usr/bin/env python3
"""
Unit and Regression Test Suite for PS-028 Partner Read-Only Preflight
Workstream C: Partner Replication Readiness
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lab import partner_preflight


class TestPartnerPreflight(unittest.TestCase):
    """Verifies non-mutating partner preflight reports and safety properties."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_partner_preflight_test_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_get_os_and_kernel_structure(self):
        """get_os_and_kernel returns expected keys without side effects."""
        info = partner_preflight.get_os_and_kernel()
        self.assertIn("system", info)
        self.assertIn("distribution", info)
        self.assertIn("kernel_release", info)
        self.assertIn("architecture", info)
        self.assertIn("is_linux", info)
        self.assertIn("is_wsl2", info)
        self.assertIn("compatible", info)

    def test_get_python_and_libraries_detects_installed(self):
        """get_python_and_libraries correctly inspects dnspython and PyYAML."""
        info = partner_preflight.get_python_and_libraries()
        self.assertIn("python_version", info)
        self.assertIn("dependencies", info)
        self.assertIn("dnspython", info["dependencies"])
        self.assertIn("pyyaml", info["dependencies"])

    def test_get_system_tools_reports_tool_dictionary(self):
        """get_system_tools reports presence and paths of required utilities."""
        tools = partner_preflight.get_system_tools()
        self.assertIn("compatible", tools)
        self.assertIn("tools", tools)
        for tname in ["ip", "tc", "nft", "tshark", "nginx", "tcpdump"]:
            self.assertIn(tname, tools["tools"])
            self.assertIn("found", tools["tools"][tname])
            self.assertIn("path", tools["tools"][tname])

    def test_get_browser_runtimes_structure(self):
        """get_browser_runtimes reports Google Chrome and Mozilla Firefox."""
        browsers = partner_preflight.get_browser_runtimes()
        self.assertIn("browsers", browsers)
        self.assertIn("google-chrome", browsers["browsers"])
        self.assertIn("firefox", browsers["browsers"])
        self.assertEqual(browsers["browsers"]["google-chrome"]["pinned_expected"], "156.0.8078.73")
        self.assertEqual(browsers["browsers"]["firefox"]["pinned_expected"], "159.0")

    def test_get_storage_status_verifies_minimum_space(self):
        """get_storage_status asserts sufficient disk space against 2 GB requirement."""
        storage = partner_preflight.get_storage_status(self.temp_dir)
        self.assertIn("sufficient_for_campaign", storage)
        self.assertIn("free_gb", storage)
        self.assertEqual(storage["required_gb"], 2.0)

    def test_get_helper_deployment_status_structure(self):
        """get_helper_deployment_status checks expected helper and sudoers paths."""
        helper = partner_preflight.get_helper_deployment_status()
        self.assertIn("helper_executable", helper)
        self.assertIn("sudoers_drop_in", helper)
        self.assertIn("deployment_manifest", helper)
        self.assertIn("ready", helper)

    def test_get_configuration_files_present_in_repo(self):
        """get_configuration_files confirms presence of core scenario files."""
        configs = partner_preflight.get_configuration_files()
        self.assertIn("all_present", configs)
        self.assertIn("files", configs)
        self.assertTrue(configs["files"]["lab/scenarios.yaml"])
        self.assertTrue(configs["files"]["lab/dns_config.json"])

    def test_run_partner_preflight_end_to_end_dict(self):
        """run_partner_preflight produces a complete structured readiness report."""
        report = partner_preflight.run_partner_preflight()
        self.assertIn("overall_status", report)
        self.assertIn(report["overall_status"], ("READY", "ACTION_REQUIRED"))
        self.assertIn("os_and_kernel", report)
        self.assertIn("python_and_libraries", report)
        self.assertIn("system_tools", report)
        self.assertIn("browsers", report)
        self.assertIn("storage", report)
        self.assertIn("privileged_helper", report)
        self.assertIn("configuration_files", report)

    def test_cli_json_output_mode(self):
        """CLI invocation with --json outputs valid parseable JSON."""
        out_file = self.temp_dir / "preflight_output.json"
        with patch("sys.argv", ["partner_preflight.py", "--json", "-o", str(out_file)]):
            exit_code = partner_preflight.main()
            self.assertIn(exit_code, (0, 1))
            self.assertTrue(out_file.is_file())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertIn("overall_status", data)


if __name__ == "__main__":
    unittest.main()
