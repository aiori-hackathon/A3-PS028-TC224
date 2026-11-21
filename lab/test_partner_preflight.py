#!/usr/bin/env python3
"""
Unit and Regression Test Suite for PS-028 Partner Read-Only Preflight
Workstream C: Partner Replication Readiness
Work Package B: Preflight Gates, Version Matching, State Model, and Remediation
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lab import partner_preflight


class TestPartnerPreflight(unittest.TestCase):
    """Verifies non-mutating partner preflight reports, strict version gates, and state model."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_partner_preflight_test_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_parse_semver(self):
        """Verifies semver parsing from tool and library version strings."""
        self.assertEqual(partner_preflight.parse_semver("6.1.0-1ubuntu1"), (6, 1, 0))
        self.assertEqual(partner_preflight.parse_semver("4.2.2"), (4, 2, 2))
        self.assertEqual(partner_preflight.parse_semver("1.24.0"), (1, 24, 0))
        self.assertEqual(partner_preflight.parse_semver("invalid"), (0,))

    def test_compare_versions(self):
        """Verifies version comparisons with equal and differing lengths."""
        self.assertTrue(partner_preflight.compare_versions("6.1.0", "6.1.0"))
        self.assertTrue(partner_preflight.compare_versions("6.2.0", "6.1.0"))
        self.assertTrue(partner_preflight.compare_versions("4.99.4", "4.99.0"))
        self.assertTrue(partner_preflight.compare_versions("8.5.0", "7.80.0"))
        self.assertFalse(partner_preflight.compare_versions("6.0.9", "6.1.0"))
        self.assertFalse(partner_preflight.compare_versions("4.0.0", "4.2.0"))

    def test_extract_tool_version_string(self):
        """Verifies extraction of normalized version numbers across all 7 tools."""
        self.assertEqual(
            partner_preflight.extract_tool_version_string("ip", "ip utility, iproute2-6.1.0, libbpf 1.3.0"),
            "6.1.0"
        )
        self.assertEqual(
            partner_preflight.extract_tool_version_string("tc", "tc utility, iproute2-6.1.0, libbpf 1.3.0"),
            "6.1.0"
        )
        self.assertEqual(
            partner_preflight.extract_tool_version_string("nft", "nftables v1.0.9 (Old Doc Yak #3)"),
            "1.0.9"
        )
        self.assertEqual(
            partner_preflight.extract_tool_version_string("tshark", "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)"),
            "4.2.2"
        )
        self.assertEqual(
            partner_preflight.extract_tool_version_string("tcpdump", "tcpdump version 4.99.4"),
            "4.99.4"
        )
        self.assertEqual(
            partner_preflight.extract_tool_version_string("nginx", "nginx version: nginx/1.24.0 (Ubuntu)"),
            "1.24.0"
        )
        self.assertEqual(
            partner_preflight.extract_tool_version_string("curl", "curl 8.5.0 (x86_64-pc-linux-gnu)..."),
            "8.5.0"
        )

    def test_get_os_and_kernel_structure(self):
        """get_os_and_kernel returns expected keys and identifies Ubuntu 24.04."""
        info = partner_preflight.get_os_and_kernel()
        self.assertIn("system", info)
        self.assertIn("distribution", info)
        self.assertIn("kernel_release", info)
        self.assertIn("architecture", info)
        self.assertIn("is_linux", info)
        self.assertIn("is_wsl2", info)
        self.assertIn("compatible", info)
        self.assertIn("is_ubuntu_2404", info)
        self.assertIn("qualification_note", info)

    def test_os_rejects_non_ubuntu_distributions(self):
        """Preflight identifies non-Ubuntu-24.04 distributions as incompatible."""
        mock_release = "PRETTY_NAME=\"Fedora Linux 40\"\nID=fedora\nVERSION_ID=40\n"
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_release), \
             patch("platform.system", return_value="Linux"):
            info = partner_preflight.get_os_and_kernel()
            self.assertFalse(info["compatible"])
            self.assertFalse(info["is_ubuntu_2404"])
            self.assertIn("Unsupported Linux distribution", info["qualification_note"])

    def test_get_python_and_libraries_detects_installed(self):
        """get_python_and_libraries correctly inspects dnspython and PyYAML."""
        info = partner_preflight.get_python_and_libraries()
        self.assertIn("python_version", info)
        self.assertIn("dependencies", info)
        self.assertIn("dnspython", info["dependencies"])
        self.assertIn("pyyaml", info["dependencies"])

    def test_python_rejects_incompatible_dnspython(self):
        """Preflight rejects dnspython versions differing from exact pin 2.6.1."""
        with patch.dict("sys.modules", {"dns": MagicMock(__version__="2.5.0", __file__="/fake/dns.py")}):
            info = partner_preflight.get_python_and_libraries()
            self.assertFalse(info["dependencies"]["dnspython"]["compatible"])
            self.assertFalse(info["compatible"])

    def test_get_system_tools_reports_tool_dictionary_and_versions(self):
        """get_system_tools reports presence, extracted versions, and compatibility."""
        tools = partner_preflight.get_system_tools()
        self.assertIn("compatible", tools)
        self.assertIn("tools", tools)
        for tname in ["ip", "tc", "nft", "tshark", "nginx", "tcpdump", "curl"]:
            self.assertIn(tname, tools["tools"])
            self.assertIn("found", tools["tools"][tname])
            self.assertIn("path", tools["tools"][tname])
            self.assertIn("version_compatible", tools["tools"][tname])

    def test_tools_rejects_sub_minimum_version(self):
        """Preflight rejects tools whose extracted version is below minimum."""
        with patch("shutil.which", return_value="/usr/bin/nft"), \
             patch("lab.partner_preflight._query_binary_version", return_value="nftables v0.9.8"):
            tools = partner_preflight.get_system_tools()
            self.assertFalse(tools["tools"]["nft"]["version_compatible"])
            self.assertEqual(tools["tools"]["nft"]["status"], "VERSION_INCOMPATIBLE")

    def test_get_browser_runtimes_rejects_version_mismatch(self):
        """Mismatched browser versions are strictly marked VERSION_MISMATCH and not ready."""
        with patch("lab.partner_preflight.shutil.which") as mock_which, \
             patch("lab.partner_preflight._query_binary_version") as mock_query, \
             patch("os.access", return_value=True), \
             patch.object(Path, "is_file", return_value=True):

            def fake_which(cmd):
                return f"/usr/bin/{cmd}"

            def fake_query(cmd_path, flag="--version"):
                if "chrome" in cmd_path:
                    return "Google Chrome 120.0.6099.109"
                if "firefox" in cmd_path:
                    return "Mozilla Firefox 159.0"
                return None

            mock_which.side_effect = fake_which
            mock_query.side_effect = fake_query

            browsers = partner_preflight.get_browser_runtimes()
            self.assertFalse(browsers["all_exact_match"])
            self.assertFalse(browsers["chrome_ready"])
            self.assertTrue(browsers["firefox_ready"])
            self.assertEqual(browsers["browsers"]["google-chrome"]["status"], "VERSION_MISMATCH")

    def test_get_browser_runtimes_detects_snap_confinement(self):
        """Snap-confined browsers are marked SNAP_CONFINED and not ready."""
        with patch("lab.partner_preflight.shutil.which") as mock_which, \
             patch("lab.partner_preflight._query_binary_version") as mock_query, \
             patch("os.access", return_value=True), \
             patch.object(Path, "is_file", return_value=True):

            def fake_which(cmd):
                if "chrome" in cmd:
                    return "/snap/bin/google-chrome"
                return "/usr/bin/firefox"

            def fake_query(cmd_path, flag="--version"):
                if "chrome" in cmd_path:
                    return "Google Chrome 156.0.8078.73"
                if "firefox" in cmd_path:
                    return "Mozilla Firefox 159.0"
                return None

            mock_which.side_effect = fake_which
            mock_query.side_effect = fake_query

            browsers = partner_preflight.get_browser_runtimes()
            self.assertFalse(browsers["all_exact_match"])
            self.assertTrue(browsers["browsers"]["google-chrome"]["is_snap"])
            self.assertFalse(browsers["browsers"]["google-chrome"]["supports_dns_isolation"])
            self.assertEqual(browsers["browsers"]["google-chrome"]["status"], "SNAP_CONFINED")

    def test_get_browser_runtimes_accepts_exact_pinned_builds(self):
        """Exact pinned builds for both Chrome and Firefox pass browser toolchain gate."""
        with patch("lab.partner_preflight.shutil.which") as mock_which, \
             patch("lab.partner_preflight._query_binary_version") as mock_query, \
             patch("os.access", return_value=True), \
             patch.object(Path, "is_file", return_value=True):

            def fake_which(cmd):
                return f"/usr/bin/{cmd}"

            def fake_query(cmd_path, flag="--version"):
                if "chrome" in cmd_path:
                    return "Google Chrome 156.0.8078.73"
                if "firefox" in cmd_path:
                    return "Mozilla Firefox 159.0"
                return None

            mock_which.side_effect = fake_which
            mock_query.side_effect = fake_query

            browsers = partner_preflight.get_browser_runtimes()
            self.assertTrue(browsers["all_exact_match"])
            self.assertTrue(browsers["chrome_ready"])
            self.assertTrue(browsers["firefox_ready"])
            self.assertEqual(browsers["browsers"]["google-chrome"]["status"], "READY")
            self.assertEqual(browsers["browsers"]["firefox"]["status"], "READY")

    def test_get_storage_status_verifies_minimum_space(self):
        """get_storage_status asserts sufficient disk space against 2 GB requirement."""
        storage = partner_preflight.get_storage_status(self.temp_dir)
        self.assertIn("sufficient_for_campaign", storage)
        self.assertIn("free_gb", storage)
        self.assertEqual(storage["required_gb"], 2.0)

    def test_get_helper_deployment_status_verifies_integrity(self):
        """Helper deployment status verifies SHA-256 against deployment manifest."""
        mock_manifest = json.dumps({
            "helper_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        })
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "read_bytes", return_value=b"fake-helper-content"), \
             patch.object(Path, "read_text", return_value=mock_manifest), \
             patch("os.stat") as mock_stat, \
             patch("hashlib.sha256") as mock_hash:

            stat_obj = MagicMock()
            stat_obj.st_mode = 0o755
            mock_stat.return_value = stat_obj

            mock_hasher = MagicMock()
            mock_hasher.hexdigest.return_value = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            mock_hash.return_value = mock_hasher

            with patch("pwd.getpwnam", return_value=MagicMock()):
                status = partner_preflight.get_helper_deployment_status()
                self.assertTrue(status["ready"])
                self.assertTrue(status["deployment_manifest"]["sha_match"])

    def test_readiness_state_model_five_states(self):
        """Verifies the 5-state readiness model transitions."""
        base_os = {"compatible": True, "distribution": "Ubuntu 24.04", "distro_version_id": "24.04"}
        base_py = {"compatible": True, "dependencies": {}}
        base_tools = {"compatible": True, "tools": {}}
        base_caps = {"compatible": True}
        base_storage = {"sufficient_for_campaign": True}
        base_configs = {"all_present": True, "files": {}}

        # State 1: ACTION_REQUIRED (storage failed)
        with patch("lab.partner_preflight.get_os_and_kernel", return_value=base_os), \
             patch("lab.partner_preflight.get_python_and_libraries", return_value=base_py), \
             patch("lab.partner_preflight.get_system_tools", return_value=base_tools), \
             patch("lab.partner_preflight.get_system_capabilities", return_value=base_caps), \
             patch("lab.partner_preflight.get_storage_status", return_value={"sufficient_for_campaign": False, "free_gb": 0.5, "required_gb": 2.0}), \
             patch("lab.partner_preflight.get_configuration_files", return_value=base_configs), \
             patch("lab.partner_preflight.get_browser_runtimes", return_value={"all_exact_match": True, "browsers": {}}), \
             patch("lab.partner_preflight.get_helper_deployment_status", return_value={"ready": True}):

            rep = partner_preflight.run_partner_preflight()
            self.assertEqual(rep["readiness_state"], partner_preflight.STATE_ACTION_REQUIRED)
            self.assertEqual(rep["overall_status"], "ACTION_REQUIRED")
            self.assertTrue(len(rep["remediation_actions"]) > 0)

        # State 2: HOST_PREREQUISITES_READY (host prereqs pass, but browsers & helper not ready)
        with patch("lab.partner_preflight.get_os_and_kernel", return_value=base_os), \
             patch("lab.partner_preflight.get_python_and_libraries", return_value=base_py), \
             patch("lab.partner_preflight.get_system_tools", return_value=base_tools), \
             patch("lab.partner_preflight.get_system_capabilities", return_value=base_caps), \
             patch("lab.partner_preflight.get_storage_status", return_value=base_storage), \
             patch("lab.partner_preflight.get_configuration_files", return_value=base_configs), \
             patch("lab.partner_preflight.get_browser_runtimes", return_value={"all_exact_match": False, "browsers": {}}), \
             patch("lab.partner_preflight.get_helper_deployment_status", return_value={"ready": False, "service_account_ps028_sv": False, "helper_executable": {}, "sudoers_drop_in": {}, "deployment_manifest": {}}):

            rep = partner_preflight.run_partner_preflight()
            self.assertEqual(rep["readiness_state"], partner_preflight.STATE_HOST_PREREQUISITES_READY)
            self.assertEqual(rep["overall_status"], "ACTION_REQUIRED")

        # State 3: BROWSER_TOOLCHAIN_READY (browsers exact match, helper not ready)
        with patch("lab.partner_preflight.get_os_and_kernel", return_value=base_os), \
             patch("lab.partner_preflight.get_python_and_libraries", return_value=base_py), \
             patch("lab.partner_preflight.get_system_tools", return_value=base_tools), \
             patch("lab.partner_preflight.get_system_capabilities", return_value=base_caps), \
             patch("lab.partner_preflight.get_storage_status", return_value=base_storage), \
             patch("lab.partner_preflight.get_configuration_files", return_value=base_configs), \
             patch("lab.partner_preflight.get_browser_runtimes", return_value={"all_exact_match": True, "browsers": {}}), \
             patch("lab.partner_preflight.get_helper_deployment_status", return_value={"ready": False, "service_account_ps028_sv": False, "helper_executable": {}, "sudoers_drop_in": {}, "deployment_manifest": {}}):

            rep = partner_preflight.run_partner_preflight()
            self.assertEqual(rep["readiness_state"], partner_preflight.STATE_BROWSER_TOOLCHAIN_READY)
            self.assertEqual(rep["overall_status"], "ACTION_REQUIRED")

        # State 4: HELPER_DEPLOYMENT_READY (helper ready, browsers not exact match)
        with patch("lab.partner_preflight.get_os_and_kernel", return_value=base_os), \
             patch("lab.partner_preflight.get_python_and_libraries", return_value=base_py), \
             patch("lab.partner_preflight.get_system_tools", return_value=base_tools), \
             patch("lab.partner_preflight.get_system_capabilities", return_value=base_caps), \
             patch("lab.partner_preflight.get_storage_status", return_value=base_storage), \
             patch("lab.partner_preflight.get_configuration_files", return_value=base_configs), \
             patch("lab.partner_preflight.get_browser_runtimes", return_value={"all_exact_match": False, "browsers": {}}), \
             patch("lab.partner_preflight.get_helper_deployment_status", return_value={"ready": True}):

            rep = partner_preflight.run_partner_preflight()
            self.assertEqual(rep["readiness_state"], partner_preflight.STATE_HELPER_DEPLOYMENT_READY)
            self.assertEqual(rep["overall_status"], "ACTION_REQUIRED")

        # State 5: REPLICATION_READY_FOR_AUTHORIZATION (everything passes!)
        with patch("lab.partner_preflight.get_os_and_kernel", return_value=base_os), \
             patch("lab.partner_preflight.get_python_and_libraries", return_value=base_py), \
             patch("lab.partner_preflight.get_system_tools", return_value=base_tools), \
             patch("lab.partner_preflight.get_system_capabilities", return_value=base_caps), \
             patch("lab.partner_preflight.get_storage_status", return_value=base_storage), \
             patch("lab.partner_preflight.get_configuration_files", return_value=base_configs), \
             patch("lab.partner_preflight.get_browser_runtimes", return_value={"all_exact_match": True, "browsers": {}}), \
             patch("lab.partner_preflight.get_helper_deployment_status", return_value={"ready": True}):

            rep = partner_preflight.run_partner_preflight()
            self.assertEqual(rep["readiness_state"], partner_preflight.STATE_REPLICATION_READY_FOR_AUTHORIZATION)
            self.assertEqual(rep["overall_status"], "READY")
            self.assertEqual(len(rep["remediation_actions"]), 0)

    def test_cli_json_output_mode(self):
        """CLI invocation with --json outputs valid parseable JSON."""
        out_file = self.temp_dir / "preflight_output.json"
        with patch("sys.argv", ["partner_preflight.py", "--json", "-o", str(out_file)]):
            exit_code = partner_preflight.main()
            self.assertIn(exit_code, (0, 1))
            self.assertTrue(out_file.is_file())
            data = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertIn("readiness_state", data)
            self.assertIn("overall_status", data)


if __name__ == "__main__":
    unittest.main()
