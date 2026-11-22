#!/usr/bin/env python3
"""
Unit and Regression Test Suite for PS-028 Partner Read-Only Preflight
Workstream C: Partner Replication Readiness
Work Package B: Preflight Gates, Version Matching, State Model, and Remediation
"""

import hashlib
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
                status = partner_preflight.get_helper_deployment_status(
                    checkout_sha_override="abcdef1234567890abcdef1234567890abcdef12"
                )
                self.assertTrue(status["helper_sha_match"])
                self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_VERIFIED)
                self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_METADATA_MISSING)
                self.assertFalse(status["deployment_ready"])
                self.assertFalse(status["ready"])

    def test_matching_helper_hash_and_matching_release_sha_yields_ready(self):
        """Test 1: Matching helper hash plus matching release SHA yields current-release readiness."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"#!/usr/bin/env python3\n# test helper content\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        sudoers_path = self.temp_dir / "ps028-helper"
        sudoers_path.write_text("ps028-sv ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

        release_sha = "8ea73666c9cfb5b9d3b885d42935298532e7950c"
        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": release_sha,
            "target_dir": str(self.temp_dir),
            "file_count": 2,
            "files": [
                {"path": "lab/__init__.py", "sha256": "a" * 64, "mode": "0644"},
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with patch("pwd.getpwnam", return_value=MagicMock()):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                sudoers_path_override=sudoers_path,
                manifest_path_override=manifest_path,
                checkout_sha_override=release_sha,
                expected_release_sha=release_sha,
            )
            self.assertTrue(status["helper_sha_match"])
            self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_VERIFIED)
            self.assertEqual(status["release_sha"], release_sha)
            self.assertEqual(status["expected_release_sha"], release_sha)
            self.assertTrue(status["release_sha_match"])
            self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_CURRENT)
            self.assertTrue(status["deployment_ready"])
            self.assertTrue(status["ready"])

    def test_matching_helper_hash_and_different_release_sha_yields_non_current(self):
        """Test 2: Matching helper hash plus different release SHA produces verified integrity but NON_CURRENT_RELEASE."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"#!/usr/bin/env python3\n# test helper content\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        sudoers_path = self.temp_dir / "ps028-helper"
        sudoers_path.write_text("ps028-sv ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

        manifest_release = "c46dfdbac218dd0a54606067fe9e91aae8e56b31"
        checkout_release = "8ea73666c9cfb5b9d3b885d42935298532e7950c"

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": manifest_release,
            "target_dir": str(self.temp_dir),
            "file_count": 2,
            "files": [
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with patch("pwd.getpwnam", return_value=MagicMock()):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                sudoers_path_override=sudoers_path,
                manifest_path_override=manifest_path,
                checkout_sha_override=checkout_release,
                expected_release_sha=checkout_release,
            )
            self.assertTrue(status["helper_sha_match"])
            self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_VERIFIED)
            self.assertEqual(status["release_sha"], manifest_release)
            self.assertEqual(status["expected_release_sha"], checkout_release)
            self.assertFalse(status["release_sha_match"])
            self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_NON_CURRENT)
            self.assertFalse(status["deployment_ready"])
            self.assertFalse(status["ready"])

    def test_jarvis_audit_fixture_matching_helper_hash_non_current_release(self):
        """Test 3: Exact JARVIS audit evidence fixture."""
        jarvis_checkout_sha = "8ea73666c9cfb5b9d3b885d42935298532e7950c"
        jarvis_manifest_release_sha = "c46dfdbac218dd0a54606067fe9e91aae8e56b31"
        jarvis_helper_sha256 = "c8d996bc10f9c7a8a622e4970684b075be0e9c650d0724ca29a07e63c2ce4fca"

        helper_path = self.temp_dir / "privileged_helper.py"
        helper_path.write_bytes(b"dummy")

        sudoers_path = self.temp_dir / "ps028-helper"
        sudoers_path.write_text("ps028-sv ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": jarvis_manifest_release_sha,
            "target_dir": "/usr/local/libexec/ps028",
            "file_count": 14,
            "files": [
                {"path": "privileged_helper.py", "sha256": jarvis_helper_sha256, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        original_sha256 = hashlib.sha256

        def fake_sha256(data=b""):
            m = MagicMock()
            m.hexdigest.return_value = jarvis_helper_sha256
            return m

        with patch("hashlib.sha256", side_effect=fake_sha256), \
             patch("pwd.getpwnam", return_value=MagicMock()):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                sudoers_path_override=sudoers_path,
                manifest_path_override=manifest_path,
                checkout_sha_override=jarvis_checkout_sha,
                expected_release_sha=jarvis_checkout_sha,
            )
            # Helper file matches manifest
            self.assertTrue(status["helper_sha_match"])
            self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_VERIFIED)
            # Release SHA differs
            self.assertEqual(status["release_sha"], jarvis_manifest_release_sha)
            self.assertEqual(status["expected_release_sha"], jarvis_checkout_sha)
            self.assertFalse(status["release_sha_match"])
            self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_NON_CURRENT)
            # Deployment readiness remains False
            self.assertFalse(status["deployment_ready"])
            self.assertFalse(status["ready"])

            # Verify remediation advice generated
            mock_rep = {
                "os_and_kernel": {"compatible": True},
                "python_and_libraries": {"compatible": True, "dependencies": {}},
                "system_tools": {"compatible": True, "tools": {}},
                "browsers": {"all_exact_match": True, "browsers": {}},
                "privileged_helper": status,
                "storage": {"sufficient_for_campaign": True},
                "configuration_files": {"all_present": True},
            }
            actions = partner_preflight.compute_remediation_actions(mock_rep)
            non_current_actions = [a for a in actions if "differs from current checkout SHA" in a["issue"]]
            self.assertEqual(len(non_current_actions), 1)
            self.assertIn("Update the partner checkout to the approved commit", non_current_actions[0]["remediation"])
            self.assertIn("./lab/deploy_privileged_helper.sh --dry-run", non_current_actions[0]["remediation"])
            self.assertIn("obtain operator authorization", non_current_actions[0]["remediation"])

    def test_genuine_helper_hash_mismatch_reported_as_integrity_failure(self):
        """Test 4: Genuine helper hash mismatch is reported as INTEGRITY_FAILED."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_path.write_bytes(b"content-a\n")

        sudoers_path = self.temp_dir / "ps028-helper"
        sudoers_path.write_text("ps028-sv ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

        release_sha = "8ea73666c9cfb5b9d3b885d42935298532e7950c"
        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": release_sha,
            "files": [
                {"path": "privileged_helper.py", "sha256": "f" * 64, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with patch("pwd.getpwnam", return_value=MagicMock()):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                sudoers_path_override=sudoers_path,
                manifest_path_override=manifest_path,
                checkout_sha_override=release_sha,
            )
            self.assertFalse(status["helper_sha_match"])
            self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_FAILED)
            self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_CURRENT)
            self.assertFalse(status["deployment_ready"])
            self.assertFalse(status["ready"])

    def test_unreadable_helper_permission_denied_reported_as_permission_required(self):
        """Test 5: Permission-denied helper read is reported as INTEGRITY_UNVERIFIABLE_PERMISSION_REQUIRED."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_path.write_bytes(b"helper content\n")

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_path.write_text(json.dumps({
            "release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "files": [{"path": "privileged_helper.py", "sha256": "a" * 64, "mode": "0750"}]
        }), encoding="utf-8")

        with patch.object(Path, "read_bytes", side_effect=PermissionError(f"Permission denied: {helper_path}")):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                manifest_path_override=manifest_path,
                checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
            )
            self.assertFalse(status["helper_sha_match"])
            self.assertIsNone(status["helper_executable"]["sha256"])
            self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_UNVERIFIABLE_PERMISSION_REQUIRED)
            self.assertFalse(status["deployment_ready"])
            self.assertIn("Permission denied", status["helper_executable"]["read_error"])

            mock_rep = {
                "os_and_kernel": {"compatible": True},
                "python_and_libraries": {"compatible": True, "dependencies": {}},
                "system_tools": {"compatible": True, "tools": {}},
                "browsers": {"all_exact_match": True, "browsers": {}},
                "privileged_helper": status,
                "storage": {"sufficient_for_campaign": True},
                "configuration_files": {"all_present": True},
            }
            actions = partner_preflight.compute_remediation_actions(mock_rep)
            perm_actions = [a for a in actions if "Permission denied" in a["issue"]]
            self.assertEqual(len(perm_actions), 1)
            self.assertIn("sudo python3 lab/partner_preflight.py", perm_actions[0]["remediation"])

    def test_legacy_top_level_helper_sha_manifest_verifies_integrity_fails_release(self):
        """Test 6: Legacy top-level helper_sha256 manifest verifies helper integrity but fails strict release verification."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"#!/usr/bin/env python3\n# legacy test\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        sudoers_path = self.temp_dir / "ps028-helper"
        sudoers_path.write_text("ps028-sv ALL=(ALL) NOPASSWD: ALL\n", encoding="utf-8")

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "helper_sha256": helper_sha
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with patch("pwd.getpwnam", return_value=MagicMock()):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                sudoers_path_override=sudoers_path,
                manifest_path_override=manifest_path,
                checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
            )
            self.assertTrue(status["helper_sha_match"])
            self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_VERIFIED)
            self.assertIsNone(status["release_sha"])
            self.assertIsNone(status["release_sha_match"])
            self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_METADATA_MISSING)
            self.assertFalse(status["deployment_ready"])
            self.assertFalse(status["ready"])

    def test_missing_release_sha_fails_closed(self):
        """Test 7: Missing release SHA fails closed (RELEASE_METADATA_MISSING)."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"content\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "files": [
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        status = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertTrue(status["helper_sha_match"])
        self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_VERIFIED)
        self.assertIsNone(status["release_sha"])
        self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_METADATA_MISSING)
        self.assertFalse(status["deployment_ready"])

    def test_invalid_release_sha_fails_closed(self):
        """Test 8: Invalid release SHA format fails closed (RELEASE_METADATA_INVALID)."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"content\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": "not-a-valid-40-hex-sha",
            "files": [
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        status = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_METADATA_INVALID)
        self.assertFalse(status["release_sha_match"])
        self.assertFalse(status["deployment_ready"])

    def test_unavailable_git_checkout_sha_fails_closed(self):
        """Test 9: Unavailable Git checkout SHA fails closed (CHECKOUT_SHA_UNAVAILABLE)."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"content\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "files": [
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        with patch("subprocess.run", side_effect=Exception("git failed")), \
             patch.dict("os.environ", {}, clear=True):
            status = partner_preflight.get_helper_deployment_status(
                helper_path_override=helper_path,
                manifest_path_override=manifest_path,
                checkout_sha_override=None,
            )
            self.assertEqual(status["release_verification_status"], partner_preflight.RELEASE_CHECKOUT_UNAVAILABLE)
            self.assertIsNone(status["release_sha_match"])
            self.assertFalse(status["deployment_ready"])

    def test_stale_or_conflicting_env_pin_cannot_override_checkout(self):
        """Test 10: Stale or conflicting environment pin cannot override actual repository checkout."""
        actual_checkout = "8ea73666c9cfb5b9d3b885d42935298532e7950c"
        stale_pin = "c46dfdbac218dd0a54606067fe9e91aae8e56b31"

        # Conflicting pin
        with patch.dict("os.environ", {"PS028_EXPECTED_RELEASE_SHA": stale_pin}):
            resolved = partner_preflight.get_checkout_sha(checkout_sha_override=actual_checkout)
            self.assertIsNone(resolved)

        # Malformed pin
        with patch.dict("os.environ", {"PS028_EXPECTED_RELEASE_SHA": "invalid_pin"}):
            resolved_bad = partner_preflight.get_checkout_sha(checkout_sha_override=actual_checkout)
            self.assertIsNone(resolved_bad)

        # Matching pin passes
        with patch.dict("os.environ", {"PS028_EXPECTED_RELEASE_SHA": actual_checkout}):
            resolved_ok = partner_preflight.get_checkout_sha(checkout_sha_override=actual_checkout)
            self.assertEqual(resolved_ok, actual_checkout)

    def test_human_readable_report_current_and_non_current_diagnostics(self):
        """Test 11: Current-release and non-current-release diagnostics in human-readable report."""
        import io
        from contextlib import redirect_stdout

        # Current release report
        current_report = partner_preflight.run_partner_preflight(
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c"
        )
        current_report["privileged_helper"] = {
            "service_account_ps028_sv": True,
            "helper_executable": {"installed": True},
            "sudoers_drop_in": {"installed": True},
            "deployment_manifest": {"installed": True},
            "helper_integrity_status": partner_preflight.INTEGRITY_VERIFIED,
            "release_verification_status": partner_preflight.RELEASE_CURRENT,
            "release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "expected_release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "deployment_ready": True,
        }
        f1 = io.StringIO()
        with redirect_stdout(f1):
            partner_preflight.print_human_report(current_report)
        out1 = f1.getvalue()
        self.assertIn("Installed & Verified (SHA-256 matches manifest entry) [OK]", out1)
        self.assertIn("Current Approved Release (8ea73666c9cfb5b9d3b885d42935298532e7950c) [OK]", out1)
        self.assertIn("Deploy Ready : [OK] (Ready for Authorization)", out1)

        # JARVIS non-current release report
        jarvis_report = partner_preflight.run_partner_preflight(
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c"
        )
        jarvis_report["privileged_helper"] = {
            "service_account_ps028_sv": True,
            "helper_executable": {"installed": True},
            "sudoers_drop_in": {"installed": True},
            "deployment_manifest": {"installed": True},
            "helper_integrity_status": partner_preflight.INTEGRITY_VERIFIED,
            "release_verification_status": partner_preflight.RELEASE_NON_CURRENT,
            "release_sha": "c46dfdbac218dd0a54606067fe9e91aae8e56b31",
            "expected_release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "deployment_ready": False,
        }
        f2 = io.StringIO()
        with redirect_stdout(f2):
            partner_preflight.print_human_report(jarvis_report)
        out2 = f2.getvalue()
        self.assertIn("Installed & Verified (SHA-256 matches manifest entry) [OK]", out2)
        self.assertIn("Non-Current Release (Installed: c46dfdbac218dd0a54606067fe9e91aae8e56b31, Checkout: 8ea73666c9cfb5b9d3b885d42935298532e7950c) [ACTION REQUIRED]", out2)
        self.assertIn("Deploy Ready : [ACTION REQUIRED]", out2)

    def test_manifest_missing_helper_entry(self):
        """Test 12a: Manifest without privileged_helper.py in files array is flagged malformed."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_path.write_bytes(b"content\n")

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "files": [
                {"path": "lab/__init__.py", "sha256": "a" * 64, "mode": "0644"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        status = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertFalse(status["deployment_ready"])
        self.assertFalse(status["helper_sha_match"])
        self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_UNVERIFIABLE_MANIFEST_INVALID)
        self.assertIn("Missing 'privileged_helper.py' entry", status["deployment_manifest"]["error"])

    def test_manifest_duplicate_helper_entries(self):
        """Test 12b: Manifest with multiple privileged_helper.py entries in files array is rejected."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_content = b"content\n"
        helper_path.write_bytes(helper_content)
        helper_sha = hashlib.sha256(helper_content).hexdigest()

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "release_sha": "8ea73666c9cfb5b9d3b885d42935298532e7950c",
            "files": [
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"},
                {"path": "privileged_helper.py", "sha256": helper_sha, "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        status = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertFalse(status["deployment_ready"])
        self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_UNVERIFIABLE_MANIFEST_INVALID)
        self.assertIn("Duplicate 'privileged_helper.py' entries", status["deployment_manifest"]["error"])

    def test_manifest_invalid_sha256_format(self):
        """Test 12c: Manifest with non-hex or non-64-character SHA is rejected as malformed."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_path.write_bytes(b"content\n")

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_data = {
            "files": [
                {"path": "privileged_helper.py", "sha256": "not-a-valid-sha", "mode": "0750"}
            ]
        }
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        status = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertFalse(status["deployment_ready"])
        self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_UNVERIFIABLE_MANIFEST_INVALID)
        self.assertIn("Invalid SHA-256", status["deployment_manifest"]["error"])

    def test_manifest_malformed_json_and_non_dict(self):
        """Test 12d: Manifest with broken JSON syntax or non-object root is rejected as malformed."""
        helper_path = self.temp_dir / "privileged_helper.py"
        helper_path.write_bytes(b"content\n")

        manifest_path = self.temp_dir / "deployment_manifest.json"
        manifest_path.write_text("{broken json", encoding="utf-8")

        status = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertFalse(status["deployment_ready"])
        self.assertEqual(status["helper_integrity_status"], partner_preflight.INTEGRITY_UNVERIFIABLE_MANIFEST_INVALID)
        self.assertIn("Malformed manifest JSON", status["deployment_manifest"]["error"])

        manifest_path.write_text("[1, 2, 3]", encoding="utf-8")
        status2 = partner_preflight.get_helper_deployment_status(
            helper_path_override=helper_path,
            manifest_path_override=manifest_path,
            checkout_sha_override="8ea73666c9cfb5b9d3b885d42935298532e7950c",
        )
        self.assertEqual(status2["helper_integrity_status"], partner_preflight.INTEGRITY_UNVERIFIABLE_MANIFEST_INVALID)
        self.assertIn("Manifest JSON root must be an object/dict", status2["deployment_manifest"]["error"])

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
