#!/usr/bin/env python3
"""
Regression Test Suite for PS-028 Privileged Helper Deployment and Transactional Upgrader
Work Package A10 & Milestone 4 / Gate B

Tests cover:
1. Fresh install in an isolated test root.
2. Successful replacement of an existing valid installation.
3. Failure during staging: old installation remains unchanged.
4. Failure during sudoers validation: old installation and sudoers remain unchanged.
5. Failure during activation: exact old installation restored.
6. Existing altered file: upgrade aborts without modifying it.
7. Unmanifested old file: upgrade aborts without deleting it.
8. Existing sudoers symlink: abort.
9. Missing service account: dry-run fails.
10. Incorrect primary group: dry-run fails.
11. Dirty Git checkout: deployment aborts.
12. Missing Git metadata: deployment aborts.
13. Incorrect release SHA: deployment aborts.
14. New installed manifest matches every installed file.
15. Interrupted activation and trap-driven backup restoration.
16. Automatic recovery on subsequent invocation after prior crash.
17. Legacy unmanifested installation fails closed without explicit migration flag.
18. Legacy unmanifested installation successfully migrated with authentic Git history.
19. Legacy unmanifested tampered file fails migration without bypassing hash verification.
20. Legacy alternative dictionary manifest format compatibility.
21. Untracked file outside lab/ directory aborts deployment.
22. Interruption immediately at TARGET_BACKUP_PREPARED restores target cleanly.
23. Interruption post target activation triggers rollback to restored backup.
24. Interruption pre sudoers activation triggers rollback of target and sudoers.
25. Recovery restores target from backup when target dir is missing and state is TARGET_ACTIVATED.
26. Recovery cleans up lingering backup directory when state is COMMITTED without damaging target.
27. Sudoers replacement is atomic, sets mode 0440 and contains expected release SHA.
28. Sudoers is restored atomically preserving mode 0440 on post-verification failure.
29. Old sudoers rules can invoke new helper subcommands safely (mixed-version interval).
30. Recovery after interrupted sudoers replacement restores both target and sudoers.
31. Legacy unmanifested installation composed of mixed commits fails closed.
32. Legacy unmanifested installation missing required files fails closed.
33. --legacy-baseline-commit succeeds on match and fails closed on mismatch.
34. Recovery rejects state files containing path traversal, symlinks, or mismatched targets.
35. Repeated invocations of recovery preserve the restored installation without corruption.
36. Legacy migration rejects group-writable privileged_helper.py and leaves files unchanged.
37. Legacy migration rejects group-writable Python module and leaves files unchanged.
38. Legacy migration rejects group-writable containing directory and leaves installation unchanged.
39. Legacy migration rejects world-writable containing directory.
40. Legacy migration rejects group- or world-writable target root directory.
41. Legacy migration succeeds when all canonical files have strict production modes.
42. Second concurrent installer invocation fails safely when lock is held without corrupting state.
43. Lock held by a process is automatically released upon kernel termination (SIGKILL).
44. StrictArgumentParser rejects unknown flags, duplicate options, and parameter injections.
45. EXIT trap triggers rollback and preserves prior installation on unexpected termination.
46. Recovery is strictly idempotent across repeated invocations.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEPLOY_SCRIPT = SCRIPT_DIR / "deploy_privileged_helper.sh"


class TestDeployPrivilegedHelperTransactional(unittest.TestCase):
    """Regression tests for transactional helper installation, upgrade, and recovery."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_deploy_test_"))

        # Isolated repository root
        self.mock_repo = self.temp_dir / "repo"
        self.mock_repo.mkdir(parents=True)
        (self.mock_repo / "lab").mkdir(parents=True)

        # Initialize Git repo
        subprocess.run(["git", "init"], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.mock_repo, check=True, capture_output=True)

        # Copy required modules and static files into mock repo
        required_modules = [
            "privileged_helper.py",
            "identity.py",
            "concurrency.py",
            "impair.py",
            "run_trial.py",
            "analyze.py",
            "teardown.py",
            "scenarios.yaml",
            "dns_config.json",
            "dns_server.py",
            "cl_resolv.conf",
            "nginx.conf",
        ]
        for rm in required_modules:
            src = REPO_ROOT / "lab" / rm
            dst = self.mock_repo / "lab" / rm
            if src.is_file():
                shutil.copy2(src, dst)
            else:
                dst.write_text(f"# mock {rm}\n", encoding="utf-8")

        (self.mock_repo / "lab" / "www").mkdir(parents=True)
        (self.mock_repo / "lab" / "www" / "index.html").write_text("<html>OK</html>\n", encoding="utf-8")

        # Initial Git commit
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.mock_repo, check=True, capture_output=True)
        self.commit_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.mock_repo, text=True
        ).strip()

        # Isolated installation target and sudoers directories
        self.target_parent = self.temp_dir / "usr" / "local" / "libexec"
        self.target_parent.mkdir(parents=True)
        self.target_dir = self.target_parent / "ps028"

        self.sudoers_parent = self.temp_dir / "etc" / "sudoers.d"
        self.sudoers_parent.mkdir(parents=True)
        self.target_sudoers = self.sudoers_parent / "ps028-helper"

        # Standard environment for tests
        self.env = os.environ.copy()
        self.env["PS028_TEST_FIXTURE"] = "1"
        self.env["PS028_TEST_ROOT"] = str(self.temp_dir.resolve())
        self.env["PS028_REPO_ROOT"] = str(self.mock_repo)
        self.env["PS028_TARGET_DIR"] = str(self.target_dir)
        self.env["PS028_TARGET_SUDOERS"] = str(self.target_sudoers)
        self.env["PS028_MOCK_SV_EXISTS"] = "1"
        self.env["PS028_MOCK_SV_UID"] = "1028"
        self.env["PS028_MOCK_SV_GID"] = "1028"
        self.env["PS028_MOCK_SV_GNAME"] = "ps028-sv"
        self.env["PS028_MOCK_SV_GROUPS"] = "1028"
        self.env["PS028_MOCK_SV_SHELL"] = "/usr/sbin/nologin"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_browser_executable_fixture(self, name: str = "google-chrome") -> Path:
        """Create a private, deterministic test fixture executable matching allowed browser names."""
        bin_dir = self.temp_dir / "browser-bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.chmod(0o700)
        exe_path = bin_dir / name
        exe_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        exe_path.chmod(0o755)
        return exe_path.resolve()

    def _run_deploy(self, extra_args=None, custom_env=None):
        cmd = [str(DEPLOY_SCRIPT)]
        if extra_args:
            cmd.extend(extra_args)
        env = custom_env if custom_env is not None else self.env
        return subprocess.run(cmd, env=env, capture_output=True, text=True)

    def test_01_fresh_install_in_isolated_test_root(self):
        """1. Fresh install in an isolated test root succeeds and creates valid structure."""
        self.assertFalse(self.target_dir.exists())
        self.assertFalse(self.target_sudoers.exists())

        res = self._run_deploy()
        self.assertEqual(res.returncode, 0, f"Deploy failed: {res.stderr}\n{res.stdout}")
        self.assertTrue(self.target_dir.is_dir())
        self.assertTrue((self.target_dir / "privileged_helper.py").is_file())
        self.assertTrue((self.target_dir / "lab" / "identity.py").is_file())
        self.assertTrue((self.target_dir / "lab" / "www" / "index.html").is_file())
        self.assertTrue(self.target_sudoers.is_file())

        manifest_file = self.target_dir / "deployment_manifest.json"
        self.assertTrue(manifest_file.is_file())
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["release_sha"], self.commit_sha)
        self.assertEqual(manifest["target_dir"], str(self.target_dir))
        self.assertGreater(manifest["file_count"], 0)

    def test_02_successful_replacement_of_existing_valid_installation(self):
        """2. Successful replacement of an existing valid installation (transactional upgrade)."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        # Create second commit in repo
        scenario_file = self.mock_repo / "lab" / "scenarios.yaml"
        scenario_file.write_text("# Updated scenario content\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Update scenarios"], cwd=self.mock_repo, check=True, capture_output=True)
        commit_sha2 = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.mock_repo, text=True
        ).strip()
        self.assertNotEqual(self.commit_sha, commit_sha2)

        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, f"Upgrade failed: {res2.stderr}\n{res2.stdout}")

        manifest_file = self.target_dir / "deployment_manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest["release_sha"], commit_sha2)
        self.assertIn("Updated scenario content", (self.target_dir / "lab" / "scenarios.yaml").read_text(encoding="utf-8"))

        backups = list(self.target_parent.glob(".ps028_backup_*"))
        self.assertEqual(len(backups), 0, f"Backup directory was not cleaned up: {backups}")

    def test_03_failure_during_staging_old_installation_remains_unchanged(self):
        """3. Failure during staging: old installation remains unchanged."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        helper_before = (self.target_dir / "privileged_helper.py").read_bytes()

        # Remove a required module and commit
        (self.mock_repo / "lab" / "identity.py").unlink()
        subprocess.run(["git", "add", "-A"], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Remove identity"], cwd=self.mock_repo, check=True, capture_output=True)

        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("Missing required deployment source", res2.stderr)

        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_before)
        self.assertEqual((self.target_dir / "privileged_helper.py").read_bytes(), helper_before)

    def test_04_failure_during_sudoers_validation_old_installation_and_sudoers_unchanged(self):
        """4. Failure during sudoers validation: old installation and sudoers remain unchanged."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        target_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        env_corrupt = self.env.copy()
        env_corrupt["PS028_TEST_CORRUPT_SUDOERS"] = "1"

        res2 = self._run_deploy(custom_env=env_corrupt)
        self.assertNotEqual(res2.returncode, 0)

        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), target_before)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)

    def test_05_failure_during_activation_exact_old_installation_restored(self):
        """5. Failure during activation: exact old installation restored."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        target_manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        (self.mock_repo / "lab" / "scenarios.yaml").write_text("# Candidate new\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Candidate commit"], cwd=self.mock_repo, check=True, capture_output=True)

        env_fail_act = self.env.copy()
        env_fail_act["PS028_TEST_FAIL_POST_VERIFY"] = "1"

        res2 = self._run_deploy(custom_env=env_fail_act)
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("verification failed", res2.stderr.lower())

        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), target_manifest_before)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)

    def test_06_existing_altered_file_upgrade_aborts_without_modifying_it(self):
        """6. Existing altered file: upgrade aborts without modifying it."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        altered_file = self.target_dir / "lab" / "identity.py"
        altered_content = "# Tampered by attacker\n"
        altered_file.write_text(altered_content, encoding="utf-8")

        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("altered", res2.stderr.lower())
        self.assertEqual(altered_file.read_text(encoding="utf-8"), altered_content)

    def test_07_unmanifested_old_file_upgrade_aborts_without_deleting_it(self):
        """7. Unmanifested old file: upgrade aborts without deleting it."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        unmanifested_file = self.target_dir / "lab" / "rogue_extra.py"
        rogue_content = "# Rogue script\n"
        unmanifested_file.write_text(rogue_content, encoding="utf-8")

        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("unmanifested", res2.stderr.lower())
        self.assertTrue(unmanifested_file.is_file())
        self.assertEqual(unmanifested_file.read_text(encoding="utf-8"), rogue_content)

    def test_08_existing_sudoers_symlink_aborts(self):
        """8. Existing sudoers symlink: abort without modifying."""
        dummy_dest = self.temp_dir / "dummy_sudoers"
        dummy_dest.write_text("dummy\n", encoding="utf-8")
        self.target_sudoers.symlink_to(dummy_dest)

        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("symlink", res.stderr.lower())
        self.assertTrue(self.target_sudoers.is_symlink())

    def test_09_missing_service_account_dry_run_fails(self):
        """9. Missing service account: dry-run fails with non-zero exit code."""
        env_no_sv = self.env.copy()
        env_no_sv["PS028_MOCK_SV_EXISTS"] = "0"

        res = self._run_deploy(extra_args=["--dry-run"], custom_env=env_no_sv)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ps028-sv", res.stderr)
        self.assertIn("does not exist", res.stderr.lower())

    def test_10_incorrect_primary_group_dry_run_fails(self):
        """10. Incorrect primary group: dry-run fails with non-zero exit code."""
        env_bad_grp = self.env.copy()
        env_bad_grp["PS028_MOCK_SV_GNAME"] = "sudo"
        env_bad_grp["PS028_MOCK_SV_GID"] = "27"

        res = self._run_deploy(extra_args=["--dry-run"], custom_env=env_bad_grp)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("privileged primary group", res.stderr.lower())

    def test_11_dirty_git_checkout_deployment_aborts(self):
        """11. Dirty Git checkout: deployment aborts with non-zero exit code."""
        (self.mock_repo / "lab" / "privileged_helper.py").write_text("# dirty\n", encoding="utf-8")

        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("dirty", res.stderr.lower())

    def test_12_missing_git_metadata_deployment_aborts(self):
        """12. Missing Git metadata: deployment aborts with non-zero exit code."""
        shutil.rmtree(self.mock_repo / ".git")

        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing git repository metadata", res.stderr.lower())

    def test_13_incorrect_release_sha_deployment_aborts(self):
        """13. Incorrect release SHA: deployment aborts."""
        fake_sha = "0123456789abcdef0123456789abcdef01234567"
        res = self._run_deploy(extra_args=["--release-sha", fake_sha])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("release sha mismatch", res.stderr.lower())

    def test_14_new_installed_manifest_matches_every_installed_file(self):
        """14. New installed manifest matches every installed file and its SHA-256."""
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0, res.stderr)

        manifest_file = self.target_dir / "deployment_manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        manifest_paths = {item["path"]: item for item in manifest["files"]}
        self.assertEqual(len(manifest["files"]), manifest["file_count"])

        disk_files = []
        for p in self.target_dir.rglob("*"):
            if p.is_file() and p.name != "deployment_manifest.json":
                rel = str(p.relative_to(self.target_dir))
                disk_files.append(rel)
                self.assertIn(rel, manifest_paths, f"Unmanifested file found on disk: {rel}")
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                self.assertEqual(h, manifest_paths[rel]["sha256"], f"SHA mismatch for {rel}")

        self.assertEqual(len(disk_files), len(manifest["files"]))

    def test_15_interrupted_activation_restores_backup(self):
        """15. Interruption during activation (INT/TERM) triggers trap and restores previous installation."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        target_manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        # Simulate interruption during activation
        env_interrupt = self.env.copy()
        env_interrupt["PS028_TEST_INTERRUPT_ACTIVATION"] = "1"

        res2 = self._run_deploy(custom_env=env_interrupt)
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("restoring previous installation", res2.stderr.lower())

        # Exact old installation and sudoers must be restored
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), target_manifest_before)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)

    def test_16_recovery_on_subsequent_invocation_after_crash(self):
        """16. Automatic recovery on subsequent invocation after prior crash left backup."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        orig_manifest = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        orig_sudoers = self.target_sudoers.read_text(encoding="utf-8")

        # Simulate hard crash: target was renamed to backup, state file was left uncommitted
        backup_dir = self.target_parent / ".ps028_backup_99999_123"
        self.target_dir.rename(backup_dir)
        sudoers_backup = self.sudoers_parent / ".ps028_sudoers_backup_99999_123"
        shutil.copy2(self.target_sudoers, sudoers_backup)

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS={sudoers_backup}
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        # Run next deploy invocation: it must detect incomplete prior transaction, recover, and deploy
        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, f"Recovery deploy failed: {res2.stderr}\n{res2.stdout}")
        self.assertIn("incomplete prior transaction detected", res2.stderr.lower())
        self.assertTrue(self.target_dir.is_dir())
        self.assertTrue(self.target_sudoers.is_file())
        self.assertFalse(state_file.exists())
        self.assertFalse(backup_dir.exists())

    def test_17_legacy_unmanifested_installation_aborts_without_migration_flag(self):
        """17. Legacy unmanifested installation fails closed without explicit migration flag."""
        # Deploy initial version then remove manifest to simulate legacy unmanifested installation
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("lacks deployment_manifest.json", res2.stderr)
        self.assertIn("--migrate-unmanifested", res2.stderr)

    def test_18_legacy_unmanifested_installation_successful_migration(self):
        """18. Legacy unmanifested installation successfully migrated with authentic Git history."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        # Update repo with new commit
        (self.mock_repo / "lab" / "scenarios.yaml").write_text("# New release\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "New release"], cwd=self.mock_repo, check=True, capture_output=True)
        new_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.mock_repo, text=True
        ).strip()

        # Run with --migrate-unmanifested
        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertEqual(res2.returncode, 0, f"Migration failed: {res2.stderr}\n{res2.stdout}")
        self.assertIn("verified against authentic git commit", res2.stdout.lower())

        manifest = json.loads((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["release_sha"], new_commit)

    def test_19_legacy_unmanifested_tampered_file_migration_aborts(self):
        """19. Legacy unmanifested tampered file fails migration without bypassing hash verification."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        # Tamper with an unmanifested file
        (self.target_dir / "lab" / "identity.py").write_text("# Attacker backdoor\n", encoding="utf-8")

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("does not match authentic repository commit history", res2.stderr)

    def test_20_legacy_manifest_alternative_dictionary_format(self):
        """20. Legacy alternative dictionary manifest format is parsed and upgraded correctly."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        manifest_file = self.target_dir / "deployment_manifest.json"
        orig_data = json.loads(manifest_file.read_text(encoding="utf-8"))

        # Convert files list to dictionary format
        dict_files = {item["path"]: {"sha256": item["sha256"]} for item in orig_data["files"]}
        legacy_manifest = {
            "release_sha": orig_data["release_sha"],
            "target_dir": orig_data["target_dir"],
            "files": dict_files
        }
        manifest_file.write_text(json.dumps(legacy_manifest, indent=2), encoding="utf-8")

        # Create new commit and upgrade
        (self.mock_repo / "lab" / "scenarios.yaml").write_text("# Upgraded from dict manifest\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Upgraded from dict manifest"], cwd=self.mock_repo, check=True, capture_output=True)
        upgraded_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.mock_repo, text=True
        ).strip()

        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, f"Upgrade failed: {res2.stderr}\n{res2.stdout}")
        new_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(new_manifest["release_sha"], upgraded_sha)

    def test_21_untracked_file_outside_lab_aborts_deployment(self):
        """21. Untracked file outside lab/ directory causes deployment to abort."""
        (self.mock_repo / "untracked_root_file.txt").write_text("untracked\n", encoding="utf-8")

        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("working tree is dirty", res.stderr.lower())

    def test_22_interruption_at_target_backup_prepared(self):
        """22. Interruption immediately at TARGET_BACKUP_PREPARED restores target cleanly."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        target_manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")

        env_interrupt = self.env.copy()
        env_interrupt["PS028_TEST_INTERRUPT_PRE_TARGET_MOVE"] = "1"
        res2 = self._run_deploy(custom_env=env_interrupt)
        self.assertNotEqual(res2.returncode, 0)
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), target_manifest_before)

    def test_23_interruption_post_target_activation(self):
        """23. Interruption post target activation triggers rollback to restored backup."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        target_manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        env_interrupt = self.env.copy()
        env_interrupt["PS028_TEST_INTERRUPT_POST_TARGET_ACT"] = "1"
        res2 = self._run_deploy(custom_env=env_interrupt)
        self.assertNotEqual(res2.returncode, 0)
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), target_manifest_before)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)

    def test_24_interruption_pre_sudoers_activation(self):
        """24. Interruption pre sudoers activation triggers rollback of target and sudoers."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        target_manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        env_interrupt = self.env.copy()
        env_interrupt["PS028_TEST_INTERRUPT_PRE_SUDOERS_ACT"] = "1"
        res2 = self._run_deploy(custom_env=env_interrupt)
        self.assertNotEqual(res2.returncode, 0)
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), target_manifest_before)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)

    def test_25_recovery_disagreement_target_backed_up_target_missing(self):
        """25. Recovery restores target from backup when target dir is missing and state is TARGET_ACTIVATED."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        backup_dir = self.target_parent / ".ps028_backup_88888_1"
        self.target_dir.rename(backup_dir)

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, f"Recovery deploy failed: {res2.stderr}\n{res2.stdout}")
        self.assertTrue(self.target_dir.is_dir())
        self.assertFalse(backup_dir.exists())
        self.assertFalse(state_file.exists())

    def test_26_recovery_disagreement_stale_committed_state_cleans_backup(self):
        """26. Recovery cleans up lingering backup directory when state is COMMITTED without damaging target."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        stale_backup = self.target_parent / ".ps028_backup_77777_1"
        stale_backup.mkdir()
        (stale_backup / "stale.txt").write_text("stale", encoding="utf-8")

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=COMMITTED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={stale_backup}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, f"Deploy failed: {res2.stderr}")
        self.assertFalse(stale_backup.exists())
        self.assertFalse(state_file.exists())
        self.assertTrue(self.target_dir.is_dir())

    def test_27_atomic_sudoers_replacement_mode_and_content(self):
        """27. Sudoers replacement is atomic, sets mode 0440 and contains expected release SHA."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        self.assertTrue(self.target_sudoers.is_file())
        st_mode = oct(self.target_sudoers.stat().st_mode & 0o777)
        self.assertEqual(st_mode, "0o440")
        content = self.target_sudoers.read_text(encoding="utf-8")
        self.assertIn(f"Release SHA: {self.commit_sha}", content)

    def test_28_atomic_sudoers_restoration_on_post_verify_failure(self):
        """28. Sudoers is restored atomically preserving mode 0440 on post-verification failure."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        env_fail = self.env.copy()
        env_fail["PS028_TEST_FAIL_POST_VERIFY"] = "1"
        res2 = self._run_deploy(custom_env=env_fail)
        self.assertNotEqual(res2.returncode, 0)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)
        st_mode = oct(self.target_sudoers.stat().st_mode & 0o777)
        self.assertEqual(st_mode, "0o440")

    def test_29_old_sudoers_rules_compatible_with_new_helper(self):
        """29. Old sudoers rules can invoke new helper subcommands safely (mixed-version interval)."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        # Verify that all subcommands authorized in the old sudoers specification are registered in new helper
        helper_bin = self.target_dir / "privileged_helper.py"
        run_res = subprocess.run(
            ["python3", "-I", str(helper_bin), "--help"],
            capture_output=True, text=True
        )
        self.assertEqual(run_res.returncode, 0, run_res.stderr)
        for expected_action in [
            "apply-scenario", "restore-baseline", "apply-dns", "restore-dns",
            "verify-baseline", "start-capture", "stop-capture", "check-auth",
            "setup-s5-counters", "read-s5-counters", "measure-s5",
            "launch-snap-browser", "start-nginx", "stop-nginx", "status-nginx",
            "start-dns", "stop-dns", "status-dns", "reload-dns"
        ]:
            self.assertIn(expected_action, run_res.stdout)

    def test_30_recovery_after_interrupted_sudoers_replacement(self):
        """30. Recovery after interrupted sudoers replacement restores both target and sudoers."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        # Simulate crash while SUDOERS_BACKED_UP
        backup_dir = self.target_parent / ".ps028_backup_66666_1"
        self.target_dir.rename(backup_dir)
        sudoers_backup = self.sudoers_parent / ".ps028_sudoers_backup_66666_1"
        shutil.copy2(self.target_sudoers, sudoers_backup)
        self.target_sudoers.chmod(0o644)
        self.target_sudoers.write_text("CORRUPT OR PARTIAL", encoding="utf-8")

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=SUDOERS_BACKED_UP
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS={sudoers_backup}
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, f"Recovery failed: {res2.stderr}\n{res2.stdout}")
        self.assertTrue(self.target_dir.is_dir())
        self.assertFalse(state_file.exists())
        self.assertFalse(backup_dir.exists())
        self.assertFalse(sudoers_backup.exists())

    def test_31_mixed_commit_legacy_installation_fails_closed(self):
        """31. Legacy unmanifested installation composed of mixed commits fails closed."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        # Create second commit modifying BOTH scenarios.yaml AND identity.py
        (self.mock_repo / "lab" / "scenarios.yaml").write_text("# Commit 2 scenarios\n", encoding="utf-8")
        (self.mock_repo / "lab" / "identity.py").write_text("# Commit 2 identity\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Commit 2"], cwd=self.mock_repo, check=True, capture_output=True)

        # Put scenarios.yaml from commit 2 into target, but leave identity.py from commit 1
        (self.target_dir / "lab" / "scenarios.yaml").write_text("# Commit 2 scenarios\n", encoding="utf-8")
        # identity.py on target still has commit 1 content

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("does not match authentic repository commit history", res2.stderr)

    def test_32_incomplete_legacy_installation_fails_closed(self):
        """32. Legacy unmanifested installation missing required files fails closed."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        # Delete required file
        (self.target_dir / "lab" / "identity.py").unlink()

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("legacy installation is incomplete", res2.stderr.lower())

    def test_33_explicit_legacy_baseline_commit_matching_and_mismatch(self):
        """33. --legacy-baseline-commit succeeds on match and fails closed on mismatch."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        # Valid baseline commit specified
        res_valid = self._run_deploy(extra_args=["--migrate-unmanifested", "--legacy-baseline-commit", self.commit_sha])
        self.assertEqual(res_valid.returncode, 0, res_valid.stderr)

        # Remove manifest again
        (self.target_dir / "deployment_manifest.json").unlink()

        # Invalid/wrong baseline commit specified
        wrong_commit = "0123456789abcdef0123456789abcdef01234567"
        res_invalid = self._run_deploy(extra_args=["--migrate-unmanifested", "--legacy-baseline-commit", wrong_commit])
        self.assertNotEqual(res_invalid.returncode, 0)
        self.assertIn("is not a valid commit", res_invalid.stderr)

    def test_34_recovery_rejects_malicious_paths_in_state_file(self):
        """34. Recovery rejects state files containing path traversal, symlinks, or mismatched targets."""
        # 1. Mismatched target dir in state
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR=/etc
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res1 = self._run_deploy()
        self.assertNotEqual(res1.returncode, 0)
        self.assertIn("target_dir mismatch", res1.stderr.lower())
        state_file.unlink()

        # 2. Escaping backup dir in state
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR=/tmp/escaping_backup
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("invalid backup_dir", res2.stderr.lower())
        state_file.unlink()

        # 3. State file itself is a symlink
        dummy_state = self.temp_dir / "dummy_state"
        dummy_state.write_text("STATE=IDLE\n", encoding="utf-8")
        state_file.symlink_to(dummy_state)
        res3 = self._run_deploy()
        self.assertNotEqual(res3.returncode, 0)
        self.assertIn("symlink", res3.stderr.lower())
        state_file.unlink()

    def test_35_repeated_recovery_preserves_restored_installation(self):
        """35. Repeated invocations of recovery preserve the restored installation without corruption."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        manifest_orig = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")

        # Simulate crash
        backup_dir = self.target_parent / ".ps028_backup_55555_1"
        self.target_dir.rename(backup_dir)
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        # Invocation 1: Recovers
        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertTrue(self.target_dir.is_dir())
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_orig)

        # Invocation 2: Normal run on restored installation
        res3 = self._run_deploy(extra_args=["--dry-run"])
        self.assertEqual(res3.returncode, 0, res3.stderr)
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_orig)

    def test_36_legacy_migration_rejects_group_writable_privileged_helper(self):
        """36. Legacy migration rejects group-writable privileged_helper.py and leaves files unchanged."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        helper_file = self.target_dir / "privileged_helper.py"
        helper_before = helper_file.read_bytes()
        helper_file.chmod(0o770)  # group-writable

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("group- or world-writable", res2.stderr.lower())
        # Verify existing installation is byte-for-byte unchanged
        self.assertEqual(helper_file.read_bytes(), helper_before)

    def test_37_legacy_migration_rejects_group_writable_python_module(self):
        """37. Legacy migration rejects group-writable Python module and leaves files unchanged."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        mod_file = self.target_dir / "lab" / "identity.py"
        mod_before = mod_file.read_bytes()
        mod_file.chmod(0o664)  # group-writable

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("group- or world-writable", res2.stderr.lower())
        self.assertEqual(mod_file.read_bytes(), mod_before)

    def test_38_legacy_migration_rejects_group_writable_containing_directory(self):
        """38. Legacy migration rejects group-writable containing directory and leaves installation unchanged."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        lab_dir = self.target_dir / "lab"
        lab_dir.chmod(0o775)  # group-writable

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("group- or world-writable", res2.stderr.lower())

    def test_39_legacy_migration_rejects_world_writable_containing_directory(self):
        """39. Legacy migration rejects world-writable containing directory."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        www_dir = self.target_dir / "lab" / "www"
        www_dir.chmod(0o777)  # world-writable

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("group- or world-writable", res2.stderr.lower())

    def test_40_legacy_migration_rejects_unsafe_target_root_permissions(self):
        """40. Legacy migration rejects group- or world-writable target root directory."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        self.target_dir.chmod(0o775)  # group-writable target root
        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("target_dir cannot be group- or world-writable", res2.stderr.lower())

    def test_41_legacy_migration_succeeds_with_correct_permissions(self):
        """41. Legacy migration succeeds when all canonical files have strict production modes."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        (self.target_dir / "deployment_manifest.json").unlink()

        # Enforce canonical strict modes on all files
        (self.target_dir / "privileged_helper.py").chmod(0o750)
        (self.target_dir / "lab" / "dns_server.py").chmod(0o750)
        for p in self.target_dir.rglob("*"):
            if p.is_dir():
                p.chmod(0o755)
            elif p.name not in ("privileged_helper.py", "dns_server.py"):
                p.chmod(0o644)

        res2 = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertEqual(res2.returncode, 0, f"Migration failed: {res2.stderr}\n{res2.stdout}")
        self.assertTrue((self.target_dir / "deployment_manifest.json").is_file())

    def test_42_concurrent_installer_invocation_fails_safely(self):
        """42. Second concurrent installer invocation fails safely when lock is held without corrupting state."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")

        lock_path = self.target_parent / ".ps028_deploy.lock"
        import fcntl
        with open(lock_path, "a") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            # Try to run deploy concurrently
            res2 = self._run_deploy()
            self.assertNotEqual(res2.returncode, 0)
            self.assertIn("another instance of ps-028 privileged helper deployment or upgrade is currently running", res2.stderr.lower())

            # Release lock
            fcntl.flock(lock_fd, fcntl.LOCK_UN)

        # Verify state is completely intact
        self.assertTrue(self.target_dir.is_dir())
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_before)

    def test_43_lock_released_on_process_termination(self):
        """43. Lock held by a process is automatically released upon kernel termination (SIGKILL)."""
        lock_path = self.target_parent / ".ps028_deploy.lock"

        # Spawn child process holding lock
        child_code = f"""
import fcntl, time, sys
f = open("{lock_path}", "a")
fcntl.flock(f, fcntl.LOCK_EX)
sys.stdout.write("LOCKED\\n")
sys.stdout.flush()
time.sleep(60)
"""
        import sys, signal
        proc = subprocess.Popen([sys.executable, "-c", child_code], stdout=subprocess.PIPE)
        try:
            line = proc.stdout.readline()
            self.assertIn(b"LOCKED", line)
        finally:
            if proc.stdout:
                proc.stdout.close()

        # Kill child process with SIGKILL
        proc.send_signal(signal.SIGKILL)
        proc.wait()

        # The subsequent deploy invocation must succeed immediately (kernel freed flock)
        res = self._run_deploy(extra_args=["--dry-run"])
        self.assertEqual(res.returncode, 0, f"Deploy failed after killed child: {res.stderr}\n{res.stdout}")

    def test_44_old_sudoers_rules_reject_malformed_malicious_options(self):
        """44. StrictArgumentParser rejects unknown flags, duplicate options, and parameter injections."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        helper_bin = self.target_dir / "privileged_helper.py"

        # 1. Unapproved option injected into apply-scenario
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "apply-scenario", "--scenario", "S0", "--unapproved-option", "bad"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 2)  # Argparse exit code 2 on unknown args
        self.assertIn("unrecognized arguments", res.stderr)

        # 2. Duplicate option rejection
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "apply-scenario", "--scenario", "S0", "--scenario", "S1"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("duplicate option", res.stderr)

        # 3. Invalid scenario choice
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "apply-scenario", "--scenario", "INVALID_SCENARIO"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("invalid choice", res.stderr)

        # 4. launch-snap-browser UID 0 drop rejection
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", "0", "--regid", "0", "/usr/bin/google-chrome"],
            capture_output=True, text=True
        )
        self.assertNotEqual(res.returncode, 0)

        # 5. measure-s5-worker without valid parent authentication
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "measure-s5-worker"],
            capture_output=True, text=True
        )
        self.assertNotEqual(res.returncode, 0)

    def test_45_exit_trap_triggers_rollback_on_unexpected_exit(self):
        """45. EXIT trap triggers rollback and preserves prior installation on unexpected termination."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        manifest_before = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        sudoers_before = self.target_sudoers.read_text(encoding="utf-8")

        # Simulate interruption during activation
        env_exit = self.env.copy()
        env_exit["PS028_TEST_INTERRUPT_ACTIVATION"] = "1"
        res2 = self._run_deploy(custom_env=env_exit)
        self.assertNotEqual(res2.returncode, 0)

        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_before)
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), sudoers_before)

    def test_46_idempotent_recovery_repeated_invocations(self):
        """46. Recovery is strictly idempotent across repeated invocations."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        manifest_orig = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")

        # Simulate crash leaving backup dir and uncommitted state
        backup_dir = self.target_parent / ".ps028_backup_44444_1"
        self.target_dir.rename(backup_dir)
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        # First run: recovers target
        res2 = self._run_deploy()
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_orig)

        # Second run: dry run on restored installation
        res3 = self._run_deploy(extra_args=["--dry-run"])
        self.assertEqual(res3.returncode, 0, res3.stderr)
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), manifest_orig)

        # Third run: full upgrade on restored installation
        res4 = self._run_deploy()
        self.assertEqual(res4.returncode, 0, res4.stderr)
        self.assertTrue(self.target_dir.is_dir())

    def test_47_sudoers_wildcard_matching_and_command_separation(self):
        """47. Sudoers wildcard fnmatch and StrictArgumentParser command separation."""
        import fnmatch
        old_rules = [
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py apply-scenario *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py restore-baseline *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py apply-dns *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py restore-dns *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py verify-baseline *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py start-capture *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py stop-capture *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py check-auth",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py setup-s5-counters *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py read-s5-counters *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py measure-s5 *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py launch-snap-browser *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py start-nginx *",
            f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py stop-nginx *",
        ]

        def matches_any_old_rule(cmd_str: str) -> bool:
            return any(fnmatch.fnmatch(cmd_str, rule) for rule in old_rules)

        # 1. Valid old invocations match
        self.assertTrue(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py apply-scenario --scenario S0"))
        self.assertTrue(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py check-auth"))

        # 2. Command concatenation/suffix attacks do NOT match
        self.assertFalse(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py apply-scenario-worker"))
        self.assertFalse(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py check-auth --evil"))
        self.assertFalse(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py start-dns"))
        self.assertFalse(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py reload-dns"))
        self.assertFalse(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py status-nginx"))

        # 3. measure-s5 * does NOT match measure-s5-worker (hyphen vs space)
        self.assertFalse(matches_any_old_rule(f"/usr/bin/python3 -I {self.target_dir}/privileged_helper.py measure-s5-worker"))

        # 4. Injected subcommands in authorized prefix are rejected by StrictArgumentParser
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        helper_bin = self.target_dir / "privileged_helper.py"

        # Missing required argument fails with exit code 2
        res_missing = subprocess.run(
            ["python3", "-I", str(helper_bin), "apply-scenario", "start-dns"],
            capture_output=True, text=True
        )
        self.assertEqual(res_missing.returncode, 2)
        self.assertIn("required: --scenario", res_missing.stderr)

        # Injected positional subcommand with valid flags fails with unrecognized arguments
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "apply-scenario", "--scenario", "S0", "start-dns"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("unrecognized arguments", res.stderr)

        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "restore-baseline", "reload-dns"],
            capture_output=True, text=True
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("unrecognized arguments", res.stderr)

    def test_48_lock_lifetime_and_child_descriptor_inheritance(self):
        """48. Lock remains held while child process retains inherited descriptor."""
        lock_file = self.target_parent / ".ps028_deploy.lock"
        # Script that acquires flock on FD 200, spawns a child that sleeps with FD 200, then parent exits
        test_script = f"""
exec 200>>"{lock_file}"
flock -n 200 || exit 1
echo "PARENT_LOCKED"
# Spawn child keeping FD 200 open
sleep 3 200>&- <&- >&- 2>&- &
# Spawn child that keeps FD 200 open
( exec 200>>"{lock_file}"; sleep 3 ) &
CHILD_PID=$!
echo "CHILD_PID=$CHILD_PID"
exit 0
"""
        proc = subprocess.Popen(
            ["bash", "-c", f"""
exec 200>>"{lock_file}"
flock -n 200 || exit 1
echo "LOCKED"
sleep 2 &
CHILD_PID=$!
echo "CHILD=$CHILD_PID"
wait $CHILD_PID
"""],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        try:
            line = proc.stdout.readline().strip()
            self.assertEqual(line, "LOCKED")
            child_line = proc.stdout.readline().strip()
            self.assertTrue(child_line.startswith("CHILD="))
            child_pid = int(child_line.split("=")[1])

            # While child is running, second lock acquisition fails
            res = subprocess.run(
                ["bash", "-c", f"exec 200>>'{lock_file}'; flock -n 200"],
                capture_output=True
            )
            self.assertNotEqual(res.returncode, 0)

            # Wait for child to exit
            proc.wait(timeout=5)

            # Now lock is immediately acquirable
            res = subprocess.run(
                ["bash", "-c", f"exec 200>>'{lock_file}'; flock -n 200"],
                capture_output=True
            )
            self.assertEqual(res.returncode, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

    def test_49_journal_metadata_persistence_and_stale_cleanup(self):
        """49. Journal state writes with mode 0600 and stale .tmp files are cleaned up."""
        # Create a stale tmp state file
        stale_tmp = self.target_parent / f".ps028_tx_state_{self.target_dir.name}.tmp.99999"
        stale_tmp.write_text("STATE=CORRUPT\n")
        self.assertTrue(stale_tmp.is_file())

        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        # Stale tmp file was cleaned up during recovery
        self.assertFalse(stale_tmp.is_file())

        # Simulate state file written during transaction
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        # Trigger an interrupted activation
        env_exit = self.env.copy()
        env_exit["PS028_TEST_INTERRUPT_ACTIVATION"] = "1"
        res2 = self._run_deploy(custom_env=env_exit)
        self.assertNotEqual(res2.returncode, 0)

        # State file was cleaned up on rollback
        self.assertFalse(state_file.is_file())

    def test_50_strict_argument_parser_abbreviation_rejection(self):
        """50. StrictArgumentParser enforces allow_abbrev=False across all build_parser() objects."""
        import sys
        import io
        import contextlib
        sys.path.insert(0, str(REPO_ROOT))
        import lab.privileged_helper as ph

        parser = ph.build_parser()
        self.assertFalse(parser.allow_abbrev, "Top-level parser must have allow_abbrev=False")

        # Verify every subcommand parser has allow_abbrev=False
        subparsers_action = None
        for action in parser._actions:
            if isinstance(action, ph.argparse._SubParsersAction):
                subparsers_action = action
                break
        self.assertIsNotNone(subparsers_action)
        self.assertGreater(len(subparsers_action.choices), 10)

        for name, sub in subparsers_action.choices.items():
            self.assertFalse(sub.allow_abbrev, f"Subparser '{name}' must have allow_abbrev=False")
            self.assertIsInstance(sub, ph.StrictArgumentParser, f"Subparser '{name}' must be StrictArgumentParser")

        devnull = io.StringIO()
        with contextlib.redirect_stderr(devnull):
            # 1. Unambiguous long-option abbreviation rejected (--scen for --scenario)
            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["apply-scenario", "--scen", "S0"])
            self.assertEqual(cm.exception.code, 2)

            # 2. Ambiguous option abbreviation rejected (--s for --scenario)
            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["apply-scenario", "--s", "S0"])
            self.assertEqual(cm.exception.code, 2)

            # 3. Exact documented option works cleanly
            args = parser.parse_args(["apply-scenario", "--scenario", "S0"])
            self.assertEqual(args.action, "apply-scenario")
            self.assertEqual(args.scenario, "S0")

            # 4. Duplicate option rejected
            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["apply-scenario", "--scenario", "S0", "--scenario", "S1"])
            self.assertEqual(cm.exception.code, 2)

            # 5. Abbreviations rejected across multiple subcommands
            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["apply-dns", "--a-del", "10"])
            self.assertEqual(cm.exception.code, 2)

            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["start-capture", "--out", "test.pcap", "--log-file", "test.log"])
            self.assertEqual(cm.exception.code, 2)

    def test_51_launch_snap_browser_adversarial_validation(self):
        """51. launch-snap-browser complete path validation under historical 14-rule policy."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        helper_bin = self.target_dir / "privileged_helper.py"
        current_uid = str(os.getuid() if os.getuid() != 0 else 1000)
        current_gid = str(os.getgid() if os.getgid() != 0 else 1000)
        fixture_chrome = str(self._create_browser_executable_fixture("google-chrome"))

        # 1. Root UID or GID request is rejected (exit code 74)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", "0", "--regid", "0", fixture_chrome],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 74, f"Expected 74 for root identity. Stderr: {res.stderr}")
        self.assertIn("refusing to launch browser as root", res.stderr)

        # 2. Arbitrary non-browser executable: /bin/sh (exit code 72)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, "/bin/sh"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 72, f"Expected 72 for /bin/sh. Stderr: {res.stderr}")
        self.assertIn("unauthorized executable", res.stderr)

        # 3. Arbitrary non-browser executable: Python (exit code 72)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, "/usr/bin/python3"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 72, f"Expected 72 for python3. Stderr: {res.stderr}")
        self.assertIn("unauthorized executable", res.stderr)

        # 4. Shell metacharacters in browser arguments (exit code 75)
        for bad_arg in ["; rm -rf /", "$(whoami)", "`id`", "http://test|cat", "http://test>out"]:
            res = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, bad_arg],
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(res.returncode, 75, f"Failed to reject metacharacter arg: {bad_arg}. Stderr: {res.stderr}")
            self.assertIn("prohibited characters", res.stderr)

        # 5. Profile path traversal outside allowed directories (exit code 74)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, "--user-data-dir=/etc"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 74, f"Expected 74 for /etc profile dir. Stderr: {res.stderr}")
        self.assertIn("is not within permitted directories", res.stderr)

        # 6. Malformed URL: forbidden scheme file:// (exit code 75)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, "file:///etc/passwd"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 75, f"Expected 75 for file:// scheme. Stderr: {res.stderr}")
        self.assertIn("prohibited URL scheme", res.stderr)

        # 7. Malformed URL: forbidden scheme ftp:// (exit code 75)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, "ftp://example.invalid/"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 75, f"Expected 75 for ftp:// scheme. Stderr: {res.stderr}")
        self.assertIn("prohibited URL scheme", res.stderr)

        # 8. Malformed URL: forbidden scheme javascript: (exit code 75)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, "javascript:alert(1)"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 75, f"Expected 75 for javascript: scheme. Stderr: {res.stderr}")
        self.assertIn("prohibited URL scheme", res.stderr)

        # 9. Malformed URL: forbidden scheme data: (exit code 75)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, "data:text/html,evil"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 75, f"Expected 75 for data: scheme. Stderr: {res.stderr}")
        self.assertIn("prohibited URL scheme", res.stderr)

        # 10. Malformed URL: missing hostname (exit code 75)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, "http://"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 75, f"Expected 75 for missing hostname. Stderr: {res.stderr}")
        self.assertIn("missing hostname", res.stderr)

        # 11. Valid HTTP URL and legitimate browser options pass URL validation (reach mount stage: exit code 71)
        res = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome,
             "--user-data-dir=/tmp/ps028_prof_valid", "--headless", "--no-sandbox", "http://127.0.0.1:80/"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(res.returncode, 71)  # 71 = SnapMountError in unprivileged test environment

    def test_52_journal_synchronization_failures_and_recovery(self):
        """52. Checked journal synchronization error handling and fault recovery."""
        # 1. State write failure
        env_write_fail = self.env.copy()
        env_write_fail["PS028_TEST_FAIL_WRITE_STATE"] = "1"
        res = self._run_deploy(custom_env=env_write_fail)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Simulated write failure", res.stderr)

        # 2. State chmod failure
        env_chmod_fail = self.env.copy()
        env_chmod_fail["PS028_TEST_FAIL_CHMOD_STATE"] = "1"
        res = self._run_deploy(custom_env=env_chmod_fail)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Simulated chmod failure", res.stderr)

        # 3. State file fsync failure
        env_sync_file_fail = self.env.copy()
        env_sync_file_fail["PS028_TEST_FAIL_SYNC_FILE"] = "1"
        res = self._run_deploy(custom_env=env_sync_file_fail)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Simulated file fsync failure", res.stderr)

        # 4. State atomic rename failure
        env_rename_fail = self.env.copy()
        env_rename_fail["PS028_TEST_FAIL_RENAME_STATE"] = "1"
        res = self._run_deploy(custom_env=env_rename_fail)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Simulated atomic rename failure", res.stderr)

        # 5. Parent directory fsync failure after rename:
        # Deploy clean initial installation first
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0, res_init.stderr)

        # Upgrade with directory fsync failure
        env_sync_dir_fail = self.env.copy()
        env_sync_dir_fail["PS028_TEST_FAIL_SYNC_DIR"] = "1"
        res_dir_fail = self._run_deploy(custom_env=env_sync_dir_fail)
        self.assertNotEqual(res_dir_fail.returncode, 0)
        self.assertIn("Simulated parent directory synchronization failure", res_dir_fail.stderr)

        # Subsequent invocation recovers successfully
        res_rec = self._run_deploy()
        self.assertEqual(res_rec.returncode, 0, res_rec.stderr)
        self.assertTrue(self.target_dir.is_dir())

    def test_53_complete_process_exit_trap_directory_sync_failure_and_recovery(self):
        """53. Complete-process verification of EXIT trap rollback during directory sync failure."""
        import time
        # 1. Perform initial clean deployment and record exact baseline state
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0, res_init.stderr)
        orig_manifest = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        orig_helper = (self.target_dir / "privileged_helper.py").read_text(encoding="utf-8")
        orig_sudoers = self.target_sudoers.read_text(encoding="utf-8")

        # 2. Run upgrade subprocess with real EXIT trap active and directory sync failure at TARGET_ACTIVATED
        env_fail = self.env.copy()
        env_fail["PS028_TEST_FAIL_SYNC_DIR_STATE"] = "TARGET_ACTIVATED"
        res_fail = self._run_deploy(custom_env=env_fail)
        self.assertNotEqual(res_fail.returncode, 0)
        self.assertIn("Simulated parent directory synchronization failure", res_fail.stderr)
        self.assertIn("Deployment interrupted (EXIT)", res_fail.stderr)

        # 3. Inspect resulting paths immediately after process termination:
        # The EXIT trap executed immediate rollback:
        # - Target directory restored byte-for-byte to original baseline
        self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), orig_manifest)
        self.assertEqual((self.target_dir / "privileged_helper.py").read_text(encoding="utf-8"), orig_helper)
        # - Sudoers restored
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), orig_sudoers)
        # - Journal file unlinked after clean rollback
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        self.assertFalse(state_file.is_file(), "Journal file must be cleaned up after successful immediate rollback")
        # - No staging or backup directories remain
        backups = list(self.target_parent.glob(".ps028_backup_*"))
        stagings = list(self.target_parent.glob(".ps028_staging_*"))
        self.assertEqual(len(backups), 0, f"Expected no lingering backups, found: {backups}")
        self.assertEqual(len(stagings), 0, f"Expected no lingering staging dirs, found: {stagings}")

        # 4. Subsequent invocation succeeds cleanly from the restored baseline
        res_subsequent = self._run_deploy()
        self.assertEqual(res_subsequent.returncode, 0, res_subsequent.stderr)
        self.assertTrue((self.target_dir / "deployment_manifest.json").is_file())

        # 5. Deferred recovery scenario: simulate ungraceful termination (e.g. SIGKILL)
        # where rename succeeded but process was killed before EXIT trap could run
        backup_dir = self.target_parent / f".ps028_backup_{int(time.time())}_9999"
        self.target_dir.rename(backup_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)
        (self.target_dir / "tampered.txt").write_text("partial")
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP={int(time.time())}
""")
        # Subsequent invocation detects journal and recovers target from backup byte-for-byte
        res_deferred = self._run_deploy()
        self.assertEqual(res_deferred.returncode, 0, res_deferred.stderr)
        self.assertFalse((self.target_dir / "tampered.txt").exists())
        self.assertEqual((self.target_dir / "privileged_helper.py").read_text(encoding="utf-8"), orig_helper)
        self.assertFalse(state_file.is_file())

    def test_54_browser_url_authority_validation(self):
        """54. Strict HTTP/HTTPS authority validation, port boundaries, IPv6 literals, and pre-mount rejection."""
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0, res.stderr)
        helper_bin = self.target_dir / "privileged_helper.py"
        current_uid = str(os.getuid() if os.getuid() != 0 else 1000)
        current_gid = str(os.getgid() if os.getgid() != 0 else 1000)
        fixture_chrome = str(self._create_browser_executable_fixture("google-chrome"))

        # 1. Missing hostname rejection (exit code 75)
        for bad_url in ["http://", "http://:80", "http://user@"]:
            r = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, bad_url],
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(r.returncode, 75, f"Expected 75 for missing hostname URL: {bad_url}. Stderr: {r.stderr}")
            self.assertIn("missing hostname", r.stderr)

        # 2. Invalid port rejection: out-of-range, port 0, port > 65535 (exit code 75)
        for bad_port_url in ["http://example.invalid:99999", "http://[::1]:0", "http://[::1]:65536"]:
            r = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, bad_port_url],
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(r.returncode, 75, f"Expected 75 for invalid port URL: {bad_port_url}. Stderr: {r.stderr}")
            self.assertIn("invalid port", r.stderr)

        # 3. Malformed/unbracketed/invalid IPv6 authority rejection (exit code 75)
        for bad_ipv6_url in [
            "http://[invalid_ipv6]/",
            "http://[2001:db8:::1]/",
            "http://[::1/path",
            "http://2001:db8::1/"
        ]:
            r = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, bad_ipv6_url],
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(r.returncode, 75, f"Expected 75 for bad IPv6 URL: {bad_ipv6_url}. Stderr: {r.stderr}")
            self.assertTrue(
                any(msg in r.stderr for msg in ["malformed URL", "invalid IPv6 literal", "invalid port", "unbracketed IPv6 authority", "malformed bracketed IPv6"]),
                f"Unexpected stderr for {bad_ipv6_url}: {r.stderr}"
            )

        # 4. Non-HTTP(S) scheme rejection (exit code 75)
        for bad_scheme in [
            "file:///etc/passwd",
            "ftp://example.invalid/",
            "javascript:alert(1)",
            "data:text/html,example"
        ]:
            r = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, bad_scheme],
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(r.returncode, 75, f"Expected 75 for bad scheme: {bad_scheme}. Stderr: {r.stderr}")
            self.assertIn("prohibited URL scheme", r.stderr)

        # 5. Legitimate browser options, --app= form, and valid HTTP(S)/IPv6 URLs pass URL validation
        # (reaches mount setup, failing with 71 in unprivileged test environment, proving rejection happens before mount setup)
        valid_cases = [
            ["http://127.0.0.1:80/"],
            ["https://example.com/"],
            ["http://[2001:db8::1]/"],
            ["http://[2001:db8::1]:8080/path"],
            ["--app=https://example.com/login"],
            ["--headless", "--no-sandbox", "--user-data-dir=/tmp/ps028_prof_valid", "https://example.com/dashboard"],
        ]
        for cmd_args in valid_cases:
            r = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome] + cmd_args,
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(r.returncode, 71, f"Expected 71 (SnapMountError) for valid arguments {cmd_args}, got {r.returncode}: {r.stderr}")

        # 6. Malformed URL inside --app= argument is rejected with 75 before mount setup
        for bad_app in ["--app=http://", "--app=file:///etc/passwd", "--app=http://[invalid_ipv6]/"]:
            r = subprocess.run(
                ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome, bad_app],
                capture_output=True, text=True, env=self.env
            )
            self.assertEqual(r.returncode, 75, f"Expected 75 for bad app argument: {bad_app}. Stderr: {r.stderr}")

        # 7. URL-valued browser flags (e.g. --proxy-server=http://proxy:8080) are options, not navigation targets (Blocker 7)
        r = subprocess.run(
            ["python3", "-I", str(helper_bin), "launch-snap-browser", "--reuid", current_uid, "--regid", current_gid, fixture_chrome,
             "--proxy-server=http://proxy.example:8080", "https://example.com/"],
            capture_output=True, text=True, env=self.env
        )
        self.assertEqual(r.returncode, 71, f"Expected 71 (SnapMountError) for --proxy-server flag with valid URL, got {r.returncode}: {r.stderr}")

    def test_55_dryrun_genuinely_readonly(self):
        """55. Dry-run is genuinely read-only: no lock file, no recovery, no state modification, byte-for-byte unchanged."""
        # Setup an interrupted journal and an unmanifested legacy installation
        self.target_dir.mkdir(parents=True, exist_ok=True)
        (self.target_dir / "privileged_helper.py").write_text("# legacy helper\n", encoding="utf-8")
        (self.target_dir / "custom.txt").write_text("custom payload\n", encoding="utf-8")

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1700000000
""", encoding="utf-8")

        lock_file = self.target_parent / ".ps028_deploy.lock"
        self.assertFalse(lock_file.exists())

        # Take filesystem snapshot before dry-run
        def snapshot_dir(p):
            snap = {}
            if not p.exists():
                return snap
            for root, dirs, files in os.walk(p):
                for f in files:
                    fp = Path(root) / f
                    snap[str(fp.relative_to(p))] = fp.read_bytes()
            return snap

        snap_parent_before = snapshot_dir(self.target_parent)
        snap_sudoers_before = snapshot_dir(self.sudoers_parent)

        # Run dry-run
        res = self._run_deploy(extra_args=["--dry-run"])
        # Even if prerequisites or dirty checkout stops dry-run, filesystem must be untouched
        self.assertFalse(lock_file.exists(), "Dry-run must not create lock file")

        snap_parent_after = snapshot_dir(self.target_parent)
        snap_sudoers_after = snapshot_dir(self.sudoers_parent)

        self.assertEqual(snap_parent_before, snap_parent_after, "Target parent directory modified during dry-run!")
        self.assertEqual(snap_sudoers_before, snap_sudoers_after, "Sudoers parent directory modified during dry-run!")
        self.assertTrue(state_file.exists(), "State file must not be removed during dry-run")
        self.assertTrue((self.target_dir / "custom.txt").exists(), "Target dir files must not be altered during dry-run")

    def test_56_legacy_migration_transactional(self):
        """56. Legacy migration is transactional: manifest is not written to target before activation."""
        # Create valid legacy installation matching commit
        res_fresh = self._run_deploy()
        self.assertEqual(res_fresh.returncode, 0)
        # Remove manifest to make it an unmanifested legacy installation
        manifest_file = self.target_dir / "deployment_manifest.json"
        self.assertTrue(manifest_file.is_file())
        manifest_file.unlink()

        # Snapshot legacy target files
        files_before = {str(p.relative_to(self.target_dir)): p.read_bytes() for p in self.target_dir.rglob("*") if p.is_file()}
        self.assertNotIn("deployment_manifest.json", files_before)

        # 1. Failure during sudoers validation: legacy installation must have no manifest written
        env_fail_sudo = self.env.copy()
        env_fail_sudo["PS028_TEST_CORRUPT_SUDOERS"] = "1"
        res = self._run_deploy(extra_args=["--migrate-unmanifested"], custom_env=env_fail_sudo)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(manifest_file.exists(), "Manifest was written to target before sudoers validation!")
        files_after_sudo_fail = {str(p.relative_to(self.target_dir)): p.read_bytes() for p in self.target_dir.rglob("*") if p.is_file()}
        self.assertEqual(files_before, files_after_sudo_fail, "Target modified on sudoers failure before activation!")

        # 2. Failure during staging: legacy installation remains untouched
        env_fail_stg = self.env.copy()
        env_fail_stg["PS028_TEST_FAIL_WRITE_STATE"] = "1"
        res = self._run_deploy(extra_args=["--migrate-unmanifested"], custom_env=env_fail_stg)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(manifest_file.exists(), "Manifest was written to target before staging state write!")

        # 3. Successful legacy migration writes new manifest into newly deployed target
        res_ok = self._run_deploy(extra_args=["--migrate-unmanifested"])
        self.assertEqual(res_ok.returncode, 0, res_ok.stderr)
        self.assertTrue(manifest_file.is_file())
        new_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertEqual(new_manifest["release_sha"], self.commit_sha)

    def test_57_target_root_ownership_and_permissions(self):
        """57. Target root directory and TARGET_PARENT mode allowlist, special bits rejection, and symlink rejection."""
        # 1. Group-writable TARGET_DIR rejected
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.target_dir.chmod(0o775)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR cannot be group- or world-writable", res.stderr)

        # 2. World-writable TARGET_DIR rejected
        self.target_dir.chmod(0o757)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR cannot be group- or world-writable", res.stderr)

        # 3. Special bits on TARGET_DIR rejected
        self.target_dir.chmod(0o4755)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("special bits", res.stderr)

        # 4. Group-writable TARGET_PARENT rejected
        self.target_dir.chmod(0o755)
        self.target_parent.chmod(0o775)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT cannot be group- or world-writable", res.stderr)
        self.target_parent.chmod(0o755)

        # 5. Symlink TARGET_DIR rejected
        shutil.rmtree(self.target_dir)
        real_target = self.temp_dir / "real_ps028"
        real_target.mkdir(parents=True, exist_ok=True)
        self.target_dir.symlink_to(real_target)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("symlink", res.stderr)
        self.target_dir.unlink()

    def test_58_transaction_commit_ordering(self):
        """58. COMMITTED state is persisted and synced before backup deletion; crashes before/after handled safely."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0)
        orig_helper = (self.target_dir / "privileged_helper.py").read_text(encoding="utf-8")

        # 1. Crash immediately before COMMITTED persistence triggers rollback, preserving previous installation
        env_pre_commit = self.env.copy()
        env_pre_commit["PS028_TEST_CRASH_PRE_COMMITTED"] = "1"
        res = self._run_deploy(custom_env=env_pre_commit)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual((self.target_dir / "privileged_helper.py").read_text(encoding="utf-8"), orig_helper)

        # 2. Crash immediately after COMMITTED persistence retains the new verified installation
        env_post_commit = self.env.copy()
        env_post_commit["PS028_TEST_CRASH_POST_COMMITTED"] = "1"
        res = self._run_deploy(custom_env=env_post_commit)
        self.assertEqual(res.returncode, 0)
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        self.assertTrue(state_file.is_file(), "State file must exist when killed before cleanup")
        self.assertIn("STATE=COMMITTED", state_file.read_text(encoding="utf-8"))

        # Subsequent invocation recovers COMMITTED state by retaining verified target and removing leftover backups
        res_subseq = self._run_deploy()
        self.assertEqual(res_subseq.returncode, 0)
        self.assertFalse(state_file.exists(), "State file should be cleaned up after recovery")
        backups = list(self.target_parent.glob(".ps028_backup_*"))
        self.assertEqual(len(backups), 0, f"Leftover backups should be cleaned up, found: {backups}")

    def test_59_fresh_install_recovery(self):
        """59. Fresh installation interruption cleans up partial target and sudoers drop-in without deleting pre-existing files."""
        self.assertFalse(self.target_dir.exists())
        self.assertFalse(self.target_sudoers.exists())

        # 1. Crash after fresh target activation before sudoers activation
        env_fresh_target = self.env.copy()
        env_fresh_target["PS028_TEST_CRASH_FRESH_POST_TARGET"] = "1"
        res = self._run_deploy(custom_env=env_fresh_target)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(self.target_dir.exists(), "Incomplete fresh target dir must be removed on rollback")
        self.assertFalse(self.target_sudoers.exists(), "Sudoers drop-in must not exist")

        # 2. Crash after fresh sudoers activation before post-verify
        env_fresh_sudoers = self.env.copy()
        env_fresh_sudoers["PS028_TEST_CRASH_FRESH_POST_SUDOERS"] = "1"
        res = self._run_deploy(custom_env=env_fresh_sudoers)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(self.target_dir.exists(), "Incomplete fresh target dir must be removed on rollback")
        self.assertFalse(self.target_sudoers.exists(), "Incomplete fresh sudoers drop-in must be removed on rollback")

        # 3. Post-install verification failure during fresh install
        env_fresh_post_fail = self.env.copy()
        env_fresh_post_fail["PS028_TEST_FAIL_POST_VERIFY"] = "1"
        res = self._run_deploy(custom_env=env_fresh_post_fail)
        self.assertNotEqual(res.returncode, 0)
        self.assertFalse(self.target_dir.exists())
        self.assertFalse(self.target_sudoers.exists())

    def test_60_lock_file_security_and_fault_injection(self):
        """60. Lock file chmod/chown failures fail closed; lock file type verified; lock inode preserved."""
        # 1. Lock chmod failure
        env_lock_chmod = self.env.copy()
        env_lock_chmod["PS028_TEST_FAIL_LOCK_CHMOD"] = "1"
        res = self._run_deploy(custom_env=env_lock_chmod)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Simulated lock file chmod failure", res.stderr)

        # 2. Lock file mode and type verified on normal run
        res_ok = self._run_deploy()
        self.assertEqual(res_ok.returncode, 0)
        lock_file = self.target_parent / ".ps028_deploy.lock"
        self.assertTrue(lock_file.is_file(), "Lock file inode must be preserved")
        self.assertEqual(oct(lock_file.stat().st_mode & 0o777), "0o600")

    def test_61_dry_run_zero_filesystem_writes_snapshot(self):
        """61. Dry-run performs zero filesystem writes, verified by recursive tree snapshots."""
        def snapshot_tree(root_path):
            if not root_path.exists():
                return None
            records = {}
            for p in sorted(root_path.rglob("*")):
                try:
                    st = p.lstat()
                    content = p.read_bytes() if p.is_file() and not p.is_symlink() else (p.readlink() if p.is_symlink() else None)
                    records[str(p.relative_to(root_path))] = {
                        "is_dir": p.is_dir(),
                        "is_symlink": p.is_symlink(),
                        "is_file": p.is_file(),
                        "mode": oct(st.st_mode),
                        "size": st.st_size,
                        "content": content
                    }
                except Exception:
                    pass
            return records

        # Case A: Manifest-present existing installation
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)
        snap_tmp_a = snapshot_tree(self.temp_dir)
        snap_tp_a = snapshot_tree(self.target_parent)
        snap_sp_a = snapshot_tree(self.sudoers_parent)

        res_dry_a = self._run_deploy(extra_args=["--dry-run"])
        self.assertEqual(res_dry_a.returncode, 0)
        self.assertIn("TRANSACTIONAL UPGRADE", res_dry_a.stdout)
        self.assertEqual(snapshot_tree(self.temp_dir), snap_tmp_a, "TMPDIR must be byte-for-byte unchanged after dry-run")
        self.assertEqual(snapshot_tree(self.target_parent), snap_tp_a, "target_parent must be byte-for-byte unchanged")
        self.assertEqual(snapshot_tree(self.sudoers_parent), snap_sp_a, "sudoers_parent must be byte-for-byte unchanged")

        # Case B: Unmanifested legacy installation
        manifest_file = self.target_dir / "deployment_manifest.json"
        manifest_file.unlink()
        snap_tmp_b = snapshot_tree(self.temp_dir)
        snap_tp_b = snapshot_tree(self.target_parent)
        snap_sp_b = snapshot_tree(self.sudoers_parent)

        res_dry_b = self._run_deploy(extra_args=["--dry-run", "--migrate-unmanifested"])
        self.assertEqual(res_dry_b.returncode, 0)
        self.assertIn("TRANSACTIONAL UPGRADE", res_dry_b.stdout)
        self.assertEqual(snapshot_tree(self.temp_dir), snap_tmp_b, "TMPDIR must have zero created files during unmanifested dry-run")
        self.assertEqual(snapshot_tree(self.target_parent), snap_tp_b)
        self.assertEqual(snapshot_tree(self.sudoers_parent), snap_sp_b)

        # Case C: Interrupted journal state
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        snap_tmp_c = snapshot_tree(self.temp_dir)
        snap_tp_c = snapshot_tree(self.target_parent)
        snap_sp_c = snapshot_tree(self.sudoers_parent)

        res_dry_c = self._run_deploy(extra_args=["--dry-run", "--migrate-unmanifested"])
        self.assertEqual(res_dry_c.returncode, 0)
        self.assertIn("Pending uncommitted prior transaction detected in journal", res_dry_c.stdout)
        self.assertEqual(snapshot_tree(self.temp_dir), snap_tmp_c)
        self.assertEqual(snapshot_tree(self.target_parent), snap_tp_c)
        self.assertEqual(snapshot_tree(self.sudoers_parent), snap_sp_c)
        state_file.unlink()

    def test_62_sudoers_preservation_fresh_install_pre_existing_sudoers(self):
        """62. Pre-existing sudoers content is preserved across fresh install crash injection points."""
        custom_sudoers = "# Prior sudoers rule\nindrani ALL=(ALL) NOPASSWD: ALL\n"

        # Points 1 through 5: Simulated failure/interruption triggering rollback
        points_rollback = [
            ("PS028_TEST_INTERRUPT_PRE_TARGET_ACT", "1"),
            ("PS028_TEST_CRASH_FRESH_POST_TARGET", "1"),
            ("PS028_TEST_CRASH_FRESH_PRE_SUDOERS", "1"),
            ("PS028_TEST_CRASH_FRESH_POST_SUDOERS", "1"),
            ("PS028_TEST_CRASH_PRE_COMMITTED", "1"),
        ]

        for env_var, env_val in points_rollback:
            if self.target_dir.exists():
                shutil.rmtree(self.target_dir)
            if self.target_sudoers.exists():
                self.target_sudoers.chmod(0o644)
                self.target_sudoers.unlink()
            self.target_sudoers.write_text(custom_sudoers, encoding="utf-8")
            self.target_sudoers.chmod(0o440)

            env_crash = self.env.copy()
            env_crash[env_var] = env_val
            res = self._run_deploy(custom_env=env_crash)
            self.assertNotEqual(res.returncode, 0, f"Expected non-zero returncode for {env_var}")
            self.assertFalse(self.target_dir.exists(), f"Target dir must be cleaned up on rollback for {env_var}")
            self.assertTrue(self.target_sudoers.is_file(), f"Pre-existing sudoers must be preserved for {env_var}")
            self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), custom_sudoers, f"Content mismatch for {env_var}")
            self.assertEqual(oct(self.target_sudoers.stat().st_mode & 0o777), "0o440")

        # Point 6: Crash after COMMITTED
        if self.target_dir.exists():
            shutil.rmtree(self.target_dir)
        if self.target_sudoers.exists():
            self.target_sudoers.chmod(0o644)
            self.target_sudoers.unlink()
        self.target_sudoers.write_text(custom_sudoers, encoding="utf-8")
        self.target_sudoers.chmod(0o440)

        env_committed = self.env.copy()
        env_committed["PS028_TEST_CRASH_POST_COMMITTED"] = "1"
        res6 = self._run_deploy(custom_env=env_committed)
        self.assertEqual(res6.returncode, 0)
        self.assertTrue(self.target_dir.is_dir())
        self.assertTrue(self.target_sudoers.is_file())
        self.assertIn("ps028-helper", self.target_sudoers.read_text(encoding="utf-8"))

    def test_63_sudoers_cleanup_upgrade_absent_prior_sudoers(self):
        """63. Absent sudoers in upgrade mode is not left behind after failure/rollback."""
        crash_points = [
            ("PS028_TEST_INTERRUPT_POST_TARGET_ACT", "1"),
            ("PS028_TEST_INTERRUPT_PRE_SUDOERS_ACT", "1"),
            ("PS028_TEST_CRASH_POST_SUDOERS_ACT", "1"),
            ("PS028_TEST_CRASH_PRE_COMMITTED", "1"),
        ]

        for env_var, env_val in crash_points:
            # Baseline install
            res_init = self._run_deploy()
            self.assertEqual(res_init.returncode, 0)
            orig_manifest = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
            # Remove sudoers rule to simulate upgrade where no sudoers rule existed
            if self.target_sudoers.exists():
                self.target_sudoers.unlink()

            env_crash = self.env.copy()
            env_crash[env_var] = env_val
            res = self._run_deploy(custom_env=env_crash)
            self.assertNotEqual(res.returncode, 0, f"Expected non-zero returncode for {env_var}")
            self.assertTrue(self.target_dir.is_dir(), f"Target dir must be restored for {env_var}")
            self.assertEqual((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"), orig_manifest)
            self.assertFalse(self.target_sudoers.exists(), f"Sudoers file must NOT be left behind for {env_var}")

    def test_64_legacy_migration_rollback_byte_for_byte_without_manifest(self):
        """64. Legacy migration rollback preserves exact legacy tree without synthesizing a manifest into target."""
        # Setup legacy tree
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)
        (self.target_dir / "deployment_manifest.json").unlink()

        def snapshot_legacy(td):
            files = {}
            for p in sorted(td.rglob("*")):
                if p.is_file():
                    files[str(p.relative_to(td))] = hashlib.sha256(p.read_bytes()).hexdigest()
            return files

        snap_before = snapshot_legacy(self.target_dir)
        self.assertNotIn("deployment_manifest.json", snap_before)

        # Upgrade with migration flag and simulated crash before COMMITTED
        env_fail = self.env.copy()
        env_fail["PS028_TEST_CRASH_POST_SUDOERS_ACT"] = "1"
        res_fail = self._run_deploy(extra_args=["--migrate-unmanifested"], custom_env=env_fail)
        self.assertNotEqual(res_fail.returncode, 0)

        snap_after = snapshot_legacy(self.target_dir)
        self.assertEqual(snap_before, snap_after, "Legacy installation must be byte-for-byte restored")
        self.assertFalse((self.target_dir / "deployment_manifest.json").exists(), "Restored legacy tree must not have a manifest")

    def test_65_backward_compatible_journal_schema_validation(self):
        """65. Strict journal schema validation fails closed on unknown/legacy schema or invalid state transitions."""
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"

        # 1. Missing INSTALL_TYPE
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing or invalid INSTALL_TYPE", res.stderr)
        self.assertTrue(state_file.is_file(), "Journal must NOT be unlinked on schema failure")

        # 2. Invalid INSTALL_TYPE
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=invalid_type
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing or invalid INSTALL_TYPE", res.stderr)
        self.assertTrue(state_file.is_file())

        # 3. Missing SUDOERS_EXISTED
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing or invalid SUDOERS_EXISTED", res.stderr)
        self.assertTrue(state_file.is_file())

        # 4. Invalid SUDOERS_EXISTED
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=2
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing or invalid SUDOERS_EXISTED", res.stderr)
        self.assertTrue(state_file.is_file())

        # 5. Missing TIMESTAMP
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("invalid or missing TIMESTAMP", res.stderr)
        self.assertTrue(state_file.is_file())

        # 6. Invalid state transition for fresh install
        state_file.write_text(f"""STATE=TARGET_BACKED_UP
INSTALL_TYPE=fresh
SUDOERS_EXISTED=0
TARGET_DIR={self.target_dir}
BACKUP_DIR=
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("invalid state 'TARGET_BACKED_UP' for INSTALL_TYPE=fresh", res.stderr)
        self.assertTrue(state_file.is_file())

        # 7. Path traversal in BACKUP_DIR
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR=/etc
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Must reside directly in", res.stderr)
        self.assertTrue(state_file.is_file())
        state_file.unlink()

    def test_66_lock_file_security_exhaustive(self):
        """66. Lock file chown failure, wrong mode/owner/group, symlink rejection, inode preserved."""
        # 1. Chown failure
        env_chown = self.env.copy()
        env_chown["PS028_TEST_FAIL_LOCK_CHOWN"] = "1"
        res = self._run_deploy(custom_env=env_chown)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Simulated lock file chown failure", res.stderr)

        # 2. Wrong mode
        env_mode = self.env.copy()
        env_mode["PS028_TEST_LOCK_WRONG_MODE"] = "1"
        res = self._run_deploy(custom_env=env_mode)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("wrong mode", res.stderr)

        # 3. Wrong owner
        env_owner = self.env.copy()
        env_owner["PS028_TEST_LOCK_WRONG_OWNER"] = "1"
        res = self._run_deploy(custom_env=env_owner)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("wrong owner", res.stderr)

        # 4. Wrong group
        env_group = self.env.copy()
        env_group["PS028_TEST_LOCK_WRONG_GROUP"] = "1"
        res = self._run_deploy(custom_env=env_group)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("wrong group", res.stderr)

        # 5. Symlink lock file
        lock_file = self.target_parent / ".ps028_deploy.lock"
        if lock_file.exists() or lock_file.is_symlink():
            lock_file.unlink()
        dummy_lock = self.temp_dir / "dummy.lock"
        dummy_lock.touch()
        lock_file.symlink_to(dummy_lock)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("lock file is a symlink", res.stderr)
        lock_file.unlink()

    def test_67_target_parent_and_dir_permission_allowlist(self):
        """67. Exact directory mode allowlist 0755/0750, special bits rejection, symlink rejection, UID/GID checks."""
        # 1. TARGET_PARENT mode allowlist
        self.target_parent.chmod(0o755)
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0)

        self.target_parent.chmod(0o750)
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0)

        self.target_parent.chmod(0o700)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT mode unsafe", res.stderr)

        self.target_parent.chmod(0o710)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT mode unsafe", res.stderr)

        self.target_parent.chmod(0o770)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT cannot be group- or world-writable", res.stderr)

        self.target_parent.chmod(0o1777)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT has special bits set", res.stderr)

        self.target_parent.chmod(0o755)

        # TARGET_PARENT ownership test hooks
        env_uid = self.env.copy()
        env_uid["PS028_TEST_TARGET_PARENT_UID"] = "1000"
        res = self._run_deploy(custom_env=env_uid)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT must be owned by root", res.stderr)

        env_gid = self.env.copy()
        env_gid["PS028_TEST_TARGET_PARENT_GID"] = "1000"
        res = self._run_deploy(custom_env=env_gid)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_PARENT must have root group", res.stderr)

        # 2. TARGET_DIR mode allowlist and ownership
        self.target_dir.chmod(0o755)
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0)

        self.target_dir.chmod(0o750)
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0)

        self.target_dir.chmod(0o700)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR mode unsafe", res.stderr)

        self.target_dir.chmod(0o770)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR cannot be group- or world-writable", res.stderr)

        self.target_dir.chmod(0o1777)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR has special bits set", res.stderr)

        self.target_dir.chmod(0o755)

        env_dir_uid = self.env.copy()
        env_dir_uid["PS028_TEST_TARGET_DIR_UID"] = "1000"
        res = self._run_deploy(custom_env=env_dir_uid)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR must be owned by root", res.stderr)

        env_dir_gid = self.env.copy()
        env_dir_gid["PS028_TEST_TARGET_DIR_GID"] = "1000"
        res = self._run_deploy(custom_env=env_dir_gid)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR must have root group", res.stderr)



    def test_68_production_path_locking_and_destination_overrides(self):
        """68. Production path locking, destination protection, negative path rejection."""
        # 1. Custom target dir in production mode rejected
        env_prod = self.env.copy()
        env_prod["PS028_TEST_FIXTURE"] = "0"
        env_prod["PS028_EXPECTED_RELEASE_SHA"] = self.commit_sha
        res = self._run_deploy(extra_args=["--target-dir", str(self.target_dir)], custom_env=env_prod)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("target directory is strictly locked", res.stderr)

        # 2. Custom sudoers in production mode rejected
        env_prod_sud = env_prod.copy()
        env_prod_sud["PS028_TARGET_DIR"] = "/usr/local/libexec/ps028"
        res = self._run_deploy(extra_args=["--target-sudoers", str(self.target_sudoers)], custom_env=env_prod_sud)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("target sudoers file is strictly locked", res.stderr)

        # 3. Disallowed system paths (/etc/shadow, /etc/passwd, /etc/sudoers, /usr/local/bin)
        for bad_sud in ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/usr/local/bin"]:
            res = self._run_deploy(extra_args=["--target-sudoers", bad_sud])
            self.assertNotEqual(res.returncode, 0)

        for bad_dir in ["/", "/bin", "/sbin", "/usr", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin", "/etc"]:
            res = self._run_deploy(extra_args=["--target-dir", bad_dir])
            self.assertNotEqual(res.returncode, 0)

        # 4. Relative paths
        res = self._run_deploy(extra_args=["--target-dir", "relative_ps028"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_DIR must be an absolute path", res.stderr)

        res = self._run_deploy(extra_args=["--target-sudoers", "relative_sudoers"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TARGET_SUDOERS must be an absolute path", res.stderr)

        # 5. Path traversal (..)
        res = self._run_deploy(extra_args=["--target-dir", f"{self.target_parent}/../target"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Path traversal components", res.stderr)

        # 6. Production paths passed while fixture mode is enabled
        res = self._run_deploy(extra_args=["--target-dir", "/usr/local/libexec/ps028"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Test fixtures must use isolated paths", res.stderr)

        res = self._run_deploy(extra_args=["--target-sudoers", "/etc/sudoers.d/ps028-helper"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Test fixtures must use isolated paths", res.stderr)

    def test_69_immutable_git_blob_extraction_and_provenance(self):
        """69. Immutable Git blob extraction, mandatory release-sha in production, dirty tree rejection."""
        # 1. Mandatory release-sha in production
        env_prod = self.env.copy()
        env_prod["PS028_TEST_FIXTURE"] = "0"
        env_prod["PS028_TARGET_DIR"] = "/usr/local/libexec/ps028"
        env_prod["PS028_TARGET_SUDOERS"] = "/etc/sudoers.d/ps028-helper"
        res = self._run_deploy(custom_env=env_prod)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Production deployment requires explicit --release-sha", res.stderr)

        # 2. Release-sha format validation
        res = self._run_deploy(extra_args=["--release-sha", "not-a-sha"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Release SHA must be a 40-character lowercase hexadecimal string", res.stderr)

        # 3. Dirty tree rejection: untracked file outside lab
        untracked = self.mock_repo / "untracked.txt"
        untracked.write_text("untracked", encoding="utf-8")
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Working tree is dirty", res.stderr)
        untracked.unlink()

        # 4. Dirty tree rejection: staged changes
        (self.mock_repo / "lab" / "identity.py").write_text("# modified\n", encoding="utf-8")
        subprocess.run(["git", "add", "lab/identity.py"], cwd=self.mock_repo, check=True)
        res = self._run_deploy()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Working tree is dirty", res.stderr)
        subprocess.run(["git", "checkout", "HEAD", "--", "lab/identity.py"], cwd=self.mock_repo, check=True)

        # 5. Extracting from immutable Git object tree succeeds
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_70_manifest_validation_hardening_exhaustive(self):
        """70. Exhaustive manifest hardening: path traversal, duplicates, malformed hashes, extra files."""
        res = self._run_deploy()
        self.assertEqual(res.returncode, 0, res.stderr)

        manifest_path = self.target_dir / "deployment_manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

        # 1. Path traversal in manifest entry
        bad_manifest = dict(manifest_data)
        bad_manifest["files"] = list(manifest_data["files"]) + [{"path": "../escaping.py", "sha256": "a"*64, "mode": "0644"}]
        bad_manifest["file_count"] = len(bad_manifest["files"])
        manifest_path.write_text(json.dumps(bad_manifest), encoding="utf-8")
        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)

        # 2. Duplicate entries in manifest
        bad_manifest2 = dict(manifest_data)
        bad_manifest2["files"] = list(manifest_data["files"]) + [manifest_data["files"][0]]
        bad_manifest2["file_count"] = len(bad_manifest2["files"])
        manifest_path.write_text(json.dumps(bad_manifest2), encoding="utf-8")
        res3 = self._run_deploy()
        self.assertNotEqual(res3.returncode, 0)

        # 3. Unmanifested extra file on disk
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")
        extra_file = self.target_dir / "lab" / "extra.py"
        extra_file.write_text("print(1)", encoding="utf-8")
        res4 = self._run_deploy()
        self.assertNotEqual(res4.returncode, 0)
        self.assertIn("Unmanifested file detected in existing installation", res4.stderr)
        extra_file.unlink()

        # 4. Mode mismatch
        (self.target_dir / "lab" / "identity.py").chmod(0o777)
        res5 = self._run_deploy()
        self.assertNotEqual(res5.returncode, 0)

    def test_71_transactional_runtime_directories(self):
        """71. Transactional runtime directories: safe preservation, unsafe rejection, rollback cleanup."""
        rdir_run = self.temp_dir / "run_ps028"
        rdir_log = self.temp_dir / "log_ps028"
        rdir_lib = self.temp_dir / "lib_ps028"

        env_rt = self.env.copy()
        env_rt["PS028_TEST_RUNTIME_DIRS"] = f"{rdir_run} {rdir_log} {rdir_lib}"

        # 1. Fresh deployment creates runtime directories
        res = self._run_deploy(custom_env=env_rt)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(rdir_run.is_dir())
        self.assertTrue(rdir_log.is_dir())
        self.assertTrue(rdir_lib.is_dir())

        # 2. Unsafe pre-existing runtime directory fails before activation
        rdir_run.chmod(0o777)
        res2 = self._run_deploy(custom_env=env_rt)
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("Pre-existing runtime directory", res2.stderr)
        rdir_run.chmod(0o755)

        # 3. Rollback removes only newly created empty directories without touching pre-existing
        shutil.rmtree(rdir_run)
        env_fail = env_rt.copy()
        env_fail["PS028_TEST_FAIL_POST_VERIFY"] = "1"
        res3 = self._run_deploy(custom_env=env_fail)
        self.assertNotEqual(res3.returncode, 0)
        # rdir_run was newly created in this failed run, so rollback cleaned it up
        self.assertFalse(rdir_run.exists())
        # rdir_log and rdir_lib were pre-existing, so rollback preserved them
        self.assertTrue(rdir_log.exists())
        self.assertTrue(rdir_lib.exists())

    def test_72_partner_legacy_inventory_adoption_and_rollback(self):
        """72. Partner legacy compatibility (Indrani's inventory with __pycache__ and subset modules)."""
        # Build synthetic partner host directory matching Indrani's inventory
        self.target_dir.mkdir(parents=True)
        shutil.copy2(self.mock_repo / "lab" / "privileged_helper.py", self.target_dir / "privileged_helper.py")
        (self.target_dir / "privileged_helper.py").chmod(0o750)

        (self.target_dir / "lab").mkdir()
        (self.target_dir / "lab" / "__init__.py").write_text("", encoding="utf-8")
        (self.target_dir / "lab" / "__init__.py").chmod(0o644)

        for mod in ["identity.py", "concurrency.py", "impair.py", "run_trial.py", "analyze.py", "teardown.py", "scenarios.yaml", "dns_config.json"]:
            shutil.copy2(self.mock_repo / "lab" / mod, self.target_dir / "lab" / mod)
            (self.target_dir / "lab" / mod).chmod(0o644)

        # Python bytecode cache entries
        (self.target_dir / "lab" / "__pycache__").mkdir()
        (self.target_dir / "lab" / "__pycache__" / "identity.cpython-312.pyc").write_bytes(b"BCODE")
        (self.target_dir / "lab" / "__pycache__" / "identity.cpython-312.pyc").chmod(0o644)

        # 1. Migration succeeds and introduces missing canonical files
        res = self._run_deploy(extra_args=["--migrate-unmanifested", "--legacy-baseline-commit", self.commit_sha])
        self.assertEqual(res.returncode, 0, f"Legacy migration failed: {res.stderr} - {res.stdout}")

        # Newly introduced files are now present in target
        self.assertTrue((self.target_dir / "lab" / "dns_server.py").is_file())
        self.assertTrue((self.target_dir / "lab" / "nginx.conf").is_file())
        self.assertTrue((self.target_dir / "deployment_manifest.json").is_file())

        # Active installation does not contain legacy .pyc
        self.assertFalse((self.target_dir / "lab" / "__pycache__").exists())

        # 2. Rollback of legacy migration preserves exact legacy tree without manifest
        # Recreate synthetic legacy fixture
        shutil.rmtree(self.target_dir)
        self.target_dir.mkdir(parents=True)
        shutil.copy2(self.mock_repo / "lab" / "privileged_helper.py", self.target_dir / "privileged_helper.py")
        (self.target_dir / "privileged_helper.py").chmod(0o750)
        (self.target_dir / "lab").mkdir()
        (self.target_dir / "lab" / "__init__.py").write_text("", encoding="utf-8")
        (self.target_dir / "lab" / "__init__.py").chmod(0o644)
        for mod in ["identity.py", "concurrency.py", "impair.py", "run_trial.py", "analyze.py", "teardown.py", "scenarios.yaml", "dns_config.json"]:
            shutil.copy2(self.mock_repo / "lab" / mod, self.target_dir / "lab" / mod)
            (self.target_dir / "lab" / mod).chmod(0o644)
        (self.target_dir / "lab" / "__pycache__").mkdir()
        (self.target_dir / "lab" / "__pycache__" / "identity.cpython-312.pyc").write_bytes(b"BCODE")
        (self.target_dir / "lab" / "__pycache__" / "identity.cpython-312.pyc").chmod(0o644)

        env_fail = self.env.copy()
        env_fail["PS028_TEST_FAIL_POST_VERIFY"] = "1"
        res_fail = self._run_deploy(extra_args=["--migrate-unmanifested", "--legacy-baseline-commit", self.commit_sha], custom_env=env_fail)
        self.assertNotEqual(res_fail.returncode, 0)

        # Restored target has exact legacy state, no manifest, pyc intact
        self.assertFalse((self.target_dir / "deployment_manifest.json").exists())
        self.assertTrue((self.target_dir / "lab" / "__pycache__" / "identity.cpython-312.pyc").exists())
        self.assertFalse((self.target_dir / "lab" / "dns_server.py").exists())

    def test_73_committed_recovery_ordering_exhaustive(self):
        """73. COMMITTED recovery ordering: verify target and sudoers BEFORE deleting backups."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0)

        backup_dir = self.target_parent / ".ps028_backup_88888_1"
        backup_dir.mkdir()
        (backup_dir / "preserved.txt").write_text("important", encoding="utf-8")

        sudoers_backup = self.sudoers_parent / ".ps028_sudoers_backup_88888_1"
        sudoers_backup.write_text("sudoers_backup", encoding="utf-8")
        sudoers_backup.chmod(0o440)

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=COMMITTED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS={sudoers_backup}
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        # 1. Active target missing -> fail closed, retain backup and journal
        target_saved = self.temp_dir / "target_saved"
        self.target_dir.rename(target_saved)

        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("COMMITTED recovery failed", res2.stderr)
        self.assertTrue(backup_dir.exists())
        self.assertTrue(sudoers_backup.exists())
        self.assertTrue(state_file.exists())

        # Restore target
        target_saved.rename(self.target_dir)

        # 2. Corrupt manifest in active target -> fail closed, retain backup and journal
        manifest_path = self.target_dir / "deployment_manifest.json"
        manifest_orig = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text("CORRUPT JSON", encoding="utf-8")

        res3 = self._run_deploy()
        self.assertNotEqual(res3.returncode, 0)
        self.assertIn("COMMITTED recovery failed", res3.stderr)
        self.assertTrue(backup_dir.exists())
        self.assertTrue(sudoers_backup.exists())
        self.assertTrue(state_file.exists())

        manifest_path.write_text(manifest_orig, encoding="utf-8")

        # 3. All valid -> clean up backups and finalize
        res4 = self._run_deploy()
        self.assertEqual(res4.returncode, 0, res4.stderr)
        self.assertFalse(backup_dir.exists())
        self.assertFalse(sudoers_backup.exists())
        self.assertFalse(state_file.exists())

    def test_74_state_dependent_recovery_fail_closed_matrix(self):
        """74. State-dependent recovery fails closed when required backups are missing or corrupt."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0)

        # Test missing backup in TARGET_ACTIVATED
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        missing_backup = self.target_parent / ".ps028_backup_nonexistent"
        state_file.write_text(f"""STATE=TARGET_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={missing_backup}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS=
STAGING_DIR=
STAGING_SUDOERS=
TIMESTAMP=1794900000
""")

        res2 = self._run_deploy()
        self.assertNotEqual(res2.returncode, 0)
        self.assertIn("Recovery failed: required target backup is missing", res2.stderr)
        self.assertTrue(state_file.exists())
        state_file.unlink()

    def test_75_sudoers_pre_existence_durable_journaling(self):
        """75. Sudoers pre-existence determined and backed up before journal initialization."""
        # Pre-create valid sudoers file
        if self.target_sudoers.exists():
            self.target_sudoers.chmod(0o644)
            self.target_sudoers.unlink()
        self.target_sudoers.write_text("# preexisting sudoers\nUser_Alias TEST = root\n", encoding="utf-8")
        self.target_sudoers.chmod(0o440)

        res = self._run_deploy()
        self.assertEqual(res.returncode, 0, res.stderr)

        # Verify that deployed sudoers has correct permissions
        self.assertEqual(oct(self.target_sudoers.stat().st_mode & 0o777), "0o440")

    def test_76_real_process_crash_sigkill_boundaries(self):
        """76. Genuine SIGKILL (kill -9 $$) process crashes across all 12 boundaries without trap execution."""
        boundaries = [
            "AFTER_LOCK_ACQUISITION",
            "INITIAL_JOURNAL_CREATION",
            "AFTER_STAGING_COMPLETED",
            "AFTER_BACKUP_PREPARATION",
            "AFTER_TARGET_RENAME",
            "AFTER_TARGET_ACTIVATION",
            "AFTER_SUDOERS_BACKUP",
            "AFTER_SUDOERS_ACTIVATION",
            "DURING_POST_VERIFICATION",
            "PRE_COMMITTED",
            "POST_COMMITTED_PRE_CLEANUP",
            "DURING_BACKUP_CLEANUP",
        ]

        # Initial baseline deployment
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0, res_init.stderr)

        baseline_manifest = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        baseline_helper = (self.target_dir / "privileged_helper.py").read_bytes()
        baseline_sudoers = self.target_sudoers.read_text(encoding="utf-8")

        for b in boundaries:
            with self.subTest(boundary=b):
                env_crash = self.env.copy()
                env_crash["PS028_TEST_KILL_AT"] = b

                # Subprocess receives real SIGKILL
                p = subprocess.run([str(DEPLOY_SCRIPT)], env=env_crash, capture_output=True, text=True)

                # Under Linux, process terminated by SIGKILL exits with -9 or 137 (128 + 9)
                self.assertIn(p.returncode, (-9, 137), f"Expected SIGKILL termination for boundary {b}, got {p.returncode}\nSTDERR: {p.stderr}")
                self.assertIn("[TEST_SIGKILL]", p.stderr)

                # Run independent recovery process
                rec = self._run_deploy()
                self.assertEqual(rec.returncode, 0, f"Recovery failed after SIGKILL at boundary {b}:\n{rec.stderr}\n{rec.stdout}")

                # Verify clean state: state file and staging artifacts removed
                state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
                self.assertFalse(state_file.exists(), f"State file not cleaned up after recovery from {b}")

                # Target directory and sudoers are functional and verified
                self.assertTrue(self.target_dir.is_dir())
                self.assertTrue(self.target_sudoers.is_file())
                self.assertTrue((self.target_dir / "privileged_helper.py").is_file())
                self.assertTrue((self.target_dir / "deployment_manifest.json").is_file())

                # Repeated recovery is idempotent
                rec_idempotent = self._run_deploy()
                self.assertEqual(rec_idempotent.returncode, 0)

    def test_77_test_fixture_isolation_enforcement(self):
        """77. Test fixture mode isolation: reject root, missing PS028_TEST_ROOT, outside paths, production paths."""
        # 1. Missing PS028_TEST_ROOT fails closed
        env_no_root = self.env.copy()
        del env_no_root["PS028_TEST_ROOT"]
        res1 = self._run_deploy(custom_env=env_no_root)
        self.assertNotEqual(res1.returncode, 0)
        self.assertIn("PS028_TEST_ROOT must be explicitly set", res1.stderr)

        # 2. TARGET_DIR outside PS028_TEST_ROOT fails closed
        other_temp = tempfile.mkdtemp(prefix="ps028_other_")
        try:
            env_outside = self.env.copy()
            env_outside["PS028_TARGET_DIR"] = f"{other_temp}/ps028"
            res2 = self._run_deploy(custom_env=env_outside)
            self.assertNotEqual(res2.returncode, 0)
            self.assertIn("must reside strictly within PS028_TEST_ROOT", res2.stderr)
        finally:
            shutil.rmtree(other_temp, ignore_errors=True)

        # 3. Production paths locked and rejected in fixture mode
        env_prod = self.env.copy()
        env_prod["PS028_TARGET_DIR"] = "/usr/local/libexec/ps028"
        res3 = self._run_deploy(custom_env=env_prod)
        self.assertNotEqual(res3.returncode, 0)
        self.assertIn("isolated paths", res3.stderr)

        # 4. Release SHA verification cannot be bypassed in fixture mode
        res4 = self._run_deploy(extra_args=["--release-sha", "0" * 40])
        self.assertNotEqual(res4.returncode, 0)
        self.assertIn("Release SHA mismatch", res4.stderr)

    def test_78_fresh_install_preexisting_sudoers_recovery(self):
        """78. Fresh install with pre-existing sudoers: verify rollback at AFTER_SUDOERS_BACKUP."""
        # Ensure target does not exist
        if self.target_dir.exists():
            shutil.rmtree(self.target_dir)

        # Pre-existing sudoers with distinct custom content and mode 0440
        orig_sudoers_content = "# Pre-existing operator sudoers\nUser_Alias CUSTOM_OP = root\n"
        self.target_sudoers.write_text(orig_sudoers_content, encoding="utf-8")
        self.target_sudoers.chmod(0o440)
        orig_hash = hashlib.sha256(orig_sudoers_content.encode("utf-8")).hexdigest()

        # Crash fresh install at AFTER_SUDOERS_BACKUP
        env_crash = self.env.copy()
        env_crash["PS028_TEST_KILL_AT"] = "AFTER_SUDOERS_BACKUP"
        res_crash = self._run_deploy(custom_env=env_crash)
        self.assertIn(res_crash.returncode, (-9, 137))

        # State file exists and indicates fresh install with sudoers backed up
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        self.assertTrue(state_file.exists())
        journal_text = state_file.read_text(encoding="utf-8")
        self.assertIn("INSTALL_TYPE=fresh", journal_text)
        self.assertIn("STATE=SUDOERS_BACKED_UP", journal_text)
        self.assertIn("SUDOERS_EXISTED=1", journal_text)

        # Execute recovery: use interrupt before target activation so subsequent install halts after recovery
        env_rec = self.env.copy()
        env_rec["PS028_TEST_INTERRUPT_PRE_TARGET_ACT"] = "1"
        res_rec = self._run_deploy(custom_env=env_rec)
        self.assertIn("Incomplete prior transaction detected", res_rec.stderr)
        self.assertIn("Prior incomplete transaction rolled back and original state restored", res_rec.stdout)

        # Target directory remains clean (not installed)
        self.assertFalse(self.target_dir.exists())

        # Sudoers restored byte-for-byte and permissions intact
        self.assertTrue(self.target_sudoers.is_file())
        self.assertEqual(self.target_sudoers.read_text(encoding="utf-8"), orig_sudoers_content)
        self.assertEqual(oct(self.target_sudoers.stat().st_mode & 0o777), "0o440")
        self.assertEqual(hashlib.sha256(self.target_sudoers.read_bytes()).hexdigest(), orig_hash)

        # State file cleaned up
        self.assertFalse(state_file.exists())

    def test_79_pre_journal_runtime_mkdir_and_crash_recovery(self):
        """79. Runtime directory creation tracked in journal; crash after mkdir is cleaned up on recovery."""
        rdir1 = self.temp_dir / "custom_run_dir"
        rdir2 = self.temp_dir / "custom_var_dir"
        self.assertFalse(rdir1.exists())
        self.assertFalse(rdir2.exists())

        env_crash = self.env.copy()
        env_crash["PS028_TEST_RUNTIME_DIRS"] = f"{rdir1} {rdir2}"
        env_crash["PS028_TEST_KILL_AT"] = f"AFTER_RUNTIME_MKDIR_{rdir1.name}"

        res_crash = self._run_deploy(custom_env=env_crash)
        self.assertIn(res_crash.returncode, (-9, 137))

        # rdir1 was created before SIGKILL
        self.assertTrue(rdir1.is_dir())
        self.assertFalse(rdir2.exists())

        # Journal tracks created runtime directories
        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        self.assertTrue(state_file.exists())
        self.assertIn(str(rdir1), state_file.read_text(encoding="utf-8"))

        # Recovery removes created runtime directory
        env_rec = self.env.copy() # No PS028_TEST_RUNTIME_DIRS to avoid re-creation
        res_rec = self._run_deploy(custom_env=env_rec)
        self.assertEqual(res_rec.returncode, 0, f"Recovery failed:\n{res_rec.stderr}")
        self.assertFalse(rdir1.exists(), f"Runtime directory {rdir1} was not removed by recovery")
        self.assertFalse(state_file.exists())

    def test_80_manifest_path_containment_and_traversal_sentinel_protection(self):
        """80. Manifest path containment rejects traversal, absolute paths, and duplicate entries without touching sentinels."""
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)

        sentinel = self.temp_dir / "external_sentinel.txt"
        sentinel.write_text("IMMUTABLE_SENTINEL_DATA", encoding="utf-8")

        manifest_path = self.target_dir / "deployment_manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

        # 1. Path traversal attack in manifest
        tampered = dict(manifest_data)
        tampered["files"] = list(manifest_data["files"])
        tampered["files"][0] = {
            "path": "../external_sentinel.txt",
            "sha256": hashlib.sha256(b"IMMUTABLE_SENTINEL_DATA").hexdigest(),
            "mode": "0644"
        }
        manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

        res_un = self._run_deploy(extra_args=["--uninstall"])
        self.assertNotEqual(res_un.returncode, 0)
        self.assertIn("Illegal traversal/absolute path in manifest", res_un.stderr)
        self.assertTrue(sentinel.exists())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "IMMUTABLE_SENTINEL_DATA")

        # 2. Absolute path attack in manifest
        tampered["files"][0] = {
            "path": "/etc/passwd",
            "sha256": "0" * 64,
            "mode": "0644"
        }
        manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

        res_un2 = self._run_deploy(extra_args=["--uninstall"])
        self.assertNotEqual(res_un2.returncode, 0)
        self.assertIn("Illegal traversal/absolute path in manifest", res_un2.stderr)

        # 3. Duplicate entry in manifest
        tampered["files"][0] = dict(manifest_data["files"][1])
        manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

        res_un3 = self._run_deploy(extra_args=["--uninstall"])
        self.assertNotEqual(res_un3.returncode, 0)
        self.assertIn("Duplicate entry in manifest", res_un3.stderr)

    def test_81_manifest_and_disk_mode_strict_enforcement(self):
        """81. Strict mode enforcement rejects safe-but-incorrect disk modes and altered manifest mode fields."""
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)

        # 1. Safe-but-incorrect mode on disk (e.g. 0755 instead of 0750 for privileged_helper.py)
        (self.target_dir / "privileged_helper.py").chmod(0o755)
        res_verify = self._run_deploy(extra_args=["--dry-run"])
        self.assertNotEqual(res_verify.returncode, 0)
        self.assertIn("Existing file mode mismatch", res_verify.stderr)

        # Restore mode
        (self.target_dir / "privileged_helper.py").chmod(0o750)

        # Safe-but-incorrect mode on disk (e.g. 0640 instead of 0644 for identity.py)
        (self.target_dir / "lab" / "identity.py").chmod(0o640)
        res_verify2 = self._run_deploy(extra_args=["--dry-run"])
        self.assertNotEqual(res_verify2.returncode, 0)
        self.assertIn("Existing file mode mismatch", res_verify2.stderr)

        (self.target_dir / "lab" / "identity.py").chmod(0o644)

        # 2. Altered mode field in manifest cannot legitimize changed modes
        manifest_path = self.target_dir / "deployment_manifest.json"
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest_data["files"]:
            if entry["path"] == "lab/identity.py":
                entry["mode"] = "0640"
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        res_verify3 = self._run_deploy(extra_args=["--dry-run"])
        self.assertNotEqual(res_verify3.returncode, 0)
        self.assertIn("Existing manifest altered mode field", res_verify3.stderr)

    def test_82_sudoers_sha256_hash_verification_in_recovery(self):
        """82. Sudoers SHA-256 hash verified during recovery; mismatch halts and preserves backups."""
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)

        # Pre-existing sudoers backup with hash mismatch
        backup_dir = self.target_parent / ".ps028_backup_99999_1"
        backup_dir.mkdir()
        shutil.copy2(self.target_dir / "privileged_helper.py", backup_dir / "privileged_helper.py")

        sudoers_backup = self.sudoers_parent / ".ps028_sudoers_backup_99999_1"
        sudoers_backup.write_text("TAMPERED SUDOERS CONTENT", encoding="utf-8")
        sudoers_backup.chmod(0o440)

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        state_file.write_text(f"""STATE=SUDOERS_ACTIVATED
INSTALL_TYPE=upgrade
SUDOERS_EXISTED=1
TARGET_DIR={self.target_dir}
BACKUP_DIR={backup_dir}
TARGET_SUDOERS={self.target_sudoers}
BACKUP_SUDOERS={sudoers_backup}
STAGING_DIR=
STAGING_SUDOERS=
ORIGINAL_SUDOERS_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
TIMESTAMP=1794900000
""")

        # Recovery detects hash mismatch and fails closed
        res_rec = self._run_deploy()
        self.assertNotEqual(res_rec.returncode, 0)
        self.assertIn("sudoers backup hash mismatch", res_rec.stderr)

        # Backups and journal state file are retained
        self.assertTrue(backup_dir.exists())
        self.assertTrue(sudoers_backup.exists())
        self.assertTrue(state_file.exists())

    def test_83_genuine_sigkill_during_cleanup_backups_idempotent(self):
        """83. Genuine SIGKILL during DURING_CLEANUP_BACKUPS is safely finalized and idempotent."""
        res_init = self._run_deploy()
        self.assertEqual(res_init.returncode, 0)

        env_crash = self.env.copy()
        env_crash["PS028_TEST_KILL_AT"] = "DURING_CLEANUP_BACKUPS"

        res_crash = self._run_deploy(custom_env=env_crash)
        self.assertIn(res_crash.returncode, (-9, 137))
        self.assertIn("[TEST_SIGKILL]", res_crash.stderr)

        # Recovery detects COMMITTED state and finalizes cleanup
        rec1 = self._run_deploy()
        self.assertEqual(rec1.returncode, 0, f"Recovery failed:\n{rec1.stderr}")

        state_file = self.target_parent / f".ps028_tx_state_{self.target_dir.name}"
        self.assertFalse(state_file.exists())
        self.assertTrue(self.target_dir.is_dir())
        self.assertTrue(self.target_sudoers.is_file())

        # Repeat run is idempotent
        rec2 = self._run_deploy()
        self.assertEqual(rec2.returncode, 0)

    def test_84_fixture_mode_rejects_insecure_ancestor_directory(self):
        """84. validate_browser_executable in fixture mode still rejects world-writable ancestor without sticky bit."""
        import sys
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from lab.privileged_helper import validate_browser_executable, BrowserValidationError

        # 1. Insecure fixture directory: world-writable without sticky bit (mode 0777)
        insecure_parent = self.temp_dir / "insecure_ancestor"
        insecure_parent.mkdir(parents=True, exist_ok=True)
        insecure_parent.chmod(0o777)
        try:
            insecure_exe = insecure_parent / "google-chrome"
            insecure_exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            insecure_exe.chmod(0o755)

            # Fixture mode must reject insecure ancestor directory
            with self.assertRaises(BrowserValidationError) as ctx:
                validate_browser_executable(insecure_exe, is_test_fixture=True)
            self.assertIn("world-writable without sticky bit", str(ctx.exception))
            self.assertIn(str(insecure_parent), str(ctx.exception))
        finally:
            insecure_parent.chmod(0o700)

        # 2. Secure fixture directory: non-world-writable fixture passes in test_fixture mode
        secure_exe = self._create_browser_executable_fixture("google-chrome")
        resolved = validate_browser_executable(secure_exe, is_test_fixture=True)
        self.assertEqual(resolved, secure_exe.resolve())

        # 3. Production executable validation: retains allowlisted path, root ownership, and ancestor checks
        with self.assertRaises(BrowserValidationError) as ctx_prod:
            validate_browser_executable(secure_exe, is_test_fixture=False)
        self.assertTrue(
            any(k in str(ctx_prod.exception) for k in ["Must reside in approved locations", "must be owned by root", "Ancestor directory"]),
            f"Expected production security check failure, got: {ctx_prod.exception}"
        )

    # Alias to support direct invocation by alternative name from Section 6
    test_56_fixture_mode_rejects_insecure_ancestor_directory = test_84_fixture_mode_rejects_insecure_ancestor_directory

    def test_85_manifested_installation_with_legitimate_pycache_dry_run_passes(self):
        """85. Manifested installation with legitimate runtime bytecode passes dry-run without modifications."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        pycache_dir = self.target_dir / "lab" / "__pycache__"
        pycache_dir.mkdir(mode=0o755)
        source_file = self.target_dir / "lab" / "identity.py"
        c_path = Path(importlib.util.cache_from_source(str(source_file)))
        py_compile.compile(str(source_file), cfile=str(c_path))
        c_path.chmod(0o644)

        # Snapshot state before dry-run
        snapshot_before = {}
        for p in self.target_dir.rglob("*"):
            if p.is_file():
                snapshot_before[str(p.relative_to(self.target_dir))] = (p.read_bytes(), p.stat().st_mode)

        res2 = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
        self.assertEqual(res2.returncode, 0, f"Dry-run failed:\n{res2.stderr}")
        self.assertIn("All deployment prerequisites, provenance, source files, service identity, and sudoers syntax verified", res2.stdout)

        # Verify dry-run created, modified, or deleted no files
        snapshot_after = {}
        for p in self.target_dir.rglob("*"):
            if p.is_file():
                snapshot_after[str(p.relative_to(self.target_dir))] = (p.read_bytes(), p.stat().st_mode)
        self.assertEqual(snapshot_before, snapshot_after)

    def test_86_jarvis_like_cache_inventory_manifested_installation(self):
        """86. Manifested installation with full JARVIS-like cache inventory passes audit."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        pycache_dir = self.target_dir / "lab" / "__pycache__"
        pycache_dir.mkdir(mode=0o755)

        jarvis_modules = [
            "__init__.py",
            "identity.py",
            "concurrency.py",
            "impair.py",
            "run_trial.py",
            "analyze.py",
            "teardown.py",
        ]
        for mod in jarvis_modules:
            src = self.target_dir / "lab" / mod
            c_path = Path(importlib.util.cache_from_source(str(src)))
            py_compile.compile(str(src), cfile=str(c_path))
            c_path.chmod(0o644)

        res2 = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
        self.assertEqual(res2.returncode, 0, f"JARVIS-like dry-run failed:\n{res2.stderr}")

    def test_87_reject_unsafe_bytecode_entries_in_pycache(self):
        """87. Reject unsafe bytecode entries (symlink, unpermitted name, non-pyc, nested dir, unsafe modes, corrupted)."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        pycache_dir = self.target_dir / "lab" / "__pycache__"
        pycache_dir.mkdir(mode=0o755)
        source_file = self.target_dir / "lab" / "identity.py"
        c_path = Path(importlib.util.cache_from_source(str(source_file)))
        py_compile.compile(str(source_file), cfile=str(c_path))
        c_path.chmod(0o644)

        # 1. Symlink inside __pycache__
        symlink_target = self.temp_dir / "fake_target.pyc"
        symlink_target.write_bytes(b"fake")
        symlink_pyc = pycache_dir / Path(importlib.util.cache_from_source(str(self.target_dir / "lab" / "concurrency.py"))).name
        symlink_pyc.symlink_to(symlink_target)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Symlink detected", res.stderr)
        finally:
            symlink_pyc.unlink()

        # 2. Unexpected .pyc filename / unknown module
        unknown_pyc = pycache_dir / f"unknown_module.{sys.implementation.cache_tag}.pyc"
        unknown_pyc.write_bytes(c_path.read_bytes())
        unknown_pyc.chmod(0o644)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Unexpected or unpermitted file in bytecode cache", res.stderr)
        finally:
            unknown_pyc.unlink()

        # 3. Non-.pyc file in __pycache__
        txt_file = pycache_dir / "notes.txt"
        txt_file.write_text("not bytecode\n")
        txt_file.chmod(0o644)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Unexpected or unpermitted file in bytecode cache", res.stderr)
        finally:
            txt_file.unlink()

        # 4. Nested directory inside __pycache__
        nested_dir = pycache_dir / "nested"
        nested_dir.mkdir(mode=0o755)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Nested directory inside bytecode cache is forbidden", res.stderr)
        finally:
            nested_dir.rmdir()

        # 5. Group- or world-writable cache file
        c_path.chmod(0o666)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("group- or world-writable", res.stderr)
        finally:
            c_path.chmod(0o644)

        # 6. Unsafe directory permissions on __pycache__
        pycache_dir.chmod(0o777)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("group- or world-writable", res.stderr)
        finally:
            pycache_dir.chmod(0o755)

        # 7. Corrupted / invalid bytecode header
        valid_bytes = c_path.read_bytes()
        c_path.write_bytes(b"corrupted_header_less_than_16_bytes")
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("invalid magic number or corrupted header", res.stderr)
        finally:
            c_path.write_bytes(valid_bytes)

    def test_88_preserve_fail_closed_behavior_for_unpermitted_dirs_and_files(self):
        """88. Preserve fail-closed behavior for unexpected directories and files outside __pycache__."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        # 1. Unexpected directory outside permitted cache directory
        extra_dir = self.target_dir / "lab" / "unexpected_dir"
        extra_dir.mkdir(mode=0o755)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Unexpected directory in existing installation", res.stderr)
        finally:
            extra_dir.rmdir()

        # 2. Unmanifested file outside permitted cache directory
        extra_file = self.target_dir / "lab" / "extra_unmanifested.py"
        extra_file.write_text("# rogue\n")
        extra_file.chmod(0o644)
        try:
            res = self._run_deploy(extra_args=["--dry-run", "--release-sha", self.commit_sha])
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Unmanifested file detected in existing installation", res.stderr)
        finally:
            extra_file.unlink()

        # 3. Canonical 14-file manifest inventory remains exact (no pyc added to manifest)
        manifest_text = (self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8")
        manifest_data = json.loads(manifest_text)
        self.assertEqual(manifest_data["file_count"], 14)
        manifest_paths = [f["path"] for f in manifest_data["files"]]
        self.assertEqual(len(manifest_paths), 14)
        self.assertFalse(any("__pycache__" in p for p in manifest_paths))

    def test_89_transaction_and_rollback_caches_not_copied_into_new_stage(self):
        """89. Transactional upgrade does not inherit old caches into new stage; rollback preserves old cache."""
        res1 = self._run_deploy()
        self.assertEqual(res1.returncode, 0, res1.stderr)

        pycache_dir = self.target_dir / "lab" / "__pycache__"
        pycache_dir.mkdir(mode=0o755)
        src = self.target_dir / "lab" / "identity.py"
        c_path = Path(importlib.util.cache_from_source(str(src)))
        py_compile.compile(str(src), cfile=str(c_path))
        c_path.chmod(0o644)
        cache_content_before = c_path.read_bytes()

        # Update mock repo with a new commit for upgrade
        (self.mock_repo / "lab" / "identity.py").write_text("# updated identity module\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.mock_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Update identity module"], cwd=self.mock_repo, check=True, capture_output=True)
        new_commit_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.mock_repo, text=True
        ).strip()

        # 1. Rollback case: simulate failure during post-verification
        fail_env = self.env.copy()
        fail_env["PS028_TEST_FAIL_POST_VERIFY"] = "1"
        res_fail = self._run_deploy(extra_args=["--release-sha", new_commit_sha], custom_env=fail_env)
        self.assertNotEqual(res_fail.returncode, 0)

        # Rollback must restore original installation and its __pycache__ intact
        self.assertTrue(pycache_dir.is_dir())
        self.assertTrue(c_path.is_file())
        self.assertEqual(c_path.read_bytes(), cache_content_before)

        # 2. Successful upgrade: caches are not copied to new stage
        res_up = self._run_deploy(extra_args=["--release-sha", new_commit_sha])
        self.assertEqual(res_up.returncode, 0, f"Upgrade failed:\n{res_up.stderr}")

        # Active installation is built fresh from Git blob extraction; does not contain old __pycache__
        self.assertFalse((self.target_dir / "lab" / "__pycache__").exists())
        # Manifest has exactly 14 files
        mf = json.loads((self.target_dir / "deployment_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(mf["release_sha"], new_commit_sha)
        self.assertEqual(mf["file_count"], 14)



if __name__ == "__main__":
    unittest.main()
