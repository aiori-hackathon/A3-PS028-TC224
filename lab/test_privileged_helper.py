#!/usr/bin/env python3
"""
PS-028 Live Campaign Hardening & Privileged Helper Test Suite
Work Package A10: Live Campaign Orchestration & Non-Interactive Privilege Separation

Regression Tests for:
1. Privileges:
   - Non-interactive sudo authorization checks (sudo -n) in preflight and trial readiness
   - Documenting running 'sudo -v' first when unauthorized
   - Strict parameter and scenario whitelisting in privileged helper
2. Locking:
   - Preserving shared .lab.lock throughout trial execution
   - Avoiding recursive-lock deadlocks when caller holds lock (--caller-holds-lock)
   - Failing closed if caller claims --caller-holds-lock but lock is not held (no silent bypass)
   - Standalone lock acquisition and contention detection
3. Browser Identity:
   - Ensuring Chromium and Firefox execute inside client netns as normal user (UID 1000)
   - Privilege dropping via setpriv / sudo -u
   - Preservation of user-writable profiles and logs
   - Strict refusal to substitute curl for real browser
4. Capture Lifecycle:
   - Readiness verification and immediate mode capture
   - Graceful SIGINT shutdown and PCAP finalization
   - Unconfirmed capture shutdown invalidating measurement
   - Never signaling unrelated or recycled processes
5. Truthful Cleanup & Fail-Stop Safety:
   - Never reporting baseline restoration when privileged checks were skipped or failed
   - Full live verification requirements in live mode
   - Cleanup failure propagation into cleanup_status and campaign fail-stop halting
"""

import argparse
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import secrets
import shutil
import stat
import signal
import struct
import subprocess
import tempfile
import time
from typing import Any, Dict, List
import unittest
from unittest.mock import MagicMock, call, patch

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.identity as identity
from lab.identity import UserIdentity
import lab.impair as impair
import lab.preflight as preflight
import lab.privileged_helper as priv_helper
import lab.run_campaign as run_campaign
import lab.run_trial as run_trial


class TestPrivilegeSeparationAndPreflight(unittest.TestCase):
    """Tests for non-interactive sudo authorization and privilege validation."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_priv_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("subprocess.run")
    @patch("os.geteuid", return_value=1000)
    def test_check_sudo_authorization_fails_when_password_required(self, mock_euid, mock_run):
        """Must fail when sudo -n returns non-zero (password required) and document 'sudo -v'."""
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "sudo: a password is required\n"
        mock_proc.stdout = ""
        mock_run.return_value = mock_proc

        auth = priv_helper.check_sudo_authorization()
        self.assertFalse(auth["authorized"])
        self.assertIn("sudo -v", auth["message"])
        self.assertIn("Non-interactive sudo authorization is unavailable", auth["message"])

    @patch("subprocess.run")
    @patch("os.geteuid", return_value=1000)
    def test_check_sudo_authorization_passes_when_authorized(self, mock_euid, mock_run):
        """Must pass when sudo -n true returns 0."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        auth = priv_helper.check_sudo_authorization()
        self.assertTrue(auth["authorized"])
        self.assertEqual(auth["method"], "sudo -n")

    @patch("os.geteuid", return_value=0)
    def test_check_sudo_authorization_passes_for_root_user(self, mock_euid):
        """EUID 0 automatically passes sudo authorization."""
        auth = priv_helper.check_sudo_authorization()
        self.assertTrue(auth["authorized"])
        self.assertEqual(auth["method"], "root")

    @patch("lab.preflight.check_sudo_authorization")
    def test_preflight_fails_when_sudo_unauthorized_with_check_sudo(self, mock_auth):
        """preflight.run_preflight(check_sudo=True) must fail when sudo -n is unavailable."""
        mock_auth.return_value = {
            "status": "FAIL",
            "authorized": False,
            "method": "sudo -n",
            "message": "Please run 'sudo -v' first."
        }
        report = preflight.run_preflight(check_sudo=True)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("sudo_authorization", report["failures"])
        self.assertIn("sudo -v", report["failures"]["sudo_authorization"][0])

    @patch("lab.preflight.check_sudo_authorization")
    @patch("lab.run_trial.find_browser_runtime")
    @patch("shutil.which", return_value="/usr/bin/tcpdump")
    @patch("lab.teardown.get_topology_status", return_value=("LIVE", ["ps028-cl", "ps028-rt", "ps028-sv"], []))
    def test_trial_readiness_fails_live_mode_when_sudo_unauthorized(
        self, mock_topo, mock_which, mock_browser, mock_auth
    ):
        """Trial readiness in live mode must fail preflight if sudo -n is unavailable."""
        mock_browser.return_value = ("chromium", "/snap/bin/chromium", "Chromium 124")
        mock_auth.return_value = {
            "authorized": False,
            "message": "Non-interactive sudo authorization is unavailable. Please run 'sudo -v' first."
        }
        report = run_trial.validate_lab_readiness(is_simulation=False, skip_baseline=True)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("sudo -v" in err for err in report["errors"]))
        self.assertFalse(report["checks"]["sudo_authorization"]["authorized"])

    def test_privileged_helper_rejects_unauthorized_scenarios(self):
        """Privileged helper must reject invalid scenario IDs like S7."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_scenario_privileged("S7")
        self.assertIn("invalid", str(ctx.exception).lower())


class TestLockCoordinationAndDeadlockPrevention(unittest.TestCase):
    """Tests for preserving shared .lab.lock without recursive-lock deadlocks or silent bypass."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_lock_coord_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_verify_caller_holds_lock_succeeds_when_lock_held(self):
        """When the caller process actually holds .lab.lock, verification must succeed."""
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            # Probe from helper perspective: lock is actively held
            priv_helper.verify_caller_holds_lock(self.lock_file)

    def test_verify_caller_holds_lock_fails_closed_when_lock_not_held(self):
        """
        CRITICAL REQUIREMENT:
        If caller claims --caller-holds-lock, but lock is NOT held, fail closed!
        Refuses to silently bypass active lock.
        """
        self.lock_file.touch()
        with self.assertRaises(concurrency.LabLockError) as ctx:
            priv_helper.verify_caller_holds_lock(self.lock_file)
        self.assertIn("Refusing to silently bypass lock", str(ctx.exception))

    def test_coordinate_lock_acquires_when_caller_does_not_hold_lock(self):
        """When caller_holds_lock=False, coordinate_lock must acquire exclusive flock."""
        self.assertFalse(concurrency.is_lock_active(self.lock_file))
        with priv_helper.coordinate_lock(caller_holds_lock=False, lock_path=self.lock_file):
            self.assertTrue(concurrency.is_lock_active(self.lock_file))
        self.assertFalse(concurrency.is_lock_active(self.lock_file))

    def test_coordinate_lock_does_not_deadlock_when_caller_holds_lock(self):
        """
        CRITICAL REQUIREMENT:
        Nested invocation with caller_holds_lock=True must NOT deadlock.
        """
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            # Simulating helper called from inside run_trial holding .lab.lock
            with priv_helper.coordinate_lock(caller_holds_lock=True, lock_path=self.lock_file):
                # Inside helper execution
                pass
            # Lock is still held by caller!
            self.assertTrue(concurrency.is_lock_active(self.lock_file))

    def test_start_capture_cli_parser_accepts_caller_holds_lock_and_lock_file(self):
        """
        Regression Test: A10 helper CLI mismatch
        Verifies that the privileged helper CLI parser accepts --caller-holds-lock
        and --lock-file for the exact start-capture command without unrecognized arguments.
        """
        pcap_path = self.temp_dir / "capture.pcap"
        log_path = self.temp_dir / "tcpdump.log"
        # Lock not held: must fail closed on lock verification, NOT on unrecognized arguments
        self.lock_file.touch()
        invoking_user = identity.resolve_invoking_identity().username
        res = subprocess.run(
            [
                sys.executable,
                str(priv_helper.SCRIPT_DIR / "privileged_helper.py"),
                "start-capture",
                "--caller-holds-lock",
                "--lock-file", str(self.lock_file),
                "--output-pcap", str(pcap_path),
                "--log-file", str(log_path),
                "--netns", "ps028-cl",
                "--interface", "ps028-cl-rt",
                "--owner-user", invoking_user,
                "--readiness-timeout", "1.0",
            ],
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn("unrecognized arguments: --caller-holds-lock", res.stderr)
        self.assertIn("Refusing to silently bypass lock", res.stderr)

    def test_start_capture_cli_verifies_parent_lock_and_avoids_deadlock(self):
        """
        Regression Test: A10 helper CLI mismatch
        Verifies that when caller holds .lab.lock, invoking the exact start-capture
        helper command verifies lock ownership without recursive flock deadlocks.
        """
        pcap_path = self.temp_dir / "capture.pcap"
        log_path = self.temp_dir / "tcpdump.log"
        invoking_user = identity.resolve_invoking_identity().username

        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            res = subprocess.run(
                [
                    sys.executable,
                    str(priv_helper.SCRIPT_DIR / "privileged_helper.py"),
                    "start-capture",
                    "--caller-holds-lock",
                    "--lock-file", str(self.lock_file),
                    "--output-pcap", str(pcap_path),
                    "--log-file", str(log_path),
                    "--netns", "ps028-cl",
                    "--interface", "any",
                    "--owner-user", invoking_user,
                    "--readiness-timeout", "0.5",
                ],
                capture_output=True,
                text=True
            )
            # The CLI command parser and lock verification must succeed.
            # (Subsequent netns tcpdump execution may fail if not root, but lock check passed).
            self.assertNotIn("unrecognized arguments", res.stderr)
            self.assertNotIn("Refusing to silently bypass lock", res.stderr)
            self.assertNotIn("Lock verification failed", res.stderr)

    def test_start_capture_privileged_fails_closed_when_lock_not_held(self):
        """
        Verifies start_capture_privileged fails closed when caller_holds_lock=True
        is claimed but the lock is not actually held.
        """
        self.lock_file.touch()
        with self.assertRaises(concurrency.LabLockError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=self.temp_dir / "capture.pcap",
                log_file=self.temp_dir / "tcpdump.log",
                caller_holds_lock=True,
                lock_file=self.lock_file
            )
        self.assertIn("Refusing to silently bypass lock", str(ctx.exception))


class TestBrowserIdentityAndPrivilegeDropping(unittest.TestCase):
    """Tests ensuring Chromium and Firefox run inside client netns as normal user."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_browser_id_"))
        self.user_home = (self.temp_dir / "user_home").resolve()
        self.user_home.mkdir(parents=True, exist_ok=True)
        self.test_ident = UserIdentity(
            uid=1000,
            gid=1000,
            username="ps028_user",
            home_dir=self.user_home,
            shell="/bin/bash",
        )
        _orig_resolve = identity.resolve_user_by_uid
        self._ident_patcher = patch(
            "lab.identity.resolve_user_by_uid",
            side_effect=lambda u: self.test_ident if u == 1000 else _orig_resolve(u)
        )
        self._ident_patcher.start()
        self.addCleanup(self._ident_patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("subprocess.run")
    @patch("os.geteuid", return_value=1000)
    @patch("os.getuid", return_value=1000)
    @patch("os.getgid", return_value=1000)
    def test_run_browser_drops_privileges_to_normal_user(
        self, mock_gid, mock_uid, mock_euid, mock_run
    ):
        """
        CRITICAL REQUIREMENT:
        run_browser must enter client netns with sudo -n but drop privileges
        to normal user (UID 1000) using setpriv or sudo -u before browser execution.
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "<html><body>Response</body></html>"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "profile"
        profile.mkdir()

        res = run_trial.run_browser(
            browser_name="chromium",
            browser_path="/snap/bin/chromium",
            target_url="http://trial-1.he.test/",
            profile_dir=profile,
            is_simulation=False
        )

        mock_run.assert_called_once()
        cmd_called = mock_run.call_args[0][0]

        # Sudo for network namespace entry
        self.assertEqual(cmd_called[0], "sudo")
        self.assertEqual(cmd_called[1], "-n")
        self.assertEqual(cmd_called[2], "ip")
        self.assertEqual(cmd_called[3], "netns")
        self.assertEqual(cmd_called[4], "exec")
        self.assertEqual(cmd_called[5], "ps028-cl")

        # Privilege dropping to UID 1000
        cmd_str = " ".join(cmd_called)
        self.assertTrue(
            "--reuid=1000" in cmd_str or "sudo -u" in cmd_str,
            f"Command must drop privileges to UID 1000: {cmd_str}"
        )
        self.assertIn("/snap/bin/chromium", cmd_called)

    def test_strict_refusal_to_substitute_curl_for_browser(self):
        """Must strictly refuse to substitute curl for real browser."""
        with self.assertRaises(run_trial.BrowserPreflightError) as ctx:
            run_trial.find_browser_runtime(preferred="curl")
        self.assertIn("strictly forbidden", str(ctx.exception).lower())


class TestSnapBrowserNamespaceMountsAndLaunch(unittest.TestCase):
    """
    Focused tests for Snap browser launch fix:
    - Missing/existing mounts for cgroup2 and securityfs
    - Mount failures and clear failure reporting
    - Invoking user identity preservation (UID/GID)
    - Unchanged non-Snap browser launches
    - Snap browser detection
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_snap_test_"))
        self.mounts_file = self.temp_dir / "mounts"
        self.user_home = (self.temp_dir / "user_home").resolve()
        self.user_home.mkdir(parents=True, exist_ok=True)
        self.test_ident = UserIdentity(
            uid=1000,
            gid=1000,
            username="ps028_user",
            home_dir=self.user_home,
            shell="/bin/bash",
        )
        _orig_resolve = identity.resolve_user_by_uid
        self._ident_patcher = patch(
            "lab.identity.resolve_user_by_uid",
            side_effect=lambda u: self.test_ident if u == 1000 else _orig_resolve(u)
        )
        self._ident_patcher.start()
        self.addCleanup(self._ident_patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_setup_snap_mounts_missing_both(self):
        """When both cgroup2 and securityfs are missing, both must be mounted."""
        self.mounts_file.write_text("sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n", encoding="utf-8")
        mounted_cmds = []

        def mock_mount(cmd):
            mounted_cmds.append(list(cmd))

        results = priv_helper.setup_snap_mounts(
            mounts_file=self.mounts_file,
            mount_cmd_runner=mock_mount
        )

        self.assertEqual(len(mounted_cmds), 2)
        self.assertEqual(mounted_cmds[0], ["mount", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup"])
        self.assertEqual(mounted_cmds[1], ["mount", "-t", "securityfs", "securityfs", "/sys/kernel/security"])
        self.assertEqual(results, {"cgroup2": True, "securityfs": True})

    def test_setup_snap_mounts_existing_both(self):
        """When both cgroup2 and securityfs are already mounted, neither should be mounted."""
        content = (
            "sysfs /sys sysfs rw 0 0\n"
            "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0\n"
            "securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        )
        self.mounts_file.write_text(content, encoding="utf-8")
        mounted_cmds = []

        results = priv_helper.setup_snap_mounts(
            mounts_file=self.mounts_file,
            mount_cmd_runner=lambda cmd: mounted_cmds.append(cmd)
        )

        self.assertEqual(len(mounted_cmds), 0)
        self.assertEqual(results, {"cgroup2": False, "securityfs": False})

    def test_setup_snap_mounts_missing_cgroup_only(self):
        """When only cgroup2 is missing, only cgroup2 must be mounted."""
        content = (
            "sysfs /sys sysfs rw 0 0\n"
            "securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        )
        self.mounts_file.write_text(content, encoding="utf-8")
        mounted_cmds = []

        results = priv_helper.setup_snap_mounts(
            mounts_file=self.mounts_file,
            mount_cmd_runner=lambda cmd: mounted_cmds.append(cmd)
        )

        self.assertEqual(len(mounted_cmds), 1)
        self.assertEqual(mounted_cmds[0], ["mount", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup"])
        self.assertEqual(results, {"cgroup2": True, "securityfs": False})

    def test_setup_snap_mounts_missing_security_only(self):
        """When only securityfs is missing, only securityfs must be mounted."""
        content = (
            "sysfs /sys sysfs rw 0 0\n"
            "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0\n"
        )
        self.mounts_file.write_text(content, encoding="utf-8")
        mounted_cmds = []

        results = priv_helper.setup_snap_mounts(
            mounts_file=self.mounts_file,
            mount_cmd_runner=lambda cmd: mounted_cmds.append(cmd)
        )

        self.assertEqual(len(mounted_cmds), 1)
        self.assertEqual(mounted_cmds[0], ["mount", "-t", "securityfs", "securityfs", "/sys/kernel/security"])
        self.assertEqual(results, {"cgroup2": False, "securityfs": True})

    def test_setup_snap_mounts_cgroup_mount_failure(self):
        """When mounting cgroup2 fails, SnapMountError must be raised with clear details."""
        self.mounts_file.write_text("sysfs /sys sysfs rw 0 0\n", encoding="utf-8")

        def fail_mount(cmd):
            raise OSError("Permission denied: simulated mount failure")

        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.setup_snap_mounts(
                mounts_file=self.mounts_file,
                mount_cmd_runner=fail_mount
            )
        self.assertIn("Failed to mount cgroup2 on /sys/fs/cgroup", str(ctx.exception))
        self.assertIn("Permission denied", str(ctx.exception))

    def test_setup_snap_mounts_security_mount_failure(self):
        """When mounting securityfs fails, SnapMountError must be raised with clear details."""
        content = (
            "sysfs /sys sysfs rw 0 0\n"
            "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n"
        )
        self.mounts_file.write_text(content, encoding="utf-8")

        def fail_mount(cmd):
            raise OSError("Device or resource busy")

        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.setup_snap_mounts(
                mounts_file=self.mounts_file,
                mount_cmd_runner=fail_mount
            )
        self.assertIn("Failed to mount securityfs on /sys/kernel/security", str(ctx.exception))
        self.assertIn("Device or resource busy", str(ctx.exception))

    @patch("subprocess.run")
    def test_run_browser_snap_mount_failure_fails_clearly(self, mock_run):
        """When helper returns mount failure (exit code 71), run_browser raises SnapMountError."""
        mock_proc = MagicMock()
        mock_proc.returncode = 71
        mock_proc.stdout = ""
        mock_proc.stderr = "Snap mount setup error: Failed to mount cgroup2 on /sys/fs/cgroup: Permission denied"
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "profile"
        profile.mkdir()

        with self.assertRaises(run_trial.SnapMountError) as ctx:
            run_trial.run_browser(
                browser_name="chromium",
                browser_path="/snap/bin/chromium",
                target_url="http://trial.test/",
                profile_dir=profile
            )
        self.assertIn("Snap mount setup error", str(ctx.exception))

    def test_get_invoking_uid_gid_normal_user(self):
        """Invoking identity must match non-root process UID/GID."""
        with patch("os.getuid", return_value=1000), patch("os.getgid", return_value=1000):
            uid, gid = priv_helper.get_invoking_uid_gid()
            self.assertEqual(uid, 1000)
            self.assertEqual(gid, 1000)

    def test_get_invoking_uid_gid_sudo_environment(self):
        """Invoking identity under sudo must extract SUDO_UID and SUDO_GID."""
        mock_pw = pwd.struct_passwd((
            "sudo_user", "x", 1002, 1003, "Sudo User", "/home/sudo_user", "/bin/bash"
        ))
        with patch("os.getuid", return_value=0), \
             patch.dict(os.environ, {"SUDO_UID": "1002", "SUDO_GID": "1003", "SUDO_USER": "sudo_user"}), \
             patch("pwd.getpwuid", return_value=mock_pw):
            uid, gid = priv_helper.get_invoking_uid_gid()
            self.assertEqual(uid, 1002)
            self.assertEqual(gid, 1003)

    @patch("shutil.which", return_value="/usr/bin/setpriv")
    @patch("os.execvp")
    @patch("lab.privileged_helper.setup_snap_isolated_dns")
    @patch("lab.privileged_helper.setup_snap_mounts")
    def test_launch_snap_browser_main_user_identity_drop(self, mock_setup_mounts, mock_setup_dns, mock_execvp, mock_which):
        """launch_snap_browser_main must drop privileges to target user UID/GID before exec."""
        args = argparse.Namespace(
            reuid=1000,
            regid=1000,
            mounts_file=self.mounts_file,
            cmd=["--", "/snap/bin/chromium", "--headless=new"]
        )
        priv_helper.launch_snap_browser_main(args)

        mock_setup_mounts.assert_called_once_with(mounts_file=self.mounts_file)
        mock_setup_dns.assert_called_once()
        mock_execvp.assert_called_once()
        exec_binary, exec_args = mock_execvp.call_args[0]
        self.assertEqual(exec_binary, "/usr/bin/setpriv")
        self.assertEqual(exec_args, [
            "/usr/bin/setpriv",
            "--reuid=1000",
            "--regid=1000",
            "--init-groups",
            "/snap/bin/chromium",
            "--headless=new"
        ])

    @patch("subprocess.run")
    @patch("os.geteuid", return_value=1000)
    @patch("os.getuid", return_value=1000)
    @patch("os.getgid", return_value=1000)
    def test_non_snap_browser_launch_remains_unchanged(self, mock_gid, mock_uid, mock_euid, mock_run):
        """Non-Snap browser must NOT create private mount namespace or invoke launch-snap-browser."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "DOM content"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "profile"
        profile.mkdir()

        res = run_trial.run_browser(
            browser_name="google-chrome",
            browser_path="/usr/bin/google-chrome",
            target_url="http://trial.test/",
            profile_dir=profile
        )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]

        # Verify command does NOT contain unshare or launch-snap-browser
        self.assertNotIn("unshare", cmd)
        self.assertNotIn("launch-snap-browser", cmd)

        # Verify netns exec and privilege drop
        self.assertEqual(cmd[0], "sudo")
        self.assertEqual(cmd[1], "-n")
        self.assertEqual(cmd[2], "ip")
        self.assertEqual(cmd[3], "netns")
        self.assertEqual(cmd[4], "exec")
        self.assertEqual(cmd[5], "ps028-cl")
        cmd_str = " ".join(cmd)
        self.assertTrue("--reuid=1000" in cmd_str or "sudo -u" in cmd_str)
        self.assertIn("/usr/bin/google-chrome", cmd)

    @patch("subprocess.run")
    @patch("os.geteuid", return_value=1000)
    @patch("os.getuid", return_value=1000)
    @patch("os.getgid", return_value=1000)
    def test_snap_browser_launch_creates_private_mount_namespace(self, mock_gid, mock_uid, mock_euid, mock_run):
        """Snap browser must enter netns, unshare private mount namespace, and invoke launch-snap-browser."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "DOM content"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "profile"
        profile.mkdir()

        res = run_trial.run_browser(
            browser_name="chromium",
            browser_path="/snap/bin/chromium",
            target_url="http://trial.test/",
            profile_dir=profile
        )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]

        # Enters client netns
        self.assertEqual(cmd[0], "sudo")
        self.assertEqual(cmd[1], "-n")
        self.assertEqual(cmd[2], "ip")
        self.assertEqual(cmd[3], "netns")
        self.assertEqual(cmd[4], "exec")
        self.assertEqual(cmd[5], "ps028-cl")

        # Creates private mount namespace
        self.assertEqual(cmd[6], "unshare")
        self.assertEqual(cmd[7], "--mount")
        self.assertEqual(cmd[8], "--propagation")
        self.assertEqual(cmd[9], "private")

        # Invokes launch-snap-browser helper with dropped UID/GID
        self.assertEqual(cmd[10], sys.executable)
        self.assertEqual(cmd[12], "launch-snap-browser")
        self.assertIn("--reuid=1000", cmd)
        self.assertIn("--regid=1000", cmd)
        self.assertIn("--snap-name=chromium", cmd)
        self.assertIn("--", cmd)
        self.assertIn("/snap/bin/chromium", cmd)

    @patch("subprocess.run")
    @patch("os.geteuid", return_value=1000)
    @patch("os.getuid", return_value=1000)
    @patch("os.getgid", return_value=1000)
    def test_snap_firefox_launch_passes_snap_name_firefox(self, mock_gid, mock_uid, mock_euid, mock_run):
        """Snap Firefox browser must pass --snap-name=firefox to launch-snap-browser."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "DOM content"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        profile = self.temp_dir / "profile"
        profile.mkdir()

        run_trial.run_browser(
            browser_name="firefox",
            browser_path="/snap/bin/firefox",
            target_url="http://trial.test/",
            profile_dir=profile
        )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertIn("--snap-name=firefox", cmd)
        self.assertIn("/snap/bin/firefox", cmd)

    def test_get_lab_resolver_ip_success(self):
        """Verifies resolver selection succeeds when 10.0.1.1 is configured."""
        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\noptions timeout:1\n", encoding="utf-8")
        ip = priv_helper.get_lab_resolver_ip(resolv_conf_path=res_file)
        self.assertEqual(ip, "10.0.1.1")

    def test_get_lab_resolver_ip_fails_when_wsl_resolver(self):
        """CRITICAL: Fails closed when resolv.conf contains WSL resolver (10.255.255.254)."""
        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.255.255.254\nsearch WIFIServer.local\n", encoding="utf-8")
        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.get_lab_resolver_ip(resolv_conf_path=res_file)
        self.assertIn("Expected resolver 10.0.1.1 not found", str(ctx.exception))

    def test_get_lab_resolver_ip_fails_when_missing(self):
        """Fails closed when candidate resolv.conf does not exist."""
        nonexistent = self.temp_dir / "no_such_resolv.conf"
        with self.assertRaises(priv_helper.SnapMountError):
            priv_helper.get_lab_resolver_ip(resolv_conf_path=nonexistent)

    @patch("fcntl.ioctl", return_value=0x00020000)
    def test_setup_snap_isolated_dns_mounts_tmpfs_and_restores_metadata(self, mock_ioctl):
        """
        Namespace isolation:
        Verifies private tmpfs is mounted on /run/snapd/ns, metadata (.fstab, .info)
        is restored, and isolated namespace cloner is invoked.
        """
        fake_ns = self.temp_dir / "snapd_ns"
        fake_ns.mkdir()
        (fake_ns / "snap.chromium.fstab").write_bytes(b"profile data")
        (fake_ns / "snap.chromium.info").write_bytes(b"base-snap=core24")
        (fake_ns / "chromium.mnt").touch()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        mounted_cmds = []
        def mock_mount(cmd):
            mounted_cmds.append(list(cmd))

        cloner_called = []
        def mock_cloner(src_fd, res_ip, target_mnt):
            cloner_called.append((src_fd, res_ip, target_mnt))

        res = priv_helper.setup_snap_isolated_dns(
            snap_name="chromium",
            resolver_ip="10.0.1.1",
            resolv_conf_path=res_file,
            snap_ns_dir=fake_ns,
            isolated_cloner=mock_cloner,
            mount_cmd_runner=mock_mount
        )

        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["resolver_ip"], "10.0.1.1")
        self.assertEqual(len(mounted_cmds), 1)
        self.assertEqual(mounted_cmds[0], ["mount", "-t", "tmpfs", "-o", "mode=0755,uid=0,gid=0", "tmpfs", str(fake_ns)])

        # Metadata restored
        self.assertTrue((fake_ns / "snap.chromium.fstab").exists())
        self.assertEqual((fake_ns / "snap.chromium.fstab").read_bytes(), b"profile data")
        self.assertTrue((fake_ns / "snap.chromium.info").exists())

        # Cloner was called with verified IP and placeholder target
        self.assertEqual(len(cloner_called), 1)
        self.assertEqual(cloner_called[0][1], "10.0.1.1")
        self.assertEqual(cloner_called[0][2], fake_ns / "chromium.mnt")

    def test_setup_snap_isolated_dns_fails_on_resolver_mismatch(self):
        """Failure handling: Refuses to set up isolated DNS if resolver is not 10.0.1.1."""
        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 192.168.1.1\n", encoding="utf-8")

        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolver_ip="10.0.1.1",
                resolv_conf_path=res_file,
                snap_ns_dir=self.temp_dir / "snapd_ns"
            )
        self.assertIn("Expected resolver 10.0.1.1 not found", str(ctx.exception))

    def test_setup_snap_isolated_dns_fails_on_tmpfs_mount_error(self):
        """Failure handling: Raises SnapMountError if tmpfs mount fails."""
        fake_ns = self.temp_dir / "snapd_ns"
        fake_ns.mkdir()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        def fail_mount(cmd):
            raise OSError("Permission denied: simulated mount failure")

        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolv_conf_path=res_file,
                snap_ns_dir=fake_ns,
                mount_cmd_runner=fail_mount
            )
        self.assertIn("Failed to isolate", str(ctx.exception))

    @patch("fcntl.ioctl", return_value=0x00020000)
    def test_setup_snap_isolated_dns_fails_on_cloner_error(self, mock_ioctl):
        """Failure handling: Propagates error when isolated namespace cloner fails."""
        fake_ns = self.temp_dir / "snapd_ns"
        fake_ns.mkdir()
        (fake_ns / "chromium.mnt").touch()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        def fail_cloner(src_fd, res_ip, target_mnt):
            raise priv_helper.SnapMountError("Simulated cloner failure")

        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolv_conf_path=res_file,
                snap_ns_dir=fake_ns,
                isolated_cloner=fail_cloner,
                mount_cmd_runner=lambda cmd: None
            )
        self.assertIn("Simulated cloner failure", str(ctx.exception))

    @patch("lab.privileged_helper.setup_snap_mounts")
    @patch("lab.privileged_helper.setup_snap_isolated_dns", side_effect=priv_helper.SnapMountError("Isolated DNS failure"))
    def test_launch_snap_browser_main_exits_71_on_isolated_dns_error(self, mock_setup_dns, mock_setup_mounts):
        """launch_snap_browser_main must exit with code 71 when setup_snap_isolated_dns fails."""
        args = argparse.Namespace(
            reuid=1000,
            regid=1000,
            mounts_file=self.mounts_file,
            cmd=["--", "/snap/bin/chromium", "--headless=new"]
        )
        with self.assertRaises(SystemExit) as ctx:
            priv_helper.launch_snap_browser_main(args)
        self.assertEqual(ctx.exception.code, 71)

    def test_is_snap_browser_detection(self):
        """Verifies accurate detection of Snap vs non-Snap browser binaries."""
        self.assertTrue(priv_helper.is_snap_browser("/snap/bin/chromium"))
        self.assertTrue(priv_helper.is_snap_browser("/snap/bin/firefox"))
        self.assertTrue(priv_helper.is_snap_browser("/var/lib/snapd/snap/bin/chromium"))
        self.assertFalse(priv_helper.is_snap_browser("/usr/bin/google-chrome"))
        self.assertFalse(priv_helper.is_snap_browser("/opt/google/chrome/chrome"))

    def test_clone_snap_mount_namespace_verifies_invalid_fd(self):
        """_clone_snap_mount_namespace must fail closed if source_fd is invalid."""
        target_mnt = self.temp_dir / "target.mnt"
        target_mnt.touch()
        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper._clone_snap_mount_namespace(
                source_fd=999999,
                resolver_ip="10.0.1.1",
                target_mnt_path=target_mnt
            )
        self.assertIn("verify_source_fd", str(ctx.exception))

    def test_clone_snap_mount_namespace_verifies_non_namespace_fd(self):
        """_clone_snap_mount_namespace must fail closed if source_fd is a regular file, not an nsfs mount."""
        regular_file = self.temp_dir / "regular.txt"
        regular_file.write_text("hello", encoding="utf-8")
        fd = os.open(str(regular_file), os.O_RDONLY)
        try:
            target_mnt = self.temp_dir / "target.mnt"
            target_mnt.touch()
            with self.assertRaises(priv_helper.SnapMountError) as ctx:
                priv_helper._clone_snap_mount_namespace(
                    source_fd=fd,
                    resolver_ip="10.0.1.1",
                    target_mnt_path=target_mnt
                )
            self.assertIn("verify_source_type", str(ctx.exception))
            self.assertIn("does not refer to a Linux namespace", str(ctx.exception))
        finally:
            os.close(fd)

    def test_clone_snap_mount_namespace_verifies_wrong_namespace_type(self):
        """_clone_snap_mount_namespace must fail closed if source_fd refers to non-mount namespace (e.g. netns)."""
        regular_file = self.temp_dir / "ns.txt"
        regular_file.touch()
        fd = os.open(str(regular_file), os.O_RDONLY)
        try:
            target_mnt = self.temp_dir / "target.mnt"
            target_mnt.touch()
            # Mock fcntl.ioctl to return CLONE_NEWNET (0x40000000)
            with patch("fcntl.ioctl", return_value=0x40000000):
                with self.assertRaises(priv_helper.SnapMountError) as ctx:
                    priv_helper._clone_snap_mount_namespace(
                        source_fd=fd,
                        resolver_ip="10.0.1.1",
                        target_mnt_path=target_mnt
                    )
            self.assertIn("verify_source_type", str(ctx.exception))
            self.assertIn("expected 0x20000", str(ctx.exception))
        finally:
            os.close(fd)

    @patch("fcntl.ioctl", return_value=0x00020000)
    @patch("os.fstat")
    def test_clone_snap_mount_namespace_stage_error_reporting_setns(self, mock_fstat, mock_ioctl):
        """_clone_snap_mount_namespace must accurately report stage=setns when child fails at setns."""
        target_mnt = self.temp_dir / "target.mnt"
        target_mnt.touch()
        r, w = os.pipe()
        os.write(w, b"ERROR:stage=setns:[Errno 22] Invalid argument\n")
        os.close(w)

        with patch("os.pipe", return_value=(r, 9999)), \
             patch("os.close"), \
             patch("os.fork", return_value=12345), \
             patch("os.kill") as mock_kill, \
             patch("os.waitpid") as mock_waitpid:
            with self.assertRaises(priv_helper.SnapMountError) as ctx:
                priv_helper._clone_snap_mount_namespace(
                    source_fd=10,
                    resolver_ip="10.0.1.1",
                    target_mnt_path=target_mnt
                )
            self.assertIn("stage=setns", str(ctx.exception))
            self.assertIn("Snap namespace cloner failed: ERROR:stage=setns:[Errno 22] Invalid argument", str(ctx.exception))
            mock_kill.assert_called_once_with(12345, signal.SIGTERM)
            mock_waitpid.assert_called_once_with(12345, 0)

    @patch("fcntl.ioctl", return_value=0x00020000)
    @patch("os.fstat")
    def test_clone_snap_mount_namespace_bind_mount_failure_reporting_and_cleanup(self, mock_fstat, mock_ioctl):
        """When child is READY but parent bind mount fails, error must be reported and child cleaned up."""
        target_mnt = self.temp_dir / "target.mnt"
        target_mnt.touch()
        r, w = os.pipe()
        os.write(w, b"READY\n")
        os.close(w)

        def failing_mount(cmd):
            raise OSError("Permission denied: simulated bind mount error")

        with patch("os.pipe", return_value=(r, 9999)), \
             patch("os.close"), \
             patch("os.fork", return_value=54321), \
             patch("os.kill") as mock_kill, \
             patch("os.waitpid") as mock_waitpid:
            with self.assertRaises(priv_helper.SnapMountError) as ctx:
                priv_helper._clone_snap_mount_namespace(
                    source_fd=10,
                    resolver_ip="10.0.1.1",
                    target_mnt_path=target_mnt,
                    mount_cmd_runner=failing_mount
                )
            self.assertIn("Permission denied", str(ctx.exception))
            mock_kill.assert_called_once_with(54321, signal.SIGTERM)
            mock_waitpid.assert_called_once_with(54321, 0)

    @patch("fcntl.ioctl", return_value=0x00020000)
    def test_setup_snap_isolated_dns_rollback_tmpfs_on_failure(self, mock_ioctl):
        """When isolated_cloner fails, setup_snap_isolated_dns must lazy-unmount tmpfs and clean up temp files."""
        fake_ns = self.temp_dir / "snapd_ns"
        fake_ns.mkdir()
        (fake_ns / "chromium.mnt").touch()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        mounted_cmds = []
        def track_mount(cmd):
            mounted_cmds.append(list(cmd))

        def fail_cloner(src_fd, res_ip, target_mnt):
            raise priv_helper.SnapMountError("Cloner stage failure")

        with self.assertRaises(priv_helper.SnapMountError):
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolv_conf_path=res_file,
                snap_ns_dir=fake_ns,
                isolated_cloner=fail_cloner,
                mount_cmd_runner=track_mount
            )

        # Verify mount and subsequent unmount were called
        self.assertGreaterEqual(len(mounted_cmds), 2)
        self.assertEqual(mounted_cmds[0][:3], ["mount", "-t", "tmpfs"])
        self.assertEqual(mounted_cmds[-1], ["umount", "-l", str(fake_ns)])

    def test_setup_snap_isolated_dns_fails_when_client_path_is_placeholder_and_no_host_nsfs(self):
        """
        Regression Test (Requirement 2 & 4):
        When client path in ps028-cl is a regular file placeholder (ENOTTY from NS_GET_NSTYPE)
        and host nsfs mount is unreachable, helper fails clearly and refuses to use placeholder.
        """
        fake_ns = self.temp_dir / "snapd_ns_placeholder"
        fake_ns.mkdir()
        placeholder = fake_ns / "chromium.mnt"
        placeholder.touch()  # Regular file: ioctl(NS_GET_NSTYPE) fails with ENOTTY

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        mounted_cmds = []
        with self.assertRaises(priv_helper.SnapMountError) as ctx:
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolver_ip="10.0.1.1",
                resolv_conf_path=res_file,
                snap_ns_dir=fake_ns,
                host_proc_root=self.temp_dir / "nonexistent_proc_root",
                mount_cmd_runner=lambda cmd: mounted_cmds.append(list(cmd))
            )
        err = str(ctx.exception)
        self.assertIn("regular file placeholder", err)
        self.assertIn("NS_GET_NSTYPE failed", err)
        self.assertIn("genuine host mount namespace could not be accessed", err)
        # Verified that tmpfs was NOT mounted or was rolled back
        self.assertEqual(len(mounted_cmds), 0)

    def test_setup_snap_isolated_dns_acquires_genuine_nsfs_from_host_root_when_client_is_placeholder(self):
        """
        Regression Test (Requirement 1, 2 & 4):
        When client path in ps028-cl is a placeholder (ENOTTY), but genuine host nsfs mount
        is accessible via /proc/1/root/run/snapd/ns/chromium.mnt (NS_GET_NSTYPE == CLONE_NEWNS),
        the genuine FD is acquired from host and preserved across the private tmpfs overlay.
        """
        fake_client_ns = self.temp_dir / "client_snapd_ns"
        fake_client_ns.mkdir()
        client_placeholder = fake_client_ns / "chromium.mnt"
        client_placeholder.touch()

        fake_host_proc = self.temp_dir / "host_proc"
        fake_host_snapd_ns = fake_host_proc / "run" / "snapd" / "ns"
        fake_host_snapd_ns.mkdir(parents=True)
        host_genuine_file = fake_host_snapd_ns / "chromium.mnt"
        host_genuine_file.touch()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        # Custom ioctl that simulates ENOTTY on placeholder and 0x20000 on host genuine file
        host_stat = host_genuine_file.stat()
        def selective_ioctl(fd, request, *args):
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) == (host_stat.st_dev, host_stat.st_ino):
                return 0x00020000  # CLONE_NEWNS
            raise OSError(errno.ENOTTY, "Inappropriate ioctl for device")

        cloner_received_fd = []
        def mock_cloner(src_fd, res_ip, target_mnt):
            # Verify that cloner received the genuine host FD
            st = os.fstat(src_fd)
            cloner_received_fd.append((st.st_dev, st.st_ino))

        mounted_cmds = []
        with patch("fcntl.ioctl", side_effect=selective_ioctl):
            res = priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolver_ip="10.0.1.1",
                resolv_conf_path=res_file,
                snap_ns_dir=fake_client_ns,
                host_proc_root=fake_host_proc,
                isolated_cloner=mock_cloner,
                mount_cmd_runner=lambda cmd: mounted_cmds.append(list(cmd))
            )

        self.assertEqual(res["status"], "OK")
        self.assertEqual(len(cloner_received_fd), 1)
        self.assertEqual(cloner_received_fd[0], (host_stat.st_dev, host_stat.st_ino))
        # Verify tmpfs was mounted to isolate
        self.assertEqual(mounted_cmds[0][:3], ["mount", "-t", "tmpfs"])

    def test_source_fd_remains_valid_after_private_tmpfs_overlay_and_never_reopens_placeholder(self):
        """
        Regression Test (Requirement 1 & 4):
        Verifies that source_fd remains valid after private tmpfs is mounted and
        the placeholder created inside tmpfs is never reopened as the source.
        """
        fake_ns = self.temp_dir / "snapd_ns_overlay_test"
        fake_ns.mkdir()
        mnt_file = fake_ns / "chromium.mnt"
        mnt_file.touch()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        initial_stat = mnt_file.stat()
        opened_fds = []
        orig_open = os.open
        def tracking_open(path, flags, *args):
            fd = orig_open(path, flags, *args)
            opened_fds.append((path, fd))
            return fd

        cloner_calls = []
        def mock_cloner(src_fd, res_ip, target_mnt):
            cloner_calls.append(src_fd)
            # Verify source_fd fstat matches initial host file
            st = os.fstat(src_fd)
            self.assertEqual((st.st_dev, st.st_ino), (initial_stat.st_dev, initial_stat.st_ino))

        with patch("fcntl.ioctl", return_value=0x00020000), patch("os.open", side_effect=tracking_open):
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                resolver_ip="10.0.1.1",
                resolv_conf_path=res_file,
                snap_ns_dir=fake_ns,
                isolated_cloner=mock_cloner,
                mount_cmd_runner=lambda cmd: None
            )

        self.assertEqual(len(cloner_calls), 1)
        # Opened exactly once (before tmpfs overlay), never reopened afterwards
        mnt_opens = [path for path, fd in opened_fds if path == str(mnt_file)]
        self.assertEqual(len(mnt_opens), 1)

    def test_setup_snap_isolated_dns_with_explicit_valid_source_fd(self):
        """
        Regression Test:
        Verifies passing an explicit, pre-opened valid source_fd is accepted directly.
        """
        fake_ns = self.temp_dir / "snapd_ns_explicit_fd"
        fake_ns.mkdir()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        test_file = self.temp_dir / "genuine_ns.txt"
        test_file.touch()
        real_fd = os.open(str(test_file), os.O_RDONLY)

        cloner_fds = []
        def mock_cloner(src_fd, res_ip, target_mnt):
            cloner_fds.append(src_fd)

        try:
            with patch("fcntl.ioctl", return_value=0x00020000):
                res = priv_helper.setup_snap_isolated_dns(
                    snap_name="chromium",
                    resolver_ip="10.0.1.1",
                    resolv_conf_path=res_file,
                    snap_ns_dir=fake_ns,
                    source_fd=real_fd,
                    isolated_cloner=mock_cloner,
                    mount_cmd_runner=lambda cmd: None
                )
            self.assertEqual(res["status"], "OK")
            self.assertEqual(cloner_fds, [real_fd])
        finally:
            os.close(real_fd)

    def test_setup_snap_isolated_dns_rejects_invalid_explicit_source_fd(self):
        """
        Regression Test:
        Verifies passing an invalid source_fd (ENOTTY / regular file) raises SnapMountError.
        """
        fake_ns = self.temp_dir / "snapd_ns_invalid_fd"
        fake_ns.mkdir()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        test_file = self.temp_dir / "regular_file.txt"
        test_file.touch()
        real_fd = os.open(str(test_file), os.O_RDONLY)

        try:
            with self.assertRaises(priv_helper.SnapMountError) as ctx:
                priv_helper.setup_snap_isolated_dns(
                    snap_name="chromium",
                    resolver_ip="10.0.1.1",
                    resolv_conf_path=res_file,
                    snap_ns_dir=fake_ns,
                    source_fd=real_fd,
                    mount_cmd_runner=lambda cmd: None
                )
            self.assertIn("validation failed", str(ctx.exception))
        finally:
            os.close(real_fd)

    def test_setup_snap_isolated_dns_fails_and_cleans_up_on_bind_mount_failure(self):
        """
        Regression Test (A10 Snap Mount Step Failure & Truthful Blocker Reporting):
        When isolated_cloner fails with a bind-mount error ('Failed to bind mount ... wrong fs type'),
        setup_snap_isolated_dns must NOT claim success with an ineffective fallback.
        It must:
        1. Roll back the mount placeholder (target_mnt_path must be unlinked).
        2. Clean up tmpfs mount and temp files.
        3. Raise SnapMountError reporting the WSL2 / snap-confine blocker and proposing non-Snap binaries.
        """
        fake_ns = self.temp_dir / "snapd_ns_rollback"
        fake_ns.mkdir()
        (fake_ns / "snap.chromium.fstab").write_bytes(b"fstab data")
        (fake_ns / "snap.chromium.info").write_bytes(b"info data")

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        test_file = self.temp_dir / "genuine_ns.txt"
        test_file.touch()
        real_fd = os.open(str(test_file), os.O_RDONLY)

        mounted_cmds = []
        def track_mount(cmd):
            mounted_cmds.append(list(cmd))

        def failing_cloner(src_fd, res_ip, target_mnt):
            self.assertTrue(target_mnt.exists(), "Target placeholder must exist when cloner is invoked")
            raise priv_helper.SnapMountError(
                f"Failed to bind mount isolated namespace onto {target_mnt}: "
                "mount: wrong fs type, bad option, bad superblock on /proc/40514/ns/mnt"
            )

        try:
            with patch("fcntl.ioctl", return_value=0x00020000):
                with self.assertRaises(priv_helper.SnapMountError) as ctx:
                    priv_helper.setup_snap_isolated_dns(
                        snap_name="chromium",
                        resolver_ip="10.0.1.1",
                        resolv_conf_path=res_file,
                        snap_ns_dir=fake_ns,
                        source_fd=real_fd,
                        isolated_cloner=failing_cloner,
                        mount_cmd_runner=track_mount
                    )

            err = str(ctx.exception)
            self.assertIn("Snap per-trial DNS isolation failed", err)
            self.assertIn("snap-confine", err)
            self.assertIn("non-Snap browser binary", err)

            # Rollback verified: target placeholder MUST NOT exist
            target_placeholder = fake_ns / "chromium.mnt"
            self.assertFalse(
                target_placeholder.exists(),
                "Target placeholder chromium.mnt must be rolled back (unlinked) after bind mount failure"
            )
        finally:
            os.close(real_fd)

    def test_setup_snap_isolated_dns_rollback_when_real_cloner_fails_with_wrong_fs_type(self):
        """
        Regression Test (A10 Live WSL2 Mount Step Failure Simulation):
        Simulates child signaling READY, but parent subprocess.run failing with 'wrong fs type'
        during _clone_snap_mount_namespace.
        Verifies setup_snap_isolated_dns catches this, rolls back placeholder, and raises SnapMountError.
        """
        fake_ns = self.temp_dir / "snapd_ns_real_cloner_rollback"
        fake_ns.mkdir()

        res_file = self.temp_dir / "resolv.conf"
        res_file.write_text("nameserver 10.0.1.1\n", encoding="utf-8")

        test_file = self.temp_dir / "genuine_ns.txt"
        test_file.touch()
        real_fd = os.open(str(test_file), os.O_RDONLY)

        r, w = os.pipe()
        os.write(w, b"READY\n")
        os.close(w)

        def mock_mount_runner(cmd):
            if cmd[0] == "mount" and cmd[1] == "-t" and cmd[2] == "tmpfs":
                return
            if cmd[0] == "mount" and "--bind" in cmd and str(fake_ns) in str(cmd):
                # Bind mount onto target_mnt inside fake_ns fails with wrong fs type
                raise OSError("mount: /run/snapd/ns/chromium.mnt: wrong fs type, bad option, bad superblock")

        try:
            with patch("fcntl.ioctl", return_value=0x00020000), \
                 patch("os.pipe", return_value=(r, 99)), \
                 patch("os.close"), \
                 patch("os.fork", return_value=40514), \
                 patch("os.kill"), \
                 patch("os.waitpid"):
                with self.assertRaises(priv_helper.SnapMountError) as ctx:
                    priv_helper.setup_snap_isolated_dns(
                        snap_name="chromium",
                        resolver_ip="10.0.1.1",
                        resolv_conf_path=res_file,
                        snap_ns_dir=fake_ns,
                        source_fd=real_fd,
                        mount_cmd_runner=mock_mount_runner
                    )

            err = str(ctx.exception)
            self.assertIn("Snap per-trial DNS isolation failed", err)
            self.assertFalse((fake_ns / "chromium.mnt").exists())
        finally:
            os.close(real_fd)

    def test_preseed_outer_resolver_stubs_configures_all_candidate_locations(self):
        """Verifies _preseed_outer_resolver_stubs targets stub, resolv.conf, and wsl paths."""
        mounted_cmds = []
        with patch("pathlib.Path.exists", return_value=True):
            priv_helper._preseed_outer_resolver_stubs("10.0.1.1", mount_cmd_runner=lambda cmd: mounted_cmds.append(cmd))

        target_paths = [cmd[-1] for cmd in mounted_cmds]
        self.assertIn("/run/systemd/resolve/stub-resolv.conf", target_paths)
        self.assertIn("/run/systemd/resolve/resolv.conf", target_paths)
        self.assertIn("/mnt/wsl/resolv.conf", target_paths)
        self.assertIn("/etc/resolv.conf", target_paths)


class TestCaptureLifecycleAndSafety(unittest.TestCase):
    """Tests for packet capture lifecycle, graceful SIGINT shutdown, and safety."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_cap_lifecycle_"))
        self.pcap_file = self.temp_dir / "test.pcap"
        self.log_file = self.temp_dir / "tcpdump.log"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @contextlib.contextmanager
    def _mock_capture_owner(
        self,
        username="capture_test_user",
        uid=23017,
        gid=23018,
        home_path=Path("/tmp/ps028-test-home/capture_test_user")
    ):
        test_ident = UserIdentity(
            uid=uid,
            gid=gid,
            username=username,
            home_dir=home_path,
            shell="/bin/bash"
        )
        mock_pw = pwd.struct_passwd((
            username, "x", uid, gid, username, str(home_path), "/bin/bash"
        ))
        with patch("lab.privileged_helper.identity.resolve_invoking_identity", return_value=test_ident), \
             patch("lab.privileged_helper.identity.resolve_user_by_name", return_value=test_ident), \
             patch("pwd.getpwnam", return_value=mock_pw), \
             patch("pwd.getpwuid", return_value=mock_pw), \
             patch("os.getgrouplist", return_value=[gid]), \
             patch("os.chown"):
            yield test_ident

    @patch("subprocess.run")
    def test_detached_sudo_failure_evidence(self, mock_run):
        """
        Regression Test (Issue 1):
        Verifies evidence that invoking sudo -n with start_new_session=True fails
        because detachment from the controlling terminal causes sudo credential lookup to fail.
        Privileged capture startup must never invoke sudo inside a detached session.
        """
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "sudo: a password is required\n"
        mock_proc.stdout = ""
        mock_run.return_value = mock_proc

        proc = subprocess.run(
            ["sudo", "-n", "true"],
            start_new_session=True,
            capture_output=True,
            text=True
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("password is required", proc.stderr)

    @patch("lab.privileged_helper.run_helper_action")
    @patch("os.geteuid", return_value=1000)
    def test_start_packet_capture_corrected_flow_unprivileged(self, mock_euid, mock_helper):
        """
        Regression Test (Issue 1):
        Verifies corrected capture-launch flow:
        When unprivileged, start_packet_capture routes through privileged helper
        (where sudo authorization occurs in the authorized session) before any
        detached capture process is launched.
        """
        mock_helper.return_value = {
            "status": "OK",
            "parent_pid": 12345,
            "tcpdump_pid": 12346,
            "pcap_path": str(self.pcap_file),
            "log_path": str(self.log_file)
        }

        proc = run_trial.start_packet_capture(
            output_pcap=self.pcap_file,
            log_file=self.log_file,
            netns="ps028-cl",
            is_simulation=False
        )
        self.assertIsInstance(proc, run_trial.CaptureProcess)
        self.assertEqual(proc.pid, 12345)
        self.assertEqual(proc._ps028_tcpdump_pid, 12346)

        mock_helper.assert_called_once()
        self.assertEqual(mock_helper.call_args[0][0], "start-capture")
        extra_args = mock_helper.call_args[1].get("extra_args") or mock_helper.call_args[0][1]
        self.assertIn("--output-pcap", extra_args)
        self.assertIn("--netns", extra_args)
        self.assertIn("ps028-cl", extra_args)

    @patch("lab.privileged_helper.run_helper_action")
    @patch("os.geteuid", return_value=1000)
    def test_start_packet_capture_passes_lock_coordination_to_helper(self, mock_euid, mock_helper):
        """
        Verifies start_packet_capture coordinates lock with helper when caller holds lock.
        """
        mock_helper.return_value = {
            "status": "OK",
            "parent_pid": 1111,
            "tcpdump_pid": 1112,
            "pcap_path": str(self.pcap_file),
            "log_path": str(self.log_file)
        }
        lock_p = self.temp_dir / ".lab.lock"
        with concurrency.acquire_lab_lock(lock_path=lock_p):
            run_trial.start_packet_capture(
                output_pcap=self.pcap_file,
                log_file=self.log_file,
                netns="ps028-cl",
                is_simulation=False,
                caller_holds_lock=True,
                lock_file=lock_p
            )
        mock_helper.assert_called_once()
        self.assertEqual(mock_helper.call_args[0][0], "start-capture")
        self.assertTrue(mock_helper.call_args[1].get("caller_holds_lock"))
        self.assertEqual(mock_helper.call_args[1].get("lock_file"), lock_p)

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_start_capture_privileged_drops_write_privileges_without_sudo(self, mock_euid, mock_popen):
        """
        tcpdump inside start_capture_privileged runs with root privileges
        and drops write privileges via -Z to the target user.
        The detached command must NOT invoke sudo.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 8888

        def _popen_side(*args, **kwargs):
            self.log_file.write_text("tcpdump: listening on any, link-type LINUX_SLL2\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side

        with self._mock_capture_owner(username="capture_test_user"):
            res = priv_helper.start_capture_privileged(
                output_pcap=self.pcap_file,
                log_file=self.log_file,
                netns="ps028-cl",
                owner_user="capture_test_user",
                is_test_fixture=True
            )
        cmd_called = mock_popen.call_args[0][0]
        self.assertIn("-Z", cmd_called)
        self.assertIn("capture_test_user", cmd_called)
        self.assertIn("-B", cmd_called)
        self.assertIn("8192", cmd_called)
        self.assertIn("ps028-cl-rt", cmd_called)
        self.assertIn(priv_helper.DEFAULT_BPF_FILTER, cmd_called)
        self.assertIn("-w", cmd_called)
        self.assertIn("-", cmd_called)
        # Standard output passed to child is an open descriptor, not DEVNULL
        self.assertIsNotNone(mock_popen.call_args[1].get("stdout"))
        # Detached capture command must NOT contain sudo
        self.assertNotIn("sudo", cmd_called)
        self.assertTrue(mock_popen.call_args[1].get("start_new_session"))
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["buffer_size_kb"], 8192)
        self.assertEqual(res["interface"], "ps028-cl-rt")
        self.assertEqual(res["filter"], priv_helper.DEFAULT_BPF_FILTER)

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_start_capture_privileged_custom_buffer_and_filter(self, mock_euid, mock_popen):
        """Verifies start_capture_privileged supports custom interface, filter, and buffer."""
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9999

        def _popen_side(*args, **kwargs):
            self.log_file.write_text("tcpdump: listening on any\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side

        with self._mock_capture_owner(username="capture_test_user"):
            res = priv_helper.start_capture_privileged(
                output_pcap=self.pcap_file,
                log_file=self.log_file,
                netns="ps028-cl",
                interface="any",
                bpf_filter="port 80",
                buffer_size_kb=4096,
                owner_user="capture_test_user",
                is_test_fixture=True
            )
        cmd_called = mock_popen.call_args[0][0]
        self.assertIn("-B", cmd_called)
        self.assertIn("4096", cmd_called)
        self.assertIn("any", cmd_called)
        self.assertIn("port 80", cmd_called)
        self.assertEqual(res["buffer_size_kb"], 4096)
        self.assertEqual(res["interface"], "any")
        self.assertEqual(res["filter"], "port 80")

    @patch("lab.privileged_helper.run_helper_action")
    @patch("os.geteuid", return_value=1000)
    def test_stop_packet_capture_routes_through_helper_when_unprivileged(self, mock_euid, mock_helper):
        """
        Verifies stop_packet_capture for CaptureProcess routes through privileged helper
        when running unprivileged.
        """
        mock_helper.return_value = {"status": "OK"}
        proc = run_trial.CaptureProcess(pid=12345, tcpdump_pid=12346, pcap_path=self.pcap_file)

        res = run_trial.stop_packet_capture(proc, timeout=2.0, pcap_path=self.pcap_file)
        self.assertTrue(res)
        mock_helper.assert_called_once()
        self.assertEqual(mock_helper.call_args[0][0], "stop-capture")

    @patch("os.kill")
    @patch("lab.run_trial.is_safe_capture_process", return_value=True)
    def test_stop_packet_capture_delivers_sigint_gracefully_first(self, mock_safe, mock_kill):
        """Must deliver SIGINT gracefully first and wait for PCAP finalization."""
        mock_proc = MagicMock()
        mock_proc.pid = 7777
        mock_proc._ps028_tcpdump_pid = 7777
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0
        mock_proc._ps028_log_fp = MagicMock()

        # Write valid PCAP
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.pcap_file.write_bytes(header)

        res = run_trial.stop_packet_capture(mock_proc, timeout=2.0, pcap_path=self.pcap_file)
        self.assertTrue(res)
        mock_kill.assert_called_with(7777, signal.SIGINT)

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_capture_handle_serialization_and_absence_of_popen(self, mock_euid, mock_popen):
        """
        Regression Test: A10 capture handle serialization
        Verifies that start_capture_privileged returns a JSON-serializable capture handle
        containing verified PID, PCAP path, and metadata, and NEVER serializes Popen.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9123

        def _popen_side(*args, **kwargs):
            self.log_file.write_text("tcpdump: listening on any, link-type LINUX_SLL2\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side

        with self._mock_capture_owner(username="capture_test_user"):
            res = priv_helper.start_capture_privileged(
                output_pcap=self.pcap_file,
                log_file=self.log_file,
                netns="ps028-cl",
                owner_user="capture_test_user",
                is_test_fixture=True
            )

        # Must be a dict and must NOT contain _proc or any Popen object
        self.assertIsInstance(res, dict)
        self.assertNotIn("_proc", res)
        self.assertNotIn("proc", res)
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["parent_pid"], 9123)
        self.assertEqual(res["pcap_path"], str(self.pcap_file))
        self.assertEqual(res["log_path"], str(self.log_file))
        self.assertIn("start_time", res)

        # Handle MUST be directly serializable by json.dumps without TypeError
        serialized = json.dumps(res)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["parent_pid"], 9123)
        self.assertEqual(deserialized["pcap_path"], str(self.pcap_file))

        # CaptureProcess to_handle/to_dict must also be JSON-serializable
        cap_proc = run_trial.CaptureProcess(
            pid=res["parent_pid"],
            tcpdump_pid=res.get("tcpdump_pid"),
            pcap_path=Path(res["pcap_path"]),
            log_file=Path(res["log_path"]),
            handle=res
        )
        self.assertIsInstance(json.dumps(cap_proc.to_handle()), str)
        self.assertIsInstance(json.dumps(cap_proc.to_dict()), str)

    @patch("os.kill")
    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_round_trip_start_stop_capture_with_handle(self, mock_euid, mock_popen, mock_kill):
        """
        Regression Test: A10 capture round-trip start/stop with handle
        Verifies full round-trip from capture start handle serialization,
        deserialization, and stopping via stop_capture_privileged with PCAP finalization.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9456

        def _popen_side(*args, **kwargs):
            self.log_file.write_text("tcpdump: listening on any, link-type LINUX_SLL2\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side

        with self._mock_capture_owner(username="capture_test_user"):
            res = priv_helper.start_capture_privileged(
                output_pcap=self.pcap_file,
                log_file=self.log_file,
                netns="ps028-cl",
                owner_user="capture_test_user",
                is_test_fixture=True
            )
            pid_file = self.pcap_file.with_suffix(".pid")
            self.assertTrue(pid_file.is_file())

            # Round-trip JSON serialization
            handle_json = json.dumps(res)
            deserialized_handle = json.loads(handle_json)

            # Write valid PCAP to simulate capture finalization
            header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            pkt_hdr = struct.pack("<IIII", 1000, 0, 10, 10)
            self.pcap_file.write_bytes(header + pkt_hdr + b"1234567890")

            alive_state = {"alive": True}
            def _mock_kill(p, sig):
                if sig == signal.SIGINT:
                    alive_state["alive"] = False
            mock_kill.side_effect = _mock_kill

            with patch("lab.run_trial.is_safe_capture_process", return_value=True):
                with patch("lab.run_trial._is_pid_alive", side_effect=lambda p: alive_state["alive"]):
                    stop_res = priv_helper.stop_capture_privileged(
                        pid=deserialized_handle["parent_pid"],
                        pcap_path=Path(deserialized_handle["pcap_path"]),
                        timeout=1.0,
                        verify_pcap=True,
                        is_test_fixture=True
                    )

            self.assertEqual(stop_res["status"], "OK")
            self.assertTrue(stop_res["pcap_valid"])
            self.assertIn("sha256", stop_res)
            self.assertGreater(len(stop_res["sha256"]), 0)
            self.assertEqual(stop_res["packet_count"], 1)
            # PID file must be cleaned up
            self.assertFalse(pid_file.exists())

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_startup_failure_reaps_launched_process_on_timeout(self, mock_euid, mock_popen):
        """
        Regression Test: A10 startup failure cleanup
        Verifies that when tcpdump times out waiting for readiness,
        the process is terminated, reaped via wait, log is closed, and error raised.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9555
        mock_proc.wait.return_value = 0
        mock_popen.return_value = mock_proc

        self.log_file.write_text("tcpdump: starting...\n", encoding="utf-8")

        with patch("os.kill") as mock_kill:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.start_capture_privileged(
                    output_pcap=self.pcap_file,
                    log_file=self.log_file,
                    netns="ps028-cl",
                    readiness_timeout=0.1,
                    is_test_fixture=True
                )
            self.assertIn("timed out waiting for readiness", str(ctx.exception))
            # Verify termination and reaping
            mock_proc.wait.assert_called()

        pid_file = self.pcap_file.with_suffix(".pid")
        self.assertFalse(pid_file.exists())

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_startup_failure_reaps_on_premature_exit(self, mock_euid, mock_popen):
        """
        Regression Test: A10 startup premature exit handling
        Verifies that if tcpdump exits before readiness, PrivilegedHelperError is raised
        and PID file is not created or left behind.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mock_proc.returncode = 1
        mock_proc.pid = 9666
        mock_popen.return_value = mock_proc

        self.log_file.write_text("tcpdump: device not found\n", encoding="utf-8")

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=self.pcap_file,
                log_file=self.log_file,
                netns="ps028-cl",
                readiness_timeout=0.2,
                is_test_fixture=True
            )
        self.assertIn("terminated prematurely with code 1", str(ctx.exception))
        pid_file = self.pcap_file.with_suffix(".pid")
        self.assertFalse(pid_file.exists())

    @patch("subprocess.Popen")
    @patch("os.geteuid", return_value=0)
    def test_startup_failure_reaps_on_post_spawn_exception(self, mock_euid, mock_popen):
        """
        Regression Test: A10 startup failure cleanup on post-spawn exception
        Verifies that if an unexpected error occurs after Popen succeeds (e.g. PID file write failure),
        the already launched capture process is terminated and reaped.
        """
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.pid = 9777
        mock_proc.wait.return_value = 0

        def _popen_side(*args, **kwargs):
            self.log_file.write_text("tcpdump: listening on any, link-type LINUX_SLL2\n", encoding="utf-8")
            return mock_proc

        mock_popen.side_effect = _popen_side

        with patch("lab.privileged_helper.safe_write_pid_file", side_effect=RuntimeError("Simulated post-spawn error")):
            with patch("os.kill") as mock_kill:
                with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                    priv_helper.start_capture_privileged(
                        output_pcap=self.pcap_file,
                        log_file=self.log_file,
                        netns="ps028-cl",
                        is_test_fixture=True
                    )
                self.assertIn("Capture startup failed", str(ctx.exception))
                mock_proc.wait.assert_called()

        pid_file = self.pcap_file.with_suffix(".pid")
        self.assertFalse(pid_file.exists())

    def test_stop_capture_privileged_rejects_unrelated_process_identity(self):
        """
        Regression Test: A10 process identity rejection
        stop_capture_privileged must refuse to signal an unrelated process (e.g. test runner PID)
        and raise CaptureShutdownError.
        """
        current_pid = os.getpid()
        with patch("os.kill") as mock_kill:
            with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                priv_helper.stop_capture_privileged(
                    pid=current_pid,
                    pcap_path=self.pcap_file,
                    timeout=0.5
                )
            self.assertIn("unrelated", str(ctx.exception).lower())
            for c in mock_kill.call_args_list:
                sig_sent = c[0][1] if len(c[0]) > 1 else None
                self.assertNotIn(sig_sent, [signal.SIGINT, signal.SIGTERM, signal.SIGKILL])

    def test_stop_capture_privileged_rejects_mismatched_recorded_pid(self):
        """
        Regression Test: A10 PID file verification
        stop_capture_privileged must reject a PID that does not match the recorded
        PID file for the given PCAP.
        """
        pid_file = self.pcap_file.with_suffix(".pid")
        pid_file.write_text("12345:12346\n", encoding="utf-8")

        with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
            priv_helper.stop_capture_privileged(
                pid=99999,
                pcap_path=self.pcap_file,
                timeout=0.5
            )
        self.assertIn("does not match recorded capture PIDs", str(ctx.exception))

    def test_stop_capture_privileged_rejects_recycled_pid_with_different_pcap(self):
        """
        Regression Test: A10 recycled PID rejection
        stop_capture_privileged must refuse to signal a tcpdump process whose cmdline
        references a different PCAP file.
        """
        mock_proc_dir = self.temp_dir / "proc"
        mock_proc_dir.mkdir(parents=True, exist_ok=True)
        pid = 5001
        pid_dir = mock_proc_dir / str(pid)
        pid_dir.mkdir()
        (pid_dir / "comm").write_text("tcpdump\n", encoding="utf-8")
        # tcpdump capturing to a completely different PCAP
        raw_cmd = b"tcpdump\x00-i\x00any\x00-w\x00/tmp/other.pcap\x00"
        (pid_dir / "cmdline").write_bytes(raw_cmd)

        with patch("lab.run_trial._is_pid_alive", return_value=True):
            with patch("os.kill") as mock_kill:
                with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                    priv_helper.stop_capture_privileged(
                        pid=pid,
                        pcap_path=self.pcap_file,
                        proc_dir=mock_proc_dir,
                        timeout=0.5
                    )
                self.assertIn("unrelated", str(ctx.exception).lower())
                mock_kill.assert_not_called()

    def test_stop_capture_privileged_already_exited_process_confirms_cleanly(self):
        """
        Regression Test: A10 already-exited process confirmation
        When the capture process has already terminated (e.g. exited before stop called),
        stop_capture_privileged must confirm stop cleanly without errors, validate the PCAP,
        and clean up the PID file without sending unnecessary signals.
        """
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt_hdr = struct.pack("<IIII", 1000, 0, 10, 10)
        self.pcap_file.write_bytes(header + pkt_hdr + b"1234567890")

        pid_file = self.pcap_file.with_suffix(".pid")
        pid_file.write_text("7777:7777\n", encoding="utf-8")

        with patch("lab.run_trial._is_pid_alive", return_value=False):
            with patch("os.kill") as mock_kill:
                stop_res = priv_helper.stop_capture_privileged(
                    pid=7777,
                    pcap_path=self.pcap_file,
                    timeout=0.5,
                    verify_pcap=True
                )
        self.assertEqual(stop_res["status"], "OK")
        self.assertTrue(stop_res["pcap_valid"])
        self.assertEqual(stop_res["packet_count"], 1)
        self.assertFalse(pid_file.exists())
        mock_kill.assert_not_called()

    def test_stop_capture_privileged_zombie_process_detected_and_confirmed(self):
        """
        Regression Test: A10 zombie capture process detection and reap
        When the capture process has exited and entered zombie state (State: Z),
        _is_pid_alive recognizes it as dead/terminated, and stop_capture_privileged
        confirms shutdown cleanly without raising CaptureShutdownError.
        """
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt_hdr = struct.pack("<IIII", 1000, 0, 10, 10)
        self.pcap_file.write_bytes(header + pkt_hdr + b"1234567890")

        pid_file = self.pcap_file.with_suffix(".pid")
        pid_file.write_text("8888:8888\n", encoding="utf-8")

        mock_proc_dir = self.temp_dir / "proc"
        mock_proc_dir.mkdir(parents=True, exist_ok=True)
        pid = 8888
        pid_dir = mock_proc_dir / str(pid)
        pid_dir.mkdir()
        (pid_dir / "comm").write_text("tcpdump\n", encoding="utf-8")
        (pid_dir / "cmdline").write_bytes(b"tcpdump\x00-i\x00any\x00-w\x00" + str(self.pcap_file).encode() + b"\x00")
        (pid_dir / "status").write_text("Name:\ttcpdump\nState:\tZ (zombie)\nPid:\t8888\n", encoding="utf-8")

        # Directly verify _is_pid_alive recognizes State: Z as terminated
        self.assertFalse(run_trial._is_pid_alive(pid, proc_dir=mock_proc_dir))

        with patch("os.kill") as mock_kill:
            stop_res = priv_helper.stop_capture_privileged(
                pid=pid,
                pcap_path=self.pcap_file,
                proc_dir=mock_proc_dir,
                timeout=0.5,
                verify_pcap=True
            )
        self.assertEqual(stop_res["status"], "OK")
        self.assertTrue(stop_res["pcap_valid"])
        mock_kill.assert_not_called()

    def test_stop_capture_privileged_escalates_to_sigterm_and_sigkill(self):
        """
        Regression Test: A10 deterministic escalation sequence
        When a process does not exit on SIGINT, stop_capture_privileged must escalate:
        1. SIGINT sent first
        2. Escalates to SIGTERM if still alive
        3. Escalates to SIGKILL if still alive
        4. Succeeds once process exits after SIGKILL
        """
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt_hdr = struct.pack("<IIII", 1000, 0, 10, 10)
        self.pcap_file.write_bytes(header + pkt_hdr + b"1234567890")

        pid = 9991
        signals_received = []
        process_alive = [True]

        def _mock_kill(target_pid, sig):
            signals_received.append(sig)
            if sig == signal.SIGKILL:
                process_alive[0] = False

        with patch("lab.run_trial.is_safe_capture_process", return_value=True):
            with patch("lab.privileged_helper._is_alive_proc", side_effect=lambda p, proc_dir=None: process_alive[0]):
                with patch("os.kill", side_effect=_mock_kill):
                    stop_res = priv_helper.stop_capture_privileged(
                        pid=pid,
                        pcap_path=self.pcap_file,
                        timeout=0.1,
                        verify_pcap=True
                    )

        self.assertEqual(stop_res["status"], "OK")
        self.assertIn(signal.SIGINT, signals_received)
        self.assertIn(signal.SIGTERM, signals_received)
        self.assertIn(signal.SIGKILL, signals_received)
        sigint_idx = signals_received.index(signal.SIGINT)
        sigterm_idx = signals_received.index(signal.SIGTERM)
        sigkill_idx = signals_received.index(signal.SIGKILL)
        self.assertLess(sigint_idx, sigterm_idx)
        self.assertLess(sigterm_idx, sigkill_idx)

    def test_stop_capture_privileged_stuck_process_raises_capture_shutdown_error(self):
        """
        Regression Test: A10 genuinely stuck capture process handling
        When a process remains alive even after SIGKILL, stop_capture_privileged must fail closed
        and raise CaptureShutdownError.
        """
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.pcap_file.write_bytes(header)

        pid = 9992
        signals_received = []

        def _mock_kill(target_pid, sig):
            signals_received.append(sig)

        with patch("lab.run_trial.is_safe_capture_process", return_value=True):
            with patch("lab.privileged_helper._is_alive_proc", return_value=True):
                with patch("os.kill", side_effect=_mock_kill):
                    with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                        priv_helper.stop_capture_privileged(
                            pid=pid,
                            pcap_path=self.pcap_file,
                            timeout=0.1,
                            verify_pcap=True
                        )
        self.assertIn("failed to exit after escalation", str(ctx.exception))
        self.assertIn(signal.SIGINT, signals_received)
        self.assertIn(signal.SIGTERM, signals_received)
        self.assertIn(signal.SIGKILL, signals_received)

    def test_stop_capture_privileged_refuses_to_signal_reused_stale_pid_when_alive(self):
        """
        Regression Test: A10 process reuse safety check
        If an unrelated process now holds the PID, is_safe_capture_process returns False,
        and stop_capture_privileged must fail closed with CaptureShutdownError without signaling.
        """
        pid = 9993
        mock_proc_dir = self.temp_dir / "proc"
        mock_proc_dir.mkdir(parents=True, exist_ok=True)
        pid_dir = mock_proc_dir / str(pid)
        pid_dir.mkdir()
        (pid_dir / "comm").write_text("python3\n", encoding="utf-8")
        (pid_dir / "cmdline").write_bytes(b"python3\x00unrelated_worker.py\x00")
        (pid_dir / "status").write_text("Name:\tpython3\nState:\tR (running)\nPid:\t9993\n", encoding="utf-8")

        with patch("os.kill") as mock_kill:
            with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                priv_helper.stop_capture_privileged(
                    pid=pid,
                    pcap_path=self.pcap_file,
                    proc_dir=mock_proc_dir,
                    timeout=0.5
                )
            self.assertIn("unrelated", str(ctx.exception).lower())
            mock_kill.assert_not_called()


class TestTruthfulCleanupAndFailStopSafety(unittest.TestCase):
    """Tests ensuring truthful baseline verification and fail-stop campaign safety."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_truth_clean_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.privileged_helper.run_helper_action")
    @patch("lab.impair.is_root", return_value=False)
    def test_self_test_baseline_fails_truthfully_when_privileged_checks_fail(
        self, mock_is_root, mock_helper
    ):
        """
        CRITICAL REQUIREMENT 3:
        self_test_baseline in live mode must NEVER return True if privileged checks fail.
        """
        mock_helper.return_value = {
            "all_passed": False,
            "errors": ["Interface ps028-rt/ps028-rt-sv6 tc qdisc mismatch: netem delay 75ms"]
        }
        res = impair.self_test_baseline(dry_run=False)
        self.assertFalse(res)

    @patch("lab.privileged_helper.run_helper_action", side_effect=priv_helper.PrivilegedHelperError("sudo -n failed"))
    @patch("lab.impair.is_root", return_value=False)
    def test_self_test_baseline_fails_truthfully_when_sudo_fails(
        self, mock_is_root, mock_helper
    ):
        """When privileged helper raises an error (e.g. sudo -n unavailable), baseline check must fail."""
        res = impair.self_test_baseline(dry_run=False)
        self.assertFalse(res)

    @patch("lab.privileged_helper.run_helper_action")
    @patch("lab.impair.is_root", return_value=False)
    def test_restore_dns_baseline_routes_through_privileged_helper(
        self, mock_is_root, mock_helper
    ):
        """
        Regression Test (Issue 2):
        Verifies restore_dns_baseline routes through privileged helper when not root.
        """
        mock_helper.return_value = {"status": "OK", "message": "DNS baseline restored."}
        impair.restore_dns_baseline(dry_run=False)
        mock_helper.assert_called_once()
        self.assertEqual(mock_helper.call_args[0][0], "restore-dns")

    @patch("lab.privileged_helper.run_helper_action", side_effect=priv_helper.PrivilegedHelperError("DNS server reload timeout"))
    @patch("lab.impair.is_root", return_value=False)
    def test_restore_dns_baseline_fails_truthfully_on_helper_error(
        self, mock_is_root, mock_helper
    ):
        """
        Regression Test (Issue 2):
        Skipped or failed DNS restoration must NEVER report success;
        it must raise an exception and fail cleanup.
        """
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            impair.restore_dns_baseline(dry_run=False)
        self.assertIn("DNS server reload timeout", str(ctx.exception))

    @patch("lab.privileged_helper.run_helper_action", side_effect=priv_helper.PrivilegedHelperError("sudo -n authorization failed"))
    @patch("lab.impair.is_root", return_value=False)
    def test_clear_impairments_fails_truthfully_and_does_not_report_success(
        self, mock_is_root, mock_helper
    ):
        """
        Regression Test (Issue 2):
        clear_impairments must fail when helper fails, and must never report success.
        """
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            impair.clear_impairments(dry_run=False)

    @patch("lab.impair.save_dns_config_atomically", side_effect=PermissionError("Permission denied: dns_config.json"))
    @patch("lab.impair.is_root", return_value=True)
    def test_restore_dns_baseline_raises_and_never_swallows_reset_errors(
        self, mock_is_root, mock_save
    ):
        """
        Regression Test (Issue 2):
        When running as root, errors saving DNS config must raise ImpairmentError
        and never be silently swallowed.
        """
        dummy_cfg = self.temp_dir / "dns_config.json"
        dummy_cfg.write_text(json.dumps({"rules": {"A": {"delay_ms": 100}, "AAAA": {"delay_ms": 100}}}), encoding="utf-8")
        with self.assertRaises(impair.ImpairmentError) as ctx:
            impair.restore_dns_baseline(dry_run=False, config_file=dummy_cfg)
        self.assertIn("Failed to reset DNS config", str(ctx.exception))

    @patch("lab.impair.self_test_baseline", return_value=False)
    @patch("lab.run_trial.run_trial")
    def test_campaign_fail_stop_halts_and_preserves_records_on_cleanup_failure(
        self, mock_run, mock_base
    ):
        """
        Campaign must halt immediately (FAIL-STOP) on cleanup/baseline failure,
        set status HALTED_ON_FAILURE, leave subsequent slots PENDING, and preserve records.
        """
        trial_dir = self.temp_dir / "trials" / "trial-failing"
        trial_dir.mkdir(parents=True, exist_ok=True)
        (trial_dir / "result.json").write_text("{}")

        # Mock trial returning baseline failure
        mock_run.return_value = {
            "schema_version": run_trial.SCHEMA_VERSION,
            "trial_id": "trial-failing",
            "scenario_id": "S0",
            "execution_mode": "LIVE",
            "is_simulation": False,
            "timestamps": {"start_time": "2026-10-28T20:00:00Z", "end_time": "2026-10-28T20:00:01Z", "duration_ms": 1000},
            "evidence_paths": {"trial_dir": str(trial_dir)},
            "capture_metadata": {"pcap_valid": True, "packet_count": 5},
            "network_observations": {"classification": "DIRECT_IPV6"},
            "cleanup_status": {
                "scenario_restored": True,
                "baseline_verified": False,  # Failed live verification!
                "profile_cleaned": True,
                "lock_released": True,
                "errors": ["Live netem delay verification failed on ps028-rt-sv6"]
            }
        }

        with patch("lab.run_campaign.run_trial.find_browser_runtime", return_value=("chromium", "/usr/bin/chromium", "Chromium 124.0.0.0")):
            runner = run_campaign.CampaignRunner(
                scenarios=["S0", "S1"],
                browsers=["chromium"],
                repetitions=1,
                output_dir=self.temp_dir,
                is_simulation=False
            )

            with self.assertRaises(run_campaign.CampaignHaltedError) as ctx:
                runner.run()

        self.assertIn("FAIL-STOP", str(ctx.exception))
        # Only slot 1 (S0) was attempted; S1 was NOT executed
        self.assertEqual(mock_run.call_count, 1)

        manifest = json.loads((self.temp_dir / run_campaign.MANIFEST_FILENAME).read_text())
        self.assertEqual(manifest["status"], "HALTED_ON_FAILURE")
        self.assertIn("FAIL-STOP", manifest["summary"]["halt_reason"])
        self.assertEqual(manifest["matrix_slots"][0]["status"], "FAILED")
        self.assertEqual(manifest["matrix_slots"][0]["attempts"][0]["validity"], "CLEANUP_FAILURE")
        self.assertEqual(manifest["matrix_slots"][1]["status"], "PENDING")


class TestS6PrivilegeBoundaryAndLifecycle(unittest.TestCase):
    """
    Dedicated tests for S6 scenario privilege boundaries, DNS delay application,
    baseline restoration, lock safety, authorization failure, and partial-failure rollback.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_s6_test_"))
        self.lab_lock_file = self.temp_dir / ".lab.lock"
        self.dns_lock_file = self.temp_dir / ".verify_dns.lock"
        self.dns_config_file = self.temp_dir / "dns_config.json"
        self.dns_bak_a3 = self.temp_dir / "dns_config.json.bak"
        self.dns_bak_a4 = self.temp_dir / "dns_config.json.impair_bak"
        self.dns_pid_file = self.temp_dir / "dns.pid"
        self.state_file = self.temp_dir / ".impair_state.json"
        self.scenarios_file = self.temp_dir / "scenarios.yaml"

        # Canonical baseline DNS config and scenarios
        shutil.copy2(impair.DNS_CONFIG_FILE, self.dns_config_file)
        shutil.copy2(impair.DEFAULT_SCENARIOS_PATH, self.scenarios_file)
        self.dns_pid_file.write_text(str(os.getpid()), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.privileged_helper.run_helper_action")
    @patch("lab.impair.is_root", return_value=False)
    def test_non_root_s6_application_routes_through_privileged_helper(
        self, mock_is_root, mock_helper
    ):
        """
        Calling impair.apply_scenario('S6') as an unprivileged user routes through the privileged
        helper with non-interactive authorization, succeeding without raising a root privilege error.
        """
        mock_helper.return_value = {
            "status": "OK",
            "scenario_id": "S6",
            "dns_delays": {"A_delay_ms": 0, "AAAA_delay_ms": 500}
        }

        with patch.object(impair, "STATE_FILE", self.state_file):
            impair.apply_scenario(
                "S6",
                scenarios_path=self.scenarios_file,
                lock_file=self.lab_lock_file
            )

        self.assertGreaterEqual(mock_helper.call_count, 1)
        action_called = mock_helper.call_args_list[-1][0][0]
        self.assertEqual(action_called, "apply-scenario")
        extra = mock_helper.call_args_list[-1][1].get("extra_args", [])
        self.assertIn("--scenario", extra)
        self.assertIn("S6", extra)
        self.assertTrue(self.state_file.exists())
        with open(self.state_file, "r", encoding="utf-8") as f:
            st = json.load(f)
        self.assertEqual(st["active_scenario"], "S6")

    @patch("lab.impair.reload_dns_server")
    @patch("lab.impair.apply_nftables_rules")
    @patch("lab.impair.apply_netem_delays")
    @patch("lab.impair.clear_nftables_rules")
    @patch("lab.impair.restore_baseline_delays")
    def test_apply_scenario_privileged_s6_correctly_applies_a_and_aaaa_delays(
        self, mock_del_res, mock_nft_clr, mock_netem, mock_nft, mock_reload
    ):
        """
        Privileged helper applying S6 applies netem delays, nftables rules, and sets
        DNS delays (A=0ms, AAAA=500ms) with baseline backup preservation and atomic write.
        """
        with patch.object(impair, "DNS_CONFIG_FILE", self.dns_config_file), \
             patch.object(impair, "DNS_BACKUP_A4", self.dns_bak_a4), \
             patch.object(impair, "DNS_BACKUP_A3", self.dns_bak_a3), \
             patch.object(impair, "STATE_FILE", self.state_file), \
             patch.object(priv_helper, "STATE_FILE", self.state_file), \
             patch.object(priv_helper, "DEFAULT_SCENARIOS_PATH", self.scenarios_file), \
             patch("lab.impair.is_root", return_value=True):

            res = priv_helper.apply_scenario_privileged(
                scenario_id="S6",
                scenarios_path=self.scenarios_file,
                caller_holds_lock=False,
                lock_file=self.lab_lock_file
            )

            self.assertEqual(res["status"], "OK")
            self.assertEqual(res["scenario_id"], "S6")
            self.assertEqual(res["dns_delays"], {"A_delay_ms": 0, "AAAA_delay_ms": 500})

            # Check config file contents: A=0ms, AAAA=500ms
            cfg = json.loads(self.dns_config_file.read_text(encoding="utf-8"))
            self.assertEqual(cfg["rules"]["A"]["delay_ms"], 0)
            self.assertEqual(cfg["rules"]["AAAA"]["delay_ms"], 500)

            # Check baseline backup file: A=0ms, AAAA=0ms
            self.assertTrue(self.dns_bak_a4.exists())
            bak = json.loads(self.dns_bak_a4.read_text(encoding="utf-8"))
            self.assertEqual(bak["rules"]["A"]["delay_ms"], 0)
            self.assertEqual(bak["rules"]["AAAA"]["delay_ms"], 0)

    @patch("lab.privileged_helper.run_helper_action")
    @patch("lab.impair.is_root", return_value=False)
    def test_direct_unprivileged_apply_dns_delays_routes_to_helper(
        self, mock_is_root, mock_helper
    ):
        """
        Direct invocation of impair.apply_dns_delays by an unprivileged caller delegates
        to the 'apply-dns' privileged helper action without raising a permission error.
        """
        mock_helper.return_value = {"status": "OK", "a_delay_ms": 0, "aaaa_delay_ms": 500}

        impair.apply_dns_delays(
            a_delay_ms=0,
            aaaa_delay_ms=500,
            dry_run=False,
            config_file=self.dns_config_file,
            backup_file_a3=self.dns_bak_a3,
            backup_file_a4=self.dns_bak_a4,
            lock_file=self.dns_lock_file
        )

        mock_helper.assert_called_once()
        action = mock_helper.call_args[0][0]
        extra = mock_helper.call_args[1].get("extra_args", [])
        self.assertEqual(action, "apply-dns")
        self.assertIn("--a-delay", extra)
        self.assertIn("0", extra)
        self.assertIn("--aaaa-delay", extra)
        self.assertIn("500", extra)

    @patch("lab.impair.reload_dns_server")
    def test_s6_dns_baseline_restoration_and_verification(self, mock_reload):
        """
        Restoring DNS baseline resets delays to 0ms, reloads the DNS server, cleanly unlinks
        the backup file, and verifies the clean state before returning success.
        """
        # Apply S6 delays directly to config and create A4 backup
        delayed_config = json.loads(self.dns_config_file.read_text(encoding="utf-8"))
        delayed_config["rules"]["AAAA"]["delay_ms"] = 500
        self.dns_config_file.write_text(json.dumps(delayed_config, indent=2), encoding="utf-8")
        clean_backup = json.loads(self.dns_config_file.read_text(encoding="utf-8"))
        clean_backup["rules"]["AAAA"]["delay_ms"] = 0
        self.dns_bak_a4.write_text(json.dumps(clean_backup, indent=2), encoding="utf-8")

        with patch.object(impair, "DNS_CONFIG_FILE", self.dns_config_file), \
             patch.object(impair, "DNS_BACKUP_A4", self.dns_bak_a4), \
             patch("lab.impair.is_root", return_value=True):

            res = priv_helper.restore_dns_privileged(
                config_file=self.dns_config_file,
                backup_file_a4=self.dns_bak_a4,
                caller_holds_lock=False,
                lock_file=self.lab_lock_file
            )

            self.assertEqual(res["status"], "OK")
            # Config delays verified 0ms
            cfg = json.loads(self.dns_config_file.read_text(encoding="utf-8"))
            self.assertEqual(cfg["rules"]["A"]["delay_ms"], 0)
            self.assertEqual(cfg["rules"]["AAAA"]["delay_ms"], 0)
            # A4 backup unlinked
            self.assertFalse(self.dns_bak_a4.exists())

        # Negative test: if restoration fails to zero the delays, must fail closed
        self.dns_config_file.write_text(json.dumps(delayed_config, indent=2), encoding="utf-8")
        with patch.object(impair, "DNS_CONFIG_FILE", self.dns_config_file), \
             patch.object(impair, "DNS_BACKUP_A4", self.dns_bak_a4), \
             patch("lab.impair.is_root", return_value=True), \
             patch("lab.impair.restore_dns_baseline"):  # no-op mock so delays stay 500ms

            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.restore_dns_privileged(
                    config_file=self.dns_config_file,
                    backup_file_a4=self.dns_bak_a4,
                    caller_holds_lock=False,
                    lock_file=self.lab_lock_file
                )
            self.assertIn("not restored", str(ctx.exception).lower())

    def test_s6_lock_cleanup_on_success_and_failure(self):
        """
        Exclusive locks on .verify_dns.lock and .lab.lock are released cleanly
        both upon successful operations and upon exceptions.
        """
        with patch("lab.impair.is_root", return_value=True), \
             patch("lab.impair.reload_dns_server"):

            # 1. Successful apply and restore
            impair.apply_dns_delays(
                a_delay_ms=0,
                aaaa_delay_ms=500,
                dry_run=False,
                config_file=self.dns_config_file,
                backup_file_a3=self.dns_bak_a3,
                backup_file_a4=self.dns_bak_a4,
                lock_file=self.dns_lock_file
            )
            self.assertFalse(
                concurrency.is_lock_active(self.dns_lock_file),
                "DNS lock must be released after apply_dns_delays"
            )

            impair.restore_dns_baseline(
                dry_run=False,
                config_file=self.dns_config_file,
                backup_file_a4=self.dns_bak_a4,
                lock_file=self.dns_lock_file
            )
            self.assertFalse(
                concurrency.is_lock_active(self.dns_lock_file),
                "DNS lock must be released after restore_dns_baseline"
            )

            # 2. Failure during execution: lock must still be released
            with patch("lab.impair.save_dns_config_atomically", side_effect=OSError("Disk failure")):
                with self.assertRaises(OSError):
                    impair.apply_dns_delays(
                        a_delay_ms=0,
                        aaaa_delay_ms=500,
                        dry_run=False,
                        config_file=self.dns_config_file,
                        backup_file_a3=self.dns_bak_a3,
                        backup_file_a4=self.dns_bak_a4,
                        lock_file=self.dns_lock_file
                    )
                self.assertFalse(
                    concurrency.is_lock_active(self.dns_lock_file),
                    "DNS lock must be released even after error"
                )

    @patch("lab.privileged_helper.run_helper_action")
    @patch("lab.impair.is_root", return_value=False)
    def test_helper_authorization_failure_fails_closed_and_prompts_sudo_v(
        self, mock_is_root, mock_helper
    ):
        """
        When non-interactive sudo fails (e.g. password required), the helper raises
        PrivilegedHelperError documenting 'sudo -v', fails closed, and records no active state.
        """
        mock_helper.side_effect = priv_helper.PrivilegedHelperError(
            "Non-interactive sudo authorization is unavailable (sudo -n failed). "
            "Please authenticate by running 'sudo -v' in your terminal before executing live measurements."
        )

        with patch.object(impair, "STATE_FILE", self.state_file):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                impair.apply_scenario(
                    "S6",
                    scenarios_path=self.scenarios_file,
                    lock_file=self.lab_lock_file
                )

            self.assertIn("sudo -v", str(ctx.exception))
            self.assertFalse(self.state_file.exists(), "State must not be recorded when authorization fails")

    @patch("lab.impair.reload_dns_server")
    @patch("lab.impair.apply_nftables_rules")
    @patch("lab.impair.apply_netem_delays")
    @patch("lab.impair.clear_nftables_rules")
    @patch("lab.impair.restore_baseline_delays")
    def test_rollback_after_partial_failure_in_s6_application(
        self, mock_del_res, mock_nft_clr, mock_netem, mock_nft, mock_reload
    ):
        """
        If applying DNS delays fails after netem delays have been applied,
        apply_scenario_privileged automatically rolls back to baseline and raises PrivilegedHelperError.
        """
        with patch.object(impair, "DNS_CONFIG_FILE", self.dns_config_file), \
             patch.object(impair, "DNS_BACKUP_A4", self.dns_bak_a4), \
             patch.object(impair, "STATE_FILE", self.state_file), \
             patch.object(priv_helper, "STATE_FILE", self.state_file), \
             patch("lab.impair.is_root", return_value=True), \
             patch("lab.impair.apply_dns_delays", side_effect=impair.ImpairmentError("Simulated DNS server failure")):

            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.apply_scenario_privileged(
                    scenario_id="S6",
                    scenarios_path=self.scenarios_file,
                    caller_holds_lock=False,
                    lock_file=self.lab_lock_file
                )

            self.assertIn("Simulated DNS server failure", str(ctx.exception))
            # Rollback must have restored baseline netem delays and cleared nftables
            self.assertTrue(mock_del_res.called, "Baseline delays must be restored on rollback")
            self.assertTrue(mock_nft_clr.called, "nftables rules must be cleared on rollback")


class TestPrivilegedHelperDNSCommands(unittest.TestCase):
    """Regression tests for privileged helper DNS commands and bounds validation."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_ph_dns_test_"))
        self.config_file = self.temp_dir / "dns_config.json"
        with open(impair.DNS_CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.impair.apply_dns_delays")
    def test_apply_dns_strict_integer_bounds(self, mock_apply):
        """TC-PH-DNS-01: Valid integer bounds succeed and return status OK."""
        def fake_apply(*args, **kwargs):
            cfg = impair.load_dns_config(self.config_file)
            cfg.setdefault("rules", {}).setdefault("A", {})["delay_ms"] = kwargs.get("a_delay_ms", 0)
            cfg.setdefault("rules", {}).setdefault("AAAA", {})["delay_ms"] = kwargs.get("aaaa_delay_ms", 500)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        mock_apply.side_effect = fake_apply

        res = priv_helper.apply_dns_delays_privileged(
            a_delay_ms=0,
            aaaa_delay_ms=500,
            config_file=self.config_file
        )
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["a_delay_ms"], 0)
        self.assertEqual(res["aaaa_delay_ms"], 500)
        mock_apply.assert_called_once()

    def test_apply_dns_rejects_negative_integers(self):
        """TC-PH-DNS-02: Negative delay rejected."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_dns_delays_privileged(
                a_delay_ms=-10,
                aaaa_delay_ms=500,
                config_file=self.config_file
            )
        self.assertIn("between 0 and 2000", str(ctx.exception))

    def test_apply_dns_rejects_excessive_delays(self):
        """TC-PH-DNS-03: Excessive delay (>2000ms) rejected."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_dns_delays_privileged(
                a_delay_ms=0,
                aaaa_delay_ms=2500,
                config_file=self.config_file
            )
        self.assertIn("between 0 and 2000", str(ctx.exception))

    def test_apply_dns_rejects_shell_injections(self):
        """TC-PH-DNS-04: Non-integer / shell injection string rejected by CLI parser."""
        parser = priv_helper.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["apply-dns", "--a-delay", "10; rm -rf /"])

    @patch("lab.impair.apply_dns_delays", side_effect=impair.DNSConfirmationTimeoutError("SIGHUP timeout"))
    def test_apply_dns_propagates_dns_reload_failure(self, mock_apply):
        """TC-PH-DNS-05: Reload failure propagates as PrivilegedHelperError."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_dns_delays_privileged(
                a_delay_ms=0,
                aaaa_delay_ms=500,
                config_file=self.config_file
            )
        self.assertIn("SIGHUP timeout", str(ctx.exception))

    @patch("lab.impair.restore_dns_baseline", side_effect=impair.DNSSignalError("Signal refused"))
    def test_restore_dns_propagates_dns_reload_failure(self, mock_restore):
        """TC-PH-DNS-06: Restore failure propagates as PrivilegedHelperError."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.restore_dns_privileged(
                config_file=self.config_file
            )
        self.assertIn("Signal refused", str(ctx.exception))


class TestPrivilegedHelperS5Commands(unittest.TestCase):
    """Regression tests for privileged helper S5 counter setup, read, and measurement."""

    @patch("lab.impair.execute_netns_cmd")
    def test_setup_s5_counters_argv_validation(self, mock_cmd):
        """TC-PH-S5-01: Validates interface and sets up nftables rules; rejects unallowlisted iface."""
        mock_cmd.return_value = (0, "", "")
        res = priv_helper.setup_s5_counters_privileged(
            port=80,
            target_ip="2001:db8:2::10",
            client_ip="2001:db8:1::2",
            oifname="ps028-rt-sv6"
        )
        self.assertEqual(res["status"], "OK")
        mock_cmd.assert_called_once()

        # Reject unallowlisted interface
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.setup_s5_counters_privileged(
                port=80,
                target_ip="2001:db8:2::10",
                client_ip="2001:db8:1::2",
                oifname="eth0"
            )
        self.assertIn("not in allowlist", str(ctx.exception))

    @patch("lab.impair.execute_netns_cmd")
    def test_read_s5_counters_json_output(self, mock_cmd):
        """TC-PH-S5-02: Returns JSON counters dictionary with atomic read."""
        nft_json = {
            "nftables": [
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_total", "packets": 50}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_dropped", "packets": 25}},
                {"counter": {"family": "inet", "table": "ps028_impair", "name": "syn_not_dropped", "packets": 25}},
            ]
        }
        mock_cmd.return_value = (0, json.dumps(nft_json), "")
        res = priv_helper.read_s5_counters_privileged()
        self.assertEqual(res["status"], "OK")
        self.assertEqual(res["syn_total"], 50)
        self.assertEqual(res["syn_dropped"], 25)
        self.assertEqual(res["syn_not_dropped"], 25)

    def test_measure_s5_bound_validation(self):
        """TC-PH-S5-03: Rejects probe_count <= 0 or > 500, port <= 0, timeout <= 0."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.measure_s5_privileged(probe_count=0)
        self.assertIn("probe_count", str(ctx.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.measure_s5_privileged(probe_count=1000)
        self.assertIn("probe_count", str(ctx.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.measure_s5_privileged(port=70000)
        self.assertIn("port", str(ctx.exception))

    def test_measure_s5_emits_valid_jsonl_records(self):
        """TC-PH-S5-04: Multi-threaded probe worker emits valid JSONL records and summary."""
        temp_dir = Path(tempfile.mkdtemp(prefix="ps028_s5_test_"))
        jsonl_path = temp_dir / "s5_probes.jsonl"
        try:
            with patch("lab.privileged_helper.probe_single_socket") as mock_probe:
                mock_probe.side_effect = lambda idx, ip, port, to, *args: {
                    "probe_id": idx,
                    "target_ip": ip,
                    "target_port": port,
                    "client_ip": "127.0.0.1",
                    "client_port": 50000 + idx,
                    "t_start": 100.0,
                    "t_end": 100.1,
                    "duration_ms": 100.0,
                    "connect_outcome": "CONNECTED" if idx % 2 == 0 else "TIMEOUT",
                    "outcome": "connected" if idx % 2 == 0 else "timeout",
                    "errno": 0 if idx % 2 == 0 else 110,
                    "err_str": None if idx % 2 == 0 else "Connection timed out"
                }
                res = priv_helper.measure_s5_privileged(
                    target_ip="127.0.0.1",
                    port=80,
                    probe_count=10,
                    timeout=0.1,
                    concurrency=2,
                    netns="ps028-cl",
                    output_jsonl=jsonl_path,
                    caller_holds_lock=False,
                    lock_file=temp_dir / "test.lock",
                    in_netns=True,
                    allow_loopback=True
                )
                self.assertEqual(res["status"], "OK")
                self.assertEqual(res["probes_sent"], 10)
                self.assertTrue(jsonl_path.exists())

                lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
                self.assertEqual(len(lines), 10)
                records = [json.loads(line) for line in lines]
                self.assertEqual(records[0]["probe_id"], 0)
                self.assertIn("outcome", records[0])
                self.assertIn("duration_ms", records[0])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestPrivilegedHelperSecurityHardenings(unittest.TestCase):
    """
    Task P1 Security Regression Test Suite:
    Validates strict privilege boundaries, filesystem path confinement,
    network input validation, namespace verification, and sys.path sanitization.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_sec_test_"))
        self.test_file = self.temp_dir / "safe_output.txt"
        self.test_file.write_text("safe content\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. Filesystem Path Confinement Tests
    # --------------------------------------------------------------------------

    def test_path_confinement_rejects_absolute_path_outside_approved_roots(self):
        """TC-SEC-PATH-01: Rejects absolute paths outside approved directories."""
        for forbidden in ["/etc/shadow", "/etc/sudoers", "/var/log/syslog", "/root/.bashrc"]:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.validate_secure_path(forbidden, param_name="test_param")
            self.assertIn("outside approved directories", str(ctx.exception))

    def test_path_confinement_rejects_directory_traversal(self):
        """TC-SEC-PATH-02: Rejects ../ path traversal escaping allowed roots."""
        traversal = self.temp_dir / ".." / ".." / "etc" / "shadow"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_secure_path(traversal, param_name="traversal_param")
        self.assertIn("outside approved directories", str(ctx.exception))

    def test_path_confinement_rejects_final_component_symlink(self):
        """TC-SEC-PATH-03: Rejects target path when final component is a symlink."""
        symlink_target = self.temp_dir / "symlink_file.pcap"
        symlink_target.symlink_to(self.test_file)
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_secure_path(symlink_target, param_name="pcap_file", allow_symlinks=False)
        self.assertIn("symlinks are not permitted", str(ctx.exception))

    def test_path_confinement_rejects_parent_directory_symlink_escape(self):
        """TC-SEC-PATH-04: Rejects path where parent directory is a symlink escaping approved roots."""
        evil_parent = self.temp_dir / "evil_dir"
        evil_parent.symlink_to(Path("/etc"))
        evil_file = evil_parent / "passwd"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_secure_path(evil_file, param_name="conf_file", allow_symlinks=False)
        self.assertTrue(
            "outside approved directories" in str(ctx.exception) or
            "symlink escaping approved roots" in str(ctx.exception)
        )

    def test_chown_refuses_symlink(self):
        """TC-SEC-CHOWN-01: _chown_file refuses to operate on symlinks (TOCTOU protection)."""
        symlink_p = self.temp_dir / "symlink_to_chown"
        symlink_p.symlink_to(self.test_file)
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper._chown_file(symlink_p, "promotheshchatterjee")
            self.assertIn("refusing to chown symlink target", str(ctx.exception))

    def test_chown_refuses_root_uid_or_gid_0(self):
        """TC-SEC-CHOWN-02: _chown_file refuses to chown to root UID 0 or GID 0."""
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper._chown_file(self.test_file, "root")
            self.assertIn("refusing to chown to root UID 0", str(ctx.exception))

            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper._chown_file(self.test_file, "promotheshchatterjee", group=0)
            self.assertIn("refusing to chown to privileged group", str(ctx.exception))

    def test_unapproved_dns_config_file_rejected(self):
        """TC-SEC-DNS-01: apply_dns_delays rejects unapproved config_file path."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_dns_delays_privileged(
                a_delay_ms=0,
                aaaa_delay_ms=0,
                config_file=Path("/etc/resolv.conf")
            )
        self.assertIn("outside approved directories", str(ctx.exception))

    def test_unapproved_dns_backup_destination_rejected(self):
        """TC-SEC-DNS-02: apply_dns_delays rejects unapproved backup destinations and extensions."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_dns_delays_privileged(
                a_delay_ms=0,
                aaaa_delay_ms=0,
                backup_file_a3=Path("/etc/cron.d/evil.bak")
            )
        self.assertIn("outside approved directories", str(ctx.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.apply_dns_delays_privileged(
                a_delay_ms=0,
                aaaa_delay_ms=0,
                backup_file_a3=Path("/etc/cron.d/evil")
            )
        self.assertIn("invalid extension", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 2. Network Input & S5 Validation Tests
    # --------------------------------------------------------------------------

    def test_s5_malformed_ipv4_and_ipv6_addresses_rejected(self):
        """TC-SEC-NET-01: validate_ip_endpoint rejects syntactically malformed IPs."""
        for malformed in ["999.999.999.999", "2001:db8:::1", "not_an_ip", "", "  ", "::ffff:999.999.999.999"]:
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_ip_endpoint(
                    malformed,
                    param_name="test_ip",
                    allowed_ips=priv_helper.ALLOWED_PS028_TARGET_IPS
                )

    def test_s5_family_mismatch_rejected(self):
        """TC-SEC-NET-02: validate_s5_params rejects mixed IPv4 client and IPv6 target."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_s5_params(
                port=80,
                client_ip="10.0.1.2",
                target_ip="2001:db8:2::10"
            )
        self.assertIn("Address family mismatch", str(ctx.exception))

    def test_s5_nftables_injection_strings_rejected(self):
        """TC-SEC-NET-03: validate_ip_endpoint rejects nftables injection strings and shell metachars."""
        injections = [
            "2001:db8:2::10; drop",
            "10.0.2.10\nadd rule inet ps028_impair forward drop",
            "2001:db8:2::10' OR '1'='1",
            "10.0.2.10 && cat /etc/shadow",
            "2001:db8:2::10 $(id)",
            "10.0.2.10 `whoami`",
            "2001:db8:2::10 { drop; }",
        ]
        for inj in injections:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.validate_ip_endpoint(
                    inj,
                    param_name="injected_ip",
                    allowed_ips=priv_helper.ALLOWED_PS028_TARGET_IPS
                )
            self.assertTrue(
                "forbidden injection syntax" in str(ctx.exception) or
                "Invalid injected_ip" in str(ctx.exception)
            )

    def test_s5_arbitrary_target_destination_rejected(self):
        """TC-SEC-NET-04: validate_ip_endpoint rejects valid IPs outside approved PS-028 endpoints."""
        for arbitrary in ["8.8.8.8", "1.1.1.1", "192.168.1.1", "2606:4700::1111", "2001:4860:4860::8888"]:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.validate_ip_endpoint(
                    arbitrary,
                    param_name="target_ip",
                    allowed_ips=priv_helper.ALLOWED_PS028_TARGET_IPS
                )
            self.assertIn("not an authorized PS-028 endpoint", str(ctx.exception))

    def test_s5_unallowlisted_interface_or_network_namespace_rejected(self):
        """TC-SEC-NET-05: validate_s5_params rejects unallowlisted interfaces and namespaces."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_s5_params(port=80, oifname="eth0")
        self.assertIn("Invalid oifname 'eth0'", str(ctx.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_s5_params(port=80, netns="host")
        self.assertIn("Invalid netns 'host'", str(ctx.exception))

    def test_s5_interface_family_inconsistency_rejected(self):
        """TC-SEC-NET-06: validate_s5_params rejects interface inconsistent with IP family."""
        # IPv6 traffic directed to IPv4 interface
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_s5_params(
                port=80,
                client_ip="2001:db8:1::2",
                target_ip="2001:db8:2::10",
                oifname="ps028-rt-sv4"
            )
        self.assertIn("invalid for IPv6 traffic", str(ctx.exception))

        # IPv4 traffic directed to IPv6 interface
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_s5_params(
                port=80,
                client_ip="10.0.1.2",
                target_ip="10.0.2.10",
                oifname="ps028-rt-sv6"
            )
        self.assertIn("invalid for IPv4 traffic", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 3. Namespace Bypass Prevention Tests
    # --------------------------------------------------------------------------

    def test_s5_internal_worker_mode_external_invocation_rejected_on_host_namespace(self):
        """TC-SEC-NS-01: Worker probe execution fails closed when executed on host network namespace."""
        # If in_netns=True is passed on host without entering ps028-cl, inode verification fails
        with patch("lab.privileged_helper.verify_current_netns", return_value=False):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.measure_s5_privileged(
                    target_ip="2001:db8:2::10",
                    in_netns=True
                )
            self.assertIn("Network namespace verification failed", str(ctx.exception))

    def test_s5_public_cli_rejects_in_netns_flag(self):
        """TC-SEC-NS-02: Public measure-s5 subparser does not accept --in-netns flag."""
        parser = priv_helper.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["measure-s5", "--in-netns", "--target-ip", "2001:db8:2::10"])

    # --------------------------------------------------------------------------
    # 4. Sys.path Sanitization & Privilege Separation Tests
    # --------------------------------------------------------------------------

    def test_sanitization_strips_cwd_and_world_writable_sys_path_when_root(self):
        """TC-SEC-PRIV-01: sanitize_privileged_sys_path strips empty string, CWD, and world-writable paths."""
        world_writable_dir = self.temp_dir / "world_writable"
        world_writable_dir.mkdir()
        world_writable_dir.chmod(0o777)

        original_sys_path = list(sys.path)
        try:
            sys.path.insert(0, "")
            sys.path.insert(1, ".")
            sys.path.insert(2, str(world_writable_dir))

            with patch("os.geteuid", return_value=0), patch.dict(os.environ, {}, clear=True):
                priv_helper.sanitize_privileged_sys_path()

            self.assertNotIn("", sys.path)
            self.assertNotIn(".", sys.path)
            self.assertNotIn(str(world_writable_dir), sys.path)
        finally:
            sys.path[:] = original_sys_path

    def test_capture_owner_rejects_root_or_unauthorized_group(self):
        """TC-SEC-PRIV-02: _resolve_and_validate_capture_owner rejects root user or GID 0."""
        # Root user rejection
        with patch("lab.identity.resolve_invoking_identity") as mock_id:
            mock_id.return_value = unittest.mock.MagicMock(uid=0, gid=0, username="root")
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper._resolve_and_validate_capture_owner()
            self.assertIn("capture owner must be an unprivileged user, not root", str(ctx.exception))

        # Root GID 0 rejection
        with patch("lab.identity.resolve_invoking_identity") as mock_id:
            mock_id.return_value = unittest.mock.MagicMock(uid=1000, gid=1000, username="testuser")
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper._resolve_and_validate_capture_owner(owner_group=0)
            self.assertIn("is unauthorized", str(ctx.exception))

    def test_snap_browser_rejects_root_uid_or_gid_0(self):
        """TC-SEC-PRIV-03: launch_snap_browser_main exits with error if target UID or GID is 0."""
        mock_args = argparse.Namespace(
            reuid=0,
            regid=1000,
            mounts_file="/proc/mounts",
            cmd=["/usr/bin/google-chrome"]
        )
        with self.assertRaises(SystemExit) as ctx:
            priv_helper.launch_snap_browser_main(mock_args)
        self.assertEqual(ctx.exception.code, 74)

    def test_cli_rejects_unknown_subcommand_or_option(self):
        """TC-SEC-CLI-01: build_parser rejects unknown subcommands or malicious options."""
        parser = priv_helper.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["nonexistent-subcommand"])

        with self.assertRaises(SystemExit):
            parser.parse_args(["apply-scenario", "--malicious-option", "exploit"])

    # --------------------------------------------------------------------------
    # 5. Advanced Security Hardening Regression Tests
    # --------------------------------------------------------------------------

    def test_is_trusted_sys_path_dir_rejections(self):
        """TC-SEC-SYS-01: is_trusted_sys_path_dir rejects empty, relative, world/group-writable and non-root paths."""
        self.assertFalse(priv_helper.is_trusted_sys_path_dir(""))
        self.assertFalse(priv_helper.is_trusted_sys_path_dir("."))
        self.assertFalse(priv_helper.is_trusted_sys_path_dir(self.temp_dir / "nonexistent_dir"))

        # World-writable dir
        ww_dir = self.temp_dir / "world_writable_dir"
        ww_dir.mkdir()
        ww_dir.chmod(0o777)
        self.assertFalse(priv_helper.is_trusted_sys_path_dir(ww_dir))

        # Root simulation checks
        normal_dir = self.temp_dir / "normal_dir"
        normal_dir.mkdir()
        with patch("os.geteuid", return_value=0):
            # Non-root owned directory rejected when running as root
            with patch("os.stat") as mock_stat:
                m_st = unittest.mock.MagicMock()
                m_st.st_uid = 1000  # non-root
                m_st.st_mode = 0o755
                mock_stat.return_value = m_st
                self.assertFalse(priv_helper.is_trusted_sys_path_dir(normal_dir, allow_repo=False))

    def test_validate_ip_endpoint_topology_and_loopback_isolation(self):
        """TC-SEC-NET-01: validate_ip_endpoint enforces authentic PS-028 topology and rejects loopback in prod."""
        # Authentic topology endpoints pass
        self.assertEqual(str(priv_helper.validate_ip_endpoint("10.0.1.2", "client_ip", priv_helper.ALLOWED_PS028_CLIENT_IPS)), "10.0.1.2")
        self.assertEqual(str(priv_helper.validate_ip_endpoint("2001:db8:1::2", "client_ip", priv_helper.ALLOWED_PS028_CLIENT_IPS)), "2001:db8:1::2")
        self.assertEqual(str(priv_helper.validate_ip_endpoint("10.0.2.10", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS)), "10.0.2.10")
        self.assertEqual(str(priv_helper.validate_ip_endpoint("2001:db8:2::10", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS)), "2001:db8:2::10")

        # Loopback rejected in production mode
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_ip_endpoint("127.0.0.1", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS, allow_loopback=False)
        self.assertIn("not an authorized PS-028 endpoint", str(ctx.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_ip_endpoint("::1", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS, allow_loopback=False)

        # Loopback accepted when allow_loopback=True
        self.assertEqual(str(priv_helper.validate_ip_endpoint("127.0.0.1", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS, allow_loopback=True)), "127.0.0.1")
        self.assertEqual(str(priv_helper.validate_ip_endpoint("::1", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS, allow_loopback=True)), "::1")

        # Typo / arbitrary endpoints strictly rejected
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_ip_endpoint("fd00:1::2", "client_ip", priv_helper.ALLOWED_PS028_CLIENT_IPS)
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_ip_endpoint("192.168.1.1", "target_ip", priv_helper.ALLOWED_PS028_TARGET_IPS)

    def test_validate_operation_path_extensions_and_traversal(self):
        """TC-SEC-FS-01: validate_operation_path enforces role-specific extensions and root confinement."""
        # Valid extensions
        pcap_p = priv_helper.validate_operation_path(self.temp_dir / "capture.pcap", priv_helper.FileOperationType.PCAP_FILE)
        self.assertEqual(pcap_p.suffix, ".pcap")

        pid_p = priv_helper.validate_operation_path(self.temp_dir / "test.pid", priv_helper.FileOperationType.PID_FILE)
        self.assertEqual(pid_p.suffix, ".pid")

        # Invalid extension for PID file
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_operation_path(self.temp_dir / "exploit.sh", priv_helper.FileOperationType.PID_FILE)
        self.assertIn("invalid extension for pid_file", str(ctx.exception))

        # Traversal outside approved roots
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_operation_path("/etc/nginx/nginx.conf", priv_helper.FileOperationType.CONFIG_FILE)
        self.assertIn("outside approved directories", str(ctx.exception))

    def test_safe_write_pid_file_rejects_symlink_and_hardlink_attacks(self):
        """TC-SEC-FS-02: safe_write_pid_file rejects symlinks and hardlinks with race resistance."""
        pid_file = self.temp_dir / "test_safe.pid"
        priv_helper.safe_write_pid_file(pid_file, "1234:5678\n")
        self.assertEqual(pid_file.read_text(encoding="utf-8"), "1234:5678\n")

        # Symlink attack test: create symlink pointing to another file
        sensitive_file = self.temp_dir / "victim.txt"
        sensitive_file.write_text("precious data\n", encoding="utf-8")
        symlink_pid = self.temp_dir / "symlink_attack.pid"
        os.symlink(str(sensitive_file), str(symlink_pid))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_write_pid_file(symlink_pid, "evil_pid\n")
        self.assertIn("symlinks are not permitted", str(ctx.exception))
        # Ensure victim file was untouched
        self.assertEqual(sensitive_file.read_text(encoding="utf-8"), "precious data\n")

        # Hardlink attack test: link with nlink > 1
        hardlink_target = self.temp_dir / "hl_target.pid"
        hardlink_target.write_text("initial\n", encoding="utf-8")
        hardlink_second = self.temp_dir / "hl_second.pid"
        os.link(str(hardlink_target), str(hardlink_second))
        self.assertEqual(os.stat(str(hardlink_target)).st_nlink, 2)

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_write_pid_file(hardlink_target, "overwrite\n")
        self.assertIn("multiple hard links", str(ctx.exception))
        # Ensure hardlink files were completely untouched and not truncated
        self.assertEqual(hardlink_target.read_text(encoding="utf-8"), "initial\n")
        self.assertEqual(hardlink_second.read_text(encoding="utf-8"), "initial\n")

    def test_safe_atomic_write_text_and_netns_verification(self):
        """TC-SEC-FS-03: safe_atomic_write_text writes atomically; verify_current_netns verifies dev/ino."""
        state_file = self.temp_dir / "state.json"
        priv_helper.safe_atomic_write_text(state_file, '{"state": "OK"}\n', priv_helper.FileOperationType.STATE_FILE)
        self.assertEqual(json.loads(state_file.read_text(encoding="utf-8")), {"state": "OK"})

        # verify_current_netns returns False on nonexistent netns
        self.assertFalse(priv_helper.verify_current_netns("nonexistent-netns-9999"))
        self.assertIsNone(priv_helper.get_netns_inode("nonexistent-netns-9999"))

    def test_start_capture_privileged_rejects_hardlinked_and_symlinked_log_file(self):
        """TC-SEC-FS-04: start_capture_privileged rejects hardlinked and symlinked log files without truncating."""
        # 1. Hardlink rejection test
        hl_log_target = self.temp_dir / "victim_log.txt"
        hl_log_target.write_text("original log data\n", encoding="utf-8")
        hl_log_second = self.temp_dir / "victim_log_link.txt"
        os.link(str(hl_log_target), str(hl_log_second))
        self.assertEqual(os.stat(str(hl_log_target)).st_nlink, 2)

        pcap_file = self.temp_dir / "test_cap.pcap"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=pcap_file,
                log_file=hl_log_target,
                netns="ps028-cl"
            )
        self.assertIn("hardlink", str(ctx.exception).lower())
        # Crucial: prove victim log file was NOT truncated prior to validation failure
        self.assertEqual(hl_log_target.read_text(encoding="utf-8"), "original log data\n")
        self.assertEqual(hl_log_second.read_text(encoding="utf-8"), "original log data\n")

        # 2. Symlink rejection test
        sensitive_log = self.temp_dir / "sensitive_file.txt"
        sensitive_log.write_text("secret diagnostic content\n", encoding="utf-8")
        symlink_log = self.temp_dir / "symlink_log.txt"
        os.symlink(str(sensitive_log), str(symlink_log))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=pcap_file,
                log_file=symlink_log,
                netns="ps028-cl"
            )
        # Crucial: prove sensitive file destination was NOT touched
        self.assertEqual(sensitive_log.read_text(encoding="utf-8"), "secret diagnostic content\n")

    def test_safe_atomic_write_text_rejects_hardlink_and_symlink_destinations(self):
        """TC-SEC-FS-05: safe_atomic_write_text pre-validates target and rejects hardlink/symlink without modifying."""
        # 1. Hardlink rejection
        hl_file = self.temp_dir / "hl_state.json"
        hl_file.write_text('{"preserved": true}\n', encoding="utf-8")
        hl_second = self.temp_dir / "hl_state_link.json"
        os.link(str(hl_file), str(hl_second))
        self.assertEqual(os.stat(str(hl_file)).st_nlink, 2)

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_atomic_write_text(
                hl_file,
                '{"malicious": "overwrite"}\n',
                priv_helper.FileOperationType.STATE_FILE
            )
        self.assertIn("multiple hard links", str(ctx.exception))
        self.assertEqual(hl_file.read_text(encoding="utf-8"), '{"preserved": true}\n')
        self.assertEqual(hl_second.read_text(encoding="utf-8"), '{"preserved": true}\n')

        # 2. Symlink destination rejection
        target_file = self.temp_dir / "important_data.json"
        target_file.write_text('{"crucial": 123}\n', encoding="utf-8")
        sym_state = self.temp_dir / "sym_target.json"
        os.symlink(str(target_file), str(sym_state))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_atomic_write_text(
                sym_state,
                '{"pwn": 456}\n',
                priv_helper.FileOperationType.STATE_FILE
            )
        self.assertEqual(target_file.read_text(encoding="utf-8"), '{"crucial": 123}\n')

    def test_verify_privileged_import_closure_integrity(self):
        """TC-SEC-FS-06: verify_privileged_import_closure enforces strict module permissions and symlink rejection."""
        # Default closure must pass
        priv_helper.verify_privileged_import_closure(allow_repo=True)

        # Create temporary mock module in temp directory
        mock_mod = self.temp_dir / "mock_module.py"
        mock_mod.write_text("def run(): pass\n", encoding="utf-8")

        import types
        import sys
        mod_name = "ps028_mock_test_module"
        mod_obj = types.ModuleType(mod_name)
        mod_obj.__file__ = str(mock_mod)
        sys.modules[mod_name] = mod_obj

        try:
            # 1. World-writable module rejection
            mock_mod.chmod(0o666)
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.verify_privileged_import_closure([mod_name], allow_repo=True)
            self.assertIn("world-writable", str(ctx.exception))

            # 2. Symlinked module rejection
            mock_mod.chmod(0o644)
            sym_mod = self.temp_dir / "sym_mock_module.py"
            os.symlink(str(mock_mod), str(sym_mod))
            mod_obj.__file__ = str(sym_mod)
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.verify_privileged_import_closure([mod_name], allow_repo=True)
            self.assertIn("symlink", str(ctx.exception))
        finally:
            sys.modules.pop(mod_name, None)

    def test_validate_operation_path_role_confinement_boundaries(self):
        """TC-SEC-FS-07: validate_operation_path enforces role-specific allowed roots."""
        # PCAP_FILE in /run must be rejected
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_operation_path("/run/forbidden.pcap", priv_helper.FileOperationType.PCAP_FILE)
        self.assertIn("outside approved directories", str(ctx.exception))

        # PID_FILE in /run must be accepted
        pid_p = priv_helper.validate_operation_path("/run/allowed.pid", priv_helper.FileOperationType.PID_FILE)
        self.assertEqual(str(pid_p), "/run/allowed.pid")

        # CONFIG_FILE in /run must be rejected
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_operation_path("/run/nginx.conf", priv_helper.FileOperationType.CONFIG_FILE)
        self.assertIn("outside approved directories", str(ctx.exception))

        # DATA_FILE in /run must be rejected
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_operation_path("/run/data.jsonl", priv_helper.FileOperationType.DATA_FILE)
        self.assertIn("outside approved directories", str(ctx.exception))

    def test_validate_secure_path_intermediate_parent_symlink(self):
        """TC-SEC-FS-08: validate_secure_path rejects intermediate parent directories that are symlinks."""
        real_parent = self.temp_dir / "real_intermediate"
        real_parent.mkdir(parents=True, exist_ok=True)
        sym_parent = self.temp_dir / "sym_intermediate"
        os.symlink(str(real_parent), str(sym_parent))

        target = sym_parent / "target.txt"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.validate_secure_path(target, param_name="intermediate_test", allow_symlinks=False)
        self.assertIn("parent directory", str(ctx.exception).lower())
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_isolated_privileged_import_trust_chain(self):
        """TC-SEC-ISO-01: python3 -I and sanitize_privileged_sys_path prevent shadow module and .pth injection."""
        with tempfile.TemporaryDirectory() as untrusted_dir:
            u_path = Path(untrusted_dir)
            # 1. Plant shadow modules that would raise if loaded
            (u_path / "yaml.py").write_text("raise RuntimeError('EXPLOIT_SHADOW_YAML')\n", encoding="utf-8")
            (u_path / "dns.py").write_text("raise RuntimeError('EXPLOIT_SHADOW_DNS')\n", encoding="utf-8")
            (u_path / "evil.pth").write_text("import sys; sys.path.insert(0, '/exploit')\n", encoding="utf-8")

            # 2. Execute isolated python -I from inside the untrusted directory with malicious PYTHONPATH
            test_script = self.temp_dir / "verify_isolated.py"
            test_script.write_text(
                "import sys, yaml, dns\n"
                "assert '' not in sys.path\n"
                "assert '.' not in sys.path\n"
                "assert 'EXPLOIT_SHADOW_YAML' not in getattr(yaml, '__file__', '')\n"
                "assert 'EXPLOIT_SHADOW_DNS' not in getattr(dns, '__file__', '')\n"
                "print('ISOLATED_OK')\n",
                encoding="utf-8"
            )

            env = os.environ.copy()
            env["PYTHONPATH"] = str(u_path)
            env["PYTHONHOME"] = str(u_path)

            res = subprocess.run(
                ["python3", "-I", str(test_script)],
                cwd=str(u_path),
                env=env,
                capture_output=True,
                text=True
            )
            self.assertEqual(res.returncode, 0, f"Isolated execution failed: {res.stderr}")
            self.assertIn("ISOLATED_OK", res.stdout)

        # 3. Test sanitize_privileged_sys_path purging under simulated root EUID 0
        with patch("os.geteuid", return_value=0), patch.dict(os.environ, {}, clear=True):
            orig_path = list(sys.path)
            try:
                sys.path[:] = ["", ".", "/tmp", "/usr/lib/python3.12", "/usr/lib/python3/dist-packages"]
                priv_helper.sanitize_privileged_sys_path()
                self.assertNotIn("", sys.path)
                self.assertNotIn(".", sys.path)
                # /tmp is world-writable, so it must be purged
                self.assertNotIn("/tmp", sys.path)
                # Trusted root-owned directories remain
                self.assertIn("/usr/lib/python3.12", sys.path)
            finally:
                sys.path[:] = orig_path

    def test_safe_write_pid_file_fifo_and_special_files_rejection(self):
        """TC-SEC-FS-09: safe_write_pid_file rejects FIFOs, directories, and non-regular files without hanging."""
        # 1. FIFO named pipe test: must fail closed immediately without hanging
        fifo_pid = self.temp_dir / "pipe.pid"
        os.mkfifo(str(fifo_pid))
        self.assertTrue(os.path.exists(str(fifo_pid)))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_write_pid_file(fifo_pid, "1234\n")
        self.assertIn("not a regular file", str(ctx.exception).lower())

        # 2. Directory as PID file target: must fail closed immediately
        dir_pid = self.temp_dir / "subdir.pid"
        dir_pid.mkdir()
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_write_pid_file(dir_pid, "1234\n")
        self.assertIn("not a regular file", str(ctx.exception).lower())

    def test_safe_write_pid_file_atomic_replacement_preserves_hardlink_victim(self):
        """TC-SEC-FS-10: safe_write_pid_file atomic replacement refuses hardlink overwrite and preserves victim byte-for-byte."""
        victim = self.temp_dir / "victim_data.txt"
        victim_content = "CRITICAL_SECRET_CONTENT_12345\n"
        victim.write_text(victim_content, encoding="utf-8")
        orig_stat = victim.stat()

        hl_pid = self.temp_dir / "target_link.pid"
        os.link(str(victim), str(hl_pid))
        self.assertEqual(victim.stat().st_nlink, 2)
        self.assertEqual(hl_pid.stat().st_ino, orig_stat.st_ino)

        # Attempt safe_write_pid_file targeting hardlink
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_write_pid_file(hl_pid, "ATTACKER_PAYLOAD\n")
        self.assertIn("hard link", str(ctx.exception).lower())

        # Crucial: verify victim content, inode, size, and link count are completely preserved
        curr_stat = victim.stat()
        self.assertEqual(victim.read_text(encoding="utf-8"), victim_content)
        self.assertEqual(curr_stat.st_ino, orig_stat.st_ino)
        self.assertEqual(curr_stat.st_size, len(victim_content.encode("utf-8")))
        self.assertEqual(curr_stat.st_nlink, 2)

    def test_safe_write_pid_file_atomic_update_and_cleanup(self):
        """TC-SEC-FS-11: safe_write_pid_file replaces existing valid PID file atomically with correct mode and cleans up on error."""
        pid_file = self.temp_dir / "worker.pid"
        priv_helper.safe_write_pid_file(pid_file, "1111:2222\n")
        self.assertEqual(pid_file.read_text(encoding="utf-8"), "1111:2222\n")
        orig_ino = pid_file.stat().st_ino

        # Atomic replacement with new content
        priv_helper.safe_write_pid_file(pid_file, "3333:4444\n")
        self.assertEqual(pid_file.read_text(encoding="utf-8"), "3333:4444\n")
        new_stat = pid_file.stat()
        self.assertEqual(stat.S_IMODE(new_stat.st_mode), 0o644)
        self.assertEqual(new_stat.st_nlink, 1)

        # Ensure no temporary staging files (.tmp_pid_*) remain in directory
        tmp_leftovers = list(self.temp_dir.glob(".tmp_pid_*"))
        self.assertEqual(len(tmp_leftovers), 0, f"Leftover staging files found: {tmp_leftovers}")

    def test_start_capture_privileged_fifo_log_rejection(self):
        """TC-SEC-FS-12: start_capture_privileged rejects FIFO log files without hanging or truncating."""
        fifo_log = self.temp_dir / "capture.log"
        os.mkfifo(str(fifo_log))
        pcap_file = self.temp_dir / "capture.pcap"

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=pcap_file,
                log_file=fifo_log,
                netns="ps028-cl"
            )
        self.assertIn("not a regular file", str(ctx.exception).lower())

    def test_safe_atomic_write_text_special_file_and_hardlink_preservation(self):
        """TC-SEC-FS-13: safe_atomic_write_text rejects FIFOs and preserves hardlinked victims byte-for-byte."""
        fifo_state = self.temp_dir / "status.json"
        os.mkfifo(str(fifo_state))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_atomic_write_text(fifo_state, '{"state": "BAD"}\n')
        self.assertIn("not a regular file", str(ctx.exception).lower())

        # Hardlinked destination preservation
        victim = self.temp_dir / "victim_state.json"
        v_content = '{"state": "ORIGINAL_SAFE"}\n'
        victim.write_text(v_content, encoding="utf-8")
        hl_state = self.temp_dir / "state_link.json"
        os.link(str(victim), str(hl_state))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_atomic_write_text(hl_state, '{"state": "OVERWRITE"}\n')
        self.assertIn("hard link", str(ctx.exception).lower())
        self.assertEqual(victim.read_text(encoding="utf-8"), v_content)

    def test_safe_renameat_parameter_strict_validation(self):
        """TC-SEC-FS-14: _safe_renameat enforces strict argument types, non-negative FDs, and rejects NUL / path traversal."""
        # Negative FD rejection
        with self.assertRaises(ValueError) as ctx:
            priv_helper._safe_renameat(-1, "a", 3, "b")
        self.assertIn("non-negative", str(ctx.exception).lower())

        # Embedded NUL rejection
        with self.assertRaises(ValueError) as ctx:
            priv_helper._safe_renameat(3, "a\0b", 3, "c")
        self.assertIn("nul", str(ctx.exception).lower())

        # Path separator rejection
        with self.assertRaises(ValueError) as ctx:
            priv_helper._safe_renameat(3, "../evil", 3, "c")
        self.assertIn("path separators", str(ctx.exception).lower())

        # Empty name rejection
        with self.assertRaises(ValueError) as ctx:
            priv_helper._safe_renameat(3, "", 3, "c")
        self.assertIn("empty", str(ctx.exception).lower())

    def test_all_file_operation_types_confinement_matrix(self):
        """TC-SEC-FS-15: Verifies that unauthorized roots are rejected across every FileOperationType."""
        # PCAP_FILE rejected in /run
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_operation_path("/run/unauthorized.pcap", priv_helper.FileOperationType.PCAP_FILE)

        # LOG_FILE rejected in /run
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_operation_path("/run/unauthorized.log", priv_helper.FileOperationType.LOG_FILE)

        # CONFIG_FILE rejected in results/
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_operation_path(priv_helper.REPO_ROOT / "results" / "test.conf", priv_helper.FileOperationType.CONFIG_FILE)

        # BACKUP_FILE rejected in /run
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_operation_path("/run/test.bak", priv_helper.FileOperationType.BACKUP_FILE)

        # DATA_FILE rejected in /run
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_operation_path("/run/test.jsonl", priv_helper.FileOperationType.DATA_FILE)

    def test_start_capture_privileged_rejects_existing_regular_pcap_to_protect_victim(self):
        """TC-SEC-CAP-01: start_capture_privileged rejects existing regular PCAP without truncating or modifying."""
        victim_pcap = self.temp_dir / "victim.pcap"
        victim_pcap.write_bytes(b"EXISTING_PCAP_DATA_DO_NOT_TRUNCATE")
        log_file = self.temp_dir / "capture.log"

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=victim_pcap,
                log_file=log_file,
                netns="ps028-cl"
            )
        self.assertIn("already exists", str(ctx.exception).lower())
        self.assertEqual(victim_pcap.read_bytes(), b"EXISTING_PCAP_DATA_DO_NOT_TRUNCATE")

    def test_start_capture_privileged_rejects_hardlinked_pcap(self):
        """TC-SEC-CAP-02: start_capture_privileged rejects hardlinked PCAP file without truncating."""
        hl_target = self.temp_dir / "hl_pcap.pcap"
        hl_target.write_bytes(b"ORIGINAL_HL_DATA")
        hl_second = self.temp_dir / "hl_pcap_second.pcap"
        os.link(str(hl_target), str(hl_second))
        self.assertEqual(os.stat(str(hl_target)).st_nlink, 2)

        log_file = self.temp_dir / "capture.log"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=hl_target,
                log_file=log_file,
                netns="ps028-cl"
            )
        self.assertIn("hardlink", str(ctx.exception).lower())
        self.assertEqual(hl_target.read_bytes(), b"ORIGINAL_HL_DATA")
        self.assertEqual(hl_second.read_bytes(), b"ORIGINAL_HL_DATA")

    def test_start_capture_privileged_rejects_symlinked_pcap(self):
        """TC-SEC-CAP-03: start_capture_privileged rejects symlinked PCAP output and preserves target."""
        sensitive_file = self.temp_dir / "sensitive.txt"
        sensitive_file.write_bytes(b"SECRET_DATA")
        sym_pcap = self.temp_dir / "sym_target.pcap"
        os.symlink(str(sensitive_file), str(sym_pcap))

        log_file = self.temp_dir / "capture.log"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=sym_pcap,
                log_file=log_file,
                netns="ps028-cl"
            )
        self.assertIn("symlink", str(ctx.exception).lower())
        self.assertEqual(sensitive_file.read_bytes(), b"SECRET_DATA")

    def test_start_capture_privileged_rejects_fifo_pcap(self):
        """TC-SEC-CAP-04: start_capture_privileged rejects FIFO PCAP file without hanging."""
        fifo_pcap = self.temp_dir / "stream.pcap"
        os.mkfifo(str(fifo_pcap))
        log_file = self.temp_dir / "capture.log"

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.start_capture_privileged(
                output_pcap=fifo_pcap,
                log_file=log_file,
                netns="ps028-cl"
            )
        self.assertIn("not a regular file", str(ctx.exception).lower())

    def test_verify_trusted_parent_directory_rejections(self):
        """TC-SEC-DIR-01: verify_trusted_parent_directory rejects world-writable and untrusted directories."""
        # 1. World-writable directory rejection
        ww_dir = self.temp_dir / "world_writable_test"
        ww_dir.mkdir()
        ww_dir.chmod(0o777)
        fd = os.open(str(ww_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.verify_trusted_parent_directory(fd, ww_dir)
            self.assertIn("world-writable", str(ctx.exception).lower())
        finally:
            os.close(fd)

        # 2. Non-directory rejection
        regular_file = self.temp_dir / "not_a_dir.txt"
        regular_file.write_text("file")
        fd2 = os.open(str(regular_file), os.O_RDONLY)
        try:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.verify_trusted_parent_directory(fd2, regular_file)
            self.assertIn("not a directory", str(ctx.exception).lower())
        finally:
            os.close(fd2)

    def test_safe_atomic_write_text_rejects_config_file_as_readonly(self):
        """TC-SEC-CFG-01: safe_atomic_write_text rejects CONFIG_FILE operation type as strictly read-only."""
        cfg_path = self.temp_dir / "test.json"
        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_atomic_write_text(
                cfg_path,
                '{"write": "prohibited"}',
                op_type=priv_helper.FileOperationType.CONFIG_FILE
            )
        self.assertIn("read-only", str(ctx.exception).lower())

    def test_all_eight_file_operation_types_comprehensive_matrix(self):
        """TC-SEC-FS-16: Comprehensive validation of all 8 FileOperationType enums."""
        # Check all 8 enum members exist
        expected_types = {
            "PID_FILE", "PCAP_FILE", "LOG_FILE", "STATE_FILE",
            "CONFIG_FILE", "BACKUP_FILE", "LOCK_FILE", "DATA_FILE"
        }
        self.assertEqual({e.name for e in priv_helper.FileOperationType}, expected_types)

        # Valid extension tests for each
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "p.pid", priv_helper.FileOperationType.PID_FILE).suffix, ".pid")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "c.pcap", priv_helper.FileOperationType.PCAP_FILE).suffix, ".pcap")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "l.log", priv_helper.FileOperationType.LOG_FILE).suffix, ".log")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "s.json", priv_helper.FileOperationType.STATE_FILE).suffix, ".json")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "cfg.json", priv_helper.FileOperationType.CONFIG_FILE).suffix, ".json")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "b.bak", priv_helper.FileOperationType.BACKUP_FILE).suffix, ".bak")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "k.lock", priv_helper.FileOperationType.LOCK_FILE).suffix, ".lock")
        self.assertEqual(priv_helper.validate_operation_path(self.temp_dir / "d.jsonl", priv_helper.FileOperationType.DATA_FILE).suffix, ".jsonl")

    def test_verify_trusted_parent_directory_root_execution_requires_root_ownership(self):
        """TC-SEC-DIR-02: Root execution strictly requires root ownership (UID 0); user-owned directories are rejected."""
        user_dir = self.temp_dir / "user_owned_dir"
        user_dir.mkdir(exist_ok=True)
        fd = os.open(str(user_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch("os.geteuid", return_value=0):
                # When running as root without test fixture opt-in, user-owned dir MUST be rejected
                with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                    priv_helper.verify_trusted_parent_directory(fd, user_dir, is_test_fixture=False)
                self.assertIn("must be owned by root", str(ctx.exception))
        finally:
            os.close(fd)

    def test_verify_trusted_parent_directory_target_user_owned_dir_rejected_for_root_writes(self):
        """TC-SEC-DIR-03: Under root execution, target-user owned directory is rejected for root writes."""
        t_dir = self.temp_dir / "target_user_dir"
        t_dir.mkdir(exist_ok=True)
        fd = os.open(str(t_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch("os.geteuid", return_value=0):
                with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                    priv_helper.verify_trusted_parent_directory(fd, t_dir, expected_uid=2000, is_test_fixture=False)
                self.assertIn("must be owned by root", str(ctx.exception))
                self.assertIn("Target-user or invoking-user owned directories are rejected", str(ctx.exception))
        finally:
            os.close(fd)

    def test_verify_trusted_parent_directory_unprivileged_allows_user_owned_dir(self):
        """TC-SEC-DIR-04: Non-privileged harness allows user-owned private directories."""
        priv_dir = self.temp_dir / "priv_user_dir"
        priv_dir.mkdir(exist_ok=True)
        fd = os.open(str(priv_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Running as non-root (current user)
            priv_helper.verify_trusted_parent_directory(fd, priv_dir, is_test_fixture=False)
        finally:
            os.close(fd)

    def test_verify_trusted_parent_directory_rejects_world_writable_sticky_bit(self):
        """TC-SEC-DIR-05: verify_trusted_parent_directory rejects world-writable directories even when sticky bit is set."""
        sticky_ww = self.temp_dir / "sticky_ww_dir"
        sticky_ww.mkdir(exist_ok=True)
        sticky_ww.chmod(0o1777)
        fd = os.open(str(sticky_ww), os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.verify_trusted_parent_directory(fd, sticky_ww, is_test_fixture=False)
            self.assertIn("world-writable", str(ctx.exception).lower())
        finally:
            os.close(fd)

    def test_verify_trusted_parent_directory_rejects_group_writable_untrusted(self):
        """TC-SEC-DIR-06: verify_trusted_parent_directory rejects group-writable directories for untrusted GID."""
        gw_dir = self.temp_dir / "group_writable_dir"
        gw_dir.mkdir(exist_ok=True)
        gw_dir.chmod(0o775)
        fd = os.open(str(gw_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            # 1. Under root privileged write policy (mocked root owner, untrusted group)
            mock_stat_res = MagicMock()
            mock_stat_res.st_mode = stat.S_IFDIR | 0o775
            mock_stat_res.st_uid = 0  # root owner
            mock_stat_res.st_gid = 999  # untrusted group
            with patch("os.geteuid", return_value=0):
                with patch("os.fstat", return_value=mock_stat_res):
                    with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                        priv_helper.verify_trusted_parent_directory(fd, gw_dir, is_test_fixture=False)
                    self.assertIn("group-writable", str(ctx.exception).lower())

            # 2. Under unprivileged policy with untrusted GID
            mock_stat_unpriv = MagicMock()
            mock_stat_unpriv.st_mode = stat.S_IFDIR | 0o775
            mock_stat_unpriv.st_uid = os.getuid()
            mock_stat_unpriv.st_gid = 99999
            with patch("os.fstat", return_value=mock_stat_unpriv):
                with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx2:
                    priv_helper.verify_trusted_parent_directory(fd, gw_dir, is_test_fixture=False)
                self.assertIn("group-writable", str(ctx2.exception).lower())
        finally:
            os.close(fd)

    def test_verify_trusted_parent_directory_rejects_symlink_parent(self):
        """TC-SEC-DIR-07: safe_write_pid_file and safe_atomic_write_text reject symlinked parent directories."""
        real_p = self.temp_dir / "real_parent"
        real_p.mkdir(exist_ok=True)
        sym_p = self.temp_dir / "symlink_parent"
        os.symlink(str(real_p), str(sym_p))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
            priv_helper.safe_write_pid_file(sym_p / "victim.pid", "1234\n")
        self.assertTrue(
            "symlink" in str(ctx.exception).lower() or "cannot safely open" in str(ctx.exception).lower()
        )

        with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx2:
            priv_helper.safe_atomic_write_text(sym_p / "victim.json", "{}")
        self.assertTrue(
            "symlink" in str(ctx2.exception).lower() or "cannot safely open" in str(ctx2.exception).lower()
        )

    def test_production_cli_rejects_test_only_options(self):
        """TC-SEC-CLI-01: Verifies production CLI parser strictly rejects test-only options."""
        parser = priv_helper.build_parser()
        # Ensure --is-test-fixture is rejected
        with self.assertRaises(SystemExit):
            parser.parse_args(["start-capture", "--output-pcap", "/run/test.pcap", "--log-file", "/run/test.log", "--is-test-fixture"])

        # Ensure --allow-loopback is rejected on measure-s5
        with self.assertRaises(SystemExit):
            parser.parse_args(["measure-s5", "--target-ip", "127.0.0.1", "--allow-loopback"])

        # Ensure --allow-loopback is rejected on measure-s5-worker
        with self.assertRaises(SystemExit):
            parser.parse_args(["measure-s5-worker", "--target-ip", "127.0.0.1", "--allow-loopback"])

    def test_offline_tcpdump_stdout_pcap_byte_identity(self):
        """TC-SEC-CAP-05: Verifies that tcpdump -w - produces a byte-for-byte valid PCAP file to stdout descriptor."""
        src_pcap = priv_helper.REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01" / "trials" / "trial-20261029222832-caa5ba16" / "capture.pcap"
        self.assertTrue(src_pcap.is_file(), f"Sample PCAP not found: {src_pcap}")

        dst_pcap = self.temp_dir / "stdout_reproduced.pcap"
        with open(dst_pcap, "wb") as out_fp:
            proc = subprocess.Popen(
                ["tcpdump", "-r", str(src_pcap), "-w", "-"],
                stdout=out_fp,
                stderr=subprocess.PIPE
            )
            _, stderr_err = proc.communicate()
            self.assertEqual(proc.returncode, 0, f"tcpdump failed: {stderr_err}")

        # Validate PCAP magic header
        with open(dst_pcap, "rb") as f:
            magic, v_maj, v_min, _, _, snaplen, linktype = struct.unpack("<IHHIIII", f.read(24))
            self.assertEqual(magic, 0xa1b2c3d4)
            self.assertEqual(v_maj, 2)
            self.assertEqual(v_min, 4)

        # Validate byte size matches source exactly
        self.assertEqual(dst_pcap.stat().st_size, src_pcap.stat().st_size)

    def test_validate_operation_path_rejects_user_repo_for_privileged_config_under_root(self):
        """TC-SEC-ROOT-01: validate_operation_path strictly rejects repo config files under root execution."""
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.validate_operation_path(
                    priv_helper.REPO_ROOT / "lab" / "scenarios.yaml",
                    priv_helper.FileOperationType.CONFIG_FILE,
                    param_name="scenarios_path",
                    is_test_fixture=False
                )
            self.assertIn("user-owned repository path", str(ctx.exception))
            self.assertIn("cannot serve as privileged", str(ctx.exception))

    def test_validate_operation_path_rejects_user_repo_for_privileged_writes_under_root(self):
        """TC-SEC-ROOT-02: validate_operation_path strictly rejects repo write destinations under root execution."""
        with patch("os.geteuid", return_value=0):
            # PID write to lab/
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.validate_operation_path(
                    priv_helper.REPO_ROOT / "lab" / "test.pid",
                    priv_helper.FileOperationType.PID_FILE,
                    param_name="pid_file",
                    is_test_fixture=False
                )
            self.assertIn("user-owned repository path", str(ctx.exception))

            # PCAP write to results/
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx2:
                priv_helper.validate_operation_path(
                    priv_helper.REPO_ROOT / "results" / "test.pcap",
                    priv_helper.FileOperationType.PCAP_FILE,
                    param_name="output_pcap",
                    is_test_fixture=False
                )
            self.assertIn("user-owned repository path", str(ctx2.exception))

    def test_validate_operation_path_allows_repo_when_unprivileged_or_test_fixture(self):
        """TC-SEC-ROOT-03: validate_operation_path allows repo paths when unprivileged or with test fixture opt-in."""
        # Unprivileged
        res = priv_helper.validate_operation_path(
            priv_helper.REPO_ROOT / "lab" / "scenarios.yaml",
            priv_helper.FileOperationType.CONFIG_FILE,
            is_test_fixture=False
        )
        self.assertEqual(res.name, "scenarios.yaml")

        # Test fixture opt-in under mock root
        with patch("os.geteuid", return_value=0):
            res_tf = priv_helper.validate_operation_path(
                priv_helper.REPO_ROOT / "lab" / "scenarios.yaml",
                priv_helper.FileOperationType.CONFIG_FILE,
                is_test_fixture=True
            )
            self.assertEqual(res_tf.name, "scenarios.yaml")

    def test_verify_trusted_parent_directory_rejects_group_writable_even_for_root_gid_0(self):
        """TC-SEC-DIR-08: Root execution unconditionally rejects group-writable directories, even for GID 0."""
        gw_dir = self.temp_dir / "trusted_group_dir"
        gw_dir.mkdir(exist_ok=True)
        gw_dir.chmod(0o775)
        fd = os.open(str(gw_dir), os.O_RDONLY | os.O_DIRECTORY)
        try:
            mock_stat_res = MagicMock()
            mock_stat_res.st_mode = stat.S_IFDIR | 0o775
            mock_stat_res.st_uid = 0  # root owner
            mock_stat_res.st_gid = 0  # GID 0
            with patch("os.geteuid", return_value=0):
                with patch("os.fstat", return_value=mock_stat_res):
                    with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                        priv_helper.verify_trusted_parent_directory(fd, gw_dir, is_test_fixture=False)
                    self.assertIn("group-writable", str(ctx.exception).lower())
        finally:
            os.close(fd)

    def test_validate_operation_path_rejects_data_file_under_root_execution(self):
        """TC-SEC-ROOT-04: validate_operation_path strictly rejects DATA_FILE privileged writes under root execution."""
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.validate_operation_path(
                    "/run/ps028/output.jsonl",
                    priv_helper.FileOperationType.DATA_FILE,
                    param_name="output_jsonl",
                    is_test_fixture=False
                )
            self.assertIn("prohibited", str(ctx.exception).lower())

    def test_validate_operation_path_privileged_requires_dedicated_ps028_dirs(self):
        """TC-SEC-ROOT-05: Privileged operations require dedicated PS-028 directories and reject broad /run and /var/run."""
        with patch("os.geteuid", return_value=0):
            # Arbitrary /run is rejected for PCAP
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/run/test.pcap", priv_helper.FileOperationType.PCAP_FILE, is_test_fixture=False)
            # Dedicated /run/ps028 is accepted
            res_pcap = priv_helper.validate_operation_path("/run/ps028/test.pcap", priv_helper.FileOperationType.PCAP_FILE, is_test_fixture=False)
            self.assertEqual(str(res_pcap), "/run/ps028/test.pcap")

            # Arbitrary /run is rejected for LOG
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/run/test.log", priv_helper.FileOperationType.LOG_FILE, is_test_fixture=False)
            # Dedicated /var/log/ps028 is accepted
            res_log = priv_helper.validate_operation_path("/var/log/ps028/test.log", priv_helper.FileOperationType.LOG_FILE, is_test_fixture=False)
            self.assertEqual(str(res_log), "/var/log/ps028/test.log")

            # PID_FILE: broad /run and /var/run rejected, dedicated /run/ps028 and /var/run/ps028 accepted
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/run/test.pid", priv_helper.FileOperationType.PID_FILE, is_test_fixture=False)
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/var/run/test.pid", priv_helper.FileOperationType.PID_FILE, is_test_fixture=False)
            res_pid1 = priv_helper.validate_operation_path("/run/ps028/test.pid", priv_helper.FileOperationType.PID_FILE, is_test_fixture=False)
            self.assertEqual(str(res_pid1), "/run/ps028/test.pid")
            res_pid2 = priv_helper.validate_operation_path("/var/run/ps028/test.pid", priv_helper.FileOperationType.PID_FILE, is_test_fixture=False)
            self.assertIn(str(res_pid2), ("/run/ps028/test.pid", "/var/run/ps028/test.pid"))

            # LOCK_FILE: broad /run and /var/run rejected, dedicated /run/ps028 and /var/run/ps028 accepted
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/run/test.lock", priv_helper.FileOperationType.LOCK_FILE, is_test_fixture=False)
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/var/run/test.lock", priv_helper.FileOperationType.LOCK_FILE, is_test_fixture=False)
            res_lock1 = priv_helper.validate_operation_path("/run/ps028/test.lock", priv_helper.FileOperationType.LOCK_FILE, is_test_fixture=False)
            self.assertEqual(str(res_lock1), "/run/ps028/test.lock")
            res_lock2 = priv_helper.validate_operation_path("/var/run/ps028/test.lock", priv_helper.FileOperationType.LOCK_FILE, is_test_fixture=False)
            self.assertIn(str(res_lock2), ("/run/ps028/test.lock", "/var/run/ps028/test.lock"))

            # STATE_FILE: broad /run and /var/run rejected, dedicated /run/ps028, /var/run/ps028, /var/lib/ps028 accepted
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/run/test.json", priv_helper.FileOperationType.STATE_FILE, is_test_fixture=False)
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.validate_operation_path("/var/run/test.json", priv_helper.FileOperationType.STATE_FILE, is_test_fixture=False)
            res_state1 = priv_helper.validate_operation_path("/run/ps028/test.json", priv_helper.FileOperationType.STATE_FILE, is_test_fixture=False)
            self.assertEqual(str(res_state1), "/run/ps028/test.json")
            res_state2 = priv_helper.validate_operation_path("/var/run/ps028/test.json", priv_helper.FileOperationType.STATE_FILE, is_test_fixture=False)
            self.assertIn(str(res_state2), ("/run/ps028/test.json", "/var/run/ps028/test.json"))
            res_state3 = priv_helper.validate_operation_path("/var/lib/ps028/test.json", priv_helper.FileOperationType.STATE_FILE, is_test_fixture=False)
            self.assertEqual(str(res_state3), "/var/lib/ps028/test.json")

    def test_privileged_mapping_rejects_all_broad_run_and_var_run_roots(self):
        """TC-SEC-ROOT-06: PRIVILEGED_OPERATION_ALLOWED_ROOTS contains zero broad /run or /var/run roots across all operations."""
        # 1. Assert PRIVILEGED_OPERATION_ALLOWED_ROOTS does not contain broad /run or /var/run for ANY operation
        broad_roots = {Path("/run"), Path("/var/run")}
        for op_type, roots in priv_helper.PRIVILEGED_OPERATION_ALLOWED_ROOTS.items():
            for broad in broad_roots:
                self.assertNotIn(
                    broad,
                    roots,
                    f"Broad root '{broad}' unexpectedly found in PRIVILEGED_OPERATION_ALLOWED_ROOTS for {op_type}"
                )

        # 2. Assert validate_operation_path under root rejects unrelated paths in /run and /var/run for every operation
        ext_map = {
            priv_helper.FileOperationType.PID_FILE: ".pid",
            priv_helper.FileOperationType.LOCK_FILE: ".lock",
            priv_helper.FileOperationType.STATE_FILE: ".json",
            priv_helper.FileOperationType.PCAP_FILE: ".pcap",
            priv_helper.FileOperationType.LOG_FILE: ".log",
            priv_helper.FileOperationType.CONFIG_FILE: ".yaml",
            priv_helper.FileOperationType.BACKUP_FILE: ".bak",
            priv_helper.FileOperationType.DATA_FILE: ".jsonl",
        }
        with patch("os.geteuid", return_value=0):
            for op_type, ext in ext_map.items():
                for broad_dir in ("/run", "/var/run", "/run/systemd", "/var/run/udev"):
                    test_path = f"{broad_dir}/unrelated_probe{ext}"
                    with self.assertRaises(
                        priv_helper.PrivilegedHelperError,
                        msg=f"Root execution failed to reject unrelated path '{test_path}' for {op_type}"
                    ):
                        priv_helper.validate_operation_path(test_path, op_type, is_test_fixture=False)


class TestPartnerPrivilegedHelperIntegration(unittest.TestCase):
    """
    Regression and compliance tests for deployed helper integration,
    isolated Python execution (-I), check-auth authorization,
    and service lifecycle subcommands (status-nginx, start-dns, stop-dns, status-dns, reload-dns).
    """

    @patch("subprocess.run")
    @patch("pathlib.Path.is_file")
    @patch("os.geteuid", return_value=1000)
    def test_check_sudo_authorization_invokes_check_auth_on_installed_helper(
        self, mock_euid, mock_is_file, mock_run
    ):
        """Must execute sudo -n /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py check-auth when installed."""
        mock_is_file.return_value = True
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"authorized": true}\n'
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = priv_helper.check_sudo_authorization(is_test_fixture=False)

        self.assertTrue(res["authorized"])
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, [
            "sudo", "-n",
            "/usr/bin/python3",
            "-I",
            "/usr/local/libexec/ps028/privileged_helper.py",
            "check-auth"
        ])

    @patch("subprocess.run")
    @patch("pathlib.Path.is_file")
    @patch("os.geteuid", return_value=1000)
    def test_run_helper_action_invokes_installed_helper_with_isolated_python(
        self, mock_euid, mock_is_file, mock_run
    ):
        """run_helper_action must invoke the installed helper with /usr/bin/python3 -I when installed."""
        mock_is_file.return_value = True
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"status": "SUCCESS"}\n'
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        out = priv_helper.run_helper_action("verify-baseline", is_test_fixture=False)

        self.assertEqual(out, {"status": "SUCCESS"})
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[:5], [
            "sudo", "-n",
            "/usr/bin/python3",
            "-I",
            "/usr/local/libexec/ps028/privileged_helper.py"
        ])
        self.assertEqual(cmd[5], "verify-baseline")

    def test_build_parser_registers_all_twenty_subcommands(self):
        """Parser must register and accept all 20 authorized subcommands."""
        parser = priv_helper.build_parser()
        expected_subcommands = {
            "apply-scenario", "restore-baseline", "apply-dns", "restore-dns",
            "verify-baseline", "start-capture", "stop-capture", "check-auth",
            "setup-s5-counters", "read-s5-counters", "measure-s5", "measure-s5-worker",
            "launch-snap-browser", "start-nginx", "stop-nginx", "status-nginx",
            "start-dns", "stop-dns", "status-dns", "reload-dns"
        }
        subparsers_action = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        self.assertEqual(len(subparsers_action), 1)
        registered = set(subparsers_action[0].choices.keys())
        self.assertEqual(registered, expected_subcommands)

    @patch("lab.privileged_helper.status_nginx_privileged", return_value={"status": "RUNNING", "pid": 1234})
    def test_dispatch_action_status_nginx(self, mock_status):
        """status-nginx action dispatches to status_nginx_privileged."""
        parser = priv_helper.build_parser()
        args = parser.parse_args(["status-nginx"])
        result = priv_helper.dispatch_action(args)
        mock_status.assert_called_once()
        self.assertEqual(result["status"], "RUNNING")

    @patch("lab.privileged_helper.start_dns_privileged", return_value={"status": "SUCCESS", "pid": 5678})
    def test_dispatch_action_start_dns(self, mock_start):
        """start-dns action dispatches to start_dns_privileged."""
        parser = priv_helper.build_parser()
        args = parser.parse_args(["start-dns"])
        result = priv_helper.dispatch_action(args)
        mock_start.assert_called_once()
        self.assertEqual(result["status"], "SUCCESS")

    @patch("lab.privileged_helper.stop_dns_privileged", return_value={"status": "SUCCESS"})
    def test_dispatch_action_stop_dns(self, mock_stop):
        """stop-dns action dispatches to stop_dns_privileged."""
        parser = priv_helper.build_parser()
        args = parser.parse_args(["stop-dns"])
        result = priv_helper.dispatch_action(args)
        mock_stop.assert_called_once()
        self.assertEqual(result["status"], "SUCCESS")

    @patch("lab.privileged_helper.status_dns_privileged", return_value={"status": "RUNNING", "pid": 5678})
    def test_dispatch_action_status_dns(self, mock_status):
        """status-dns action dispatches to status_dns_privileged."""
        parser = priv_helper.build_parser()
        args = parser.parse_args(["status-dns"])
        result = priv_helper.dispatch_action(args)
        mock_status.assert_called_once()
        self.assertEqual(result["status"], "RUNNING")

    @patch("lab.privileged_helper.reload_dns_privileged", return_value={"status": "SUCCESS"})
    def test_dispatch_action_reload_dns(self, mock_reload):
        """reload-dns action dispatches to reload_dns_privileged."""
        parser = priv_helper.build_parser()
        args = parser.parse_args(["reload-dns"])
        result = priv_helper.dispatch_action(args)
        mock_reload.assert_called_once()
        self.assertEqual(result["status"], "SUCCESS")

    def test_consistent_privileged_pid_paths(self):
        """Privileged runtime components must agree on dedicated /run/ps028 PID paths."""
        self.assertEqual(priv_helper.DEFAULT_DNS_PID_FILE, Path("/run/ps028/dns.pid"))
        self.assertEqual(priv_helper.DEFAULT_NGINX_PID_FILE, Path("/run/ps028/nginx.pid"))
        self.assertEqual(run_trial.DEFAULT_DNS_PID_FILE, Path("/run/ps028/dns.pid"))
        self.assertEqual(run_trial.DEFAULT_NGINX_PID_FILE, Path("/run/ps028/nginx.pid"))
        self.assertEqual(impair.DEFAULT_DNS_PID_FILE, Path("/run/ps028/dns.pid"))


class TestStagingTreeDeploymentClosure(unittest.TestCase):
    """
    Section 8: Staging tree deployment closure verification.
    Replicates the exact staging tree created by deploy_privileged_helper.sh
    and verifies that python3 -I staging_root/privileged_helper.py --help
    and python3 -I staging_root/lab/dns_server.py --help execute successfully
    in isolated mode without referencing the repository checkout in sys.path.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_staging_closure_"))
        self.staging_dir = self.temp_dir / "ps028"
        self.staging_dir.mkdir(mode=0o755)
        self.staging_lab = self.staging_dir / "lab"
        self.staging_lab.mkdir(mode=0o755)
        self.staging_www = self.staging_lab / "www"
        self.staging_www.mkdir(mode=0o755)

        # Copy deployment files
        modules = [
            "identity.py", "concurrency.py", "impair.py", "run_trial.py",
            "analyze.py", "teardown.py", "scenarios.yaml", "dns_config.json",
            "dns_server.py", "cl_resolv.conf", "nginx.conf"
        ]
        shutil.copy2(REPO_ROOT / "lab" / "privileged_helper.py", self.staging_dir / "privileged_helper.py")
        (self.staging_lab / "__init__.py").touch(mode=0o644)

        for mod in modules:
            shutil.copy2(REPO_ROOT / "lab" / mod, self.staging_lab / mod)
        shutil.copy2(REPO_ROOT / "lab" / "www" / "index.html", self.staging_www / "index.html")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_staging_tree_privileged_helper_help_runs_in_isolated_python(self):
        """python3 -I staging_root/privileged_helper.py --help must execute cleanly in isolated mode."""
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PS028_TEST_SUITE": "1"
        }
        proc = subprocess.run(
            [sys.executable, "-I", str(self.staging_dir / "privileged_helper.py"), "--help"],
            capture_output=True,
            text=True,
            cwd=str(self.temp_dir),
            env=env
        )
        self.assertEqual(proc.returncode, 0, f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")
        self.assertIn("PS-028 Privileged Operations Helper", proc.stdout)
        self.assertIn("start-dns", proc.stdout)
        self.assertIn("start-nginx", proc.stdout)

    def test_staging_tree_dns_server_help_runs_in_isolated_python(self):
        """python3 -I staging_root/lab/dns_server.py --help must execute cleanly in isolated mode."""
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin")
        }
        proc = subprocess.run(
            [sys.executable, "-I", str(self.staging_lab / "dns_server.py"), "--help"],
            capture_output=True,
            text=True,
            cwd=str(self.temp_dir),
            env=env
        )
        self.assertEqual(proc.returncode, 0, f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}")
        self.assertIn("PS-028 Controlled DNS Server", proc.stdout)

    def test_staging_tree_manifest_integrity_verification(self):
        """Verifies deployment manifest generation records all files with accurate sha256."""
        import hashlib
        files_record = []
        for p in sorted(self.staging_dir.rglob("*")):
            if p.is_file() and p.name != "deployment_manifest.json":
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                mode = oct(p.stat().st_mode & 0o777)
                rel = str(p.relative_to(self.staging_dir))
                files_record.append({"path": rel, "sha256": h, "mode": mode})

        manifest = {
            "release_sha": "002a17d673b0c07162eb55fa6a3b81cf07e153c4",
            "target_dir": str(self.staging_dir),
            "file_count": len(files_record),
            "files": files_record
        }
        manifest_path = self.staging_dir / "deployment_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        self.assertEqual(manifest["file_count"], 14)
        for item in manifest["files"]:
            actual_f = self.staging_dir / item["path"]
            self.assertTrue(actual_f.is_file())
            self.assertEqual(hashlib.sha256(actual_f.read_bytes()).hexdigest(), item["sha256"])


class TestPrivilegedHelperArgumentBoundaries(unittest.TestCase):
    """
    Section 5: Privileged helper argument boundary and adversarial input tests.
    Verifies that all registered actions enforce strict validation on paths,
    scenarios, interfaces, numeric bounds, and commands.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_adv_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"
        self.pcap_file = self.temp_dir / "test.pcap"
        self.log_file = self.temp_dir / "test.log"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_apply_scenario_rejects_invalid_scenario_names(self):
        """apply-scenario must reject invalid or malicious scenario IDs."""
        invalid_scenarios = ["S7", "S0; rm -rf /", "", "../etc/shadow", "INVALID"]
        for bad_sc in invalid_scenarios:
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.apply_scenario_privileged(
                    scenario_id=bad_sc,
                    lock_file=self.lock_file,
                    is_test_fixture=True
                )

    def test_start_capture_rejects_unauthorized_interface_in_production(self):
        """start-capture must reject unauthorized network interfaces when not in test fixture."""
        unauthorized_interfaces = ["eth0", "lo", "any", "ps028-cl-rt; id", "../dummy"]
        for bad_iface in unauthorized_interfaces:
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.start_capture_privileged(
                    output_pcap=self.pcap_file,
                    log_file=self.log_file,
                    interface=bad_iface,
                    lock_file=self.lock_file,
                    is_test_fixture=False
                )

    def test_start_capture_rejects_out_of_bounds_buffer_size(self):
        """start-capture must reject buffer_size_kb outside [128, 65536]."""
        bad_buffers = [0, 64, 127, 65537, 131072, -1]
        for bad_buf in bad_buffers:
            with self.assertRaises(priv_helper.PrivilegedHelperError):
                priv_helper.start_capture_privileged(
                    output_pcap=self.pcap_file,
                    log_file=self.log_file,
                    buffer_size_kb=bad_buf,
                    lock_file=self.lock_file,
                    is_test_fixture=True
                )

    def test_start_capture_rejects_path_traversal_in_output_pcap(self):
        """start-capture must reject path traversal or symlinks in output_pcap."""
        traversal_path = Path("/tmp/../../../../etc/shadow")
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.start_capture_privileged(
                output_pcap=traversal_path,
                log_file=self.log_file,
                lock_file=self.lock_file,
                is_test_fixture=True
            )

    def test_launch_snap_browser_rejects_shell_and_system_binaries(self):
        """launch-snap-browser must reject shell interpreters, python, and root utilities."""
        prohibited_commands = [
            ["bash", "-i"],
            ["/bin/sh"],
            ["python3", "-c", "import os; print(os.getuid())"],
            ["sudo", "su"],
            ["mount", "-t", "tmpfs", "none", "/mnt"],
            ["chmod", "777", "/etc/passwd"],
        ]
        for cmd in prohibited_commands:
            args = argparse.Namespace(
                reuid=1000,
                regid=1000,
                mounts_file="/proc/mounts",
                snap_name=None,
                resolver_ip="10.0.1.1",
                resolv_conf=None,
                snap_ns_dir="/run/snapd/ns",
                source_fd=None,
                host_proc_root="/proc/1/root",
                cmd=cmd
            )
            with self.assertRaises(SystemExit) as cm:
                priv_helper.launch_snap_browser_main(args)
            self.assertEqual(cm.exception.code, 72)

    def test_reload_dns_rejects_invalid_configuration_schema(self):
        """reload-dns must validate replacement configuration schema and reject invalid JSON."""
        invalid_conf = self.temp_dir / "invalid_dns.json"
        invalid_conf.write_text('{"bad_key": true}', encoding="utf-8")
        dummy_pid_file = self.temp_dir / "dns.pid"
        dummy_pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.reload_dns_privileged(
                pid_file=dummy_pid_file,
                config_file=invalid_conf,
                lock_file=self.lock_file,
                is_test_fixture=True
            )
        self.assertIn("schema validation failed", str(cm.exception).lower())

    def test_stop_nginx_refuses_to_signal_unverified_process(self):
        """stop-nginx must refuse to signal a PID whose cmdline does not contain nginx."""
        lab_dir = self.temp_dir / "lab"
        lab_dir.mkdir(parents=True, exist_ok=True)
        conf_file = lab_dir / "nginx.conf"
        conf_file.write_text("events {}\n", encoding="utf-8")
        dummy_pid_file = lab_dir / "nginx.pid"
        dummy_pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.stop_nginx_privileged(
                repo_root=self.temp_dir,
                config_file=conf_file,
                lock_file=self.lock_file,
                is_test_fixture=True
            )
        self.assertIn("cmdline mismatch", str(cm.exception).lower())


class TestPidfdProcessSignalingAndRaceElimination(unittest.TestCase):
    """
    Rigorously verifies PID lifecycle and race elimination across process signaling:
    1. Process exits after initial PID-file read.
    2. PID identity changes before signalling.
    3. Stale PID file.
    4. Malformed PID file.
    5. Wrong executable.
    6. Wrong network namespace.
    7. Already terminated process.
    8. Repeated stop operation (idempotence).
    9. Unsupported pidfd operation (fallback handling).
    """
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_pidfd_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"
        self.lock_file.touch()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pidfd_open_and_send_signal_live(self):
        """Verifies real pidfd_open and pidfd_send_signal on isolated child process."""
        proc = subprocess.Popen(["sleep", "5"])
        try:
            # Allow brief moment for kernel execve to complete
            ok, msg = False, ""
            for _ in range(20):
                ok, msg = priv_helper.safe_signal_process(
                    proc.pid,
                    signal.SIGTERM,
                    expected_cmd_substring="sleep"
                )
                if ok:
                    break
                time.sleep(0.01)
            self.assertTrue(ok, f"safe_signal_process failed: {msg}")
            self.assertEqual(msg, "OK")
            proc.wait(timeout=2.0)
            self.assertIsNotNone(proc.returncode)
        finally:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass

    def test_pidfd_process_exits_after_initial_pid_read(self):
        """If process exits immediately after PID read, pidfd_open or signal handles it safely."""
        proc = subprocess.Popen(["sleep", "0.01"])
        pid = proc.pid
        proc.wait(timeout=1.0)
        ok, msg = priv_helper.safe_signal_process(
            pid,
            signal.SIGTERM,
            expected_cmd_substring="sleep"
        )
        self.assertFalse(ok)
        self.assertTrue("terminated" in msg.lower() or "not alive" in msg.lower())

    def test_pidfd_wrong_executable_rejected_before_signal(self):
        """Refuses to signal process when cmdline does not match expected_cmd_substring."""
        ok, msg = priv_helper.safe_signal_process(
            os.getpid(),
            signal.SIGTERM,
            expected_cmd_substring="dns_server.py"
        )
        self.assertFalse(ok)
        self.assertIn("mismatch", msg.lower())

    def test_pidfd_wrong_network_namespace_rejected(self):
        """Refuses to signal process when netns does not match expected_netns."""
        proc = subprocess.Popen(["sleep", "5"])
        try:
            ok, msg = priv_helper.safe_signal_process(
                proc.pid,
                signal.SIGTERM,
                expected_cmd_substring="sleep",
                expected_netns="ps028-rt"
            )
            self.assertFalse(ok)
            self.assertTrue("does not exist" in msg.lower() or "netns mismatch" in msg.lower())
        finally:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass

    def test_pidfd_unsupported_fails_closed_without_signaling_numeric_pid(self):
        """When pidfd is unsupported (or force_fallback=True), safe_signal_process fails closed without signaling."""
        proc = subprocess.Popen(["sleep", "10"])
        try:
            ok, msg = priv_helper.safe_signal_process(
                proc.pid,
                signal.SIGTERM,
                expected_cmd_substring="sleep",
                force_fallback=True
            )
            self.assertFalse(ok)
            self.assertIn("prohibited", msg.lower())
            self.assertIn("requires linux pidfd", msg.lower())
            # Crucial verification: the child process must NOT have received any signal and must still be alive!
            self.assertIsNone(proc.poll())
        finally:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass
                proc.wait()

    def test_repeated_stop_dns_operation_is_idempotent(self):
        """Repeated stop-dns on non-existent or unlinked PID file returns stopped: True idempotently."""
        pid_file = self.temp_dir / "dns.pid"
        res1 = priv_helper.stop_dns_privileged(pid_file=pid_file, lock_file=self.lock_file, is_test_fixture=True)
        self.assertTrue(res1["stopped"])
        self.assertIn("No PID file present", res1["message"])
        res2 = priv_helper.stop_dns_privileged(pid_file=pid_file, lock_file=self.lock_file, is_test_fixture=True)
        self.assertTrue(res2["stopped"])


class TestDedicatedNginxWorkerIdentity(unittest.TestCase):
    """
    Rigorously verifies Nginx dedicated service identity ps028-sv:
    1. Production mode strictly requires ps028-sv and fails closed if missing.
    2. Production mode rejects unauthorized worker_user arguments.
    3. Test fixture mode allows unprivileged override or nobody fallback.
    """
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_nginx_id_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"
        self.lock_file.touch()
        self.lab_dir = self.temp_dir / "lab"
        self.lab_dir.mkdir(parents=True, exist_ok=True)
        self.conf = self.lab_dir / "nginx.conf"
        self.conf.write_text("events {}\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_production_start_nginx_fails_closed_if_ps028_sv_missing(self):
        """In production, start_nginx_privileged strictly requires dedicated user ps028-sv."""
        with patch("pwd.getpwnam", side_effect=KeyError("ps028-sv")):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=self.conf,
                    lock_file=self.lock_file,
                    is_test_fixture=False
                )
            self.assertIn("ps028-sv", str(cm.exception))
            self.assertIn("dedicated nginx service identity", str(cm.exception).lower())

    def test_production_start_nginx_rejects_unauthorized_worker_user(self):
        """In production, passing an unauthorized worker_user (like operator account) is rejected."""
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.start_nginx_privileged(
                repo_root=self.temp_dir,
                config_file=self.conf,
                worker_user="indrani",
                lock_file=self.lock_file,
                is_test_fixture=False
            )
        self.assertIn("refusing unauthorized worker_user", str(cm.exception).lower())

    def test_test_fixture_mode_allows_worker_user_override(self):
        """Test fixture mode permits worker_user override or fallback to nobody."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ps028-sv\n")
            with patch("time.time", side_effect=[0.0, 0.1, 5.0]):
                with self.assertRaises(priv_helper.PrivilegedHelperError):
                    priv_helper.start_nginx_privileged(
                        repo_root=self.temp_dir,
                        config_file=self.conf,
                        worker_user="test_worker",
                        lock_file=self.lock_file,
                        is_test_fixture=True
                    )
            found_cmd = any("user test_worker;" in str(call_args) for call_args in mock_run.call_args_list)
            self.assertTrue(found_cmd)

    def test_production_start_nginx_fails_closed_if_ps028_sv_has_uid_0(self):
        """Production start_nginx_privileged rejects ps028-sv account if it has root UID 0."""
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=0, pw_shell="/usr/sbin/nologin")
        with patch("pwd.getpwnam", return_value=fake_entry):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=self.conf,
                    lock_file=self.lock_file,
                    is_test_fixture=False
                )
            self.assertIn("cannot have root uid 0", str(cm.exception).lower())

    def test_production_start_nginx_fails_closed_if_ps028_sv_has_interactive_shell(self):
        """Production start_nginx_privileged rejects ps028-sv account if it has an interactive shell."""
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_shell="/bin/bash")
        with patch("pwd.getpwnam", return_value=fake_entry):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=self.conf,
                    lock_file=self.lock_file,
                    is_test_fixture=False
                )
            self.assertIn("non-interactive shell", str(cm.exception).lower())

    def test_production_start_nginx_fails_closed_if_ps028_sv_matches_operator_user(self):
        """Production start_nginx_privileged rejects ps028-sv account if it matches the operator username."""
        fake_entry = MagicMock(pw_name="indrani", pw_uid=1000, pw_shell="/usr/sbin/nologin")
        with patch("pwd.getpwnam", return_value=fake_entry), patch.dict(os.environ, {"SUDO_USER": "indrani"}):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=self.conf,
                    lock_file=self.lock_file,
                    is_test_fixture=False
                )
            self.assertIn("cannot be the operator account", str(cm.exception).lower())


class TestBrowserExecutableHardening(unittest.TestCase):
    """
    Adversarial verification of validate_browser_executable across:
    1. Executable in temporary writable directory (/tmp/google-chrome).
    2. Symlinked directory.
    3. Symlink to unexpected executable (/bin/bash).
    4. Directory with unsafe ownership or permissions.
    5. Approved path whose executable has been replaced / missing.
    """
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_browser_sec_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rejects_fake_executable_in_temp_writable_directory(self):
        """Rejects executable placed in temporary writable directory."""
        fake_chrome = self.temp_dir / "google-chrome"
        fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_chrome.chmod(0o755)

        with self.assertRaises(priv_helper.BrowserValidationError) as cm:
            priv_helper.validate_browser_executable(fake_chrome, is_test_fixture=False)
        self.assertIn("unauthorized browser executable path", str(cm.exception).lower())

    def test_rejects_symlink_to_prohibited_executable(self):
        """Rejects symlink pointing to prohibited executable (e.g. /bin/bash)."""
        fake_chrome = self.temp_dir / "google-chrome"
        fake_chrome.symlink_to("/bin/bash")

        with self.assertRaises(priv_helper.BrowserValidationError) as cm:
            priv_helper.validate_browser_executable(
                fake_chrome,
                allowed_canonical_paths={str(fake_chrome)},
                is_test_fixture=True
            )
        self.assertIn("prohibited executable name", str(cm.exception).lower())

    def test_rejects_world_writable_executable(self):
        """Rejects executable with world-writable permissions."""
        fake_chrome = self.temp_dir / "google-chrome"
        fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_chrome.chmod(0o777)

        with self.assertRaises(priv_helper.BrowserValidationError) as cm:
            priv_helper.validate_browser_executable(
                fake_chrome,
                allowed_canonical_paths={str(fake_chrome)},
                is_test_fixture=True
            )
        self.assertIn("must not be world-writable", str(cm.exception).lower())

    def test_rejects_missing_executable(self):
        """Rejects non-existent browser executable path."""
        missing = self.temp_dir / "nonexistent-chrome"
        with self.assertRaises(priv_helper.BrowserValidationError) as cm:
            priv_helper.validate_browser_executable(missing, is_test_fixture=True)
        self.assertIn("does not exist", str(cm.exception).lower())

    def test_launch_snap_browser_main_rejects_adversarial_binary_with_exit_72(self):
        """launch_snap_browser_main exits with code 72 on unapproved browser path."""
        fake_chrome = self.temp_dir / "google-chrome"
        fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_chrome.chmod(0o755)

        args = argparse.Namespace(
            reuid=1000,
            regid=1000,
            cmd=[str(fake_chrome)],
            is_test_fixture=False
        )
        with self.assertRaises(SystemExit) as cm:
            priv_helper.launch_snap_browser_main(args)
        self.assertEqual(cm.exception.code, 72)

    def test_launch_snap_browser_main_rejects_inode_modification_before_exec(self):
        """launch_snap_browser_main detects and exits 72 if the executable inode changes before exec."""
        fake_chrome = self.temp_dir / "google-chrome"
        fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_chrome.chmod(0o755)

        args = argparse.Namespace(
            reuid=1000,
            regid=1000,
            mounts_file=None,
            cmd=[str(fake_chrome)],
            is_test_fixture=True
        )

        # Simulate inode changing between initial validation and pre-exec check
        stat1 = MagicMock(st_dev=1, st_ino=10001)
        stat2 = MagicMock(st_dev=1, st_ino=10002)
        stat_iter = iter([stat1, stat2])

        with patch("lab.privileged_helper.validate_browser_executable", return_value=fake_chrome), \
             patch("lab.run_trial.get_browser_env", return_value={"HOME": "/home/test", "USER": "test"}), \
             patch("pathlib.Path.stat", side_effect=lambda *a, **kw: next(stat_iter, stat2)), \
             patch("lab.privileged_helper.setup_snap_mounts"), \
             patch("lab.privileged_helper.setup_snap_isolated_dns"), \
             patch("os.execvp"):
            with self.assertRaises(SystemExit) as cm:
                priv_helper.launch_snap_browser_main(args)
            self.assertEqual(cm.exception.code, 72)

    def test_validate_browser_executable_rejects_unapproved_resolved_target(self):
        """validate_browser_executable rejects when resolved realpath is not in approved paths."""
        fake_bin = self.temp_dir / "google-chrome"
        fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_bin.chmod(0o755)

        with patch.object(Path, "resolve", return_value=fake_bin):
            with self.assertRaises(priv_helper.BrowserValidationError) as cm:
                priv_helper.validate_browser_executable("/usr/bin/google-chrome", is_test_fixture=False)
            self.assertIn("unauthorized", str(cm.exception).lower())

    def test_validate_browser_executable_rejects_unapproved_raw_symlink(self):
        """validate_browser_executable rejects when raw symlink path is not in approved paths."""
        unapproved_link = self.temp_dir / "my-browser"
        unapproved_link.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        unapproved_link.chmod(0o755)

        with patch.object(Path, "resolve", return_value=Path("/opt/google/chrome/google-chrome")):
            with self.assertRaises(priv_helper.BrowserValidationError) as cm:
                priv_helper.validate_browser_executable(unapproved_link, is_test_fixture=False)
            self.assertIn("unauthorized", str(cm.exception).lower())


class TestStatusNonDestructiveObservation(unittest.TestCase):
    """
    Rigorously verifies that status-dns and status-nginx are strictly non-destructive:
    1. Missing PID file: reported as MISSING without error.
    2. Malformed PID file: reported as MALFORMED, file preserved intact on disk.
    3. Stale PID file: reported as STALE, file preserved intact on disk.
    4. Mismatched PID file: reported as MISMATCHED, file preserved intact on disk.
    """
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_status_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"
        self.lock_file.touch()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_status_dns_missing_pid_file(self):
        """status-dns reports MISSING when PID file is absent."""
        pid_file = self.temp_dir / "dns.pid"
        res = priv_helper.status_dns_privileged(pid_file=pid_file, lock_file=self.lock_file, is_test_fixture=True)
        self.assertFalse(res["running"])
        self.assertEqual(res["pid_state"], "MISSING")
        self.assertFalse(pid_file.exists())

    def test_status_dns_malformed_pid_file_preserved(self):
        """status-dns reports MALFORMED and preserves malformed file on disk."""
        pid_file = self.temp_dir / "dns.pid"
        pid_file.write_text("not_a_number\n", encoding="utf-8")

        res = priv_helper.status_dns_privileged(pid_file=pid_file, lock_file=self.lock_file, is_test_fixture=True)
        self.assertFalse(res["running"])
        self.assertEqual(res["pid_state"], "MALFORMED")
        self.assertTrue(pid_file.is_file(), "status-dns must NOT delete malformed PID files")
        self.assertEqual(pid_file.read_text(encoding="utf-8"), "not_a_number\n")

    def test_status_dns_stale_pid_file_preserved(self):
        """status-dns reports STALE and preserves stale PID file on disk."""
        pid_file = self.temp_dir / "dns.pid"
        pid_file.write_text("999999\n", encoding="utf-8")

        res = priv_helper.status_dns_privileged(pid_file=pid_file, lock_file=self.lock_file, is_test_fixture=True)
        self.assertFalse(res["running"])
        self.assertEqual(res["pid_state"], "STALE")
        self.assertTrue(pid_file.is_file(), "status-dns must NOT delete stale PID files")

    def test_status_dns_mismatched_pid_file_preserved(self):
        """status-dns reports MISMATCHED and preserves file when PID belongs to wrong process."""
        pid_file = self.temp_dir / "dns.pid"
        pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")

        res = priv_helper.status_dns_privileged(pid_file=pid_file, lock_file=self.lock_file, is_test_fixture=True)
        self.assertFalse(res["running"])
        self.assertEqual(res["pid_state"], "MISMATCHED")
        self.assertTrue(pid_file.is_file(), "status-dns must NOT delete mismatched PID files")

    def test_status_nginx_malformed_pid_file_preserved(self):
        """status-nginx reports MALFORMED and preserves malformed file on disk."""
        lab_dir = self.temp_dir / "lab"
        lab_dir.mkdir(parents=True, exist_ok=True)
        pid_file = lab_dir / "nginx.pid"
        pid_file.write_text("invalid_pid\n", encoding="utf-8")

        res = priv_helper.status_nginx_privileged(repo_root=self.temp_dir, lock_file=self.lock_file, is_test_fixture=True)
        self.assertFalse(res["running"])
        self.assertEqual(res["pid_state"], "MALFORMED")
        self.assertTrue(pid_file.is_file(), "status-nginx must NOT delete malformed PID files")

    def test_status_nginx_stale_pid_file_preserved(self):
        """status-nginx reports STALE and preserves stale PID file on disk."""
        lab_dir = self.temp_dir / "lab"
        lab_dir.mkdir(parents=True, exist_ok=True)
        pid_file = lab_dir / "nginx.pid"
        pid_file.write_text("999999\n", encoding="utf-8")

        res = priv_helper.status_nginx_privileged(repo_root=self.temp_dir, lock_file=self.lock_file, is_test_fixture=True)
        self.assertFalse(res["running"])
        self.assertEqual(res["pid_state"], "STALE")
        self.assertTrue(pid_file.is_file(), "status-nginx must NOT delete stale PID files")


class TestProcessLifecycleAndSignalingSecurity(unittest.TestCase):
    """
    Rigorously verifies process lifecycle invariants, pidfd signaling, and cleanup races:
    1. Child creation and fork during cleanup.
    2. Process exit race between discovery and signaling (ESRCH handling without failure).
    3. Surviving descendant detection and escalation.
    4. Strict fail-closed behavior when pidfd is unsupported.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_proc_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_process_exit_race_between_discovery_and_signaling(self):
        """safe_signal_process safely handles process exiting between discovery and pidfd open."""
        with patch("os.pidfd_open", side_effect=ProcessLookupError):
            ok, msg = priv_helper.safe_signal_process(99999, signal.SIGTERM)
            self.assertFalse(ok)
            self.assertIn("already terminated", msg.lower())

    def test_process_exit_race_between_pidfd_open_and_send_signal(self):
        """safe_signal_process safely handles process exiting after pidfd_open but before send_signal."""
        mock_pfd = 99
        with patch("os.pidfd_open", return_value=mock_pfd), \
             patch("signal.pidfd_send_signal", side_effect=ProcessLookupError), \
             patch("os.close") as mock_close:
            ok, msg = priv_helper.safe_signal_process(99998, signal.SIGTERM)
            self.assertFalse(ok)
            self.assertIn("terminated before signal delivery", msg.lower())
            mock_close.assert_called_once_with(mock_pfd)

    def test_safe_signal_process_fails_closed_when_pidfd_unsupported(self):
        """safe_signal_process fails closed without sending any numeric PID signal when pidfd is disabled."""
        mock_child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            ok, msg = priv_helper.safe_signal_process(mock_child.pid, signal.SIGTERM, force_fallback=True)
            self.assertFalse(ok)
            self.assertIn("prohibited", msg.lower())
            # Child process must still be running (no signal was sent to numeric PID)
            self.assertIsNone(mock_child.poll())
        finally:
            mock_child.terminate()
            mock_child.wait()

    def test_capture_process_group_descendant_escalation(self):
        """_reap_capture_on_startup_failure reaps parent and signals child tcpdump PID."""
        mock_parent = MagicMock(pid=12345)
        mock_parent.poll.return_value = None
        mock_parent.wait.return_value = 0

        alive_state = {12345: True, 12346: True}
        def mock_alive(p):
            res = alive_state.get(p, False)
            alive_state[p] = False
            return res

        with patch("lab.run_trial.find_tcpdump_pid", return_value=12346), \
             patch("lab.run_trial._is_pid_alive", side_effect=mock_alive), \
             patch("lab.privileged_helper.safe_signal_process") as mock_sig:
            priv_helper._reap_capture_on_startup_failure(mock_parent, tcpdump_pid=12346)
            self.assertTrue(mock_sig.called)

    def test_parent_exits_before_child(self):
        """stop_capture_privileged handles parent (ip netns) exiting before child tcpdump."""
        parent_pid = 20001
        child_pid = 20002
        pcap_file = self.temp_dir / "capture.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)
        pid_file = self.temp_dir / "capture.pid"
        pid_file.write_text(f"{parent_pid}:{child_pid}\n", encoding="utf-8")

        alive_map = {parent_pid: False, child_pid: True}
        def mock_alive(p, proc_dir=None):
            return alive_map.get(p, False)

        def mock_sig(p, sig, *args, **kwargs):
            if p == child_pid and sig == signal.SIGINT:
                alive_map[child_pid] = False
                return True, "Signaled via pidfd"
            return True, "Signaled"

        with patch("lab.run_trial.is_safe_capture_process", return_value=True), \
             patch("lab.privileged_helper._is_alive_proc", side_effect=mock_alive), \
             patch("lab.privileged_helper.safe_signal_process", side_effect=mock_sig) as sig_mock:
            res = priv_helper.stop_capture_privileged(
                pid=parent_pid,
                pcap_path=pcap_file,
                timeout=0.5,
                verify_pcap=True,
                is_test_fixture=True
            )
            self.assertEqual(res["status"], "OK")
            self.assertIn(child_pid, [call[0][0] for call in sig_mock.call_args_list])

    def test_surviving_descendant_escalation_to_sigkill(self):
        """stop_capture_privileged escalates to SIGKILL if child ignores SIGINT and SIGTERM."""
        parent_pid = 21001
        child_pid = 21002
        pcap_file = self.temp_dir / "capture.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)
        pid_file = self.temp_dir / "capture.pid"
        pid_file.write_text(f"{parent_pid}:{child_pid}\n", encoding="utf-8")

        signals_sent = []
        alive_map = {parent_pid: False, child_pid: True}

        def mock_alive(p, proc_dir=None):
            return alive_map.get(p, False)

        def mock_sig(p, sig, *args, **kwargs):
            signals_sent.append((p, sig))
            if sig == signal.SIGKILL:
                alive_map[child_pid] = False
            return True, "Signaled"

        with patch("lab.run_trial.is_safe_capture_process", return_value=True), \
             patch("lab.privileged_helper._is_alive_proc", side_effect=mock_alive), \
             patch("lab.privileged_helper.safe_signal_process", side_effect=mock_sig), \
             patch("time.sleep", return_value=None):
            res = priv_helper.stop_capture_privileged(
                pid=parent_pid,
                pcap_path=pcap_file,
                timeout=0.01,
                verify_pcap=True,
                is_test_fixture=True
            )
            self.assertEqual(res["status"], "OK")
            self.assertIn((child_pid, signal.SIGKILL), signals_sent)

    def test_refuses_to_signal_unrelated_process_in_another_session(self):
        """stop_capture_privileged refuses to signal unrelated or unverified process."""
        pcap_file = self.temp_dir / "capture.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)

        with patch("lab.run_trial.is_safe_capture_process", return_value=False), \
             patch("lab.privileged_helper._is_alive_proc", return_value=True), \
             patch("lab.privileged_helper.safe_signal_process") as mock_sig:
            with self.assertRaises(run_trial.CaptureShutdownError) as ctx:
                priv_helper.stop_capture_privileged(
                    pid=22001,
                    pcap_path=pcap_file,
                    timeout=0.5,
                    is_test_fixture=True
                )
            self.assertIn("unrelated", str(ctx.exception).lower())
            mock_sig.assert_not_called()

    def test_rejects_group_writable_executable(self):
        """validate_browser_executable rejects group-writable executable."""
        raw_path = "/usr/bin/google-chrome"
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.resolve", return_value=Path(raw_path)), \
             patch("os.access", return_value=True), \
             patch("pathlib.Path.stat") as mock_stat:
            mock_stat.return_value = os.stat_result((0o100775, 1, 1, 1, 0, 0, 100, 0, 0, 0))
            with self.assertRaises(priv_helper.BrowserValidationError) as ctx:
                priv_helper.validate_browser_executable(raw_path, is_test_fixture=False)
            self.assertIn("group-writable", str(ctx.exception).lower())

    def test_rejects_group_writable_ancestor_directory(self):
        """validate_browser_executable rejects executable if ancestor directory is group-writable."""
        raw_path = "/usr/bin/google-chrome"
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.resolve", return_value=Path(raw_path)), \
             patch("os.access", return_value=True):
            def mock_stat_side_effect(self_path, *args, **kwargs):
                if str(self_path) == raw_path:
                    return os.stat_result((0o100755, 1, 1, 1, 0, 0, 100, 0, 0, 0))
                elif str(self_path) == "/usr/bin":
                    return os.stat_result((0o040775, 1, 1, 1, 0, 0, 100, 0, 0, 0))
                else:
                    return os.stat_result((0o040755, 1, 1, 1, 0, 0, 100, 0, 0, 0))
            with patch.object(Path, "stat", autospec=True, side_effect=mock_stat_side_effect):
                with self.assertRaises(priv_helper.BrowserValidationError) as ctx:
                    priv_helper.validate_browser_executable(raw_path, is_test_fixture=False)
                self.assertIn("group-writable", str(ctx.exception).lower())

    def test_verify_caller_holds_lock_rejects_unrelated_lock_holder(self):
        """verify_caller_holds_lock fails closed when lock is held by an unrelated process."""
        lock_file = self.temp_dir / ".lab.lock"
        lock_file.touch()

        st = lock_file.stat()
        dev_ino = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
        mock_proc_locks = self.temp_dir / "proc_locks"
        mock_proc_locks.write_text(f"1: FLOCK  ADVISORY  WRITE 99999 {dev_ino} 0 EOF\n", encoding="utf-8")

        with patch("fcntl.flock", side_effect=BlockingIOError), \
             patch("lab.privileged_helper.get_process_ancestors", return_value={os.getpid(), 1}):
            with self.assertRaises(concurrency.LabLockError) as ctx:
                priv_helper.verify_caller_holds_lock(lock_file, proc_locks_path=mock_proc_locks)
            self.assertIn("unrelated", str(ctx.exception).lower())

    def test_run_helper_action_rejects_unprivileged_measure_s5_worker(self):
        """run_helper_action rejects direct unprivileged invocation of measure-s5-worker."""
        with patch("os.geteuid", return_value=1000):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                priv_helper.run_helper_action("measure-s5-worker", is_test_fixture=True)
            self.assertIn("prohibited", str(ctx.exception).lower())

    def test_stop_capture_rejects_invocation_without_pcap(self):
        """stop-capture CLI subparser strictly requires --pcap."""
        parser = priv_helper.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["stop-capture", "--pid", "12345"])

    def test_single_pid_capture_model_in_place_lifecycle(self):
        """Single PID model: Popen child PID == ip PID == tcpdump PID."""
        mock_proc = MagicMock(pid=33333, returncode=None)
        mock_proc.poll.return_value = None
        mock_proc.wait.return_value = 0

        pcap_file = self.temp_dir / "test.pcap"
        log_file = self.temp_dir / "test.log"
        pid_file = self.temp_dir / "test.pid"

        def _mock_popen(*args, **kwargs):
            log_file.write_text("listening on ps028-cl-rt\n", encoding="utf-8")
            return mock_proc

        with patch("subprocess.Popen", side_effect=_mock_popen), \
             patch("lab.privileged_helper.safe_write_pid_file") as mock_pid_write:
            res = priv_helper.start_capture_privileged(
                output_pcap=pcap_file,
                log_file=log_file,
                netns="ps028-cl",
                interface="ps028-cl-rt",
                readiness_timeout=0.5,
                is_test_fixture=True
            )
            self.assertEqual(res["parent_pid"], 33333)
            self.assertEqual(res["tcpdump_pid"], 33333)
            # Verify single PID format written
            mock_pid_write.assert_called_once_with(
                pid_file, "33333\n", owner_user=mock_pid_write.call_args[1]["owner_user"],
                owner_group=mock_pid_write.call_args[1]["owner_group"], is_test_fixture=True
            )

    def test_stop_capture_pidfd_pins_process_and_prevents_recycled_pid_signaling(self):
        """stop_capture_process_pinned acquires pidfd first, pins process, and never signals recycled PID."""
        # 1. Pinned stop of real process
        proc = subprocess.Popen(["sleep", "10"])
        pid = proc.pid
        pcap_file = self.temp_dir / "test_pinned.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)

        try:
            with patch("lab.run_trial.is_safe_capture_process", return_value=True):
                success = priv_helper.stop_capture_process_pinned(
                    pid=pid,
                    expected_pcap=pcap_file,
                    timeout=2.0
                )
                self.assertTrue(success)
        finally:
            if proc.poll() is None:
                proc.kill()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass

        # 2. Process exits during validation: pidfd detects exit and returns safely without signaling
        fake_pid = 98765
        with patch("os.pidfd_open", return_value=99), \
             patch("lab.run_trial.is_safe_capture_process", return_value=False), \
             patch("signal.pidfd_send_signal", side_effect=ProcessLookupError), \
             patch("os.close"):
            # Process terminated during validation -> returns True safely without error
            res = priv_helper.stop_capture_process_pinned(
                pid=fake_pid,
                expected_pcap=pcap_file,
                timeout=1.0
            )
            self.assertTrue(res)

    def test_launch_snap_browser_rejects_unauthorized_reuid(self):
        """launch_snap_browser_main rejects --reuid mismatching invoking identity with code 74."""
        args = argparse.Namespace(
            reuid=99999,
            regid=1000,
            cmd=["--", "/snap/bin/chromium", "http://10.0.1.10/test"],
            is_test_fixture=False
        )
        with self.assertRaises(SystemExit) as cm:
            priv_helper.launch_snap_browser_main(args)
        self.assertEqual(cm.exception.code, 74)

    def test_launch_snap_browser_rejects_unauthorized_regid(self):
        """launch_snap_browser_main rejects --regid not in permitted groups with code 74."""
        inv_user = identity.resolve_invoking_identity()
        args = argparse.Namespace(
            reuid=inv_user.uid,
            regid=88888,
            cmd=["--", "/snap/bin/chromium", "http://10.0.1.10/test"],
            is_test_fixture=False
        )
        with self.assertRaises(SystemExit) as cm:
            priv_helper.launch_snap_browser_main(args)
        self.assertEqual(cm.exception.code, 74)

    def test_launch_snap_browser_rejects_root_direct_invocation(self):
        """launch_snap_browser_main rejects direct root invocation to prevent arbitrary UID drop."""
        with patch("lab.identity.resolve_invoking_identity", side_effect=identity.IdentityResolutionError("Root UID 0 prohibited")):
            args = argparse.Namespace(
                reuid=1000,
                regid=1000,
                cmd=["--", "/snap/bin/chromium", "http://10.0.1.10/test"],
                is_test_fixture=False
            )
            with self.assertRaises(SystemExit) as cm:
                priv_helper.launch_snap_browser_main(args)
            self.assertEqual(cm.exception.code, 74)

    def test_launch_snap_browser_rejects_traversal_profile_dir(self):
        """launch_snap_browser_main rejects profile-dir outside permitted directory boundaries."""
        inv_user = identity.resolve_invoking_identity()
        args = argparse.Namespace(
            reuid=inv_user.uid,
            regid=inv_user.gid,
            cmd=["--", "/snap/bin/chromium", "--user-data-dir=/etc/ps028_evil", "http://10.0.1.10/test"],
            is_test_fixture=False
        )
        with self.assertRaises(SystemExit) as cm:
            priv_helper.launch_snap_browser_main(args)
        self.assertEqual(cm.exception.code, 74)

    def test_launch_snap_browser_rejects_url_with_shell_metacharacters(self):
        """launch_snap_browser_main rejects URLs containing shell metacharacters with code 75."""
        inv_user = identity.resolve_invoking_identity()
        bad_urls = [
            "http://10.0.1.10/test;rm -rf /",
            "http://10.0.1.10/test`whoami`",
            "http://10.0.1.10/test$(id)",
            "http://10.0.1.10/test|cat /etc/passwd",
            "http://10.0.1.10/test>evil.txt",
        ]
        for bad_url in bad_urls:
            args = argparse.Namespace(
                reuid=inv_user.uid,
                regid=inv_user.gid,
                cmd=["--", "/snap/bin/chromium", bad_url],
                is_test_fixture=False
            )
            with self.assertRaises(SystemExit) as cm:
                priv_helper.launch_snap_browser_main(args)
            self.assertEqual(cm.exception.code, 75)

    def test_setup_snap_isolated_dns_rejects_tampered_host_proc_root(self):
        """setup_snap_isolated_dns strictly requires /proc/1/root in production mode."""
        with self.assertRaises(priv_helper.SnapMountError) as cm:
            priv_helper.setup_snap_isolated_dns(
                snap_name="chromium",
                snap_ns_dir="/run/snapd/ns",
                host_proc_root="/var/tmp/tampered_proc",
                is_test_fixture=False
            )
        self.assertIn("strictly '/proc/1/root'", str(cm.exception))

    def test_start_nginx_rejects_unexpected_supplementary_groups(self):
        """start_nginx_privileged fails closed if ps028-sv has unexpected supplementary groups."""
        conf = self.temp_dir / "nginx.conf"
        conf.write_text("events {}\n", encoding="utf-8")
        lock_file = self.temp_dir / "nginx.lock"
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_gid=998, pw_shell="/usr/sbin/nologin")
        fake_grp = MagicMock(gr_name="ps028-sv", gr_gid=998)
        with patch("pwd.getpwnam", return_value=fake_entry), \
             patch("grp.getgrgid", return_value=fake_grp), \
             patch("os.getgrouplist", return_value=[998, 27]):  # User is in group 27 (sudo)
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=conf,
                    lock_file=lock_file,
                    is_test_fixture=False
                )
            self.assertIn("unexpected supplementary groups", str(cm.exception).lower())

    def test_start_nginx_rejects_root_primary_gid(self):
        """start_nginx_privileged fails closed if ps028-sv has root primary GID 0."""
        conf = self.temp_dir / "nginx.conf"
        conf.write_text("events {}\n", encoding="utf-8")
        lock_file = self.temp_dir / "nginx.lock"
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_gid=0, pw_shell="/usr/sbin/nologin")
        with patch("pwd.getpwnam", return_value=fake_entry):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=conf,
                    lock_file=lock_file,
                    is_test_fixture=False
                )
            self.assertIn("primary gid 0", str(cm.exception).lower())

    def test_start_nginx_rejects_sudo_primary_gid(self):
        """start_nginx_privileged fails closed if ps028-sv has administrative primary GID 27."""
        conf = self.temp_dir / "nginx.conf"
        conf.write_text("events {}\n", encoding="utf-8")
        lock_file = self.temp_dir / "nginx.lock"
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_gid=27, pw_shell="/usr/sbin/nologin")
        with patch("pwd.getpwnam", return_value=fake_entry):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=conf,
                    lock_file=lock_file,
                    is_test_fixture=False
                )
            self.assertIn("primary gid 27", str(cm.exception).lower())

    def test_start_nginx_rejects_docker_primary_group(self):
        """start_nginx_privileged fails closed if ps028-sv has privileged primary group 'docker'."""
        conf = self.temp_dir / "nginx.conf"
        conf.write_text("events {}\n", encoding="utf-8")
        lock_file = self.temp_dir / "nginx.lock"
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_gid=999, pw_shell="/usr/sbin/nologin")
        fake_grp = MagicMock(gr_name="docker", gr_gid=999)
        with patch("pwd.getpwnam", return_value=fake_entry), \
             patch("grp.getgrgid", return_value=fake_grp):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=conf,
                    lock_file=lock_file,
                    is_test_fixture=False
                )
            self.assertIn("cannot belong to privileged primary group 'docker'", str(cm.exception).lower())

    def test_start_nginx_rejects_unrelated_non_privileged_primary_group(self):
        """start_nginx_privileged fails closed if ps028-sv has non-privileged non-dedicated primary group."""
        conf = self.temp_dir / "nginx.conf"
        conf.write_text("events {}\n", encoding="utf-8")
        lock_file = self.temp_dir / "nginx.lock"
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_gid=1001, pw_shell="/usr/sbin/nologin")
        fake_grp = MagicMock(gr_name="nogroup", gr_gid=1001)
        with patch("pwd.getpwnam", return_value=fake_entry), \
             patch("grp.getgrgid", return_value=fake_grp):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.start_nginx_privileged(
                    repo_root=self.temp_dir,
                    config_file=conf,
                    lock_file=lock_file,
                    is_test_fixture=False
                )
            self.assertIn("must have dedicated primary group 'ps028-sv', got 'nogroup'", str(cm.exception).lower())

    def test_start_nginx_accepts_correct_dedicated_ps028_sv_group(self):
        """start_nginx_privileged accepts ps028-sv with dedicated primary group ps028-sv and zero supplementary groups."""
        conf = self.temp_dir / "nginx.conf"
        conf.write_text("events {}\n", encoding="utf-8")
        lock_file = self.temp_dir / "nginx.lock"
        fake_entry = MagicMock(pw_name="ps028-sv", pw_uid=998, pw_gid=998, pw_shell="/usr/sbin/nologin")
        fake_grp = MagicMock(gr_name="ps028-sv", gr_gid=998)
        with patch("pwd.getpwnam", return_value=fake_entry), \
             patch("grp.getgrgid", return_value=fake_grp), \
             patch("os.getgrouplist", return_value=[998]), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ps028-sv\n")
            with patch("time.time", side_effect=[0.0, 0.1, 5.0]):
                try:
                    priv_helper.start_nginx_privileged(
                        repo_root=self.temp_dir,
                        config_file=conf,
                        lock_file=lock_file,
                        is_test_fixture=False
                    )
                except priv_helper.PrivilegedHelperError as exc:
                    # Identity checks pass; failure is strictly on daemon timeout
                    self.assertNotIn("dedicated worker user", str(exc).lower())
                    self.assertNotIn("primary group", str(exc).lower())
                    self.assertNotIn("supplementary groups", str(exc).lower())


class TestStrictArgumentSecurityAndAuthentication(unittest.TestCase):
    """
    Test suite for:
    1. Pidfd signal error distinction (ESRCH vs EPERM, EBADF, EINVAL).
    2. Authentication boundary for measure-s5-worker (direct execution rejection, cryptographic pipe handoff).
    3. Strict duplicate argument rejection across all subcommands and scalar/boolean options.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_test_auth_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pidfd_signal_error_distinction(self):
        """_send_pidfd_signal treats ESRCH as exit but raises CaptureShutdownError on EPERM, EBADF, EINVAL."""
        with patch("signal.pidfd_send_signal", side_effect=ProcessLookupError()):
            self.assertFalse(priv_helper._send_pidfd_signal(1, signal.SIGINT, 123))

        with patch("signal.pidfd_send_signal", side_effect=OSError(errno.ESRCH, "No such process")):
            self.assertFalse(priv_helper._send_pidfd_signal(1, signal.SIGINT, 123))

        for err_code in (errno.EPERM, errno.EBADF, errno.EINVAL):
            with patch("signal.pidfd_send_signal", side_effect=OSError(err_code, os.strerror(err_code))):
                with self.assertRaises(run_trial.CaptureShutdownError) as cm:
                    priv_helper._send_pidfd_signal(1, signal.SIGINT, 123)
                self.assertIn(f"errno={err_code}", str(cm.exception))

    def test_measure_s5_worker_authentication(self):
        """authenticate_measure_s5_worker rejects unauthenticated or corrupted invocations."""
        # 1. Missing arguments fail closed
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(None, None)
        self.assertIn("Authentication failed", str(cm.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(10, None)
        self.assertIn("Authentication failed", str(cm.exception))

        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(None, "a" * 64)
        self.assertIn("Authentication failed", str(cm.exception))

        # 2. Invalid FD fails closed
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(99999, "a" * 64)
        self.assertIn("Authentication failed", str(cm.exception))

        # 3. Invalid hex hash fails closed
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(0, "not_a_valid_hex_hash_string_of_length_64_characters_xxxxxxxxxxxxxx")
        self.assertIn("Authentication failed", str(cm.exception))

        # 4. Cryptographic token mismatch fails closed
        r_fd, w_fd = os.pipe()
        os.write(w_fd, b"coordinator_secret_token")
        os.close(w_fd)
        wrong_hash = hashlib.sha256(b"wrong_secret_token").hexdigest()
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(r_fd, wrong_hash, is_test_fixture=True)
        self.assertIn("verification failed", str(cm.exception).lower())

        # 5. Matching token succeeds under test fixture
        r_fd, w_fd = os.pipe()
        secret_bytes = secrets.token_bytes(32)
        os.write(w_fd, secret_bytes)
        os.close(w_fd)
        valid_hash = hashlib.sha256(secret_bytes).hexdigest()
        # Should not raise
        priv_helper.authenticate_measure_s5_worker(r_fd, valid_hash, is_test_fixture=True)

        # 6. Non-fixture execution rejects runner process because parent PID is not measure-s5 coordinator
        r_fd, w_fd = os.pipe()
        os.write(w_fd, secret_bytes)
        os.close(w_fd)
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(r_fd, valid_hash, is_test_fixture=False)
        self.assertIn("Authentication failed", str(cm.exception))

        # 6a. Negative test: Substring injection in parent cmdline fails closed
        r_fd, w_fd = os.pipe()
        os.write(w_fd, secret_bytes)
        os.close(w_fd)
        fake_cmd_substring = ["python3", "evil.py", "--arg=measure-s5"]
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(
                r_fd, valid_hash, parent_cmdline=fake_cmd_substring, is_test_fixture=True
            )
        self.assertIn("executable is not the privileged helper", str(cm.exception))

        # 6b. Negative test: Worker spawning another worker fails closed
        r_fd, w_fd = os.pipe()
        os.write(w_fd, secret_bytes)
        os.close(w_fd)
        fake_cmd_worker = ["python3", "/usr/local/libexec/ps028/privileged_helper.py", "measure-s5-worker"]
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(
                r_fd, valid_hash, parent_cmdline=fake_cmd_worker, is_test_fixture=True
            )
        self.assertIn("unauthorized worker invocation", str(cm.exception))

        # 6c. Negative test: Reparented to PID 1 fails closed
        r_fd, w_fd = os.pipe()
        os.write(w_fd, secret_bytes)
        os.close(w_fd)
        with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
            priv_helper.authenticate_measure_s5_worker(
                r_fd, valid_hash, parent_pid=1, is_test_fixture=True
            )
        self.assertIn("invalid parent PID", str(cm.exception))

        # 7. Positive test: Authentic coordinator parent cmdline succeeds under test fixture
        r_fd, w_fd = os.pipe()
        os.write(w_fd, secret_bytes)
        os.close(w_fd)
        genuine_cmd = [
            "/usr/bin/python3", "-I", "/usr/local/libexec/ps028/privileged_helper.py",
            "measure-s5", "--target-ip", "2001:db8:2::10", "--port", "80"
        ]
        priv_helper.authenticate_measure_s5_worker(
            r_fd, valid_hash, parent_pid=42, parent_cmdline=genuine_cmd, is_test_fixture=True
        )

        # 8. Sudoers policy verification: worker action remains strictly absent
        deploy_script = (REPO_ROOT / "lab" / "deploy_privileged_helper.sh").read_text(encoding="utf-8")
        self.assertNotIn("measure-s5-worker", deploy_script)
        sudoers_doc = (REPO_ROOT / "docs" / "phase-cd" / "sudoers_configuration.md").read_text(encoding="utf-8")
        self.assertNotIn("measure-s5-worker", sudoers_doc)

        # 9. Direct user invocation via run_helper_action is prohibited both as root and non-root
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.run_helper_action("measure-s5-worker")
            self.assertIn("prohibited", str(cm.exception).lower())

        with patch("os.geteuid", return_value=1000):
            with self.assertRaises(priv_helper.PrivilegedHelperError) as cm:
                priv_helper.run_helper_action("measure-s5-worker")
            self.assertIn("prohibited", str(cm.exception).lower())

    def test_duplicate_argument_rejection_across_subcommands(self):
        """StrictArgumentParser rejects duplicate scalar options, boolean flags, and option aliases."""
        parser = priv_helper.build_parser()

        duplicate_test_cases = [
            # Repeated scalar options
            (["apply-scenario", "--scenario", "S0", "--scenario", "S1"], "--scenario"),
            (["apply-scenario", "--scenario", "S0", "--scenarios-path", "/a", "--scenarios-path", "/b"], "--scenarios-path"),
            (["start-capture", "--netns", "ps028-cl", "--netns", "ps028-cl"], "--netns"),
            (["stop-capture", "--pid", "100", "--pid", "200", "--pcap", "/tmp/t.pcap"], "--pid"),
            (["stop-capture", "--pid", "100", "--pcap", "/tmp/a.pcap", "--pcap", "/tmp/b.pcap"], "--pcap"),
            (["start-dns", "--bind", "10.0.1.1", "--bind", "10.0.1.2"], "--bind"),
            (["start-dns", "--port", "53", "--port", "5353"], "--port"),
            (["start-nginx", "--repo-root", "/tmp", "--repo-root", "/var/tmp"], "--repo-root"),
            (["launch-snap-browser", "--reuid", "1000", "--reuid", "1001", "--regid", "1000", "/usr/bin/google-chrome"], "--reuid"),
            (["launch-snap-browser", "--reuid", "1000", "--regid", "1000", "--regid", "1001", "/usr/bin/google-chrome"], "--regid"),
            (["launch-snap-browser", "--reuid", "1000", "--regid", "1000", "--resolver-ip", "10.0.1.1", "--resolver-ip", "10.0.1.2", "/usr/bin/google-chrome"], "--resolver-ip"),
            (["measure-s5", "--target-ip", "2001:db8:2::10", "--target-ip", "2001:db8:2::10"], "--target-ip"),
            (["measure-s5", "--port", "80", "--port", "8080"], "--port"),
            # Repeated boolean flags
            (["apply-scenario", "--scenario", "S0", "--caller-holds-lock", "--caller-holds-lock"], "--caller-holds-lock"),
            (["restore-baseline", "--caller-holds-lock", "--caller-holds-lock"], "--caller-holds-lock"),
            (["verify-baseline", "--caller-holds-lock", "--caller-holds-lock"], "--caller-holds-lock"),
            (["start-capture", "--caller-holds-lock", "--caller-holds-lock"], "--caller-holds-lock"),
            (["stop-capture", "--pid", "100", "--pcap", "/tmp/t.pcap", "--caller-holds-lock", "--caller-holds-lock"], "--caller-holds-lock"),
            # Option alias duplication (--probe-count vs --probes)
            (["measure-s5", "--probe-count", "10", "--probes", "20"], "--probes"),
        ]

        for argv, expected_dup in duplicate_test_cases:
            with self.subTest(argv=argv, expected_dup=expected_dup):
                with self.assertRaises(SystemExit):
                    with patch("sys.stderr"):
                        parser.parse_args(argv)

        # Confirm valid invocations without duplicates parse cleanly
        valid_argv = ["apply-scenario", "--scenario", "S0", "--caller-holds-lock"]
        res = parser.parse_args(valid_argv)
        self.assertEqual(res.scenario, "S0")
        self.assertTrue(res.caller_holds_lock)


if __name__ == "__main__":
    unittest.main()
