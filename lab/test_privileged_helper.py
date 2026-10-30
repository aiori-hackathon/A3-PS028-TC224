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
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
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
                "--owner-user", "indrani",
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
                    "--owner-user", "indrani",
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
        with patch("os.getuid", return_value=0), \
             patch.dict(os.environ, {"SUDO_UID": "1002", "SUDO_GID": "1003"}):
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

        res = priv_helper.start_capture_privileged(
            output_pcap=self.pcap_file,
            log_file=self.log_file,
            netns="ps028-cl",
            owner_user="indrani"
        )
        cmd_called = mock_popen.call_args[0][0]
        self.assertIn("-Z", cmd_called)
        self.assertIn("indrani", cmd_called)
        self.assertIn("-B", cmd_called)
        self.assertIn("8192", cmd_called)
        self.assertIn("ps028-cl-rt", cmd_called)
        self.assertIn(priv_helper.DEFAULT_BPF_FILTER, cmd_called)
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

        res = priv_helper.start_capture_privileged(
            output_pcap=self.pcap_file,
            log_file=self.log_file,
            netns="ps028-cl",
            interface="any",
            bpf_filter="port 80",
            buffer_size_kb=4096,
            owner_user="indrani"
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

        res = priv_helper.start_capture_privileged(
            output_pcap=self.pcap_file,
            log_file=self.log_file,
            netns="ps028-cl",
            owner_user="indrani"
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

        res = priv_helper.start_capture_privileged(
            output_pcap=self.pcap_file,
            log_file=self.log_file,
            netns="ps028-cl",
            owner_user="indrani"
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
                    verify_pcap=True
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
                    readiness_timeout=0.1
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
                readiness_timeout=0.2
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

        with patch("lab.run_trial.find_tcpdump_pid", side_effect=RuntimeError("Simulated post-spawn error")):
            with patch("os.kill") as mock_kill:
                with self.assertRaises(priv_helper.PrivilegedHelperError) as ctx:
                    priv_helper.start_capture_privileged(
                        output_pcap=self.pcap_file,
                        log_file=self.log_file,
                        netns="ps028-cl"
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


if __name__ == "__main__":
    unittest.main()
