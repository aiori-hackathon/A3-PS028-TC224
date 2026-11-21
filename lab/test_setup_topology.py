#!/usr/bin/env python3
"""
PS-028 Lab Topology and Host Invariance Unit and Regression Tests
Work Package F: Environment & Topology Hardening

Tests portable host-state capture, dynamic SLAAC lifetime normalization,
and host-invariance verification without modifying system configuration.
"""

from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SETUP_TOPOLOGY_SH = SCRIPT_DIR / "setup_topology.sh"


class TestSetupTopologyHostInvariance(unittest.TestCase):
    """Tests portable host snapshotting and invariance verification."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_topo_test_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_snapshot_host_state_captures_portable_interfaces_and_normalizes(self):
        """snapshot-host executes without root and produces portable snapshot with normalized lifetimes."""
        snap_file = self.temp_dir / "baseline.txt"
        proc = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc.returncode, 0, f"snapshot-host failed: {proc.stderr}")
        self.assertTrue(snap_file.is_file())

        content = snap_file.read_text(encoding="utf-8")
        self.assertIn("=== HOST INTERFACES ===", content)
        self.assertNotIn("=== HOST INTERFACES (eth0) ===", content)
        self.assertIn("=== IPV4 ROUTES ===", content)
        self.assertIn("=== IPV6 ROUTES ===", content)
        self.assertIn("=== IPV4 RULES ===", content)
        self.assertIn("=== IPV6 RULES ===", content)

        # Dynamic lifetimes must be normalized
        self.assertNotIn("valid_lft forever", content)
        if "valid_lft" in content:
            self.assertIn("valid_lft <dynamic>", content)

    def test_check_host_invariance_passes_on_intact_state(self):
        """check-host-invariance returns 0 when host network state matches baseline."""
        snap_file = self.temp_dir / "baseline.txt"
        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_snap.returncode, 0)

        proc_check = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "check-host-invariance", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_check.returncode, 0, f"check-host-invariance failed: {proc_check.stderr}")
        self.assertIn("HOST INVARIANCE VERIFIED", proc_check.stdout)

    def test_check_host_invariance_fails_closed_on_drift(self):
        """check-host-invariance returns 1 when network configuration has drifted."""
        snap_file = self.temp_dir / "baseline.txt"
        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_snap.returncode, 0)

        # Simulate host drift in baseline
        content = snap_file.read_text(encoding="utf-8")
        tampered_content = content + "\n198.51.100.0/24 dev dummy0 proto static\n"
        snap_file.write_text(tampered_content, encoding="utf-8")

        proc_check = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "check-host-invariance", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_check.returncode, 1)
        self.assertIn("HOST INVARIANCE VIOLATION DETECTED", proc_check.stderr + proc_check.stdout)

    def test_check_host_invariance_detects_residual_ps028_interface(self):
        """check-host-invariance fails closed if residual project interface is left on host."""
        snap_file = self.temp_dir / "baseline.txt"
        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_snap.returncode, 0)
        self.assertNotIn("ps028-cl-rt", snap_file.read_text(encoding="utf-8"))

        # If residual ps028- interface or route exists, invariance check fails closed
        tampered = snap_file.read_text(encoding="utf-8").replace(
            "=== HOST INTERFACES ===",
            "=== HOST INTERFACES ===\n99: ps028-cl-rt: <BROADCAST> mtu 1500\n    inet 10.0.1.2/24 scope global ps028-cl-rt"
        )
        snap_file.write_text(tampered, encoding="utf-8")

        proc_check = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "check-host-invariance", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_check.returncode, 1)
        self.assertIn("HOST INVARIANCE VIOLATION DETECTED", proc_check.stderr + proc_check.stdout)


if __name__ == "__main__":
    unittest.main()
