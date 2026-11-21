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
        self.assertEqual(proc_check.returncode, 0, f"check-host-invariance failed: stdout={proc_check.stdout}\nstderr={proc_check.stderr}")
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

    def test_check_host_invariance_fails_on_genuine_route_changes(self):
        """check-host-invariance fails closed on genuine route destination, gateway, or metric changes."""
        snap_file = self.temp_dir / "baseline.txt"
        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_snap.returncode, 0)

        # Inject an unauthorized route under IPV4 ROUTES
        content = snap_file.read_text(encoding="utf-8")
        tampered = content.replace(
            "=== IPV4 ROUTES ===\n",
            "=== IPV4 ROUTES ===\n203.0.113.0/24 via 192.0.2.1 dev eth0 proto static metric 100\n"
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

    def test_check_host_invariance_fails_on_address_and_gateway_changes(self):
        """check-host-invariance fails closed if host IP address or default gateway is modified."""
        snap_file = self.temp_dir / "baseline.txt"
        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_snap.returncode, 0)

        # Tamper host interface IP address
        content = snap_file.read_text(encoding="utf-8")
        tampered_addr = content.replace("127.0.0.1", "10.99.99.1")
        snap_file.write_text(tampered_addr, encoding="utf-8")

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

        # If residual ps028- interface exists, invariance check fails closed
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

    def test_check_host_invariance_detects_residual_ps028_route(self):
        """check-host-invariance fails closed if residual project route is left on host."""
        snap_file = self.temp_dir / "baseline.txt"
        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(proc_snap.returncode, 0)
        self.assertNotIn("ps028-cl-rt", snap_file.read_text(encoding="utf-8"))

        # If residual ps028- route exists, invariance check fails closed
        tampered = snap_file.read_text(encoding="utf-8").replace(
            "=== IPV6 ROUTES ===",
            "=== IPV6 ROUTES ===\n2001:db8:1::/64 dev ps028-cl-rt proto kernel metric 256"
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

    def test_dynamic_ra_countdown_normalization(self):
        """Route normalization converts dynamic 'expires Nsec' countdowns to '<dynamic>'."""
        raw_routes = (
            "default via fe80::1 dev eth0 proto ra metric 1024 expires 1798sec mtu 1500 hoplimit 64 pref medium\n"
            "fe80::/64 dev eth0 proto kernel metric 256 expires 2123sec pref medium\n"
        )
        # Apply normalization pipeline
        norm_cmd = ["sed", "-E", "-e", "s/expires [0-9]+sec/expires <dynamic>/g", "-e", "s/cache <[^>]+>//g"]
        proc1 = subprocess.run(norm_cmd, input=raw_routes, capture_output=True, text=True, check=True)

        raw_routes_shifted = (
            "default via fe80::1 dev eth0 proto ra metric 1024 expires 1742sec mtu 1500 hoplimit 64 pref medium\n"
            "fe80::/64 dev eth0 proto kernel metric 256 expires 2000sec pref medium\n"
        )
        proc2 = subprocess.run(norm_cmd, input=raw_routes_shifted, capture_output=True, text=True, check=True)

        # Both must normalize to identical output
        self.assertEqual(proc1.stdout, proc2.stdout)
        self.assertIn("expires <dynamic>", proc1.stdout)
        self.assertNotIn("1798sec", proc1.stdout)
        self.assertNotIn("1742sec", proc1.stdout)

    def test_route_ordering_invariance(self):
        """LC_ALL=C sort ensures route order permutation does not trigger false invariance failure."""
        order_a = "10.0.2.0/24 dev eth1 proto kernel scope link src 10.0.2.1\n10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.1\n"
        order_b = "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.1\n10.0.2.0/24 dev eth1 proto kernel scope link src 10.0.2.1\n"

        sort_cmd = ["sort"]
        proc_a = subprocess.run(sort_cmd, input=order_a, capture_output=True, text=True, check=True, env={"LC_ALL": "C"})
        proc_b = subprocess.run(sort_cmd, input=order_b, capture_output=True, text=True, check=True, env={"LC_ALL": "C"})

        self.assertEqual(proc_a.stdout, proc_b.stdout)

    def test_interface_multiline_structure_preserved(self):
        """Host interfaces section preserves contiguous multiline interface blocks."""
        snap_file = self.temp_dir / "baseline.txt"
        subprocess.run([str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)], check=True)
        content = snap_file.read_text(encoding="utf-8")

        # In multiline interface blocks, 'inet 127.0.0.1' must directly follow 'lo' interface line
        lines = content.splitlines()
        lo_idx = None
        inet_lo_idx = None
        for i, line in enumerate(lines):
            if "lo:" in line and "LOOPBACK" in line:
                lo_idx = i
            elif lo_idx is not None and "inet 127.0.0.1" in line and inet_lo_idx is None:
                inet_lo_idx = i

        self.assertIsNotNone(lo_idx, "lo interface header must exist")
        self.assertIsNotNone(inet_lo_idx, "lo inet line must exist")
        self.assertTrue(inet_lo_idx > lo_idx and (inet_lo_idx - lo_idx) <= 3, "Interface block must not be broken by sorting")


if __name__ == "__main__":
    unittest.main()
