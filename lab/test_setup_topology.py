#!/usr/bin/env python3
"""
PS-028 Lab Topology and Host Invariance Unit and Regression Tests
Work Package F: Environment & Topology Hardening

Tests portable host-state capture, dynamic SLAAC lifetime normalization,
and host-invariance verification without modifying system configuration.
"""

import os
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

    SAMPLE_DOCKER_BRIDGE_FIXTURE = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 allmulti 0 minmtu 0 maxmtu 0 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 524280 tso_max_segs 65535 gro_max_size 65536 \n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "       valid_lft forever preferred_lft forever\n"
        "4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default \n"
        "    link/ether ee:4a:b0:16:ff:14 brd ff:ff:ff:ff:ff:ff promiscuity 0  allmulti 0 minmtu 68 maxmtu 65535 \n"
        "    bridge forward_delay 1500 hello_time 200 max_age 2000 ageing_time 30000 stp_state 0 priority 32768 vlan_filtering 0 vlan_protocol 802.1Q bridge_id 8000.ee:4a:b0:16:ff:14 designated_root 8000.ee:4a:b0:16:ff:14 root_port 0 root_path_cost 0 topology_change 0 topology_change_detected 0 hello_timer    0.00 tcn_timer    0.00 topology_change_timer    0.00 gc_timer  199.43 vlan_default_pvid 1 vlan_stats_enabled 0 vlan_stats_per_port 0 group_fwd_mask 0 group_address 01:80:c2:00:00:00 mcast_snooping 1 no_linklocal_learn 0 mcast_vlan_snooping 0 mcast_router 1 mcast_query_use_ifaddr 0 mcast_querier 0 mcast_hash_elasticity 16 mcast_hash_max 4096 mcast_last_member_count 2 mcast_startup_query_count 2 mcast_last_member_interval 100 mcast_membership_interval 26000 mcast_querier_interval 25500 mcast_query_interval 12500 mcast_query_response_interval 1000 mcast_startup_query_interval 3125 mcast_stats_enabled 0 mcast_igmp_version 2 mcast_mld_version 1 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535 tso_max_size 65536 tso_max_segs 65535 gro_max_size 65536 \n"
        "    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
        "       valid_lft forever preferred_lft forever\n"
    )

    def _create_fake_ip_environment(self, interface_fixture: str):
        """Creates a temporary bin directory with a controlled fake ip script returning deterministic fixtures."""
        fake_bin = self.temp_dir / "bin"
        fake_bin.mkdir(parents=True, exist_ok=True)
        fixture_file = self.temp_dir / "ip_addr_fixture.txt"
        fixture_file.write_text(interface_fixture, encoding="utf-8")

        fake_ip = fake_bin / "ip"
        script_body = f"""#!/bin/bash
if [[ "$*" == *"-d addr show"* ]]; then
    cat "{fixture_file}"
elif [[ "$*" == *"-4 route show"* ]]; then
    echo "default via 172.21.32.1 dev eth0 proto static"
elif [[ "$*" == *"-6 route show"* ]]; then
    echo "fe80::/64 dev eth0 proto kernel metric 256"
elif [[ "$*" == *"-4 rule show"* ]]; then
    echo "0: from all lookup local"
    echo "32766: from all lookup main"
    echo "32767: from all lookup default"
elif [[ "$*" == *"-6 rule show"* ]]; then
    echo "0: from all lookup local"
    echo "32766: from all lookup main"
else
    exec /usr/bin/ip "$@"
fi
"""
        fake_ip.write_text(script_body, encoding="utf-8")
        fake_ip.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
        return env, fixture_file

    def test_bridge_countdown_timer_normalization_passes_invariance(self):
        """Case A: Invariance check passes when only Linux bridge dynamic countdown timers drift."""
        env, fixture_file = self._create_fake_ip_environment(self.SAMPLE_DOCKER_BRIDGE_FIXTURE)
        snap_file = self.temp_dir / "baseline.txt"

        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_snap.returncode, 0, f"snapshot-host failed: {proc_snap.stderr}")

        # Update fixture with all 4 volatile timer countdown shifts observed on CI
        shifted_timers_fixture = (
            self.SAMPLE_DOCKER_BRIDGE_FIXTURE
            .replace("hello_timer    0.00", "hello_timer    0.05")
            .replace("tcn_timer    0.00", "tcn_timer    0.01")
            .replace("topology_change_timer    0.00", "topology_change_timer    0.02")
            .replace("gc_timer  199.43", "gc_timer  199.42")
        )
        fixture_file.write_text(shifted_timers_fixture, encoding="utf-8")

        proc_check = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "check-host-invariance", str(snap_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            proc_check.returncode,
            0,
            f"check-host-invariance must pass on countdown-only drift: {proc_check.stdout}\n{proc_check.stderr}"
        )
        self.assertIn("HOST INVARIANCE VERIFIED", proc_check.stdout)

    def test_bridge_internal_whitespace_canonicalization_passes_invariance(self):
        """Case B: Invariance check passes when only internal repeated whitespace differs in diagnostic output."""
        env, fixture_file = self._create_fake_ip_environment(self.SAMPLE_DOCKER_BRIDGE_FIXTURE)
        snap_file = self.temp_dir / "baseline.txt"

        proc_snap = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc_snap.returncode, 0)

        # Alter repeated spacing around promiscuity, allmulti, and bridge attributes
        spacing_variant_fixture = (
            self.SAMPLE_DOCKER_BRIDGE_FIXTURE
            .replace("promiscuity 0  allmulti 0", "promiscuity 0 allmulti 0")
            .replace("bridge forward_delay 1500 hello_time 200", "bridge  forward_delay  1500   hello_time  200")
        )
        fixture_file.write_text(spacing_variant_fixture, encoding="utf-8")

        proc_check = subprocess.run(
            [str(SETUP_TOPOLOGY_SH), "check-host-invariance", str(snap_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            proc_check.returncode,
            0,
            f"check-host-invariance must pass on whitespace-only differences: {proc_check.stdout}\n{proc_check.stderr}"
        )
        self.assertIn("HOST INVARIANCE VERIFIED", proc_check.stdout)

    def test_bridge_stable_configuration_changes_fail_invariance(self):
        """Case C: Invariance check strictly fails closed when stable bridge configuration attributes change."""
        stable_mutations = [
            ("stp_state 0", "stp_state 1"),
            ("forward_delay 1500", "forward_delay 2000"),
            ("vlan_filtering 0", "vlan_filtering 1"),
            ("bridge_id 8000.ee:4a:b0:16:ff:14", "bridge_id 8000.11:22:33:44:55:66"),
        ]

        for target, tampered in stable_mutations:
            with self.subTest(attribute=target.split()[0]):
                env, fixture_file = self._create_fake_ip_environment(self.SAMPLE_DOCKER_BRIDGE_FIXTURE)
                snap_file = self.temp_dir / f"baseline_{target.split()[0]}.txt"

                proc_snap = subprocess.run(
                    [str(SETUP_TOPOLOGY_SH), "snapshot-host", str(snap_file)],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(proc_snap.returncode, 0)

                tampered_fixture = self.SAMPLE_DOCKER_BRIDGE_FIXTURE.replace(target, tampered)
                fixture_file.write_text(tampered_fixture, encoding="utf-8")

                proc_check = subprocess.run(
                    [str(SETUP_TOPOLOGY_SH), "check-host-invariance", str(snap_file)],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    proc_check.returncode,
                    1,
                    f"check-host-invariance must fail when stable attribute '{target}' is changed to '{tampered}'"
                )
                self.assertIn("HOST INVARIANCE VIOLATION DETECTED", proc_check.stdout + proc_check.stderr)


if __name__ == "__main__":
    unittest.main()
