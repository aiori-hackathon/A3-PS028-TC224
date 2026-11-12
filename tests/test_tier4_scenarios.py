"""
PS-028 Tier 4: Real-World Application Scenarios Test Suite
Independent E2E Testing Track

Simulates realistic network deployment environments and browser application workloads:
1. Fast FTTH Dual-Stack Broadband (Clean IPv6 path)
2. Mobile Cellular Handover with Transient Packet Loss
3. Broken Enterprise WAN / Firewall IPv6 Blackhole
4. CDN Anycast DNS with Degraded AAAA Propagation
5. High-Latency Satellite Link (GEO/LEO) with Local Fallback
6. Modern Dual-Stack Web Service with HTTPS/SVCB (Type 65) ALPN Hints

Normative references: RFC 8305, RFC 9293, RFC 9460, PS-028
"""

import unittest
from typing import Any, Dict, List

from tests.common.models import (
    AddressFamily,
    AttemptRecord,
    AttemptValidity,
    ConnectionAttemptRecord,
    ConnectionOutcome,
    DNSTransaction,
    EventSource,
    TrialMetrics,
)
from tests.common.simulators import (
    DNSWireCodec,
    ExportReconciler,
    HappyEyeballsSimulator,
    SchemaValidator,
)


class TestTier4RealWorldScenarios(unittest.TestCase):
    """Verifies end-to-end fallback behavior under realistic production conditions."""

    def test_scenario_dual_stack_fiber_broadband(self):
        """
        Scenario 1: Residential FTTH Fiber.
        IPv6 link: 15ms RTT. IPv4 link: 20ms RTT. DNS: 5ms.
        RFC 8305 §4 prefers IPv6. IPv6 finishes in 15ms < 250ms CAD.
        Result: Clean IPv6 win, 0 fallback overhead, single flow.
        """
        sim = HappyEyeballsSimulator(
            dns_a_delay_ms=5.0,
            dns_aaaa_delay_ms=5.0,
            ipv6_rtt_ms=15.0,
            ipv4_rtt_ms=20.0,
            connection_attempt_delay_ms=250.0,
        )
        metrics, packets, _, conn_attempts = sim.run(trial_id="fiber-broadband-01")

        self.assertEqual(metrics.winning_family, AddressFamily.IPV6.value)
        self.assertEqual(metrics.t_connect_ms, 15.0)
        self.assertEqual(metrics.t_setup_total_ms, 15.0)
        self.assertEqual(metrics.syn_to_synack_ms, 7.5)
        self.assertEqual(len(conn_attempts), 1)
        self.assertEqual(conn_attempts[0].outcome, ConnectionOutcome.ESTABLISHED.value)

    def test_scenario_mobile_cellular_handover(self):
        """
        Scenario 2: Mobile Cellular Network Handover.
        During base-station handoff, IPv6 link drops initial SYN packet.
        CAD timer (250ms) fires before SYN retransmission completes.
        IPv4 secondary path establishes cleanly at 270ms.
        """
        sim = HappyEyeballsSimulator(
            dns_a_delay_ms=10.0,
            dns_aaaa_delay_ms=10.0,
            ipv6_rtt_ms=40.0,
            ipv6_syn_loss_pct=100.0,  # Packet dropped during cell handoff
            syn_retransmit_timeout_ms=1000.0,
            ipv4_rtt_ms=30.0,
            connection_attempt_delay_ms=250.0,
        )
        metrics, _, _, conn_attempts = sim.run(trial_id="cellular-handover-01")

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 30.0)
        # First SYN sent at t=10ms (IPv6); IPv4 starts at t=260ms, final ACK at 290ms -> 280ms total setup
        self.assertEqual(metrics.t_setup_total_ms, 280.0)
        self.assertEqual(len(conn_attempts), 2)

    def test_scenario_broken_enterprise_ipv6_firewall_blackhole(self):
        """
        Scenario 3: Broken Enterprise IPv6 Routing / WAN Blackhole.
        Client gets IPv6 via SLAAC, but enterprise border firewall drops outgoing SYN.
        Happy Eyeballs seamlessly falls back to IPv4 after CAD expires.
        """
        sim = HappyEyeballsSimulator(
            dns_a_delay_ms=2.0,
            dns_aaaa_delay_ms=2.0,
            ipv6_rtt_ms=None,  # Silently dropped by border firewall
            ipv4_rtt_ms=18.0,
            connection_attempt_delay_ms=250.0,
        )
        metrics, _, _, conn_attempts = sim.run(trial_id="enterprise-blackhole-01")

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 18.0)
        # First SYN at 2ms (IPv6); IPv4 starts at 252ms, finishes at 270ms -> 268ms total
        self.assertEqual(metrics.t_setup_total_ms, 268.0)
        v6_conn = next(ca for ca in conn_attempts if ca.family == "ipv6")
        self.assertEqual(v6_conn.outcome, ConnectionOutcome.TIMEOUT.value)

    def test_scenario_cdn_anycast_delayed_aaaa_resolution(self):
        """
        Scenario 4: CDN Anycast with Degraded Authoritative AAAA Nameserver.
        AAAA takes 350ms to resolve, while A takes 15ms.
        RFC 8305 §3 Resolution Delay is 50ms.
        Client starts IPv4 at 50ms without waiting for slow AAAA.
        IPv4 completes at 70ms. User experiences fast page load.
        """
        sim = HappyEyeballsSimulator(
            resolution_delay_ms=50.0,
            dns_a_delay_ms=15.0,
            dns_aaaa_delay_ms=350.0,
            ipv6_rtt_ms=20.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, _ = sim.run(trial_id="cdn-delayed-aaaa-01")

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        self.assertEqual(metrics.t_setup_total_ms, 20.0)
        # DNS query launched at 0ms, IPv4 finishes at 70ms, payload received at 81ms
        self.assertEqual(metrics.dns_query_to_first_payload_ms, 81.0)

    def test_scenario_satellite_link_high_latency_with_local_cache(self):
        """
        Scenario 5: High-Latency Satellite Link (GEO/LEO) vs Local Fast Gateway.
        Satellite IPv6 link has 600ms RTT. IPv4 link has 25ms RTT.
        CAD is 250ms.
        IPv6 starts at t=0ms. At t=250ms, CAD expires -> IPv4 starts.
        IPv4 completes at t=275ms, beating IPv6 by 325ms!
        """
        sim = HappyEyeballsSimulator(
            ipv6_rtt_ms=600.0,
            ipv4_rtt_ms=25.0,
            connection_attempt_delay_ms=250.0,
        )
        metrics, _, _, conn_attempts = sim.run(trial_id="satellite-high-latency-01")

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 25.0)
        self.assertEqual(metrics.t_setup_total_ms, 275.0)
        self.assertEqual(len(conn_attempts), 2)

    def test_scenario_dual_stack_service_binding_svcb_racing(self):
        """
        Scenario 6: Modern Dual-Stack Web Service with RFC 9460 HTTPS/SVCB.
        DNS delivers A, AAAA, and Type 65 HTTPS record with ALPN 'h2,h3'.
        IPv6 establishes cleanly; SVCB queries are segregated into their own metrics block.
        """
        sim = HappyEyeballsSimulator(
            include_svcb=True,
            dns_svcb_delay_ms=8.0,
            dns_a_delay_ms=8.0,
            dns_aaaa_delay_ms=8.0,
            ipv6_rtt_ms=22.0,
            ipv4_rtt_ms=22.0,
            connection_attempt_delay_ms=250.0,
        )
        metrics, _, _, _ = sim.run(trial_id="svcb-racing-01")

        self.assertEqual(metrics.winning_family, AddressFamily.IPV6.value)
        self.assertEqual(metrics.t_connect_ms, 22.0)
        self.assertEqual(len(metrics.https_svcb_queries), 1)
        self.assertEqual(metrics.https_svcb_queries[0].qtype, 65)
        self.assertIn("alpn=h2,h3", metrics.https_svcb_queries[0].answers)


if __name__ == "__main__":
    unittest.main()
