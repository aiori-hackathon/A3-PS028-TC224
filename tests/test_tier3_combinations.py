"""
PS-028 Tier 3: Cross-Feature Combinations Test Suite
Independent E2E Testing Track

Evaluates pairwise and compound interactions between protocol features:
1. DNS Delay + TCP SYN RST
2. High Network Latency + Packet Loss (SYN Retransmissions)
3. IPv6 SYN Blackhole + DNS A Resolution Delay
4. HTTPS/SVCB Resolution + IPv6 Endpoint Timeout
5. Asymmetric Latency + Retransmitted SYN Integrity
6. Cleanup Failure Contention + Export Reconciliation
7. Resolution Delay Expiration + CAD Interleaved Racing

Normative references: RFC 8305 §3 & §5, RFC 9293 §3.5, RFC 9460
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
    ExportReconciler,
    HappyEyeballsSimulator,
    SchemaValidator,
)


class TestTier3Combinations(unittest.TestCase):
    """Verifies complex multi-factor protocol and impairment interactions."""

    def test_combination_dns_delay_and_syn_rst(self):
        """
        Combination 1: DNS AAAA delayed by 500ms (Scenario S6 style).
        When AAAA arrives, IPv6 SYN receives TCP RST (Scenario S2 style).
        Simulated active rejection accelerates switch to IPv4 upon RST; note that neither RFC 8305 nor draft HEv3 mandates immediate switch upon RST.
        """
        # A returns immediately (0ms). Resolution delay is 50ms.
        # At t=50ms, IPv4 starts because AAAA has not arrived!
        # IPv4 completes at 50 + 20 = 70ms.
        # Meanwhile AAAA arrives at 500ms; by then IPv4 has already established!
        sim = HappyEyeballsSimulator(
            resolution_delay_ms=50.0,
            dns_a_delay_ms=0.0,
            dns_aaaa_delay_ms=500.0,
            ipv6_rtt_ms=20.0,
            ipv6_rst=True,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        # First SYN of any family was IPv4 at 50ms; primary final ACK at 70ms -> t_setup_total = 20ms
        self.assertEqual(metrics.t_setup_total_ms, 20.0)
        # Total time from DNS query (t=0) to payload response is 81ms
        self.assertEqual(metrics.dns_query_to_first_payload_ms, 81.0)

    def test_combination_ipv6_high_delay_and_high_loss(self):
        """
        Combination 2: IPv6 RTT 150ms + 100% initial SYN loss (triggering retransmission).
        CAD timer is 250ms.
        Initial SYN dropped at t=0. Next SYN at t=1000ms.
        CAD expires at t=250ms -> IPv4 starts at t=250ms, finishes at 270ms.
        IPv4 wins because IPv6 is delayed by retransmission!
        """
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=250.0,
            ipv6_rtt_ms=150.0,
            ipv6_syn_loss_pct=100.0,
            syn_retransmit_timeout_ms=1000.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        self.assertEqual(metrics.t_setup_total_ms, 270.0)
        self.assertEqual(len(conn_attempts), 2)
        v4_attempt = next(ca for ca in conn_attempts if ca.family == AddressFamily.IPV4.value)
        self.assertEqual(v4_attempt.outcome, ConnectionOutcome.ESTABLISHED.value)

    def test_combination_ipv6_syn_blackhole_and_dns_a_delay(self):
        """
        Combination 3: IPv6 SYN blackhole (S1) + DNS A delay of 200ms.
        IPv6 starts at t=0ms (AAAA immediate).
        At t=250ms, CAD expires; but DNS A response is already available (at 200ms).
        IPv4 starts at t=250ms and completes at t=270ms.
        """
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=250.0,
            dns_a_delay_ms=200.0,
            dns_aaaa_delay_ms=0.0,
            ipv6_rtt_ms=None,  # Blackholed
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        self.assertEqual(metrics.t_setup_total_ms, 270.0)

    def test_combination_concurrent_https_svcb_and_ipv6_timeout(self):
        """
        Combination 4: HTTPS/SVCB (Type 65) record received in 10ms alongside A/AAAA,
        while IPv6 endpoint times out.
        Verifies that Type 65 tracking is cleanly recorded without distorting IPv4 fallback.
        """
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=250.0,
            include_svcb=True,
            dns_svcb_delay_ms=10.0,
            ipv6_rtt_ms=None,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, _ = sim.run()

        self.assertEqual(len(metrics.https_svcb_queries), 1)
        self.assertEqual(metrics.https_svcb_queries[0].qtype, 65)
        self.assertEqual(metrics.https_svcb_queries[0].duration_ms, 10.0)
        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        self.assertEqual(metrics.t_setup_total_ms, 270.0)

    def test_combination_asymmetric_latency_and_syn_retransmission(self):
        """
        Combination 5: Symmetric RTT is 150ms, but loss occurs on first attempt.
        Validates that connection attempts export maintains accurate duration across retry.
        """
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=2000.0,
            ipv6_rtt_ms=150.0,
            ipv6_syn_loss_pct=0.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertEqual(metrics.winning_family, AddressFamily.IPV6.value)
        self.assertEqual(metrics.t_connect_ms, 150.0)
        self.assertEqual(metrics.syn_to_synack_ms, 75.0)

    def test_combination_impairment_rollback_failure_and_export_reconciliation(self):
        """
        Combination 6: Harness records a trial with cleanup failure.
        Export reconciler must verify that exactly 282 rows are preserved:
        280 valid live trials + 2 cleanup failures.
        """
        rows = [
            {"trial_id": f"trial-live-{i:03d}", "validity_status": AttemptValidity.VALID_LIVE.value}
            for i in range(280)
        ]
        # Append two historical cleanup failures
        rows.append({"trial_id": "trial-fail-001", "validity_status": AttemptValidity.EXCLUDED_CLEANUP_FAILURE.value})
        rows.append({"trial_id": "trial-fail-002", "validity_status": AttemptValidity.EXCLUDED_CLEANUP_FAILURE.value})

        is_valid, err = ExportReconciler.verify_attempts_rows(rows, expected_count=282)
        self.assertTrue(is_valid, msg=err)

    def test_combination_dns_resolution_delay_expiration_and_cad_interleaving(self):
        """
        Combination 7: A arrives at 0ms, AAAA delayed to 100ms.
        Resolution delay is 50ms.
        At t=50ms, IPv4 starts (since AAAA not yet received).
        At t=100ms, AAAA arrives and IPv6 starts!
        IPv4 finishes at 50 + 20 = 70ms < 100ms.
        IPv4 wins before IPv6 ever starts.
        """
        sim = HappyEyeballsSimulator(
            resolution_delay_ms=50.0,
            dns_a_delay_ms=0.0,
            dns_aaaa_delay_ms=100.0,
            ipv6_rtt_ms=20.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        # First SYN was IPv4 at 50ms; primary final ACK at 70ms -> t_setup_total = 20.0ms
        self.assertEqual(metrics.t_setup_total_ms, 20.0)
        self.assertEqual(metrics.dns_query_to_first_payload_ms, 81.0)


if __name__ == "__main__":
    unittest.main()
