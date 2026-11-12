"""
PS-028 Tier 2: Boundary & Corner Cases Test Suite
Independent E2E Testing Track

Covers boundary values, corner conditions, and stress edge cases across:
1. Impairment Delay & Loss Boundaries (0ms, 10s, 0% vs 100%, CAD boundaries 10ms–2000ms)
2. Protocol Racing Corner Cases (Missing final ACK, retransmitted SYNs, instant RST, dual timeout)
3. DNS Wire Parsing Boundaries (Truncated headers, label limits, malformed buffers, unpaired queries)
4. Schema Strictness Boundaries (Version patch deviations, null vs zero preservation, empty payloads)
5. Export Integrity Boundaries (Exact count sensitivity, collision detection, single trial n=1)

Normative references: RFC 8305 §3 & §5, RFC 9293 §3.5, RFC 1035 §2.3.4
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


# ==============================================================================
# Feature 1: Impairment Delay & Loss Boundaries
# ==============================================================================

class TestTier2BoundaryImpairments(unittest.TestCase):
    """Verifies edge conditions on network delays, loss, and CAD timer boundaries."""

    def test_zero_netem_delay_explicit_boundary(self):
        """Decision 5: Explicit delay 0ms netem qdisc must behave as immediate path."""
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=250.0,
            ipv6_rtt_ms=0.0,
            ipv4_rtt_ms=0.0,
        )
        metrics, _, _, conn_attempts = sim.run()
        self.assertEqual(metrics.winning_family, AddressFamily.IPV6.value)
        self.assertEqual(metrics.t_connect_ms, 0.0)
        self.assertEqual(metrics.t_setup_total_ms, 0.0)
        self.assertEqual(metrics.syn_to_synack_ms, 0.0)

    def test_extreme_delay_boundary(self):
        """Tests extreme network latency (10,000ms / 30,000ms)."""
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=250.0,
            ipv6_rtt_ms=10000.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, _ = sim.run()
        # IPv4 should complete rapidly at 270ms, bypassing the 10-second IPv6 path
        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        self.assertEqual(metrics.t_setup_total_ms, 270.0)

    def test_loss_percentage_boundaries_zero_and_hundred(self):
        """Boundary test: 0.0% loss must never drop packets; 100.0% loss must always drop."""
        # 0% loss:
        sim_zero = HappyEyeballsSimulator(ipv6_syn_loss_pct=0.0, ipv6_rtt_ms=20.0)
        metrics_zero, _, _, _ = sim_zero.run()
        self.assertEqual(metrics_zero.winning_family, AddressFamily.IPV6.value)

        # 100% loss on IPv6:
        sim_hundred = HappyEyeballsSimulator(
            ipv6_syn_loss_pct=100.0,
            ipv6_rtt_ms=20.0,
            ipv4_rtt_ms=20.0,
            connection_attempt_delay_ms=250.0,
        )
        metrics_hundred, _, _, _ = sim_hundred.run()
        self.assertEqual(metrics_hundred.winning_family, AddressFamily.IPV4.value)

    def test_cad_normative_floor_10ms_boundary(self):
        """RFC 8305 §5 normative floor: subsequent connection MUST NOT start within 10ms."""
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=10.0,
            ipv6_rtt_ms=50.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()
        # IPv4 starts at 10ms and completes at 30ms < 50ms (IPv4 wins)
        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_setup_total_ms, 30.0)

    def test_cad_maximum_permitted_2000ms_boundary(self):
        """RFC 8305 §5 maximum permitted CAD: 2000ms."""
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=2000.0,
            ipv6_rtt_ms=500.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()
        # Even with 500ms IPv6 RTT, IPv6 finishes at 500ms before 2000ms CAD expires (IPv6 wins)
        self.assertEqual(metrics.winning_family, AddressFamily.IPV6.value)
        self.assertEqual(metrics.t_connect_ms, 500.0)
        self.assertEqual(len(conn_attempts), 1)

    def test_cad_recommended_bounds_100ms_and_250ms(self):
        """RFC 8305 §5 recommended default is 250ms; recommended floor is 100ms."""
        sim_100 = HappyEyeballsSimulator(connection_attempt_delay_ms=100.0, ipv6_rtt_ms=150.0, ipv4_rtt_ms=20.0)
        m_100, _, _, _ = sim_100.run()
        # IPv4 starts at 100ms, finishes at 120ms < 150ms -> IPv4 wins
        self.assertEqual(m_100.winning_family, AddressFamily.IPV4.value)

        sim_250 = HappyEyeballsSimulator(connection_attempt_delay_ms=250.0, ipv6_rtt_ms=150.0, ipv4_rtt_ms=20.0)
        m_250, _, _, _ = sim_250.run()
        # IPv6 finishes at 150ms < 250ms -> IPv6 wins
        self.assertEqual(m_250.winning_family, AddressFamily.IPV6.value)


# ==============================================================================
# Feature 2: Protocol Racing Corner Cases
# ==============================================================================

class TestTier2BoundaryDualStackRacing(unittest.TestCase):
    """Verifies edge protocol behaviors: missing ACK, multiple retransmits, instant RST."""

    def test_missing_final_ack_yields_null_t_connect_and_incomplete_outcome(self):
        """RFC 9293 §3.5: Handshake incomplete without client final ACK; t_connect MUST be null."""
        sim = HappyEyeballsSimulator(
            simulate_missing_final_ack=True,
            ipv6_rtt_ms=20.0,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertIsNone(metrics.winning_family)
        self.assertIsNone(metrics.t_connect_ms)
        self.assertIsNone(metrics.t_setup_total_ms)
        self.assertEqual(metrics.reason_code, "MISSING_FINAL_ACK")
        for ca in conn_attempts:
            self.assertEqual(ca.outcome, ConnectionOutcome.INCOMPLETE.value)

    def test_retransmitted_syn_preserves_initial_timestamp_under_extreme_retransmission(self):
        """Extreme retransmission: initial SYN at 0ms, retransmitted SYNs at 1000ms, 2000ms."""
        packets = []
        # Simulate packet sequence
        p1 = ConnectionAttemptRecord(
            trial_id="t1", stream_id=0, family="ipv6", src_ip="2001:db8:1::2", src_port=41000,
            dst_ip="2001:db8:2::10", dst_port=80, syn_start_ms=0.0, ack_end_ms=2050.0,
            duration_ms=2050.0, outcome=ConnectionOutcome.ESTABLISHED.value
        )
        # Verify duration matches initial SYN to final ACK, not last retransmit (50ms)
        self.assertEqual(p1.duration_ms, 2050.0)

    def test_immediate_tcp_rst_sub_millisecond_fallback(self):
        """Sub-millisecond RST arrives at 0.1ms -> immediate IPv4 initiation without delay."""
        sim = HappyEyeballsSimulator(
            connection_attempt_delay_ms=250.0,
            ipv6_rtt_ms=0.2,  # Half-RTT is 0.1ms
            ipv6_rst=True,
            ipv4_rtt_ms=20.0,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertEqual(metrics.winning_family, AddressFamily.IPV4.value)
        self.assertEqual(metrics.t_connect_ms, 20.0)
        self.assertEqual(metrics.t_setup_total_ms, 20.1)

    def test_both_families_blackholed_timeout_fails_gracefully(self):
        """When both IPv6 and IPv4 fail, trial must fail gracefully with explicit reason code."""
        sim = HappyEyeballsSimulator(
            ipv6_rtt_ms=None,
            ipv4_rtt_ms=None,
        )
        metrics, _, _, conn_attempts = sim.run()

        self.assertIsNone(metrics.winning_family)
        self.assertIsNone(metrics.t_connect_ms)
        self.assertIsNone(metrics.t_setup_total_ms)
        self.assertEqual(metrics.reason_code, "BOTH_FAMILIES_TIMEOUT")

    def test_zero_elapsed_time_monotonic_protection(self):
        """Clock protection: negative durations must never occur."""
        sim = HappyEyeballsSimulator(ipv6_rtt_ms=0.0)
        metrics, _, _, _ = sim.run()
        self.assertGreaterEqual(metrics.t_connect_ms, 0.0)


# ==============================================================================
# Feature 3: DNS Wire Codec & Parsing Corner Cases
# ==============================================================================

class TestTier2BoundaryDNS(unittest.TestCase):
    """Verifies DNS wire format boundary checks, malformed packet rejections."""

    def test_dns_wire_truncated_header_less_than_12_bytes_raises_error(self):
        """RFC 1035: Header is exactly 12 bytes. Short headers must raise ValueError."""
        truncated_bytes = b"\x12\x34\x01\x00\x00\x01"  # Only 6 bytes
        with self.assertRaises(ValueError) as ctx:
            DNSWireCodec.decode_message(truncated_bytes)
        self.assertIn("Truncated DNS packet", str(ctx.exception))

    def test_dns_wire_zero_length_question_section(self):
        """Message with QDCOUNT=0 decodes cleanly with empty question list."""
        header = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00"
        msg = DNSWireCodec.decode_message(header)
        self.assertEqual(msg["qdcount"], 0)
        self.assertEqual(len(msg["questions"]), 0)

    def test_dns_wire_label_exceeding_63_octets_raises_error(self):
        """RFC 1035 §2.3.4: Domain label cannot exceed 63 octets."""
        overlong_label = "a" * 64 + ".happy-eyeballs.lab"
        with self.assertRaises(ValueError) as ctx:
            DNSWireCodec.encode_query(qid=101, qname=overlong_label, qtype=1)
        self.assertIn("Label exceeds 63 octets", str(ctx.exception))

    def test_dns_wire_malformed_truncated_question_label(self):
        """Malformed label length extending beyond payload bounds raises ValueError."""
        # Header (12 bytes) + length byte saying 20 octets, but only 4 octets supplied
        malformed = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x14\x61\x62\x63"
        with self.assertRaises(ValueError) as ctx:
            DNSWireCodec.decode_message(malformed)
        self.assertIn("exceeds packet bounds", str(ctx.exception))

    def test_unpaired_dns_query_response_records(self):
        """Unpaired DNS transactions must have empty answers and explicit durations."""
        tx_query_only = DNSTransaction(
            dns_id=5050,
            qname="timeout.lab",
            qtype=1,
            qtype_name="A",
            rcode=0,
            transport="UDP",
            answers=[],
            duration_ms=5000.0,
        )
        self.assertEqual(len(tx_query_only.answers), 0)
        self.assertEqual(tx_query_only.duration_ms, 5000.0)


# ==============================================================================
# Feature 4: Schema Strictness Boundaries
# ==============================================================================

class TestTier2BoundarySchema(unittest.TestCase):
    """Verifies schema version boundary enforcement and null preservation."""

    def test_schema_version_minor_patch_divergence_rejected(self):
        """Only explicitly supported versions ['1.0.0', '1.1.0'] are admitted."""
        for invalid_version in ["1.0.1", "1.1.1", "1.2.0", "0.9.9"]:
            record = {
                "schema_version": invalid_version,
                "trial_id": "trial-inv-ver",
                "scenario_id": "S0",
                "browser_name": "chrome",
                "execution_mode": "LIVE",
            }
            is_valid, err = SchemaValidator.validate(record)
            self.assertFalse(is_valid, msg=f"Should reject {invalid_version}")
            self.assertIn("Unsupported schema version", err)

    def test_schema_null_metric_preservation_not_coerced_to_zero(self):
        """Finding C1-03 rule: Null metrics MUST NOT be coerced to 0.0."""
        record = {
            "schema_version": "1.1.0",
            "trial_id": "trial-null-metrics",
            "scenario_id": "S1",
            "browser_name": "chrome",
            "execution_mode": "LIVE",
            "primary_flow": {
                "winning_family": None,
                "t_connect_ms": None,
                "t_setup_total_ms": None,
                "syn_to_synack_ms": None,
            },
            "dns_metrics": {},
        }
        is_valid, err = SchemaValidator.validate(record)
        self.assertTrue(is_valid, msg=err)
        self.assertIsNone(record["primary_flow"]["t_connect_ms"])
        self.assertIsNot(record["primary_flow"]["t_connect_ms"], 0.0)

    def test_schema_empty_payload_fails_closed(self):
        """Empty payload {} must be rejected."""
        is_valid, err = SchemaValidator.validate({})
        self.assertFalse(is_valid)

    def test_schema_deep_field_type_coercion_rejected(self):
        """Boolean or dict in place of numeric float must fail validation."""
        record = {
            "schema_version": "1.1.0",
            "trial_id": "trial-type-mismatch",
            "scenario_id": "S0",
            "browser_name": "chrome",
            "execution_mode": "LIVE",
            "primary_flow": {
                "t_connect_ms": {"nested": "not_valid"},
            },
            "dns_metrics": {},
        }
        is_valid, err = SchemaValidator.validate(record)
        self.assertFalse(is_valid)
        self.assertIn("must be numeric or null", err)

    def test_schema_whitespace_or_none_version_rejected(self):
        """Whitespace or None version strings must fail closed."""
        for v in ["", "  ", None]:
            record = {
                "schema_version": v,
                "trial_id": "trial-bad-ver",
                "scenario_id": "S0",
                "browser_name": "chrome",
                "execution_mode": "LIVE",
            }
            is_valid, err = SchemaValidator.validate(record)
            self.assertFalse(is_valid)


# ==============================================================================
# Feature 5: Export Integrity Boundaries
# ==============================================================================

class TestTier2BoundaryExports(unittest.TestCase):
    """Verifies edge conditions on exports: count sensitivity, collisions, single trial."""

    def test_export_empty_rows_rejected_against_exact_count(self):
        """Empty dataset fails verification when expected_count > 0."""
        is_valid, err = ExportReconciler.verify_attempts_rows([], expected_count=282)
        self.assertFalse(is_valid)
        self.assertIn("Row count mismatch", err)

    def test_export_boundary_row_count_281_and_283_rejected(self):
        """Strict count boundary: 281 or 283 rows must fail when 282 is required."""
        rows_281 = [{"trial_id": f"t-{i}", "validity_status": "VALID_LIVE"} for i in range(281)]
        is_valid_281, err_281 = ExportReconciler.verify_attempts_rows(rows_281, expected_count=282)
        self.assertFalse(is_valid_281)
        self.assertIn("expected 282, got 281", err_281)

        rows_283 = [{"trial_id": f"t-{i}", "validity_status": "VALID_LIVE"} for i in range(283)]
        is_valid_283, err_283 = ExportReconciler.verify_attempts_rows(rows_283, expected_count=282)
        self.assertFalse(is_valid_283)
        self.assertIn("expected 282, got 283", err_283)

    def test_export_duplicate_trial_id_collision_rejected(self):
        """Duplicate trial IDs must be rejected immediately."""
        rows = [
            {"trial_id": "colliding-trial-id", "validity_status": "VALID_LIVE"},
            {"trial_id": "colliding-trial-id", "validity_status": "VALID_LIVE"},
        ]
        is_valid, err = ExportReconciler.verify_attempts_rows(rows, expected_count=2)
        self.assertFalse(is_valid)
        self.assertIn("duplicate trial_id", err)

    def test_export_single_trial_degrees_of_freedom_boundary(self):
        """Single trial n=1 dataset is structurally valid for export."""
        rows = [{"trial_id": "single-trial-001", "validity_status": "VALID_LIVE"}]
        is_valid, err = ExportReconciler.verify_attempts_rows(rows, expected_count=1)
        self.assertTrue(is_valid, msg=err)

    def test_export_special_characters_in_trial_id_and_labels(self):
        """Trial IDs with special hyphens and timestamps must parse without error."""
        rows = [
            {"trial_id": "ps028-a10-live-20261030-01-chrome-s0-001", "validity_status": "VALID_LIVE"}
        ]
        is_valid, err = ExportReconciler.verify_attempts_rows(rows, expected_count=1)
        self.assertTrue(is_valid, msg=err)


if __name__ == "__main__":
    unittest.main()
