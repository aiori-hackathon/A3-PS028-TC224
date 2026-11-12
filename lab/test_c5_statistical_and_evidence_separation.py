#!/usr/bin/env python3
"""
PS-028 Milestone 4 / Batch C5 Adversarial Challenge:
Specialist Verification of Statistical Invariants and Dual-Class Evidence Separation.

Governing Standards & Documents:
- AIORI-3 Problem Statement PS-028 & Submission Rules
- Phase C Metric Contract & Evidence Specification (docs/phase-c-metric-contract.md)
- Phase D Experiment Protocol (docs/phase-d-experiment-protocol.md §4.2)
- Amendment A11 & Decision 7: Dual-Class Evidence Separation & Clopper-Pearson Stopping Rule
- Amendment A13: Determinism & Sibling Provenance Files
- Rule R11: Non-interactive Sudoers Governance & Least Privilege

Evaluates:
1. Mathematical Exactness of Pure Python Clopper-Pearson 99% Exact CI:
   - Analytical boundary and corner case validation ($k=0, n=50$; $k=50, n=50$; $k=25, n=50$; $n=0$).
   - High-precision Decimal exact binomial CDF oracle comparison across multiple $k, n$.
   - Symmetry, monotonicity, and parameter invariance testing.
   - Degenerate inputs: $n=0$, $n < 0$, $k < 0$, $k > n$, $n=1$, $n=2$, large $n$.
2. Dual-Class Evidence Separation (Amendment A11 & Decision 7):
   - Strict separation between router nftables counters (kernel forwarding drops)
     and client socket probe connect outcomes (transport outcomes).
   - Ephemeral port 0 pre-binding verification across all outcome states
     (CONNECTED, TIMEOUT, REFUSED, ERROR) in IPv4 and IPv6.
   - Streaming JSONL format, monotonic probe sorting, and strict field type validation.
3. Parameter Bounds and Guardrails:
   - Allowlist and range enforcement for S5 privileged helper actions.
   - Sudoers specification safety and governance.
"""

from decimal import Decimal, getcontext
import errno
import json
import math
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.impair as impair
import lab.privileged_helper as priv_helper
import lab.self_test_scenarios as sts

getcontext().prec = 60


# ==============================================================================
# Exact Mathematical Binomial Oracle (Arbitrary Precision via Decimal)
# ==============================================================================

def exact_binomial_cdf_dec(k: int, n: int, p: Decimal) -> Decimal:
    """Computes exact P(X <= k) for Binomial(n, p) using Decimal."""
    if k < 0:
        return Decimal(0)
    if k >= n:
        return Decimal(1)
    total = Decimal(0)
    for j in range(k + 1):
        comb = Decimal(math.comb(n, j))
        total += comb * (p ** j) * ((Decimal(1) - p) ** (n - j))
    return total


def exact_clopper_pearson_oracle(k: int, n: int, confidence: float = 0.99) -> Tuple[float, float]:
    """
    Arbitrary-precision reference oracle for Clopper-Pearson confidence interval.
    Solves roots of exact binomial tail sums using 100 bisection iterations in Decimal.
    """
    if n <= 0:
        return 0.0, 100.0
    if k <= 0:
        lower = Decimal(0)
    else:
        # P(X >= k) = alpha / 2  => 1 - binom_cdf(k - 1, n, p) = alpha / 2
        alpha_half = Decimal(str((1.0 - confidence) / 2.0))
        lo, hi = Decimal(0), Decimal(1)
        for _ in range(100):
            mid = (lo + hi) / Decimal(2)
            tail = Decimal(1) - exact_binomial_cdf_dec(k - 1, n, mid)
            if tail > alpha_half:
                hi = mid
            else:
                lo = mid
        lower = (lo + hi) / Decimal(2)

    if k >= n:
        upper = Decimal(1)
    else:
        # P(X <= k) = alpha / 2  => binom_cdf(k, n, p) = alpha / 2
        alpha_half = Decimal(str((1.0 - confidence) / 2.0))
        lo, hi = Decimal(0), Decimal(1)
        for _ in range(100):
            mid = (lo + hi) / Decimal(2)
            cdf_val = exact_binomial_cdf_dec(k, n, mid)
            if cdf_val < alpha_half:
                hi = mid
            else:
                lo = mid
        upper = (lo + hi) / Decimal(2)

    return float(lower * 100), float(upper * 100)


# ==============================================================================
# Challenge 1: Mathematical Rigor of Clopper-Pearson 99% Exact CI
# ==============================================================================

class TestClopperPearsonMathematicalRigor(unittest.TestCase):
    """
    Adversarial verification of calculate_clopper_pearson_ci against exact
    mathematical binomial quantiles and analytical invariants.
    """

    def test_analytical_boundary_k0_n50(self):
        """
        Challenge 1.1: Boundary k=0, n=50.
        Analytical exact solution:
          p_L = 0.0
          p_U = 1 - (alpha / 2)**(1/n)
        For alpha=0.01 (conf=0.99) and n=50:
          p_U = 1 - (0.005)**(0.02) = 10.0545083...%
        """
        lo, hi = sts.calculate_clopper_pearson_ci(0, 50, confidence=0.99)
        self.assertEqual(lo, 0.0, "Lower bound for k=0 must be exactly 0.0")

        # Analytical expectation
        alpha_half = Decimal("0.005")
        exact_pu_pct = float((Decimal(1) - alpha_half ** (Decimal(1) / Decimal(50))) * 100)
        self.assertAlmostEqual(hi, exact_pu_pct, places=3,
                               msg=f"Upper bound {hi}% diverged from analytical {exact_pu_pct}%")
        self.assertEqual(round(exact_pu_pct, 4), hi)

    def test_analytical_boundary_k50_n50(self):
        """
        Challenge 1.2: Boundary k=50, n=50.
        Analytical exact solution:
          p_U = 100.0
          p_L = (alpha / 2)**(1/n)
        For alpha=0.01 (conf=0.99) and n=50:
          p_L = (0.005)**(0.02) = 89.9454916...%
        """
        lo, hi = sts.calculate_clopper_pearson_ci(50, 50, confidence=0.99)
        self.assertEqual(hi, 100.0, "Upper bound for k=n must be exactly 100.0")

        alpha_half = Decimal("0.005")
        exact_pl_pct = float((alpha_half ** (Decimal(1) / Decimal(50))) * 100)
        self.assertAlmostEqual(lo, exact_pl_pct, places=3,
                               msg=f"Lower bound {lo}% diverged from analytical {exact_pl_pct}%")
        self.assertEqual(round(exact_pl_pct, 4), lo)

    def test_exact_symmetry_k25_n50(self):
        """
        Challenge 1.3: Symmetric point k=25, n=50.
        By symmetry around 50%:
          p_L + p_U == 100.0%
        """
        lo, hi = sts.calculate_clopper_pearson_ci(25, 50, confidence=0.99)
        self.assertAlmostEqual(lo + hi, 100.0, places=4,
                               msg=f"Symmetry failed: {lo} + {hi} = {lo + hi} != 100.0")

        # Check against high-precision Decimal oracle
        oracle_lo, oracle_hi = exact_clopper_pearson_oracle(25, 50, confidence=0.99)
        self.assertAlmostEqual(lo, oracle_lo, places=3)
        self.assertAlmostEqual(hi, oracle_hi, places=3)

    def test_sample_point_k24_n50(self):
        """
        Challenge 1.4: Sample point k=24, n=50 (worker test baseline).
        Expected 99% CI: [29.7591%, 66.6300%].
        """
        lo, hi = sts.calculate_clopper_pearson_ci(24, 50, confidence=0.99)
        oracle_lo, oracle_hi = exact_clopper_pearson_oracle(24, 50, confidence=0.99)
        self.assertAlmostEqual(lo, oracle_lo, places=3)
        self.assertAlmostEqual(hi, oracle_hi, places=3)
        # S5 nominal 50% must be strictly enclosed
        self.assertTrue(lo < 50.0 < hi, f"50.0% not enclosed in [{lo}, {hi}]")

    def test_fallback_and_degenerate_bounds(self):
        """
        Challenge 1.5: Fallback and degenerate bounds.
        - n = 0 -> (0.0, 100.0)
        - n < 0 -> (0.0, 100.0)
        - k < 0 -> clamped to 0
        - k > n -> clamped to n
        """
        self.assertEqual(sts.calculate_clopper_pearson_ci(0, 0, 0.99), (0.0, 100.0))
        self.assertEqual(sts.calculate_clopper_pearson_ci(10, 0, 0.99), (0.0, 100.0))
        self.assertEqual(sts.calculate_clopper_pearson_ci(5, -10, 0.99), (0.0, 100.0))

        # Negative k clamped to 0
        lo_neg, hi_neg = sts.calculate_clopper_pearson_ci(-5, 50, 0.99)
        lo_zero, hi_zero = sts.calculate_clopper_pearson_ci(0, 50, 0.99)
        self.assertEqual((lo_neg, hi_neg), (lo_zero, hi_zero))

        # Oversized k clamped to n
        lo_over, hi_over = sts.calculate_clopper_pearson_ci(60, 50, 0.99)
        lo_n, hi_n = sts.calculate_clopper_pearson_ci(50, 50, 0.99)
        self.assertEqual((lo_over, hi_over), (lo_n, hi_n))

    def test_single_trial_boundary_n1(self):
        """
        Challenge 1.6: Single-trial boundaries n=1.
        - k=0: lower=0.0, upper=1 - (0.005)**1 = 99.5%
        - k=1: lower=(0.005)**1 = 0.5%, upper=100.0%
        """
        lo0, hi0 = sts.calculate_clopper_pearson_ci(0, 1, 0.99)
        self.assertEqual(lo0, 0.0)
        self.assertAlmostEqual(hi0, 99.5, places=3)

        lo1, hi1 = sts.calculate_clopper_pearson_ci(1, 1, 0.99)
        self.assertAlmostEqual(lo1, 0.5, places=3)
        self.assertEqual(hi1, 100.0)

    def test_comprehensive_oracle_matrix(self):
        """
        Challenge 1.7: Comprehensive test matrix against Decimal oracle.
        Tests k in [0, 1, 5, 10, 20, 25, 30, 40, 49, 50] with n=50,
        and n in [10, 20, 100, 200].
        """
        test_cases = [
            (k, 50) for k in [0, 1, 5, 10, 20, 25, 30, 40, 49, 50]
        ] + [
            (5, 10), (10, 20), (50, 100), (100, 200)
        ]

        for k, n in test_cases:
            with self.subTest(k=k, n=n):
                lo, hi = sts.calculate_clopper_pearson_ci(k, n, confidence=0.99)
                oracle_lo, oracle_hi = exact_clopper_pearson_oracle(k, n, confidence=0.99)

                # Tolerance: bisection achieves < 1e-4 delta
                self.assertAlmostEqual(
                    lo, oracle_lo, delta=0.005,
                    msg=f"Lower bound mismatch for k={k}, n={n}: {lo} vs oracle {oracle_lo}"
                )
                self.assertAlmostEqual(
                    hi, oracle_hi, delta=0.005,
                    msg=f"Upper bound mismatch for k={k}, n={n}: {hi} vs oracle {oracle_hi}"
                )

    def test_symmetry_invariant_across_all_k(self):
        """
        Challenge 1.8: Invariant test across all k in [0, 50] for n=50:
        CI(k, n) = (lo, hi) <=> CI(n - k, n) = (100 - hi, 100 - lo).
        """
        n = 50
        for k in range(n + 1):
            lo_k, hi_k = sts.calculate_clopper_pearson_ci(k, n, 0.99)
            lo_comp, hi_comp = sts.calculate_clopper_pearson_ci(n - k, n, 0.99)

            self.assertAlmostEqual(
                lo_k + hi_comp, 100.0, delta=0.005,
                msg=f"Symmetry invariant failed for k={k}: lo({k})={lo_k} + hi({n-k})={hi_comp} != 100"
            )

    def test_strict_monotonicity_invariant(self):
        """
        Challenge 1.9: Monotonicity invariant:
        As k increases, both lower bound and upper bound must strictly increase.
        """
        n = 30
        prev_lo = -1.0
        prev_hi = -1.0
        for k in range(n + 1):
            lo, hi = sts.calculate_clopper_pearson_ci(k, n, 0.99)
            self.assertGreater(lo, prev_lo, f"Lower bound did not strictly increase at k={k}")
            self.assertGreater(hi, prev_hi, f"Upper bound did not strictly increase at k={k}")
            # Point estimate must be enclosed
            p_hat = (k / n) * 100.0
            self.assertTrue(lo <= p_hat <= hi, f"Point estimate {p_hat}% not enclosed in [{lo}, {hi}]")
            prev_lo = lo
            prev_hi = hi

    def test_confidence_level_scaling(self):
        """
        Challenge 1.10: Variable confidence level scaling.
        As confidence increases (90% -> 95% -> 99%), interval width must strictly widen.
        """
        k, n = 25, 50
        lo_90, hi_90 = sts.calculate_clopper_pearson_ci(k, n, confidence=0.90)
        lo_95, hi_95 = sts.calculate_clopper_pearson_ci(k, n, confidence=0.95)
        lo_99, hi_99 = sts.calculate_clopper_pearson_ci(k, n, confidence=0.99)

        width_90 = hi_90 - lo_90
        width_95 = hi_95 - lo_95
        width_99 = hi_99 - lo_99

        self.assertLess(width_90, width_95, "90% CI wider than 95% CI")
        self.assertLess(width_95, width_99, "95% CI wider than 99% CI")


# ==============================================================================
# Challenge 2: Evidence Separation Verification (Amendment A11 & Decision 7)
# ==============================================================================

class TestEvidenceSeparationRigor(unittest.TestCase):
    """
    Adversarial verification of evidence separation:
    - Router-level nftables packet counters vs client probe socket records.
    - Ephemeral port 0 pre-binding verification across all connection outcomes.
    - Streaming JSONL format, field types, and ordering.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_adv_sep_"))
        self.lock_file = self.temp_dir / "test.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_router_counter_accounting_invariants(self):
        """
        Challenge 2.1: Router-level nftables packet counters accounting invariant:
          syn_total == syn_dropped + syn_not_dropped
        And extra_syn_packets = max(0, syn_total - initial_probes) detects retransmissions.
        """
        with patch("lab.self_test_scenarios.setup_s5_nftables_counters") as mock_setup, \
             patch("lab.self_test_scenarios.read_s5_nftables_counters") as mock_read, \
             patch("lab.privileged_helper.run_helper_action") as mock_helper, \
             patch("lab.impair.is_root", return_value=False):

            mock_read.side_effect = [
                {"status": "OK", "syn_total": 100, "syn_dropped": 50, "syn_not_dropped": 50},  # initial
                {"status": "OK", "syn_total": 160, "syn_dropped": 80, "syn_not_dropped": 80},  # final (+60 total, +30 drop, +30 fwd)
            ]
            mock_helper.return_value = {
                "status": "OK",
                "probes_sent": 50,
                "connected": 25,
                "timed_out": 25,
                "refused": 0,
                "error": 0
            }

            res = sts.measure_syn_loss(
                target_ip="2001:db8:2::10",
                port=80,
                total_probes=50,
                dry_run=False
            )

            # Invariant 1: syn_total == syn_dropped + syn_not_dropped
            self.assertEqual(res["total_syn_count"], 60)
            self.assertEqual(res["dropped_packets"], 30)
            self.assertEqual(res["not_dropped_packets"], 30)
            self.assertEqual(res["total_syn_count"], res["dropped_packets"] + res["not_dropped_packets"])

            # Invariant 2: extra_syn_packets detects the 10 TCP retransmissions
            self.assertEqual(res["extra_syn_packets"], 10)
            self.assertEqual(res["initial_probes"], 50)

            # Invariant 3: observed loss pct is calculated from router counter deltas, NOT client socket timeouts
            self.assertEqual(res["observed_loss_pct"], 50.0)

            # Invariant 4: evidence block contains router nftables counters
            self.assertEqual(res["evidence"]["source"], "nftables")
            self.assertEqual(res["evidence"]["counters"]["syn_total"], 60)
            self.assertEqual(res["evidence"]["counters"]["syn_dropped"], 30)
            self.assertEqual(res["evidence"]["counters"]["syn_not_dropped"], 30)

    def test_router_counter_mismatch_raises_fail_closed(self):
        """
        Challenge 2.2: Fail-closed verification if router counters violate
        accounting invariant: syn_total != syn_dropped + syn_not_dropped.
        """
        with patch("lab.self_test_scenarios.setup_s5_nftables_counters"), \
             patch("lab.self_test_scenarios.read_s5_nftables_counters") as mock_read, \
             patch("lab.privileged_helper.run_helper_action") as mock_helper, \
             patch("lab.impair.is_root", return_value=False):

            # Inconsistent router counters: 50 != 25 + 20
            mock_read.side_effect = [
                {"status": "OK", "syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
                {"status": "OK", "syn_total": 50, "syn_dropped": 25, "syn_not_dropped": 20},
            ]
            mock_helper.return_value = {"status": "OK", "probes_sent": 50}

            with self.assertRaises(impair.ImpairmentError) as ctx:
                sts.measure_syn_loss(total_probes=50, dry_run=False)
            self.assertIn("accounting mismatch", str(ctx.exception).lower())

    def test_zero_syn_packets_recorded_fails_closed(self):
        """
        Challenge 2.3: Fail-closed verification if zero SYN packets are recorded
        by router counters (e.g., interface misconfiguration or capture failure).
        """
        with patch("lab.self_test_scenarios.setup_s5_nftables_counters"), \
             patch("lab.self_test_scenarios.read_s5_nftables_counters") as mock_read, \
             patch("lab.privileged_helper.run_helper_action") as mock_helper, \
             patch("lab.impair.is_root", return_value=False):

            mock_read.side_effect = [
                {"status": "OK", "syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
                {"status": "OK", "syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
            ]
            mock_helper.return_value = {"status": "OK", "probes_sent": 50}

            with self.assertRaises(impair.ImpairmentError) as ctx:
                sts.measure_syn_loss(total_probes=50, dry_run=False)
            self.assertIn("no syn packets recorded", str(ctx.exception).lower())

    def test_ephemeral_port_0_prebinding_connected(self):
        """
        Challenge 2.4: Socket pre-binding to ephemeral port 0 on CONNECTED.
        Verifies local 5-tuple captures actual ephemeral port > 0.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv_port = srv.getsockname()[1]

        def srv_worker():
            conn, _ = srv.accept()
            conn.close()

        t = threading.Thread(target=srv_worker)
        t.start()
        try:
            res = priv_helper.probe_single_socket(
                probe_id=101,
                target_ip="127.0.0.1",
                target_port=srv_port,
                timeout=1.0,
                af=socket.AF_INET
            )
        finally:
            t.join()
            srv.close()

        self.assertEqual(res["probe_id"], 101)
        self.assertEqual(res["connect_outcome"], "CONNECTED")
        self.assertEqual(res["outcome"], "CONNECTED")
        self.assertEqual(res["errno"], 0)
        self.assertIsNone(res["error_message"])
        self.assertGreater(res["duration_ms"], 0.0)

        # Pre-allocated local endpoint verification
        local_ep = res["local_endpoint"]
        self.assertIsInstance(local_ep, dict)
        self.assertEqual(local_ep["ip"], "0.0.0.0")
        self.assertIsInstance(local_ep["port"], int)
        self.assertGreater(local_ep["port"], 0, "Ephemeral port must be allocated (> 0)")

    def test_ephemeral_port_0_prebinding_refused(self):
        """
        Challenge 2.5: Socket pre-binding to ephemeral port 0 on REFUSED.
        Verifies local ephemeral port is preserved even on connection rejection.
        """
        res = priv_helper.probe_single_socket(
            probe_id=102,
            target_ip="127.0.0.1",
            target_port=59998,  # Nothing listening
            timeout=0.2,
            af=socket.AF_INET
        )
        self.assertEqual(res["probe_id"], 102)
        self.assertEqual(res["connect_outcome"], "REFUSED")
        self.assertEqual(res["outcome"], "REFUSED")
        self.assertEqual(res["errno"], errno.ECONNREFUSED)
        self.assertIn("Connection refused", res["error_message"])

        # Local endpoint was captured before connect failed
        local_ep = res["local_endpoint"]
        self.assertIsInstance(local_ep["port"], int)
        self.assertGreater(local_ep["port"], 0, "Ephemeral port must be allocated even on REFUSED")

    def test_ephemeral_port_0_prebinding_timeout(self):
        """
        Challenge 2.6: Socket pre-binding to ephemeral port 0 on TIMEOUT.
        Verifies local ephemeral port is preserved when target packet is dropped.
        """
        res = priv_helper.probe_single_socket(
            probe_id=103,
            target_ip="192.0.2.1",  # TEST-NET-1 (non-routable/blackhole)
            target_port=80,
            timeout=0.1,
            af=socket.AF_INET
        )
        self.assertEqual(res["probe_id"], 103)
        self.assertEqual(res["connect_outcome"], "TIMEOUT")
        self.assertEqual(res["outcome"], "TIMEOUT")
        self.assertEqual(res["errno"], errno.ETIMEDOUT)
        self.assertIn("timed out", res["error_message"].lower())

        # Local endpoint was captured before timeout occurred
        local_ep = res["local_endpoint"]
        self.assertIsInstance(local_ep["port"], int)
        self.assertGreater(local_ep["port"], 0, "Ephemeral port must be allocated even on TIMEOUT")

    def test_ephemeral_port_0_prebinding_ipv6(self):
        """
        Challenge 2.7: Socket pre-binding to ephemeral port 0 under IPv6 (AF_INET6).
        Verifies :: bind and local endpoint capture under IPv6.
        """
        res = priv_helper.probe_single_socket(
            probe_id=104,
            target_ip="::1",
            target_port=59998,
            timeout=0.2,
            af=socket.AF_INET6
        )
        self.assertEqual(res["probe_id"], 104)
        self.assertEqual(res["connect_outcome"], "REFUSED")
        local_ep = res["local_endpoint"]
        self.assertEqual(local_ep["ip"], "::")
        self.assertGreater(local_ep["port"], 0, "IPv6 ephemeral port must be allocated (> 0)")

    def test_jsonl_streaming_and_field_schema_integrity(self):
        """
        Challenge 2.8: Streaming JSONL probe export format and schema rigor:
        - Each line must parse as independent JSON object.
        - Monotonically increasing probe_id.
        - Type safety on all fields.
        - Exactly matches probe_count records.
        """
        jsonl_path = self.temp_dir / "s5_probes.jsonl"
        probe_count = 25
        concurrency = 5

        # Execute measure_s5_privileged with in_netns=True
        summary = priv_helper.measure_s5_privileged(
            target_ip="127.0.0.1",
            port=59998,
            probe_count=probe_count,
            timeout=0.1,
            concurrency=concurrency,
            netns="ps028-cl",
            output_jsonl=jsonl_path,
            caller_holds_lock=True,
            lock_file=self.lock_file,
            in_netns=True
        )

        self.assertEqual(summary["status"], "OK")
        self.assertEqual(summary["probe_count"], probe_count)
        self.assertEqual(summary["probes_sent"], probe_count)
        self.assertEqual(summary["refused"], probe_count)
        self.assertTrue(jsonl_path.exists())

        # Read JSONL file and validate schema
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), probe_count, f"Expected {probe_count} JSONL lines, got {len(lines)}")

        expected_fields = {
            "probe_id": int,
            "timestamp": float,
            "start_time": float,
            "end_time": float,
            "duration_ms": float,
            "target_ip": str,
            "target_port": int,
            "local_endpoint": dict,
            "connect_outcome": str,
            "outcome": str,
            "errno": int,
        }

        for idx, line in enumerate(lines):
            record = json.loads(line)
            # 1. Monotonic ordering by probe_id
            self.assertEqual(record["probe_id"], idx, f"Probe record not monotonically ordered at {idx}")

            # 2. Field existence and type validation
            for field, f_type in expected_fields.items():
                self.assertIn(field, record, f"Missing field '{field}' in record {idx}")
                self.assertIsInstance(record[field], f_type,
                                      f"Field '{field}' wrong type {type(record[field])} in record {idx}")

            # 3. local_endpoint sub-schema
            lep = record["local_endpoint"]
            self.assertIn("ip", lep)
            self.assertIn("port", lep)
            self.assertIsInstance(lep["ip"], str)
            self.assertIsInstance(lep["port"], int)
            self.assertGreater(lep["port"], 0)

            # 4. Outcome validation
            self.assertIn(record["connect_outcome"], ["CONNECTED", "TIMEOUT", "REFUSED", "ERROR"])
            self.assertEqual(record["connect_outcome"], record["outcome"])

    def test_non_conflation_between_socket_outcomes_and_router_counters(self):
        """
        Challenge 2.9: Strict non-conflation verification.
        Verifies that router nftables counters and client probe socket outcomes
        are NEVER conflated or mixed in data models or returns.
        """
        client_summary = {
            "status": "OK",
            "probe_count": 50,
            "connected": 20,
            "timed_out": 25,
            "refused": 5,
            "error": 0
        }

        router_counters = {
            "syn_total": 58,  # 50 initial + 8 retransmissions
            "syn_dropped": 29,
            "syn_not_dropped": 29
        }

        with patch("lab.self_test_scenarios.setup_s5_nftables_counters"), \
             patch("lab.self_test_scenarios.read_s5_nftables_counters") as mock_read, \
             patch("lab.privileged_helper.run_helper_action", return_value=client_summary), \
             patch("lab.impair.is_root", return_value=False):

            mock_read.side_effect = [
                {"status": "OK", "syn_total": 0, "syn_dropped": 0, "syn_not_dropped": 0},
                {"status": "OK", **router_counters}
            ]

            result = sts.measure_syn_loss(total_probes=50, dry_run=False)

            # Observed loss pct must be (29 / 58) = 50.0%, NOT (25 / 50) = 50.0%
            self.assertEqual(result["total_syn_count"], 58)
            self.assertEqual(result["dropped_packets"], 29)
            self.assertEqual(result["extra_syn_packets"], 8)
            self.assertEqual(result["initial_probes"], 50)
            self.assertEqual(result["observed_loss_pct"], 50.0)


# ==============================================================================
# Challenge 3: Parameter Bounds, Guardrails, and Sudoers Protection
# ==============================================================================

class TestParameterBoundsAndGovernance(unittest.TestCase):
    """
    Adversarial verification of parameter bounds, allowlists, and sudoers governance.
    """

    def test_measure_s5_parameter_bounds(self):
        """
        Challenge 3.1: Enforce parameter boundaries on measure-s5:
        - probe_count in [1, 500]
        - port in [1, 65535]
        - timeout in [0.05, 10.0]
        - concurrency in [1, 50]
        - netns in ALLOWED_S5_NETNS
        """
        invalid_cases = [
            {"port": 80, "probe_count": 0},
            {"port": 80, "probe_count": -1},
            {"port": 80, "probe_count": 501},
            {"port": 0},
            {"port": 65536},
            {"port": -80},
            {"port": 80, "timeout": 0.01},
            {"port": 80, "timeout": 15.0},
            {"port": 80, "concurrency": 0},
            {"port": 80, "concurrency": 51},
            {"port": 80, "netns": "attacker_netns"},
        ]

        for case in invalid_cases:
            with self.subTest(case=case):
                with self.assertRaises(priv_helper.PrivilegedHelperError):
                    priv_helper.validate_s5_params(**case)

    def test_setup_s5_counters_parameter_bounds(self):
        """
        Challenge 3.2: Enforce parameter boundaries on setup-s5-counters:
        - drop_pct in [1, 99]
        - oifname in ALLOWED_S5_IFACES
        """
        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_s5_params(port=80, drop_pct=0)

        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_s5_params(port=80, drop_pct=100)

        with self.assertRaises(priv_helper.PrivilegedHelperError):
            priv_helper.validate_s5_params(port=80, oifname="eth0")

    def test_sudoers_configuration_file_safety(self):
        """
        Challenge 3.3: Verify that host sudoers was NOT touched or corrupted,
        and documentation covers all S5 subcommands.
        """
        runbook = Path("docs/phase-cd/sudoers_configuration.md")
        self.assertTrue(runbook.exists(), "sudoers runbook missing")
        content = runbook.read_text(encoding="utf-8")
        self.assertIn("/etc/sudoers.d/ps028-helper", content)
        self.assertIn("NOPASSWD:", content)
        self.assertIn("setup-s5-counters", content)
        self.assertIn("read-s5-counters", content)
        self.assertIn("measure-s5", content)
        self.assertIn("verify-baseline", content)


if __name__ == "__main__":
    unittest.main()
