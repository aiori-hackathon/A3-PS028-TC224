#!/usr/bin/env python3
"""
Unit and Regression Test Suite for PS-028 Scientific Campaign Comparison Pipeline
Work Package I: Scientific Comparison Pipeline

Tests statistical routines (Wilson CIs, bootstrap median CIs),
cohort classification rules, and end-to-end comparison against synthetic campaigns.
"""

from pathlib import Path
import tempfile
import unittest

from lab import compare_campaigns
from lab.test_verify_partner_handover import make_synthetic_campaign


class TestStatisticalRoutines(unittest.TestCase):
    """Tests deterministic pure-Python statistical calculations."""

    def test_compute_percentile_and_median(self):
        vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        med = compare_campaigns.compute_median(vals)
        self.assertEqual(med, 30.0)

        q1 = compare_campaigns.compute_percentile(vals, 25.0)
        q3 = compare_campaigns.compute_percentile(vals, 75.0)
        self.assertEqual(q1, 20.0)
        self.assertEqual(q3, 40.0)

        iqr = compare_campaigns.compute_iqr(vals)
        self.assertEqual(iqr, 20.0)

    def test_wilson_score_interval(self):
        # 20 out of 20 IPv6 wins
        p, low, high = compare_campaigns.compute_wilson_ci(20, 20)
        self.assertEqual(p, 1.0)
        self.assertGreater(low, 0.8)
        self.assertLessEqual(high, 1.0)

        # 10 out of 20 (p = 0.50)
        p50, low50, high50 = compare_campaigns.compute_wilson_ci(10, 20)
        self.assertEqual(p50, 0.5)
        self.assertLess(low50, 0.5)
        self.assertGreater(high50, 0.5)

        # Zero sample
        pz, lz, hz = compare_campaigns.compute_wilson_ci(0, 0)
        self.assertEqual(pz, 0.0)

    def test_wilson_score_interval_99_pct_synthetic_fixtures(self):
        """
        Validate Wilson 99% confidence interval against known synthetic statistical fixtures.
        (Fixture labels: synthetic binomial trials k/n, non-seeded, analytical score test inversion).
        """
        # Synthetic fixture 1: S5 50% loss trial cohort (k=10, n=20, confidence=0.99)
        p, low99, high99 = compare_campaigns.compute_wilson_ci(10, 20, confidence=0.99)
        self.assertEqual(p, 0.5)
        self.assertAlmostEqual(low99, 0.2504, places=3)
        self.assertAlmostEqual(high99, 0.7496, places=3)

        # Synthetic fixture 2: Unanimous cohort (k=20, n=20, confidence=0.99)
        p20, low99_20, high99_20 = compare_campaigns.compute_wilson_ci(20, 20, confidence=0.99)
        self.assertEqual(p20, 1.0)
        self.assertAlmostEqual(low99_20, 0.7509, places=3)
        self.assertEqual(high99_20, 1.0)

        # Synthetic fixture 3: Zero success cohort (k=0, n=20, confidence=0.99)
        p0, low99_0, high99_0 = compare_campaigns.compute_wilson_ci(0, 20, confidence=0.99)
        self.assertEqual(p0, 0.0)
        self.assertEqual(low99_0, 0.0)
        self.assertAlmostEqual(high99_0, 0.2491, places=3)

        # Monotonicity check: 99% CI must be strictly wider than 95% CI
        _, low95, high95 = compare_campaigns.compute_wilson_ci(10, 20, confidence=0.95)
        self.assertLess(low99, low95)
        self.assertGreater(high99, high95)

    def test_bootstrap_median_confidence_interval(self):
        vals = [20.0, 20.5, 21.0, 21.5, 22.0, 22.5, 23.0]
        low, high = compare_campaigns.compute_bootstrap_median_ci(vals, iterations=200, seed=42)
        self.assertIsNotNone(low)
        self.assertIsNotNone(high)
        self.assertLessEqual(low, high)
        self.assertGreaterEqual(low, 20.0)
        self.assertLessEqual(high, 23.0)

    def test_two_sample_bootstrap_median_ci(self):
        # Two identical samples must have median difference near 0
        s1 = [20.0, 20.5, 21.0, 21.5, 22.0] * 4
        s2 = [20.0, 20.5, 21.0, 21.5, 22.0] * 4
        diff, low, high = compare_campaigns.compute_two_sample_bootstrap_median_ci(s1, s2, iterations=500, seed=42)
        self.assertEqual(diff, 0.0)
        self.assertLess(low, 1.0)
        self.assertGreater(high, -1.0)

        # Shifted sample (s2 shifted by +15ms)
        s3 = [v + 15.0 for v in s1]
        diff15, low15, high15 = compare_campaigns.compute_two_sample_bootstrap_median_ci(s1, s3, iterations=500, seed=42)
        self.assertEqual(diff15, 15.0)
        self.assertGreater(low15, 13.0)
        self.assertLess(high15, 17.0)

    def test_agresti_caffo_diff_ci(self):
        # Unanimous cohorts (zero sample variance)
        d0, l0, h0 = compare_campaigns.compute_agresti_caffo_diff_ci(20, 20, 20, 20)
        self.assertEqual(d0, 0.0)
        self.assertEqual(l0, 0.0)
        self.assertEqual(h0, 0.0)

        # Divergent cohorts (100% vs 0%)
        d_div, l_div, h_div = compare_campaigns.compute_agresti_caffo_diff_ci(20, 20, 0, 20)
        self.assertEqual(d_div, -1.0)
        self.assertLess(h_div, -0.7)

        # 50% vs 50%
        d50, l50, h50 = compare_campaigns.compute_agresti_caffo_diff_ci(10, 20, 10, 20)
        self.assertEqual(d50, 0.0)
        self.assertAlmostEqual(l50, -0.248, places=2)
        self.assertAlmostEqual(h50, 0.248, places=2)


class TestCohortEvaluation(unittest.TestCase):
    """Tests scientific replication classification rules across scenarios."""

    def test_replicated_cohort_classification(self):
        base_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.5, "iqr": 1.2, "ci_95": (20.0, 21.0)},
            "winning_family": {"ipv6_count": 20, "ipv4_count": 0, "ipv6_proportion": 1.0, "ipv6_wilson_ci_95": (0.83, 1.0)}
        }
        part_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.8, "iqr": 1.5, "ci_95": (20.1, 21.3)},
            "winning_family": {"ipv6_count": 20, "ipv4_count": 0, "ipv6_proportion": 1.0, "ipv6_wilson_ci_95": (0.83, 1.0)}
        }
        res = compare_campaigns.evaluate_cohort("S0", "google-chrome", base_stats, part_stats)
        self.assertEqual(res["classification"], "REPLICATED")

    def test_systematic_shift_cohort_classification(self):
        base_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.0, "iqr": 1.0, "ci_95": (19.5, 20.5)},
            "winning_family": {"ipv6_count": 20, "ipv4_count": 0, "ipv6_proportion": 1.0, "ipv6_wilson_ci_95": (0.83, 1.0)}
        }
        part_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 35.0, "iqr": 2.0, "ci_95": (34.0, 36.0)},
            "winning_family": {"ipv6_count": 20, "ipv4_count": 0, "ipv6_proportion": 1.0, "ipv6_wilson_ci_95": (0.83, 1.0)}
        }
        res = compare_campaigns.evaluate_cohort("S0", "google-chrome", base_stats, part_stats)
        self.assertEqual(res["classification"], "SYSTEMATIC_SHIFT")

    def test_behavioral_divergence_in_s1_fallback(self):
        base_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.0, "iqr": 1.0, "ci_95": (19.5, 20.5)},
            "winning_family": {"ipv6_count": 0, "ipv4_count": 20, "ipv6_proportion": 0.0, "ipv6_wilson_ci_95": (0.0, 0.17)}
        }
        part_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.0, "iqr": 1.0, "ci_95": (19.5, 20.5)},
            "winning_family": {"ipv6_count": 5, "ipv4_count": 15, "ipv6_proportion": 0.25, "ipv6_wilson_ci_95": (0.11, 0.47)}
        }
        res = compare_campaigns.evaluate_cohort("S1", "google-chrome", base_stats, part_stats)
        self.assertEqual(res["classification"], "BEHAVIORAL_DIVERGENCE")

    def test_inconclusive_cohort_on_extreme_variance(self):
        base_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.0, "iqr": 1.0, "ci_95": (19.5, 20.5)},
            "winning_family": {"ipv6_count": 20, "ipv4_count": 0, "ipv6_proportion": 1.0, "ipv6_wilson_ci_95": (0.83, 1.0)}
        }
        part_stats = {
            "trial_count": 20,
            "t_connect_ms": {"median": 20.0, "iqr": 95.0, "ci_95": (10.0, 110.0)},
            "winning_family": {"ipv6_count": 20, "ipv4_count": 0, "ipv6_proportion": 1.0, "ipv6_wilson_ci_95": (0.83, 1.0)}
        }
        res = compare_campaigns.evaluate_cohort("S0", "google-chrome", base_stats, part_stats)
        self.assertEqual(res["classification"], "INCONCLUSIVE")


class TestEndToEndComparison(unittest.TestCase):
    """Tests end-to-end campaign comparison against generated synthetic campaigns."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_comp_test_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_compare_identical_campaigns_yields_replicated(self):
        camp1 = make_synthetic_campaign(self.temp_dir, campaign_id="camp1", repetitions=20)
        camp2 = make_synthetic_campaign(self.temp_dir, campaign_id="camp2", repetitions=20)

        report = compare_campaigns.compare_campaigns(camp1, camp2)
        self.assertIn("overall_classification", report)
        self.assertEqual(len(report["cohort_evaluations"]), 14)
        self.assertIn(report["overall_classification"], ("REPLICATED", "SYSTEMATIC_SHIFT"))

        md = compare_campaigns.format_markdown_report(report)
        self.assertIn("PS-028 Happy Eyeballs: Campaign Comparison & Replication Report", md)
        self.assertIn("| Scenario | Browser |", md)


if __name__ == "__main__":
    unittest.main()
