#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Demonstration Bundle Builder Tests
Verifies authoritative reconciliation, byte-identical determinism, canonical metric
naming, JSON numeric preservation, and Phase D simulation exclusion.
"""

import json
from pathlib import Path
import tempfile
import unittest

from lab.build_demo_bundle import (
    DEFAULT_CAMPAIGN_DIR,
    DEFAULT_PHASE_C_DIR,
    EXPECTED_ATTEMPTS_COUNT,
    EXPECTED_VALID_LIVE_COUNT,
    EXPECTED_EXCLUSIONS_COUNT,
    EXPECTED_TCP_FLOWS_COUNT,
    EXPECTED_S5_FLOWS_COUNT,
    EXPECTED_TIMELINE_EVENTS_COUNT,
    EXPECTED_COHORTS_COUNT,
    EXPECTED_TRIALS_PER_COHORT,
    build_demonstration_bundle,
    compute_sha256,
)


class TestDemoBundleBuilder(unittest.TestCase):
    """Test suite for lab/build_demo_bundle.py."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.output_dir = Path(cls.temp_dir.name)
        cls.bundle_file, cls.prov_file, cls.reg_file = build_demonstration_bundle(
            campaign_dir=DEFAULT_CAMPAIGN_DIR,
            phase_c_dir=DEFAULT_PHASE_C_DIR,
            output_dir=cls.output_dir,
            commit_sha_override="testcommit1234567890abcdef",
        )
        with open(cls.bundle_file, "r", encoding="utf-8") as f:
            cls.bundle_data = json.load(f)
        with open(cls.prov_file, "r", encoding="utf-8") as f:
            cls.prov_data = json.load(f)
        with open(cls.reg_file, "r", encoding="utf-8") as f:
            cls.reg_data = json.load(f)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_reconciliation_counts(self):
        """Reconcile 282 attempts as exactly 280 valid live trials and 2 exclusions."""
        recon = self.bundle_data["reconciliation_summary"]
        self.assertEqual(recon["total_attempts"], EXPECTED_ATTEMPTS_COUNT)
        self.assertEqual(recon["valid_live_trials"], EXPECTED_VALID_LIVE_COUNT)
        self.assertEqual(recon["cleanup_failure_exclusions"], EXPECTED_EXCLUSIONS_COUNT)
        self.assertEqual(recon["connection_attempts_count"], EXPECTED_TCP_FLOWS_COUNT)
        self.assertEqual(recon["s5_flows_count"], EXPECTED_S5_FLOWS_COUNT)
        self.assertEqual(recon["timeline_events_count"], EXPECTED_TIMELINE_EVENTS_COUNT)

        self.assertEqual(len(self.bundle_data["trials"]), EXPECTED_VALID_LIVE_COUNT)
        self.assertEqual(len(self.bundle_data["exclusions"]), EXPECTED_EXCLUSIONS_COUNT)

    def test_cohort_distribution(self):
        """Verify exactly 14 cohorts (7 scenarios x 2 browsers) with exactly 20 trials each."""
        cohorts = {}
        for t in self.bundle_data["trials"]:
            key = (t["browser"], t["scenario_id"])
            cohorts[key] = cohorts.get(key, 0) + 1

        self.assertEqual(len(cohorts), EXPECTED_COHORTS_COUNT)
        for cohort_key, count in cohorts.items():
            self.assertEqual(
                count,
                EXPECTED_TRIALS_PER_COHORT,
                f"Cohort {cohort_key} count {count} != expected {EXPECTED_TRIALS_PER_COHORT}",
            )

    def test_canonical_metric_keys_preserved(self):
        """Canonical key connection_attempt_delay_ms must be retained, not replaced by cad_ms."""
        for t in self.bundle_data["trials"]:
            metrics = t["metrics"]
            self.assertIn("connection_attempt_delay_ms", metrics)
            self.assertNotIn("cad_ms", metrics, "Prohibited key cad_ms must not be introduced")
            self.assertIn("t_connect_ms", metrics)
            self.assertIn("t_setup_total_ms", metrics)
            self.assertIn("syn_to_synack_ms", metrics)

    def test_json_numeric_preservation_not_string_coerced(self):
        """Numeric metrics in JSON must remain numbers (int/float) or null, never strings."""
        for t in self.bundle_data["trials"][:20]:
            metrics = t["metrics"]
            for mkey, mval in metrics.items():
                if mkey == "null_reasons":
                    continue
                if mval is not None:
                    self.assertIsInstance(
                        mval,
                        (int, float),
                        f"Metric {mkey} value {mval!r} in trial {t['trial_id']} was string-coerced!",
                    )

    def test_statistical_summaries_report_sample_counts_and_null_reasons(self):
        """Statistical summaries must include n_valid, n_null, null_reasons, median, iqr, p95."""
        summaries = self.bundle_data["statistical_summaries"]
        self.assertEqual(len(summaries), EXPECTED_COHORTS_COUNT)

        for cohort_str, s in summaries.items():
            self.assertEqual(s["sample_size"], 20)
            self.assertIn("winning_family_counts", s)
            cad_stats = s["metrics"]["connection_attempt_delay_ms"]
            self.assertIn("n_valid", cad_stats)
            self.assertIn("n_null", cad_stats)
            self.assertIn("null_reasons", cad_stats)
            self.assertEqual(cad_stats["n_valid"] + cad_stats["n_null"], 20)

    def test_exclusions_separated_from_empirical_trials(self):
        """Exclusions (cleanup failures) must be held in separate collection from valid trials."""
        valid_ids = set(t["trial_id"] for t in self.bundle_data["trials"])
        excl_ids = set(e["trial_id"] for e in self.bundle_data["exclusions"])

        # No overlap between valid trials and exclusions
        self.assertEqual(len(valid_ids.intersection(excl_ids)), 0)
        self.assertEqual(len(excl_ids), 2)
        for e in self.bundle_data["exclusions"]:
            self.assertEqual(e["validity_category"], "CLEANUP_FAILURE")

    def test_phase_d_simulation_prohibition(self):
        """Prohibit ingestion of Phase D simulation data fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_dir = Path(tmpdir) / "phase-d"
            fake_dir.mkdir()
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=fake_dir,
                    phase_c_dir=DEFAULT_PHASE_C_DIR,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Phase D simulation", str(ctx.exception))

    def test_byte_identical_multi_run_determinism(self):
        """Repeated generation runs must produce byte-identical files."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1)
            out2 = Path(tmp2)
            b1, p1, r1 = build_demonstration_bundle(
                DEFAULT_CAMPAIGN_DIR, DEFAULT_PHASE_C_DIR, out1, commit_sha_override="deterministic_sha"
            )
            b2, p2, r2 = build_demonstration_bundle(
                DEFAULT_CAMPAIGN_DIR, DEFAULT_PHASE_C_DIR, out2, commit_sha_override="deterministic_sha"
            )

            # Compare bytes directly
            self.assertEqual(b1.read_bytes(), b2.read_bytes(), "demo_bundle.json not byte-identical")
            self.assertEqual(p1.read_bytes(), p2.read_bytes(), "provenance sidecar not byte-identical")
            self.assertEqual(r1.read_bytes(), r2.read_bytes(), "metric_registry.json not byte-identical")

    def test_metric_registry_structure(self):
        """Metric registry must expose all required canonical metrics from metric contract."""
        metrics = self.reg_data["metrics"]
        required_metrics = [
            "t_connect_ms",
            "t_setup_total_ms",
            "syn_to_synack_ms",
            "connection_attempt_delay_ms",
            "dns_query_to_first_payload_ms",
            "dns_last_positive_response_to_first_payload_ms",
            "dns_resolution_time_ms",
            "dns_latency_a_ms",
            "dns_latency_aaaa_ms",
        ]
        for rm in required_metrics:
            self.assertIn(rm, metrics)
            m = metrics[rm]
            self.assertEqual(m["canonical_name"], rm)
            self.assertIn("definition", m)
            self.assertIn("mathematical_formula", m)
            self.assertIn("unit", m)
            self.assertIn("null_reasons", m)


if __name__ == "__main__":
    unittest.main()
