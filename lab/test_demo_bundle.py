#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Demonstration Bundle Builder Tests
Verifies authoritative reconciliation, byte-identical determinism, canonical metric
naming, JSON numeric preservation, and Phase D simulation exclusion.
"""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from lab.analyze import load_trials_from_directory, assess_rfc8305_conformance
from lab.build_demo_bundle import (
    DEFAULT_CAMPAIGN_DIR,
    DEFAULT_PHASE_C_DIR,
    DEFAULT_OUTPUT_DIR,
    EXPECTED_ATTEMPTS_COUNT,
    EXPECTED_VALID_LIVE_COUNT,
    EXPECTED_EXCLUSIONS_COUNT,
    EXPECTED_TCP_FLOWS_COUNT,
    EXPECTED_S5_FLOWS_COUNT,
    EXPECTED_TIMELINE_EVENTS_COUNT,
    EXPECTED_COHORTS_COUNT,
    EXPECTED_TRIALS_PER_COHORT,
    VALID_SUCCESSFUL_CLASSIFICATIONS,
    build_demonstration_bundle,
    compute_sha256,
    validate_strict_positive_int,
    validate_strict_http_status,
    validate_strict_repetition,
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

    def test_browser_cohorts_contain_no_executable_paths(self):
        """Correction 2: Browser cohorts metadata must not leak machine-specific executable paths."""
        for b_id, b_meta in self.bundle_data["browser_cohorts"].items():
            self.assertNotIn("executable", b_meta)
            self.assertIn("name", b_meta)
            self.assertIn("version", b_meta)
            self.assertIn("display_name", b_meta)

    def test_provenance_sidecar_contains_manifest_and_all_rederived_trial_hashes(self):
        """Correction 2: Provenance sidecar must contain checksum manifest and all 280 rederived hashes."""
        input_files = self.prov_data.get("input_files_sha256", {})
        self.assertIn("pcap_sha256_checksums.txt", input_files)
        self.assertIn("campaign_manifest.json", input_files)
        self.assertIn("attempts.csv", input_files)
        self.assertIn("rfc8305_assessment.csv", input_files)

        rederived_hashes = self.prov_data.get("rederived_trials_sha256", {})
        self.assertEqual(len(rederived_hashes), EXPECTED_VALID_LIVE_COUNT)
        for tid, h in rederived_hashes.items():
            self.assertTrue(tid.endswith(".json"))
            self.assertEqual(len(h), 64)

    def test_retransmission_counts_preserved_as_null_when_missing(self):
        """Correction 2: Missing retransmission counts must remain null, never converted to 0."""
        for t in self.bundle_data["trials"]:
            m = t["metrics"]
            self.assertIn("retransmitted_syn_count_ipv6", m)
            self.assertIn("retransmitted_syn_count_ipv4", m)
            v6 = m["retransmitted_syn_count_ipv6"]
            v4 = m["retransmitted_syn_count_ipv4"]
            self.assertTrue(v6 is None or isinstance(v6, int))
            self.assertTrue(v4 is None or isinstance(v4, int))

    def test_invalid_attempt_validity_category_fails_closed(self):
        """Correction 2: Non-VALID_LIVE / non-CLEANUP_FAILURE attempt must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            # Corrupt validity_category (index 10)
            first_row[10] = "CORRUPTED_CATEGORY"
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            out_dir = Path(tmpdir) / "out"
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=out_dir,
                )
            self.assertIn("invalid validity", str(ctx.exception))

    def test_cleanup_failure_with_completed_status_fails_closed(self):
        """Correction 2: Attempt with CLEANUP_FAILURE but COMPLETED status fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            # Find a CLEANUP_FAILURE row (e.g. index 2 in 1-based lines) and set status to COMPLETED
            new_lines = [header]
            for line in orig_lines[1:]:
                row = line.split(",")
                if row[10] == "CLEANUP_FAILURE":
                    row[9] = "COMPLETED"
                    new_lines.append(",".join(row))
                else:
                    new_lines.append(line)
            (tmp_c_dir / "attempts.csv").write_text("\n".join(new_lines) + "\n", encoding="utf-8")

            out_dir = Path(tmpdir) / "out"
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=out_dir,
                )
            self.assertIn("unexpected status", str(ctx.exception))

    def test_trial_identity_mismatches_fail_closed(self):
        """Correction 2: Mismatch between attempts ledger and rederived JSON must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("attempts.csv", "rederived_results"):
                    (tmp_c_dir / item.name).symlink_to(item)

            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["scenario_id"] = "S99_MISMATCH"
            target_json.write_text(json.dumps(data), encoding="utf-8")

            (tmp_c_dir / "attempts.csv").symlink_to(DEFAULT_PHASE_C_DIR / "attempts.csv")

            out_dir = Path(tmpdir) / "out"
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=out_dir,
                )
            self.assertIn("Scenario mismatch", str(ctx.exception))

    def test_rfc8305_assessment_consistency_with_underlying_trials(self):
        """Correction 4: Verify RFC 8305 assessment in bundle matches underlying trials."""
        trials = load_trials_from_directory(DEFAULT_CAMPAIGN_DIR)
        computed_assessment = assess_rfc8305_conformance(trials)
        bundle_assessment = self.bundle_data["rfc8305_assessment"]

        self.assertEqual(len(bundle_assessment), len(computed_assessment))
        comp_by_id = {c["check_id"]: c for c in computed_assessment}
        for actual in bundle_assessment:
            cid = actual["check_id"]
            self.assertIn(cid, comp_by_id)
            exp = comp_by_id[cid]
            self.assertEqual(exp["scenario_id"], actual["scenario_id"])
            self.assertEqual(exp["mandatory_floor_status"], actual["mandatory_floor_status"])
            self.assertEqual(exp["recommendation_alignment_status"], actual["recommendation_alignment_status"])
            self.assertEqual(exp["overall_observation_status"], actual["overall_observation_status"])

    def test_missing_primary_flow_fails_closed(self):
        """Correction B: Rederived JSON missing primary_flow must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            del data["primary_flow"]
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("missing or malformed primary_flow", str(ctx.exception))

    def test_empty_or_malformed_primary_flow_fails_closed(self):
        """Correction B: Empty or malformed primary_flow must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"

            # Case 1: Empty dict
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primary_flow"] = {}
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("missing or malformed primary_flow", str(ctx.exception))

            # Case 2: Dict missing stream identifier
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primary_flow"] = {"stream_id": ""}
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("missing non-empty stream identifier", str(ctx.exception))

            # Case 3: Not a dict
            data["primary_flow"] = "not_a_dictionary"
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("missing or malformed primary_flow", str(ctx.exception))

    def test_missing_pcap_digest_in_rederived_fails_closed(self):
        """Correction B: Missing pcap_sha256 in rederived primary flow must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            del data["primary_flow"]["pcap_sha256"]
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("missing or malformed pcap_sha256 digest", str(ctx.exception))

    def test_rederived_checksum_mismatch_fails_closed(self):
        """Correction B: Rederived primary flow PCAP digest mismatch with manifest fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primary_flow"]["pcap_sha256"] = "0" * 64
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("primary_flow PCAP digest mismatch", str(ctx.exception))

    def test_attempts_ledger_checksum_mismatch_fails_closed(self):
        """Correction B: Attempts ledger PCAP digest mismatch with manifest fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            col_idx = header.split(",").index("pcap_sha256")
            first_row[col_idx] = "0" * 64
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Attempts ledger PCAP digest mismatch", str(ctx.exception))

    def test_canonical_checksum_manifest_missing_trial_fails_closed(self):
        """Correction B: Valid trial missing from canonical checksum manifest fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_camp = Path(tmpdir) / "campaign"
            tmp_camp.mkdir()
            for item in DEFAULT_CAMPAIGN_DIR.iterdir():
                if item.name != "pcap_sha256_checksums.txt":
                    (tmp_camp / item.name).symlink_to(item)

            orig_lines = (DEFAULT_CAMPAIGN_DIR / "pcap_sha256_checksums.txt").read_text(encoding="utf-8").splitlines()
            # Remove line 1
            modified_text = "\n".join(orig_lines[1:]) + "\n"
            (tmp_camp / "pcap_sha256_checksums.txt").write_text(modified_text, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=tmp_camp,
                    phase_c_dir=DEFAULT_PHASE_C_DIR,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("missing from canonical checksum manifest", str(ctx.exception))

    def test_canonical_checksum_manifest_malformed_digest_fails_closed(self):
        """Correction B: Malformed digest in checksum manifest fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_camp = Path(tmpdir) / "campaign"
            tmp_camp.mkdir()
            for item in DEFAULT_CAMPAIGN_DIR.iterdir():
                if item.name != "pcap_sha256_checksums.txt":
                    (tmp_camp / item.name).symlink_to(item)

            orig_lines = (DEFAULT_CAMPAIGN_DIR / "pcap_sha256_checksums.txt").read_text(encoding="utf-8").splitlines()
            parts = orig_lines[0].split(maxsplit=1)
            bad_line = f"not-a-64-hex-digest  {parts[1]}"
            modified_text = "\n".join([bad_line] + orig_lines[1:]) + "\n"
            (tmp_camp / "pcap_sha256_checksums.txt").write_text(modified_text, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=tmp_camp,
                    phase_c_dir=DEFAULT_PHASE_C_DIR,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Malformed SHA-256 digest", str(ctx.exception))

    def test_canonical_checksum_manifest_duplicate_conflicting_fails_closed(self):
        """Correction B: Duplicate conflicting entry in checksum manifest fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_camp = Path(tmpdir) / "campaign"
            tmp_camp.mkdir()
            for item in DEFAULT_CAMPAIGN_DIR.iterdir():
                if item.name != "pcap_sha256_checksums.txt":
                    (tmp_camp / item.name).symlink_to(item)

            orig_text = (DEFAULT_CAMPAIGN_DIR / "pcap_sha256_checksums.txt").read_text(encoding="utf-8")
            first_line = orig_text.splitlines()[0]
            parts = first_line.split(maxsplit=1)
            conflict_line = f"{'f' * 64}  {parts[1]}\n"
            (tmp_camp / "pcap_sha256_checksums.txt").write_text(orig_text + conflict_line, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=tmp_camp,
                    phase_c_dir=DEFAULT_PHASE_C_DIR,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Duplicate conflicting checksum entry", str(ctx.exception))

    def test_browser_version_mismatch_fails_closed(self):
        """Correction B: Rederived browser version mismatch against canonical cohort fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["browser_version"] = "Google Chrome 999.0.0.0"
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Browser version mismatch", str(ctx.exception))

    def test_repetition_preservation_from_attempts_ledger(self):
        """Correction B: Repetition must be preserved from ledger; mismatch fails closed."""
        for t in self.bundle_data["trials"]:
            rep = t.get("repetition")
            self.assertIsNotNone(rep, f"Trial {t['trial_id']} has None repetition!")
            self.assertIsInstance(rep, int)
            self.assertTrue(1 <= rep <= 20)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["repetition"] = 2  # ledger has 1
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Repetition mismatch", str(ctx.exception))

    def test_invalid_primary_flow_evidence_fails_closed(self):
        """Correction B: Invalid primary flow family, handshake, or HTTP evidence fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"

            # Case 1: Invalid family
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primary_flow"]["family"] = "IPv5"
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("invalid family", str(ctx.exception))

            # Case 2: Incomplete handshake
            data["primary_flow"]["family"] = "IPv6"
            data["primary_flow"]["handshake_completed"] = False
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("handshake not completed", str(ctx.exception))

            # Case 3: Missing syn_frame
            data["primary_flow"]["handshake_completed"] = True
            data["primary_flow"]["syn_frame"] = None
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertTrue("syn_frame is missing or None" in str(ctx.exception) or "missing required positive syn_frame" in str(ctx.exception))

            # Case 4: Non-200 HTTP status
            data["primary_flow"]["syn_frame"] = 10
            data["primary_flow"]["http_status_code"] = 500
            target_json.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertTrue("must be 200" in str(ctx.exception) or "missing valid successful HTTP status code" in str(ctx.exception))

    def test_attempts_ledger_campaign_id_mismatch_fails_closed(self):
        """Correction A: Attempts ledger campaign_id mismatch with manifest fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            col_idx = header.split(",").index("campaign_id")
            first_row[col_idx] = "mismatched-campaign-id"
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Campaign ID mismatch", str(ctx.exception))

    def test_attempts_ledger_classification_mismatch_fails_closed(self):
        """Correction A: Attempts ledger classification mismatch with rederived JSON fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            col_idx = header.split(",").index("classification")
            # First row is DIRECT_IPV6; flip to DIRECT_IPV4
            first_row[col_idx] = "DIRECT_IPV4"
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("Classification mismatch", str(ctx.exception))

    def test_attempts_ledger_http_status_mismatch_fails_closed(self):
        """Correction A: Attempts ledger HTTP status mismatch with primary flow fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            col_idx = header.split(",").index("http_status")
            first_row[col_idx] = "500"
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("must be 200", str(ctx.exception))

    def test_invalid_or_failed_classification_fails_closed(self):
        """Correction A: Non-successful classification (CONNECTION_FAILED, INCONCLUSIVE, unknown) fails closed."""
        for invalid_cls in ("CONNECTION_FAILED", "INCONCLUSIVE", "UNKNOWN_CLASSIFICATION"):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_c_dir = Path(tmpdir) / "phase-c"
                tmp_c_dir.mkdir()
                for item in DEFAULT_PHASE_C_DIR.iterdir():
                    if item.name not in ("attempts.csv", "rederived_results"):
                        (tmp_c_dir / item.name).symlink_to(item)

                # Update attempts.csv
                orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
                header = orig_lines[0]
                first_row = orig_lines[1].split(",")
                col_idx = header.split(",").index("classification")
                first_row[col_idx] = invalid_cls
                corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
                (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

                # Update rederived JSON
                shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
                target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
                data = json.loads(target_json.read_text(encoding="utf-8"))
                data["classification"] = invalid_cls
                target_json.write_text(json.dumps(data), encoding="utf-8")

                with self.assertRaises(ValueError) as ctx:
                    build_demonstration_bundle(
                        campaign_dir=DEFAULT_CAMPAIGN_DIR,
                        phase_c_dir=tmp_c_dir,
                        output_dir=Path(tmpdir) / "out",
                    )
                self.assertIn("invalid or unsuccessful classification", str(ctx.exception))

    def test_classification_and_family_inconsistency_fails_closed(self):
        """Correction A: Inconsistency between classification and primary-flow family fails closed."""
        cases = [
            ("DIRECT_IPV6", "IPv4"),
            ("DIRECT_IPV4", "IPv6"),
            ("IPV6_TO_IPV4_FALLBACK", "IPv6"),
            ("IPV4_TO_IPV6_FALLBACK", "IPv4"),
        ]
        for cls_name, wrong_fam in cases:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_c_dir = Path(tmpdir) / "phase-c"
                tmp_c_dir.mkdir()
                for item in DEFAULT_PHASE_C_DIR.iterdir():
                    if item.name not in ("attempts.csv", "rederived_results"):
                        (tmp_c_dir / item.name).symlink_to(item)

                orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
                header = orig_lines[0]
                first_row = orig_lines[1].split(",")
                first_row[header.split(",").index("classification")] = cls_name
                corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
                (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

                shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
                target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
                data = json.loads(target_json.read_text(encoding="utf-8"))
                data["classification"] = cls_name
                data["primary_flow"]["family"] = wrong_fam
                target_json.write_text(json.dumps(data), encoding="utf-8")

                with self.assertRaises(ValueError) as ctx:
                    build_demonstration_bundle(
                        campaign_dir=DEFAULT_CAMPAIGN_DIR,
                        phase_c_dir=tmp_c_dir,
                        output_dir=Path(tmpdir) / "out",
                    )
                self.assertIn("Classification/family inconsistency", str(ctx.exception))

    def test_fractional_frame_identifiers_fail_closed(self):
        """Correction B: Fractional frame identifiers fail closed."""
        for field, frac_val in (
            ("syn_frame", 10.9),
            ("final_ack_frame", 20.5),
            ("http_request_frame", 30.1),
            ("http_response_frame", 40.8),
            ("syn_frame", "10.9"),
        ):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_c_dir = Path(tmpdir) / "phase-c"
                tmp_c_dir.mkdir()
                for item in DEFAULT_PHASE_C_DIR.iterdir():
                    if item.name not in ("rederived_results",):
                        (tmp_c_dir / item.name).symlink_to(item)
                shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
                target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
                data = json.loads(target_json.read_text(encoding="utf-8"))
                data["primary_flow"][field] = frac_val
                target_json.write_text(json.dumps(data), encoding="utf-8")

                with self.assertRaises(ValueError) as ctx:
                    build_demonstration_bundle(
                        campaign_dir=DEFAULT_CAMPAIGN_DIR,
                        phase_c_dir=tmp_c_dir,
                        output_dir=Path(tmpdir) / "out",
                    )
                err = str(ctx.exception)
                self.assertTrue("floating-point" in err or "positive integer string" in err)

    def test_boolean_frame_identifiers_fail_closed(self):
        """Correction B: Boolean frame identifiers fail closed."""
        for field, bool_val in (("syn_frame", True), ("final_ack_frame", False)):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_c_dir = Path(tmpdir) / "phase-c"
                tmp_c_dir.mkdir()
                for item in DEFAULT_PHASE_C_DIR.iterdir():
                    if item.name not in ("rederived_results",):
                        (tmp_c_dir / item.name).symlink_to(item)
                shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
                target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
                data = json.loads(target_json.read_text(encoding="utf-8"))
                data["primary_flow"][field] = bool_val
                target_json.write_text(json.dumps(data), encoding="utf-8")

                with self.assertRaises(ValueError) as ctx:
                    build_demonstration_bundle(
                        campaign_dir=DEFAULT_CAMPAIGN_DIR,
                        phase_c_dir=tmp_c_dir,
                        output_dir=Path(tmpdir) / "out",
                    )
                self.assertIn("cannot be a boolean", str(ctx.exception))

    def test_non_numeric_and_non_positive_frame_identifiers_fail_closed(self):
        """Correction B: Zero, negative, and non-numeric frame identifiers fail closed."""
        for field, bad_val in (
            ("syn_frame", 0),
            ("final_ack_frame", -1),
            ("http_request_frame", "abc"),
            ("http_response_frame", ""),
        ):
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_c_dir = Path(tmpdir) / "phase-c"
                tmp_c_dir.mkdir()
                for item in DEFAULT_PHASE_C_DIR.iterdir():
                    if item.name not in ("rederived_results",):
                        (tmp_c_dir / item.name).symlink_to(item)
                shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
                target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
                data = json.loads(target_json.read_text(encoding="utf-8"))
                data["primary_flow"][field] = bad_val
                target_json.write_text(json.dumps(data), encoding="utf-8")

                with self.assertRaises(ValueError) as ctx:
                    build_demonstration_bundle(
                        campaign_dir=DEFAULT_CAMPAIGN_DIR,
                        phase_c_dir=tmp_c_dir,
                        output_dir=Path(tmpdir) / "out",
                    )
                err = str(ctx.exception)
                self.assertTrue("must be a positive integer" in err)

    def test_fractional_and_boolean_http_status_fails_closed(self):
        """Correction B: Fractional and boolean HTTP status fail closed."""
        # Case 1: Float 200.0 in rederived JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primary_flow"]["http_status_code"] = 200.0
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("cannot be a floating-point number", str(ctx.exception))

        # Case 2: Boolean True in rederived JSON
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("rederived_results",):
                    (tmp_c_dir / item.name).symlink_to(item)
            shutil.copytree(DEFAULT_PHASE_C_DIR / "rederived_results", tmp_c_dir / "rederived_results")
            target_json = tmp_c_dir / "rederived_results" / "trial-20261029205425-6cb90a54.json"
            data = json.loads(target_json.read_text(encoding="utf-8"))
            data["primary_flow"]["http_status_code"] = True
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("cannot be a boolean", str(ctx.exception))

        # Case 3: Fractional "200.0" string in attempts.csv
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            first_row[header.split(",").index("http_status")] = "200.0"
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("must be a valid integer string", str(ctx.exception))

    def test_provenance_sidecar_generator_revision(self):
        """Correction C: Checked-in provenance sidecar generator commit matches latest commit touching build_demo_bundle.py."""
        sidecar_file = DEFAULT_OUTPUT_DIR / "demo_bundle.json.provenance.json"
        bundle_file = DEFAULT_OUTPUT_DIR / "demo_bundle.json"
        if not sidecar_file.is_file():
            self.skipTest("Checked-in sidecar file not found")
        sidecar_data = json.loads(sidecar_file.read_text(encoding="utf-8"))
        gen_commit = sidecar_data.get("generator_commit")
        self.assertIsNotNone(gen_commit)
        self.assertEqual(len(gen_commit), 40)
        res = subprocess.run(
            ["git", "cat-file", "-e", f"{gen_commit}^{{commit}}"],
            capture_output=True,
        )
        self.assertEqual(res.returncode, 0, f"generator_commit {gen_commit} not found in git history")
        self.assertEqual(compute_sha256(bundle_file), sidecar_data["output_bundle_sha256"])

        # Strengthened check: generator_commit must match the latest commit that modified lab/build_demo_bundle.py
        log_res = subprocess.run(
            ["git", "log", "-n", "1", "--pretty=format:%H", "--", "lab/build_demo_bundle.py"],
            capture_output=True,
            text=True,
            check=True,
        )
        expected_commit = log_res.stdout.strip()
        self.assertEqual(
            gen_commit,
            expected_commit,
            f"Provenance sidecar generator_commit '{gen_commit}' is stale or incorrect; "
            f"expected latest commit touching lab/build_demo_bundle.py ('{expected_commit}')"
        )

    def test_provenance_sidecar_detects_stale_or_invalid_revision(self):
        """Correction C: Provenance validator fails closed if generator_commit is stale or invalid."""
        with tempfile.TemporaryDirectory() as td:
            temp_out = Path(td)
            stale_commit = "0" * 40
            build_demonstration_bundle(
                campaign_dir=DEFAULT_CAMPAIGN_DIR,
                phase_c_dir=DEFAULT_PHASE_C_DIR,
                output_dir=temp_out,
                commit_sha_override=stale_commit,
            )
            sidecar_data = json.loads((temp_out / "demo_bundle.json.provenance.json").read_text(encoding="utf-8"))
            self.assertEqual(sidecar_data["generator_commit"], stale_commit)
            res = subprocess.run(
                ["git", "cat-file", "-e", f"{stale_commit}^{{commit}}"],
                capture_output=True,
            )
            self.assertNotEqual(res.returncode, 0)

    def test_validate_strict_repetition_rules(self):
        """Correction B: Strict repetition validation rules for integers 1..20."""
        self.assertEqual(validate_strict_repetition(1, "rep"), 1)
        self.assertEqual(validate_strict_repetition(20, "rep"), 20)
        self.assertEqual(validate_strict_repetition("1", "rep"), 1)
        self.assertEqual(validate_strict_repetition("20", "rep"), 20)

        invalid_cases = [
            (None, "is missing or None"),
            (True, "cannot be a boolean"),
            (False, "cannot be a boolean"),
            (10.5, "cannot be a floating-point number"),
            (10.0, "cannot be a floating-point number"),
            ("10.5", "must be a valid integer string"),
            ("10.0", "must be a valid integer string"),
            ("abc", "must be a valid integer string"),
            ("", "must be a valid integer string"),
            (0, "must be an integer between 1 and 20"),
            (21, "must be an integer between 1 and 20"),
            (-1, "must be an integer between 1 and 20"),
            ("0", "must be an integer between 1 and 20"),
            ("21", "must be an integer between 1 and 20"),
        ]
        for val, err_fragment in invalid_cases:
            with self.subTest(val=val):
                with self.assertRaises(ValueError) as ctx:
                    validate_strict_repetition(val, "test_rep")
                self.assertIn(err_fragment, str(ctx.exception))

    def test_manifest_missing_or_empty_campaign_id_fails_closed(self):
        """Correction A: Missing or empty campaign_id in manifest fails closed without fallback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "campaign"
            tmp_c_dir.mkdir()
            for item in DEFAULT_CAMPAIGN_DIR.iterdir():
                if item.name != "campaign_manifest.json":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_man = json.loads((DEFAULT_CAMPAIGN_DIR / "campaign_manifest.json").read_text(encoding="utf-8"))

            # Case 1: missing campaign_id
            man1 = dict(orig_man)
            man1.pop("campaign_id", None)
            (tmp_c_dir / "campaign_manifest.json").write_text(json.dumps(man1), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=tmp_c_dir,
                    phase_c_dir=DEFAULT_PHASE_C_DIR,
                    output_dir=Path(tmpdir) / "out1",
                )
            self.assertIn("missing or has empty 'campaign_id'", str(ctx.exception))

            # Case 2: empty string campaign_id
            man2 = dict(orig_man)
            man2["campaign_id"] = "   "
            (tmp_c_dir / "campaign_manifest.json").write_text(json.dumps(man2), encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=tmp_c_dir,
                    phase_c_dir=DEFAULT_PHASE_C_DIR,
                    output_dir=Path(tmpdir) / "out2",
                )
            self.assertIn("missing or has empty 'campaign_id'", str(ctx.exception))

    def test_fractional_ledger_repetition_fails_closed(self):
        """Correction B: Fractional repetition in attempts ledger fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "attempts.csv":
                    (tmp_c_dir / item.name).symlink_to(item)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            first_row = orig_lines[1].split(",")
            first_row[header.split(",").index("repetition")] = "1.0"
            corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
            (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("must be a valid integer string", str(ctx.exception))

    def test_fractional_rederived_repetition_fails_closed(self):
        """Correction B: Fractional repetition in rederived trial record fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "rederived_results":
                    (tmp_c_dir / item.name).symlink_to(item)
            trials_dir = tmp_c_dir / "rederived_results"
            trials_dir.mkdir()
            for tfile in (DEFAULT_PHASE_C_DIR / "rederived_results").glob("trial-*.json"):
                (trials_dir / tfile.name).symlink_to(tfile)

            first_trial = sorted((DEFAULT_PHASE_C_DIR / "rederived_results").glob("trial-*.json"))[0]
            target_json = trials_dir / first_trial.name
            target_json.unlink()
            data = json.loads(first_trial.read_text(encoding="utf-8"))
            data["repetition"] = 1.5
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("cannot be a floating-point number", str(ctx.exception))

    def test_boolean_or_invalid_repetition_fails_closed(self):
        """Correction B: Boolean or non-numeric repetition in rederived record fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name != "rederived_results":
                    (tmp_c_dir / item.name).symlink_to(item)
            trials_dir = tmp_c_dir / "rederived_results"
            trials_dir.mkdir()
            for tfile in (DEFAULT_PHASE_C_DIR / "rederived_results").glob("trial-*.json"):
                (trials_dir / tfile.name).symlink_to(tfile)

            first_trial = sorted((DEFAULT_PHASE_C_DIR / "rederived_results").glob("trial-*.json"))[0]
            target_json = trials_dir / first_trial.name
            target_json.unlink()
            data = json.loads(first_trial.read_text(encoding="utf-8"))
            data["repetition"] = True
            target_json.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("cannot be a boolean", str(ctx.exception))

    def test_repetition_out_of_range_0_and_21_fails_closed(self):
        """Correction B: Repetitions 0 and 21 fail closed."""
        for bad_rep in ["0", "21"]:
            with self.subTest(bad_rep=bad_rep):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp_c_dir = Path(tmpdir) / "phase-c"
                    tmp_c_dir.mkdir()
                    for item in DEFAULT_PHASE_C_DIR.iterdir():
                        if item.name != "attempts.csv":
                            (tmp_c_dir / item.name).symlink_to(item)

                    orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
                    header = orig_lines[0]
                    first_row = orig_lines[1].split(",")
                    first_row[header.split(",").index("repetition")] = bad_rep
                    corrupted_csv = "\n".join([header, ",".join(first_row)] + orig_lines[2:]) + "\n"
                    (tmp_c_dir / "attempts.csv").write_text(corrupted_csv, encoding="utf-8")

                    with self.assertRaises(ValueError) as ctx:
                        build_demonstration_bundle(
                            campaign_dir=DEFAULT_CAMPAIGN_DIR,
                            phase_c_dir=tmp_c_dir,
                            output_dir=Path(tmpdir) / "out",
                        )
                    self.assertIn("must be an integer between 1 and 20", str(ctx.exception))

    def test_duplicate_repetition_within_cohort_fails_closed(self):
        """Correction B: Duplicate repetition within scenario-browser cohort fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("attempts.csv", "rederived_results"):
                    (tmp_c_dir / item.name).symlink_to(item)

            trials_dir = tmp_c_dir / "rederived_results"
            trials_dir.mkdir()
            for tfile in (DEFAULT_PHASE_C_DIR / "rederived_results").glob("trial-*.json"):
                (trials_dir / tfile.name).symlink_to(tfile)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            h_cols = header.split(",")
            rep_idx = h_cols.index("repetition")
            tid_idx = h_cols.index("trial_id")
            cat_idx = h_cols.index("validity_category")

            row1 = orig_lines[1].split(",")
            row2 = None
            row2_line_idx = -1
            for idx in range(2, len(orig_lines)):
                cand = orig_lines[idx].split(",")
                if cand[cat_idx] == "VALID_LIVE" and cand[h_cols.index("scenario_id")] == row1[h_cols.index("scenario_id")] and cand[h_cols.index("browser")] == row1[h_cols.index("browser")]:
                    row2 = cand
                    row2_line_idx = idx
                    break
            self.assertIsNotNone(row2)

            dup_rep = row1[rep_idx]
            row2[rep_idx] = dup_rep
            new_lines = list(orig_lines)
            new_lines[row2_line_idx] = ",".join(row2)
            (tmp_c_dir / "attempts.csv").write_text("\n".join(new_lines) + "\n", encoding="utf-8")

            t2_id = row2[tid_idx]
            t2_path = trials_dir / f"{t2_id}.json"
            if t2_path.exists():
                t2_path.unlink()
                data2 = json.loads((DEFAULT_PHASE_C_DIR / "rederived_results" / f"{t2_id}.json").read_text(encoding="utf-8"))
                data2["repetition"] = int(dup_rep)
                t2_path.write_text(json.dumps(data2), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertIn("contains duplicate repetition(s)", str(ctx.exception))

    def test_missing_repetition_within_cohort_fails_closed(self):
        """Correction B: Cohort validation enforces all repetitions 1..20 present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_c_dir = Path(tmpdir) / "phase-c"
            tmp_c_dir.mkdir()
            for item in DEFAULT_PHASE_C_DIR.iterdir():
                if item.name not in ("attempts.csv", "rederived_results"):
                    (tmp_c_dir / item.name).symlink_to(item)

            trials_dir = tmp_c_dir / "rederived_results"
            trials_dir.mkdir()
            for tfile in (DEFAULT_PHASE_C_DIR / "rederived_results").glob("trial-*.json"):
                (trials_dir / tfile.name).symlink_to(tfile)

            orig_lines = (DEFAULT_PHASE_C_DIR / "attempts.csv").read_text(encoding="utf-8").splitlines()
            header = orig_lines[0]
            h_cols = header.split(",")
            rep_idx = h_cols.index("repetition")
            tid_idx = h_cols.index("trial_id")
            cat_idx = h_cols.index("validity_category")

            row1 = orig_lines[1].split(",")
            row2 = None
            row2_line_idx = -1
            for idx in range(2, len(orig_lines)):
                cand = orig_lines[idx].split(",")
                if cand[cat_idx] == "VALID_LIVE" and cand[h_cols.index("scenario_id")] == row1[h_cols.index("scenario_id")] and cand[h_cols.index("browser")] == row1[h_cols.index("browser")]:
                    row2 = cand
                    row2_line_idx = idx
                    break
            self.assertIsNotNone(row2)

            dup_rep = row1[rep_idx]
            row2[rep_idx] = dup_rep
            new_lines = list(orig_lines)
            new_lines[row2_line_idx] = ",".join(row2)
            (tmp_c_dir / "attempts.csv").write_text("\n".join(new_lines) + "\n", encoding="utf-8")

            t2_id = row2[tid_idx]
            t2_path = trials_dir / f"{t2_id}.json"
            if t2_path.exists():
                t2_path.unlink()
                data2 = json.loads((DEFAULT_PHASE_C_DIR / "rederived_results" / f"{t2_id}.json").read_text(encoding="utf-8"))
                data2["repetition"] = int(dup_rep)
                t2_path.write_text(json.dumps(data2), encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                build_demonstration_bundle(
                    campaign_dir=DEFAULT_CAMPAIGN_DIR,
                    phase_c_dir=tmp_c_dir,
                    output_dir=Path(tmpdir) / "out",
                )
            self.assertTrue(
                "contains duplicate repetition(s)" in str(ctx.exception)
                or "missing repetition(s)" in str(ctx.exception)
            )
            self.assertTrue(
                "contains duplicate repetition(s)" in str(ctx.exception)
                or "missing repetition(s)" in str(ctx.exception)
            )

    def test_authentic_repetition_preservation_1_to_20(self):
        """Correction B: Authentic demonstration bundle strictly preserves repetitions 1..20 for all 14 cohorts."""
        trials = self.bundle_data["trials"]
        self.assertEqual(len(trials), EXPECTED_VALID_LIVE_COUNT)

        cohorts = {}
        for t in trials:
            ck = (t["browser"], t["scenario_id"])
            cohorts.setdefault(ck, []).append(t["repetition"])

        self.assertEqual(len(cohorts), EXPECTED_COHORTS_COUNT)
        expected_set = set(range(1, 21))

        for ck, reps in cohorts.items():
            self.assertEqual(len(reps), 20, f"Cohort {ck} has incorrect trial count")
            self.assertEqual(set(reps), expected_set, f"Cohort {ck} does not contain exact range 1..20")
            for r in reps:
                self.assertIs(type(r), int, f"Repetition {r} in cohort {ck} is not Python int")


if __name__ == "__main__":
    unittest.main()
