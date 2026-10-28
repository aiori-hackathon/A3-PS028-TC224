#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Test Suite for Statistical Analysis
Work Package A9: Statistical Analysis, Exclusions, Reconciliation & RFC 8305 Evaluator
"""

import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.analyze as analyze


def _create_synthetic_trial(
    trial_id: str = "trial-20261028120000-synthetic",
    scenario_id: str = "S0",
    browser_name: str = "google-chrome",
    is_simulation: bool = False,
    http_success: bool = True,
    winning_family: str = "IPv6",
    setup_time_ms: float = 20.0,
    cad_ms: float = None,
    dns_a_lat: float = 5.0,
    dns_aaaa_lat: float = 5.0,
    packet_count: int = 100,
    pcap_valid: bool = True,
    scenario_restored: bool = True,
    baseline_verified: bool = True,
    cleanup_errors: list = None,
    classification: str = "DIRECT_IPV6"
) -> dict:
    dns_queries = []
    dns_responses = []
    t0 = 1793200000.0

    if dns_a_lat is not None:
        dns_queries.append({"qname": f"{trial_id}.he.test", "qtype": "A", "timestamp": t0})
        dns_responses.append({"qname": f"{trial_id}.he.test", "qtype": "A", "address": "10.0.2.10", "timestamp": t0 + dns_a_lat / 1000.0})

    if dns_aaaa_lat is not None:
        dns_queries.append({"qname": f"{trial_id}.he.test", "qtype": "AAAA", "timestamp": t0 + 0.001})
        dns_responses.append({"qname": f"{trial_id}.he.test", "qtype": "AAAA", "address": "2001:db8:2::10", "timestamp": t0 + 0.001 + dns_aaaa_lat / 1000.0})

    return {
        "schema_version": "1.0.0",
        "trial_id": trial_id,
        "scenario_id": scenario_id,
        "scenario_name": analyze.SCENARIO_NAMES.get(scenario_id, "unknown"),
        "hostname": f"{trial_id}.he.test",
        "target_url": f"http://{trial_id}.he.test/",
        "execution_mode": "SIMULATION" if is_simulation else "LIVE",
        "is_simulation": is_simulation,
        "timestamps": {
            "start_time": "2026-10-28T12:00:00+00:00",
            "end_time": "2026-10-28T12:00:10+00:00",
            "total_duration_ms": 10000.0
        },
        "browser": {
            "name": browser_name,
            "executable": f"/usr/bin/{browser_name}",
            "version": f"{browser_name} 156.0.0.0",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 1100.0,
            "profile_cleaned": True
        },
        "http_outcome": {
            "status_code": 200 if http_success else 500,
            "success": http_success,
            "winning_address_family": winning_family,
            "winning_ip": "2001:db8:2::10" if winning_family == "IPv6" else "10.0.2.10",
            "response_body_bytes": 300
        },
        "dns_observations": {
            "queries": dns_queries,
            "responses": dns_responses
        },
        "network_observations": {
            "ipv6_attempt": True,
            "ipv4_attempt": (winning_family == "IPv4" or cad_ms is not None),
            "ipv6_success": (winning_family == "IPv6"),
            "ipv4_success": (winning_family == "IPv4"),
            "connection_attempt_delay_ms": cad_ms,
            "connection_setup_time_ms": setup_time_ms,
            "fallback_occurred": (cad_ms is not None),
            "classification": classification,
            "classification_reason": "Synthetic test classification"
        },
        "capture_metadata": {
            "pcap_path": f"/tmp/{trial_id}/capture.pcap",
            "pcap_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "pcap_size_bytes": 1000,
            "pcap_valid": pcap_valid,
            "packet_count": packet_count,
            "validation_message": "Valid PCAP" if pcap_valid else "Invalid PCAP"
        },
        "evidence_paths": {
            "trial_dir": f"/tmp/{trial_id}",
            "result_json": f"/tmp/{trial_id}/result.json"
        },
        "cleanup_status": {
            "scenario_restored": scenario_restored,
            "baseline_verified": baseline_verified,
            "profile_cleaned": True,
            "lock_released": True,
            "errors": cleanup_errors if cleanup_errors is not None else []
        }
    }


def _dict_to_evidence(d: dict, validity: str = "VALID_LIVE") -> analyze.TrialEvidence:
    net_obs = d.get("network_observations", {})
    http = d.get("http_outcome", {})
    dns = d.get("dns_observations", {})
    browser = d.get("browser", {})
    cleanup = d.get("cleanup_status", {})
    capture = d.get("capture_metadata", {})
    a_lat, aaaa_lat, res_time = analyze.extract_dns_latencies(dns)

    return analyze.TrialEvidence(
        trial_id=d["trial_id"],
        scenario_id=d["scenario_id"],
        scenario_name=d["scenario_name"],
        browser_name=browser.get("name", "google-chrome"),
        browser_version=browser.get("version", "156.0"),
        execution_mode=d.get("execution_mode", "LIVE"),
        is_simulation=d.get("is_simulation", False),
        http_status_code=http.get("status_code", 200),
        http_success=http.get("success", True),
        winning_address_family=http.get("winning_address_family"),
        winning_ip=http.get("winning_ip"),
        connection_setup_time_ms=net_obs.get("connection_setup_time_ms"),
        connection_attempt_delay_ms=net_obs.get("connection_attempt_delay_ms"),
        dns_latency_a_ms=a_lat,
        dns_latency_aaaa_ms=aaaa_lat,
        dns_resolution_time_ms=res_time,
        browser_duration_ms=browser.get("duration_ms"),
        packet_count=capture.get("packet_count", 100),
        pcap_valid=capture.get("pcap_valid", True),
        pcap_sha256=capture.get("pcap_sha256"),
        scenario_restored=cleanup.get("scenario_restored", True),
        baseline_verified=cleanup.get("baseline_verified", True),
        cleanup_errors=cleanup.get("errors", []),
        classification=net_obs.get("classification", "DIRECT_IPV6"),
        classification_reason=net_obs.get("classification_reason", "OK"),
        validity_category=validity,
        exclusion_reason=None if validity == "VALID_LIVE" else "Test exclusion",
        source_path="/tmp"
    )


class TestStatistics(unittest.TestCase):
    """Verifies mathematical correctness of statistical functions and edge cases."""

    def test_percentile_calculations(self):
        # Empty array
        self.assertIsNone(analyze.compute_percentile([], 0.5))

        # Single element
        self.assertEqual(analyze.compute_percentile([42.0], 0.5), 42.0)
        self.assertEqual(analyze.compute_percentile([42.0], 0.95), 42.0)

        # Odd length sorted array: [10, 20, 30, 40, 50]
        odd_arr = [10.0, 20.0, 30.0, 40.0, 50.0]
        self.assertEqual(analyze.compute_percentile(odd_arr, 0.5), 30.0)
        self.assertEqual(analyze.compute_percentile(odd_arr, 0.0), 10.0)
        self.assertEqual(analyze.compute_percentile(odd_arr, 1.0), 50.0)
        # p95: pos = 0.95 * 4 = 3.8 -> 40 + 0.8 * 10 = 48.0
        self.assertEqual(analyze.compute_percentile(odd_arr, 0.95), 48.0)

        # Even length array: [10, 20, 30, 40]
        even_arr = [10.0, 20.0, 30.0, 40.0]
        # p50: pos = 0.5 * 3 = 1.5 -> 20 + 0.5 * 10 = 25.0
        self.assertEqual(analyze.compute_percentile(even_arr, 0.5), 25.0)

    def test_wilson_score_interval(self):
        # n <= 0 returns None
        self.assertIsNone(analyze.wilson_score_interval(0, 0))
        self.assertIsNone(analyze.wilson_score_interval(5, -1))

        # 0 successes out of 10: lower bound strictly 0.0
        ci_0 = analyze.wilson_score_interval(0, 10)
        self.assertIsNotNone(ci_0)
        self.assertEqual(ci_0[0], 0.0)
        self.assertGreater(ci_0[1], 0.0)
        self.assertLessEqual(ci_0[1], 1.0)

        # 10 successes out of 10: upper bound strictly 1.0
        ci_10 = analyze.wilson_score_interval(10, 10)
        self.assertIsNotNone(ci_10)
        self.assertGreater(ci_10[0], 0.0)
        self.assertEqual(ci_10[1], 1.0)

        # 5 out of 10: symmetric around 0.5
        ci_5 = analyze.wilson_score_interval(5, 10)
        self.assertIsNotNone(ci_5)
        self.assertAlmostEqual(ci_5[0] + ci_5[1], 1.0, places=3)

        # Single trial 1/1
        ci_1 = analyze.wilson_score_interval(1, 1)
        self.assertEqual(ci_1[1], 1.0)
        self.assertGreater(ci_1[0], 0.0)

    def test_bootstrap_median_ci_determinism(self):
        data = [20.0, 22.0, 25.0, 28.0, 30.0, 35.0, 40.0]
        ci1 = analyze.bootstrap_median_ci(data, seed=42, resamples=500)
        ci2 = analyze.bootstrap_median_ci(data, seed=42, resamples=500)
        self.assertIsNotNone(ci1)
        self.assertEqual(ci1, ci2)

        # Single element
        ci_single = analyze.bootstrap_median_ci([15.5], seed=42)
        self.assertEqual(ci_single, (15.5, 15.5))

        # Empty array
        self.assertIsNone(analyze.bootstrap_median_ci([], seed=42))

    def test_continuous_stats_complete(self):
        # Empty array returns None stats without crash or zero substitution
        empty_res = analyze.compute_continuous_stats([])
        self.assertEqual(empty_res["count"], 0)
        self.assertIsNone(empty_res["median"])
        self.assertIsNone(empty_res["p95"])
        self.assertIsNone(empty_res["iqr"])
        self.assertIsNone(empty_res["mean"])
        self.assertIsNone(empty_res["median_ci_95"])

        # Regular array
        vals = [10.0, 20.0, 30.0, 40.0, 50.0]
        res = analyze.compute_continuous_stats(vals, seed=42)
        self.assertEqual(res["count"], 5)
        self.assertEqual(res["median"], 30.0)
        self.assertEqual(res["mean"], 30.0)
        self.assertEqual(res["iqr"], 20.0)  # Q3(40) - Q1(20) = 20
        self.assertIsNotNone(res["median_ci_95"])
        self.assertIsNotNone(res["mean_ci_95"])


class TestMissingData(unittest.TestCase):
    """Verifies that missing data is never replaced with zero and nulls are preserved."""

    def test_null_cad_preserved_in_aggregates(self):
        t_s0 = _create_synthetic_trial(trial_id="t-s0", scenario_id="S0", cad_ms=None)
        t_obj = _dict_to_evidence(t_s0)

        group_stats = analyze.aggregate_group_metrics([t_obj], "google-chrome", "S0")
        cad_stats = group_stats["connection_attempt_delay_ms"]

        self.assertEqual(cad_stats["count"], 0)
        self.assertIsNone(cad_stats["median"])
        self.assertIsNone(cad_stats["p95"])
        self.assertIsNone(cad_stats["iqr"])
        self.assertIsNone(cad_stats["mean"])

        # In CSV, verify it renders as empty string rather than '0' or '0.0'
        report = analyze.generate_analysis_report([t_obj], [])
        csv_str = analyze.generate_summary_csv(report)
        lines = csv_str.strip().split("\n")
        self.assertEqual(len(lines), 8)  # header + 7 scenarios S0-S6
        s0_row = [line for line in lines if "google-chrome,S0" in line][0]
        # In s0_row, setup_time has values, but cad fields are empty commas
        self.assertIn(",0,,,,,,,", s0_row)  # cad_n is 0, median, p95, iqr, ci lower, ci upper, mean are empty

    def test_empty_dns_observations_yield_none(self):
        dns_empty = {"queries": [], "responses": []}
        a_lat, aaaa_lat, res_time = analyze.extract_dns_latencies(dns_empty)
        self.assertIsNone(a_lat)
        self.assertIsNone(aaaa_lat)
        self.assertIsNone(res_time)

    def test_partial_dns_matching(self):
        # Only A query and response, no AAAA response
        dns_partial = {
            "queries": [
                {"qtype": "A", "timestamp": 100.0},
                {"qtype": "AAAA", "timestamp": 100.0}
            ],
            "responses": [
                {"qtype": "A", "timestamp": 100.015}
            ]
        }
        a_lat, aaaa_lat, res_time = analyze.extract_dns_latencies(dns_partial)
        self.assertEqual(a_lat, 15.0)
        self.assertIsNone(aaaa_lat)
        self.assertEqual(res_time, 15.0)


class TestMalformedRecords(unittest.TestCase):
    """Verifies graceful handling of corrupted JSON, schema mismatches, and broken records."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="ps028_test_malformed_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_corrupted_json_syntax(self):
        bad_json = self.test_dir / "broken.json"
        bad_json.write_text("{ this is not valid json : [", encoding="utf-8")

        evidence = analyze.load_trial_from_json(bad_json)
        self.assertEqual(evidence.validity_category, "CORRUPTED_RECORD")
        self.assertIn("Malformed JSON", evidence.exclusion_reason)

    def test_schema_version_mismatch(self):
        data = _create_synthetic_trial(trial_id="t-mismatch")
        data["schema_version"] = "99.0.0"
        trial_file = self.test_dir / "schema_mismatch.json"
        trial_file.write_text(json.dumps(data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(trial_file)
        self.assertEqual(evidence.validity_category, "CORRUPTED_RECORD")
        self.assertIn("Schema version mismatch", evidence.exclusion_reason)

    def test_missing_required_sections(self):
        data = _create_synthetic_trial(trial_id="t-missing-cleanup")
        del data["cleanup_status"]
        trial_file = self.test_dir / "missing_cleanup.json"
        trial_file.write_text(json.dumps(data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(trial_file)
        self.assertEqual(evidence.validity_category, "INCOMPLETE")
        self.assertIn("Missing cleanup_status", evidence.exclusion_reason)

    def test_nonexistent_file(self):
        nonexistent = self.test_dir / "does_not_exist.json"
        evidence = analyze.load_trial_from_json(nonexistent)
        self.assertEqual(evidence.validity_category, "INCOMPLETE")
        self.assertIn("File not found", evidence.exclusion_reason)


class TestExclusionsAndValidity(unittest.TestCase):
    """Verifies that invalid evidence, cleanup failures, and simulations are properly excluded."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="ps028_test_exclusions_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_simulation_separated_by_default(self):
        sim_data = _create_synthetic_trial(trial_id="t-sim", is_simulation=True)
        f = self.test_dir / "sim.json"
        f.write_text(json.dumps(sim_data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(f)
        self.assertEqual(evidence.validity_category, "SIMULATION")

        report = analyze.generate_analysis_report([evidence], [], include_simulations=False)
        self.assertEqual(report["dataset_summary"]["valid_live_count"], 0)
        self.assertEqual(report["dataset_summary"]["simulation_count"], 1)
        self.assertEqual(len(report["exclusions"]), 1)
        self.assertEqual(report["exclusions"][0]["category"], "SIMULATION")

    def test_zero_packet_capture_excluded(self):
        zero_pkt_data = _create_synthetic_trial(trial_id="t-zero", packet_count=0)
        f = self.test_dir / "zero.json"
        f.write_text(json.dumps(zero_pkt_data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(f)
        self.assertEqual(evidence.validity_category, "MEASUREMENT_FAILURE")
        self.assertIn("Zero-packet capture", evidence.exclusion_reason)

    def test_cleanup_failure_excluded(self):
        cl_fail_data = _create_synthetic_trial(trial_id="t-cl-fail", baseline_verified=False)
        f = self.test_dir / "cl_fail.json"
        f.write_text(json.dumps(cl_fail_data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(f)
        self.assertEqual(evidence.validity_category, "CLEANUP_FAILURE")
        self.assertIn("baseline_verified is False", evidence.exclusion_reason)

    def test_cleanup_errors_list_excluded(self):
        cl_err_data = _create_synthetic_trial(trial_id="t-cl-err", cleanup_errors=["Netns unmounted abnormally"])
        f = self.test_dir / "cl_err.json"
        f.write_text(json.dumps(cl_err_data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(f)
        self.assertEqual(evidence.validity_category, "CLEANUP_FAILURE")
        self.assertIn("Netns unmounted abnormally", evidence.exclusion_reason)

    def test_inconclusive_classification_excluded(self):
        inconcl_data = _create_synthetic_trial(trial_id="t-inconcl", classification="INCONCLUSIVE")
        f = self.test_dir / "inconcl.json"
        f.write_text(json.dumps(inconcl_data), encoding="utf-8")

        evidence = analyze.load_trial_from_json(f)
        self.assertEqual(evidence.validity_category, "MEASUREMENT_FAILURE")
        self.assertIn("Inconclusive network classification", evidence.exclusion_reason)


class TestReconciliation(unittest.TestCase):
    """Verifies reconciliation of campaign manifests, retry attempts, and pending slots."""

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="ps028_test_recon_"))
        self.trials_dir = self.test_dir / "trials"
        self.trials_dir.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_campaign_manifest_reconciliation(self):
        # Create trial 1 on disk (COMPLETED)
        t1_id = "trial-20261028-001"
        t1_dir = self.trials_dir / t1_id
        t1_dir.mkdir()
        t1_data = _create_synthetic_trial(trial_id=t1_id, scenario_id="S0")
        (t1_dir / "result.json").write_text(json.dumps(t1_data), encoding="utf-8")

        # Create trial 2 on disk (CLEANUP_FAILURE)
        t2_id = "trial-20261028-002"
        t2_dir = self.trials_dir / t2_id
        t2_dir.mkdir()
        t2_data = _create_synthetic_trial(trial_id=t2_id, scenario_id="S1", baseline_verified=False)
        (t2_dir / "result.json").write_text(json.dumps(t2_data), encoding="utf-8")

        # Create manifest
        manifest_data = {
            "schema_version": "1.0.0",
            "campaign_id": "campaign-test-recon",
            "status": "HALTED_ON_FAILURE",
            "execution_mode": "LIVE",
            "is_simulation": False,
            "configuration": {
                "scenarios": ["S0", "S1", "S2"],
                "browsers": ["google-chrome"],
                "repetitions": 1,
                "output_dir": str(self.test_dir)
            },
            "matrix_slots": [
                {
                    "slot_id": "slot-0001-S0-google-chrome-rep01",
                    "scenario_id": "S0",
                    "browser": "google-chrome",
                    "status": "COMPLETED",
                    "attempts": [
                        {
                            "attempt_number": 1,
                            "trial_id": t1_id,
                            "status": "COMPLETED",
                            "validity": "VALID_LIVE",
                            "evidence_paths": {"result_json": str(t1_dir / "result.json")}
                        }
                    ]
                },
                {
                    "slot_id": "slot-0002-S1-google-chrome-rep01",
                    "scenario_id": "S1",
                    "browser": "google-chrome",
                    "status": "FAILED",
                    "attempts": [
                        {
                            "attempt_number": 1,
                            "trial_id": t2_id,
                            "status": "FAILED",
                            "validity": "CLEANUP_FAILURE",
                            "evidence_paths": {"result_json": str(t2_dir / "result.json")},
                            "error_message": "Baseline verification failed"
                        }
                    ]
                },
                {
                    "slot_id": "slot-0003-S2-google-chrome-rep01",
                    "scenario_id": "S2",
                    "browser": "google-chrome",
                    "status": "PENDING",
                    "attempts": []
                }
            ]
        }
        manifest_file = self.test_dir / "campaign_manifest.json"
        manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

        trials, exclusions = analyze.load_campaign_manifest(manifest_file)

        # slot 1 should be loaded as valid trial
        self.assertEqual(len(trials), 2)
        valid_trials = [t for t in trials if t.is_valid_live()]
        self.assertEqual(len(valid_trials), 1)
        self.assertEqual(valid_trials[0].trial_id, t1_id)

        # slot 2 is cleanup failure
        failed_trials = [t for t in trials if t.validity_category == "CLEANUP_FAILURE"]
        self.assertEqual(len(failed_trials), 1)

        # slot 3 was pending with 0 attempts, so it's in exclusions as INCOMPLETE
        pending_excl = [e for e in exclusions if e.category == "INCOMPLETE"]
        self.assertEqual(len(pending_excl), 1)
        self.assertIn("slot-0003-S2", pending_excl[0].trial_id)


class TestRFC8305Assessment(unittest.TestCase):
    """
    Verifies that RFC 8305 evaluator accurately distinguishes observed conformance,
    observed deviation, and indeterminate results across normative timing boundaries.
    """

    def test_rfc8305_checks_status_types(self):
        """Verifies that all checks return one of the three standard status categories."""
        allowed_statuses = {"OBSERVED_CONFORMANCE", "OBSERVED_DEVIATION", "INDETERMINATE"}
        allowed_detail_statuses = {"OBSERVED_CONFORMANCE", "OBSERVED_DEVIATION", "INDETERMINATE", "NOT_APPLICABLE"}
        t_s0 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S0", winning_family="IPv6"))
        assessment = analyze.assess_rfc8305_conformance([t_s0])
        for c in assessment:
            self.assertIn(c["status"], allowed_statuses)
            self.assertIn(c["mandatory_status"], allowed_detail_statuses)
            self.assertIn(c["recommended_status"], allowed_detail_statuses)

    def test_s2_timing_boundaries(self):
        """
        RFC 8305 Section 5 distinguishes:
        - Mandatory: subsequent connection attempts MUST NOT start within 10 ms.
        - Recommended: minimum CAD of 100 ms.
        - Recommended: maximum CAD of 2 seconds.

        Verifies that:
        - 2.65ms (live observation) and 9.99ms are classified as OBSERVED_DEVIATION for mandatory-floor violation.
        - 10ms, 25ms, and 99.99ms meet mandatory MUST requirements (mandatory_status=OBSERVED_CONFORMANCE)
          while deviating from recommended parameters (recommended_status=OBSERVED_DEVIATION,
          overall status=OBSERVED_DEVIATION). They are not labeled as MUST violations.
        - 100ms and 2000ms meet both mandatory and recommended bounds (OBSERVED_CONFORMANCE).
        - 2000.01ms meets mandatory floor but exceeds recommended 2-second upper bound (OBSERVED_DEVIATION).
        - Missing timing data returns INDETERMINATE.
        """
        # 1. Live trial observation: 2.65ms (< 10ms mandatory floor) -> OBSERVED_DEVIATION
        t_s2_live = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=2.65))
        res = analyze.assess_rfc8305_conformance([t_s2_live])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("mandatory-floor deviation", check["evidence_summary"])
        self.assertIn("< 10ms", check["evidence_summary"])

        # 2. Boundary: 9.99ms (< 10ms mandatory floor) -> OBSERVED_DEVIATION
        t_s2_sub10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=9.99))
        res = analyze.assess_rfc8305_conformance([t_s2_sub10])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("mandatory-floor deviation", check["evidence_summary"])

        # 3. Boundary: 10ms (exact mandatory floor; < 100ms recommended minimum) -> OBSERVED_DEVIATION
        t_s2_exact_10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=10.0))
        res = analyze.assess_rfc8305_conformance([t_s2_exact_10])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("mandatory_status=OBSERVED_CONFORMANCE", check["evidence_summary"])
        self.assertIn("not a mandatory MUST violation", check["evidence_summary"])

        # 4. Boundary: 25ms (meets MUST >= 10ms, < 100ms recommended min) -> OBSERVED_DEVIATION
        t_s2_25 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=25.0))
        res = analyze.assess_rfc8305_conformance([t_s2_25])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("mandatory_status=OBSERVED_CONFORMANCE", check["evidence_summary"])
        self.assertIn("not a mandatory MUST violation", check["evidence_summary"])

        # 5. Boundary: 99.99ms (meets MUST >= 10ms, < 100ms recommended min) -> OBSERVED_DEVIATION
        t_s2_sub100 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=99.99))
        res = analyze.assess_rfc8305_conformance([t_s2_sub100])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("not a mandatory MUST violation", check["evidence_summary"])

        # 6. Boundary: 100ms (exact recommended minimum bound) -> OBSERVED_CONFORMANCE
        t_s2_exact_100 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=100.0))
        res = analyze.assess_rfc8305_conformance([t_s2_exact_100])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

        # 7. Boundary: 2000ms (exact 2-second upper bound) -> OBSERVED_CONFORMANCE
        t_s2_exact_2000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=2000.0))
        res = analyze.assess_rfc8305_conformance([t_s2_exact_2000])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

        # 8. Boundary: 2000.01ms (> 2000ms upper bound) -> OBSERVED_DEVIATION
        t_s2_over_2000_01 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=2000.01))
        res = analyze.assess_rfc8305_conformance([t_s2_over_2000_01])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("not a mandatory MUST violation", check["evidence_summary"])

        # 9. Missing timing data (cad_ms is None) -> INDETERMINATE
        t_s2_nocad = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=None))
        res = analyze.assess_rfc8305_conformance([t_s2_nocad])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "INDETERMINATE")
        self.assertEqual(check["mandatory_status"], "INDETERMINATE")
        self.assertEqual(check["recommended_status"], "INDETERMINATE")

    def test_s1_timing_boundaries(self):
        """
        RFC 8305 Section 5 specifies permitted CAD range [100ms, 2000ms] (recommended target: 250ms),
        with an absolute minimum of 10ms.
        """
        # CAD < 10ms -> OBSERVED_DEVIATION (mandatory floor deviation)
        t_s1_sub10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=8.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_sub10]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")

        # CAD = 9.99ms (rounded < 10ms) -> OBSERVED_DEVIATION
        t_s1_sub10_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=9.99))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_sub10_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_DEVIATION")

        # CAD < 100ms (e.g. 25ms, 99.9ms) -> OBSERVED_DEVIATION (recommended range deviation, meets MUST floor)
        t_s1_25 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=25.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_25]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")

        t_s1_fast = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=99.9))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_fast]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")

        # CAD = 99.99ms (rounded < 100ms) -> OBSERVED_DEVIATION
        t_s1_fast_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=99.99))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_fast_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")

        # CAD == 100.0ms (exact minimum bound) -> OBSERVED_CONFORMANCE
        t_s1_exact_min = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=100.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_min]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

        # CAD == 100.00ms (rounded exact minimum bound) -> OBSERVED_CONFORMANCE
        t_s1_exact_min_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=100.00))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_min_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")

        # CAD == 250.0ms (recommended default) -> OBSERVED_CONFORMANCE
        t_s1_target = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=250.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_target]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")

        # CAD == 301.19ms (live S1 trial observation) -> OBSERVED_CONFORMANCE
        t_s1_live = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=301.19))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_live]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")

        # CAD == 2000.0ms (exact upper bound) -> OBSERVED_CONFORMANCE
        t_s1_exact_max = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_max]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

        # CAD == 2000.00ms (rounded exact upper bound) -> OBSERVED_CONFORMANCE
        t_s1_exact_max_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.00))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_max_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")

        # CAD == 2000.01ms (> 2000ms) -> OBSERVED_DEVIATION
        t_s1_over_01 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.01))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_over_01]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")

        # CAD == 2000.1ms (> 2000ms) -> OBSERVED_DEVIATION
        t_s1_over = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.1))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_over]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")

    def test_s4_timing_boundaries(self):
        """Verifies alternative path selection under 600ms IPv6 RTT."""
        # IPv4 won + CAD in bounds (294.87ms) -> OBSERVED_CONFORMANCE
        t_s4_ok = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=294.87))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_ok]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")

        # IPv4 won + CAD < 10ms -> OBSERVED_DEVIATION
        t_s4_fast = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=5.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_fast]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")

        # IPv6 won (didn't switch to IPv4 despite 600ms RTT) -> OBSERVED_DEVIATION
        t_s4_nowin = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv6", cad_ms=None))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_nowin]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")

    def test_s6_chrome_trial_scoped_deviation(self):
        """
        Verifies that S6 conclusion is specifically scoped to the recorded Chrome trial
        and disclaims general browser non-conformance.
        """
        t_s6 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None, dns_aaaa_lat=515.27
        ))
        assessment = analyze.assess_rfc8305_conformance([t_s6])
        check = [c for c in assessment if c["scenario_id"] == "S6"][0]

        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertIn("recorded Chrome trial", check["evidence_summary"])
        self.assertIn("strictly scoped", check["evidence_summary"])
        self.assertIn("not an inference of general browser implementation", check["reasoning"])

    def test_missing_evidence_all_scenarios_indeterminate(self):
        """Verifies that an empty dataset marks all checks INDETERMINATE with sample_size 0."""
        assessment = analyze.assess_rfc8305_conformance([])
        self.assertEqual(len(assessment), 7)
        for check in assessment:
            self.assertEqual(check["status"], "INDETERMINATE")
            self.assertEqual(check["sample_size"], 0)
            self.assertIn("Indeterminate", check["evidence_summary"])

    def test_partial_scenarios_missing_evidence_indeterminate(self):
        """Verifies that when only S0 is tested, S1, S2, S4, and S6 are marked INDETERMINATE."""
        t_s0 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S0", winning_family="IPv6"))
        assessment = analyze.assess_rfc8305_conformance([t_s0])
        status_map = {c["scenario_id"]: c["status"] for c in assessment}

        self.assertEqual(status_map["S0"], "OBSERVED_CONFORMANCE")
        self.assertEqual(status_map["S1"], "INDETERMINATE")
        self.assertEqual(status_map["S2"], "INDETERMINATE")
        self.assertEqual(status_map["S4"], "INDETERMINATE")
        self.assertEqual(status_map["S6"], "INDETERMINATE")
        self.assertEqual(status_map["ALL"], "INDETERMINATE")

    def test_missing_cad_in_trial_returns_indeterminate(self):
        """Verifies that S1 or S2 trials without CAD measurement return INDETERMINATE."""
        t_s1_nocad = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", cad_ms=None))
        check1 = [c for c in analyze.assess_rfc8305_conformance([t_s1_nocad]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check1["status"], "INDETERMINATE")
        self.assertIn("missing connection attempt delay", check1["evidence_summary"])

        t_s2_nocad = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", cad_ms=None))
        check2 = [c for c in analyze.assess_rfc8305_conformance([t_s2_nocad]) if c["scenario_id"] == "S2"][0]
        self.assertEqual(check2["status"], "INDETERMINATE")
        self.assertIn("missing connection attempt delay", check2["evidence_summary"])

    def test_unsupported_checks_remain_indeterminate(self):
        """Verifies that Section 7 (statefulness) and Section 8 (transports) remain INDETERMINATE."""
        t_s0 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S0", winning_family="IPv6"))
        assessment = analyze.assess_rfc8305_conformance([t_s0])
        check_map = {c["check_id"]: c for c in assessment}

        sec7 = check_map["RFC8305-SEC7-STATEFULNESS-CACHING"]
        self.assertEqual(sec7["status"], "INDETERMINATE")
        self.assertIn("Unsupported check", sec7["evidence_summary"])

        sec8 = check_map["RFC8305-SEC8-NON-TCP-TRANSPORTS"]
        self.assertEqual(sec8["status"], "INDETERMINATE")
        self.assertIn("Unsupported check", sec8["evidence_summary"])


class TestDeterministicOutput(unittest.TestCase):
    """Verifies that generated JSON and CSV summaries are 100% deterministic."""

    def test_deterministic_json_and_csv_equality(self):
        t1 = _create_synthetic_trial(trial_id="t-001", scenario_id="S0")
        t2 = _create_synthetic_trial(trial_id="t-002", scenario_id="S1", winning_family="IPv4", cad_ms=300.0)

        ev1 = _dict_to_evidence(t1)
        ev2 = _dict_to_evidence(t2)

        rep1 = analyze.generate_analysis_report([ev1, ev2], [], seed=42)
        rep2 = analyze.generate_analysis_report([ev1, ev2], [], seed=42)

        # Strip timestamps for exact structural equality
        rep1_clean = copy.deepcopy(rep1)
        rep2_clean = copy.deepcopy(rep2)
        del rep1_clean["generated_at"]
        del rep2_clean["generated_at"]

        json1 = json.dumps(rep1_clean, indent=2, sort_keys=True)
        json2 = json.dumps(rep2_clean, indent=2, sort_keys=True)
        self.assertEqual(json1, json2)

        csv1 = analyze.generate_summary_csv(rep1)
        csv2 = analyze.generate_summary_csv(rep2)
        self.assertEqual(csv1, csv2)


class TestLiveEvidenceIntegration(unittest.TestCase):
    """
    Executes analyze.py against the repository's genuine lab/trials/ directory.
    Validates against the documented runbook baseline without modifying files.
    """

    def test_live_trials_analysis(self):
        trials_dir = SCRIPT_DIR / "trials"
        if not trials_dir.is_dir():
            self.skipTest("lab/trials directory not present")

        trials, exclusions = analyze.ingest_evidence([trials_dir])
        self.assertEqual(len(trials), 9)

        report = analyze.generate_analysis_report(trials, exclusions, seed=42)
        ds = report["dataset_summary"]

        # 8 valid live trials, 1 measurement failure (trial-20261028083344-ccc4810f)
        self.assertEqual(ds["valid_live_count"], 8)
        self.assertEqual(ds["excluded_failures_count"], 1)

        # Check exclusions
        excl = report["exclusions"]
        self.assertEqual(len(excl), 1)
        self.assertEqual(excl[0]["trial_id"], "trial-20261028083344-ccc4810f")
        self.assertIn("Zero-packet capture", excl[0]["reason"])

        # Check scenario metrics against runbook observations
        group_map = {g["scenario_id"]: g for g in report["groups"]}

        # S1: CAD ~ 301.19 ms
        s1 = group_map["S1"]
        self.assertEqual(s1["winning_address_family"]["ipv4"]["count"], 1)
        self.assertAlmostEqual(s1["connection_attempt_delay_ms"]["median"], 301.19, places=1)

        # S2: CAD ~ 2.65 ms
        s2 = group_map["S2"]
        self.assertEqual(s2["winning_address_family"]["ipv4"]["count"], 1)
        self.assertAlmostEqual(s2["connection_attempt_delay_ms"]["median"], 2.65, places=1)

        # S4: CAD ~ 294.87 ms, IPv4 won
        s4 = group_map["S4"]
        self.assertEqual(s4["winning_address_family"]["ipv4"]["count"], 1)
        self.assertAlmostEqual(s4["connection_attempt_delay_ms"]["median"], 294.87, places=1)

        # S6: delayed AAAA ~ 515.27 ms, IPv6 won
        s6 = group_map["S6"]
        self.assertEqual(s6["winning_address_family"]["ipv6"]["count"], 1)
        self.assertAlmostEqual(s6["dns_latency"]["aaaa_record_ms"]["median"], 515.27, places=1)

        # Check RFC 8305 assessment results on live evidence:
        # S0: IPv6 preference confirmed
        # S1: CAD in bounds [100ms, 2000ms]
        # S2: CAD 2.65ms < 10ms normative lower bound -> OBSERVED_DEVIATION
        # S4: IPv4 won with CAD 294.87ms in bounds
        # S6: Chrome waited ~515ms for AAAA -> OBSERVED_DEVIATION
        # SEC7, SEC8: INDETERMINATE (unsupported checks)
        rfc_map = {a["check_id"]: a["status"] for a in report["rfc8305_assessment"]}
        self.assertEqual(rfc_map["RFC8305-SEC3-IPV6-PREFERENCE"], "OBSERVED_CONFORMANCE")
        self.assertEqual(rfc_map["RFC8305-SEC5-IMMEDIATE-RST-FALLBACK"], "OBSERVED_DEVIATION")
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-SYN-TIMEOUT"], "OBSERVED_CONFORMANCE")
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-HIGH-LATENCY"], "OBSERVED_CONFORMANCE")
        self.assertEqual(rfc_map["RFC8305-SEC4-RESOLUTION-DELAY"], "OBSERVED_DEVIATION")
        self.assertEqual(rfc_map["RFC8305-SEC7-STATEFULNESS-CACHING"], "INDETERMINATE")
        self.assertEqual(rfc_map["RFC8305-SEC8-NON-TCP-TRANSPORTS"], "INDETERMINATE")


if __name__ == "__main__":
    unittest.main()
