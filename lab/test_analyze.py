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


from typing import Any


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
    classification: str = "DIRECT_IPV6",
    ipv4_attempt: Any = None,
    ipv6_attempt: Any = True,
    ipv4_success: Any = None,
    ipv6_success: Any = None,
    ipv4_attempt_timestamp: Any = None,
    ipv4_syn_timestamp: Any = None,
    ipv4_attempt_start_time: Any = None,
    empty_dns_address: bool = False,
    dns_a_address: str = None,
    dns_aaaa_address: str = None,
    dns_qname: str = None,
    hostname: str = None,
    omit_response_qname: bool = False,
    http_outcome: Any = "DEFAULT"
) -> dict:
    dns_queries = []
    dns_responses = []
    t0 = 1793200000.0

    h_name = hostname if hostname is not None else f"{trial_id}.he.test"
    q_name = dns_qname if dns_qname is not None else h_name

    if dns_a_lat is not None:
        dns_queries.append({"qname": q_name, "qtype": "A", "timestamp": t0})
        addr = dns_a_address if dns_a_address is not None else ("" if empty_dns_address else "10.0.2.10")
        resp_a = {"qtype": "A", "address": addr, "timestamp": t0 + dns_a_lat / 1000.0}
        if not omit_response_qname:
            resp_a["qname"] = q_name
        dns_responses.append(resp_a)

    if dns_aaaa_lat is not None:
        # If dns_a_lat is present, AAAA timestamp is relative to t0 + dns_aaaa_lat/1000.0
        # If dns_a_lat is None, use t0 + dns_aaaa_lat/1000.0
        ts_aaaa = t0 + (dns_aaaa_lat / 1000.0) if dns_a_lat is None else (t0 + dns_aaaa_lat / 1000.0)
        dns_queries.append({"qname": q_name, "qtype": "AAAA", "timestamp": t0 + 0.001})
        addr = dns_aaaa_address if dns_aaaa_address is not None else ("" if empty_dns_address else "2001:db8:2::10")
        resp_aaaa = {"qtype": "AAAA", "address": addr, "timestamp": ts_aaaa}
        if not omit_response_qname:
            resp_aaaa["qname"] = q_name
        dns_responses.append(resp_aaaa)

    resolved_v4_attempt = (winning_family == "IPv4" or cad_ms is not None) if ipv4_attempt is None else ipv4_attempt

    net_obs = {
        "ipv6_attempt": ipv6_attempt,
        "ipv4_attempt": resolved_v4_attempt,
        "ipv6_success": (winning_family == "IPv6") if ipv6_success is None else ipv6_success,
        "ipv4_success": (winning_family == "IPv4") if ipv4_success is None else ipv4_success,
        "connection_attempt_delay_ms": cad_ms,
        "connection_setup_time_ms": setup_time_ms,
        "fallback_occurred": (cad_ms is not None),
        "classification": classification,
        "classification_reason": "Synthetic test classification"
    }
    if ipv4_attempt_timestamp is not None:
        net_obs["ipv4_attempt_timestamp"] = ipv4_attempt_timestamp
    if ipv4_syn_timestamp is not None:
        net_obs["ipv4_syn_timestamp"] = ipv4_syn_timestamp
    if ipv4_attempt_start_time is not None:
        net_obs["ipv4_attempt_start_time"] = ipv4_attempt_start_time

    if http_outcome == "DEFAULT":
        resolved_http = {
            "status_code": 200 if http_success else 500,
            "success": http_success,
            "winning_address_family": winning_family,
            "winning_ip": "2001:db8:2::10" if winning_family == "IPv6" else "10.0.2.10",
            "response_body_bytes": 300
        }
    else:
        resolved_http = http_outcome

    return {
        "schema_version": "1.0.0",
        "trial_id": trial_id,
        "scenario_id": scenario_id,
        "scenario_name": analyze.SCENARIO_NAMES.get(scenario_id, "unknown"),
        "hostname": h_name,
        "target_url": f"http://{h_name}/",
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
        "http_outcome": resolved_http,
        "dns_observations": {
            "queries": dns_queries,
            "responses": dns_responses
        },
        "network_observations": net_obs,
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
    net_obs = d.get("network_observations") if isinstance(d.get("network_observations"), dict) else {}
    raw_http = d.get("http_outcome")
    http = raw_http if isinstance(raw_http, dict) else {}
    dns = d.get("dns_observations") if isinstance(d.get("dns_observations"), dict) else {}
    browser = d.get("browser") if isinstance(d.get("browser"), dict) else {}
    cleanup = d.get("cleanup_status") if isinstance(d.get("cleanup_status"), dict) else {}
    capture = d.get("capture_metadata") if isinstance(d.get("capture_metadata"), dict) else {}
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
        source_path="/tmp",
        raw_dict=d
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
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

        # IPv4 won + CAD < 10ms -> OBSERVED_DEVIATION (mandatory floor violation, recommendation conformance)
        t_s4_fast = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=5.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_fast]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

        # IPv6 won (didn't switch to IPv4 despite 600ms RTT, no subsequent attempt) -> OBSERVED_DEVIATION at recommendation level, NOT_APPLICABLE for mandatory floor
        t_s4_nowin = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv6", cad_ms=None))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_nowin]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")

    def test_s6_a_preceding_aaaa_sub_50ms(self):
        """1. S6 A response preceding AAAA by less than 50 ms -> OBSERVED_CONFORMANCE."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=30.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")
        self.assertIn("Observed conformance", check["evidence_summary"])

    def test_s6_a_preceding_aaaa_over_50ms_no_ipv4_attempt(self):
        """2. S6 A response preceding AAAA by more than 50 ms with no IPv4 attempt -> OBSERVED_DEVIATION."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("Observed recommendation-level deviation", check["evidence_summary"])
        self.assertNotIn("trial-20261028171417-b2d83f2f", check["evidence_summary"])
        self.assertNotIn("515.27", check["evidence_summary"])

    def test_s6_late_aaaa_with_ipv4_attempt_no_timestamp(self):
        """3. S6 late AAAA with an IPv4 attempt but no attempt timestamp -> INDETERMINATE."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=None
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["status"], "INDETERMINATE")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "INDETERMINATE")
        self.assertIn("Indeterminate", check["evidence_summary"])

    def test_s6_missing_positive_dns_evidence(self):
        """4. S6 missing positive DNS response evidence -> INDETERMINATE."""
        # Missing A response
        t_no_a = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_lat=None, dns_aaaa_lat=500.0
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t_no_a]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "INDETERMINATE")

        # Empty address in response (not a positive response)
        t_empty_addr = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_lat=5.0, dns_aaaa_lat=500.0, empty_dns_address=True
        ))
        check2 = [c for c in analyze.assess_rfc8305_conformance([t_empty_addr]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check2["status"], "INDETERMINATE")

    def test_s6_multiple_browsers_and_aggregate_counts(self):
        """5. S6 multiple browsers and aggregate counts."""
        t_chrome = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s6-chrome", browser_name="google-chrome",
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=505.0, ipv4_attempt=False
        ))
        t_firefox = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s6-firefox", browser_name="firefox",
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=505.0, ipv4_attempt=False
        ))
        assessment = analyze.assess_rfc8305_conformance([t_chrome, t_firefox])
        check = [c for c in assessment if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["sample_size"], 2)
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertIn("Google Chrome", check["evidence_summary"])
        self.assertIn("Firefox", check["evidence_summary"])
        self.assertIn("2/2 trials with observed deviation", check["evidence_summary"])

    def test_s4_all_ipv4_wins_valid_cad(self):
        """6. S4 all IPv4 wins with valid CAD -> OBSERVED_CONFORMANCE."""
        t1 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-c1", browser_name="google-chrome", scenario_id="S4", winning_family="IPv4", cad_ms=250.0
        ))
        t2 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-f1", browser_name="firefox", scenario_id="S4", winning_family="IPv4", cad_ms=300.0
        ))
        assessment = analyze.assess_rfc8305_conformance([t1, t2])
        check = [c for c in assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")
        self.assertIn("IPv4 won in 2/2 trials", check["evidence_summary"])

    def test_s4_mixed_outcomes_with_one_ipv6_exception(self):
        """7. S4 mixed outcomes with exactly one IPv6-winning exception."""
        trials = []
        for i in range(20):
            trials.append(_dict_to_evidence(_create_synthetic_trial(
                trial_id=f"t-s4-c-{i}", browser_name="google-chrome", scenario_id="S4",
                winning_family="IPv4", cad_ms=300.80
            )))
        for i in range(19):
            trials.append(_dict_to_evidence(_create_synthetic_trial(
                trial_id=f"t-s4-f-{i}", browser_name="firefox", scenario_id="S4",
                winning_family="IPv4", cad_ms=397.94
            )))
        # 1 Firefox IPv6 win
        trials.append(_dict_to_evidence(_create_synthetic_trial(
            trial_id="trial-20261029222109-5c74c26a", browser_name="firefox", scenario_id="S4",
            winning_family="IPv6", cad_ms=None
        )))
        assessment = analyze.assess_rfc8305_conformance(trials)
        check = [c for c in assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["sample_size"], 40)
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("39/40", check["evidence_summary"])
        self.assertIn("Google Chrome: 20/20", check["evidence_summary"])
        self.assertIn("Firefox: 19/20", check["evidence_summary"])
        self.assertIn("trial-20261029222109-5c74c26a", check["evidence_summary"])

    def test_s4_browser_filtering(self):
        """8. S4 browser filtering distinguishes browser cohorts."""
        trials = []
        for i in range(5):
            trials.append(_dict_to_evidence(_create_synthetic_trial(
                trial_id=f"t-s4-c-{i}", browser_name="google-chrome", scenario_id="S4",
                winning_family="IPv4", cad_ms=300.0
            )))
        for i in range(4):
            trials.append(_dict_to_evidence(_create_synthetic_trial(
                trial_id=f"t-s4-f-{i}", browser_name="firefox", scenario_id="S4",
                winning_family="IPv4", cad_ms=350.0
            )))
        trials.append(_dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-f-v6", browser_name="firefox", scenario_id="S4",
            winning_family="IPv6", cad_ms=None
        )))

        # Chrome alone: 5/5 IPv4 wins -> OBSERVED_CONFORMANCE
        chrome_assessment = analyze.assess_rfc8305_conformance(trials, browser="google-chrome")
        c_check = [c for c in chrome_assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_check["recommended_status"], "OBSERVED_CONFORMANCE")

        # Firefox alone: 4/5 IPv4 wins + 1 IPv6 win -> OBSERVED_DEVIATION
        firefox_assessment = analyze.assess_rfc8305_conformance(trials, browser="firefox")
        f_check = [c for c in firefox_assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(f_check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(f_check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(f_check["recommended_status"], "OBSERVED_DEVIATION")

    def test_s4_mandatory_10ms_vs_recommended_100ms_boundary(self):
        """9. S4 mandatory 10 ms boundary versus recommended 100 ms boundary."""
        # CAD < 10ms (5ms) -> mandatory violation, recommendation conformance
        t_sub10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=5.0))
        c_sub10 = [c for c in analyze.assess_rfc8305_conformance([t_sub10]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_sub10["status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_sub10["mandatory_status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_sub10["recommended_status"], "OBSERVED_CONFORMANCE")

        # CAD = 10ms (meets mandatory >= 10ms, but < 100ms recommended) -> recommendation deviation
        t_10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=10.0))
        c_10 = [c for c in analyze.assess_rfc8305_conformance([t_10]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_10["status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_10["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_10["recommended_status"], "OBSERVED_DEVIATION")

        # CAD = 50ms (meets mandatory >= 10ms, but < 100ms recommended) -> recommendation deviation
        t_50 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=50.0))
        c_50 = [c for c in analyze.assess_rfc8305_conformance([t_50]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_50["status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_50["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_50["recommended_status"], "OBSERVED_DEVIATION")

        # CAD = 100ms (exact recommended minimum) -> OBSERVED_CONFORMANCE
        t_100 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=100.0))
        c_100 = [c for c in analyze.assess_rfc8305_conformance([t_100]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_100["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_100["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_100["recommended_status"], "OBSERVED_CONFORMANCE")

    def test_s4_recommended_2s_upper_bound(self):
        """10. S4 recommended 2-second upper bound."""
        # CAD = 2000ms -> in bounds
        t_2000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.0))
        c_2000 = [c for c in analyze.assess_rfc8305_conformance([t_2000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_2000["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_2000["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_2000["recommended_status"], "OBSERVED_CONFORMANCE")

        # CAD = 2000.01ms -> exceeds recommended upper bound, meets mandatory floor
        t_over = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.01))
        c_over = [c for c in analyze.assess_rfc8305_conformance([t_over]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_over["status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_over["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_over["recommended_status"], "OBSERVED_DEVIATION")

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

    # --------------------------------------------------------------------------
    # S6 Regression Tests (Phase 2A Review Corrections - Batch 2)
    # --------------------------------------------------------------------------

    def test_s6_exactly_50ms_a_to_aaaa_conformance(self):
        """S6 1: Exactly 50.0 ms A-to-AAAA interval -> OBSERVED_CONFORMANCE."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=50.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")
        self.assertIn("conforming", check["evidence_summary"])

    def test_s6_over_50ms_no_ipv4_attempt_deviation(self):
        """S6 2: More than 50 ms A-to-AAAA (50.1 ms) with no IPv4 attempt -> OBSERVED_DEVIATION."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=50.1, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("observed deviation", check["evidence_summary"])

    def test_s6_ipv4_attempt_at_exactly_50ms_conformance(self):
        """S6 3: IPv4 attempt initiated at exactly 50.0 ms after positive A -> OBSERVED_CONFORMANCE."""
        t0 = 1793200000.0
        # A response arrives at t0 + 0.0s. IPv4 attempt at t0 + 0.050s (50.0ms).
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=t0 + 0.050
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")
        self.assertIn("1/1 trials conforming", check["evidence_summary"])

    def test_s6_ipv4_attempt_just_above_50ms_deviation(self):
        """S6 4: IPv4 attempt initiated just above 50 ms (50.5 ms) -> OBSERVED_DEVIATION."""
        t0 = 1793200000.0
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=t0 + 0.0505
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("1/1 trials with observed deviation", check["evidence_summary"])

    def test_s6_negative_attempt_timestamp_indeterminate(self):
        """S6 5: Negative IPv4 attempt timestamp -> INDETERMINATE."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=-10.0
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "INDETERMINATE")
        self.assertEqual(check["recommended_status"], "INDETERMINATE")
        self.assertIn("indeterminate", check["evidence_summary"])

    def test_s6_nan_and_infinite_attempt_timestamps_indeterminate(self):
        """S6 6: NaN and infinite IPv4 attempt timestamps -> INDETERMINATE."""
        t_nan = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=float("nan")
        ))
        c_nan = [c for c in analyze.assess_rfc8305_conformance([t_nan]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_nan["status"], "INDETERMINATE")

        t_inf = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=float("inf")
        ))
        c_inf = [c for c in analyze.assess_rfc8305_conformance([t_inf]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_inf["status"], "INDETERMINATE")

    def test_s6_invalid_and_missing_timestamps_indeterminate(self):
        """S6 7: Non-numeric, boolean, preceding-A, and missing timestamps -> INDETERMINATE."""
        t0 = 1793200000.0
        # Non-numeric string
        t_str = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp="invalid-timestamp"
        ))
        c_str = [c for c in analyze.assess_rfc8305_conformance([t_str]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_str["status"], "INDETERMINATE")

        # Boolean timestamp
        t_bool = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=True
        ))
        c_bool = [c for c in analyze.assess_rfc8305_conformance([t_bool]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_bool["status"], "INDETERMINATE")

        # Timestamp preceding positive A response (contradictory chronology)
        t_pre = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=t0  # precedes positive A at t0 + 0.005s
        ))
        c_pre = [c for c in analyze.assess_rfc8305_conformance([t_pre]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_pre["status"], "INDETERMINATE")

        # Missing timestamp when ipv4_attempt=True
        t_none = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=None
        ))
        c_none = [c for c in analyze.assess_rfc8305_conformance([t_none]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_none["status"], "INDETERMINATE")

    def test_s6_mixed_deviation_conformance_indeterminate_counts(self):
        """S6 8: Dataset with deviation, conformance, and indeterminate records reports all 3 counts."""
        t_dev = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s6-dev", scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=False
        ))
        t_conf = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s6-conf", scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=30.0, ipv4_attempt=False
        ))
        t_indet = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s6-indet", scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True, ipv4_attempt_timestamp=None
        ))
        assessment = analyze.assess_rfc8305_conformance([t_dev, t_conf, t_indet])
        check = [c for c in assessment if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["sample_size"], 3)
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        # All three counts visible in summary
        self.assertIn("1/3 trials with observed deviation", check["evidence_summary"])
        self.assertIn("1/3 conforming", check["evidence_summary"])
        self.assertIn("1/3 indeterminate", check["evidence_summary"])

    def test_s6_malformed_attempt_flags_and_contradictions(self):
        """S6 9: Malformed attempt flags and contradictory winner/success observations -> INDETERMINATE."""
        # Non-boolean ipv4_attempt
        t_str_att = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt="yes", dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c1 = [c for c in analyze.assess_rfc8305_conformance([t_str_att]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c1["status"], "INDETERMINATE")

        # Non-boolean ipv6_attempt
        t_str_v6 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv6_attempt="yes", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c2 = [c for c in analyze.assess_rfc8305_conformance([t_str_v6]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c2["status"], "INDETERMINATE")

        # Contradiction: ipv4_success without ipv4_attempt
        t_contra1 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt=False, ipv4_success=True, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c3 = [c for c in analyze.assess_rfc8305_conformance([t_contra1]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c3["status"], "INDETERMINATE")

        # Contradiction: winning IPv4 without ipv4_attempt
        t_contra2 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c4 = [c for c in analyze.assess_rfc8305_conformance([t_contra2]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c4["status"], "INDETERMINATE")

        # Contradiction: winning IPv6 without ipv6_attempt
        t_contra3 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", ipv6_attempt=False, ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c5 = [c for c in analyze.assess_rfc8305_conformance([t_contra3]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c5["status"], "INDETERMINATE")

    def test_s6_invalid_address_families_and_unrelated_hostnames(self):
        """S6 10: Invalid address families or unrelated DNS query names -> INDETERMINATE."""
        # A record with IPv6 address
        t_bad_a = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_address="2001:db8::1", dns_aaaa_lat=500.0
        ))
        c1 = [c for c in analyze.assess_rfc8305_conformance([t_bad_a]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c1["status"], "INDETERMINATE")

        # AAAA record with IPv4 address
        t_bad_aaaa = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_lat=0.0, dns_aaaa_address="10.0.0.1"
        ))
        c2 = [c for c in analyze.assess_rfc8305_conformance([t_bad_aaaa]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c2["status"], "INDETERMINATE")

        # Unrelated DNS qname
        t_unrelated = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", hostname="target.he.test", dns_qname="unrelated.example.com",
            dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c3 = [c for c in analyze.assess_rfc8305_conformance([t_unrelated]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c3["status"], "INDETERMINATE")

    # --------------------------------------------------------------------------
    # S4 Regression Tests (Phase 2A Review Corrections - Batch 2)
    # --------------------------------------------------------------------------

    def test_s4_direct_ipv6_without_subsequent_attempt_mandatory_not_applicable(self):
        """S4 1: One direct IPv6 trial without a subsequent attempt -> mandatory NOT_APPLICABLE."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("NOT_APPLICABLE", check["evidence_summary"])

    def test_s4_ipv4_attempt_with_missing_cad(self):
        """S4 2: An IPv4 attempt with missing CAD is indeterminate unless confirmed deviation exists."""
        # Single trial with subsequent IPv4 attempt but missing CAD
        t_missing_cad = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv4", cad_ms=None, ipv4_attempt=True
        ))
        check1 = [c for c in analyze.assess_rfc8305_conformance([t_missing_cad]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check1["status"], "INDETERMINATE")
        self.assertEqual(check1["mandatory_status"], "INDETERMINATE")
        self.assertEqual(check1["recommended_status"], "INDETERMINATE")

        # Missing CAD combined with an independently confirmed deviation (IPv6 win)
        t_v6_dev = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-v6", scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        ))
        check2 = [c for c in analyze.assess_rfc8305_conformance([t_missing_cad, t_v6_dev]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check2["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check2["mandatory_status"], "INDETERMINATE")
        self.assertEqual(check2["recommended_status"], "OBSERVED_DEVIATION")

    def test_s4_cad_sub_100ms_median_in_range(self):
        """S4 3: One CAD below 100 ms and another in range, where median is in range."""
        t1 = _dict_to_evidence(_create_synthetic_trial(trial_id="t1", scenario_id="S4", winning_family="IPv4", cad_ms=50.0))
        t2 = _dict_to_evidence(_create_synthetic_trial(trial_id="t2", scenario_id="S4", winning_family="IPv4", cad_ms=250.0))
        t3 = _dict_to_evidence(_create_synthetic_trial(trial_id="t3", scenario_id="S4", winning_family="IPv4", cad_ms=300.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t1, t2, t3]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        # Median is 250ms (in range): summary must accurately report individual count and NOT claim median violates threshold
        self.assertIn("1 trial(s) measured CAD < 100ms recommended floor", check["evidence_summary"])
        self.assertNotIn("median 250.00ms < 100ms", check["evidence_summary"])
        self.assertIn("1/3 < 100ms", check["evidence_summary"])
        self.assertIn("2/3 in recommended range", check["evidence_summary"])

    def test_s4_cad_over_2000ms_median_in_range(self):
        """S4 4: One CAD above 2000 ms and another in range, where median is in range."""
        t1 = _dict_to_evidence(_create_synthetic_trial(trial_id="t1", scenario_id="S4", winning_family="IPv4", cad_ms=2500.0))
        t2 = _dict_to_evidence(_create_synthetic_trial(trial_id="t2", scenario_id="S4", winning_family="IPv4", cad_ms=250.0))
        t3 = _dict_to_evidence(_create_synthetic_trial(trial_id="t3", scenario_id="S4", winning_family="IPv4", cad_ms=300.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t1, t2, t3]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        # Median is 300ms (in range): summary must report individual count without accusing median
        self.assertIn("1 trial(s) measured CAD > 2000ms recommended upper bound", check["evidence_summary"])
        self.assertNotIn("median 300.00ms > 2000ms", check["evidence_summary"])
        self.assertIn("1/3 > 2000ms", check["evidence_summary"])

    def test_s4_both_lower_and_upper_cad_exceptions_reported(self):
        """S4 5: Both lower-bound (<100ms) and upper-bound (>2000ms) exceptions reported simultaneously."""
        t_low = _dict_to_evidence(_create_synthetic_trial(trial_id="t-low", scenario_id="S4", winning_family="IPv4", cad_ms=50.0))
        t_mid = _dict_to_evidence(_create_synthetic_trial(trial_id="t-mid", scenario_id="S4", winning_family="IPv4", cad_ms=250.0))
        t_high = _dict_to_evidence(_create_synthetic_trial(trial_id="t-high", scenario_id="S4", winning_family="IPv4", cad_ms=2500.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_low, t_mid, t_high]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        # Neither branch should hide the other
        self.assertIn("1 trial(s) measured CAD < 100ms recommended floor", check["evidence_summary"])
        self.assertIn("1 trial(s) measured CAD > 2000ms recommended upper bound", check["evidence_summary"])
        self.assertIn("1/3 < 100ms", check["evidence_summary"])
        self.assertIn("1/3 > 2000ms", check["evidence_summary"])
        self.assertIn("1/3 in recommended range", check["evidence_summary"])

    def test_s4_unknown_winning_address_family_indeterminate(self):
        """S4 6: Unknown winning address family treated as indeterminate, not counted as IPv6."""
        t_unk = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-unk", scenario_id="S4", winning_family="UNKNOWN", cad_ms=250.0
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t_unk]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "INDETERMINATE")
        self.assertEqual(check["recommended_status"], "INDETERMINATE")
        self.assertIn("unknown winning address family", check["evidence_summary"])
        self.assertNotIn("completed over IPv6", check["evidence_summary"])

    # --------------------------------------------------------------------------
    # Final Evidence-Validation Regression Tests
    # --------------------------------------------------------------------------

    def test_s4_unrounded_boundary_thresholds(self):
        """S4 Unrounded Boundaries: Directly tests 9.999ms, 10.000ms, 99.999ms, 100.000ms, 2000.000ms, 2000.001ms."""
        # 1. 9.999ms: strictly < 10.0ms -> mandatory deviation
        t_9_999 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=9.999))
        c_9_999 = [c for c in analyze.assess_rfc8305_conformance([t_9_999]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_9_999["mandatory_status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_9_999["status"], "OBSERVED_DEVIATION")

        # 2. Exactly 10.000ms: meets mandatory >= 10.0ms floor, but < 100.0ms recommended -> mandatory conformance, recommended deviation
        t_10_000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=10.000))
        c_10_000 = [c for c in analyze.assess_rfc8305_conformance([t_10_000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_10_000["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_10_000["recommended_status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_10_000["status"], "OBSERVED_DEVIATION")

        # 3. 99.999ms: strictly < 100.0ms -> recommended lower-bound deviation, mandatory conformance
        t_99_999 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=99.999))
        c_99_999 = [c for c in analyze.assess_rfc8305_conformance([t_99_999]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_99_999["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_99_999["recommended_status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_99_999["status"], "OBSERVED_DEVIATION")
        self.assertIn("1 trial(s) measured CAD < 100ms recommended floor", c_99_999["evidence_summary"])

        # 4. Exactly 100.000ms: recommended conformance (100.0 <= cad <= 2000.0)
        t_100_000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=100.000))
        c_100_000 = [c for c in analyze.assess_rfc8305_conformance([t_100_000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_100_000["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_100_000["recommended_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_100_000["status"], "OBSERVED_CONFORMANCE")

        # 5. Exactly 2000.000ms: recommended conformance (100.0 <= cad <= 2000.0)
        t_2000_000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.000))
        c_2000_000 = [c for c in analyze.assess_rfc8305_conformance([t_2000_000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_2000_000["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_2000_000["recommended_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_2000_000["status"], "OBSERVED_CONFORMANCE")

        # 6. 2000.001ms: strictly > 2000.0ms -> recommended upper-bound deviation
        t_2000_001 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.001))
        c_2000_001 = [c for c in analyze.assess_rfc8305_conformance([t_2000_001]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_2000_001["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(c_2000_001["recommended_status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_2000_001["status"], "OBSERVED_DEVIATION")
        self.assertIn("1 trial(s) measured CAD > 2000ms recommended upper bound", c_2000_001["evidence_summary"])

    def test_s4_invalid_cad_values(self):
        """S4 Invalid CAD: NaN, +inf, -inf, and negative CAD values are invalid timing evidence, not conformance."""
        invalid_values = [float("nan"), float("inf"), float("-inf"), -5.0, -0.001]
        for val in invalid_values:
            t_inv = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=val, ipv4_attempt=True))
            c_inv = [c for c in analyze.assess_rfc8305_conformance([t_inv]) if c["scenario_id"] == "S4"][0]
            self.assertEqual(c_inv["status"], "INDETERMINATE", f"Expected INDETERMINATE for CAD {val}")
            self.assertEqual(c_inv["mandatory_status"], "INDETERMINATE")
            self.assertEqual(c_inv["recommended_status"], "INDETERMINATE")
            self.assertIn("invalid connection attempt delay measurements", c_inv["evidence_summary"])

        # Invalid CAD combined with an independently confirmed deviation (IPv6 win)
        t_nan = _dict_to_evidence(_create_synthetic_trial(trial_id="t-nan", scenario_id="S4", winning_family="IPv4", cad_ms=float("nan"), ipv4_attempt=True))
        t_v6 = _dict_to_evidence(_create_synthetic_trial(trial_id="t-v6", scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False))
        c_combo = [c for c in analyze.assess_rfc8305_conformance([t_nan, t_v6]) if c["scenario_id"] == "S4"][0]
        # Aggregate deviation preserved
        self.assertEqual(c_combo["status"], "OBSERVED_DEVIATION")
        self.assertEqual(c_combo["mandatory_status"], "INDETERMINATE")
        self.assertIn("invalid CAD measurement(s)", c_combo["evidence_summary"])

    def test_s6_response_omitting_qname_is_indeterminate(self):
        """S6 Strict Target Matching: DNS response omitting qname must not be accepted for target host."""
        t_no_qname = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", hostname="trial-host.he.test",
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=False,
            omit_response_qname=True
        ))
        res = analyze.classify_s6_resolution_delay_trial(t_no_qname)
        self.assertEqual(res["classification"], "INDETERMINATE")
        self.assertIn("Missing or invalid positive A or AAAA DNS response", res["reason"])

        check = [c for c in analyze.assess_rfc8305_conformance([t_no_qname]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "INDETERMINATE")

    def test_s6_contradictory_attempt_and_winner_evidence(self):
        """S6 Contradictions: Validates all 5 explicit consistency checks."""
        # 1. ipv4_attempt=False but attempt timestamp populated
        t_ts1 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0,
            ipv4_attempt_timestamp=1793200000.05
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_ts1)["classification"], "INDETERMINATE")

        t_ts2 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0,
            ipv4_syn_timestamp=1793200000.05
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_ts2)["classification"], "INDETERMINATE")

        t_ts3 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0,
            ipv4_attempt_start_time=1793200000.05
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_ts3)["classification"], "INDETERMINATE")

        # 2. Winning family neither IPv4 nor IPv6
        t_bad_win = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv8", dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=False
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_bad_win)["classification"], "INDETERMINATE")

        t_unk_win = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="UNKNOWN", dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=False
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_unk_win)["classification"], "INDETERMINATE")

        # 3. Winning family conflicts with attempt or success flag
        t_v4_no_att = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", ipv4_attempt=False, ipv4_success=True, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_v4_no_att)["classification"], "INDETERMINATE")

        t_v4_no_succ = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", ipv4_attempt=True, ipv4_success=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_v4_no_succ)["classification"], "INDETERMINATE")

        t_v6_no_att = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", ipv6_attempt=False, ipv6_success=True, ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_v6_no_att)["classification"], "INDETERMINATE")

        t_v6_no_succ = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", ipv6_attempt=True, ipv6_success=False, ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_v6_no_succ)["classification"], "INDETERMINATE")

        # 4. Winning family absent while success flag claims success
        t_absent_v4 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family=None, ipv4_attempt=True, ipv4_success=True, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_absent_v4)["classification"], "INDETERMINATE")

        t_absent_v6 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family=None, ipv6_attempt=True, ipv6_success=True, ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        self.assertEqual(analyze.classify_s6_resolution_delay_trial(t_absent_v6)["classification"], "INDETERMINATE")

    def test_s6_early_ipv4_attempt_before_aaaa_deviation(self):
        """Correction A: IPv4 attempt started before positive AAAA response (when AAAA <= 50ms) -> DEVIATION."""
        t0 = 1793200000.0
        # Positive A at t0, positive AAAA at t0 + 0.030s (30ms later, <= 50ms)
        # IPv4 attempt at t0 + 0.015s (15ms later, before AAAA)
        t_dev = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=30.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=t0 + 0.015
        ))
        res = analyze.classify_s6_resolution_delay_trial(t_dev)
        self.assertEqual(res["classification"], "DEVIATION")
        self.assertIn("before positive AAAA response", res["reason"])

        check = [c for c in analyze.assess_rfc8305_conformance([t_dev]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")

    def test_s6_ipv4_attempt_after_aaaa_conformance(self):
        """Correction A: IPv4 attempt started at or after positive AAAA response (when AAAA <= 50ms) -> CONFORMANCE."""
        t0 = 1793200000.0
        # Positive A at t0, positive AAAA at t0 + 0.030s (30ms later, <= 50ms)
        # IPv4 attempt at t0 + 0.035s (35ms later, after AAAA)
        t_conf = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=30.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=t0 + 0.035
        ))
        res = analyze.classify_s6_resolution_delay_trial(t_conf)
        self.assertEqual(res["classification"], "CONFORMANCE")
        self.assertIn("not initiated before positive AAAA response", res["reason"])

        check = [c for c in analyze.assess_rfc8305_conformance([t_conf]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(check["recommended_status"], "OBSERVED_CONFORMANCE")

    def test_s6_ipv4_attempt_within_50ms_missing_and_invalid_timing_indeterminate(self):
        """Correction A: IPv4 attempt recorded within 50ms window but missing or invalid timing -> INDETERMINATE."""
        t0 = 1793200000.0
        # 1. Missing timestamp (None)
        t_notime = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=30.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=None
        ))
        res1 = analyze.classify_s6_resolution_delay_trial(t_notime)
        self.assertEqual(res1["classification"], "INDETERMINATE")
        self.assertIn("no timestamp proving", res1["reason"])

        # 2. Non-numeric timestamp string
        t_str = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=30.0,
            ipv4_attempt=True, ipv4_attempt_timestamp="invalid_ts"
        ))
        res2 = analyze.classify_s6_resolution_delay_trial(t_str)
        self.assertEqual(res2["classification"], "INDETERMINATE")
        self.assertIn("Non-numeric", res2["reason"])

        # 3. NaN timestamp
        t_nan = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=30.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=float("nan")
        ))
        res3 = analyze.classify_s6_resolution_delay_trial(t_nan)
        self.assertEqual(res3["classification"], "INDETERMINATE")
        self.assertIn("NaN or infinite", res3["reason"])

        # 4. Attempt timestamp preceding positive A
        t_pre = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=30.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=t0 - 0.005
        ))
        res4 = analyze.classify_s6_resolution_delay_trial(t_pre)
        self.assertEqual(res4["classification"], "INDETERMINATE")
        self.assertIn("Contradictory chronology", res4["reason"])

    def test_s6_exact_50ms_dns_boundary_attempt_chronology(self):
        """Correction A: Exact 50.0 ms DNS boundary with attempt before, at, after, missing, and no attempt."""
        t0 = 1793200000.0
        # Positive A at t0, positive AAAA at t0 + 0.050s (exact 50.0ms)

        # 1. Attempt before AAAA at 40ms -> DEVIATION
        t_before = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=50.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=t0 + 0.040
        ))
        res1 = analyze.classify_s6_resolution_delay_trial(t_before)
        self.assertEqual(res1["classification"], "DEVIATION")

        # 2. Attempt at exact AAAA arrival (50ms) -> CONFORMANCE
        t_at = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=50.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=t0 + 0.050
        ))
        res2 = analyze.classify_s6_resolution_delay_trial(t_at)
        self.assertEqual(res2["classification"], "CONFORMANCE")

        # 3. Attempt after AAAA at 60ms -> CONFORMANCE
        t_after = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=50.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=t0 + 0.060
        ))
        res3 = analyze.classify_s6_resolution_delay_trial(t_after)
        self.assertEqual(res3["classification"], "CONFORMANCE")

        # 4. Attempt with missing timestamp -> INDETERMINATE
        t_notime = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4",
            dns_a_lat=0.0, dns_aaaa_lat=50.0,
            ipv4_attempt=True, ipv4_attempt_timestamp=None
        ))
        res4 = analyze.classify_s6_resolution_delay_trial(t_notime)
        self.assertEqual(res4["classification"], "INDETERMINATE")

        # 5. No IPv4 attempt -> CONFORMANCE
        t_noatt = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6",
            dns_a_lat=0.0, dns_aaaa_lat=50.0,
            ipv4_attempt=False
        ))
        res5 = analyze.classify_s6_resolution_delay_trial(t_noatt)
        self.assertEqual(res5["classification"], "CONFORMANCE")

    def test_s6_malformed_http_outcome_indeterminate(self):
        """Correction B: Malformed http_outcome (None, list, valid dict) handled safely without crash."""
        # 1. http_outcome is None -> INDETERMINATE with clear reason
        t_none = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6",
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=False,
            http_outcome=None
        ))
        res_none = analyze.classify_s6_resolution_delay_trial(t_none)
        self.assertEqual(res_none["classification"], "INDETERMINATE")
        self.assertIn("Malformed http_outcome section", res_none["reason"])

        # 2. http_outcome is a list -> INDETERMINATE with clear reason
        t_list = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6",
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=False,
            http_outcome=["malformed", "list"]
        ))
        res_list = analyze.classify_s6_resolution_delay_trial(t_list)
        self.assertEqual(res_list["classification"], "INDETERMINATE")
        self.assertIn("Malformed http_outcome section", res_list["reason"])

        # 3. http_outcome is a valid dictionary -> validly classified
        valid_dict = {
            "status_code": 200,
            "success": True,
            "winning_address_family": "IPv6",
            "winning_ip": "2001:db8:2::10",
            "response_body_bytes": 300
        }
        t_valid = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6",
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=False,
            http_outcome=valid_dict
        ))
        res_valid = analyze.classify_s6_resolution_delay_trial(t_valid)
        self.assertEqual(res_valid["classification"], "DEVIATION")

    def test_s4_sub10ms_cad_with_unknown_winner_indeterminate(self):
        """Correction C: sub-10ms CAD with unknown winner -> mandatory OBSERVED_DEVIATION, recommended INDETERMINATE."""
        t_sub10_unk = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="UNKNOWN", cad_ms=5.0
        ))
        checks = analyze.assess_rfc8305_conformance([t_sub10_unk])
        s4_check = [c for c in checks if c["scenario_id"] == "S4"][0]

        # Overall status is DEVIATION because of mandatory violation
        self.assertEqual(s4_check["status"], "OBSERVED_DEVIATION")
        # Independent mandatory deviation is preserved
        self.assertEqual(s4_check["mandatory_status"], "OBSERVED_DEVIATION")
        # Recommendation-level status is INDETERMINATE due to unknown outcome
        self.assertEqual(s4_check["recommended_status"], "INDETERMINATE")
        self.assertIn("mandatory_status=OBSERVED_DEVIATION", s4_check["evidence_summary"])
        self.assertIn("recommendation_status=INDETERMINATE", s4_check["evidence_summary"])

    def test_s6_aggregate_reasoning_chronology_distinction(self):
        """Batch 5: S6 aggregate reasoning explicitly distinguishes attempt chronology."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=30.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        reasoning = check["reasoning"]

        # 1. Distinguishes attempt before positive AAAA vs at or after positive AAAA
        self.assertIn("starts before the positive AAAA response is an observed recommendation-level deviation", reasoning)
        self.assertIn("if no IPv4 attempt starts before that positive AAAA response, the trial conforms", reasoning)
        self.assertIn("If positive AAAA arrives more than 50ms after positive A", reasoning)
        self.assertIn("an IPv4 attempt should have started within the 50ms window", reasoning)
        self.assertIn("no attempt, or an attempt starting after that window, is an observed deviation", reasoning)
        self.assertIn("If an attempt is recorded but its timing cannot establish the relevant chronology", reasoning)

        # 2. Does not contain old unconditional claim
        self.assertNotIn("or where an IPv4 attempt starts within 50ms, conform", reasoning)
        self.assertNotIn(
            "trials where positive AAAA arrives <= 50ms after positive A, or where an IPv4 attempt starts within 50ms",
            reasoning
        )

        # 3. Retains recommendation-level versus mandatory-requirement distinction
        self.assertIn("recommendation-level", reasoning)
        self.assertIn("mandatory MUST violation", reasoning)
        self.assertIn("general browser non-conformance", reasoning)


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
    Executes analyze.py against the repository's genuine October 29 campaign:
    lab/campaigns/ps028-a10-live-20261030-01
    Validates genuine campaign accounting and RFC 8305 assessments without modifying files.
    """

    def test_live_trials_analysis(self):
        campaign_dir = SCRIPT_DIR / "campaigns" / "ps028-a10-live-20261030-01"
        if not campaign_dir.is_dir():
            self.skipTest(f"Campaign directory not present: {campaign_dir}")

        manifest_path = campaign_dir / "campaign_manifest.json"
        self.assertTrue(manifest_path.is_file(), f"Manifest missing: {manifest_path}")

        # Ingest evidence using genuine manifest & campaign directory
        trials, exclusions = analyze.ingest_evidence([campaign_dir])

        # Campaign accounting assertions
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        matrix_slots = manifest_data.get("matrix_slots", [])
        completed_slots = [s for s in matrix_slots if s.get("status") == "COMPLETED"]
        self.assertEqual(len(completed_slots), 280)

        valid_live = [t for t in trials if t.is_valid_live()]
        simulations = [t for t in trials if t.is_simulation]
        self.assertEqual(len(valid_live), 280)
        self.assertEqual(len(simulations), 0)
        self.assertEqual(len(exclusions), 2)
        total_attempts = len(valid_live) + len(exclusions)
        self.assertEqual(total_attempts, 282)

        # Scenarios & browsers
        scenarios = sorted(set(t.scenario_id for t in valid_live))
        self.assertEqual(scenarios, ["S0", "S1", "S2", "S3", "S4", "S5", "S6"])

        browsers = sorted(set(t.browser_name for t in valid_live))
        self.assertEqual(browsers, ["firefox", "google-chrome"])

        for sc in scenarios:
            for b in browsers:
                cell_trials = [t for t in valid_live if t.scenario_id == sc and t.browser_name == b]
                self.assertEqual(len(cell_trials), 20, f"Expected 20 trials for ({sc}, {b}), got {len(cell_trials)}")

        # Exclusions: two cleanup failures excluded rather than counted as valid
        for e in exclusions:
            self.assertEqual(e.category, "CLEANUP_FAILURE")
            self.assertIn(e.trial_id, ["trial-20261029205442-aba6193c", "trial-20261029210226-944fcfaa"])

        # Generate report
        report = analyze.generate_analysis_report(trials, exclusions, seed=42)
        ds = report["dataset_summary"]
        self.assertEqual(ds["valid_live_count"], 280)
        self.assertEqual(ds["simulation_count"], 0)
        self.assertEqual(ds["excluded_failures_count"], 2)

        rfc_map = {a["check_id"]: a for a in report["rfc8305_assessment"]}

        # Check that Section 3 check ID is used, and Section 4 check ID is absent
        self.assertIn("RFC8305-SEC3-RESOLUTION-DELAY", rfc_map)
        self.assertNotIn("RFC8305-SEC4-RESOLUTION-DELAY", rfc_map)

        # RFC check statuses
        self.assertEqual(rfc_map["RFC8305-SEC3-IPV6-PREFERENCE"]["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(rfc_map["RFC8305-SEC5-IMMEDIATE-RST-FALLBACK"]["status"], "OBSERVED_DEVIATION")
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-SYN-TIMEOUT"]["status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-HIGH-LATENCY"]["status"], "OBSERVED_DEVIATION")
        self.assertEqual(rfc_map["RFC8305-SEC3-RESOLUTION-DELAY"]["status"], "OBSERVED_DEVIATION")
        self.assertEqual(rfc_map["RFC8305-SEC7-STATEFULNESS-CACHING"]["status"], "INDETERMINATE")
        self.assertEqual(rfc_map["RFC8305-SEC8-NON-TCP-TRANSPORTS"]["status"], "INDETERMINATE")

        # S4 assessment details:
        s4_check = rfc_map["RFC8305-SEC5-CAD-HIGH-LATENCY"]
        self.assertEqual(s4_check["sample_size"], 40)
        self.assertEqual(s4_check["mandatory_status"], "OBSERVED_CONFORMANCE")
        self.assertEqual(s4_check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("39/40", s4_check["evidence_summary"])
        self.assertIn("trial-20261029222109-5c74c26a", s4_check["evidence_summary"])
        self.assertIn("Google Chrome: 20/20", s4_check["evidence_summary"])
        self.assertIn("Firefox: 19/20", s4_check["evidence_summary"])

        # S6 assessment details:
        s6_check = rfc_map["RFC8305-SEC3-RESOLUTION-DELAY"]
        self.assertEqual(s6_check["sample_size"], 40)
        self.assertEqual(s6_check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(s6_check["recommended_status"], "OBSERVED_DEVIATION")
        self.assertIn("40/40", s6_check["evidence_summary"])
        self.assertIn("Google Chrome", s6_check["evidence_summary"])
        self.assertIn("Firefox", s6_check["evidence_summary"])
        self.assertIn("0 IPv4 attempts", s6_check["evidence_summary"])
        self.assertNotIn("trial-20261028171417-b2d83f2f", s6_check["evidence_summary"])
        self.assertNotIn("515.27", s6_check["evidence_summary"])
        self.assertIn("starts before the positive AAAA response is an observed recommendation-level deviation", s6_check["reasoning"])
        self.assertNotIn("or where an IPv4 attempt starts within 50ms, conform", s6_check["reasoning"])


if __name__ == "__main__":
    unittest.main()
