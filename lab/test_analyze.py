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
    http_outcome: Any = "DEFAULT",
    attempt_pairing_verified: bool = False
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
        "classification_reason": "Synthetic test classification",
        "attempt_pairing_verified": attempt_pairing_verified
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
        "attempt_pairing_verified": attempt_pairing_verified,
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
        """Verifies that all checks return one of the four standard status categories."""
        allowed_statuses = {"OBSERVED_BEHAVIOR", "POTENTIAL_CRITERION_MISMATCH", "NOT_ASSESSED", "OUT_OF_SCOPE"}
        allowed_detail_statuses = {"OBSERVED_BEHAVIOR", "POTENTIAL_CRITERION_MISMATCH", "NOT_ASSESSED", "OUT_OF_SCOPE", "NOT_APPLICABLE"}
        t_s0 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S0", winning_family="IPv6"))
        assessment = analyze.assess_rfc8305_conformance([t_s0])
        for c in assessment:
            self.assertIn(c["status"], allowed_statuses)
            self.assertIn(c["mandatory_status"], allowed_detail_statuses)
            self.assertIn(c["recommended_status"], allowed_detail_statuses)

    def test_s2_timing_boundaries(self):
        """
        RFC 8305 Section 5 / v3 draft -04 Section 6 distinguishes:
        - Mandatory: subsequent connection attempts MUST NOT start within 10 ms.
        - Recommended: CAD minimum 100 ms, maximum 2000 ms.
        - Neither RFC 8305 nor v3 draft -04 mandates immediate retry upon TCP RST.
        - A below-10-ms interval is NOT classified as a criterion mismatch without verified attempt pairing.
        """
        # 1. Unverified pairing (default): 2.65ms (< 10ms) -> NOT_ASSESSED with pairing explanation
        t_s2_unpaired = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=2.65))
        res = analyze.assess_rfc8305_conformance([t_s2_unpaired])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC5-CAD-10MS-FLOOR")
        self.assertNotEqual(check["check_id"], "RFC8305-SEC5-IMMEDIATE-RST-FALLBACK")
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_floor_status"], "NOT_ASSESSED")
        self.assertEqual(check["recommendation_alignment_status"], "NOT_ASSESSED")
        self.assertIn("cannot be validly assessed", check["evidence_summary"])
        self.assertIn("attempt pairing", check["evidence_summary"])

        # 2. Verified pairing: 2.65ms (< 10ms mandatory floor) -> POTENTIAL_CRITERION_MISMATCH
        t_s2_paired_sub10 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=2.65, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_paired_sub10])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC5-CAD-10MS-FLOOR")
        self.assertNotEqual(check["check_id"], "RFC8305-SEC5-IMMEDIATE-RST-FALLBACK")
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_floor_status"], "BELOW_MANDATORY_FLOOR")
        self.assertEqual(check["recommendation_alignment_status"], "OUTSIDE_RECOMMENDED_RANGE")
        self.assertIn("mandatory-floor criterion mismatch", check["evidence_summary"])
        self.assertIn("< 10ms", check["evidence_summary"])

        # 3. Verified pairing: 9.99ms (< 10ms mandatory floor) -> POTENTIAL_CRITERION_MISMATCH
        t_s2_sub10 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=9.99, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_sub10])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_floor_status"], "BELOW_MANDATORY_FLOOR")

        # 4. Verified pairing: 10ms (exact mandatory floor; < 100ms recommended) -> POTENTIAL_CRITERION_MISMATCH (recommended range mismatch)
        t_s2_exact_10 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=10.0, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_exact_10])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
        self.assertEqual(check["recommendation_alignment_status"], "OUTSIDE_RECOMMENDED_RANGE")

        # 5. Verified pairing: 25ms (meets mandatory >= 10ms, < 100ms recommended min) -> POTENTIAL_CRITERION_MISMATCH
        t_s2_25 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=25.0, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_25])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")

        # 6. Verified pairing: 99.99ms (meets mandatory >= 10ms, < 100ms recommended min) -> POTENTIAL_CRITERION_MISMATCH
        t_s2_sub100 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=99.99, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_sub100])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")

        # 7. Verified pairing: 100ms (exact recommended minimum bound) -> OBSERVED_BEHAVIOR
        t_s2_exact_100 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=100.0, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_exact_100])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
        self.assertEqual(check["recommendation_alignment_status"], "ALIGNED")

        # 8. Verified pairing: 2000ms (exact 2-second upper bound) -> OBSERVED_BEHAVIOR
        t_s2_exact_2000 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=2000.0, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_exact_2000])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
        self.assertEqual(check["recommendation_alignment_status"], "ALIGNED")

        # 9. Verified pairing: 2000.01ms (> 2000ms upper bound) -> POTENTIAL_CRITERION_MISMATCH
        t_s2_over_2000_01 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=2000.01, attempt_pairing_verified=True
        ))
        res = analyze.assess_rfc8305_conformance([t_s2_over_2000_01])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
        self.assertEqual(check["recommendation_alignment_status"], "OUTSIDE_RECOMMENDED_RANGE")

        # 10. Missing timing data (cad_ms is None) -> NOT_ASSESSED
        t_s2_nocad = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", winning_family="IPv4", cad_ms=None))
        res = analyze.assess_rfc8305_conformance([t_s2_nocad])
        check = [c for c in res if c["scenario_id"] == "S2"][0]
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_floor_status"], "NOT_ASSESSED")
        self.assertEqual(check["recommendation_alignment_status"], "NOT_ASSESSED")

    def test_s1_timing_boundaries(self):
        """
        RFC 8305 Section 5 specifies permitted CAD range [100ms, 2000ms] (recommended target: 250ms),
        with an absolute minimum of 10ms.
        """
        # CAD < 10ms -> POTENTIAL_CRITERION_MISMATCH (mandatory floor deviation)
        t_s1_sub10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=8.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_sub10]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD = 9.99ms (rounded < 10ms) -> POTENTIAL_CRITERION_MISMATCH
        t_s1_sub10_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=9.99))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_sub10_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD < 100ms (e.g. 25ms, 99.9ms) -> POTENTIAL_CRITERION_MISMATCH (recommended range deviation, meets MUST floor)
        t_s1_25 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=25.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_25]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        t_s1_fast = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=99.9))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_fast]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD = 99.99ms (rounded < 100ms) -> POTENTIAL_CRITERION_MISMATCH
        t_s1_fast_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=99.99))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_fast_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD == 100.0ms (exact minimum bound) -> OBSERVED_BEHAVIOR
        t_s1_exact_min = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=100.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_min]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")

        # CAD == 100.00ms (rounded exact minimum bound) -> OBSERVED_BEHAVIOR
        t_s1_exact_min_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=100.00))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_min_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")

        # CAD == 250.0ms (recommended default) -> OBSERVED_BEHAVIOR
        t_s1_target = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=250.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_target]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")

        # CAD == 301.19ms (live S1 trial observation) -> OBSERVED_BEHAVIOR
        t_s1_live = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=301.19))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_live]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")

        # CAD == 2000.0ms (exact upper bound) -> OBSERVED_BEHAVIOR
        t_s1_exact_max = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_max]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")

        # CAD == 2000.00ms (rounded exact upper bound) -> OBSERVED_BEHAVIOR
        t_s1_exact_max_rounded = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.00))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_exact_max_rounded]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")

        # CAD == 2000.01ms (> 2000ms) -> POTENTIAL_CRITERION_MISMATCH
        t_s1_over_01 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.01))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_over_01]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD == 2000.1ms (> 2000ms) -> POTENTIAL_CRITERION_MISMATCH
        t_s1_over = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", winning_family="IPv4", cad_ms=2000.1))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s1_over]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")

    def test_s4_timing_boundaries(self):
        """Verifies alternative path selection under 600ms IPv6 RTT."""
        # IPv4 won + CAD in bounds (294.87ms) -> OBSERVED_BEHAVIOR
        t_s4_ok = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=294.87))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_ok]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")

        # IPv4 won + CAD < 10ms -> POTENTIAL_CRITERION_MISMATCH (mandatory floor violation, recommendation alignment)
        t_s4_fast = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=5.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_fast]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")

        # IPv6 won (no subsequent IPv4 attempt observed) -> NOT_ASSESSED for timing, NOT_APPLICABLE for mandatory floor
        t_s4_nowin = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False))
        check = [c for c in analyze.assess_rfc8305_conformance([t_s4_nowin]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")

    def test_s6_a_preceding_aaaa_sub_50ms(self):
        """1. S6 A response preceding AAAA by less than 50 ms -> OBSERVED_BEHAVIOR."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=30.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertIn("conforming", check["evidence_summary"])

    def test_s6_a_preceding_aaaa_over_50ms_no_ipv4_attempt(self):
        """2. S6 A response preceding AAAA by more than 50 ms with no IPv4 attempt -> POTENTIAL_CRITERION_MISMATCH."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("Observed recommendation-level criterion mismatch", check["evidence_summary"])
        self.assertNotIn("trial-20261028171417-b2d83f2f", check["evidence_summary"])
        self.assertNotIn("515.27", check["evidence_summary"])

    def test_s6_late_aaaa_with_ipv4_attempt_no_timestamp(self):
        """3. S6 late AAAA with an IPv4 attempt but no attempt timestamp -> NOT_ASSESSED."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=None
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["check_id"], "RFC8305-SEC3-RESOLUTION-DELAY")
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")
        self.assertIn("Not assessed", check["evidence_summary"])

    def test_s6_missing_positive_dns_evidence(self):
        """4. S6 missing positive DNS response evidence -> NOT_ASSESSED."""
        # Missing A response
        t_no_a = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_lat=None, dns_aaaa_lat=500.0
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t_no_a]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "NOT_ASSESSED")

        # Empty address in response (not a positive response)
        t_empty_addr = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_lat=5.0, dns_aaaa_lat=500.0, empty_dns_address=True
        ))
        check2 = [c for c in analyze.assess_rfc8305_conformance([t_empty_addr]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check2["status"], "NOT_ASSESSED")

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
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("Google Chrome", check["evidence_summary"])
        self.assertIn("Firefox", check["evidence_summary"])
        self.assertIn("2/2 trials with potential criterion mismatch", check["evidence_summary"])

    def test_s4_all_ipv4_wins_valid_cad(self):
        """6. S4 all IPv4 wins with valid CAD -> OBSERVED_BEHAVIOR."""
        t1 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-c1", browser_name="google-chrome", scenario_id="S4", winning_family="IPv4", cad_ms=250.0
        ))
        t2 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-f1", browser_name="firefox", scenario_id="S4", winning_family="IPv4", cad_ms=300.0
        ))
        assessment = analyze.assess_rfc8305_conformance([t1, t2])
        check = [c for c in assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
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
            winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        )))
        assessment = analyze.assess_rfc8305_conformance(trials)
        check = [c for c in assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["sample_size"], 40)
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommendation_alignment_status"], "ALIGNED")
        self.assertEqual(check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
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
            winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        )))

        # Chrome alone: 5/5 IPv4 wins -> OBSERVED_BEHAVIOR
        chrome_assessment = analyze.assess_rfc8305_conformance(trials, browser="google-chrome")
        c_check = [c for c in chrome_assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_check["recommendation_alignment_status"], "ALIGNED")

        # Firefox alone: 4/5 IPv4 wins + 1 IPv6 win -> OBSERVED_BEHAVIOR (timing aligned)
        firefox_assessment = analyze.assess_rfc8305_conformance(trials, browser="firefox")
        f_check = [c for c in firefox_assessment if c["scenario_id"] == "S4"][0]
        self.assertEqual(f_check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(f_check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(f_check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(f_check["recommendation_alignment_status"], "ALIGNED")

    def test_s4_mandatory_10ms_vs_recommended_100ms_boundary(self):
        """9. S4 mandatory 10 ms boundary versus recommended 100 ms boundary."""
        # CAD < 10ms (5ms) -> mandatory violation, recommendation alignment
        t_sub10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=5.0))
        c_sub10 = [c for c in analyze.assess_rfc8305_conformance([t_sub10]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_sub10["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_sub10["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_sub10["recommended_status"], "OBSERVED_BEHAVIOR")

        # CAD = 10ms (meets mandatory >= 10ms, but < 100ms recommended) -> recommendation deviation
        t_10 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=10.0))
        c_10 = [c for c in analyze.assess_rfc8305_conformance([t_10]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_10["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_10["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_10["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD = 50ms (meets mandatory >= 10ms, but < 100ms recommended) -> recommendation deviation
        t_50 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=50.0))
        c_50 = [c for c in analyze.assess_rfc8305_conformance([t_50]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_50["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_50["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_50["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

        # CAD = 100ms (exact recommended minimum) -> OBSERVED_BEHAVIOR
        t_100 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=100.0))
        c_100 = [c for c in analyze.assess_rfc8305_conformance([t_100]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_100["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_100["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_100["recommended_status"], "OBSERVED_BEHAVIOR")

    def test_s4_recommended_2s_upper_bound(self):
        """10. S4 recommended 2-second upper bound."""
        # CAD = 2000ms -> in bounds
        t_2000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.0))
        c_2000 = [c for c in analyze.assess_rfc8305_conformance([t_2000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_2000["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_2000["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_2000["recommended_status"], "OBSERVED_BEHAVIOR")

        # CAD = 2000.01ms -> exceeds recommended upper bound, meets mandatory floor
        t_over = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.01))
        c_over = [c for c in analyze.assess_rfc8305_conformance([t_over]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_over["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_over["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_over["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

    def test_missing_evidence_all_scenarios_indeterminate(self):
        """Verifies that an empty dataset marks checks NOT_ASSESSED or OUT_OF_SCOPE with sample_size 0."""
        assessment = analyze.assess_rfc8305_conformance([])
        self.assertEqual(len(assessment), 7)
        for check in assessment:
            self.assertIn(check["status"], {"NOT_ASSESSED", "OUT_OF_SCOPE"})
            self.assertEqual(check["sample_size"], 0)

    def test_partial_scenarios_missing_evidence_indeterminate(self):
        """Verifies that when only S0 is tested, S1, S2, S4, and S6 are marked NOT_ASSESSED."""
        t_s0 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S0", winning_family="IPv6"))
        assessment = analyze.assess_rfc8305_conformance([t_s0])
        status_map = {c["scenario_id"]: c["status"] for c in assessment}

        self.assertEqual(status_map["S0"], "OBSERVED_BEHAVIOR")
        self.assertEqual(status_map["S1"], "NOT_ASSESSED")
        self.assertEqual(status_map["S2"], "NOT_ASSESSED")
        self.assertEqual(status_map["S4"], "NOT_ASSESSED")
        self.assertEqual(status_map["S6"], "NOT_ASSESSED")

    def test_missing_cad_in_trial_returns_indeterminate(self):
        """Verifies that S1 or S2 trials without CAD measurement return NOT_ASSESSED."""
        t_s1_nocad = _dict_to_evidence(_create_synthetic_trial(scenario_id="S1", cad_ms=None))
        check1 = [c for c in analyze.assess_rfc8305_conformance([t_s1_nocad]) if c["scenario_id"] == "S1"][0]
        self.assertEqual(check1["status"], "NOT_ASSESSED")
        self.assertIn("missing connection attempt delay", check1["evidence_summary"])

        t_s2_nocad = _dict_to_evidence(_create_synthetic_trial(scenario_id="S2", cad_ms=None))
        check2 = [c for c in analyze.assess_rfc8305_conformance([t_s2_nocad]) if c["scenario_id"] == "S2"][0]
        self.assertEqual(check2["status"], "NOT_ASSESSED")
        self.assertIn("missing connection attempt delay", check2["evidence_summary"])

    def test_unsupported_checks_remain_indeterminate(self):
        """Verifies that Section 4 (historical state) and QUIC checks use proper IDs and statuses."""
        t_s0 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S0", winning_family="IPv6"))
        assessment = analyze.assess_rfc8305_conformance([t_s0])
        check_map = {c["check_id"]: c for c in assessment}

        sec4 = check_map["RFC8305-SEC4-HISTORICAL-STATE"]
        self.assertEqual(sec4["status"], "NOT_ASSESSED")
        self.assertIn("Unsupported check", sec4["evidence_summary"])
        self.assertIn("RFC 8305 Section 4", sec4["rfc_section"])

        quic = check_map["HEV3-DRAFT04-SEC6.1-QUIC"]
        self.assertEqual(quic["status"], "OUT_OF_SCOPE")
        self.assertIn("Out of scope", quic["evidence_summary"])
        self.assertIn("draft-ietf-happy-happyeyeballs-v3-04 Section 6.1", quic["rfc_section"])

        self.assertNotIn("RFC8305-SEC7-STATEFULNESS-CACHING", check_map)
        self.assertNotIn("RFC8305-SEC8-NON-TCP-TRANSPORTS", check_map)

    # --------------------------------------------------------------------------
    # S6 Regression Tests (Phase 2A Review Corrections - Batch 2)
    # --------------------------------------------------------------------------

    def test_s6_exactly_50ms_a_to_aaaa_conformance(self):
        """S6 1: Exactly 50.0 ms A-to-AAAA interval -> OBSERVED_BEHAVIOR."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=50.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertIn("conforming", check["evidence_summary"])

    def test_s6_over_50ms_no_ipv4_attempt_deviation(self):
        """S6 2: More than 50 ms A-to-AAAA (50.1 ms) with no IPv4 attempt -> POTENTIAL_CRITERION_MISMATCH."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=50.1, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("potential criterion mismatch", check["evidence_summary"])

    def test_s6_ipv4_attempt_at_exactly_50ms_conformance(self):
        """S6 3: IPv4 attempt initiated at exactly 50.0 ms after positive A -> OBSERVED_BEHAVIOR."""
        t0 = 1793200000.0
        # A response arrives at t0 + 0.0s. IPv4 attempt at t0 + 0.050s (50.0ms).
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=t0 + 0.050
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertIn("1/1 trials conforming", check["evidence_summary"])

    def test_s6_ipv4_attempt_just_above_50ms_deviation(self):
        """S6 4: IPv4 attempt initiated just above 50 ms (50.5 ms) -> POTENTIAL_CRITERION_MISMATCH."""
        t0 = 1793200000.0
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=t0 + 0.0505
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("1/1 trials with potential criterion mismatch", check["evidence_summary"])

    def test_s6_negative_attempt_timestamp_indeterminate(self):
        """S6 5: Negative IPv4 attempt timestamp -> NOT_ASSESSED."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=-10.0
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")
        self.assertIn("not assessed", check["evidence_summary"])

    def test_s6_nan_and_infinite_attempt_timestamps_indeterminate(self):
        """S6 6: NaN and infinite IPv4 attempt timestamps -> NOT_ASSESSED."""
        t_nan = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=float("nan")
        ))
        c_nan = [c for c in analyze.assess_rfc8305_conformance([t_nan]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_nan["status"], "NOT_ASSESSED")

        t_inf = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=float("inf")
        ))
        c_inf = [c for c in analyze.assess_rfc8305_conformance([t_inf]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_inf["status"], "NOT_ASSESSED")

    def test_s6_invalid_and_missing_timestamps_indeterminate(self):
        """S6 7: Non-numeric, boolean, preceding-A, and missing timestamps -> NOT_ASSESSED."""
        t0 = 1793200000.0
        # Non-numeric string
        t_str = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp="invalid-timestamp"
        ))
        c_str = [c for c in analyze.assess_rfc8305_conformance([t_str]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_str["status"], "NOT_ASSESSED")

        # Boolean timestamp
        t_bool = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=True
        ))
        c_bool = [c for c in analyze.assess_rfc8305_conformance([t_bool]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_bool["status"], "NOT_ASSESSED")

        # Timestamp preceding positive A response (contradictory chronology)
        t_pre = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=t0  # precedes positive A at t0 + 0.005s
        ))
        c_pre = [c for c in analyze.assess_rfc8305_conformance([t_pre]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_pre["status"], "NOT_ASSESSED")

        # Missing timestamp when ipv4_attempt=True
        t_none = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", cad_ms=None,
            dns_a_lat=0.0, dns_aaaa_lat=500.0, ipv4_attempt=True,
            ipv4_attempt_timestamp=None
        ))
        c_none = [c for c in analyze.assess_rfc8305_conformance([t_none]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c_none["status"], "NOT_ASSESSED")

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
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        # All three counts visible in summary
        self.assertIn("1/3 trials with potential criterion mismatch", check["evidence_summary"])
        self.assertIn("1/3 aligned", check["evidence_summary"])
        self.assertIn("1/3 not assessed", check["evidence_summary"])

    def test_s6_malformed_attempt_flags_and_contradictions(self):
        """S6 9: Malformed attempt flags and contradictory winner/success observations -> NOT_ASSESSED."""
        # Non-boolean ipv4_attempt
        t_str_att = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt="yes", dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c1 = [c for c in analyze.assess_rfc8305_conformance([t_str_att]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c1["status"], "NOT_ASSESSED")

        # Non-boolean ipv6_attempt
        t_str_v6 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv6_attempt="yes", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c2 = [c for c in analyze.assess_rfc8305_conformance([t_str_v6]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c2["status"], "NOT_ASSESSED")

        # Contradiction: ipv4_success without ipv4_attempt
        t_contra1 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", ipv4_attempt=False, ipv4_success=True, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c3 = [c for c in analyze.assess_rfc8305_conformance([t_contra1]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c3["status"], "NOT_ASSESSED")

        # Contradiction: winning IPv4 without ipv4_attempt
        t_contra2 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv4", ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c4 = [c for c in analyze.assess_rfc8305_conformance([t_contra2]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c4["status"], "NOT_ASSESSED")

        # Contradiction: winning IPv6 without ipv6_attempt
        t_contra3 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", ipv6_attempt=False, ipv4_attempt=False, dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c5 = [c for c in analyze.assess_rfc8305_conformance([t_contra3]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c5["status"], "NOT_ASSESSED")

    def test_s6_invalid_address_families_and_unrelated_hostnames(self):
        """S6 10: Invalid address families or unrelated DNS query names -> NOT_ASSESSED."""
        # A record with IPv6 address
        t_bad_a = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_address="2001:db8::1", dns_aaaa_lat=500.0
        ))
        c1 = [c for c in analyze.assess_rfc8305_conformance([t_bad_a]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c1["status"], "NOT_ASSESSED")

        # AAAA record with IPv4 address
        t_bad_aaaa = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", dns_a_lat=0.0, dns_aaaa_address="10.0.0.1"
        ))
        c2 = [c for c in analyze.assess_rfc8305_conformance([t_bad_aaaa]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c2["status"], "NOT_ASSESSED")

        # Unrelated DNS qname
        t_unrelated = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", hostname="target.he.test", dns_qname="unrelated.example.com",
            dns_a_lat=0.0, dns_aaaa_lat=500.0
        ))
        c3 = [c for c in analyze.assess_rfc8305_conformance([t_unrelated]) if c["scenario_id"] == "S6"][0]
        self.assertEqual(c3["status"], "NOT_ASSESSED")

    # --------------------------------------------------------------------------
    # S4 Regression Tests (Phase 2A Review Corrections - Batch 2)
    # --------------------------------------------------------------------------

    def test_s4_direct_ipv6_without_subsequent_attempt_mandatory_not_applicable(self):
        """S4 1: One direct IPv6 trial without a subsequent attempt -> mandatory NOT_APPLICABLE, recommended NOT_ASSESSED."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")
        self.assertEqual(check["recommendation_alignment_status"], "NOT_ASSESSED")
        self.assertIn("no connection attempt delay measurements available", check["evidence_summary"])

    def test_s4_ipv4_attempt_with_missing_cad(self):
        """S4 2: An IPv4 attempt with missing CAD is indeterminate unless confirmed deviation exists."""
        # Single trial with subsequent IPv4 attempt but missing CAD
        t_missing_cad = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv4", cad_ms=None, ipv4_attempt=True
        ))
        check1 = [c for c in analyze.assess_rfc8305_conformance([t_missing_cad]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check1["status"], "NOT_ASSESSED")
        self.assertEqual(check1["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(check1["recommended_status"], "NOT_ASSESSED")

        # Missing CAD combined with an independently confirmed timing deviation (CAD = 50ms)
        t_dev = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t-s4-dev", scenario_id="S4", winning_family="IPv4", cad_ms=50.0, ipv4_attempt=True
        ))
        check2 = [c for c in analyze.assess_rfc8305_conformance([t_missing_cad, t_dev]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check2["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check2["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(check2["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")

    def test_s4_cad_sub_100ms_median_in_range(self):
        """S4 3: One CAD below 100 ms and another in range, where median is in range."""
        t1 = _dict_to_evidence(_create_synthetic_trial(trial_id="t1", scenario_id="S4", winning_family="IPv4", cad_ms=50.0))
        t2 = _dict_to_evidence(_create_synthetic_trial(trial_id="t2", scenario_id="S4", winning_family="IPv4", cad_ms=250.0))
        t3 = _dict_to_evidence(_create_synthetic_trial(trial_id="t3", scenario_id="S4", winning_family="IPv4", cad_ms=300.0))
        check = [c for c in analyze.assess_rfc8305_conformance([t1, t2, t3]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
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
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
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
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
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
        self.assertEqual(check["status"], "NOT_ASSESSED")
        self.assertEqual(check["recommended_status"], "NOT_ASSESSED")
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
        self.assertEqual(c_9_999["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_9_999["status"], "POTENTIAL_CRITERION_MISMATCH")

        # 2. Exactly 10.000ms: meets mandatory >= 10.0ms floor, but < 100.0ms recommended -> mandatory conformance, recommended deviation
        t_10_000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=10.000))
        c_10_000 = [c for c in analyze.assess_rfc8305_conformance([t_10_000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_10_000["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_10_000["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_10_000["status"], "POTENTIAL_CRITERION_MISMATCH")

        # 3. 99.999ms: strictly < 100.0ms -> recommended lower-bound deviation, mandatory conformance
        t_99_999 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=99.999))
        c_99_999 = [c for c in analyze.assess_rfc8305_conformance([t_99_999]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_99_999["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_99_999["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_99_999["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("1 trial(s) measured CAD < 100ms recommended floor", c_99_999["evidence_summary"])

        # 4. Exactly 100.000ms: recommended conformance (100.0 <= cad <= 2000.0)
        t_100_000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=100.000))
        c_100_000 = [c for c in analyze.assess_rfc8305_conformance([t_100_000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_100_000["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_100_000["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_100_000["status"], "OBSERVED_BEHAVIOR")

        # 5. Exactly 2000.000ms: recommended conformance (100.0 <= cad <= 2000.0)
        t_2000_000 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.000))
        c_2000_000 = [c for c in analyze.assess_rfc8305_conformance([t_2000_000]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_2000_000["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_2000_000["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_2000_000["status"], "OBSERVED_BEHAVIOR")

        # 6. 2000.001ms: strictly > 2000.0ms -> recommended upper-bound deviation
        t_2000_001 = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=2000.001))
        c_2000_001 = [c for c in analyze.assess_rfc8305_conformance([t_2000_001]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(c_2000_001["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_2000_001["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_2000_001["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("1 trial(s) measured CAD > 2000ms recommended upper bound", c_2000_001["evidence_summary"])

    def test_s4_invalid_cad_values(self):
        """S4 Invalid CAD: NaN, +inf, -inf, and negative CAD values are invalid timing evidence, not conformance."""
        invalid_values = [float("nan"), float("inf"), float("-inf"), -5.0, -0.001]
        for val in invalid_values:
            t_inv = _dict_to_evidence(_create_synthetic_trial(scenario_id="S4", winning_family="IPv4", cad_ms=val, ipv4_attempt=True))
            c_inv = [c for c in analyze.assess_rfc8305_conformance([t_inv]) if c["scenario_id"] == "S4"][0]
            self.assertEqual(c_inv["status"], "NOT_ASSESSED", f"Expected NOT_ASSESSED for CAD {val}")
            self.assertEqual(c_inv["mandatory_status"], "NOT_ASSESSED")
            self.assertEqual(c_inv["recommended_status"], "NOT_ASSESSED")
            self.assertIn("invalid connection attempt delay measurements", c_inv["evidence_summary"])

        # Invalid CAD combined with an independently confirmed timing deviation (CAD = 50ms)
        t_nan = _dict_to_evidence(_create_synthetic_trial(trial_id="t-nan", scenario_id="S4", winning_family="IPv4", cad_ms=float("nan"), ipv4_attempt=True))
        t_dev = _dict_to_evidence(_create_synthetic_trial(trial_id="t-dev", scenario_id="S4", winning_family="IPv4", cad_ms=50.0, ipv4_attempt=True))
        c_combo = [c for c in analyze.assess_rfc8305_conformance([t_nan, t_dev]) if c["scenario_id"] == "S4"][0]
        # Aggregate deviation preserved
        self.assertEqual(c_combo["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_combo["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(c_combo["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
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
        self.assertEqual(check["status"], "NOT_ASSESSED")

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
        self.assertEqual(check["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
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
        self.assertEqual(check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(check["recommended_status"], "OBSERVED_BEHAVIOR")

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
        """Correction C: sub-10ms CAD with unknown winner -> mandatory POTENTIAL_CRITERION_MISMATCH, recommended NOT_ASSESSED."""
        t_sub10_unk = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="UNKNOWN", cad_ms=5.0
        ))
        checks = analyze.assess_rfc8305_conformance([t_sub10_unk])
        s4_check = [c for c in checks if c["scenario_id"] == "S4"][0]

        # Overall status is POTENTIAL_CRITERION_MISMATCH because of mandatory violation
        self.assertEqual(s4_check["status"], "POTENTIAL_CRITERION_MISMATCH")
        # Independent mandatory deviation is preserved
        self.assertEqual(s4_check["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        # Recommendation-level status is NOT_ASSESSED due to unknown outcome
        self.assertEqual(s4_check["recommended_status"], "NOT_ASSESSED")
        self.assertIn("mandatory_status=POTENTIAL_CRITERION_MISMATCH", s4_check["evidence_summary"])
        self.assertIn("recommendation_status=NOT_ASSESSED", s4_check["evidence_summary"])

    def test_s6_aggregate_reasoning_chronology_distinction(self):
        """Batch 5: S6 aggregate reasoning explicitly distinguishes attempt chronology."""
        t = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S6", winning_family="IPv6", cad_ms=None,
            dns_a_lat=5.0, dns_aaaa_lat=30.0, ipv4_attempt=False
        ))
        check = [c for c in analyze.assess_rfc8305_conformance([t]) if c["scenario_id"] == "S6"][0]
        reasoning = check["reasoning"]

        # 1. Distinguishes attempt before positive AAAA vs at or after positive AAAA
        self.assertIn("starts before the positive AAAA response is an observed recommendation-level criterion mismatch", reasoning)
        self.assertIn("if no IPv4 attempt starts before that positive AAAA response, the trial aligns with this timing recommendation", reasoning)
        self.assertIn("If positive AAAA arrives more than 50ms after positive A", reasoning)
        self.assertIn("an IPv4 attempt should have started within the 50ms window", reasoning)
        self.assertIn("no attempt, or an attempt starting after that window, is an observed potential criterion mismatch", reasoning)
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

    def test_rfc_assessment_task3_specifications(self):
        """
        Comprehensive regression suite verifying all 17 specifications from Task 3:
        1. No result labelled RFC8305-SEC7-STATEFULNESS-CACHING
        2. No result labelled RFC8305-SEC8-NON-TCP-TRANSPORTS
        3. RFC 8305 §7 identified as NAT64/DNS64
        4. RFC 8305 §8 identified as configurable values
        5. RFC 8305 §4 used for historical address-selection behaviour
        6. RFC 8305 §5 used for CAD requirements
        7. v3 draft -04 §5.3 used for historical endpoint ordering
        8. v3 draft -04 §6 used for CAD requirements
        9. v3 draft -04 §6.1 used for successful-connection establishment
        10. QUIC references not attributed to RFC 8305
        11. SCTP not represented as tested or specified
        12. No global OBSERVED_CONFORMANCE or OBSERVED_DEVIATION status remains in output
        13. S2 does not attribute immediate retry after RST to an RFC requirement
        14. Below-10-ms observation not called criterion mismatch unless compared attempts adequately paired
        15. Insufficient attempt correlation produces explicitly qualified status (NOT_ASSESSED)
        16. Raw measured timestamps and trial counts remain unchanged
        17. Assessment generation is deterministic
        """
        campaign_dir = SCRIPT_DIR / "campaigns" / "ps028-a10-live-20261030-01"
        if not campaign_dir.is_dir():
            self.skipTest(f"Campaign directory not present: {campaign_dir}")

        trials, exclusions = analyze.ingest_evidence([campaign_dir])
        report = analyze.generate_analysis_report(trials, exclusions, seed=42)
        assessments = report["rfc8305_assessment"]
        check_ids = [c["check_id"] for c in assessments]
        check_map = {c["check_id"]: c for c in assessments}

        # 1. No result labelled RFC8305-SEC7-STATEFULNESS-CACHING
        self.assertNotIn("RFC8305-SEC7-STATEFULNESS-CACHING", check_ids)

        # 2. No result labelled RFC8305-SEC8-NON-TCP-TRANSPORTS
        self.assertNotIn("RFC8305-SEC8-NON-TCP-TRANSPORTS", check_ids)

        # 3. RFC 8305 §7 identified as NAT64/DNS64
        sec4_check = check_map["RFC8305-SEC4-HISTORICAL-STATE"]
        self.assertIn("NAT64", sec4_check["specification_context"])
        self.assertIn("DNS64", sec4_check["specification_context"])
        self.assertIn("Section 7", sec4_check["specification_context"])

        # 4. RFC 8305 §8 identified as configurable values
        quic_check = check_map["HEV3-DRAFT04-SEC6.1-QUIC"]
        self.assertIn("Section 8", quic_check["specification_context"])
        self.assertIn("Configurable Values", quic_check["specification_context"])

        # 5. RFC 8305 §4 used for historical address-selection behaviour
        self.assertEqual(sec4_check["rfc_section"], "RFC 8305 Section 4")
        self.assertIn("RFC 8305 Section 4", sec4_check["specification_context"])

        # 6. RFC 8305 §5 used for CAD requirements
        s1_check = check_map["RFC8305-SEC5-CAD-SYN-TIMEOUT"]
        s4_check = check_map["RFC8305-SEC5-CAD-HIGH-LATENCY"]
        self.assertEqual(s1_check["rfc_section"], "RFC 8305 Section 5")
        self.assertEqual(s4_check["rfc_section"], "RFC 8305 Section 5")

        # 7. v3 draft -04 §5.3 used for historical endpoint ordering
        self.assertIn("draft-ietf-happy-happyeyeballs-v3-04 Section 5.3", sec4_check["specification_context"])

        # 8. v3 draft -04 §6 used for CAD requirements
        self.assertIn("draft-ietf-happy-happyeyeballs-v3-04 Section 6", s1_check["specification_context"])
        self.assertIn("draft-ietf-happy-happyeyeballs-v3-04 Section 6", s4_check["specification_context"])

        # 9. v3 draft -04 §6.1 used for successful-connection establishment
        self.assertEqual(quic_check["rfc_section"], "draft-ietf-happy-happyeyeballs-v3-04 Section 6.1")
        self.assertIn("draft-ietf-happy-happyeyeballs-v3-04 Section 6.1", quic_check["specification_context"])

        # 10. QUIC references not attributed to RFC 8305
        self.assertNotIn("RFC 8305", quic_check["rfc_specification_requirement"])
        self.assertIn("RFC 8305 Section 8 provides a Summary of Configurable Values and does not specify alternative transports", quic_check["specification_context"])

        # 11. SCTP not represented as tested or specified
        self.assertIn("SCTP is not specified", quic_check["evidence_summary"])
        self.assertIn("SCTP is not specified in either document", quic_check["specification_context"])

        # 12. No global OBSERVED_CONFORMANCE or OBSERVED_DEVIATION status remains in output
        controlled_vocabulary = {"OBSERVED_BEHAVIOR", "POTENTIAL_CRITERION_MISMATCH", "NOT_ASSESSED", "OUT_OF_SCOPE"}
        for c in assessments:
            self.assertIn(c["status"], controlled_vocabulary)
            self.assertNotIn("CONFORMANCE", c["status"])
            self.assertNotIn("DEVIATION", c["status"])
            self.assertIn(c["mandatory_status"], controlled_vocabulary | {"NOT_APPLICABLE"})
            self.assertIn(c["recommended_status"], controlled_vocabulary | {"NOT_APPLICABLE"})

        # 13. S2 does not attribute immediate retry after RST to an RFC requirement and uses RFC8305-SEC5-CAD-10MS-FLOOR
        self.assertIn("RFC8305-SEC5-CAD-10MS-FLOOR", check_ids)
        self.assertNotIn("RFC8305-SEC5-IMMEDIATE-RST-FALLBACK", check_ids)
        s2_check = check_map["RFC8305-SEC5-CAD-10MS-FLOOR"]
        self.assertEqual(s2_check["check_id"], "RFC8305-SEC5-CAD-10MS-FLOOR")
        self.assertNotIn("SHOULD start immediately upon TCP RST", s2_check["rfc_specification_requirement"])
        self.assertIn("Neither specification contains an immediate-retry requirement upon TCP RST", s2_check["specification_context"])

        # 14. Below-10-ms observation not called criterion mismatch unless compared attempts adequately paired
        # Empirical S2 trials have CAD < 10ms in Chrome, but are unpaired -> NOT_ASSESSED
        self.assertEqual(s2_check["status"], "NOT_ASSESSED")
        self.assertEqual(s2_check["mandatory_status"], "NOT_ASSESSED")
        # Verified paired trial with CAD < 10ms produces POTENTIAL_CRITERION_MISMATCH
        paired_trial = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=2.65, attempt_pairing_verified=True
        ))
        paired_assessment = analyze.assess_rfc8305_conformance([paired_trial])
        paired_s2 = [c for c in paired_assessment if c["scenario_id"] == "S2"][0]
        self.assertEqual(paired_s2["status"], "POTENTIAL_CRITERION_MISMATCH")

        # 15. Insufficient attempt correlation produces explicitly qualified status (NOT_ASSESSED)
        self.assertEqual(s2_check["status"], "NOT_ASSESSED")
        self.assertIn("without establishing verified attempt pairing", s2_check["evidence_summary"])
        self.assertIn("cannot be validly assessed against the 10 ms mandatory floor criterion", s2_check["evidence_summary"])

        # 16. Raw measured timestamps and trial counts remain unchanged
        self.assertEqual(report["dataset_summary"]["valid_live_count"], 280)
        self.assertEqual(len(exclusions), 2)
        # S2 median CAD unchanged (68.800 ms, min 0.350 ms, max 336.230 ms)
        self.assertAlmostEqual(s2_check["observed_delay_ms"], 68.8, places=2)
        self.assertAlmostEqual(s2_check["observed_min_delay_ms"], 0.35, places=2)
        self.assertAlmostEqual(s2_check["observed_max_delay_ms"], 336.23, places=2)

        # 17. Assessment generation is deterministic
        report2 = analyze.generate_analysis_report(trials, exclusions, seed=42)
        rep1_clean = copy.deepcopy(report)
        rep2_clean = copy.deepcopy(report2)
        del rep1_clean["generated_at"]
        del rep2_clean["generated_at"]
        self.assertEqual(
            json.dumps(rep1_clean, indent=2, sort_keys=True),
            json.dumps(rep2_clean, indent=2, sort_keys=True)
        )

    def test_s2_identifier_task3a_specifications(self):
        """
        Task 3A regression tests:
        1. The new identifier RFC8305-SEC5-CAD-10MS-FLOOR exists in the generated assessment.
        2. The old identifier RFC8305-SEC5-IMMEDIATE-RST-FALLBACK does not appear in the generated assessment.
        3. The S2 assessment remains NOT_ASSESSED when empirical attempt pairing is unverified.
        4. Synthetic verified-pairing tests retain their existing behaviour.
        5. The 10 ms criterion is described as a minimum spacing requirement, not an immediate-RST retry requirement.
        6. The regenerated assessment is deterministic.
        """
        campaign_dir = SCRIPT_DIR / "campaigns" / "ps028-a10-live-20261030-01"
        if not campaign_dir.is_dir():
            self.skipTest(f"Campaign directory not present: {campaign_dir}")

        trials, exclusions = analyze.ingest_evidence([campaign_dir])
        report = analyze.generate_analysis_report(trials, exclusions, seed=42)
        assessments = report["rfc8305_assessment"]
        check_ids = [c["check_id"] for c in assessments]
        check_map = {c["check_id"]: c for c in assessments}

        # 1. New identifier exists
        self.assertIn("RFC8305-SEC5-CAD-10MS-FLOOR", check_ids)

        # 2. Old identifier does not appear
        self.assertNotIn("RFC8305-SEC5-IMMEDIATE-RST-FALLBACK", check_ids)

        # 3. S2 remains NOT_ASSESSED when empirical attempt pairing is unverified
        s2 = check_map["RFC8305-SEC5-CAD-10MS-FLOOR"]
        self.assertEqual(s2["scenario_id"], "S2")
        self.assertEqual(s2["status"], "NOT_ASSESSED")
        self.assertEqual(s2["mandatory_status"], "NOT_ASSESSED")
        self.assertIn("without establishing verified attempt pairing", s2["evidence_summary"])

        # 4. Synthetic verified-pairing tests retain their existing behaviour
        # a) Verified pairing with sub-10ms CAD -> POTENTIAL_CRITERION_MISMATCH
        t_sub10 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=2.65, attempt_pairing_verified=True
        ))
        res_sub10 = analyze.assess_rfc8305_conformance([t_sub10])
        c_sub10 = [c for c in res_sub10 if c["scenario_id"] == "S2"][0]
        self.assertEqual(c_sub10["check_id"], "RFC8305-SEC5-CAD-10MS-FLOOR")
        self.assertEqual(c_sub10["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(c_sub10["mandatory_floor_status"], "BELOW_MANDATORY_FLOOR")

        # b) Verified pairing with CAD in recommended range (250ms) -> OBSERVED_BEHAVIOR
        t_ok = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=250.0, attempt_pairing_verified=True
        ))
        res_ok = analyze.assess_rfc8305_conformance([t_ok])
        c_ok = [c for c in res_ok if c["scenario_id"] == "S2"][0]
        self.assertEqual(c_ok["check_id"], "RFC8305-SEC5-CAD-10MS-FLOOR")
        self.assertEqual(c_ok["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(c_ok["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
        self.assertEqual(c_ok["recommendation_alignment_status"], "ALIGNED")

        # 5. 10 ms criterion is described as minimum spacing requirement, not immediate-RST retry
        self.assertIn("Subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt", s2["rfc_specification_requirement"])
        self.assertNotIn("SHOULD start immediately upon TCP RST", s2["rfc_specification_requirement"])
        self.assertIn("subsequent connection attempts MUST NOT start within 10 milliseconds of the previous attempt", s2["specification_context"])
        self.assertIn("Neither specification contains an immediate-retry requirement upon TCP RST", s2["specification_context"])

        # 6. Regenerated assessment is deterministic
        report2 = analyze.generate_analysis_report(trials, exclusions, seed=42)
        s2_run1 = json.dumps(check_map["RFC8305-SEC5-CAD-10MS-FLOOR"], sort_keys=True)
        s2_run2 = json.dumps({c["check_id"]: c for c in report2["rfc8305_assessment"]}["RFC8305-SEC5-CAD-10MS-FLOOR"], sort_keys=True)
        self.assertEqual(s2_run1, s2_run2)


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
        self.assertEqual(rfc_map["RFC8305-SEC2-IPV6-PREFERENCE"]["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-10MS-FLOOR"]["status"], "NOT_ASSESSED")
        self.assertNotIn("RFC8305-SEC5-IMMEDIATE-RST-FALLBACK", rfc_map)
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-SYN-TIMEOUT"]["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(rfc_map["RFC8305-SEC5-CAD-HIGH-LATENCY"]["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(rfc_map["RFC8305-SEC3-RESOLUTION-DELAY"]["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(rfc_map["RFC8305-SEC4-HISTORICAL-STATE"]["status"], "NOT_ASSESSED")
        self.assertEqual(rfc_map["HEV3-DRAFT04-SEC6.1-QUIC"]["status"], "OUT_OF_SCOPE")
        self.assertNotIn("RFC8305-SEC7-STATEFULNESS-CACHING", rfc_map)
        self.assertNotIn("RFC8305-SEC8-NON-TCP-TRANSPORTS", rfc_map)

        # S4 assessment details:
        s4_check = rfc_map["RFC8305-SEC5-CAD-HIGH-LATENCY"]
        self.assertEqual(s4_check["sample_size"], 40)
        self.assertEqual(s4_check["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4_check["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4_check["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4_check["recommendation_alignment_status"], "ALIGNED")
        self.assertEqual(s4_check["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")
        self.assertIn("39/40", s4_check["evidence_summary"])
        self.assertIn("trial-20261029222109-5c74c26a", s4_check["evidence_summary"])
        self.assertIn("Google Chrome: 20/20", s4_check["evidence_summary"])
        self.assertIn("Firefox: 19/20", s4_check["evidence_summary"])

        # S6 assessment details:
        s6_check = rfc_map["RFC8305-SEC3-RESOLUTION-DELAY"]
        self.assertEqual(s6_check["sample_size"], 40)
        self.assertEqual(s6_check["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(s6_check["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertIn("40/40", s6_check["evidence_summary"])
        self.assertIn("Google Chrome", s6_check["evidence_summary"])
        self.assertIn("Firefox", s6_check["evidence_summary"])
        self.assertIn("0 IPv4 attempts", s6_check["evidence_summary"])
        self.assertNotIn("trial-20261028171417-b2d83f2f", s6_check["evidence_summary"])
        self.assertNotIn("515.27", s6_check["evidence_summary"])
        self.assertIn("starts before the positive AAAA response is an observed recommendation-level criterion mismatch", s6_check["reasoning"])
        self.assertNotIn("or where an IPv4 attempt starts within 50ms, conform", s6_check["reasoning"])


class TestSchemaEvolutionAndPhaseC1Metrics(unittest.TestCase):
    """
    Milestone 2 Batch C1 Schema Evolution & Phase C1 Metrics Tests in analyze.py:
    - Schema 1.1.0 ingestion, validation, and TrialEvidence population
    - Schema 1.0.0 backward compatibility
    - Fail-closed rejection of unsupported schema versions (CORRUPTED_RECORD)
    - Strict null preservation (no coercion to 0.0)
    - Type verification and corrupt record exclusion
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_schema_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_1_1_0_validation_and_loading(self):
        """Schema 1.1.0 trial record validates as VALID_LIVE and populates all Phase C1 fields."""
        trial_dict = _create_synthetic_trial(trial_id="trial-test-c1-110", scenario_id="S0")
        trial_dict["schema_version"] = "1.1.0"
        trial_dict["metrics"] = {
            "t_connect_ms": 25.5,
            "t_setup_total_ms": 30.0,
            "syn_to_synack_ms": 22.0,
            "dns_query_to_first_payload_ms": 65.0,
            "dns_last_positive_response_to_first_payload_ms": 45.0,
            "null_reasons": {}
        }
        trial_dict["primary_flow"] = {
            "stream_id": "0",
            "family": "IPv6",
            "winning_family": "ipv6",
            "t_connect_ms": 25.5,
            "t_setup_total_ms": 30.0,
            "syn_to_synack_ms": 22.0,
        }
        trial_dict["dns_transactions"] = [
            {"dns_id": 0x1234, "qname": "trial-test-c1-110.he.test", "qtype": "AAAA", "duration_ms": 5.0}
        ]
        trial_dict["https_svcb_queries"] = [
            {"dns_id": 0x5678, "qname": "trial-test-c1-110.he.test", "qtype": "HTTPS"}
        ]

        result_path = self.temp_dir / "result.json"
        result_path.write_text(json.dumps(trial_dict), encoding="utf-8")

        validity, reason = analyze.validate_trial_record(trial_dict, result_path)
        self.assertEqual(validity, "VALID_LIVE")
        self.assertIsNone(reason)

        evidence = analyze.load_trial_from_json(result_path)
        self.assertEqual(evidence.validity_category, "VALID_LIVE")
        self.assertAlmostEqual(evidence.t_connect_ms, 25.5)
        self.assertAlmostEqual(evidence.t_setup_total_ms, 30.0)
        self.assertAlmostEqual(evidence.syn_to_synack_ms, 22.0)
        self.assertAlmostEqual(evidence.dns_query_to_first_payload_ms, 65.0)
        self.assertAlmostEqual(evidence.dns_last_positive_response_to_first_payload_ms, 45.0)
        self.assertIsInstance(evidence.primary_flow, dict)
        self.assertEqual(len(evidence.dns_transactions), 1)
        self.assertEqual(len(evidence.https_svcb_queries), 1)

    def test_schema_1_0_0_backward_compatibility(self):
        """Schema 1.0.0 record validates and loads correctly with fallback metrics."""
        trial_dict = _create_synthetic_trial(trial_id="trial-test-c1-100", scenario_id="S0", setup_time_ms=21.5)
        trial_dict["schema_version"] = "1.0.0"

        result_path = self.temp_dir / "result.json"
        result_path.write_text(json.dumps(trial_dict), encoding="utf-8")

        validity, reason = analyze.validate_trial_record(trial_dict, result_path)
        self.assertEqual(validity, "VALID_LIVE")
        self.assertIsNone(reason)

        evidence = analyze.load_trial_from_json(result_path)
        self.assertEqual(evidence.validity_category, "VALID_LIVE")
        self.assertAlmostEqual(evidence.connection_setup_time_ms, 21.5)

    def test_fail_closed_unsupported_schema_versions(self):
        """Any schema version outside {1.0.0, 1.1.0} fails closed as CORRUPTED_RECORD."""
        invalid_versions = ["1.0.1", "1.2.0", "2.0.0", "0.9.0", "", None, 1.1, 1]
        for bad_ver in invalid_versions:
            trial_dict = _create_synthetic_trial(trial_id=f"trial-bad-{bad_ver}")
            trial_dict["schema_version"] = bad_ver

            result_path = self.temp_dir / f"result_{bad_ver}.json"
            validity, reason = analyze.validate_trial_record(trial_dict, result_path)
            self.assertEqual(validity, "CORRUPTED_RECORD", f"Failed to reject invalid version: {bad_ver}")
            self.assertIn("Schema version mismatch", reason)

    def test_null_preservation_not_coerced_to_zero(self):
        """Incomplete handshakes retain explicit nulls and null reasons without zero coercion."""
        trial_dict = _create_synthetic_trial(trial_id="trial-null-test", scenario_id="S1")
        trial_dict["schema_version"] = "1.1.0"
        trial_dict["metrics"] = {
            "t_connect_ms": None,
            "t_setup_total_ms": None,
            "syn_to_synack_ms": None,
            "null_reasons": {
                "t_connect_ms": "INDETERMINATE_NO_FINAL_ACK",
                "syn_to_synack_ms": "INDETERMINATE_NO_SYNACK"
            }
        }
        trial_dict["primary_flow"] = {
            "stream_id": "0",
            "family": "IPv6",
            "t_connect_ms": None,
            "t_setup_total_ms": None,
            "syn_to_synack_ms": None,
        }
        result_path = self.temp_dir / "result_null.json"
        result_path.write_text(json.dumps(trial_dict), encoding="utf-8")

        evidence = analyze.load_trial_from_json(result_path)
        self.assertIsNone(evidence.t_connect_ms)
        self.assertIsNone(evidence.t_setup_total_ms)
        self.assertIsNone(evidence.syn_to_synack_ms)
        self.assertIsNotNone(evidence.null_reasons)
        self.assertEqual(evidence.null_reasons.get("t_connect_ms"), "INDETERMINATE_NO_FINAL_ACK")
        self.assertEqual(evidence.null_reasons.get("syn_to_synack_ms"), "INDETERMINATE_NO_SYNACK")

    # =========================================================================
    # DEFECT-C1-CHALLENGE-01 Regression Suite: Deep Field Type Enforcement
    # =========================================================================

    def test_validation_rejects_string_metrics_as_corrupted(self):
        """
        DEFECT-C1-CHALLENGE-01: Verifies that trial records containing non-numeric strings
        (or other non-null, non-numeric types) in numeric metric fields fail closed.
        They must evaluate to ('CORRUPTED_RECORD', ...) in validate_trial_record,
        load with validity_category='CORRUPTED_RECORD' in load_trial_from_json,
        and be strictly excluded from VALID_LIVE.
        """
        test_cases = [
            ("metrics", "t_connect_ms", "twenty", "String representation in metrics.t_connect_ms"),
            ("metrics", "t_connect_ms", "", "Empty string in metrics.t_connect_ms"),
            ("metrics", "t_connect_ms", "25.5ms", "String with units in metrics.t_connect_ms"),
            ("metrics", "t_connect_ms", {"bad": "type"}, "Dictionary in metrics.t_connect_ms"),
            ("metrics", "t_connect_ms", [25.5], "List in metrics.t_connect_ms"),
            ("metrics", "t_setup_total_ms", "thirty", "String in metrics.t_setup_total_ms"),
            ("metrics", "syn_to_synack_ms", "invalid", "String in metrics.syn_to_synack_ms"),
            ("metrics", "connection_attempt_delay_ms", "cad_string", "String in metrics.connection_attempt_delay_ms"),
            ("metrics", "dns_query_to_first_payload_ms", "payload_delay", "String in metrics.dns_query_to_first_payload_ms"),
            ("metrics", "dns_last_positive_response_to_first_payload_ms", "late", "String in metrics.dns_last_positive_response_to_first_payload_ms"),
            ("metrics", "dns_resolution_time_ms", "five", "String in metrics.dns_resolution_time_ms"),
            ("metrics", "dns_latency_a_ms", "five", "String in metrics.dns_latency_a_ms"),
            ("metrics", "dns_latency_aaaa_ms", "five", "String in metrics.dns_latency_aaaa_ms"),
            ("primary_flow", "t_connect_ms", "twenty", "String in primary_flow.t_connect_ms"),
            ("primary_flow", "t_setup_total_ms", "thirty", "String in primary_flow.t_setup_total_ms"),
            ("primary_flow", "syn_to_synack_ms", "bad", "String in primary_flow.syn_to_synack_ms"),
            ("network_observations", "connection_setup_time_ms", "fast", "String in network_observations.connection_setup_time_ms"),
            ("network_observations", "connection_attempt_delay_ms", "delayed", "String in network_observations.connection_attempt_delay_ms"),
        ]

        for idx, (section, field, bad_val, desc) in enumerate(test_cases):
            trial = _create_synthetic_trial(trial_id=f"corrupt-metric-{idx}", scenario_id="S0")
            trial["schema_version"] = "1.1.0"
            if "metrics" not in trial:
                trial["metrics"] = {}
            if "primary_flow" not in trial:
                trial["primary_flow"] = {"stream_id": "0", "family": "IPv6"}

            if section not in trial or not isinstance(trial[section], dict):
                trial[section] = {}
            trial[section][field] = bad_val

            result_file = self.temp_dir / f"corrupt_metric_{idx}.json"
            result_file.write_text(json.dumps(trial), encoding="utf-8")

            # 1. validate_trial_record must reject fail-closed
            validity, reason = analyze.validate_trial_record(trial, result_file)
            self.assertEqual(
                validity,
                "CORRUPTED_RECORD",
                f"Failed for {desc} ({section}.{field}={bad_val!r}): Expected CORRUPTED_RECORD, got {validity}"
            )
            self.assertIsNotNone(reason, f"Expected non-empty exclusion reason for {desc}")
            self.assertNotEqual(validity, "VALID_LIVE", f"{desc} must never be classified as VALID_LIVE")

            # 2. load_trial_from_json must load safely without unhandled exception and retain CORRUPTED_RECORD
            evidence = analyze.load_trial_from_json(result_file)
            self.assertEqual(
                evidence.validity_category,
                "CORRUPTED_RECORD",
                f"Failed for {desc}: TrialEvidence validity_category must be CORRUPTED_RECORD, got {evidence.validity_category}"
            )
            self.assertIsNotNone(evidence.exclusion_reason)

    test_deep_field_type_enforcement_string_in_numeric_metric_rejected = test_validation_rejects_string_metrics_as_corrupted
    test_deep_field_type_validation_rejects_strings = test_validation_rejects_string_metrics_as_corrupted

    def test_validation_rejects_boolean_metrics_as_corrupted(self):
        """
        DEFECT-C1-CHALLENGE-01: Verifies that boolean values (True/False) in numeric
        metric fields are rejected as CORRUPTED_RECORD and NOT silently coerced to 1.0 or 0.0.
        In Python, isinstance(True, int) is True, creating a dangerous silent coercion trap
        where float(True) produces 1.0ms latency.
        """
        bool_cases = [
            ("metrics", "t_connect_ms", True),
            ("metrics", "t_connect_ms", False),
            ("metrics", "t_setup_total_ms", True),
            ("metrics", "syn_to_synack_ms", True),
            ("metrics", "dns_latency_a_ms", True),
            ("metrics", "dns_latency_aaaa_ms", False),
            ("metrics", "dns_resolution_time_ms", True),
            ("primary_flow", "t_connect_ms", True),
            ("primary_flow", "t_setup_total_ms", False),
            ("network_observations", "connection_setup_time_ms", True),
            ("network_observations", "connection_attempt_delay_ms", False),
        ]

        for idx, (section, field, bool_val) in enumerate(bool_cases):
            trial = _create_synthetic_trial(trial_id=f"bool-metric-{idx}", scenario_id="S0")
            trial["schema_version"] = "1.1.0"
            if "metrics" not in trial:
                trial["metrics"] = {}
            if "primary_flow" not in trial:
                trial["primary_flow"] = {"stream_id": "0", "family": "IPv6"}

            trial[section][field] = bool_val

            result_file = self.temp_dir / f"bool_metric_{idx}.json"
            result_file.write_text(json.dumps(trial), encoding="utf-8")

            # 1. validate_trial_record must reject boolean as CORRUPTED_RECORD
            validity, reason = analyze.validate_trial_record(trial, result_file)
            self.assertEqual(
                validity,
                "CORRUPTED_RECORD",
                f"Boolean {bool_val} in {section}.{field} was not rejected as CORRUPTED_RECORD (got {validity})"
            )
            self.assertIsNotNone(reason)

            # 2. load_trial_from_json must not coerce True to 1.0 or False to 0.0
            evidence = analyze.load_trial_from_json(result_file)
            self.assertEqual(evidence.validity_category, "CORRUPTED_RECORD")

            # Explicitly guard against silent float(True) coercion
            if field == "t_connect_ms" and bool_val is True:
                self.assertNotEqual(
                    evidence.t_connect_ms,
                    1.0,
                    "Silent coercion detected: Boolean True in t_connect_ms was coerced to 1.0"
                )
            if field == "connection_setup_time_ms" and bool_val is True:
                self.assertNotEqual(
                    evidence.connection_setup_time_ms,
                    1.0,
                    "Silent coercion detected: Boolean True in connection_setup_time_ms was coerced to 1.0"
                )

    test_deep_field_type_enforcement_boolean_rejected = test_validation_rejects_boolean_metrics_as_corrupted
    test_deep_field_type_validation_rejects_booleans = test_validation_rejects_boolean_metrics_as_corrupted

    def test_validation_rejects_invalid_packet_count_types(self):
        """
        DEFECT-C1-CHALLENGE-01: Verifies that non-int values in capture_metadata["packet_count"]
        do not crash validate_trial_record with unhandled TypeError (e.g. '<=' not supported between str and int).
        Non-integer packet counts must fail closed safely as CORRUPTED_RECORD.
        """
        bad_packet_counts = [
            ("invalid_count_string", "Non-numeric string"),
            ("120", "Numeric string"),
            ("", "Empty string"),
            (True, "Boolean True (would satisfy packet_count > 0 without bool guard)"),
            (False, "Boolean False"),
            (120.5, "Float packet count (packets must be discrete integers)"),
            ({"count": 100}, "Dictionary packet count"),
            ([100], "List packet count"),
        ]

        for idx, (bad_cnt, desc) in enumerate(bad_packet_counts):
            trial = _create_synthetic_trial(trial_id=f"bad-pkt-{idx}", scenario_id="S0")
            trial["schema_version"] = "1.1.0"
            trial["capture_metadata"]["packet_count"] = bad_cnt

            result_file = self.temp_dir / f"bad_pkt_{idx}.json"
            result_file.write_text(json.dumps(trial), encoding="utf-8")

            # 1. validate_trial_record must not raise TypeError or any unhandled exception
            try:
                validity, reason = analyze.validate_trial_record(trial, result_file)
            except Exception as exc:
                self.fail(f"validate_trial_record crashed with {type(exc).__name__}: {exc} for {desc}")

            self.assertEqual(
                validity,
                "CORRUPTED_RECORD",
                f"Non-integer packet_count ({desc}) must be rejected as CORRUPTED_RECORD, got {validity}"
            )
            self.assertIsNotNone(reason)

            # 2. load_trial_from_json must also succeed safely without crash
            try:
                evidence = analyze.load_trial_from_json(result_file)
            except Exception as exc:
                self.fail(f"load_trial_from_json crashed with {type(exc).__name__}: {exc} for {desc}")

            self.assertEqual(evidence.validity_category, "CORRUPTED_RECORD")

    test_deep_field_type_enforcement_packet_count_string_does_not_crash = test_validation_rejects_invalid_packet_count_types
    test_packet_count_string_fails_closed_without_type_error = test_validation_rejects_invalid_packet_count_types

    def test_loader_handles_corrupted_metrics_gracefully(self):
        """
        DEFECT-C1-CHALLENGE-01: Verifies conversion shielding and defense-in-depth in
        load_trial_from_json. Even if unexpected types or corrupt values bypass or
        occur outside validate_trial_record (e.g. status_code, browser duration,
        or uncoerced metrics), load_trial_from_json catches the exception, avoids
        crashing the process, and returns a safe CORRUPTED_RECORD TrialEvidence.
        """
        conversion_defect_cases = [
            ({"http_outcome": {"status_code": "not_an_int", "success": True}}, "Corrupted status_code string"),
            ({"browser": {"name": "chrome", "duration_ms": "slow"}}, "Corrupted browser duration string"),
            ({"metrics": {"t_connect_ms": "cannot_convert"}}, "Corrupted metric string bypassing validation"),
            ({"network_observations": {"connection_attempt_delay_ms": "bad_float"}}, "Corrupted CAD string"),
        ]

        for idx, (override_dict, desc) in enumerate(conversion_defect_cases):
            trial = _create_synthetic_trial(trial_id=f"shield-test-{idx}", scenario_id="S0")
            trial["schema_version"] = "1.1.0"
            for k, v in override_dict.items():
                if isinstance(v, dict) and isinstance(trial.get(k), dict):
                    trial[k].update(v)
                else:
                    trial[k] = v

            result_file = self.temp_dir / f"shield_test_{idx}.json"
            result_file.write_text(json.dumps(trial), encoding="utf-8")

            try:
                evidence = analyze.load_trial_from_json(result_file)
            except Exception as exc:
                self.fail(
                    f"load_trial_from_json raised uncaught exception {type(exc).__name__}: {exc} for {desc}"
                )

            # Record must fail closed as CORRUPTED_RECORD
            self.assertEqual(
                evidence.validity_category,
                "CORRUPTED_RECORD",
                f"Expected CORRUPTED_RECORD for {desc}, got {evidence.validity_category}"
            )
            self.assertIsNotNone(evidence.exclusion_reason)

    test_load_trial_from_json_shields_unhandled_type_conversions = test_loader_handles_corrupted_metrics_gracefully

    def test_directory_loader_isolates_corrupted_files(self):
        """
        DEFECT-C1-CHALLENGE-01: Verifies campaign directory scanning isolation.
        When scanning a directory containing a mix of valid live trials and corrupted trials
        (e.g. string metrics, non-int packet count, boolean metric), load_trials_from_directory
        must not abort. It must load all trials, classifying valid ones as VALID_LIVE and
        corrupted ones as CORRUPTED_RECORD, preventing pipeline interruption or data poisoning.
        """
        campaign_dir = self.temp_dir / "mixed_campaign"
        campaign_dir.mkdir(parents=True, exist_ok=True)

        # 1. Valid Trial A (VALID_LIVE)
        trial_a_dir = campaign_dir / "trial_01"
        trial_a_dir.mkdir()
        trial_a = _create_synthetic_trial(trial_id="trial-01", scenario_id="S0")
        trial_a["schema_version"] = "1.1.0"
        trial_a["metrics"] = {"t_connect_ms": 20.0, "t_setup_total_ms": 20.0, "syn_to_synack_ms": 19.0, "null_reasons": {}}
        trial_a["primary_flow"] = {"stream_id": "0", "family": "IPv6", "t_connect_ms": 20.0, "t_setup_total_ms": 20.0, "syn_to_synack_ms": 19.0}
        (trial_a_dir / "result.json").write_text(json.dumps(trial_a), encoding="utf-8")

        # 2. Corrupted Trial B (String in metric: t_connect_ms = "twenty")
        trial_b_dir = campaign_dir / "trial_02"
        trial_b_dir.mkdir()
        trial_b = _create_synthetic_trial(trial_id="trial-02", scenario_id="S0")
        trial_b["schema_version"] = "1.1.0"
        trial_b["metrics"] = {"t_connect_ms": "twenty", "t_setup_total_ms": 25.0}
        (trial_b_dir / "result.json").write_text(json.dumps(trial_b), encoding="utf-8")

        # 3. Corrupted Trial C (Non-int packet_count: "invalid")
        trial_c_dir = campaign_dir / "trial_03"
        trial_c_dir.mkdir()
        trial_c = _create_synthetic_trial(trial_id="trial-03", scenario_id="S0")
        trial_c["schema_version"] = "1.1.0"
        trial_c["capture_metadata"]["packet_count"] = "invalid_count"
        (trial_c_dir / "result.json").write_text(json.dumps(trial_c), encoding="utf-8")

        # 4. Corrupted Trial D (Boolean metric: True in t_connect_ms)
        trial_d_dir = campaign_dir / "trial_04"
        trial_d_dir.mkdir()
        trial_d = _create_synthetic_trial(trial_id="trial-04", scenario_id="S0")
        trial_d["schema_version"] = "1.1.0"
        trial_d["metrics"] = {"t_connect_ms": True}
        (trial_d_dir / "result.json").write_text(json.dumps(trial_d), encoding="utf-8")

        # 5. Valid Trial E (VALID_LIVE)
        trial_e_dir = campaign_dir / "trial_05"
        trial_e_dir.mkdir()
        trial_e = _create_synthetic_trial(trial_id="trial-05", scenario_id="S0")
        trial_e["schema_version"] = "1.1.0"
        trial_e["metrics"] = {"t_connect_ms": 30.0, "t_setup_total_ms": 30.0, "syn_to_synack_ms": 29.0, "null_reasons": {}}
        trial_e["primary_flow"] = {"stream_id": "0", "family": "IPv6", "t_connect_ms": 30.0, "t_setup_total_ms": 30.0, "syn_to_synack_ms": 29.0}
        (trial_e_dir / "result.json").write_text(json.dumps(trial_e), encoding="utf-8")

        # Execute directory scan
        try:
            loaded_trials = analyze.load_trials_from_directory(campaign_dir)
        except Exception as exc:
            self.fail(f"load_trials_from_directory crashed on mixed directory: {type(exc).__name__}: {exc}")

        # Assert all 5 trials were scanned and ingested
        self.assertEqual(len(loaded_trials), 5, f"Expected 5 trials loaded, got {len(loaded_trials)}")

        # Verify separation of validity categories
        valid_live = [t for t in loaded_trials if t.validity_category == "VALID_LIVE"]
        corrupted = [t for t in loaded_trials if t.validity_category == "CORRUPTED_RECORD"]

        self.assertEqual(len(valid_live), 2, f"Expected exactly 2 VALID_LIVE trials, got {len(valid_live)}")
        self.assertEqual(len(corrupted), 3, f"Expected exactly 3 CORRUPTED_RECORD trials, got {len(corrupted)}")

        # Verify valid trials metrics remain pure and uncorrupted
        valid_t_connect = [t.t_connect_ms for t in valid_live]
        self.assertEqual(valid_t_connect, [20.0, 30.0])
        mean_t_connect = sum(valid_t_connect) / len(valid_t_connect)
        self.assertAlmostEqual(mean_t_connect, 25.0)

        # Verify corrupted trials did not pollute valid set and contain exclusion reasons
        for bad_t in corrupted:
            self.assertIsNotNone(bad_t.exclusion_reason)

    test_load_trials_from_directory_isolates_corrupted_record_without_crash = test_directory_loader_isolates_corrupted_files
    test_directory_scan_survives_corrupted_records = test_directory_loader_isolates_corrupted_files


class TestResearchCohortKeysAndUnifiedEnums(unittest.TestCase):
    """
    Unit tests for Finding C4-01 (Version-Aware Research Cohort Keys)
    and Finding C2-02 (Canonical Shared Enums).
    """

    def test_canonical_enums_defined_and_string_compatible(self):
        """Validates that all canonical enums match Metric Contract v1.1.0 specifications."""
        # FallbackClassification
        self.assertEqual(analyze.FallbackClassification.DIRECT_IPV6, "DIRECT_IPV6")
        self.assertEqual(analyze.FallbackClassification.DIRECT_IPV4, "DIRECT_IPV4")
        self.assertEqual(analyze.FallbackClassification.IPV6_TO_IPV4_FALLBACK, "IPV6_TO_IPV4_FALLBACK")
        self.assertEqual(analyze.FallbackClassification.IPV4_TO_IPV6_FALLBACK, "IPV4_TO_IPV6_FALLBACK")
        self.assertEqual(analyze.FallbackClassification.CONNECTION_FAILED, "CONNECTION_FAILED")
        self.assertEqual(analyze.FallbackClassification.INCONCLUSIVE, "INCONCLUSIVE")

        # TrialValidity
        self.assertEqual(analyze.TrialValidity.VALID_LIVE, "VALID_LIVE")
        self.assertEqual(analyze.TrialValidity.SIMULATION, "SIMULATION")
        self.assertEqual(analyze.TrialValidity.CLEANUP_FAILURE, "CLEANUP_FAILURE")
        self.assertEqual(analyze.TrialValidity.MEASUREMENT_FAILURE, "MEASUREMENT_FAILURE")
        self.assertEqual(analyze.TrialValidity.CORRUPTED_RECORD, "CORRUPTED_RECORD")

        # ConnectionOutcome
        self.assertEqual(analyze.ConnectionOutcome.ESTABLISHED_PRIMARY, "ESTABLISHED_PRIMARY")
        self.assertEqual(analyze.ConnectionOutcome.ESTABLISHED_ANCILLARY, "ESTABLISHED_ANCILLARY")
        self.assertEqual(analyze.ConnectionOutcome.RESET, "RESET")
        self.assertEqual(analyze.ConnectionOutcome.NO_SYNACK_TIMEOUT, "NO_SYNACK_TIMEOUT")
        self.assertEqual(analyze.ConnectionOutcome.ABANDONED, "ABANDONED")
        self.assertEqual(analyze.ConnectionOutcome.INDETERMINATE, "INDETERMINATE")

        # EventSource
        self.assertEqual(analyze.EventSource.HARNESS, "HARNESS")
        self.assertEqual(analyze.EventSource.PCAP, "PCAP")
        self.assertEqual(analyze.EventSource.BROWSER_TELEMETRY, "BROWSER_TELEMETRY")

    def test_research_cohort_key_construction_and_serialization(self):
        """Finding C4-01: Verifies composite cohort key hashing, serialization, and slug derivation."""
        key = analyze.ResearchCohortKey(
            browser_name="google-chrome",
            browser_version="156.0.8078.73",
            os_kernel="Linux-6.18.58.1",
            host_class="wsl2_x86_64",
            git_commit="7c6ab23",
            condition_id="S0",
            resolver_mode="in_lab_dns",
        )

        canonical = key.to_canonical_string()
        self.assertEqual(
            canonical,
            "google-chrome:156.0.8078.73:Linux-6.18.58.1:wsl2_x86_64:7c6ab23:S0:in_lab_dns"
        )

        slug = key.to_short_slug()
        self.assertEqual(slug, "google-chrome-156-wsl2_x86_64-s0")

    def test_trial_evidence_cohort_key_derivation(self):
        """Verifies make_research_cohort_key and TrialEvidence.get_research_cohort_key."""
        evidence = analyze.TrialEvidence(
            trial_id="trial-test-01",
            scenario_id="S5",
            scenario_name="ipv6_syn_loss_50pct",
            browser_name="firefox",
            browser_version="159.0",
            execution_mode="LIVE",
            is_simulation=False,
            http_status_code=200,
            http_success=True,
            winning_address_family="IPv6",
            winning_ip="2001:db8:2::10",
            connection_setup_time_ms=25.0,
            connection_attempt_delay_ms=None,
            dns_latency_a_ms=5.0,
            dns_latency_aaaa_ms=5.0,
            dns_resolution_time_ms=5.0,
            browser_duration_ms=1000.0,
            packet_count=50,
            pcap_valid=True,
            pcap_sha256="abc",
            scenario_restored=True,
            baseline_verified=True,
            cleanup_errors=[],
            classification="DIRECT_IPV6",
            classification_reason="Clean IPv6",
            validity_category="VALID_LIVE",
            exclusion_reason=None,
            source_path="/tmp/test",
            raw_dict={
                "environment_metadata": {
                    "os_kernel": "Linux-6.8.0",
                    "host_class": "baremetal_linux_x86_64",
                    "git_commit": "abcdef1",
                    "resolver_mode": "delayed_dns",
                }
            }
        )

        cohort_key = evidence.get_research_cohort_key()
        self.assertEqual(cohort_key.browser_name, "firefox")
        self.assertEqual(cohort_key.browser_version, "159.0")
        self.assertEqual(cohort_key.condition_id, "S5")
        self.assertEqual(cohort_key.os_kernel, "Linux-6.8.0")
        self.assertEqual(cohort_key.host_class, "baremetal_linux_x86_64")
        self.assertEqual(cohort_key.to_short_slug(), "firefox-159-baremetal_linux_x86_64-s5")


class TestP0WorkstreamBCADSeparation(unittest.TestCase):
    """
    Dedicated tests for P0 Workstream B (Audit Findings #3 and #10):
    Separation of CAD timing measurements from path-selection outcomes.
    Directly covers the 6 required cases from Section 4.3.
    """

    def test_case_1_timing_values_inside_range_with_ipv6_win(self):
        """Case 1: Timing values all inside [100, 2000]ms range alongside an IPv6 win trial."""
        t1 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t1-v4", scenario_id="S4", winning_family="IPv4", cad_ms=250.0, ipv4_attempt=True
        ))
        t2 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t2-v4", scenario_id="S4", winning_family="IPv4", cad_ms=350.0, ipv4_attempt=True
        ))
        t3_v6 = _dict_to_evidence(_create_synthetic_trial(
            trial_id="t3-v6", scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        ))
        checks = analyze.assess_rfc8305_conformance([t1, t2, t3_v6])
        s4 = [c for c in checks if c["scenario_id"] == "S4"][0]
        self.assertEqual(s4["status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4["recommended_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4["recommendation_alignment_status"], "ALIGNED")
        self.assertEqual(s4["mandatory_floor_status"], "MEETS_MANDATORY_FLOOR")

    def test_case_2_genuine_measured_timing_deviation_low_and_high(self):
        """Case 2: Genuine measured timing deviation (<100ms or >2000ms)."""
        # Low timing deviation (< 100ms, e.g. 50ms)
        t_low = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv4", cad_ms=50.0, ipv4_attempt=True
        ))
        s4_low = [c for c in analyze.assess_rfc8305_conformance([t_low]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(s4_low["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(s4_low["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4_low["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(s4_low["recommendation_alignment_status"], "OUTSIDE_RECOMMENDED_RANGE")

        # High timing deviation (> 2000ms, e.g. 2500ms)
        t_high = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv4", cad_ms=2500.0, ipv4_attempt=True
        ))
        s4_high = [c for c in analyze.assess_rfc8305_conformance([t_high]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(s4_high["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(s4_high["mandatory_status"], "OBSERVED_BEHAVIOR")
        self.assertEqual(s4_high["recommended_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(s4_high["recommendation_alignment_status"], "OUTSIDE_RECOMMENDED_RANGE")

    def test_case_3_trial_where_cad_is_unavailable(self):
        """Case 3: Trial where CAD is unavailable / missing."""
        t_missing = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv4", cad_ms=None, ipv4_attempt=True
        ))
        s4 = [c for c in analyze.assess_rfc8305_conformance([t_missing]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(s4["status"], "NOT_ASSESSED")
        self.assertEqual(s4["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(s4["recommended_status"], "NOT_ASSESSED")
        self.assertEqual(s4["recommendation_alignment_status"], "NOT_ASSESSED")

    def test_case_4_trial_with_no_observed_alternative_family_attempt(self):
        """Case 4: Trial with no observed alternative-family attempt (direct single-family completion)."""
        t_no_alt = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv6", cad_ms=None, ipv4_attempt=False
        ))
        s4 = [c for c in analyze.assess_rfc8305_conformance([t_no_alt]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(s4["status"], "NOT_ASSESSED")
        self.assertEqual(s4["mandatory_status"], "NOT_APPLICABLE")
        self.assertEqual(s4["recommended_status"], "NOT_ASSESSED")

    def test_case_5_valid_attempt_interval_below_10ms_mandatory_floor(self):
        """Case 5: Valid attempt interval strictly below the 10ms mandatory floor."""
        t_sub10 = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S4", winning_family="IPv4", cad_ms=6.5, ipv4_attempt=True
        ))
        s4 = [c for c in analyze.assess_rfc8305_conformance([t_sub10]) if c["scenario_id"] == "S4"][0]
        self.assertEqual(s4["status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(s4["mandatory_status"], "POTENTIAL_CRITERION_MISMATCH")
        self.assertEqual(s4["mandatory_floor_status"], "BELOW_MANDATORY_FLOOR")
        self.assertEqual(s4["recommended_status"], "OBSERVED_BEHAVIOR")

    def test_case_6_family_wide_first_syn_offset_without_logical_attempt_pairing(self):
        """Case 6: Family-wide first-SYN offset without logical attempt pairing (S2)."""
        t_s2_unpaired = _dict_to_evidence(_create_synthetic_trial(
            scenario_id="S2", winning_family="IPv4", cad_ms=2.65, attempt_pairing_verified=False
        ))
        checks = analyze.assess_rfc8305_conformance([t_s2_unpaired])
        s2 = [c for c in checks if c["scenario_id"] == "S2"][0]
        self.assertEqual(s2["status"], "NOT_ASSESSED")
        self.assertEqual(s2["mandatory_status"], "NOT_ASSESSED")
        self.assertEqual(s2["recommended_status"], "NOT_ASSESSED")
        self.assertEqual(s2["mandatory_floor_status"], "NOT_ASSESSED")
        self.assertEqual(s2["recommendation_alignment_status"], "NOT_ASSESSED")


if __name__ == "__main__":
    unittest.main()


