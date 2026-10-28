#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Campaign Runner Unit Test Suite
Work Package A8: Campaign Runner & Orchestration Test Suite

Fully mocked, unprivileged test suite verifying:
1. CLI parsing and configuration validation
2. Matrix slot and execution attempt separation (Safety Requirement 1)
3. Manifest concurrency lock and atomic persistence (Safety Requirement 2)
4. Strict reuse of existing A7 evidence-validation rules (Safety Requirement 3)
5. Safe resume with evidence integrity verification and non-overwriting behavior
6. Fail-stop safety: immediate campaign halt upon cleanup or baseline restoration failure
7. S2/S4 documented mismatch preservation in manifest metadata
8. Distinction between valid live, simulation, and measurement failures
"""

import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from typing import Any, Dict, List, Optional
import unittest
from unittest.mock import MagicMock, call, patch

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
import sys
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.run_campaign as run_campaign
import lab.run_trial as run_trial


def _create_dummy_pcap(path: Path, packet_count: int = 1) -> str:
    """Creates a dummy valid PCAP file and returns its hex SHA-256."""
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    body = bytearray(header)
    for i in range(packet_count):
        pkt = b"\x00" * 40
        pkt_hdr = struct.pack("<IIII", 1729000000 + i, 0, len(pkt), len(pkt))
        body += pkt_hdr + pkt
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    import hashlib
    return hashlib.sha256(body).hexdigest()


def _create_mock_trial_result(
    scenario_id: str,
    trial_id: str,
    output_dir: Path,
    is_simulation: bool = False,
    scenario_restored: bool = True,
    baseline_verified: bool = True,
    cleanup_errors: Optional[List[str]] = None,
    packet_count: int = 5,
    http_success: bool = True,
    classification: str = "DIRECT_IPV6"
) -> Dict[str, Any]:
    """Builds a realistic A7 trial result dict and on-disk files."""
    trial_dir = output_dir / "trials" / trial_id
    trial_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = trial_dir / "capture.pcap"
    sha256 = _create_dummy_pcap(pcap_path, packet_count=packet_count)
    result_path = trial_dir / "result.json"

    result = {
        "schema_version": run_trial.SCHEMA_VERSION,
        "trial_id": trial_id,
        "scenario_id": scenario_id,
        "scenario_name": f"name_{scenario_id}",
        "scenario_description": f"desc_{scenario_id}",
        "hostname": f"{trial_id}.he.test",
        "target_url": f"http://{trial_id}.he.test/",
        "execution_mode": "SIMULATION" if is_simulation else "LIVE",
        "is_simulation": is_simulation,
        "timestamps": {
            "start_time": "2026-10-28T18:00:00Z",
            "end_time": "2026-10-28T18:00:01Z",
            "total_duration_ms": 1000.0
        },
        "browser": {
            "name": "google-chrome",
            "executable": "/usr/bin/google-chrome",
            "version": "124.0.0.0",
            "exit_code": 0 if http_success else 1,
            "timed_out": False,
            "duration_ms": 500.0,
            "profile_cleaned": True
        },
        "http_outcome": {
            "status_code": 200 if http_success else None,
            "success": http_success,
            "winning_address_family": "IPv6",
            "winning_ip": "2001:db8:2::10",
            "response_body_bytes": 100
        },
        "dns_observations": {"queries": [], "responses": []},
        "network_observations": {
            "ipv6_attempt": True,
            "ipv4_attempt": False,
            "ipv6_success": True,
            "ipv4_success": False,
            "connection_attempt_delay_ms": None,
            "connection_setup_time_ms": 20.0,
            "fallback_occurred": False,
            "classification": classification,
            "classification_reason": "Direct IPv6 connection"
        },
        "capture_metadata": {
            "pcap_path": str(pcap_path),
            "pcap_sha256": sha256,
            "pcap_size_bytes": pcap_path.stat().st_size,
            "pcap_valid": True,
            "packet_count": packet_count,
            "validation_message": "Valid PCAP",
            "tcpdump_log_path": str(trial_dir / "tcpdump.log")
        },
        "evidence_paths": {
            "trial_dir": str(trial_dir),
            "result_json": str(result_path),
            "capture_pcap": str(pcap_path),
            "tcpdump_log": str(trial_dir / "tcpdump.log"),
            "browser_log": str(trial_dir / "browser.log")
        },
        "cleanup_status": {
            "scenario_restored": scenario_restored,
            "baseline_verified": baseline_verified,
            "profile_cleaned": True,
            "lock_released": True,
            "errors": cleanup_errors if cleanup_errors is not None else []
        }
    }
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


class TestCampaignCLIAndConfig(unittest.TestCase):
    """Test CLI argument parsing and campaign configuration validation."""

    def test_cli_defaults(self):
        args = run_campaign.parse_args([])
        self.assertEqual(args.repetitions, 1)
        self.assertFalse(args.simulation)
        self.assertFalse(args.resume)
        self.assertIn("S0", args.scenarios)
        self.assertIn("S6", args.scenarios)

    def test_cli_custom_scenarios_and_browsers(self):
        args = run_campaign.parse_args(["-s", "S0,S1", "-b", "firefox", "-n", "5", "--simulation"])
        self.assertEqual(args.scenarios, "S0,S1")
        self.assertEqual(args.browsers, "firefox")
        self.assertEqual(args.repetitions, 5)
        self.assertTrue(args.simulation)

    def test_invalid_scenario_rejected(self):
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(scenarios=["S0", "S99"])
        self.assertIn("Invalid scenario", str(ctx.exception))

    def test_invalid_repetitions_rejected(self):
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(repetitions=0)
        self.assertIn("Repetitions must be >= 1", str(ctx.exception))

    @patch("lab.run_trial.find_browser_runtime")
    def test_live_browser_validation_fails_if_runtime_missing(self, mock_find):
        mock_find.side_effect = run_trial.BrowserPreflightError("Browser not found")
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(browsers=["nonexistent-browser"], is_simulation=False)
        self.assertIn("Browser validation failed", str(ctx.exception))


class TestMatrixAndAttemptSeparation(unittest.TestCase):
    """
    Verifies Safety Requirement 1:
    Strictly distinguishes planned matrix slots from concrete execution attempts.
    """

    def test_build_matrix_slots_dimensions(self):
        scenarios = ["S0", "S1", "S2"]
        browsers = ["google-chrome", "firefox"]
        repetitions = 3
        slots = run_campaign.build_matrix_slots(scenarios, browsers, repetitions)
        self.assertEqual(len(slots), len(scenarios) * len(browsers) * repetitions)

    def test_matrix_slots_sequential_ordering(self):
        slots = run_campaign.build_matrix_slots(["S0", "S1"], ["chrome"], 2)
        self.assertEqual(slots[0].scenario_id, "S0")
        self.assertEqual(slots[0].repetition, 1)
        self.assertEqual(slots[1].scenario_id, "S1")
        self.assertEqual(slots[1].repetition, 1)
        self.assertEqual(slots[2].scenario_id, "S0")
        self.assertEqual(slots[2].repetition, 2)
        self.assertEqual(slots[3].scenario_id, "S1")
        self.assertEqual(slots[3].repetition, 2)

    def test_slot_tracks_multiple_attempts_in_history(self):
        slot = run_campaign.MatrixSlot(
            slot_id="slot-001",
            slot_index=1,
            scenario_id="S0",
            browser="chrome",
            repetition=1
        )
        self.assertEqual(slot.status, "PENDING")
        self.assertEqual(len(slot.attempts), 0)

        # Attempt 1: Failed
        att1 = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-1",
            execution_mode="LIVE",
            is_simulation=False,
            timestamps={},
            status="FAILED",
            validity="MEASUREMENT_FAILURE",
            evidence_paths={},
            capture_metadata={},
            http_outcome={},
            network_observations={},
            cleanup_status={},
            error_message="timeout"
        )
        slot.add_attempt(att1)
        self.assertEqual(slot.status, "FAILED")
        self.assertEqual(slot.current_trial_id, "trial-1")
        self.assertEqual(len(slot.attempts), 1)

        # Attempt 2: Succeeded
        att2 = run_campaign.ExecutionAttempt(
            attempt_number=2,
            trial_id="trial-2",
            execution_mode="LIVE",
            is_simulation=False,
            timestamps={},
            status="COMPLETED",
            validity="VALID_LIVE",
            evidence_paths={},
            capture_metadata={},
            http_outcome={},
            network_observations={},
            cleanup_status={},
        )
        slot.add_attempt(att2)
        self.assertEqual(slot.status, "COMPLETED")
        self.assertEqual(slot.current_trial_id, "trial-2")
        self.assertEqual(len(slot.attempts), 2)
        # Attempt 1 record is preserved in history
        self.assertEqual(slot.attempts[0].trial_id, "trial-1")
        self.assertEqual(slot.attempts[1].trial_id, "trial-2")


class TestManifestConcurrencyAndLocking(unittest.TestCase):
    """
    Verifies Safety Requirement 2:
    Prevents concurrent access to one campaign manifest and guarantees atomic saves.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_camp_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_lock_prevents_concurrent_access(self):
        lock_file = self.temp_dir / ".campaign.lock"
        with run_campaign.acquire_manifest_lock(lock_file, timeout=1.0):
            # Attempt to acquire lock in another context with a mock of different PID
            tracker = run_campaign._get_manifest_locks()
            # Temporarily clear local tracker to simulate external concurrent process
            with patch.dict(tracker, {}, clear=True):
                with self.assertRaises(run_campaign.CampaignLockError):
                    with run_campaign.acquire_manifest_lock(lock_file, timeout=0.1):
                        pass

    def test_manifest_lock_supports_reentrancy_in_same_thread(self):
        lock_file = self.temp_dir / ".campaign.lock"
        with run_campaign.acquire_manifest_lock(lock_file, timeout=1.0):
            with run_campaign.acquire_manifest_lock(lock_file, timeout=1.0):
                # Re-entrant acquisition must succeed without deadlock
                self.assertTrue(lock_file.exists())

    def test_manifest_atomic_save_creates_valid_file(self):
        manifest_path = self.temp_dir / run_campaign.MANIFEST_FILENAME
        slots = run_campaign.build_matrix_slots(["S0"], ["chrome"], 1)
        manifest = run_campaign.CampaignManifest(
            campaign_id="test-camp-1",
            output_dir=self.temp_dir,
            scenarios=["S0"],
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots
        )
        manifest.save_atomically()

        self.assertTrue(manifest_path.is_file())
        self.assertFalse((self.temp_dir / f"{run_campaign.MANIFEST_FILENAME}.tmp").exists())
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], run_campaign.SCHEMA_VERSION)
        self.assertEqual(data["campaign_id"], "test-camp-1")
        self.assertEqual(data["summary"]["total_slots"], 1)


class TestEvidenceValidationRules(unittest.TestCase):
    """
    Verifies Safety Requirement 3:
    Uses only existing A7 evidence validation rules (PCAP magic, SHA-256, packet count).
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_valid_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_validate_attempt_evidence_passes_valid_trial(self):
        res = _create_mock_trial_result("S0", "trial-1", self.temp_dir, is_simulation=False)
        result_json_path = Path(res["evidence_paths"]["result_json"])
        is_valid, msg, data = run_campaign.validate_attempt_evidence(
            result_json_path=result_json_path,
            expected_scenario="S0",
            is_simulation=False
        )
        self.assertTrue(is_valid)
        self.assertIn("Evidence verified", msg)

    def test_validate_attempt_evidence_rejects_missing_result_json(self):
        is_valid, msg, _ = run_campaign.validate_attempt_evidence(
            result_json_path=self.temp_dir / "nonexistent.json",
            expected_scenario="S0",
            is_simulation=False
        )
        self.assertFalse(is_valid)
        self.assertIn("missing", msg)

    def test_validate_attempt_evidence_rejects_scenario_mismatch(self):
        res = _create_mock_trial_result("S0", "trial-1", self.temp_dir, is_simulation=False)
        result_json_path = Path(res["evidence_paths"]["result_json"])
        is_valid, msg, _ = run_campaign.validate_attempt_evidence(
            result_json_path=result_json_path,
            expected_scenario="S1",  # Expect S1 but trial was S0
            is_simulation=False
        )
        self.assertFalse(is_valid)
        self.assertIn("Scenario mismatch", msg)

    def test_validate_attempt_evidence_rejects_unverified_baseline(self):
        res = _create_mock_trial_result("S0", "trial-1", self.temp_dir, baseline_verified=False)
        result_json_path = Path(res["evidence_paths"]["result_json"])
        is_valid, msg, _ = run_campaign.validate_attempt_evidence(
            result_json_path=result_json_path,
            expected_scenario="S0",
            is_simulation=False
        )
        self.assertFalse(is_valid)
        self.assertIn("baseline was not verified", msg)

    def test_validate_attempt_evidence_rejects_sha256_mismatch(self):
        res = _create_mock_trial_result("S0", "trial-1", self.temp_dir)
        pcap_path = Path(res["evidence_paths"]["capture_pcap"])
        # Append corrupting bytes to PCAP
        with open(pcap_path, "ab") as f:
            f.write(b"\x99" * 20)

        result_json_path = Path(res["evidence_paths"]["result_json"])
        is_valid, msg, _ = run_campaign.validate_attempt_evidence(
            result_json_path=result_json_path,
            expected_scenario="S0",
            is_simulation=False
        )
        self.assertFalse(is_valid)
        self.assertIn("PCAP", msg)

    def test_validate_attempt_evidence_rejects_zero_packets_in_live_mode(self):
        # Create zero-packet PCAP (only global header)
        trial_dir = self.temp_dir / "trials" / "trial-zero"
        trial_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = trial_dir / "capture.pcap"
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pcap_path.write_bytes(header)
        import hashlib
        pcap_sha = hashlib.sha256(header).hexdigest()

        result_json = trial_dir / "result.json"
        res_data = {
            "schema_version": run_trial.SCHEMA_VERSION,
            "scenario_id": "S0",
            "is_simulation": False,
            "cleanup_status": {"scenario_restored": True, "baseline_verified": True, "errors": []},
            "capture_metadata": {"pcap_path": str(pcap_path), "pcap_sha256": pcap_sha}
        }
        result_json.write_text(json.dumps(res_data))

        is_valid, msg, _ = run_campaign.validate_attempt_evidence(
            result_json_path=result_json,
            expected_scenario="S0",
            is_simulation=False
        )
        self.assertFalse(is_valid)
        self.assertIn("PCAP contains 0 packets", msg)


class TestSafeResume(unittest.TestCase):
    """
    Verifies safe resume behavior:
    1. Skips verified completed trials.
    2. Re-runs unverified or corrupted trials with a NEW unique trial ID without overwriting.
    3. Rejects incompatible resume configurations.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_resume_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_resume_skips_verified_completed_slots(self, mock_run, mock_base):
        # Set up a campaign with 2 slots: S0 and S1
        scenarios = ["S0", "S1"]
        slots = run_campaign.build_matrix_slots(scenarios, ["chrome"], 1)

        # Slot 0 is already completed and verified
        res0 = _create_mock_trial_result("S0", "trial-completed-0", self.temp_dir, is_simulation=True)
        att0 = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-completed-0",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={},
            status="COMPLETED",
            validity="SIMULATION",
            evidence_paths=res0["evidence_paths"],
            capture_metadata=res0["capture_metadata"],
            http_outcome=res0["http_outcome"],
            network_observations=res0["network_observations"],
            cleanup_status=res0["cleanup_status"]
        )
        slots[0].add_attempt(att0)

        manifest = run_campaign.CampaignManifest(
            campaign_id="resume-camp",
            output_dir=self.temp_dir,
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots
        )
        manifest.save_atomically()

        # Mock run_trial to handle the pending slot S1
        def mock_run_trial_side_effect(**kwargs):
            return _create_mock_trial_result("S1", kwargs["trial_id"], self.temp_dir, is_simulation=True)
        mock_run.side_effect = mock_run_trial_side_effect

        runner = run_campaign.CampaignRunner(
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=True,
            resume=True
        )
        res = runner.run()

        # Slot S0 must have been skipped: run_trial only called for S1
        self.assertEqual(mock_run.call_count, 1)
        self.assertEqual(mock_run.call_args[1]["scenario_id"], "S1")
        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["summary"]["completed_slots"], 2)

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_resume_reruns_corrupted_slot_under_new_trial_id(self, mock_run, mock_base):
        # Create a slot with a corrupt PCAP
        scenarios = ["S0"]
        slots = run_campaign.build_matrix_slots(scenarios, ["chrome"], 1)
        res0 = _create_mock_trial_result("S0", "trial-corrupted-old", self.temp_dir, is_simulation=True)

        # Corrupt the PCAP
        Path(res0["evidence_paths"]["capture_pcap"]).write_bytes(b"\x00\x00")

        att0 = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-corrupted-old",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={},
            status="COMPLETED",
            validity="SIMULATION",
            evidence_paths=res0["evidence_paths"],
            capture_metadata=res0["capture_metadata"],
            http_outcome=res0["http_outcome"],
            network_observations=res0["network_observations"],
            cleanup_status=res0["cleanup_status"]
        )
        slots[0].add_attempt(att0)

        manifest = run_campaign.CampaignManifest(
            campaign_id="resume-corrupt-camp",
            output_dir=self.temp_dir,
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots
        )
        manifest.save_atomically()

        # Mock second execution attempt
        def mock_run_trial_side_effect(**kwargs):
            return _create_mock_trial_result("S0", kwargs["trial_id"], self.temp_dir, is_simulation=True)
        mock_run.side_effect = mock_run_trial_side_effect

        runner = run_campaign.CampaignRunner(
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=True,
            resume=True
        )
        res = runner.run()

        # Corrupted slot must have been re-run under a fresh trial ID
        self.assertEqual(mock_run.call_count, 1)
        new_trial_id = mock_run.call_args[1]["trial_id"]
        self.assertNotEqual(new_trial_id, "trial-corrupted-old")

        # Old corrupted evidence is preserved intact
        self.assertTrue((self.temp_dir / "trials" / "trial-corrupted-old").is_dir())
        # New trial directory created separately
        self.assertTrue((self.temp_dir / "trials" / new_trial_id).is_dir())

        # Slot now records 2 attempts
        slot_data = res["matrix_slots"][0]
        self.assertEqual(len(slot_data["attempts"]), 2)
        self.assertEqual(slot_data["attempts"][0]["trial_id"], "trial-corrupted-old")
        self.assertEqual(slot_data["attempts"][1]["trial_id"], new_trial_id)
        self.assertEqual(slot_data["status"], "COMPLETED")

    def test_resume_rejects_incompatible_configuration(self):
        manifest = run_campaign.CampaignManifest(
            campaign_id="resume-diff-camp",
            output_dir=self.temp_dir,
            scenarios=["S0", "S1"],
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=[]
        )
        manifest.save_atomically()

        # Attempt to resume with different scenarios
        runner = run_campaign.CampaignRunner(
            scenarios=["S0", "S2"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=True,
            resume=True
        )
        with self.assertRaises(run_campaign.CampaignResumeError) as ctx:
            runner.initialize_manifest()
        self.assertIn("Resume scenario mismatch", str(ctx.exception))


class TestFailStopSafety(unittest.TestCase):
    """
    Verifies fail-stop behavior:
    Immediately halts execution upon any cleanup or baseline failure.
    Never executes subsequent slots on an impaired lab state.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_failstop_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_fail_stop_halts_campaign_when_cleanup_fails(self, mock_run, mock_base):
        # Configure campaign with S0, S1, S2
        scenarios = ["S0", "S1", "S2"]

        # First trial S0 returns cleanup failure
        def mock_run_trial_side_effect(**kwargs):
            return _create_mock_trial_result(
                kwargs["scenario_id"],
                kwargs["trial_id"],
                self.temp_dir,
                is_simulation=True,
                scenario_restored=False,
                baseline_verified=False,
                cleanup_errors=["nftables restore error"]
            )
        mock_run.side_effect = mock_run_trial_side_effect

        runner = run_campaign.CampaignRunner(
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=True
        )

        with self.assertRaises(run_campaign.CampaignHaltedError) as ctx:
            runner.run()

        self.assertIn("FAIL-STOP", str(ctx.exception))
        # run_trial must have been called ONLY once: S1 and S2 were NOT executed
        self.assertEqual(mock_run.call_count, 1)

        # Inspect saved manifest
        manifest_data = json.loads((self.temp_dir / run_campaign.MANIFEST_FILENAME).read_text())
        self.assertEqual(manifest_data["status"], "HALTED_ON_FAILURE")
        self.assertIn("FAIL-STOP", manifest_data["summary"]["halt_reason"])

        # S0 is marked FAILED with CLEANUP_FAILURE
        self.assertEqual(manifest_data["matrix_slots"][0]["status"], "FAILED")
        self.assertEqual(manifest_data["matrix_slots"][0]["attempts"][0]["validity"], "CLEANUP_FAILURE")

        # S1 and S2 remain PENDING (never executed)
        self.assertEqual(manifest_data["matrix_slots"][1]["status"], "PENDING")
        self.assertEqual(manifest_data["matrix_slots"][2]["status"], "PENDING")

    @patch("lab.impair.self_test_baseline")
    @patch("lab.run_trial.run_trial")
    def test_fail_stop_halts_campaign_when_post_trial_baseline_verification_fails(self, mock_run, mock_base):
        # Trial result claims baseline was verified, but external impair.self_test_baseline fails
        mock_run.side_effect = lambda **kwargs: _create_mock_trial_result(
            kwargs["scenario_id"], kwargs["trial_id"], self.temp_dir, is_simulation=True, baseline_verified=True
        )
        mock_base.return_value = False  # Baseline check fails!

        runner = run_campaign.CampaignRunner(
            scenarios=["S0", "S1"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=True
        )

        with self.assertRaises(run_campaign.CampaignHaltedError):
            runner.run()

        self.assertEqual(mock_run.call_count, 1)
        manifest_data = json.loads((self.temp_dir / run_campaign.MANIFEST_FILENAME).read_text())
        self.assertEqual(manifest_data["status"], "HALTED_ON_FAILURE")


class TestScenarioMismatchNoticesAndEvidencePreservation(unittest.TestCase):
    """
    Verifies that the documented README/scenarios.yaml mismatch for S2 and S4
    is permanently recorded in manifest metadata without altering canonical scenarios.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_mismatch_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_manifest_contains_s2_and_s4_mismatch_notices(self):
        slots = run_campaign.build_matrix_slots(["S0"], ["chrome"], 1)
        manifest = run_campaign.CampaignManifest(
            campaign_id="mismatch-camp",
            output_dir=self.temp_dir,
            scenarios=["S0"],
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots
        )
        manifest.save_atomically()

        data = json.loads((self.temp_dir / run_campaign.MANIFEST_FILENAME).read_text())
        notices = data.get("scenario_mismatch_notices", {})

        self.assertIn("S2", notices)
        self.assertEqual(notices["S2"]["readme_documentation"], "IPv4 connection path unavailable")
        self.assertIn("ipv6_tcp_rst", notices["S2"]["configured_behavior"])

        self.assertIn("S4", notices)
        self.assertEqual(notices["S4"]["readme_documentation"], "Increased IPv4 path latency")
        self.assertIn("600ms RTT", notices["S4"]["configured_behavior"])


class TestCampaignSimulationExecution(unittest.TestCase):
    """Verifies complete end-to-end simulated campaign execution and JSON output."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_sim_camp_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_full_simulated_campaign_runs_sequentially(self, mock_run, mock_base):
        def mock_trial(**kwargs):
            return _create_mock_trial_result(
                scenario_id=kwargs["scenario_id"],
                trial_id=kwargs["trial_id"],
                output_dir=self.temp_dir,
                is_simulation=True
            )
        mock_run.side_effect = mock_trial

        runner = run_campaign.CampaignRunner(
            scenarios=["S0", "S1"],
            browsers=["chrome"],
            repetitions=2,
            output_dir=self.temp_dir,
            is_simulation=True
        )
        res = runner.run()

        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(mock_run.call_count, 4)  # 2 scenarios * 2 reps = 4 trials
        self.assertEqual(res["summary"]["total_slots"], 4)
        self.assertEqual(res["summary"]["completed_slots"], 4)
        self.assertEqual(res["summary"]["simulated_attempts"], 4)
        self.assertEqual(res["summary"]["valid_live_attempts"], 0)

        # Verify that all 4 trials were given unique IDs
        trial_ids = [call_args[1]["trial_id"] for call_args in mock_run.call_args_list]
        self.assertEqual(len(set(trial_ids)), 4)


if __name__ == "__main__":
    unittest.main()
