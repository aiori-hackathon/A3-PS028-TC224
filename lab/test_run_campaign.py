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

import errno
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import tempfile
import time
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

    def test_strict_partner_cli_parsing(self):
        args = run_campaign.parse_args(["--strict-partner"])
        self.assertTrue(args.strict_partner)

    def test_strict_partner_rejects_simulation(self):
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(strict_partner=True, is_simulation=True)
        self.assertIn("forbids simulation mode", str(ctx.exception))

    def test_strict_partner_rejects_non_canonical_scenarios(self):
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(
                strict_partner=True,
                scenarios=["S0", "S1"],
                repetitions=20,
                browsers=["google-chrome", "firefox"]
            )
        self.assertIn("requires exactly 7 canonical scenarios", str(ctx.exception))

    def test_strict_partner_rejects_non_20_repetitions(self):
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(
                strict_partner=True,
                repetitions=5,
                scenarios=["S0", "S1", "S2", "S3", "S4", "S5", "S6"],
                browsers=["google-chrome", "firefox"]
            )
        self.assertIn("requires exactly 20 repetitions", str(ctx.exception))

    def test_strict_partner_rejects_non_canonical_browsers(self):
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(
                strict_partner=True,
                repetitions=20,
                scenarios=["S0", "S1", "S2", "S3", "S4", "S5", "S6"],
                browsers=["google-chrome"]
            )
        self.assertIn("requires both canonical browsers", str(ctx.exception))

    @patch("lab.partner_preflight.get_browser_runtimes")
    def test_strict_partner_aborts_on_browser_preflight_failure(self, mock_runtimes):
        mock_runtimes.return_value = {
            "all_exact_match": False,
            "browsers": {
                "google-chrome": {"status": "VERSION_MISMATCH", "raw_version_output": "Chrome 120", "pinned_expected": "156.0.8078.73"},
                "firefox": {"status": "NOT_FOUND", "raw_version_output": None, "pinned_expected": "159.0"}
            }
        }
        with self.assertRaises(run_campaign.CampaignConfigError) as ctx:
            run_campaign.CampaignRunner(
                strict_partner=True,
                repetitions=20,
                scenarios=["S0", "S1", "S2", "S3", "S4", "S5", "S6"],
                browsers=["google-chrome", "firefox"]
            )
        self.assertIn("Strict partner replication failed browser preflight", str(ctx.exception))

    @patch("lab.partner_preflight.get_browser_runtimes")
    def test_strict_partner_succeeds_and_initializes_280_slots(self, mock_runtimes):
        mock_runtimes.return_value = {
            "all_exact_match": True,
            "browsers": {
                "google-chrome": {"status": "READY", "pinned_expected": "156.0.8078.73"},
                "firefox": {"status": "READY", "pinned_expected": "159.0"}
            }
        }
        with tempfile.TemporaryDirectory() as td:
            runner = run_campaign.CampaignRunner(
                strict_partner=True,
                repetitions=20,
                scenarios=["S0", "S1", "S2", "S3", "S4", "S5", "S6"],
                browsers=["google-chrome", "firefox"],
                output_dir=Path(td) / "test_campaign"
            )
            manifest = runner.initialize_manifest()
            self.assertEqual(len(manifest.matrix_slots), 280)
            self.assertTrue(manifest.strict_partner)
            self.assertEqual(manifest.protocol_version, "1.0.0")



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

    def test_validate_attempt_evidence_resolves_repo_relative_result_and_pcap_paths(self):
        trial_dir = self.temp_dir / "lab" / "campaigns" / "relative-test" / "trials" / "trial-relative"
        pcap_path = trial_dir / "capture.pcap"
        pcap_sha = _create_dummy_pcap(pcap_path, packet_count=2)
        result_path = trial_dir / "result.json"
        result = {
            "schema_version": run_trial.SCHEMA_VERSION,
            "scenario_id": "S0",
            "is_simulation": False,
            "cleanup_status": {
                "scenario_restored": True,
                "baseline_verified": True,
                "errors": [],
            },
            "capture_metadata": {
                "pcap_path": "lab/campaigns/relative-test/trials/trial-relative/capture.pcap",
                "pcap_sha256": pcap_sha,
                "pcap_valid": True,
                "packet_count": 2,
            },
        }
        result_path.write_text(json.dumps(result), encoding="utf-8")

        with patch.object(run_campaign, "REPO_ROOT", self.temp_dir):
            is_valid, message, _ = run_campaign.validate_attempt_evidence(
                "lab/campaigns/relative-test/trials/trial-relative/result.json",
                expected_scenario="S0",
                is_simulation=False,
            )

        self.assertTrue(is_valid, message)
        self.assertIn("Evidence verified", message)

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


class TestPortableEvidencePathResolution(unittest.TestCase):
    """Repository-relative evidence metadata remains resolvable after checkout relocation."""

    def test_repo_relative_paths_resolve_from_repository_root(self):
        expected = (run_campaign.REPO_ROOT / "lab" / "scenarios.yaml").resolve()
        self.assertEqual(
            run_campaign._resolve_repo_relative_path("lab/scenarios.yaml"),
            expected,
        )

    def test_absolute_external_paths_remain_absolute(self):
        external = Path(tempfile.gettempdir()) / "ps028-external-evidence" / "result.json"
        self.assertEqual(run_campaign._resolve_repo_relative_path(external), external)

    def test_legacy_foreign_checkout_path_maps_to_current_checkout_when_present(self):
        with tempfile.TemporaryDirectory(prefix="ps028_relocated_repo_") as temp_root:
            relocated_root = Path(temp_root)
            (relocated_root / "lab").mkdir(parents=True, exist_ok=True)
            expected = relocated_root / "lab" / "scenarios.yaml"
            expected.write_text("scenarios: {}\n", encoding="utf-8")
            legacy = Path("/home/indrani/projects/he-webtester/lab/scenarios.yaml")
            with patch.object(run_campaign, "REPO_ROOT", relocated_root):
                self.assertEqual(run_campaign._resolve_repo_relative_path(legacy), expected.resolve())

    def test_unrelated_external_checkout_name_is_not_remapped(self):
        with tempfile.TemporaryDirectory(prefix="ps028_external_path_") as temp_root:
            temp_root = Path(temp_root)
            relocated_root = temp_root / "current-checkout"
            relocated_file = relocated_root / "lab" / "scenarios.yaml"
            relocated_file.parent.mkdir(parents=True)
            relocated_file.write_text("scenarios: {}\n", encoding="utf-8")

            external = (
                temp_root / "external" / "he-webtester" / "lab" / "scenarios.yaml"
            )
            with patch.object(run_campaign, "REPO_ROOT", relocated_root):
                self.assertEqual(
                    run_campaign._resolve_repo_relative_path(external),
                    external.resolve(),
                )


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

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_resume_from_halted_on_failure_completes_and_updates_manifest(self, mock_run, mock_base):
        # Manifest was previously HALTED_ON_FAILURE at slot 1
        scenarios = ["S0", "S1"]
        slots = run_campaign.build_matrix_slots(scenarios, ["chrome"], 1)

        # Slot 0 succeeded
        res0 = _create_mock_trial_result("S0", "trial-succ-0", self.temp_dir, is_simulation=True)
        att0 = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-succ-0",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={"end_time": "2026-10-30T00:00:01Z"},
            status="COMPLETED",
            validity="SIMULATION",
            evidence_paths=res0["evidence_paths"],
            capture_metadata=res0["capture_metadata"],
            http_outcome=res0["http_outcome"],
            network_observations=res0["network_observations"],
            cleanup_status=res0["cleanup_status"]
        )
        slots[0].add_attempt(att0)

        # Slot 1 failed with CLEANUP_FAILURE on attempt 1
        att1_fail = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-failed-1",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={"end_time": "2026-10-30T00:00:02Z"},
            status="FAILED",
            validity="CLEANUP_FAILURE",
            evidence_paths={"trial_dir": str(self.temp_dir / "trials" / "trial-failed-1")},
            capture_metadata={},
            http_outcome={},
            network_observations={},
            cleanup_status={"scenario_restored": False, "baseline_verified": False, "errors": ["Root error"]},
            error_message="CLEANUP OR BASELINE FAILURE: Root error"
        )
        slots[1].add_attempt(att1_fail)

        manifest = run_campaign.CampaignManifest(
            campaign_id="resume-halted-camp",
            output_dir=self.temp_dir,
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots,
            status="HALTED_ON_FAILURE",
            halt_reason="FAIL-STOP: Lab cleanup failed at slot 1"
        )
        manifest.save_atomically()

        # Mock run_trial to succeed for slot 1 on resume
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

        # Verify campaign completed successfully
        self.assertEqual(res["status"], "COMPLETED")
        self.assertIsNotNone(res["completed_at"])
        self.assertIsNone(res["summary"]["halt_reason"])
        self.assertEqual(res["summary"]["completed_slots"], 2)
        self.assertEqual(res["summary"]["failed_attempts"], 1)
        self.assertEqual(res["summary"]["total_attempts"], 3)

        # Verify historical failure was preserved in slot 1 attempts
        slot1_attempts = res["matrix_slots"][1]["attempts"]
        self.assertEqual(len(slot1_attempts), 2)
        self.assertEqual(slot1_attempts[0]["validity"], "CLEANUP_FAILURE")
        self.assertEqual(slot1_attempts[0]["error_message"], "CLEANUP OR BASELINE FAILURE: Root error")
        self.assertEqual(slot1_attempts[1]["validity"], "SIMULATION")

    def test_finalize_campaign_manifest_success_and_preserves_history(self):
        scenarios = ["S0"]
        slots = run_campaign.build_matrix_slots(scenarios, ["chrome"], 1)
        res0 = _create_mock_trial_result("S0", "trial-finalize-test", self.temp_dir, is_simulation=True)

        # Prepend a historical failed attempt
        att_fail = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-old-fail",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={"end_time": "2026-10-30T00:00:01Z"},
            status="FAILED",
            validity="CLEANUP_FAILURE",
            evidence_paths={},
            capture_metadata={},
            http_outcome={},
            network_observations={},
            cleanup_status={"scenario_restored": False, "baseline_verified": False, "errors": ["err"]},
            error_message="CLEANUP OR BASELINE FAILURE: err"
        )
        slots[0].add_attempt(att_fail)

        att_succ = run_campaign.ExecutionAttempt(
            attempt_number=2,
            trial_id="trial-finalize-test",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={"end_time": "2026-10-30T00:00:10Z"},
            status="COMPLETED",
            validity="SIMULATION",
            evidence_paths=res0["evidence_paths"],
            capture_metadata=res0["capture_metadata"],
            http_outcome=res0["http_outcome"],
            network_observations=res0["network_observations"],
            cleanup_status=res0["cleanup_status"]
        )
        slots[0].add_attempt(att_succ)

        manifest = run_campaign.CampaignManifest(
            campaign_id="finalize-test-camp",
            output_dir=self.temp_dir,
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots,
            status="HALTED_ON_FAILURE",
            halt_reason="FAIL-STOP: previous halt"
        )
        manifest.save_atomically()

        # Finalize using utility
        fin_manifest = run_campaign.finalize_campaign_manifest(self.temp_dir / run_campaign.MANIFEST_FILENAME)
        self.assertEqual(fin_manifest.status, "COMPLETED")
        self.assertEqual(fin_manifest.completed_at, "2026-10-30T00:00:10Z")
        self.assertIsNone(fin_manifest.halt_reason)

        # Verify historical failure is intact
        self.assertEqual(len(fin_manifest.matrix_slots[0].attempts), 2)
        self.assertEqual(fin_manifest.matrix_slots[0].attempts[0].validity, "CLEANUP_FAILURE")

    def test_finalize_campaign_manifest_fails_on_incomplete_slot(self):
        scenarios = ["S0", "S1"]
        slots = run_campaign.build_matrix_slots(scenarios, ["chrome"], 1)
        res0 = _create_mock_trial_result("S0", "trial-fin-0", self.temp_dir, is_simulation=True)
        att0 = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id="trial-fin-0",
            execution_mode="SIMULATION",
            is_simulation=True,
            timestamps={"end_time": "2026-10-30T00:00:01Z"},
            status="COMPLETED",
            validity="SIMULATION",
            evidence_paths=res0["evidence_paths"],
            capture_metadata=res0["capture_metadata"],
            http_outcome=res0["http_outcome"],
            network_observations=res0["network_observations"],
            cleanup_status=res0["cleanup_status"]
        )
        slots[0].add_attempt(att0)
        # Slot 1 is PENDING without attempts

        manifest = run_campaign.CampaignManifest(
            campaign_id="finalize-incomplete-camp",
            output_dir=self.temp_dir,
            scenarios=scenarios,
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=slots,
            status="IN_PROGRESS"
        )
        manifest.save_atomically()

        with self.assertRaises(run_campaign.CampaignResumeError) as ctx:
            run_campaign.finalize_campaign_manifest(self.temp_dir / run_campaign.MANIFEST_FILENAME)
        self.assertIn("not all 2 slots have verified completed evidence", str(ctx.exception))


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


class TestFailedAttemptRecordIntegrity(unittest.TestCase):
    """
    Verifies that every failed campaign attempt produces an atomic, durable
    failed_attempt_record.json under trials/<trial_id>/ and preserves genuine
    prior evidence (result.json, capture.pcap, logs) without silent relabeling.
    """

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_failure_rec_test_"))
        self.trials_dir = self.temp_dir / "trials"
        self.trials_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_failed_attempt_record_atomic_and_durable(self):
        trial_id = "trial-synth-fail-001"
        trial_dir = self.trials_dir / trial_id
        attempt = run_campaign.ExecutionAttempt(
            attempt_number=1,
            trial_id=trial_id,
            execution_mode="LIVE",
            is_simulation=False,
            timestamps={"start_time": "2026-11-18T10:00:00Z", "end_time": "2026-11-18T10:00:01Z", "duration_ms": 1000.0},
            status="FAILED",
            validity="CLEANUP_FAILURE",
            evidence_paths={"trial_dir": str(trial_dir)},
            capture_metadata={},
            http_outcome={},
            network_observations={},
            cleanup_status={"scenario_restored": False, "baseline_verified": False, "errors": ["Mock baseline error"]},
            error_message="Mock baseline error"
        )
        rec_path = run_campaign.write_failed_attempt_record(trial_dir, attempt)
        self.assertTrue(rec_path.is_file())
        self.assertEqual(rec_path.name, "failed_attempt_record.json")

        fdata = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fdata["trial_id"], trial_id)
        self.assertEqual(fdata["status"], "FAILED")
        self.assertEqual(fdata["validity"], "CLEANUP_FAILURE")
        self.assertEqual(fdata["execution_mode"], "LIVE")
        self.assertEqual(fdata["error_message"], "Mock baseline error")
        self.assertFalse(fdata["is_simulation"])

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_cleanup_failure_writes_durable_failure_record_and_preserves_evidence(self, mock_run, mock_base):
        def mock_trial(**kwargs):
            tdir = kwargs["output_dir"]
            tid = kwargs["trial_id"]
            pcap_file = tdir / "capture.pcap"
            sha = _create_dummy_pcap(pcap_file, packet_count=3)
            res_file = tdir / "result.json"
            res_data = {
                "schema_version": "1.1.0",
                "trial_id": tid,
                "scenario_id": "S0",
                "browser": "google-chrome",
                "is_simulation": False,
                "execution_mode": "LIVE",
                "cleanup_status": {
                    "scenario_restored": False,
                    "baseline_verified": False,
                    "errors": ["Cleanup restoration failed"]
                },
                "evidence_paths": {
                    "trial_dir": str(tdir),
                    "result_json": str(res_file),
                    "capture_pcap": str(pcap_file)
                },
                "capture_metadata": {
                    "pcap_valid": True,
                    "pcap_sha256": sha,
                    "packet_count": 3
                }
            }
            res_file.write_text(json.dumps(res_data), encoding="utf-8")
            return res_data

        mock_run.side_effect = mock_trial

        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["google-chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=False
        )
        slot = run_campaign.MatrixSlot("slot-0001", 1, "S0", "google-chrome", 1)

        attempt = runner.execute_slot_attempt(slot, attempt_number=1)
        self.assertEqual(attempt.status, "FAILED")
        self.assertEqual(attempt.validity, "CLEANUP_FAILURE")

        # Verify durable failed_attempt_record.json on disk
        rec_path = Path(attempt.evidence_paths["trial_dir"]) / "failed_attempt_record.json"
        self.assertTrue(rec_path.is_file())
        fdata = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fdata["status"], "FAILED")
        self.assertEqual(fdata["validity"], "CLEANUP_FAILURE")
        self.assertEqual(fdata["trial_id"], attempt.trial_id)

        # Verify genuine prior evidence is preserved and not overwritten
        pcap_path = Path(attempt.evidence_paths["capture_pcap"])
        self.assertTrue(pcap_path.is_file())
        res_json_path = Path(attempt.evidence_paths["result_json"])
        self.assertTrue(res_json_path.is_file())

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_measurement_failure_writes_durable_failure_record(self, mock_run, mock_base):
        def mock_trial(**kwargs):
            return _create_mock_trial_result(
                scenario_id=kwargs["scenario_id"],
                trial_id=kwargs["trial_id"],
                output_dir=self.temp_dir,
                is_simulation=False,
                packet_count=0,
                classification="INCONCLUSIVE"
            )
        mock_run.side_effect = mock_trial

        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["google-chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=False
        )
        slot = run_campaign.MatrixSlot("slot-0001", 1, "S0", "google-chrome", 1)

        attempt = runner.execute_slot_attempt(slot, attempt_number=1)
        self.assertEqual(attempt.status, "FAILED")
        self.assertEqual(attempt.validity, "MEASUREMENT_FAILURE")

        rec_path = Path(attempt.evidence_paths["trial_dir"]) / "failed_attempt_record.json"
        self.assertTrue(rec_path.is_file())
        fdata = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fdata["status"], "FAILED")
        self.assertEqual(fdata["validity"], "MEASUREMENT_FAILURE")


class TestCampaignSignalInterruption(unittest.TestCase):
    """
    Regression tests for attempt-safe SIGINT and SIGTERM handling:
    1. Controlled interruption during an active trial preserves partial evidence.
    2. Durable failed_attempt_record.json written atomically with POSIX fsync.
    3. Manifest records INTERRUPTED state; attempts marked INTERRUPTED.
    4. Interruption with baseline/cleanup failure transitions to CLEANUP_FAILURE.
    5. Interruption between slots does not invent fictitious attempts.
    6. Subprocess signal delivery exits with conventional 130 (SIGINT) and 143 (SIGTERM).
    7. Subprocess repeated signal triggers immediate termination.
    """

    def setUp(self):
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_dir = Path(self.temp_dir_obj.name)

    def tearDown(self):
        self.temp_dir_obj.cleanup()

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_in_process_sigint_interruption_during_trial(self, mock_run, mock_base):
        def mock_trial(**kwargs):
            tdir = kwargs["output_dir"]
            # Write partial evidence before raising KeyboardInterrupt
            pcap = tdir / "capture.pcap"
            _create_dummy_pcap(pcap, packet_count=2)
            (tdir / "tcpdump.log").write_text("Partial capture started\n", encoding="utf-8")
            raise KeyboardInterrupt("Simulated Ctrl+C during trial execution")

        mock_run.side_effect = mock_trial

        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["google-chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=False,
            exit_on_interruption=False
        )

        manifest_dict = runner.run()
        self.assertEqual(manifest_dict["status"], "INTERRUPTED")
        self.assertIn("SIGINT", manifest_dict["halt_reason"])

        slot = manifest_dict["matrix_slots"][0]
        self.assertFalse(slot["status"] == "COMPLETED")
        self.assertEqual(len(slot["attempts"]), 1)
        att = slot["attempts"][0]
        self.assertEqual(att["status"], "INTERRUPTED")
        self.assertEqual(att["validity"], "INTERRUPTED")
        self.assertIsNotNone(att.get("interruption"))
        self.assertEqual(att["interruption"]["signal_number"], 2)
        self.assertEqual(att["interruption"]["signal_name"], "SIGINT")

        # Verify durable failed_attempt_record.json on disk
        rec_path = Path(att["evidence_paths"]["trial_dir"]) / "failed_attempt_record.json"
        self.assertTrue(rec_path.is_file())
        fdata = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fdata["status"], "INTERRUPTED")
        self.assertEqual(fdata["validity"], "INTERRUPTED")
        self.assertEqual(fdata["trial_id"], att["trial_id"])
        self.assertEqual(fdata["interruption"]["signal_name"], "SIGINT")

        # Verify partial evidence preserved
        self.assertTrue((Path(att["evidence_paths"]["trial_dir"]) / "capture.pcap").is_file())
        self.assertEqual(att["capture_metadata"]["packet_count"], 2)

    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_in_process_sigterm_interruption_during_trial(self, mock_base):
        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["google-chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=False,
            exit_on_interruption=False
        )
        slot = run_campaign.MatrixSlot("slot-0001", 1, "S0", "google-chrome", 1)

        # Simulate runner receiving SIGTERM
        runner._interrupted = True
        runner._interrupted_signum = signal.SIGTERM
        runner._interrupted_signal_name = "SIGTERM"

        with patch("lab.run_trial.run_trial", side_effect=InterruptedError("Simulated SIGTERM")):
            attempt = runner.execute_slot_attempt(slot, attempt_number=1)

        self.assertEqual(attempt.status, "INTERRUPTED")
        self.assertEqual(attempt.validity, "INTERRUPTED")
        self.assertIsNotNone(attempt.interruption)
        self.assertEqual(attempt.interruption["signal_number"], int(signal.SIGTERM))
        self.assertEqual(attempt.interruption["signal_name"], "SIGTERM")

        rec_path = Path(attempt.evidence_paths["trial_dir"]) / "failed_attempt_record.json"
        self.assertTrue(rec_path.is_file())
        fdata = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fdata["status"], "INTERRUPTED")
        self.assertEqual(fdata["validity"], "INTERRUPTED")

    @patch("lab.impair.clear_impairments")
    @patch("lab.impair.self_test_baseline", return_value=False)
    @patch("lab.run_trial.run_trial", side_effect=KeyboardInterrupt("Interrupted"))
    def test_interruption_with_cleanup_failure_records_cleanup_failure(self, mock_run, mock_base, mock_clear):
        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["google-chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=False,
            exit_on_interruption=False
        )
        slot = run_campaign.MatrixSlot("slot-0001", 1, "S0", "google-chrome", 1)

        attempt = runner.execute_slot_attempt(slot, attempt_number=1)
        self.assertEqual(attempt.status, "FAILED")
        self.assertEqual(attempt.validity, "CLEANUP_FAILURE")
        self.assertIsNotNone(attempt.interruption)

        rec_path = Path(attempt.evidence_paths["trial_dir"]) / "failed_attempt_record.json"
        self.assertTrue(rec_path.is_file())
        fdata = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fdata["validity"], "CLEANUP_FAILURE")

    @patch("lab.impair.self_test_baseline", return_value=True)
    @patch("lab.run_trial.run_trial")
    def test_signal_between_attempts_does_not_create_fictitious_attempt(self, mock_run, mock_base):
        def mock_trial(**kwargs):
            return _create_mock_trial_result(
                scenario_id=kwargs["scenario_id"],
                trial_id=kwargs["trial_id"],
                output_dir=self.temp_dir,
                is_simulation=False,
                packet_count=2,
                classification="DIRECT_IPV6"
            )
        mock_run.side_effect = mock_trial

        runner = run_campaign.CampaignRunner(
            scenarios=["S0", "S1"],
            browsers=["google-chrome"],
            repetitions=1,
            output_dir=self.temp_dir,
            is_simulation=False,
            exit_on_interruption=False
        )

        orig_execute = runner.execute_slot_attempt
        def intercepted_execute(slot, attempt_number):
            att = orig_execute(slot, attempt_number)
            # Inject interruption immediately after first slot attempt completes
            runner._interrupted = True
            runner._interrupted_signum = signal.SIGINT
            runner._interrupted_signal_name = "SIGINT"
            return att

        runner.execute_slot_attempt = intercepted_execute

        manifest_dict = runner.run()
        self.assertEqual(manifest_dict["status"], "INTERRUPTED")
        slots = manifest_dict["matrix_slots"]
        self.assertEqual(len(slots), 2)
        # Slot 0 completed successfully
        self.assertEqual(len(slots[0]["attempts"]), 1)
        self.assertEqual(slots[0]["status"], "COMPLETED")
        # Slot 1 was never attempted: 0 attempts, no fictitious trials
        self.assertEqual(len(slots[1]["attempts"]), 0)
        self.assertEqual(slots[1]["status"], "PENDING")

    def test_subprocess_sigint_controlled_exit_130_and_manifest_durability(self):
        camp_dir = self.temp_dir / "camp_sigint"
        camp_dir.mkdir(parents=True, exist_ok=True)
        flag_file = self.temp_dir / "started_sigint.flag"

        code = f"""
import os, sys, time, signal
from pathlib import Path
import lab.run_campaign as run_campaign
import lab.run_trial as run_trial

browser_child_script = "import sys, time, pathlib; pathlib.Path({repr(str(flag_file))}).write_text('ready'); time.sleep(15)"

runner = run_campaign.CampaignRunner(
    scenarios=["S0"],
    browsers=["google-chrome"],
    repetitions=1,
    output_dir=Path({repr(str(camp_dir))}),
    is_simulation=True,
    exit_on_interruption=True,
    browser_cmd_override=[sys.executable, "-c", browser_child_script]
)
runner.run()
"""
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        t0 = time.time()
        while not flag_file.exists() and time.time() - t0 < 5.0:
            time.sleep(0.05)
        self.assertTrue(flag_file.exists(), "Subprocess did not start trial within timeout")

        proc.send_signal(signal.SIGINT)
        stdout, stderr = proc.communicate(timeout=5.0)

        self.assertEqual(proc.returncode, 130, f"Expected returncode 130, got {proc.returncode}. Stderr: {stderr}")

        mpath = camp_dir / "campaign_manifest.json"
        self.assertTrue(mpath.is_file())
        mdata = json.loads(mpath.read_text(encoding="utf-8"))
        self.assertEqual(mdata["status"], "INTERRUPTED")
        self.assertIn("SIGINT", mdata.get("halt_reason", ""))

        # Verify exactly one attempt recorded in manifest and matches failed_attempt_record.json
        slot_0 = mdata["matrix_slots"][0]
        self.assertEqual(len(slot_0["attempts"]), 1)
        attempt = slot_0["attempts"][0]
        self.assertEqual(attempt["status"], "INTERRUPTED")
        self.assertEqual(attempt["validity"], "INTERRUPTED")
        self.assertIsNotNone(attempt["interruption"])
        self.assertEqual(attempt["interruption"]["signal_number"], 2)

        fail_rec_path = camp_dir / "trials" / attempt["trial_id"] / "failed_attempt_record.json"
        self.assertTrue(fail_rec_path.is_file(), f"Expected failure record at {fail_rec_path}")
        fail_rec = json.loads(fail_rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fail_rec["trial_id"], attempt["trial_id"])
        self.assertEqual(fail_rec["status"], attempt["status"])
        self.assertEqual(fail_rec["validity"], attempt["validity"])
        self.assertEqual(fail_rec["interruption"]["signal_name"], "SIGINT")

    def test_subprocess_sigterm_controlled_exit_143(self):
        camp_dir = self.temp_dir / "camp_sigterm"
        camp_dir.mkdir(parents=True, exist_ok=True)
        flag_file = self.temp_dir / "started_sigterm.flag"

        code = f"""
import os, sys, time, signal
from pathlib import Path
import lab.run_campaign as run_campaign
import lab.run_trial as run_trial

browser_child_script = "import sys, time, pathlib; pathlib.Path({repr(str(flag_file))}).write_text('ready'); time.sleep(15)"

runner = run_campaign.CampaignRunner(
    scenarios=["S0"],
    browsers=["google-chrome"],
    repetitions=1,
    output_dir=Path({repr(str(camp_dir))}),
    is_simulation=True,
    exit_on_interruption=True,
    browser_cmd_override=[sys.executable, "-c", browser_child_script]
)
runner.run()
"""
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        t0 = time.time()
        while not flag_file.exists() and time.time() - t0 < 5.0:
            time.sleep(0.05)
        self.assertTrue(flag_file.exists(), "Subprocess did not start trial within timeout")

        proc.send_signal(signal.SIGTERM)
        stdout, stderr = proc.communicate(timeout=5.0)

        self.assertEqual(proc.returncode, 143, f"Expected returncode 143, got {proc.returncode}. Stderr: {stderr}")

        mpath = camp_dir / "campaign_manifest.json"
        self.assertTrue(mpath.is_file())
        mdata = json.loads(mpath.read_text(encoding="utf-8"))
        self.assertEqual(mdata["status"], "INTERRUPTED")
        self.assertIn("SIGTERM", mdata.get("halt_reason", ""))

        slot_0 = mdata["matrix_slots"][0]
        self.assertEqual(len(slot_0["attempts"]), 1)
        attempt = slot_0["attempts"][0]
        self.assertEqual(attempt["interruption"]["signal_number"], 15)

        fail_rec_path = camp_dir / "trials" / attempt["trial_id"] / "failed_attempt_record.json"
        self.assertTrue(fail_rec_path.is_file())
        fail_rec = json.loads(fail_rec_path.read_text(encoding="utf-8"))
        self.assertEqual(fail_rec["trial_id"], attempt["trial_id"])
        self.assertEqual(fail_rec["interruption"]["signal_name"], "SIGTERM")

        mpath = camp_dir / "campaign_manifest.json"
        self.assertTrue(mpath.is_file())
        mdata = json.loads(mpath.read_text(encoding="utf-8"))
        self.assertEqual(mdata["status"], "INTERRUPTED")
        self.assertIn("SIGTERM", mdata.get("halt_reason", ""))

    def test_subprocess_repeated_signal_forces_immediate_termination(self):
        camp_dir = self.temp_dir / "camp_repeat_sig"
        camp_dir.mkdir(parents=True, exist_ok=True)
        flag_file = self.temp_dir / "started_repeat.flag"

        code = f"""
import os, sys, time, signal
from pathlib import Path
import lab.run_campaign as run_campaign
import lab.run_trial as run_trial

flag_path = Path({repr(str(flag_file))})
def slow_trial(**kwargs):
    flag_path.write_text("ready", encoding="utf-8")
    while True:
        try:
            time.sleep(10.0)
        except (KeyboardInterrupt, InterruptedError):
            time.sleep(5.0)
            break
    return {{"timestamps": {{}}, "cleanup_status": {{"scenario_restored": True, "baseline_verified": True, "errors": []}}}}

run_trial.run_trial = slow_trial

runner = run_campaign.CampaignRunner(
    scenarios=["S0"],
    browsers=["google-chrome"],
    repetitions=1,
    output_dir=Path({repr(str(camp_dir))}),
    is_simulation=True,
    exit_on_interruption=True
)
runner.run()
"""
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        t0 = time.time()
        while not flag_file.exists() and time.time() - t0 < 5.0:
            time.sleep(0.05)
        self.assertTrue(flag_file.exists())

        proc.send_signal(signal.SIGINT)
        time.sleep(0.05)
        proc.send_signal(signal.SIGINT)

        stdout, stderr = proc.communicate(timeout=5.0)
        self.assertEqual(proc.returncode, 130)


class TestCampaignFsyncDirectoryFailClosed(unittest.TestCase):
    """
    Validates fail-closed semantics for directory fsync in run_campaign:
    - Genuine OSErrors (EIO, ENOSPC, EACCES) propagate.
    - File descriptors are unconditionally closed even when fsync fails.
    - Interrupted system calls (EINTR) are retried until completion.
    - Non-POSIX environments raise explicit OSError(errno.ENOSYS).
    - write_failed_attempt_record and save_atomically fail closed if fsync fails.
    """
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="ps028_camp_fsync_")
        self.td_path = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_fsync_directory_raises_on_open_oserror(self):
        """Genuine OSError on opening directory propagates with error code."""
        with patch("os.open", side_effect=OSError(errno.EACCES, "Permission denied")):
            with self.assertRaises(OSError) as ctx:
                run_campaign.fsync_directory(self.td_path)
            self.assertEqual(ctx.exception.errno, errno.EACCES)

    def test_fsync_directory_raises_on_fsync_oserror(self):
        """Genuine OSError during directory fsync propagates with error code."""
        with patch("os.fsync", side_effect=OSError(errno.EIO, "I/O error")):
            with self.assertRaises(OSError) as ctx:
                run_campaign.fsync_directory(self.td_path)
            self.assertEqual(ctx.exception.errno, errno.EIO)

    def test_fsync_directory_closes_fd_on_fsync_error(self):
        """File descriptor is guaranteed to be closed even when os.fsync raises."""
        fake_fd = 9999
        with patch("os.open", return_value=fake_fd), \
             patch("os.fsync", side_effect=OSError(errno.EIO, "Disk write failure")), \
             patch("os.close") as mock_close:
            with self.assertRaises(OSError):
                run_campaign.fsync_directory(self.td_path)
            mock_close.assert_called_with(fake_fd)

    def test_fsync_directory_retries_on_eintr(self):
        """Retries open and fsync when interrupted by EINTR signal."""
        fake_fd = 8888
        open_attempts = [InterruptedError(errno.EINTR, "Interrupted"), fake_fd]
        fsync_attempts = [InterruptedError(errno.EINTR, "Interrupted"), None]

        with patch("os.open", side_effect=open_attempts), \
             patch("os.fsync", side_effect=fsync_attempts), \
             patch("os.close") as mock_close:
            run_campaign.fsync_directory(self.td_path)
            mock_close.assert_called_once_with(fake_fd)

    def test_fsync_directory_fails_on_non_posix(self):
        """Explicitly raises OSError(errno.ENOSYS) on non-POSIX platforms."""
        with patch("os.name", "nt"):
            with self.assertRaises(OSError) as ctx:
                run_campaign.fsync_directory(self.td_path)
            self.assertEqual(ctx.exception.errno, errno.ENOSYS)

    def test_write_failed_attempt_record_fails_closed_on_directory_fsync_error(self):
        """write_failed_attempt_record propagates directory fsync OSError."""
        trial_dir = self.td_path / "trial_err"
        dummy_attempt = {
            "attempt_number": 1,
            "trial_id": "trial-test-01",
            "execution_mode": "SIMULATION",
            "is_simulation": True,
            "timestamps": {},
            "status": "FAILED",
            "validity": "MEASUREMENT_FAILURE",
            "evidence_paths": {},
            "capture_metadata": {},
            "http_outcome": {},
            "network_observations": {},
            "cleanup_status": {}
        }
        with patch("lab.run_campaign.fsync_directory", side_effect=OSError(errno.EIO, "I/O failure")):
            with self.assertRaises(OSError):
                run_campaign.write_failed_attempt_record(trial_dir, dummy_attempt)

    def test_manifest_save_atomically_fails_closed_on_directory_fsync_error(self):
        """manifest.save_atomically propagates directory fsync OSError."""
        manifest = run_campaign.CampaignManifest(
            campaign_id="camp-fsync-test",
            output_dir=self.td_path,
            scenarios=["S0"],
            browsers=["chrome"],
            repetitions=1,
            is_simulation=True,
            matrix_slots=[]
        )
        with patch("lab.run_campaign.fsync_directory", side_effect=OSError(errno.ENOSPC, "No space")):
            with self.assertRaises(OSError):
                manifest.save_atomically()


class TestInterruptionLifecycleAndSignalSafety(unittest.TestCase):
    """
    Synthetic software tests exercising actual run_trial and run_campaign
    interruption lifecycle, process termination, cleanup preservation, and exit codes:
    1. Critical section defers KeyboardInterrupt until section finishes.
    2. Registered subprocesses are terminated and reaped upon signal.
    3. Signal during active trial finalizes cleanly (exit 130/143, durable failure record).
    4. Signal during cleanup does not abort baseline restoration.
    5. Signal after valid completed trial preserves COMPLETED/VALID_LIVE status.
    6. Cleanup failure following interruption triggers fail-stop (HALTED_ON_FAILURE).
    7. Repeated signal triggers immediate forced exit (sys.exit).
    """
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="ps028_interr_test_")
        self.td_path = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_coordinator_critical_section_defers_interruption(self):
        """Critical sections allow execution to complete without raising KeyboardInterrupt."""
        coord = run_campaign.InterruptionCoordinator()
        critical_executed = False

        with coord.critical_section("test_section"):
            coord.handle_signal(signal.SIGINT, None)
            critical_executed = True

        self.assertTrue(critical_executed)
        self.assertTrue(coord.interrupted)
        self.assertEqual(coord.signum, signal.SIGINT)
        self.assertEqual(coord.signal_name, "SIGINT")

    def test_coordinator_registers_and_terminates_subprocess(self):
        """Registered child process is terminated and reaped when signal arrives."""
        coord = run_campaign.InterruptionCoordinator()
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        coord.register_process(proc)

        self.assertIsNone(proc.poll(), "Process should be alive initially")

        with coord.critical_section("signal_delivery"):
            coord.handle_signal(signal.SIGTERM, None)

        self.assertIsNotNone(proc.poll(), "Process must be terminated and reaped by coordinator")
        self.assertTrue(coord.interrupted)
        self.assertEqual(coord.signum, signal.SIGTERM)

    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_campaign_runner_signal_during_active_trial_finalizes_cleanly(self, mock_base):
        """SIGINT during active trial reaps process, preserves partial evidence, and marks manifest INTERRUPTED."""
        camp_dir = self.td_path / "camp_interrupted"
        camp_dir.mkdir(parents=True, exist_ok=True)

        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=camp_dir,
            is_simulation=True,
            exit_on_interruption=False
        )

        def mock_trial_with_signal(**kwargs):
            coord = kwargs.get("coordinator")
            dummy_proc = MagicMock()
            dummy_proc.poll.return_value = None
            if coord:
                coord.register_process(dummy_proc)
                coord.handle_signal(signal.SIGINT, None)
            raise KeyboardInterrupt("Interrupted during trial")

        with patch("lab.run_trial.run_trial", side_effect=mock_trial_with_signal):
            res = runner.run()

        self.assertEqual(res["status"], "INTERRUPTED")
        self.assertIn("SIGINT", res.get("summary", {}).get("halt_reason", ""))

        # Verify exactly one attempt was recorded for slot 1
        slot0 = res["matrix_slots"][0]
        self.assertEqual(len(slot0["attempts"]), 1)
        att0 = slot0["attempts"][0]
        self.assertEqual(att0["status"], "INTERRUPTED")
        self.assertEqual(att0["validity"], "INTERRUPTED")

        # Verify durable failed_attempt_record.json exists on disk
        trial_id = att0["trial_id"]
        failure_record_path = camp_dir / "trials" / trial_id / run_campaign.FAILURE_RECORD_FILENAME
        self.assertTrue(failure_record_path.is_file())
        rec_data = json.loads(failure_record_path.read_text(encoding="utf-8"))
        self.assertEqual(rec_data["trial_id"], trial_id)
        self.assertEqual(rec_data["status"], "INTERRUPTED")
        self.assertEqual(rec_data["validity"], "INTERRUPTED")

    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_signal_during_cleanup_does_not_abort_cleanup(self, mock_base):
        """Signal received during cleanup critical section allows cleanup to complete."""
        camp_dir = self.td_path / "camp_cleanup_sig"
        camp_dir.mkdir(parents=True, exist_ok=True)

        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=camp_dir,
            is_simulation=True,
            exit_on_interruption=False
        )

        # Signal delivered during attempt finalization
        def mock_trial_ok(**kwargs):
            # Fire signal inside finalization
            runner.coordinator.handle_signal(signal.SIGTERM, None)
            return None  # trial errored or was interrupted

        with patch("lab.run_trial.run_trial", side_effect=mock_trial_ok):
            res = runner.run()

        self.assertEqual(res["status"], "INTERRUPTED")
        self.assertIn("SIGTERM", res.get("summary", {}).get("halt_reason", ""))
        self.assertEqual(len(res["matrix_slots"][0]["attempts"]), 1)

    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_signal_after_completed_valid_trial_preserves_valid_evidence(self, mock_base):
        """Signal arriving after a trial succeeded preserves genuine COMPLETED / VALID_LIVE evidence."""
        camp_dir = self.td_path / "camp_signal_after_success"
        camp_dir.mkdir(parents=True, exist_ok=True)

        runner = run_campaign.CampaignRunner(
            scenarios=["S0", "S1"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=camp_dir,
            is_simulation=True,
            exit_on_interruption=False
        )

        call_count = 0
        def mock_trial_seq(**kwargs):
            nonlocal call_count
            call_count += 1
            tid = kwargs["trial_id"]
            sc = kwargs["scenario_id"]
            # Create mock trial result that succeeded
            tdir = camp_dir / "trials" / tid
            tdir.mkdir(parents=True, exist_ok=True)
            res = _create_mock_trial_result(sc, tid, camp_dir, is_simulation=True, baseline_verified=True)
            # Deliver SIGINT right after first trial succeeds
            if call_count == 1:
                runner.coordinator.record_interruption(signal.SIGINT, "SIGINT")
            return res

        with patch("lab.run_trial.run_trial", side_effect=mock_trial_seq):
            res = runner.run()

        # Slot 1 should be COMPLETED (genuine success preserved without false reclassification!)
        slot0 = res["matrix_slots"][0]
        self.assertEqual(slot0["status"], "COMPLETED")
        att0 = slot0["attempts"][0]
        self.assertEqual(att0["status"], "COMPLETED")
        self.assertEqual(att0["validity"], "SIMULATION")

        # Slot 2 should remain PENDING (not executed due to interruption)
        slot1 = res["matrix_slots"][1]
        self.assertEqual(slot1["status"], "PENDING")
        self.assertEqual(len(slot1["attempts"]), 0)

        # Campaign manifest is INTERRUPTED
        self.assertEqual(res["status"], "INTERRUPTED")
        self.assertIn("SIGINT", res.get("summary", {}).get("halt_reason", ""))

    @patch("lab.impair.self_test_baseline", return_value=False)
    @patch("lab.impair.clear_impairments")
    def test_cleanup_failure_following_interruption_triggers_fail_stop(self, mock_clear, mock_base):
        """Cleanup failure following interruption halts campaign with FAIL-STOP and status HALTED_ON_FAILURE."""
        camp_dir = self.td_path / "camp_cleanup_fail"
        camp_dir.mkdir(parents=True, exist_ok=True)

        runner = run_campaign.CampaignRunner(
            scenarios=["S0"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=camp_dir,
            is_simulation=True,
            exit_on_interruption=False
        )

        def mock_trial_fail(**kwargs):
            runner.coordinator.record_interruption(signal.SIGINT, "SIGINT")
            raise KeyboardInterrupt("Interrupted")

        with patch("lab.run_trial.run_trial", side_effect=mock_trial_fail):
            with self.assertRaises(run_campaign.CampaignHaltedError):
                runner.run()

        mpath = camp_dir / run_campaign.MANIFEST_FILENAME
        self.assertTrue(mpath.is_file())
        mdata = json.loads(mpath.read_text(encoding="utf-8"))
        self.assertEqual(mdata["status"], "HALTED_ON_FAILURE")
        self.assertIn("FAIL-STOP", mdata.get("summary", {}).get("halt_reason", ""))

        slot0 = mdata["matrix_slots"][0]
        att0 = slot0["attempts"][0]
        self.assertEqual(att0["status"], "FAILED")
        self.assertEqual(att0["validity"], "CLEANUP_FAILURE")

    def test_repeated_signal_causes_immediate_forced_exit(self):
        """Second signal delivered to coordinator immediately forces exit with 128 + signum."""
        coord = run_campaign.InterruptionCoordinator()
        # First signal
        with coord.critical_section("init"):
            coord.handle_signal(signal.SIGINT, None)
        self.assertEqual(coord.signal_count, 1)

        # Second signal must invoke sys.exit(130)
        with self.assertRaises(SystemExit) as ctx:
            coord.handle_signal(signal.SIGINT, None)
        self.assertEqual(ctx.exception.code, 130)

    @patch("lab.impair.self_test_baseline", return_value=True)
    def test_incomplete_descendant_discovery_end_to_end_cleanup_failure(self, mock_base):
        """End-to-end CampaignRunner test forcing incomplete descendant discovery verifies fail-stop and durable error persistence."""
        camp_dir = self.td_path / "camp_incomplete_desc"
        camp_dir.mkdir(parents=True, exist_ok=True)

        runner = run_campaign.CampaignRunner(
            scenarios=["S0", "S1"],
            browsers=["chrome"],
            repetitions=1,
            output_dir=camp_dir,
            is_simulation=True,
            exit_on_interruption=False
        )

        def mock_trial_with_incomplete_discovery(**kwargs):
            runner.coordinator.record_termination_error(
                "Descendant discovery incomplete (Permission denied reading /proc/999/stat); cannot verify detached descendants for PID 999"
            )
            return {
                "status": "COMPLETED",
                "validity": "VALID_LIVE",
                "cleanup_status": {
                    "scenario_restored": True,
                    "baseline_verified": True,
                    "profile_cleaned": True,
                    "lock_released": True,
                    "errors": []
                },
                "capture_metadata": {"pcap_valid": True, "packet_count": 10},
                "network_observations": {"classification": "HAPPY_EYEBALLS_V6_FALLBACK"},
                "evidence_paths": {},
                "timestamps": {
                    "start_time": "2026-11-18T10:00:00Z",
                    "end_time": "2026-11-18T10:00:01Z",
                    "duration_ms": 1000.0
                }
            }

        with patch("lab.run_trial.run_trial", side_effect=mock_trial_with_incomplete_discovery):
            with self.assertRaises(run_campaign.CampaignHaltedError):
                runner.run()

        mpath = camp_dir / run_campaign.MANIFEST_FILENAME
        self.assertTrue(mpath.is_file())
        mdata = json.loads(mpath.read_text(encoding="utf-8"))

        self.assertEqual(mdata["status"], "HALTED_ON_FAILURE")
        self.assertIn("FAIL-STOP", mdata.get("summary", {}).get("halt_reason", ""))

        self.assertEqual(len(mdata["matrix_slots"]), 2)
        slot0 = mdata["matrix_slots"][0]
        slot1 = mdata["matrix_slots"][1]

        self.assertEqual(len(slot0["attempts"]), 1)
        att0 = slot0["attempts"][0]

        self.assertEqual(att0["status"], "FAILED")
        self.assertEqual(att0["validity"], "CLEANUP_FAILURE")

        c_errors = att0.get("cleanup_status", {}).get("errors", [])
        self.assertTrue(len(c_errors) > 0)
        self.assertIn("Descendant discovery incomplete", c_errors[0])

        rec_path = camp_dir / "trials" / att0["trial_id"] / "failed_attempt_record.json"
        self.assertTrue(rec_path.is_file())
        rec_data = json.loads(rec_path.read_text(encoding="utf-8"))
        self.assertEqual(rec_data["trial_id"], att0["trial_id"])
        self.assertEqual(rec_data["validity"], "CLEANUP_FAILURE")
        rec_errors = rec_data.get("cleanup_status", {}).get("errors", [])
        self.assertTrue(len(rec_errors) > 0)
        self.assertIn("Descendant discovery incomplete", rec_errors[0])

        self.assertEqual(len(slot1["attempts"]), 0)


if __name__ == "__main__":
    unittest.main()
