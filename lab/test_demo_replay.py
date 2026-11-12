#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Demo Replay Test Suite
Verifies fail-closed validation, checksum integrity, and authentic PCAP acceptance
for lab/demo_replay.py across all 14 representative trials.
"""

from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from lab.demo_replay import (
    REPRESENTATIVE_TRIALS,
    CHECKSUM_FILE,
    CAMPAIGN_DIR,
    REDERIVED_DIR,
    load_canonical_pcap_checksums,
    compute_sha256,
    replay_single_trial,
    run_demonstration,
)


class TestDemoReplayDeterministicUnit(unittest.TestCase):
    """Deterministic failure-path unit tests using controlled mocks and synthetic fixtures."""

    def setUp(self):
        self.valid_spec = dict(REPRESENTATIVE_TRIALS[0])
        self.trial_id = self.valid_spec["trial_id"]
        self.valid_checksum_map = {
            self.trial_id: self.valid_spec["expected_pcap_sha256"]
        }

    def test_missing_pcap_fails_closed(self):
        """Rule R5: Missing PCAP file must fail closed and record error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_campaign = Path(tmpdir)
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=empty_campaign,
                rederived_dir=REDERIVED_DIR,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("missing or unreadable" in err for err in rec["errors"]))

    @patch("lab.demo_replay.compute_sha256")
    def test_pcap_digest_mismatch_fails_closed(self, mock_sha):
        """Rule R2: PCAP SHA-256 mismatch with expected registry must fail closed."""
        mock_sha.return_value = "0000000000000000000000000000000000000000000000000000000000000000"
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("digest mismatch" in err for err in rec["errors"]))

    @patch("lab.demo_replay.compute_sha256")
    def test_missing_from_checksum_manifest_fails_closed(self, mock_sha):
        """Missing trial from canonical checksum file must fail closed."""
        mock_sha.return_value = self.valid_spec["expected_pcap_sha256"]
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map={},  # empty checksum map
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("absent from canonical checksum manifest" in err for err in rec["errors"]))

    def test_missing_rederived_record_fails_closed(self):
        """Correction 1: Missing rederived JSON record must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_rederived = Path(tmpdir)
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=empty_rederived,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("Rederived result JSON record missing" in err for err in rec["errors"]))

    def test_malformed_rederived_record_fails_closed(self):
        """Correction 1: Malformed rederived JSON must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            bad_file = tmp_path / f"{self.trial_id}.json"
            bad_file.write_text("{this is not valid json", encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("Rederived result JSON record malformed" in err for err in rec["errors"]))

    def test_mismatched_rederived_trial_id_fails_closed(self):
        """Correction 1: Mismatched trial_id in rederived record must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_file = tmp_path / f"{self.trial_id}.json"
            # Read real file and corrupt trial_id
            real_data = json.loads((REDERIVED_DIR / f"{self.trial_id}.json").read_text())
            real_data["trial_id"] = "trial-wrong-id"
            fake_file.write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("Rederived trial_id mismatch" in err for err in rec["errors"]))

    def test_mismatched_rederived_validity_category_fails_closed(self):
        """Correction 1: Rederived record with validity != VALID_LIVE fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_file = tmp_path / f"{self.trial_id}.json"
            real_data = json.loads((REDERIVED_DIR / f"{self.trial_id}.json").read_text())
            real_data["validity_category"] = "CORRUPTED_RECORD"
            fake_file.write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("validity category not VALID_LIVE" in err for err in rec["errors"]))

    def test_mismatched_rederived_classification_fails_closed(self):
        """Correction 1: Rederived record with unexpected classification fails closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_file = tmp_path / f"{self.trial_id}.json"
            real_data = json.loads((REDERIVED_DIR / f"{self.trial_id}.json").read_text())
            real_data["classification"] = "CONNECTION_FAILED"
            fake_file.write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("classification mismatch" in err for err in rec["errors"]))

    def test_missing_rederived_primary_flow_pcap_digest_fails_closed(self):
        """Correction A: Missing rederived primary flow pcap_sha256 digest must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_file = tmp_path / f"{self.trial_id}.json"
            real_data = json.loads((REDERIVED_DIR / f"{self.trial_id}.json").read_text())
            del real_data["primary_flow"]["pcap_sha256"]
            fake_file.write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("missing pcap_sha256 digest" in err for err in rec["errors"]))

    def test_malformed_rederived_primary_flow_pcap_digest_fails_closed(self):
        """Correction A: Malformed rederived primary flow pcap_sha256 digest must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_file = tmp_path / f"{self.trial_id}.json"
            real_data = json.loads((REDERIVED_DIR / f"{self.trial_id}.json").read_text())
            real_data["primary_flow"]["pcap_sha256"] = "malformed-not-64-hex"
            fake_file.write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("malformed pcap_sha256 digest" in err for err in rec["errors"]))

    def test_mismatched_rederived_primary_flow_pcap_digest_fails_closed(self):
        """Correction A: Valid-format but mismatched primary flow pcap_sha256 must fail closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_file = tmp_path / f"{self.trial_id}.json"
            real_data = json.loads((REDERIVED_DIR / f"{self.trial_id}.json").read_text())
            real_data["primary_flow"]["pcap_sha256"] = "0" * 64
            fake_file.write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=tmp_path,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("primary flow PCAP digest mismatch" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_missing_primary_flow_fails_closed(self, mock_dissect):
        """Blocker P0-A: Empty or missing primary flow must fail closed without fallback."""
        mock_dissect.return_value = {
            "tcp_streams": {},
            "primary_flow": None,
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Primary HTTP flow not correlated" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_missing_http_status_code_fails_closed(self, mock_dissect):
        """Blocker P0-A: Missing HTTP status code must NOT default to 200."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": None,  # Missing!
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("HTTP status code missing" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_float_http_status_code_in_replay_fails_closed(self, mock_dissect):
        """Correction B: Replay engine rejects floating-point 200.0 HTTP status."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 200.0,  # Float!
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Primary flow HTTP status must be integer 200" in err for err in rec["errors"]))

    def test_float_http_status_code_in_rederived_fails_closed(self):
        """Correction B: Replay engine rejects floating-point 200.0 in rederived record."""
        real_reder_file = REDERIVED_DIR / f"{self.valid_spec['trial_id']}.json"
        real_data = json.loads(real_reder_file.read_text(encoding="utf-8"))
        real_data["primary_flow"]["http_status_code"] = 200.0
        with tempfile.TemporaryDirectory() as td:
            temp_rdir = Path(td)
            (temp_rdir / real_reder_file.name).write_text(json.dumps(real_data), encoding="utf-8")
            rec = replay_single_trial(
                demo=self.valid_spec,
                checksum_map=self.valid_checksum_map,
                campaign_dir=CAMPAIGN_DIR,
                rederived_dir=temp_rdir,
            )
            self.assertEqual(rec["status"], "FAIL")
            self.assertTrue(any("HTTP status mismatch or non-integer" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_boolean_http_status_code_fails_closed(self, mock_dissect):
        """Correction B: Replay engine rejects boolean True HTTP status."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": True,  # Boolean!
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Primary flow HTTP status must be integer 200" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_dissected_status_201_fails_closed(self, mock_dissect):
        """Correction C: Replay engine rejects HTTP status 201 Created (must strictly be 200)."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 201,  # 201 is not 200
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Primary flow HTTP status must be integer 200, got: 201" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_dissected_status_202_fails_closed(self, mock_dissect):
        """Correction C: Replay engine rejects HTTP status 202 Accepted (must strictly be 200)."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 202,  # 202 is not 200
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Primary flow HTTP status must be integer 200, got: 202" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_dissected_and_rederived_status_discrepancy_fails_closed(self, mock_dissect):
        """Correction C: Replay engine detects discrepancy between dissected status and rederived status."""
        # Rederived has 200, mock dissect has 201
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 201,
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Dissected HTTP status mismatch with rederived: 201 != 200" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_fractional_frame_in_replay_fails_closed(self, mock_dissect):
        """Correction B: Replay engine rejects fractional syn_frame."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": True,
                "syn_frame": 10.9,  # Float!
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 200,
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("initial SYN frame missing or invalid positive integer" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_incomplete_handshake_fails_closed(self, mock_dissect):
        """Handshake without completion (handshake_completed=False) fails closed."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv6",
                "handshake_completed": False,
                "syn_frame": 1,
                "final_ack_frame": None,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 200,
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("3-way handshake was not completed" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_winning_family_discrepancy_fails_closed(self, mock_dissect):
        """Winning family discrepancy against ground truth fails closed."""
        mock_dissect.return_value = {
            "tcp_streams": {"0": {}},
            "primary_flow": {
                "stream_id": "0",
                "family": "IPv4",  # S0 expected IPv6!
                "handshake_completed": True,
                "syn_frame": 1,
                "final_ack_frame": 3,
                "http_request_frame": 4,
                "http_response_frame": 5,
                "http_status_code": 200,
            },
            "metrics": {},
        }
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("Winning family discrepancy" in err for err in rec["errors"]))

    @patch("lab.demo_replay.dissect_pcap")
    def test_dissection_exception_fails_closed(self, mock_dissect):
        """Dissection exception must be caught and reported as error."""
        mock_dissect.side_effect = RuntimeError("Simulated TShark crash")
        rec = replay_single_trial(
            demo=self.valid_spec,
            checksum_map=self.valid_checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "FAIL")
        self.assertTrue(any("TShark dissection failed" in err for err in rec["errors"]))

    def test_checksum_file_ambiguous_duplicate_rejected(self):
        """Pathological checksum file with conflicting hashes for the same trial fails closed."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
            f.write(
                "69fd09eb63b53f2be42428e40d99ed61eeef4da47bead93fe129ecab1ba47f72 /some/path/trials/trial-20261029205425-6cb90a54/capture.pcap\n"
                "1111111111111111111111111111111111111111111111111111111111111111 /other/path/trials/trial-20261029205425-6cb90a54/capture.pcap\n"
            )
            f.flush()
            with self.assertRaises(ValueError) as ctx:
                load_canonical_pcap_checksums(Path(f.name))
            self.assertIn("Ambiguous conflicting checksums", str(ctx.exception))

    def test_checksum_file_malformed_digest_rejected(self):
        """Checksum file with short or non-hex digest fails closed."""
        with tempfile.NamedTemporaryFile("w+", encoding="utf-8") as f:
            f.write("deadbeef /some/path/trials/trial-20261029205425-6cb90a54/capture.pcap\n")
            f.flush()
            with self.assertRaises(ValueError) as ctx:
                load_canonical_pcap_checksums(Path(f.name))
            self.assertIn("Invalid SHA-256 digest", str(ctx.exception))

    def test_run_demonstration_nonzero_exit_on_failure(self):
        """run_demonstration returns non-zero code if any trial fails."""
        # Querying an invalid non-existent scenario filter
        code = run_demonstration(scenario_filter="S99", summary_mode=True)
        self.assertNotEqual(code, 0)


class TestDemoReplayAuthenticAcceptance(unittest.TestCase):
    """
    Authentic acceptance tests executing full offline dissection against all 14 preserved PCAPs.
    Guarantees that authentic October 29 campaign PCAPs satisfy every scientific and protocol constraint.
    """

    @classmethod
    def setUpClass(cls):
        cls.checksum_map = load_canonical_pcap_checksums(CHECKSUM_FILE)

    def test_all_14_representative_trials_defined_and_unique(self):
        """Registry must contain exactly 14 unique trials covering S0-S6 x Chrome/Firefox."""
        self.assertEqual(len(REPRESENTATIVE_TRIALS), 14)
        trial_ids = [t["trial_id"] for t in REPRESENTATIVE_TRIALS]
        self.assertEqual(len(set(trial_ids)), 14, "Trial IDs must be strictly unique")

        scenarios = set(t["scenario_id"] for t in REPRESENTATIVE_TRIALS)
        self.assertEqual(scenarios, {"S0", "S1", "S2", "S3", "S4", "S5", "S6"})

        browsers = set(t["browser"] for t in REPRESENTATIVE_TRIALS)
        self.assertEqual(browsers, {"google-chrome", "firefox"})

    def test_all_14_authentic_pcaps_pass_validation(self):
        """Every one of the 14 authentic PCAPs must pass complete fail-closed verification."""
        for demo in REPRESENTATIVE_TRIALS:
            with self.subTest(scenario=demo["scenario_id"], browser=demo["browser"], trial_id=demo["trial_id"]):
                rec = replay_single_trial(
                    demo=demo,
                    checksum_map=self.checksum_map,
                    campaign_dir=CAMPAIGN_DIR,
                    rederived_dir=REDERIVED_DIR,
                    verbose_events=True,
                )
                self.assertEqual(
                    rec["status"],
                    "PASS",
                    f"Trial {demo['trial_id']} ({demo['scenario_id']} {demo['browser']}) failed: {rec['errors']}",
                )
                self.assertEqual(rec["errors"], [])

                # Verify primary flow properties
                pf = rec["primary_flow"]
                self.assertEqual(pf["family"], demo["expected_family"])
                self.assertEqual(pf["http_status_code"], 200)
                self.assertTrue(pf["handshake_completed"])

                # Verify metrics are finite non-negative
                metrics = rec["metrics"]
                self.assertIsNotNone(metrics["t_connect_ms"])
                self.assertGreater(metrics["t_connect_ms"], 0.0)

                # Verify event timeline extraction
                self.assertGreater(len(rec["events"]), 0)

    def test_valid_authentic_http_200_replay(self):
        """Correction C: Authentic PCAP replay strictly verifies integer HTTP 200 outcome."""
        demo = REPRESENTATIVE_TRIALS[0]
        rec = replay_single_trial(
            demo=demo,
            checksum_map=self.checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
        )
        self.assertEqual(rec["status"], "PASS")
        self.assertEqual(rec["errors"], [])
        pf = rec["primary_flow"]
        self.assertIs(type(pf["http_status_code"]), int)
        self.assertEqual(pf["http_status_code"], 200)

    def test_full_replay_demonstration_cli_success(self):
        """Full CLI replay must return exit code 0."""
        code = run_demonstration(summary_mode=True)
        self.assertEqual(code, 0)

    def test_json_replay_output_structure(self):
        """JSON replay output must produce valid JSON with all_passed=True."""
        out = StringIO()
        with patch("sys.stdout", out):
            code = run_demonstration(as_json=True)
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertTrue(data["all_passed"])
        self.assertEqual(data["total_selected"], 14)
        self.assertEqual(data["passed_count"], 14)
        self.assertEqual(data["failed_count"], 0)


if __name__ == "__main__":
    unittest.main()
