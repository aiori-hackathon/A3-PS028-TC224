#!/usr/bin/env python3
"""
Unit and Regression Test Suite for PS-028 Partner Handover Verifier
Workstream C: Partner Replication Readiness
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from lab import verify_partner_handover


def make_synthetic_campaign(root: Path, campaign_id: str = "ps028-partner-lab2-20261117", simulation: bool = False, repetitions: int = 20) -> Path:
    camp_dir = root / campaign_id
    camp_dir.mkdir(parents=True, exist_ok=True)

    trials = []
    trial_num = 1
    for sc in verify_partner_handover.CANONICAL_SCENARIOS:
        for br in verify_partner_handover.CANONICAL_BROWSERS:
            for rep in range(repetitions):
                tid = f"trial-{campaign_id}-{sc}-{br[:2]}-{rep:02d}-{trial_num:04d}"
                trial_num += 1
                tdir = camp_dir / tid
                tdir.mkdir(parents=True, exist_ok=True)

                pcap = tdir / "capture.pcap"
                pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32)

                rec = tdir / "trial_record.json"
                rec.write_text(json.dumps({"trial_id": tid, "scenario": sc, "browser": br, "status": "PASS"}), encoding="utf-8")

                trials.append({
                    "trial_id": tid,
                    "scenario": sc,
                    "browser": br,
                    "status": "PASS"
                })

    manifest = {
        "campaign_id": campaign_id,
        "simulation": simulation,
        "trials": trials
    }
    (camp_dir / "campaign_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return camp_dir


class TestVerifyPartnerHandover(unittest.TestCase):
    """Verifies that the partner evidence verifier enforces all strict engineering and authenticity rules."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_partner_handover_test_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_synthetic_campaign_passes(self):
        """A complete 280-trial non-simulated campaign passes verification."""
        camp = make_synthetic_campaign(self.temp_dir, simulation=False, repetitions=20)
        res = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["valid_trials_count"], 280)
        self.assertTrue(res["matrix_verified"])

    def test_simulation_campaign_rejected(self):
        """Campaign marked simulation: true is strictly rejected with VerificationError."""
        camp = make_synthetic_campaign(self.temp_dir, simulation=True, repetitions=20)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("simulation: true", str(ctx.exception).lower())

    def test_historical_campaign_id_rejected(self):
        """Campaign using the protected historical baseline campaign ID is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, campaign_id="ps028-a10-live-20261030-01", simulation=False, repetitions=20)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("historical", str(ctx.exception).lower())

    def test_incomplete_repetitions_rejected(self):
        """Campaign with fewer than 20 repetitions per slot is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=19)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("incomplete matrix slot", str(ctx.exception).lower())

    def test_duplicate_trial_id_rejected(self):
        """Campaign containing duplicate trial IDs is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        data["trials"][1]["trial_id"] = data["trials"][0]["trial_id"]
        mpath.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("duplicate trial_id", str(ctx.exception).lower())

    def test_empty_pcap_rejected(self):
        """Trial with 0-byte capture.pcap is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        first_trial = camp / "trial-ps028-partner-lab2-20261117-S0-go-00-0001"
        (first_trial / "capture.pcap").write_bytes(b"")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_checksum_manifest_mismatch_rejected(self):
        """Tampered file mismatching partner_evidence.sha256 is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        first_trial = camp / "trial-ps028-partner-lab2-20261117-S0-go-00-0001"
        pcap = first_trial / "capture.pcap"

        # Create checksum manifest
        sha_manifest = camp / "partner_evidence.sha256"
        h = hashlib.sha256(pcap.read_bytes()).hexdigest()
        rel = pcap.relative_to(camp).as_posix()
        sha_manifest.write_text(f"{h}  {rel}\n", encoding="utf-8")

        # Now tamper with the pcap
        pcap.write_bytes(b"\xff" * 40)

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("checksum mismatch", str(ctx.exception).lower())

    def test_derived_directory_with_missing_provenance_rejected(self):
        """Derived export directory missing .provenance.json sidecar is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = self.temp_dir / "derived"
        derived.mkdir()
        (derived / "attempts.csv").write_text("trial_id,status\n1,PASS\n", encoding="utf-8")
        (derived / "connection_attempts.csv").write_text("trial_id,status\n1,PASS\n", encoding="utf-8")
        (derived / "trial_timeline.csv").write_text("trial_id,time\n1,0\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("missing cryptographic provenance sidecar", str(ctx.exception).lower())

    def test_archive_tar_gz_verification(self):
        """Valid .tar.gz archive and accompanying .sha256 passes verification."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        arch_path = self.temp_dir / "partner_handover.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            tar.add(camp, arcname=camp.name)

        sha = verify_partner_handover.sha256_file(arch_path)
        (self.temp_dir / "partner_handover.tar.gz.sha256").write_text(f"{sha}  partner_handover.tar.gz\n", encoding="utf-8")

        res = verify_partner_handover.verify_partner_archive(arch_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["valid_trials_count"], 280)


if __name__ == "__main__":
    unittest.main()
