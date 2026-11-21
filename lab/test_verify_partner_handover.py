#!/usr/bin/env python3
"""
Unit and Regression Test Suite for PS-028 Partner Handover Verifier
Workstream C: Partner Replication Readiness

Tests CampaignRunner schema compatibility, matrix rigor (280 slots),
live execution authenticity, physical evidence layout (trials/<trial_id>/),
preserved failure history, PCAP integrity, archive path/type safety,
fail-closed checksum sidecars, and derived ledger provenance validation.
"""

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
from typing import Any, Dict, List, Optional
import unittest

from lab import verify_partner_handover


def create_synthetic_pcap_bytes(pkt_count: int = 1) -> bytes:
    """
    Creates deterministic synthetic binary PCAP data:
    24-byte PCAP header (swapped endian 0xd4c3b2a1) + pkt_count valid packet records.
    Explicitly labeled as synthetic test fixture data.
    """
    # 24-byte header: magic (4), major (2), minor (2), tz (4), sigfigs (4), snaplen (4), network (4)
    hdr = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    packets = bytearray()
    for i in range(pkt_count):
        payload = b"\xde\xad\xbe\xef"  # 4 bytes synthetic payload
        # 16-byte packet record header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
        pkt_hdr = struct.pack("<IIII", 1700000000 + i, 1000 * i, len(payload), len(payload))
        packets.extend(pkt_hdr + payload)
    return hdr + bytes(packets)


def make_synthetic_campaign(
    root: Path,
    campaign_id: str = "ps028-partner-testlab-20261118",
    is_simulation: bool = False,
    execution_mode: str = "LIVE",
    status: str = "COMPLETED",
    repetitions: int = 20,
    include_retried_slot: bool = False,
    schema_version: str = "1.0.0"
) -> Path:
    """
    Builds a synthetic campaign directory strictly shaped like actual CampaignRunner output:
    - campaign_manifest.json with matrix_slots and ExecutionAttempt records.
    - Physical layout under trials/<trial_id>/: result.json, capture.pcap.
    - Preserved failed attempts under trials/<failed_trial_id>/: failed_attempt_record.json.
    """
    camp_dir = root / campaign_id
    camp_dir.mkdir(parents=True, exist_ok=True)
    trials_dir = camp_dir / "trials"
    trials_dir.mkdir(parents=True, exist_ok=True)

    slots: List[Dict[str, Any]] = []
    slot_idx = 1
    total_valid = 0
    total_failed = 0

    for rep in range(1, repetitions + 1):
        for sc in verify_partner_handover.CANONICAL_SCENARIOS:
            for br in verify_partner_handover.CANONICAL_BROWSERS:
                slot_id = f"slot-{slot_idx:04d}-{sc}-{br}-rep{rep:02d}"

                # If requested, make slot 2 contain a preserved failed attempt and successful retry
                if include_retried_slot and slot_idx == 2:
                    fail_tid = f"trial-synth-{campaign_id}-fail-{slot_idx:04d}-01"
                    fail_tdir = trials_dir / fail_tid
                    fail_tdir.mkdir(parents=True, exist_ok=True)

                    fail_record = {
                        "attempt_number": 1,
                        "trial_id": fail_tid,
                        "execution_mode": execution_mode,
                        "is_simulation": is_simulation,
                        "timestamps": {
                            "start_time": "2026-11-18T00:00:00.000000+00:00",
                            "end_time": "2026-11-18T00:00:05.000000+00:00",
                            "duration_ms": 5000.0
                        },
                        "status": "FAILED",
                        "validity": "CLEANUP_FAILURE",
                        "evidence_paths": {"trial_dir": str(fail_tdir)},
                        "capture_metadata": {},
                        "cleanup_status": {
                            "scenario_restored": False,
                            "baseline_verified": False,
                            "errors": ["Synthetic transient cleanup error"]
                        },
                        "error_message": "Synthetic cleanup failure"
                    }
                    (fail_tdir / "failed_attempt_record.json").write_text(
                        json.dumps(fail_record, indent=2), encoding="utf-8"
                    )

                    succ_tid = f"trial-synth-{campaign_id}-succ-{slot_idx:04d}-02"
                    succ_tdir = trials_dir / succ_tid
                    succ_tdir.mkdir(parents=True, exist_ok=True)

                    pcap_data = create_synthetic_pcap_bytes(pkt_count=2)
                    (succ_tdir / "capture.pcap").write_bytes(pcap_data)
                    pcap_sha = hashlib.sha256(pcap_data).hexdigest()

                    br_ver = "156.0.8078.73" if br in ("google-chrome", "chrome") else "159.0"
                    succ_res = {
                        "schema_version": schema_version,
                        "trial_id": succ_tid,
                        "scenario_id": sc,
                        "execution_mode": execution_mode,
                        "is_simulation": is_simulation,
                        "browser": {"name": br, "version": br_ver, "executable": f"/usr/bin/{br}"},
                        "timestamps": {
                            "start_time": "2026-11-18T00:00:10.000000+00:00",
                            "end_time": "2026-11-18T00:00:15.000000+00:00",
                            "total_duration_ms": 5000.0
                        },
                        "capture_metadata": {
                            "pcap_path": str(succ_tdir / "capture.pcap"),
                            "pcap_sha256": pcap_sha,
                            "pcap_size_bytes": len(pcap_data),
                            "packet_count": 2,
                            "pcap_valid": True
                        },
                        "cleanup_status": {
                            "scenario_restored": True,
                            "baseline_verified": True,
                            "errors": []
                        }
                    }
                    (succ_tdir / "result.json").write_text(
                        json.dumps(succ_res, indent=2), encoding="utf-8"
                    )

                    succ_attempt = {
                        "attempt_number": 2,
                        "trial_id": succ_tid,
                        "execution_mode": execution_mode,
                        "is_simulation": is_simulation,
                        "timestamps": succ_res["timestamps"],
                        "status": "COMPLETED",
                        "validity": "VALID_LIVE",
                        "evidence_paths": {
                            "trial_dir": str(succ_tdir),
                            "result_json": str(succ_tdir / "result.json"),
                            "capture_pcap": str(succ_tdir / "capture.pcap")
                        },
                        "capture_metadata": succ_res["capture_metadata"],
                        "cleanup_status": succ_res["cleanup_status"],
                        "error_message": None
                    }

                    slot = {
                        "slot_id": slot_id,
                        "slot_index": slot_idx,
                        "scenario_id": sc,
                        "browser": br,
                        "repetition": rep,
                        "status": "COMPLETED",
                        "current_trial_id": succ_tid,
                        "attempts": [fail_record, succ_attempt]
                    }
                    slots.append(slot)
                    total_failed += 1
                    total_valid += 1
                    slot_idx += 1
                    continue

                # Standard valid slot
                tid = f"trial-synth-{campaign_id}-{slot_idx:04d}-01"
                tdir = trials_dir / tid
                tdir.mkdir(parents=True, exist_ok=True)

                pcap_data = create_synthetic_pcap_bytes(pkt_count=1)
                (tdir / "capture.pcap").write_bytes(pcap_data)
                pcap_sha = hashlib.sha256(pcap_data).hexdigest()

                br_ver = "156.0.8078.73" if br in ("google-chrome", "chrome") else "159.0"
                res_data = {
                    "schema_version": schema_version,
                    "trial_id": tid,
                    "scenario_id": sc,
                    "execution_mode": execution_mode,
                    "is_simulation": is_simulation,
                    "browser": {"name": br, "version": br_ver, "executable": f"/usr/bin/{br}"},
                    "timestamps": {
                        "start_time": "2026-11-18T00:00:00.000000+00:00",
                        "end_time": "2026-11-18T00:00:05.000000+00:00",
                        "total_duration_ms": 5000.0
                    },
                    "capture_metadata": {
                        "pcap_path": str(tdir / "capture.pcap"),
                        "pcap_sha256": pcap_sha,
                        "pcap_size_bytes": len(pcap_data),
                        "packet_count": 1,
                        "pcap_valid": True
                    },
                    "cleanup_status": {
                        "scenario_restored": True,
                        "baseline_verified": True,
                        "errors": []
                    }
                }
                (tdir / "result.json").write_text(
                    json.dumps(res_data, indent=2), encoding="utf-8"
                )

                att = {
                    "attempt_number": 1,
                    "trial_id": tid,
                    "execution_mode": execution_mode,
                    "is_simulation": is_simulation,
                    "timestamps": res_data["timestamps"],
                    "status": "COMPLETED",
                    "validity": "VALID_LIVE" if not is_simulation else "SIMULATION",
                    "evidence_paths": {
                        "trial_dir": str(tdir),
                        "result_json": str(tdir / "result.json"),
                        "capture_pcap": str(tdir / "capture.pcap")
                    },
                    "capture_metadata": res_data["capture_metadata"],
                    "cleanup_status": res_data["cleanup_status"],
                    "error_message": None
                }

                slot = {
                    "slot_id": slot_id,
                    "slot_index": slot_idx,
                    "scenario_id": sc,
                    "browser": br,
                    "repetition": rep,
                    "status": status,
                    "current_trial_id": tid,
                    "attempts": [att]
                }
                slots.append(slot)
                total_valid += 1
                slot_idx += 1

    manifest = {
        "schema_version": schema_version,
        "campaign_id": campaign_id,
        "status": status,
        "execution_mode": execution_mode,
        "is_simulation": is_simulation,
        "created_at": "2026-11-18T00:00:00.000000+00:00",
        "completed_at": "2026-11-18T01:00:00.000000+00:00",
        "configuration": {
            "scenarios": verify_partner_handover.CANONICAL_SCENARIOS,
            "browsers": verify_partner_handover.CANONICAL_BROWSERS,
            "repetitions": repetitions,
            "output_dir": str(camp_dir)
        },
        "summary": {
            "total_slots": len(slots),
            "completed_slots": len(slots) if status == "COMPLETED" else 0,
            "total_attempts": total_valid + total_failed,
            "valid_live_attempts": total_valid if not is_simulation else 0,
            "simulated_attempts": total_valid if is_simulation else 0,
            "failed_attempts": total_failed,
            "halt_reason": None
        },
        "matrix_slots": slots
    }

    (camp_dir / "campaign_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return camp_dir


def make_synthetic_derived_directory(
    camp_dir: Path,
    out_dir: Path,
    git_dirty: bool = False,
    prov_status: str = "VERIFIED",
    git_status: str = "VERIFIED",
    tamper_csv: bool = False,
    mismatch_campaign_id: bool = False
) -> Path:
    """Creates synthetic derived ledgers and cryptographic .provenance.json sidecars."""
    out_dir.mkdir(parents=True, exist_ok=True)
    mpath = camp_dir / "campaign_manifest.json"
    mdata = json.loads(mpath.read_text(encoding="utf-8"))
    cid = "mismatched-campaign-id" if mismatch_campaign_id else mdata["campaign_id"]

    # 1. attempts.csv
    attempts_rows = []
    conn_rows = []
    timeline_rows = []

    for slot in mdata.get("matrix_slots", []):
        sid = slot["slot_id"]
        sidx = slot["slot_index"]
        sc = slot["scenario_id"]
        br = slot["browser"]
        rep = slot["repetition"]
        for att in slot.get("attempts", []):
            att_num = att["attempt_number"]
            tid = att["trial_id"]
            st = att["status"]
            val = att["validity"]
            pcap_sha = att.get("capture_metadata", {}).get("pcap_sha256", "")
            att_id = f"{sid}-att{att_num:02d}"

            attempts_rows.append({
                "attempt_id": att_id,
                "slot_id": sid,
                "slot_index": sidx,
                "campaign_id": cid,
                "scenario_id": sc,
                "browser": br,
                "repetition": rep,
                "attempt_number": att_num,
                "trial_id": tid,
                "status": st,
                "validity_category": val,
                "classification": "DIRECT_IPV6" if val == "VALID_LIVE" else "INCONCLUSIVE",
                "http_status": "200" if val == "VALID_LIVE" else "",
                "t_connect_ms": "20.00" if val == "VALID_LIVE" else "",
                "t_setup_total_ms": "20.00" if val == "VALID_LIVE" else "",
                "syn_to_synack_ms": "19.00" if val == "VALID_LIVE" else "",
                "cad_ms": "",
                "pcap_sha256": pcap_sha,
                "start_time": "2026-11-18T00:00:00.000000+00:00",
                "end_time": "2026-11-18T00:00:05.000000+00:00"
            })

            if val == "VALID_LIVE":
                conn_rows.append({
                    "trial_id": tid,
                    "pcap_sha256": pcap_sha,
                    "tcp_stream": "0",
                    "family": "IPv6",
                    "client_ip": "2001:db8:1::2",
                    "client_port": "50000",
                    "server_ip": "2001:db8:2::10",
                    "server_port": "80",
                    "syn_time": "1700000000.0",
                    "synack_time": "1700000000.02",
                    "final_ack_time": "1700000000.021",
                    "rst_time": "",
                    "offset_from_first_syn_ms": "0.00",
                    "outcome": "ESTABLISHED_PRIMARY",
                    "is_primary": "True",
                    "retransmitted_syn_count": "0"
                })

            timeline_rows.append({
                "trial_id": tid,
                "event_index": "1",
                "event_timestamp_epoch": "1700000000.0",
                "event_source": "HARNESS",
                "event_type": "TRIAL_START",
                "address_family": "",
                "tcp_stream": "",
                "frame_number": "",
                "details": "Synthetic start",
                "pcap_sha256": pcap_sha,
                "source_path": f"trials/{tid}/result.json"
            })

    datasets = {
        "attempts.csv": attempts_rows,
        "connection_attempts.csv": conn_rows,
        "trial_timeline.csv": timeline_rows
    }

    for fname, rows in datasets.items():
        fpath = out_dir / fname
        if rows:
            with open(fpath, "w", encoding="utf-8", newline="") as cf:
                writer = csv.DictWriter(cf, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        else:
            fpath.write_text("trial_id\n", encoding="utf-8")

        calc_hash = verify_partner_handover.sha256_file(fpath)

        if tamper_csv and fname == "attempts.csv":
            # Tamper with CSV after computing sidecar hash
            with open(fpath, "a", encoding="utf-8") as cf:
                cf.write("tampered,data\n")

        prov = {
            "target_file": fname,
            "sha256": calc_hash,
            "row_count": len(rows),
            "generated_by_command": "python3 lab/export_campaign_evidence.py",
            "provenance_status": prov_status,
            "git_commit": "abcdef1234567890abcdef1234567890abcdef12",
            "git_branch": "fix/phase-e-bundle-timeline-mapping",
            "git_dirty": git_dirty,
            "git_status": git_status
        }
        (out_dir / f"{fname}.provenance.json").write_text(
            json.dumps(prov, indent=2), encoding="utf-8"
        )

    return out_dir


class TestVerifyPartnerHandover(unittest.TestCase):
    """Verifies that the partner evidence verifier enforces all strict engineering and authenticity rules."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_partner_test_"))
        verify_partner_handover._DISSECTION_CACHE.clear()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        verify_partner_handover._DISSECTION_CACHE.clear()

    def test_valid_synthetic_campaign_passes(self):
        """A complete 280-slot non-simulated live campaign passes verification."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        res = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["valid_trials_count"], 280)
        self.assertEqual(res["total_slots"], 280)
        self.assertEqual(res["total_attempts"], 280)
        self.assertEqual(res["failed_attempts_preserved"], 0)
        self.assertTrue(res["matrix_verified"])

    def test_campaign_with_preserved_failed_attempts_passes(self):
        """Campaign with retried slot and preserved failed-attempt history passes and verifies both."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        res = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["valid_trials_count"], 280)
        self.assertEqual(res["total_slots"], 280)
        self.assertEqual(res["total_attempts"], 281)
        self.assertEqual(res["failed_attempts_preserved"], 1)

    def test_unsupported_schema_version_rejected(self):
        """Campaign with unsupported manifest schema_version is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, schema_version="0.9.0")
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("schema_version", str(ctx.exception).lower())

    def test_simulation_manifest_rejected(self):
        """Campaign manifest declaring is_simulation=true is strictly rejected."""
        camp = make_synthetic_campaign(self.temp_dir, is_simulation=True, repetitions=20)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("is_simulation=true", str(ctx.exception).lower())

    def test_execution_mode_simulation_rejected(self):
        """Campaign manifest declaring execution_mode='SIMULATION' is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, execution_mode="SIMULATION", repetitions=20)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("execution_mode", str(ctx.exception).lower())

    def test_campaign_status_not_completed_rejected(self):
        """Campaign manifest with status != 'COMPLETED' is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, status="IN_PROGRESS", repetitions=20)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("status is 'in_progress'", str(ctx.exception).lower())

    def test_historical_campaign_id_rejected(self):
        """Campaign pointing to or named after protected historical baseline is rejected."""
        camp = make_synthetic_campaign(
            self.temp_dir, campaign_id="ps028-a10-live-20261030-01", repetitions=20
        )
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("historical", str(ctx.exception).lower())

    def test_incomplete_repetitions_rejected(self):
        """Campaign with fewer than 20 repetitions per slot is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=19)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("slot count mismatch", str(ctx.exception).lower())

    def test_duplicate_slot_id_rejected(self):
        """Campaign with duplicate slot IDs is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        data["matrix_slots"][1]["slot_id"] = data["matrix_slots"][0]["slot_id"]
        mpath.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("duplicate slot_id", str(ctx.exception).lower())

    def test_duplicate_trial_id_rejected(self):
        """Campaign containing duplicate trial IDs across slots is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        dup_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        data["matrix_slots"][1]["attempts"][0]["trial_id"] = dup_tid
        data["matrix_slots"][1]["current_trial_id"] = dup_tid
        mpath.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("duplicate trial_id", str(ctx.exception).lower())

    def test_missing_result_json_rejected(self):
        """Trial with missing result.json is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        (camp / "trials" / first_tid / "result.json").unlink()

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("missing result.json", str(ctx.exception).lower())

    def test_empty_or_small_pcap_rejected(self):
        """Trial with 0-byte or truncated capture.pcap is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        (camp / "trials" / first_tid / "capture.pcap").write_bytes(b"\x00" * 10)

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("too small", str(ctx.exception).lower())

    def test_invalid_pcap_magic_rejected(self):
        """Trial with corrupted PCAP header magic is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        raw = pcap_file.read_bytes()
        pcap_file.write_bytes(b"\xff\xff\xff\xff" + raw[4:])

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("invalid pcap header magic", str(ctx.exception).lower())

    def test_pcap_sha256_mismatch_rejected(self):
        """Altered PCAP mismatching recorded digest in result.json is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        # Append extra byte so size >= 24 but hash changes
        pcap_file.write_bytes(pcap_file.read_bytes() + b"\x00")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("pcap sha-256 mismatch", str(ctx.exception).lower())

    def test_cleanup_failure_in_result_rejected(self):
        """Trial whose result.json indicates cleanup or baseline failure is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        rpath = camp / "trials" / first_tid / "result.json"
        rdata = json.loads(rpath.read_text(encoding="utf-8"))
        rdata["cleanup_status"]["scenario_restored"] = False
        rpath.write_text(json.dumps(rdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("scenario was not restored", str(ctx.exception).lower())

    def test_checksum_manifest_verification_and_tamper_rejection(self):
        """partner_evidence.sha256 is verified when valid, and rejected when tampered."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        pcap = camp / "trials" / first_tid / "capture.pcap"

        sha_manifest = camp / "partner_evidence.sha256"
        h = hashlib.sha256(pcap.read_bytes()).hexdigest()
        rel = pcap.relative_to(camp).as_posix()
        sha_manifest.write_text(f"{h}  {rel}\n", encoding="utf-8")

        # Passes with intact file
        res = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(res["checksum_files_checked"], 1)

        # Tampering with manifest hash causes failure
        sha_manifest.write_text(f"{'0'*64}  {rel}\n", encoding="utf-8")
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("checksum mismatch", str(ctx.exception).lower())

    def test_checksum_manifest_path_traversal_rejected(self):
        """partner_evidence.sha256 containing path traversal is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        sha_manifest = camp / "partner_evidence.sha256"
        sha_manifest.write_text(f"{'a'*64}  ../escaped.txt\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("illegal or traversal path", str(ctx.exception).lower())

    def test_portable_paths_relocation(self):
        """Campaign directory relocated to a new path passes verification portably."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        new_loc = self.temp_dir / "relocated_campaign_dir"
        shutil.move(camp, new_loc)

        res = verify_partner_handover.verify_partner_campaign_directory(new_loc)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["valid_trials_count"], 280)

    def test_archive_tar_gz_verification_success(self):
        """Valid .tar.gz archive and accompanying .sha256 sidecar pass verification."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        arch_path = self.temp_dir / "partner_handover.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            tar.add(camp, arcname=camp.name)

        sha = verify_partner_handover.sha256_file(arch_path)
        (self.temp_dir / "partner_handover.tar.gz.sha256").write_text(
            f"{sha}  partner_handover.tar.gz\n", encoding="utf-8"
        )

        res = verify_partner_handover.verify_partner_archive(arch_path)
        self.assertEqual(res["status"], "PASS")
        self.assertEqual(res["valid_trials_count"], 280)

    def test_archive_missing_sha256_sidecar_fails_closed(self):
        """Archive without mandatory .sha256 sidecar fails closed with VerificationError."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        arch_path = self.temp_dir / "partner_handover.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            tar.add(camp, arcname=camp.name)

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_archive(arch_path)
        self.assertIn("missing mandatory archive sha-256 sidecar", str(ctx.exception).lower())

    def test_archive_path_traversal_rejected(self):
        """Archive containing path traversal member is rejected before extraction."""
        arch_path = self.temp_dir / "malicious.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="../escape.txt")
            ti.size = 5
            tar.addfile(ti, fileobj=io.BytesIO(b"hello"))

        sha = verify_partner_handover.sha256_file(arch_path)
        (self.temp_dir / "malicious.tar.gz.sha256").write_text(f"{sha}  malicious.tar.gz\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_archive(arch_path)
        self.assertIn("directory traversal", str(ctx.exception).lower())

    def test_archive_absolute_path_rejected(self):
        """Archive containing absolute path member is rejected before extraction."""
        arch_path = self.temp_dir / "absolute_path.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="/etc/malicious.txt")
            ti.size = 5
            tar.addfile(ti, fileobj=io.BytesIO(b"hello"))

        sha = verify_partner_handover.sha256_file(arch_path)
        (self.temp_dir / "absolute_path.tar.gz.sha256").write_text(f"{sha}  absolute_path.tar.gz\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_archive(arch_path)
        self.assertIn("illegal path", str(ctx.exception).lower())

    def test_archive_symlink_escaping_root_rejected(self):
        """Archive containing symlink escaping extraction root is rejected."""
        arch_path = self.temp_dir / "symlink_attack.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="campaign/bad_symlink")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "../../etc/passwd"
            tar.addfile(ti)

        sha = verify_partner_handover.sha256_file(arch_path)
        (self.temp_dir / "symlink_attack.tar.gz.sha256").write_text(f"{sha}  symlink_attack.tar.gz\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_archive(arch_path)
        self.assertIn("illegal link target", str(ctx.exception).lower())

    def test_derived_directory_verification_success(self):
        """Complete derived export directory with verified provenance passes audit."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = self.temp_dir / "derived"
        make_synthetic_derived_directory(camp, derived)

        res = verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIsNotNone(res["derived_audit"])
        self.assertEqual(len(res["derived_audit"]["ledgers_verified"]), 3)

    def test_derived_missing_dir_fails_closed(self):
        """Explicitly requested --derived-dir pointing to non-existent directory fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        non_existent = self.temp_dir / "does_not_exist"
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=non_existent)
        self.assertIn("does not exist", str(ctx.exception).lower())

    def test_derived_missing_provenance_rejected(self):
        """Derived export directory missing .provenance.json sidecar is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = self.temp_dir / "derived"
        make_synthetic_derived_directory(camp, derived)
        (derived / "attempts.csv.provenance.json").unlink()

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("missing cryptographic provenance sidecar", str(ctx.exception).lower())

    def test_derived_tampered_csv_rejected(self):
        """Tampered derived CSV mismatching provenance sidecar hash is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = self.temp_dir / "derived"
        make_synthetic_derived_directory(camp, derived, tamper_csv=True)

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("digest mismatch", str(ctx.exception).lower())

    def test_derived_git_dirty_rejected(self):
        """Derived export whose provenance sidecar records git_dirty=true is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = self.temp_dir / "derived"
        make_synthetic_derived_directory(camp, derived, git_dirty=True)

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("dirty git tree", str(ctx.exception).lower())

    def test_derived_campaign_id_mismatch_rejected(self):
        """Derived export attempts.csv with different campaign_id is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = self.temp_dir / "derived"
        make_synthetic_derived_directory(camp, derived, mismatch_campaign_id=True)

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("does not match campaign", str(ctx.exception).lower())

    def test_non_canonical_scenario_rejected(self):
        """Slot containing non-canonical scenario is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        data["matrix_slots"][0]["scenario_id"] = "S99"
        mpath.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("non-canonical scenario", str(ctx.exception).lower())

    def test_non_canonical_browser_rejected(self):
        """Slot containing non-canonical browser is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        data["matrix_slots"][0]["browser"] = "safari"
        mpath.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("non-canonical browser", str(ctx.exception).lower())

    def test_attempt_simulation_flag_rejected(self):
        """Attempt inside slot declaring is_simulation=true is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        data["matrix_slots"][0]["attempts"][0]["is_simulation"] = True
        mpath.write_text(json.dumps(data), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("simulation attempts are strictly forbidden", str(ctx.exception).lower())

    def test_failed_attempt_without_preserved_record_rejected(self):
        """Retried slot missing preserved failure evidence file is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        # Remove failed_attempt_record.json for failed attempt
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        (camp / "trials" / fail_tid / "failed_attempt_record.json").unlink()

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("preserved failure evidence missing", str(ctx.exception).lower())

    def test_failed_attempt_record_falsely_claiming_valid_rejected(self):
        """Failed attempt record claiming COMPLETED / VALID_LIVE is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        frec_path = camp / "trials" / fail_tid / "failed_attempt_record.json"
        fdata = json.loads(frec_path.read_text(encoding="utf-8"))
        fdata["status"] = "COMPLETED"
        fdata["validity"] = "VALID_LIVE"
        frec_path.write_text(json.dumps(fdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("contradicts failure status", str(ctx.exception).lower())

    def test_failed_attempt_record_trial_id_mismatch_rejected(self):
        """Failed attempt record whose trial_id does not match manifest attempt is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        frec_path = camp / "trials" / fail_tid / "failed_attempt_record.json"
        fdata = json.loads(frec_path.read_text(encoding="utf-8"))
        fdata["trial_id"] = "trial-synth-mismatched-tid"
        frec_path.write_text(json.dumps(fdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("trial id mismatch", str(ctx.exception).lower())

    def test_failed_attempt_record_status_mismatch_rejected(self):
        """Failed attempt record whose status does not match manifest attempt is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        frec_path = camp / "trials" / fail_tid / "failed_attempt_record.json"
        fdata = json.loads(frec_path.read_text(encoding="utf-8"))
        fdata["status"] = "ABORTED"
        frec_path.write_text(json.dumps(fdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("status mismatch", str(ctx.exception).lower())

    def test_failed_attempt_record_validity_mismatch_rejected(self):
        """Failed attempt record whose validity does not match manifest attempt is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        frec_path = camp / "trials" / fail_tid / "failed_attempt_record.json"
        fdata = json.loads(frec_path.read_text(encoding="utf-8"))
        fdata["validity"] = "MEASUREMENT_FAILURE"
        frec_path.write_text(json.dumps(fdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("validity mismatch", str(ctx.exception).lower())

    def test_failed_attempt_record_execution_mode_mismatch_rejected(self):
        """Failed attempt record whose execution_mode does not match manifest attempt is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        frec_path = camp / "trials" / fail_tid / "failed_attempt_record.json"
        fdata = json.loads(frec_path.read_text(encoding="utf-8"))
        fdata["execution_mode"] = "SIMULATION"
        frec_path.write_text(json.dumps(fdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("execution mode mismatch", str(ctx.exception).lower())

    def test_failed_attempt_with_falsely_successful_result_json_rejected(self):
        """Failed attempt directory containing a falsely successful result.json is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        tdir = camp / "trials" / fail_tid

        # Plant a falsely successful result.json claiming 100% success
        false_success_result = {
            "schema_version": "1.0.0",
            "trial_id": fail_tid,
            "scenario_id": "S0",
            "execution_mode": "LIVE",
            "is_simulation": False,
            "browser": {"name": "firefox"},
            "capture_metadata": {"pcap_valid": True, "packet_count": 5},
            "network_observations": {"classification": "DIRECT_IPV6"},
            "cleanup_status": {"scenario_restored": True, "baseline_verified": True, "errors": []},
            "validity": "VALID_LIVE",
            "status": "COMPLETED"
        }
        (tdir / "result.json").write_text(json.dumps(false_success_result), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("falsely successful result.json", str(ctx.exception).lower())

    def test_failed_attempt_with_unrelated_result_json_rejected(self):
        """Failed attempt directory containing result.json from an unrelated trial is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        fail_tid = data["matrix_slots"][1]["attempts"][0]["trial_id"]
        tdir = camp / "trials" / fail_tid

        unrelated_result = {
            "schema_version": "1.0.0",
            "trial_id": "trial-synth-unrelated-999",
            "cleanup_status": {"scenario_restored": False, "errors": ["Mock error"]}
        }
        (tdir / "result.json").write_text(json.dumps(unrelated_result), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("unrelated result.json", str(ctx.exception).lower())

    def test_derived_attempts_csv_duplicate_trial_id_rejected(self):
        """attempts.csv containing duplicate trial IDs (even with matching row count) is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        # Read attempts.csv, duplicate first row and replace second row
        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[1]["trial_id"] = rows[0]["trial_id"]
        fieldnames = list(rows[0].keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        # Update provenance sha256 to isolate to ledger reconciliation check
        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("duplicate trial_id", str(ctx.exception).lower())

    def test_derived_attempts_csv_misclassified_attempt_rejected(self):
        """attempts.csv containing misclassified attempt status or validity is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20, include_retried_slot=True)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        # Find failed attempt row and misclassify its validity
        for r in rows:
            if r.get("validity_category") == "CLEANUP_FAILURE":
                r["validity_category"] = "MEASUREMENT_FAILURE"
                break
        fieldnames = list(rows[0].keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("validity mismatch", str(ctx.exception).lower())

    def test_derived_connection_attempts_missing_valid_live_trial_rejected(self):
        """connection_attempts.csv missing a valid live trial is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        conn_csv = derived / "connection_attempts.csv"
        with open(conn_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        omitted_tid = rows[0]["trial_id"]
        filtered_rows = [r for r in rows if r["trial_id"] != omitted_tid]
        fieldnames = list(rows[0].keys())
        with open(conn_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_rows)

        prov_file = derived / "connection_attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(conn_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("missing connection data", str(ctx.exception).lower())

    def test_derived_trial_timeline_missing_campaign_trial_rejected(self):
        """trial_timeline.csv missing events for a campaign trial is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        time_csv = derived / "trial_timeline.csv"
        with open(time_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        omitted_tid = rows[0]["trial_id"]
        filtered_rows = [r for r in rows if r["trial_id"] != omitted_tid]
        fieldnames = list(rows[0].keys())
        with open(time_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_rows)

        prov_file = derived / "trial_timeline.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(time_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("missing events", str(ctx.exception).lower())

    def test_pcap_with_truncated_packet_record_rejected(self):
        """PCAP with a truncated packet record header is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        pcap_file = camp / "trials" / first_tid / "capture.pcap"

        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        # 24-byte header + 8 bytes truncated record header
        corrupt_pcap = header + b"\x00" * 8
        pcap_file.write_bytes(corrupt_pcap)

        # Update result.json SHA to point to corrupt bytes so SHA check passes and record audit runs
        rpath = camp / "trials" / first_tid / "result.json"
        rdata = json.loads(rpath.read_text(encoding="utf-8"))
        new_sha = hashlib.sha256(corrupt_pcap).hexdigest()
        rdata["capture_metadata"]["pcap_sha256"] = new_sha
        rpath.write_text(json.dumps(rdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("pcap validation failed", str(ctx.exception).lower())
        self.assertIn("truncated packet record header", str(ctx.exception).lower())

    def test_pcap_with_impossible_packet_length_rejected(self):
        """PCAP declaring impossible captured packet length is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        pcap_file = camp / "trials" / first_tid / "capture.pcap"

        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        pkt_hdr = struct.pack("<IIII", 1729000000, 0, 300000, 300000)
        corrupt_pcap = header + pkt_hdr + b"\x00" * 100
        pcap_file.write_bytes(corrupt_pcap)

        rpath = camp / "trials" / first_tid / "result.json"
        rdata = json.loads(rpath.read_text(encoding="utf-8"))
        new_sha = hashlib.sha256(corrupt_pcap).hexdigest()
        rdata["capture_metadata"]["pcap_sha256"] = new_sha
        rpath.write_text(json.dumps(rdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("pcap validation failed", str(ctx.exception).lower())
        self.assertIn("impossible packet captured length", str(ctx.exception).lower())

    def test_archive_device_node_rejected(self):
        """Archive containing special device node is rejected."""
        arch_path = self.temp_dir / "device_node.tar.gz"
        with tarfile.open(arch_path, "w:gz") as tar:
            ti = tarfile.TarInfo(name="dev/zero")
            ti.type = tarfile.CHRTYPE
            tar.addfile(ti)

        sha = verify_partner_handover.sha256_file(arch_path)
        (self.temp_dir / "device_node.tar.gz.sha256").write_text(f"{sha}  device_node.tar.gz\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_archive(arch_path)
        self.assertIn("special device node", str(ctx.exception).lower())

    def test_derived_attempts_csv_malformed_slot_index_rejected(self):
        """attempts.csv with non-integer slot_index (e.g. float or string) fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[0]["slot_index"] = "1.5"
        fieldnames = list(rows[0].keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("must be a valid integer", str(ctx.exception).lower())

    def test_derived_attempts_csv_malformed_repetition_rejected(self):
        """attempts.csv with out-of-range repetition fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[0]["repetition"] = "0"
        fieldnames = list(rows[0].keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("below minimum", str(ctx.exception).lower())

    def test_derived_attempts_csv_malformed_attempt_number_rejected(self):
        """attempts.csv with invalid attempt_number fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[0]["attempt_number"] = "-1"
        fieldnames = list(rows[0].keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("below minimum", str(ctx.exception).lower())

    def test_derived_attempts_csv_tampered_attempt_id_rejected(self):
        """attempts.csv with duplicate attempt_id fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[1]["attempt_id"] = rows[0]["attempt_id"]
        fieldnames = list(rows[0].keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("duplicate attempt_id", str(ctx.exception).lower())

    def test_derived_attempts_csv_omitted_manifest_attempt_rejected(self):
        """attempts.csv missing an attempt that exists in manifest fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        att_csv = derived / "attempts.csv"
        with open(att_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        # Omit the first row
        omitted = rows.pop(0)
        fieldnames = list(omitted.keys())
        with open(att_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(att_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("row count mismatch", str(ctx.exception).lower())

    def test_derived_connection_attempts_malformed_port_rejected(self):
        """connection_attempts.csv with invalid port fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        conn_csv = derived / "connection_attempts.csv"
        with open(conn_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[0]["client_port"] = "70000"
        fieldnames = list(rows[0].keys())
        with open(conn_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "connection_attempts.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(conn_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("exceeds maximum", str(ctx.exception).lower())

    def test_derived_timeline_malformed_event_index_rejected(self):
        """trial_timeline.csv with invalid event_index fails closed."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")

        time_csv = derived / "trial_timeline.csv"
        with open(time_csv, "r", encoding="utf-8") as rf:
            rows = list(csv.DictReader(rf))
        rows[0]["event_index"] = "abc"
        fieldnames = list(rows[0].keys())
        with open(time_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        prov_file = derived / "trial_timeline.csv.provenance.json"
        pdata = json.loads(prov_file.read_text(encoding="utf-8"))
        pdata["sha256"] = verify_partner_handover.sha256_file(time_csv)
        prov_file.write_text(json.dumps(pdata), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)
        self.assertIn("must be a valid integer", str(ctx.exception).lower())

    def test_campaign_and_derived_with_interrupted_attempt_accepted(self):
        """Campaign and derived ledgers with an INTERRUPTED attempt and subsequent retry verify cleanly."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        mdata = json.loads(mpath.read_text(encoding="utf-8"))

        # In slot 0, insert an INTERRUPTED attempt prior to the successful attempt
        slot0 = mdata["matrix_slots"][0]
        succ_att = slot0["attempts"][0]
        succ_att["attempt_number"] = 2

        interrupted_tid = f"trial-synth-{mdata['campaign_id']}-interrupted-0001-01"
        int_tdir = camp / "trials" / interrupted_tid
        int_tdir.mkdir(parents=True, exist_ok=True)

        int_record = {
            "attempt_number": 1,
            "trial_id": interrupted_tid,
            "execution_mode": "LIVE",
            "is_simulation": False,
            "timestamps": {
                "start_time": "2026-11-18T00:00:00.000000+00:00",
                "end_time": "2026-11-18T00:00:02.000000+00:00",
                "duration_ms": 2000.0
            },
            "status": "INTERRUPTED",
            "validity": "INTERRUPTED",
            "evidence_paths": {"trial_dir": str(int_tdir)},
            "capture_metadata": {},
            "cleanup_status": {
                "scenario_restored": True,
                "baseline_verified": True,
                "errors": []
            },
            "error_message": "Campaign attempt interrupted by signal 2 (SIGINT)",
            "interruption": {
                "signal_number": 2,
                "signal_name": "SIGINT",
                "interrupted_at": "2026-11-18T00:00:02.000000+00:00",
                "error_details": "Campaign attempt interrupted by signal 2"
            }
        }
        (int_tdir / "failed_attempt_record.json").write_text(
            json.dumps(int_record, indent=2), encoding="utf-8"
        )

        slot0["attempts"] = [int_record, succ_att]
        mdata["summary"]["total_attempts"] += 1
        mdata["summary"]["failed_attempts"] += 1
        mpath.write_text(json.dumps(mdata, indent=2), encoding="utf-8")

        derived = make_synthetic_derived_directory(camp, self.temp_dir / "derived")
        verify_partner_handover.verify_partner_campaign_directory(camp, derived_dir=derived)

    def test_browser_version_mismatch_rejected(self):
        """Trial result.json recording unpinned browser build is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["browser"]["version"] = "Google Chrome 155.0.0.0"
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("browser version mismatch", str(ctx.exception).lower())

    def test_require_partner_info_enforced(self):
        """--require-partner-info fails on placeholder metadata and passes when populated."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"

        # Missing or default placeholder info fails closed
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, require_partner_info=True)
        self.assertIn("partner_institution", str(ctx.exception).lower())

        # Populated valid partner metadata passes
        mdata = json.loads(mpath.read_text(encoding="utf-8"))
        mdata["partner_info"] = {
            "partner_institution": "University Partner Laboratory",
            "operator_id": "REPL-OP-01"
        }
        mpath.write_text(json.dumps(mdata, indent=2), encoding="utf-8")

        res = verify_partner_handover.verify_partner_campaign_directory(camp, require_partner_info=True)
        self.assertEqual(res["status"], "PASS")

    def test_require_checksum_manifest_missing_rejected(self):
        """--require-checksum-manifest fails closed when partner_evidence.sha256 is missing."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, require_checksum_manifest=True)
        self.assertIn("missing mandatory checksum manifest", str(ctx.exception).lower())

    def test_require_checksum_manifest_incomplete_coverage_rejected(self):
        """--require-checksum-manifest fails closed when partner_evidence.sha256 omits required files."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        sha_f = camp / "partner_evidence.sha256"
        # Only list campaign_manifest.json, omitting trial evidence
        m_hash = hashlib.sha256((camp / "campaign_manifest.json").read_bytes()).hexdigest()
        sha_f.write_text(f"{m_hash}  campaign_manifest.json\n", encoding="utf-8")

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp, require_checksum_manifest=True)
        self.assertIn("incomplete", str(ctx.exception).lower())

    def test_require_checksum_manifest_full_coverage_passes(self):
        """--require-checksum-manifest passes when partner_evidence.sha256 covers all artifacts."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        sha_f = camp / "partner_evidence.sha256"
        lines = []
        for f in sorted(camp.rglob("*")):
            if f.is_file() and f.name != "partner_evidence.sha256":
                rel = f.relative_to(camp).as_posix()
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                lines.append(f"{h}  {rel}")
        sha_f.write_text("\n".join(lines) + "\n", encoding="utf-8")

        res = verify_partner_handover.verify_partner_campaign_directory(camp, require_checksum_manifest=True)
        self.assertEqual(res["status"], "PASS")
        self.assertGreaterEqual(res["checksum_files_checked"], 561)

    def test_pcap_semantic_contradiction_winning_family_rejected(self):
        """result.json claiming IPv6 when PCAP dissection indicates IPv4 is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["http_outcome"] = {"winning_address_family": "IPv6", "status_code": 200}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv4", "status_code": 200},
            "ipv4": {}, "ipv6": {}, "metrics": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("winning family semantic contradiction", str(ctx.exception).lower())

    def test_pcap_semantic_contradiction_http_status_rejected(self):
        """result.json claiming HTTP 200 when PCAP shows HTTP 500 is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["http_outcome"] = {"winning_address_family": "IPv6", "status_code": 200}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv6", "status_code": 500},
            "ipv4": {}, "ipv6": {}, "metrics": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("http status code contradiction", str(ctx.exception).lower())

    def test_pcap_semantic_timing_tolerance_rejected(self):
        """result.json timing deviating from PCAP dissection by >2.0ms is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["metrics"] = {"t_connect_ms": 28.5, "t_setup_total_ms": 35.0}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "metrics": {"t_connect_ms": 25.0, "t_setup_total_ms": 35.0},
            "main_http_flow": {}, "ipv4": {}, "ipv6": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("t_connect_ms discrepancy", str(ctx.exception).lower())

    def test_pcap_semantic_timing_tolerance_boundary_strictly_below(self):
        """Timing tolerance boundary test: delta = 1.99ms (< 2.0ms) is ACCEPTED."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["metrics"] = {"t_connect_ms": 26.99, "t_setup_total_ms": 35.0}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "metrics": {"t_connect_ms": 25.0, "t_setup_total_ms": 35.0},
            "main_http_flow": {}, "ipv4": {}, "ipv6": {}
        }

        # Delta is 1.99ms <= 2.0ms -> should pass verification
        summary = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(summary["valid_trials_count"], 280)
        self.assertEqual(summary["status"], "PASS")

    def test_pcap_semantic_timing_tolerance_boundary_exact(self):
        """Timing tolerance boundary test: delta = 2.00ms (== 2.0ms) is ACCEPTED."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["metrics"] = {"t_connect_ms": 27.00, "t_setup_total_ms": 35.0}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "metrics": {"t_connect_ms": 25.0, "t_setup_total_ms": 35.0},
            "main_http_flow": {}, "ipv4": {}, "ipv6": {}
        }

        # Delta is exactly 2.00ms <= 2.0ms -> should pass verification
        summary = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(summary["valid_trials_count"], 280)
        self.assertEqual(summary["status"], "PASS")

    def test_pcap_semantic_timing_tolerance_boundary_strictly_above(self):
        """Timing tolerance boundary test: delta = 2.01ms (> 2.0ms) is REJECTED."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        first_tid = data["matrix_slots"][0]["attempts"][0]["trial_id"]
        res_file = camp / "trials" / first_tid / "result.json"
        pcap_file = camp / "trials" / first_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["metrics"] = {"t_connect_ms": 27.01, "t_setup_total_ms": 35.0}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "metrics": {"t_connect_ms": 25.0, "t_setup_total_ms": 35.0},
            "main_http_flow": {}, "ipv4": {}, "ipv6": {}
        }

        # Delta is 2.01ms > 2.0ms -> must raise VerificationError
        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("t_connect_ms discrepancy", str(ctx.exception).lower())
        self.assertIn("diff > 2.0ms tolerance", str(ctx.exception).lower())

    def test_s1_impairment_violation_in_pcap_rejected(self):
        """S1 trial where PCAP shows completed IPv6 TCP handshake is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s1_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S1")
        s1_tid = s1_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s1_tid / "result.json"
        pcap_file = camp / "trials" / s1_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "ipv6": {"tcp_handshake_completed": True},
            "main_http_flow": {}, "metrics": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s1 impairment violation", str(ctx.exception).lower())

    def test_s2_impairment_violation_in_pcap_rejected(self):
        """S2 trial where PCAP shows completed IPv6 TCP handshake is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s2_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S2")
        s2_tid = s2_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s2_tid / "result.json"
        pcap_file = camp / "trials" / s2_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "ipv6": {"tcp_handshake_completed": True},
            "main_http_flow": {}, "metrics": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s2 impairment violation", str(ctx.exception).lower())

    def test_s6_impairment_violation_in_pcap_rejected(self):
        """S6 trial where AAAA response was not delayed relative to A is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s6_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S6")
        s6_tid = s6_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s6_tid / "result.json"
        pcap_file = camp / "trials" / s6_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "dns_metrics": {"dns_latency_a_ms": 20.0, "dns_latency_aaaa_ms": 25.0},
            "main_http_flow": {}, "metrics": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s6 impairment violation", str(ctx.exception).lower())

    def test_s0_valid_ipv4_winner_accepted(self):
        """
        Scientific Correction (Issue B):
        S0 trial where browser genuine observable result selects IPv4 on healthy baseline
        is accepted as a valid observation, NOT rejected as an experimental invalidity.
        """
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s0_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S0")
        s0_tid = s0_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s0_tid / "result.json"
        pcap_file = camp / "trials" / s0_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))
        rdata["http_outcome"] = {"winning_address_family": "IPv4", "status_code": 200}
        rdata["metrics"] = {"t_connect_ms": 20.0, "t_setup_total_ms": 25.0}
        res_file.write_text(json.dumps(rdata, indent=2), encoding="utf-8")

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv4", "status_code": 200},
            "metrics": {"t_connect_ms": 20.0, "t_setup_total_ms": 25.0},
            "ipv4": {"tcp_handshake_completed": True},
            "ipv6": {"tcp_handshake_completed": False}
        }

        # Must verify without error (valid live observation)
        summary = verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertEqual(summary["valid_trials_count"], 280)
        self.assertEqual(summary["status"], "PASS")

    def test_s0_impairment_violation_excessive_latency_rejected(self):
        """S0 trial where PCAP shows t_connect_ms > 100ms on 20ms link is rejected as physical experiment violation."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s0_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S0")
        s0_tid = s0_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s0_tid / "result.json"
        pcap_file = camp / "trials" / s0_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv6", "status_code": 200},
            "metrics": {"t_connect_ms": 150.0, "t_setup_total_ms": 155.0},
            "ipv4": {}, "ipv6": {"tcp_handshake_completed": True}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s0 impairment violation", str(ctx.exception).lower())

    def test_s3_impairment_violation_in_pcap_rejected(self):
        """S3 trial where PCAP shows IPv6 connect latency < 100ms on 150ms link is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s3_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S3")
        s3_tid = s3_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s3_tid / "result.json"
        pcap_file = camp / "trials" / s3_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv6", "status_code": 200},
            "metrics": {"t_connect_ms": 25.0, "t_setup_total_ms": 30.0},
            "ipv4": {}, "ipv6": {"tcp_handshake_completed": True}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s3 impairment violation", str(ctx.exception).lower())

    def test_s4_impairment_violation_in_pcap_rejected(self):
        """S4 trial where PCAP shows IPv4 fallback connect latency > 150ms on 20ms IPv4 link is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s4_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S4")
        s4_tid = s4_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s4_tid / "result.json"
        pcap_file = camp / "trials" / s4_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv4", "status_code": 200},
            "metrics": {"t_connect_ms": 200.0, "t_setup_total_ms": 450.0},
            "ipv4": {"tcp_handshake_completed": True}, "ipv6": {}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s4 impairment violation", str(ctx.exception).lower())

    def test_s5_impairment_violation_in_pcap_rejected(self):
        """S5 trial claiming valid HTTP 200 but neither IPv6 nor IPv4 handshake completed is rejected."""
        camp = make_synthetic_campaign(self.temp_dir, repetitions=20)
        mpath = camp / "campaign_manifest.json"
        data = json.loads(mpath.read_text(encoding="utf-8"))
        s5_slot = next(s for s in data["matrix_slots"] if s["scenario_id"] == "S5")
        s5_tid = s5_slot["attempts"][0]["trial_id"]
        res_file = camp / "trials" / s5_tid / "result.json"
        pcap_file = camp / "trials" / s5_tid / "capture.pcap"
        rdata = json.loads(res_file.read_text(encoding="utf-8"))

        pcap_sha = rdata["capture_metadata"]["pcap_sha256"]
        verify_partner_handover._DISSECTION_CACHE[(str(pcap_file.resolve()), pcap_sha)] = {
            "main_http_flow": {"family": "IPv6", "status_code": 200},
            "http_status_code": 200,
            "metrics": {"t_connect_ms": 25.0, "t_setup_total_ms": 30.0},
            "ipv4": {"tcp_handshake_completed": False},
            "ipv6": {"tcp_handshake_completed": False}
        }

        with self.assertRaises(verify_partner_handover.VerificationError) as ctx:
            verify_partner_handover.verify_partner_campaign_directory(camp)
        self.assertIn("s5 impairment violation", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
