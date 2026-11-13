#!/usr/bin/env python3
"""
Regression test suite for lab/export_campaign_evidence.py.

Verifies:
T01: Attempts Count & Reconciliation (exactly 282 rows: 280 live + 2 cleanup failures)
T02: Attempts Header & Column Schema (Metric Contract §4.1 exact 20 columns)
T03: Cleanup Failures Null Contract (Rule R3/R4 null metric preservation)
T04: Connection Attempts Row Count (exactly 765 target connection attempts)
T05: S5 Flow Dissection (Finding C4-02: exactly 95 streams across 40 S5 PCAPs)
T06: Connection Attempts 5-Tuple Schema & Outcome Enums
T07: Trial Timeline Event Provenance (Amendment A9: HARNESS, PCAP, BROWSER_TELEMETRY)
T08: Determinism & Byte Reproducibility (Amendment A13 byte-identical SHA-256)
T09: Sibling Provenance Sidecars (Amendment A13 <csv>.provenance.json)
T10: Fail-Closed on Corrupt Manifest or Schema (Rule R5)
"""

import csv
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Optional
import unittest

from lab.export_campaign_evidence import (
    EventSource,
    export_trial_timeline,
    validate_campaign_timeline,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN_ROOT = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
DERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"


class TestExportCampaignEvidence(unittest.TestCase):
    """Test suite for evidence export engine."""

    @classmethod
    def setUpClass(cls):
        """Ensure campaign evidence exports are generated before testing."""
        attempts_csv = DERIVED_DIR / "attempts.csv"
        conn_csv = DERIVED_DIR / "connection_attempts.csv"
        s5_csv = DERIVED_DIR / "s5_flow_dissection.csv"
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"

        if not (attempts_csv.is_file() and conn_csv.is_file() and s5_csv.is_file() and timeline_csv.is_file()):
            cmd = [
                "python3",
                str(REPO_ROOT / "lab" / "export_campaign_evidence.py"),
                "--campaign-dir", str(CAMPAIGN_ROOT),
                "--output-dir", str(DERIVED_DIR),
            ]
            subprocess.run(cmd, check=True, cwd=str(REPO_ROOT))

    # --------------------------------------------------------------------------
    # T01: Attempts Count & Reconciliation (282 rows)
    # --------------------------------------------------------------------------
    def test_export_attempts_row_count_and_reconciliation(self):
        """C2-01: attempts.csv must contain exactly 282 rows (280 live + 2 cleanup failures)."""
        attempts_csv = DERIVED_DIR / "attempts.csv"
        self.assertTrue(attempts_csv.is_file(), f"Missing export: {attempts_csv}")

        with open(attempts_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 282, f"Expected exactly 282 rows in attempts.csv, got {len(rows)}")

        valid_live = [r for r in rows if r["validity_category"] == "VALID_LIVE"]
        cleanup_failures = [r for r in rows if r["validity_category"] == "CLEANUP_FAILURE"]

        self.assertEqual(len(valid_live), 280, f"Expected 280 VALID_LIVE rows, got {len(valid_live)}")
        self.assertEqual(len(cleanup_failures), 2, f"Expected 2 CLEANUP_FAILURE rows, got {len(cleanup_failures)}")

    # --------------------------------------------------------------------------
    # T02: Attempts Header & Column Schema
    # --------------------------------------------------------------------------
    def test_export_attempts_header_and_column_schema(self):
        """Metric Contract §4.1: attempts.csv must match the exact 20-column header."""
        expected_header = [
            "attempt_id", "slot_id", "slot_index", "campaign_id", "scenario_id",
            "browser", "repetition", "attempt_number", "trial_id", "status",
            "validity_category", "classification", "http_status", "t_connect_ms",
            "t_setup_total_ms", "syn_to_synack_ms", "cad_ms", "pcap_sha256",
            "start_time", "end_time"
        ]
        attempts_csv = DERIVED_DIR / "attempts.csv"
        with open(attempts_csv, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)

        self.assertEqual(header, expected_header, "attempts.csv header does not match metric contract §4.1")

    # --------------------------------------------------------------------------
    # T03: Cleanup Failures Null Contract
    # --------------------------------------------------------------------------
    def test_export_attempts_cleanup_failures_null_contract(self):
        """Rule R4: Cleanup failure rows must preserve null metrics without zero-coercion."""
        attempts_csv = DERIVED_DIR / "attempts.csv"
        with open(attempts_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            failures = [r for r in reader if r["validity_category"] == "CLEANUP_FAILURE"]

        expected_failure_trials = {
            "trial-20261029205442-aba6193c",  # Firefox S0 rep01 att1
            "trial-20261029210226-944fcfaa"   # Chrome S6 rep01 att1
        }
        actual_failure_trials = {r["trial_id"] for r in failures}
        self.assertEqual(actual_failure_trials, expected_failure_trials)

        for row in failures:
            self.assertEqual(row["status"], "FAILED")
            self.assertEqual(row["validity_category"], "CLEANUP_FAILURE")
            self.assertEqual(row["http_status"], "")
            self.assertEqual(row["t_connect_ms"], "")
            self.assertEqual(row["t_setup_total_ms"], "")
            self.assertEqual(row["syn_to_synack_ms"], "")
            self.assertEqual(row["cad_ms"], "")
            self.assertEqual(row["pcap_sha256"], "")

    # --------------------------------------------------------------------------
    # T04: Connection Attempts Row Count (765 target connections)
    # --------------------------------------------------------------------------
    def test_export_connection_attempts_row_count(self):
        """Amendment A1: connection_attempts.csv must record exactly 765 target connections."""
        conn_csv = DERIVED_DIR / "connection_attempts.csv"
        self.assertTrue(conn_csv.is_file(), f"Missing export: {conn_csv}")

        with open(conn_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        self.assertEqual(len(rows), 765, f"Expected 765 connection attempts, got {len(rows)}")

    # --------------------------------------------------------------------------
    # T05: S5 Flow Dissection (95 target streams)
    # --------------------------------------------------------------------------
    def test_export_connection_attempts_s5_flow_dissection(self):
        """C4-02: Scenario S5 across 40 PCAPs must dissect to exactly 95 target streams."""
        conn_csv = DERIVED_DIR / "connection_attempts.csv"
        attempts_csv = DERIVED_DIR / "attempts.csv"
        s5_csv = DERIVED_DIR / "s5_flow_dissection.csv"

        self.assertTrue(s5_csv.is_file(), f"Missing export: {s5_csv}")

        with open(attempts_csv, "r", encoding="utf-8") as f:
            s5_trials = {r["trial_id"] for r in csv.DictReader(f) if r["scenario_id"] == "S5"}

        self.assertEqual(len(s5_trials), 40, f"Expected 40 S5 trials, found {len(s5_trials)}")

        with open(conn_csv, "r", encoding="utf-8") as f:
            s5_conn_rows = [r for r in csv.DictReader(f) if r["trial_id"] in s5_trials]

        self.assertEqual(len(s5_conn_rows), 95, f"Expected 95 S5 connection rows, got {len(s5_conn_rows)}")

        primary_rows = [r for r in s5_conn_rows if r["is_primary"] in ("True", "true", "1", "TRUE")]
        self.assertEqual(len(primary_rows), 40, f"Each of 40 S5 trials must have exactly 1 primary flow, got {len(primary_rows)}")

        # Verify s5_flow_dissection.csv breakdown
        with open(s5_csv, "r", encoding="utf-8") as f:
            s5_dissection_rows = list(csv.DictReader(f))

        self.assertEqual(len(s5_dissection_rows), 95, f"Expected 95 rows in s5_flow_dissection.csv, got {len(s5_dissection_rows)}")

        primary_count = sum(1 for r in s5_dissection_rows if r["flow_category"] == "PRIMARY")
        ancillary_count = sum(1 for r in s5_dissection_rows if r["flow_category"] == "ANCILLARY")
        speculative_count = sum(1 for r in s5_dissection_rows if r["flow_category"] == "SPECULATIVE")
        unmatched_count = sum(1 for r in s5_dissection_rows if r["flow_category"] == "UNMATCHED")

        self.assertEqual(primary_count, 40)
        self.assertEqual(ancillary_count, 12)
        self.assertEqual(speculative_count, 6)
        self.assertEqual(unmatched_count, 37)

    # --------------------------------------------------------------------------
    # T06: Connection Attempts Schema & Outcome Enums
    # --------------------------------------------------------------------------
    def test_export_connection_attempts_5tuple_and_stream_id(self):
        """Metric Contract §4.2: Enforce 5-tuple schema and allowed outcome states."""
        expected_header = [
            "trial_id", "pcap_sha256", "tcp_stream", "family", "client_ip",
            "client_port", "server_ip", "server_port", "syn_time", "synack_time",
            "final_ack_time", "rst_time", "offset_from_first_syn_ms", "outcome",
            "is_primary", "retransmitted_syn_count"
        ]
        allowed_outcomes = {
            "ESTABLISHED_PRIMARY", "ESTABLISHED_ANCILLARY", "RESET",
            "NO_SYNACK_TIMEOUT", "ABANDONED", "INDETERMINATE"
        }
        conn_csv = DERIVED_DIR / "connection_attempts.csv"
        with open(conn_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self.assertEqual(reader.fieldnames, expected_header)
            for i, row in enumerate(reader):
                self.assertIn(row["outcome"], allowed_outcomes, f"Invalid outcome at row {i}: {row['outcome']}")
                self.assertIn(row["family"], ("IPv4", "IPv6"))
                self.assertTrue(row["tcp_stream"].isdigit(), f"tcp_stream must be integer at row {i}")

    # --------------------------------------------------------------------------
    # T07: Trial Timeline Event Provenance
    # --------------------------------------------------------------------------
    def test_export_trial_timeline_event_provenance(self):
        """
        Amendment A9 & Rule R5: trial_timeline.csv full campaign validation across all rows.
        Replaces 500-row spot check with complete campaign validation:
        1. All 280 authoritative valid trial IDs represented.
        2. No valid trial is missing from the timeline.
        3. Every valid trial has HARNESS, PCAP and BROWSER_TELEMETRY events.
        4. Every timeline row has a valid event source enum.
        5. Every timeline row has a valid numeric timestamp.
        6. No event has an invalid or unknown trial ID.
        7. Event indexes are deterministic and chronological within each trial.
        8. The valid-trial and exclusion event counts reconcile with the total.
        """
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        self.assertTrue(timeline_csv.is_file(), f"Missing export: {timeline_csv}")

        expected_header = [
            "trial_id", "event_index", "event_timestamp_epoch", "event_source",
            "event_type", "address_family", "tcp_stream", "frame_number",
            "details", "pcap_sha256", "source_path"
        ]
        allowed_sources = {"HARNESS", "PCAP", "BROWSER_TELEMETRY"}
        with open(timeline_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            self.assertEqual(reader.fieldnames, expected_header)
            rows = list(reader)

        manifest_file = CAMPAIGN_ROOT / "campaign_manifest.json"
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # 1 & 2. Authoritative valid live trials from manifest
        valid_trial_ids = set()
        exclusion_trial_ids = set()
        all_manifest_trial_ids = set()

        for slot in manifest.get("matrix_slots", []):
            for att in slot.get("attempts", []):
                tid = att["trial_id"]
                all_manifest_trial_ids.add(tid)
                st = att.get("status")
                val = att.get("validity")
                if st == "COMPLETED" and val == "VALID_LIVE":
                    valid_trial_ids.add(tid)
                elif val == "CLEANUP_FAILURE":
                    exclusion_trial_ids.add(tid)

        self.assertEqual(len(valid_trial_ids), 280, f"Expected 280 valid trial IDs, got {len(valid_trial_ids)}")
        self.assertEqual(len(exclusion_trial_ids), 2, f"Expected 2 exclusion trial IDs, got {len(exclusion_trial_ids)}")

        # Group timeline rows by trial
        rows_by_trial: dict = {}
        for idx, row in enumerate(rows):
            tid = row["trial_id"]
            # 6. No event has an invalid or unknown trial ID
            self.assertIn(tid, all_manifest_trial_ids, f"Row {idx} has unknown trial_id {tid}")
            rows_by_trial.setdefault(tid, []).append(row)

            # 4. Valid event source
            self.assertIn(row["event_source"], allowed_sources, f"Invalid event_source at row {idx}: {row['event_source']}")

            # 5. Valid numeric timestamp
            try:
                ts = float(row["event_timestamp_epoch"])
                self.assertTrue(math.isfinite(ts), f"Non-finite timestamp at row {idx}")
            except (ValueError, TypeError):
                self.fail(f"Invalid timestamp at row {idx}: {row['event_timestamp_epoch']}")

            # Event type must be non-empty
            self.assertTrue(bool(row["event_type"].strip()), f"Empty event_type at row {idx}")

            # PCAP events must have valid sha256
            if row["event_source"] == "PCAP":
                self.assertTrue(bool(re.fullmatch(r"[0-9a-fA-F]{64}", row["pcap_sha256"])), f"Invalid pcap_sha256 at row {idx}")

        # 1. All 280 authoritative valid trial IDs are represented
        # 2. No valid trial is missing from the timeline
        self.assertEqual(set(rows_by_trial.keys()) & valid_trial_ids, valid_trial_ids)
        self.assertEqual(len(rows_by_trial), 282)

        # 3. Every valid trial has HARNESS, PCAP, and BROWSER_TELEMETRY events
        for tid in valid_trial_ids:
            trial_sources = {r["event_source"] for r in rows_by_trial[tid]}
            self.assertEqual(
                trial_sources,
                allowed_sources,
                f"Valid trial {tid} missing mandatory event sources: {allowed_sources - trial_sources}",
            )

        # 7. Event indexes are deterministic and chronological within each trial
        for tid, t_rows in rows_by_trial.items():
            prev_ts = -1.0
            for seq, r in enumerate(t_rows, start=1):
                self.assertEqual(int(r["event_index"]), seq, f"Trial {tid} non-consecutive event_index at {seq}")
                cur_ts = float(r["event_timestamp_epoch"])
                self.assertGreaterEqual(cur_ts, prev_ts, f"Trial {tid} chronology inversion at index {seq}")
                prev_ts = cur_ts

        # 8. Valid-trial and exclusion event counts reconcile with total
        valid_trial_events = sum(len(rows_by_trial[tid]) for tid in valid_trial_ids)
        exclusion_events = sum(len(rows_by_trial[tid]) for tid in exclusion_trial_ids)
        self.assertEqual(valid_trial_events, 28326, f"Valid trial events {valid_trial_events} != 28326")
        self.assertEqual(exclusion_events, 4, f"Exclusion events {exclusion_events} != 4")
        self.assertEqual(len(rows), 28330, f"Total timeline rows {len(rows)} != 28330")
        self.assertEqual(valid_trial_events + exclusion_events, len(rows))

    def _create_synthetic_trial(
        self,
        tmp_path: Path,
        browser: str = "google-chrome",
        status: str = "COMPLETED",
        validity: str = "VALID_LIVE",
        include_result: bool = True,
        result_content: Optional[str] = None,
        include_pcap: bool = True,
        include_telemetry: bool = True,
        include_failed_record: bool = True,
    ):
        """Helper to create minimal synthetic trial fixture without mutating historical data."""
        campaign_dir = tmp_path / "campaign"
        trials_dir = campaign_dir / "trials"
        trial_id = "trial-synth-001"
        tdir = trials_dir / trial_id
        tdir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "schema_version": "1.0.0",
            "campaign_id": "ps028-synth-test",
            "matrix_slots": [
                {
                    "slot_id": "slot-001",
                    "slot_index": 1,
                    "scenario_id": "S0",
                    "browser": browser,
                    "repetition": 1,
                    "status": status,
                    "attempts": [
                        {
                            "attempt_number": 1,
                            "trial_id": trial_id,
                            "status": status,
                            "validity": validity,
                        }
                    ],
                }
            ],
        }
        manifest_file = campaign_dir / "campaign_manifest.json"
        manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

        if validity == "VALID_LIVE":
            if include_result:
                rfile = tdir / "result.json"
                if result_content is not None:
                    rfile.write_text(result_content, encoding="utf-8")
                else:
                    rdata = {
                        "schema_version": "1.0.0",
                        "trial_id": trial_id,
                        "browser": {"name": browser},
                        "timestamps": {
                            "start_time": "2026-10-29T20:54:25.657889+00:00",
                            "scenario_applied_time": "2026-10-29T20:54:30.654577+00:00",
                            "capture_start_time": "2026-10-29T20:54:30.654591+00:00",
                            "browser_start_time": "2026-10-29T20:54:30.915968+00:00",
                            "browser_end_time": "2026-10-29T20:54:32.346343+00:00",
                            "capture_stop_time": "2026-10-29T20:54:33.222140+00:00",
                            "baseline_restored_time": "2026-10-29T20:54:33.398354+00:00",
                            "end_time": "2026-10-29T20:54:37.871666+00:00",
                        },
                    }
                    rfile.write_text(json.dumps(rdata), encoding="utf-8")

            if include_pcap:
                (tdir / "capture.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)

            if include_telemetry:
                if browser == "google-chrome":
                    netlog = {
                        "constants": {"timeTickOffset": 1793307270000, "logEventTypes": {"URL_REQUEST_START_JOB": 1}},
                        "events": [{"type": 1, "time": 100, "phase": 1}],
                    }
                    (tdir / "netlog.json").write_text(json.dumps(netlog), encoding="utf-8")
                elif browser == "firefox":
                    log_text = "2026-10-29 20:59:30.209532 UTC - nsHttpHandler::Init\n"
                    (tdir / "browser_telemetry.log").write_text(log_text, encoding="utf-8")
        elif validity == "CLEANUP_FAILURE":
            if include_failed_record:
                failed_data = {
                    "attempt_number": 1,
                    "trial_id": trial_id,
                    "status": "FAILED",
                    "validity": "CLEANUP_FAILURE",
                    "timestamps": {
                        "start_time": "2026-10-29T20:54:42.092344+00:00",
                        "end_time": "2026-10-29T20:54:46.246842+00:00",
                    },
                }
                (tdir / "failed_attempt_record.json").write_text(json.dumps(failed_data), encoding="utf-8")

        return campaign_dir, trial_id, tdir, manifest_file

    def test_timeline_fail_closed_missing_result_json(self):
        """Requirement 9: Missing valid trial result.json causes explicit failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(tmp, include_result=False)
            dissections_cache = {tid: {"dns_transactions": [{"query_time": 1793307271.0, "query_frame": 1, "qname": "test.he.test", "qtype": "A", "transport": "UDP"}], "tcp_streams": {}}}
            with self.assertRaises(FileNotFoundError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out", dissections_cache=dissections_cache)
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("result.json", str(ctx.exception))

    def test_timeline_fail_closed_missing_capture_pcap(self):
        """Requirement 10: Missing valid trial capture.pcap causes explicit failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(tmp, include_pcap=False)
            with self.assertRaises(FileNotFoundError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out")
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("capture.pcap", str(ctx.exception))

    def test_timeline_fail_closed_missing_cleanup_failure_record(self):
        """Requirement 11: Missing required cleanup-failure record causes explicit failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(
                tmp, status="FAILED", validity="CLEANUP_FAILURE", include_failed_record=False
            )
            with self.assertRaises(FileNotFoundError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out")
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("failed_attempt_record.json", str(ctx.exception))

    def test_timeline_fail_closed_invalid_result_json(self):
        """Requirement 12: Invalid JSON in a mandatory result file causes explicit failure."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(
                tmp, include_result=True, result_content="{bad_json_not_closed"
            )
            with self.assertRaises(ValueError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out")
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("result.json", str(ctx.exception))

    def test_timeline_fail_closed_missing_browser_telemetry(self):
        """Requirement 13: Missing browser telemetry input causes explicit failure rather than silent omission."""
        # Case A: Chrome missing netlog.json
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(
                tmp, browser="google-chrome", include_telemetry=False
            )
            dissections_cache = {tid: {"dns_transactions": [{"query_time": 1793307271.0, "query_frame": 1, "qname": "test.he.test", "qtype": "A", "transport": "UDP"}], "tcp_streams": {}}}
            with self.assertRaises(FileNotFoundError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out", dissections_cache=dissections_cache)
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("netlog.json", str(ctx.exception))

        # Case B: Firefox missing browser_telemetry.log
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(
                tmp, browser="firefox", include_telemetry=False
            )
            dissections_cache = {tid: {"dns_transactions": [{"query_time": 1793307271.0, "query_frame": 1, "qname": "test.he.test", "qtype": "A", "transport": "UDP"}], "tcp_streams": {}}}
            with self.assertRaises(FileNotFoundError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out", dissections_cache=dissections_cache)
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("browser_telemetry.log", str(ctx.exception))

    def test_timeline_fail_closed_missing_event_source_coverage(self):
        """Requirement 3 & fail-closed: Missing any required source raises explicit error."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cdir, tid, tdir, _ = self._create_synthetic_trial(tmp, browser="google-chrome", include_telemetry=True)
            # Make netlog.json valid JSON but empty events list -> no BROWSER_TELEMETRY events generated
            (tdir / "netlog.json").write_text('{"constants": {}, "events": []}', encoding="utf-8")
            dissections_cache = {tid: {"dns_transactions": [{"query_time": 1793307271.0, "query_frame": 1, "qname": "test.he.test", "qtype": "A", "transport": "UDP"}], "tcp_streams": {}}}
            with self.assertRaises(ValueError) as ctx:
                export_trial_timeline(campaign_dir=cdir, output_dir=tmp / "out", dissections_cache=dissections_cache)
            self.assertIn(tid, str(ctx.exception))
            self.assertIn("BROWSER_TELEMETRY", str(ctx.exception))

    # --------------------------------------------------------------------------
    # T08: Determinism & Byte Reproducibility
    # --------------------------------------------------------------------------
    def test_export_determinism_and_byte_reproducibility(self):
        """Amendment A13: Consecutive exports must yield byte-identical outputs."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out1 = Path(tmp1)
            out2 = Path(tmp2)

            cmd1 = [
                "python3", "lab/export_campaign_evidence.py",
                "--output-dir", str(out1),
                "--campaign-dir", str(CAMPAIGN_ROOT),
                "--target", "attempts",
            ]
            cmd2 = [
                "python3", "lab/export_campaign_evidence.py",
                "--output-dir", str(out2),
                "--campaign-dir", str(CAMPAIGN_ROOT),
                "--target", "attempts",
            ]

            subprocess.run(cmd1, check=True, cwd=str(REPO_ROOT))
            subprocess.run(cmd2, check=True, cwd=str(REPO_ROOT))

            f1 = out1 / "attempts.csv"
            f2 = out2 / "attempts.csv"
            self.assertTrue(f1.is_file() and f2.is_file())
            d1 = hashlib.sha256(f1.read_bytes()).hexdigest()
            d2 = hashlib.sha256(f2.read_bytes()).hexdigest()
            self.assertEqual(d1, d2, f"Byte reproducibility failure on attempts.csv: {d1} != {d2}")

            # Also verify provenance file is byte-identical
            p1 = out1 / "attempts.csv.provenance.json"
            p2 = out2 / "attempts.csv.provenance.json"
            self.assertTrue(p1.is_file() and p2.is_file())
            pd1 = hashlib.sha256(p1.read_bytes()).hexdigest()
            pd2 = hashlib.sha256(p2.read_bytes()).hexdigest()
            self.assertEqual(pd1, pd2, f"Byte reproducibility failure on provenance sidecar: {pd1} != {pd2}")

    # --------------------------------------------------------------------------
    # T09: Sibling Provenance Sidecars
    # --------------------------------------------------------------------------
    def test_export_sibling_provenance_sidecars(self):
        """Amendment A13: Every CSV must have a valid *.provenance.json sibling sidecar."""
        required_provenance_keys = {
            "target_file", "sha256", "row_count", "generated_by_command",
            "git_commit", "python_version", "tshark_version", "platform", "dissector_flags"
        }
        for csv_name in ["attempts.csv", "connection_attempts.csv", "s5_flow_dissection.csv", "trial_timeline.csv"]:
            csv_path = DERIVED_DIR / csv_name
            prov_path = DERIVED_DIR / f"{csv_name}.provenance.json"
            self.assertTrue(prov_path.is_file(), f"Missing provenance sidecar: {prov_path}")

            with open(prov_path, "r", encoding="utf-8") as f:
                prov = json.load(f)

            for key in required_provenance_keys:
                self.assertIn(key, prov, f"Missing key '{key}' in {prov_path}")

            actual_sha256 = hashlib.sha256(csv_path.read_bytes()).hexdigest()
            self.assertEqual(prov["sha256"], actual_sha256, f"Checksum mismatch in {prov_path}")

    # --------------------------------------------------------------------------
    # T10: Fail-Closed on Corrupt Manifest or Schema
    # --------------------------------------------------------------------------
    def test_export_fail_closed_on_corrupt_manifest(self):
        """Rule R5: Exporter must fail closed on unknown schema or corrupted manifest."""
        with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:
            bad_manifest = Path(tmp_in) / "campaign_manifest.json"
            bad_manifest.write_text('{"schema_version": "99.9.9", "matrix_slots": []}', encoding="utf-8")

            cmd = [
                "python3", "lab/export_campaign_evidence.py",
                "--manifest", str(bad_manifest),
                "--output-dir", str(tmp_out)
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
            self.assertNotEqual(proc.returncode, 0, "Exporter must fail closed on unknown schema version")


if __name__ == "__main__":
    unittest.main()
