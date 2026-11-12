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
from pathlib import Path
import subprocess
import tempfile
import unittest

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
        """Amendment A9: trial_timeline.csv events must have explicit event_source enum."""
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

        self.assertGreater(len(rows), 20000, f"Expected >20000 timeline events, got {len(rows)}")
        for i, row in enumerate(rows[:500]):  # Spot check first 500
            self.assertIn(row["event_source"], allowed_sources, f"Invalid event_source at row {i}: {row['event_source']}")

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
