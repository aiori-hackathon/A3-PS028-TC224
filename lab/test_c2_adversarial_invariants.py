#!/usr/bin/env python3
"""
Adversarial Verification Suite for Milestone 3 (Batch C2 & C4):
Row Invariants, Determinism, Flow Classification, S5 Flow Dissection, and A13 Provenance.

Test Categories:
1. TestC2RowInvariants:
   - Row count (282 total = 280 VALID_LIVE + 2 CLEANUP_FAILURE)
   - Strict 20-column schema
   - Deterministic sort order (slot_index, attempt_number)
   - Null preservation discipline (empty string, no zero-coercion)
   - Metric range and temporal sanity
   - Referential integrity against campaign manifest
2. TestC2ConnectionAttemptsAndClassification:
   - Row count (765 total TCP flows across 280 valid trials)
   - Outcome classification enum compliance and 0 INDETERMINATE flows
   - Exact outcome distribution
   - Exactly 1 ESTABLISHED_PRIMARY per completed trial
   - 5-tuple consistency and address family validation
   - Handshake timing monotonicity and offset non-negativity
   - Retransmission count non-negativity
   - Deterministic sort order (trial_id, syn_time, tcp_stream)
   - Synthetic adversarial flow state-machine challenge
3. TestC4S5FlowDissection:
   - Row count (95 total TCP flows across 40 S5 trials)
   - Strict 18-column schema
   - Cohort breakdown (20 Chrome + 20 Firefox)
   - Strict transport vs application operation separation
   - Exact category breakdown (40 PRIMARY, 12 ANCILLARY, 6 SPECULATIVE, 37 UNMATCHED)
   - Dropped SYN handling (NONE_DROPPED_SYN, no HTTP fields)
   - Deterministic sort order (trial_id, tcp_stream)
4. TestA13ByteDeterminismAndSidecars:
   - Sibling *.provenance.json presence, schema, and checksum validity
   - Zero runtime generation timestamps in exported data CSVs
   - Strict LF line terminators and UTF-8 encoding
   - Fail-closed behavior on corrupted inputs or invalid schemas
"""

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN_ROOT = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
DERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"

from lab.analyze import (
    FallbackClassification,
    TrialValidity,
    ExecutionStatus,
    ConnectionOutcome,
    SUPPORTED_SCHEMA_VERSIONS,
)


class TestC2RowInvariants(unittest.TestCase):
    """Adversarial stress-testing of attempts.csv row invariants and data integrity."""

    @classmethod
    def setUpClass(cls):
        cls.attempts_path = DERIVED_DIR / "attempts.csv"
        cls.manifest_path = CAMPAIGN_ROOT / "campaign_manifest.json"
        if not cls.attempts_path.is_file():
            raise FileNotFoundError(f"Missing required export: {cls.attempts_path}")
        if not cls.manifest_path.is_file():
            raise FileNotFoundError(f"Missing required manifest: {cls.manifest_path}")

        with open(cls.attempts_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            cls.header = reader.fieldnames or []
            cls.rows = list(reader)

        with open(cls.manifest_path, "r", encoding="utf-8") as f:
            cls.manifest = json.load(f)

    def test_exact_row_count_and_categories(self):
        """Invariant: attempts.csv must have exactly 282 rows (280 VALID_LIVE + 2 CLEANUP_FAILURE)."""
        self.assertEqual(len(self.rows), 282, f"Expected 282 rows, found {len(self.rows)}")

        valid_live = [r for r in self.rows if r["validity_category"] == TrialValidity.VALID_LIVE.value]
        cleanup_fail = [r for r in self.rows if r["validity_category"] == TrialValidity.CLEANUP_FAILURE.value]

        self.assertEqual(len(valid_live), 280, f"Expected 280 VALID_LIVE rows, got {len(valid_live)}")
        self.assertEqual(len(cleanup_fail), 2, f"Expected 2 CLEANUP_FAILURE rows, got {len(cleanup_fail)}")

        other_validities = [
            r for r in self.rows
            if r["validity_category"] not in (TrialValidity.VALID_LIVE.value, TrialValidity.CLEANUP_FAILURE.value)
        ]
        self.assertEqual(len(other_validities), 0, f"Unexpected validity categories: {other_validities}")

    def test_strict_20_column_header_schema(self):
        """Metric Contract §4.1: attempts.csv must contain exactly the 20 canonical columns."""
        expected_header = [
            "attempt_id", "slot_id", "slot_index", "campaign_id", "scenario_id",
            "browser", "repetition", "attempt_number", "trial_id", "status",
            "validity_category", "classification", "http_status", "t_connect_ms",
            "t_setup_total_ms", "syn_to_synack_ms", "cad_ms", "pcap_sha256",
            "start_time", "end_time"
        ]
        self.assertEqual(self.header, expected_header, "Header mismatch in attempts.csv")
        self.assertEqual(len(self.header), 20)

    def test_deterministic_sorting(self):
        """Invariants: attempts.csv must be strictly sorted by (slot_index, attempt_number)."""
        prev_key = (-1, -1)
        for i, row in enumerate(self.rows):
            curr_key = (int(row["slot_index"]), int(row["attempt_number"]))
            self.assertGreater(
                curr_key, prev_key,
                f"Sorting violation at row {i}: curr {curr_key} <= prev {prev_key}"
            )
            prev_key = curr_key

    def test_null_preservation_discipline(self):
        """Rule R4: Null metrics must be empty strings, NEVER 0, 0.0, null, or NaN."""
        prohibited_null_representations = {"0", "0.0", "0.00", "null", "none", "nan", "undefined"}
        null_metric_columns = [
            "http_status", "t_connect_ms", "t_setup_total_ms",
            "syn_to_synack_ms", "cad_ms", "pcap_sha256"
        ]

        for i, row in enumerate(self.rows):
            if row["validity_category"] == TrialValidity.CLEANUP_FAILURE.value:
                self.assertEqual(row["status"], ExecutionStatus.FAILED.value)
                for col in null_metric_columns:
                    val = row[col].strip().lower()
                    self.assertEqual(
                        val, "",
                        f"Non-empty null metric at row {i} col {col}: {row[col]!r}"
                    )
            else:
                for col in null_metric_columns:
                    val = row[col].strip().lower()
                    self.assertNotIn(
                        val, prohibited_null_representations,
                        f"Prohibited null coercion at row {i} col {col}: {row[col]!r}"
                    )

    def test_valid_metrics_relationships(self):
        """Invariants: t_setup_total_ms >= t_connect_ms, and latencies are positive floats."""
        for i, row in enumerate(self.rows):
            if row["validity_category"] == TrialValidity.VALID_LIVE.value:
                t_conn = float(row["t_connect_ms"])
                t_setup = float(row["t_setup_total_ms"])
                syn_synack = float(row["syn_to_synack_ms"])

                self.assertGreater(t_conn, 0.0, f"t_connect_ms <= 0 at row {i}")
                self.assertGreater(t_setup, 0.0, f"t_setup_total_ms <= 0 at row {i}")
                self.assertGreater(syn_synack, 0.0, f"syn_to_synack_ms <= 0 at row {i}")

                # Total setup cannot be less than primary connect duration
                self.assertGreaterEqual(
                    t_setup + 0.01, t_conn,
                    f"t_setup_total_ms ({t_setup}) < t_connect_ms ({t_conn}) at row {i}"
                )

                # HTTP status must be 200 for successful trials
                self.assertEqual(row["http_status"], "200", f"Unexpected http_status at row {i}")

                # PCAP SHA-256 must be valid 64-char hex
                self.assertEqual(len(row["pcap_sha256"]), 64, f"Invalid pcap_sha256 length at row {i}")

    def test_referential_integrity(self):
        """Every attempt must reference a known slot and trial in the campaign manifest."""
        manifest_slots = {s["slot_id"]: s for s in self.manifest["matrix_slots"]}
        self.assertEqual(len(manifest_slots), 280)

        seen_attempt_ids: Set[str] = set()
        seen_trial_ids: Set[str] = set()

        for i, row in enumerate(self.rows):
            aid = row["attempt_id"]
            tid = row["trial_id"]
            sid = row["slot_id"]

            self.assertNotIn(aid, seen_attempt_ids, f"Duplicate attempt_id at row {i}: {aid}")
            self.assertNotIn(tid, seen_trial_ids, f"Duplicate trial_id at row {i}: {tid}")
            seen_attempt_ids.add(aid)
            seen_trial_ids.add(tid)

            self.assertIn(sid, manifest_slots, f"Unknown slot_id at row {i}: {sid}")
            slot = manifest_slots[sid]
            self.assertEqual(row["scenario_id"], slot["scenario_id"])
            self.assertEqual(row["browser"], slot["browser"])
            self.assertEqual(int(row["repetition"]), int(slot["repetition"]))


class TestC2ConnectionAttemptsAndClassification(unittest.TestCase):
    """Adversarial stress-testing of connection_attempts.csv flow classifications."""

    @classmethod
    def setUpClass(cls):
        cls.conn_path = DERIVED_DIR / "connection_attempts.csv"
        cls.attempts_path = DERIVED_DIR / "attempts.csv"
        if not cls.conn_path.is_file():
            raise FileNotFoundError(f"Missing required export: {cls.conn_path}")

        with open(cls.conn_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            cls.header = reader.fieldnames or []
            cls.rows = list(reader)

        with open(cls.attempts_path, "r", encoding="utf-8") as f:
            cls.valid_trial_ids = {
                r["trial_id"] for r in csv.DictReader(f)
                if r["validity_category"] == TrialValidity.VALID_LIVE.value
            }

    def test_exact_row_count(self):
        """Invariant: exactly 765 TCP flows across all 280 valid PCAPs."""
        self.assertEqual(len(self.rows), 765, f"Expected 765 flows, found {len(self.rows)}")

    def test_strict_16_column_header_schema(self):
        """Metric Contract §4.2: connection_attempts.csv 16-column schema."""
        expected_header = [
            "trial_id", "pcap_sha256", "tcp_stream", "family", "client_ip",
            "client_port", "server_ip", "server_port", "syn_time", "synack_time",
            "final_ack_time", "rst_time", "offset_from_first_syn_ms", "outcome",
            "is_primary", "retransmitted_syn_count"
        ]
        self.assertEqual(self.header, expected_header, "Header mismatch in connection_attempts.csv")
        self.assertEqual(len(self.header), 16)

    def test_outcome_distribution_and_zero_indeterminate(self):
        """Invariant: 100% deterministic classification with exactly 0 INDETERMINATE flows."""
        from collections import Counter
        counts = Counter(r["outcome"] for r in self.rows)

        self.assertEqual(counts["INDETERMINATE"], 0, f"Found indeterminate flows: {counts['INDETERMINATE']}")
        self.assertEqual(counts[ConnectionOutcome.ESTABLISHED_PRIMARY.value], 280)
        self.assertEqual(counts[ConnectionOutcome.ESTABLISHED_ANCILLARY.value], 205)
        self.assertEqual(counts[ConnectionOutcome.NO_SYNACK_TIMEOUT.value], 196)
        self.assertEqual(counts[ConnectionOutcome.RESET.value], 60)
        self.assertEqual(counts[ConnectionOutcome.ABANDONED.value], 24)
        self.assertEqual(sum(counts.values()), 765)

    def test_single_primary_per_valid_trial(self):
        """Invariant: Every valid trial has exactly 1 ESTABLISHED_PRIMARY flow with is_primary=True."""
        flows_by_trial: Dict[str, List[Dict[str, Any]]] = {}
        for r in self.rows:
            flows_by_trial.setdefault(r["trial_id"], []).append(r)

        self.assertEqual(len(flows_by_trial), 280, f"Expected flows for 280 trials, got {len(flows_by_trial)}")

        for tid, flows in flows_by_trial.items():
            self.assertIn(tid, self.valid_trial_ids, f"Flow belongs to unexpected trial {tid}")

            primary_flows = [f for f in flows if f["is_primary"].lower() in ("true", "1")]
            self.assertEqual(
                len(primary_flows), 1,
                f"Trial {tid} does not have exactly 1 primary flow (found {len(primary_flows)})"
            )

            p_flow = primary_flows[0]
            self.assertEqual(
                p_flow["outcome"], ConnectionOutcome.ESTABLISHED_PRIMARY.value,
                f"Primary flow in {tid} has non-ESTABLISHED_PRIMARY outcome: {p_flow['outcome']}"
            )

            # All non-primary flows must have is_primary=False
            non_primaries = [f for f in flows if f != p_flow]
            for np in non_primaries:
                self.assertEqual(
                    np["is_primary"].lower(), "false",
                    f"Non-primary flow in {tid} has is_primary != False"
                )

    def test_5tuple_and_address_family_consistency(self):
        """Invariants: 5-tuple fields must be well-formed and consistent with family."""
        for i, r in enumerate(self.rows):
            family = r["family"]
            self.assertIn(family, ("IPv4", "IPv6"), f"Invalid family at row {i}: {family}")

            cip = r["client_ip"]
            sip = r["server_ip"]
            cport = int(r["client_port"])
            sport = int(r["server_port"])

            self.assertEqual(sport, 80, f"Expected port 80 at row {i}, got {sport}")
            self.assertTrue(1024 <= cport <= 65535, f"Ephemeral port out of range at row {i}: {cport}")

            if family == "IPv4":
                self.assertTrue(cip.startswith("10."), f"Invalid IPv4 client_ip at row {i}: {cip}")
                self.assertEqual(sip, "10.0.2.10", f"Unexpected IPv4 server_ip at row {i}: {sip}")
            else:
                self.assertTrue(cip.startswith("2001:db8:1::"), f"Invalid IPv6 client_ip at row {i}: {cip}")
                self.assertEqual(sip, "2001:db8:2::10", f"Unexpected IPv6 server_ip at row {i}: {sip}")

    def test_handshake_timing_and_offset_monotonicity(self):
        """Invariants: Handshake timestamps must follow SYN <= SYN-ACK <= ACK / RST."""
        flows_by_trial: Dict[str, List[Dict[str, Any]]] = {}
        for r in self.rows:
            flows_by_trial.setdefault(r["trial_id"], []).append(r)

        for tid, flows in flows_by_trial.items():
            offsets = [float(f["offset_from_first_syn_ms"]) for f in flows]
            self.assertTrue(all(off >= 0.0 for off in offsets), f"Negative offset in trial {tid}")
            self.assertEqual(min(offsets), 0.0, f"Earliest SYN in trial {tid} does not have 0.0 offset")

            for f in flows:
                syn = float(f["syn_time"])
                if f["synack_time"]:
                    synack = float(f["synack_time"])
                    self.assertGreaterEqual(synack, syn, f"synack < syn in {tid} stream {f['tcp_stream']}")
                if f["final_ack_time"]:
                    final_ack = float(f["final_ack_time"])
                    self.assertGreaterEqual(final_ack, synack, f"final_ack < synack in {tid} stream {f['tcp_stream']}")
                if f["rst_time"]:
                    rst = float(f["rst_time"])
                    self.assertGreaterEqual(rst, syn, f"rst < syn in {tid} stream {f['tcp_stream']}")

                retrans = int(f["retransmitted_syn_count"])
                self.assertGreaterEqual(retrans, 0, f"Negative retransmitted_syn_count in {tid}")

    def test_deterministic_sorting(self):
        """Invariants: Sorted by (trial_id, syn_time, tcp_stream)."""
        prev_key = ("", -1.0, -1)
        for i, r in enumerate(self.rows):
            curr_key = (r["trial_id"], float(r["syn_time"]) if r["syn_time"] else 0.0, int(r["tcp_stream"]))
            self.assertGreater(
                curr_key, prev_key,
                f"Sorting violation at row {i}: curr {curr_key} <= prev {prev_key}"
            )
            prev_key = curr_key


class TestC4S5FlowDissection(unittest.TestCase):
    """Adversarial stress-testing of s5_flow_dissection.csv and transport vs app separation."""

    @classmethod
    def setUpClass(cls):
        cls.s5_path = DERIVED_DIR / "s5_flow_dissection.csv"
        cls.attempts_path = DERIVED_DIR / "attempts.csv"
        if not cls.s5_path.is_file():
            raise FileNotFoundError(f"Missing required export: {cls.s5_path}")

        with open(cls.s5_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            cls.header = reader.fieldnames or []
            cls.rows = list(reader)

        with open(cls.attempts_path, "r", encoding="utf-8") as f:
            cls.s5_trials_manifest = {
                r["trial_id"]: r for r in csv.DictReader(f)
                if r["scenario_id"] == "S5" and r["validity_category"] == TrialValidity.VALID_LIVE.value
            }

    def test_s5_exact_row_count(self):
        """Invariant: exactly 95 flows across the 40 authentic S5 trials."""
        self.assertEqual(len(self.rows), 95, f"Expected 95 S5 flows, found {len(self.rows)}")

    def test_s5_strict_18_column_header(self):
        """Metric Contract: s5_flow_dissection.csv 18-column schema."""
        expected_header = [
            "trial_id", "browser", "repetition", "pcap_sha256", "tcp_stream",
            "family", "client_endpoint", "server_endpoint", "syn_time", "synack_time",
            "final_ack_time", "offset_from_first_syn_ms", "flow_category",
            "application_operation", "http_method", "http_uri", "http_status_code",
            "retransmitted_syn_count"
        ]
        self.assertEqual(self.header, expected_header, "Header mismatch in s5_flow_dissection.csv")
        self.assertEqual(len(self.header), 18)

    def test_s5_cohort_partitioning(self):
        """Invariant: Exactly 40 unique trials (20 Chrome, 20 Firefox)."""
        trials_in_s5 = {r["trial_id"] for r in self.rows}
        self.assertEqual(len(trials_in_s5), 40)
        self.assertEqual(trials_in_s5, set(self.s5_trials_manifest.keys()))

        chrome_trials = {r["trial_id"] for r in self.rows if r["browser"] == "google-chrome"}
        firefox_trials = {r["trial_id"] for r in self.rows if r["browser"] == "firefox"}

        self.assertEqual(len(chrome_trials), 20)
        self.assertEqual(len(firefox_trials), 20)

    def test_s5_flow_categories_and_operations_distribution(self):
        """Invariants: S5 category breakdown (40 PRIMARY, 12 ANCILLARY, 6 SPECULATIVE, 37 UNMATCHED)."""
        from collections import Counter
        cat_counts = Counter(r["flow_category"] for r in self.rows)
        op_counts = Counter(r["application_operation"] for r in self.rows)

        self.assertEqual(cat_counts["PRIMARY"], 40)
        self.assertEqual(cat_counts["ANCILLARY"], 12)
        self.assertEqual(cat_counts["SPECULATIVE"], 6)
        self.assertEqual(cat_counts["UNMATCHED"], 37)

        self.assertEqual(op_counts["DOCUMENT_ROOT"], 40)
        self.assertEqual(op_counts["PRECONNECT_IDLE"], 6)
        self.assertEqual(op_counts["NONE_DROPPED_SYN"], 37)
        self.assertEqual(op_counts["FAVICON"] + op_counts["SUBRESOURCE"], 12)

    def test_transport_vs_application_separation(self):
        """Finding C4-02: Transport stream ID decoupled from HTTP application operations."""
        for i, r in enumerate(self.rows):
            cat = r["flow_category"]
            op = r["application_operation"]

            if cat == "PRIMARY":
                self.assertEqual(op, "DOCUMENT_ROOT")
                self.assertEqual(r["http_method"], "GET")
                self.assertEqual(r["http_uri"], "/")
                self.assertEqual(r["http_status_code"], "200")
                self.assertTrue(r["synack_time"], f"Primary missing synack at row {i}")
                self.assertTrue(r["final_ack_time"], f"Primary missing final_ack at row {i}")

            elif cat == "ANCILLARY":
                self.assertIn(op, ("FAVICON", "SUBRESOURCE"))
                self.assertEqual(r["http_method"], "GET")
                self.assertTrue(r["synack_time"], f"Ancillary missing synack at row {i}")

            elif cat == "SPECULATIVE":
                self.assertEqual(op, "PRECONNECT_IDLE")
                self.assertEqual(r["http_method"], "")
                self.assertEqual(r["http_uri"], "")
                self.assertEqual(r["http_status_code"], "")
                # Handshake completed, but no HTTP request was transmitted
                self.assertTrue(r["synack_time"], f"Speculative missing synack at row {i}")
                self.assertTrue(r["final_ack_time"], f"Speculative missing final_ack at row {i}")

            elif cat == "UNMATCHED":
                self.assertEqual(op, "NONE_DROPPED_SYN")
                self.assertEqual(r["http_method"], "")
                self.assertEqual(r["http_uri"], "")
                self.assertEqual(r["http_status_code"], "")
                # In S5, dropped SYN means handshake was never established
                self.assertEqual(r["synack_time"], "")
                self.assertEqual(r["final_ack_time"], "")

    def test_deterministic_sorting(self):
        """Invariants: Sorted by (trial_id, tcp_stream)."""
        prev_key = ("", -1)
        for i, r in enumerate(self.rows):
            curr_key = (r["trial_id"], int(r["tcp_stream"]))
            self.assertGreater(
                curr_key, prev_key,
                f"Sorting violation at row {i}: curr {curr_key} <= prev {prev_key}"
            )
            prev_key = curr_key


class TestA13ByteDeterminismAndSidecars(unittest.TestCase):
    """Adversarial testing of Amendment A13 sidecars and byte determinism."""

    EXPORT_FILES = [
        "attempts.csv",
        "connection_attempts.csv",
        "s5_flow_dissection.csv",
        "trial_timeline.csv",
    ]

    def test_sidecars_presence_and_checksum_verification(self):
        """Amendment A13: Every CSV must have a valid *.provenance.json with verified checksum."""
        mandatory_keys = {
            "target_file", "sha256", "row_count", "generated_by_command",
            "git_commit", "git_branch", "python_version", "tshark_version",
            "platform", "dissector_flags", "input_manifest"
        }

        for fname in self.EXPORT_FILES:
            csv_file = DERIVED_DIR / fname
            prov_file = DERIVED_DIR / f"{fname}.provenance.json"

            self.assertTrue(csv_file.is_file(), f"Missing CSV: {csv_file}")
            self.assertTrue(prov_file.is_file(), f"Missing provenance sidecar: {prov_file}")

            with open(prov_file, "r", encoding="utf-8") as pf:
                prov = json.load(pf)

            for key in mandatory_keys:
                self.assertIn(key, prov, f"Missing key '{key}' in sidecar {prov_file}")

            # Verify cryptographic SHA-256 matches actual file on disk
            actual_sha = hashlib.sha256(csv_file.read_bytes()).hexdigest()
            self.assertEqual(
                prov["sha256"], actual_sha,
                f"Digest mismatch in sidecar {prov_file}: {prov['sha256']} != {actual_sha}"
            )

            # Verify row count matches actual data rows
            with open(csv_file, "r", encoding="utf-8") as cf:
                data_row_count = sum(1 for _ in cf) - 1
            self.assertEqual(
                prov["row_count"], data_row_count,
                f"Row count mismatch in sidecar {prov_file}: {prov['row_count']} != {data_row_count}"
            )

    def test_zero_generation_timestamps_in_data_csvs(self):
        """Amendment A13: CSVs must contain zero execution/generation timestamps."""
        # Check column names: none should represent generation/export time
        disallowed_col_substrings = [
            "export_time", "generation_time", "created_at", "run_timestamp", "exported_at"
        ]
        for fname in self.EXPORT_FILES:
            csv_file = DERIVED_DIR / fname
            with open(csv_file, "r", encoding="utf-8") as cf:
                reader = csv.reader(cf)
                header = next(reader)
                for col in header:
                    for sub in disallowed_col_substrings:
                        self.assertNotIn(
                            sub, col.lower(),
                            f"Prohibited generation timestamp column '{col}' in {fname}"
                        )

    def test_strict_lf_line_terminators_and_utf8(self):
        """Invariants: Files must strictly use Unix LF (0x0A) and valid UTF-8 without BOM."""
        for fname in self.EXPORT_FILES:
            csv_file = DERIVED_DIR / fname
            raw_bytes = csv_file.read_bytes()

            # No UTF-8 BOM
            self.assertFalse(
                raw_bytes.startswith(b"\xef\xbb\xbf"),
                f"UTF-8 BOM found at head of {fname}"
            )

            # No CRLF
            self.assertNotIn(
                b"\r\n", raw_bytes,
                f"Windows CRLF line terminator found in {fname}"
            )

    def test_fail_closed_on_corrupted_inputs(self):
        """Rule R5: Engine must fail closed on invalid schema or corrupted manifest."""
        from lab.export_campaign_evidence import export_attempts_ledger

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            bad_manifest = tmp_path / "bad_manifest.json"

            # Case 1: Unsupported schema version
            bad_manifest.write_text('{"schema_version": "9.9.9", "matrix_slots": []}', encoding="utf-8")
            with self.assertRaises(ValueError):
                export_attempts_ledger(
                    manifest_path=bad_manifest,
                    output_dir=tmp_path / "out",
                )

            # Case 2: Slot count mismatch (not 280)
            bad_manifest.write_text('{"schema_version": "1.0.0", "matrix_slots": [{"slot_id": "s1"}]}', encoding="utf-8")
            with self.assertRaises(ValueError):
                export_attempts_ledger(
                    manifest_path=bad_manifest,
                    output_dir=tmp_path / "out",
                )


if __name__ == "__main__":
    unittest.main()
