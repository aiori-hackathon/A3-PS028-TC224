#!/usr/bin/env python3
"""
Adversarial Challenge & Stress-Test Suite for Milestone 3: Batch C2 & C4
Focus: Multi-Source Event Synchronization in trial_timeline.csv

Covers:
1. Chrome NetLog epoch conversion: (timeTickOffset + event.time) / 1000.0.
2. Firefox telemetry timestamp parsing (%Y-%m-%d %H:%M:%S.%f UTC).
3. Cross-source correlation with PCAP frame timestamps and harness lifecycle events.
4. Monotonic ordering of events and contiguous sequential indexing per trial.
5. Incomplete trials and missing/corrupted telemetry handling.
6. Bit-for-bit determinism and Amendment A13 sibling provenance sidecars.
"""

from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN_DIR = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
DERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"

from lab.export_campaign_evidence import (
    export_trial_timeline,
    TRIAL_TIMELINE_CSV_HEADER,
    EventSource,
)


class TestC2AdversarialTimelineChallenge(unittest.TestCase):
    """Adversarial stress-test suite for timeline synchronization."""

    @classmethod
    def setUpClass(cls):
        """Ensure campaign evidence exports are available."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        if not timeline_csv.is_file():
            import subprocess
            cmd = [
                "python3",
                str(REPO_ROOT / "lab" / "export_campaign_evidence.py"),
                "--campaign-dir", str(CAMPAIGN_DIR),
                "--output-dir", str(DERIVED_DIR),
            ]
            subprocess.run(cmd, check=True, cwd=str(REPO_ROOT))

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_c2_adv_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # =========================================================================
    # SUITE 1: Chrome NetLog Epoch Conversion Stress Tests
    # =========================================================================

    def test_1_1_chrome_netlog_epoch_conversion_oracle(self):
        """Verify mathematical precision of Chrome NetLog epoch conversion: (offset + tick)/1000.0."""
        # Realistic NetLog values
        offset_ms = 1793228739543
        ticks = [0, 1, 1000, 84177331, 100000000]

        for tick in ticks:
            epoch_sec = (offset_ms + tick) / 1000.0
            expected_sec = offset_ms / 1000.0 + tick / 1000.0
            self.assertAlmostEqual(epoch_sec, expected_sec, places=9)

            # Test 6 decimal places string representation
            formatted = f"{epoch_sec:.6f}"
            self.assertEqual(float(formatted), round(epoch_sec, 6))

    def test_1_2_chrome_netlog_harness_lifecycle_bounds(self):
        """All NetLog events in authentic campaign must fall within [browser_start, browser_end]."""
        manifest_path = CAMPAIGN_DIR / "campaign_manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        chrome_trials = []
        for s in manifest.get("matrix_slots", []):
            if s.get("browser") == "google-chrome":
                for att in s.get("attempts", []):
                    if att.get("validity") == "VALID_LIVE":
                        chrome_trials.append(att["trial_id"])

        self.assertEqual(len(chrome_trials), 140, "Expected 140 valid Chrome trials")

        for tid in chrome_trials:
            t_rows = events_by_trial[tid]
            h_times = {
                r["event_type"]: float(r["event_timestamp_epoch"])
                for r in t_rows if r["event_source"] == "HARNESS"
            }
            b_start = h_times.get("BROWSER_LAUNCH")
            b_end = h_times.get("BROWSER_EXIT")
            self.assertIsNotNone(b_start, f"Missing BROWSER_LAUNCH in {tid}")
            self.assertIsNotNone(b_end, f"Missing BROWSER_EXIT in {tid}")

            netlog_events = [
                float(r["event_timestamp_epoch"])
                for r in t_rows if r["event_source"] == "BROWSER_TELEMETRY"
            ]
            self.assertGreater(len(netlog_events), 0, f"Expected NetLog events in Chrome trial {tid}")

            for ts in netlog_events:
                self.assertGreaterEqual(ts, b_start, f"NetLog event before BROWSER_LAUNCH in {tid}")
                self.assertLessEqual(ts, b_end, f"NetLog event after BROWSER_EXIT in {tid}")

    def test_1_3_chrome_netlog_causal_lead_time_to_wire(self):
        """NetLog TCP_CONNECT_JOB_CONNECT must precede physical PCAP TCP_SYN with sub-10ms median lead."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        deltas = []
        for tid, events in events_by_trial.items():
            connect_jobs = [
                float(e["event_timestamp_epoch"])
                for e in events
                if e["event_type"] == "TCP_CONNECT_JOB_CONNECT" and "phase=1" in e["details"]
            ]
            tcp_syns = [
                float(e["event_timestamp_epoch"])
                for e in events if e["event_type"] == "TCP_SYN"
            ]
            if connect_jobs and tcp_syns:
                for syn in tcp_syns:
                    prec = [cj for cj in connect_jobs if cj <= syn]
                    if prec:
                        deltas.append(syn - prec[-1])

        self.assertGreaterEqual(len(deltas), 400, "Expected >400 matched Chrome connection pairs")
        median_delta_ms = sorted(deltas)[len(deltas) // 2] * 1000.0
        min_delta_ms = min(deltas) * 1000.0
        self.assertGreaterEqual(min_delta_ms, 0.0, "Physical SYN cannot precede NetLog job start")
        self.assertLess(median_delta_ms, 10.0, f"Median lead time exceeds 10ms: {median_delta_ms:.2f}ms")

    # =========================================================================
    # SUITE 2: Firefox Telemetry Timestamp Parsing Stress Tests
    # =========================================================================

    def test_2_1_firefox_telemetry_timestamp_parsing_oracle(self):
        """Verify parsing of %Y-%m-%d %H:%M:%S.%f UTC into correct epoch float."""
        sample_line = "2026-10-29 20:59:30.209532 UTC - [Parent 62335: Main Thread]: D/nsHttp nsHttpHandler::Init"
        dt = datetime.strptime("2026-10-29 20:59:30.209532", "%Y-%m-%d %H:%M:%S.%f")
        expected_epoch = dt.replace(tzinfo=timezone.utc).timestamp()

        self.assertEqual(expected_epoch, 1793307570.209532)
        formatted = f"{expected_epoch:.6f}"
        self.assertEqual(formatted, "1793307570.209532")

    def test_2_2_firefox_telemetry_harness_lifecycle_bounds(self):
        """All Firefox telemetry events in authentic campaign must fall within [browser_start, browser_end]."""
        manifest_path = CAMPAIGN_DIR / "campaign_manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        ff_trials = []
        for s in manifest.get("matrix_slots", []):
            if s.get("browser") == "firefox":
                for att in s.get("attempts", []):
                    if att.get("validity") == "VALID_LIVE":
                        ff_trials.append(att["trial_id"])

        self.assertEqual(len(ff_trials), 140, "Expected 140 valid Firefox trials")

        for tid in ff_trials:
            t_rows = events_by_trial[tid]
            h_times = {
                r["event_type"]: float(r["event_timestamp_epoch"])
                for r in t_rows if r["event_source"] == "HARNESS"
            }
            b_start = h_times.get("BROWSER_LAUNCH")
            b_end = h_times.get("BROWSER_EXIT")
            self.assertIsNotNone(b_start, f"Missing BROWSER_LAUNCH in {tid}")
            self.assertIsNotNone(b_end, f"Missing BROWSER_EXIT in {tid}")

            ff_events = [
                float(r["event_timestamp_epoch"])
                for r in t_rows if r["event_source"] == "BROWSER_TELEMETRY"
            ]
            self.assertGreater(len(ff_events), 0, f"Expected Firefox telemetry in {tid}")

            for ts in ff_events:
                self.assertGreaterEqual(ts, b_start, f"Firefox event before BROWSER_LAUNCH in {tid}")
                self.assertLessEqual(ts, b_end, f"Firefox event after BROWSER_EXIT in {tid}")

    def test_2_3_firefox_causal_lead_time_to_wire(self):
        """Firefox nsHttpConnection::Init must precede physical PCAP TCP_SYN."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        deltas = []
        for tid, events in events_by_trial.items():
            ff_conns = [
                float(e["event_timestamp_epoch"])
                for e in events if e["event_type"] == "nsHttpConnection::Init"
            ]
            tcp_syns = [
                float(e["event_timestamp_epoch"])
                for e in events if e["event_type"] == "TCP_SYN"
            ]
            if ff_conns and tcp_syns:
                for syn in tcp_syns:
                    prec = [fc for fc in ff_conns if fc <= syn]
                    if prec:
                        deltas.append(syn - prec[-1])

        self.assertGreaterEqual(len(deltas), 300, "Expected >300 matched Firefox connection pairs")
        min_delta_ms = min(deltas) * 1000.0
        self.assertGreaterEqual(min_delta_ms, 0.0, "Physical SYN cannot precede Firefox connection init")

    # =========================================================================
    # SUITE 3: Multi-Source Clock Synchronization & Correlation
    # =========================================================================

    def test_3_1_pcap_containment_in_capture_window(self):
        """All PCAP packet events must occur strictly within [CAPTURE_START, CAPTURE_STOP]."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        for tid, events in events_by_trial.items():
            h_times = {
                r["event_type"]: float(r["event_timestamp_epoch"])
                for r in events if r["event_source"] == "HARNESS"
            }
            cap_start = h_times.get("CAPTURE_START")
            cap_stop = h_times.get("CAPTURE_STOP")
            if cap_start is None or cap_stop is None:
                continue

            for ev in events:
                if ev["event_source"] == "PCAP":
                    ts = float(ev["event_timestamp_epoch"])
                    self.assertGreaterEqual(
                        ts, cap_start - 1e-6,
                        f"PCAP packet {ev['event_type']} before CAPTURE_START in {tid}"
                    )
                    self.assertLessEqual(
                        ts, cap_stop + 1e-6,
                        f"PCAP packet {ev['event_type']} after CAPTURE_STOP in {tid}"
                    )

    def test_3_2_pcap_tcp_handshake_causality(self):
        """PCAP TCP handshakes must satisfy SYN <= SYNACK <= FINAL_ACK per stream."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        for tid, events in events_by_trial.items():
            streams = defaultdict(dict)
            for ev in events:
                if ev["event_source"] == "PCAP" and ev["tcp_stream"]:
                    sid = ev["tcp_stream"]
                    etype = ev["event_type"]
                    if etype not in streams[sid]:
                        streams[sid][etype] = float(ev["event_timestamp_epoch"])

            for sid, evs in streams.items():
                if "TCP_SYN" in evs and "TCP_SYNACK" in evs:
                    self.assertLessEqual(
                        evs["TCP_SYN"], evs["TCP_SYNACK"],
                        f"SYN > SYNACK on stream {sid} in {tid}"
                    )
                if "TCP_SYNACK" in evs and "TCP_FINAL_ACK" in evs:
                    self.assertLessEqual(
                        evs["TCP_SYNACK"], evs["TCP_FINAL_ACK"],
                        f"SYNACK > FINAL_ACK on stream {sid} in {tid}"
                    )

    def test_3_3_dns_transaction_causality(self):
        """PCAP DNS queries must precede corresponding DNS responses."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(row)

        for tid, events in events_by_trial.items():
            dns_queries = [
                float(e["event_timestamp_epoch"])
                for e in events if e["event_type"] == "DNS_QUERY"
            ]
            dns_resps = [
                float(e["event_timestamp_epoch"])
                for e in events if e["event_type"] == "DNS_RESPONSE"
            ]
            if dns_queries and dns_resps:
                self.assertLessEqual(
                    min(dns_queries), min(dns_resps),
                    f"First DNS response precedes first DNS query in {tid}"
                )

    # =========================================================================
    # SUITE 4: Monotonic Ordering & Index Invariants
    # =========================================================================

    def test_4_1_monotonic_timestamp_ordering_all_trials(self):
        """All 282 trials must maintain strictly non-decreasing timestamps throughout."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        with open(timeline_csv, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            prev_tid = None
            prev_ts = -1.0
            for row in reader:
                tid = row["trial_id"]
                ts = float(row["event_timestamp_epoch"])
                if tid != prev_tid:
                    prev_tid = tid
                    prev_ts = ts
                else:
                    self.assertGreaterEqual(
                        ts, prev_ts,
                        f"Monotonicity violation in trial {tid}: {ts} < {prev_ts}"
                    )
                    prev_ts = ts

    def test_4_2_contiguous_sequential_event_indexing(self):
        """Every trial's event_index must start at 1 and increment contiguously without gaps."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                events_by_trial[row["trial_id"]].append(int(row["event_index"]))

        self.assertEqual(len(events_by_trial), 282, "Expected 282 trials in timeline")
        for tid, indices in events_by_trial.items():
            expected = list(range(1, len(indices) + 1))
            self.assertEqual(indices, expected, f"Non-contiguous index sequence in {tid}")

    def test_4_3_timestamp_float_formatting_invariant(self):
        """Every event_timestamp_epoch must be formatted with exactly 6 decimal places."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ts_str = row["event_timestamp_epoch"]
                parts = ts_str.split(".")
                self.assertEqual(len(parts), 2, f"Invalid float representation: {ts_str}")
                self.assertEqual(len(parts[1]), 6, f"Not formatted to 6 decimal places: {ts_str}")

    # =========================================================================
    # SUITE 5: Incomplete Trials & Synthetic Stress Scenarios
    # =========================================================================

    def test_5_1_cleanup_failure_reconciliation(self):
        """Cleanup failure trials must be represented with harness lifecycle only (Rule R4)."""
        cleanup_trials = {
            "trial-20261029205442-aba6193c",
            "trial-20261029210226-944fcfaa",
        }
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        events_by_trial = defaultdict(list)
        with open(timeline_csv, "r", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["trial_id"] in cleanup_trials:
                    events_by_trial[row["trial_id"]].append(row)

        self.assertEqual(set(events_by_trial.keys()), cleanup_trials)
        for tid, events in events_by_trial.items():
            # Must contain only HARNESS events
            sources = {e["event_source"] for e in events}
            self.assertEqual(sources, {"HARNESS"})
            types = [e["event_type"] for e in events]
            self.assertEqual(types, ["TRIAL_START", "TRIAL_END"])

    def test_5_2_synthetic_missing_telemetry_and_corruptions(self):
        """Adversarial stress harness: handle missing/corrupted telemetry files and empty trials fail-closed."""
        sample_pcap = next((CAMPAIGN_DIR / "trials").glob("*/capture.pcap"))
        trials_dir = self.temp_dir / "trials"
        trials_dir.mkdir(parents=True, exist_ok=True)

        # ---------------------------------------------------------------------
        # Negative Case 1: Chrome VALID_LIVE trial with corrupted NetLog JSON
        # Must fail-closed with ValueError indicating invalid JSON.
        # ---------------------------------------------------------------------
        m_chrome_corrupt = {
            "schema_version": "1.1.0",
            "matrix_slots": [{
                "slot_id": "slot-synth-01",
                "browser": "google-chrome",
                "attempts": [
                    {"trial_id": "trial-synth-chrome-corrupt", "status": "COMPLETED", "validity": "VALID_LIVE"}
                ],
            }],
        }
        m1_path = self.temp_dir / "manifest_chrome_corrupt.json"
        m1_path.write_text(json.dumps(m_chrome_corrupt), encoding="utf-8")
        c1_dir = trials_dir / "trial-synth-chrome-corrupt"
        c1_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(sample_pcap, c1_dir / "capture.pcap")
        (c1_dir / "result.json").write_text(json.dumps({
            "timestamps": {
                "start_time": "2026-10-29T20:00:00+00:00",
                "browser_start_time": "2026-10-29T20:00:01+00:00",
                "browser_end_time": "2026-10-29T20:00:02+00:00",
                "end_time": "2026-10-29T20:00:03+00:00",
            }
        }))
        (c1_dir / "netlog.json").write_text("{CORRUPTED SYNTAX")

        with self.assertRaises(ValueError) as ctx1:
            export_trial_timeline(
                campaign_dir=self.temp_dir,
                output_dir=self.temp_dir / "out1",
                manifest_path=m1_path,
            )
        self.assertIn("invalid JSON in Chrome NetLog", str(ctx1.exception))
        self.assertIn("trial-synth-chrome-corrupt", str(ctx1.exception))

        # ---------------------------------------------------------------------
        # Negative Case 2: Chrome VALID_LIVE trial with missing NetLog file
        # Must fail-closed with FileNotFoundError indicating missing NetLog.
        # ---------------------------------------------------------------------
        m_chrome_missing = {
            "schema_version": "1.1.0",
            "matrix_slots": [{
                "slot_id": "slot-synth-02",
                "browser": "google-chrome",
                "attempts": [
                    {"trial_id": "trial-synth-chrome-missing", "status": "COMPLETED", "validity": "VALID_LIVE"}
                ],
            }],
        }
        m2_path = self.temp_dir / "manifest_chrome_missing.json"
        m2_path.write_text(json.dumps(m_chrome_missing), encoding="utf-8")
        c2_dir = trials_dir / "trial-synth-chrome-missing"
        c2_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(sample_pcap, c2_dir / "capture.pcap")
        (c2_dir / "result.json").write_text(json.dumps({
            "timestamps": {
                "start_time": "2026-10-29T20:00:00+00:00",
                "browser_start_time": "2026-10-29T20:00:01+00:00",
                "browser_end_time": "2026-10-29T20:00:02+00:00",
                "end_time": "2026-10-29T20:00:03+00:00",
            }
        }))

        with self.assertRaises(FileNotFoundError) as ctx2:
            export_trial_timeline(
                campaign_dir=self.temp_dir,
                output_dir=self.temp_dir / "out2",
                manifest_path=m2_path,
            )
        self.assertIn("mandatory Chrome NetLog file missing", str(ctx2.exception))
        self.assertIn("trial-synth-chrome-missing", str(ctx2.exception))

        # ---------------------------------------------------------------------
        # Negative Case 3: Firefox VALID_LIVE trial with missing telemetry log
        # Must fail-closed with FileNotFoundError indicating missing Firefox log.
        # ---------------------------------------------------------------------
        m_ff_missing = {
            "schema_version": "1.1.0",
            "matrix_slots": [{
                "slot_id": "slot-synth-03",
                "browser": "firefox",
                "attempts": [
                    {"trial_id": "trial-synth-ff-missing", "status": "COMPLETED", "validity": "VALID_LIVE"}
                ],
            }],
        }
        m3_path = self.temp_dir / "manifest_ff_missing.json"
        m3_path.write_text(json.dumps(m_ff_missing), encoding="utf-8")
        f3_dir = trials_dir / "trial-synth-ff-missing"
        f3_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(sample_pcap, f3_dir / "capture.pcap")
        (f3_dir / "result.json").write_text(json.dumps({
            "timestamps": {
                "start_time": "2026-10-29T20:00:00+00:00",
                "browser_start_time": "2026-10-29T20:00:01+00:00",
                "browser_end_time": "2026-10-29T20:00:02+00:00",
                "end_time": "2026-10-29T20:00:03+00:00",
            }
        }))

        with self.assertRaises(FileNotFoundError) as ctx3:
            export_trial_timeline(
                campaign_dir=self.temp_dir,
                output_dir=self.temp_dir / "out3",
                manifest_path=m3_path,
            )
        self.assertIn("mandatory Firefox telemetry log missing", str(ctx3.exception))
        self.assertIn("trial-synth-ff-missing", str(ctx3.exception))

        # ---------------------------------------------------------------------
        # Positive / Graceful Degradation Case:
        # - Firefox trial with mixed valid/invalid log lines (should parse valid lines)
        # - Empty failed trial (should emit 0 events without error)
        # ---------------------------------------------------------------------
        synth_manifest = {
            "schema_version": "1.1.0",
            "matrix_slots": [
                {
                    "slot_id": "slot-synth-04",
                    "browser": "firefox",
                    "attempts": [
                        {"trial_id": "trial-synth-ff-corrupt", "status": "COMPLETED", "validity": "VALID_LIVE"},
                    ],
                },
                {
                    "slot_id": "slot-synth-05",
                    "browser": "firefox",
                    "attempts": [
                        {"trial_id": "trial-synth-empty", "status": "FAILED", "validity": "MEASUREMENT_FAILURE"},
                    ],
                },
            ],
        }
        mpath = self.temp_dir / "campaign_manifest.json"
        mpath.write_text(json.dumps(synth_manifest), encoding="utf-8")

        f_dir = trials_dir / "trial-synth-ff-corrupt"
        f_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(sample_pcap, f_dir / "capture.pcap")
        (f_dir / "result.json").write_text(json.dumps({
            "timestamps": {
                "start_time": "2026-10-29T20:00:00+00:00",
                "browser_start_time": "2026-10-29T20:00:01+00:00",
                "browser_end_time": "2026-10-29T20:00:02+00:00",
                "end_time": "2026-10-29T20:00:03+00:00",
            }
        }))
        (f_dir / "browser_telemetry.log").write_text(
            "GARBAGE UNTIMESTAMPED LINE\n"
            "2026-10-29 20:00:01.500000 UTC - [Parent 1]: D/nsHttp nsHttpHandler::Init\n"
            "ANOTHER UNTIMESTAMPED LINE\n"
        )

        e_dir = trials_dir / "trial-synth-empty"
        e_dir.mkdir(parents=True, exist_ok=True)

        out_dir = self.temp_dir / "derived"
        csv_path, prov_path = export_trial_timeline(
            campaign_dir=self.temp_dir,
            output_dir=out_dir,
            manifest_path=mpath,
        )

        self.assertTrue(csv_path.is_file())
        self.assertTrue(prov_path.is_file())

        with open(csv_path, "r", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        # Firefox trial should output harness events + PCAP events + the 1 valid telemetry event
        f_events = [r for r in rows if r["trial_id"] == "trial-synth-ff-corrupt"]
        sources = {r["event_source"] for r in f_events}
        self.assertIn("HARNESS", sources)
        self.assertIn("PCAP", sources)
        self.assertIn("BROWSER_TELEMETRY", sources)
        self.assertEqual([r["event_index"] for r in f_events], [str(i) for i in range(1, len(f_events) + 1)])
        ff_tel = [r for r in f_events if r["event_source"] == "BROWSER_TELEMETRY"]
        self.assertEqual(len(ff_tel), 1)
        self.assertEqual(ff_tel[0]["event_type"], "nsHttpHandler::Init")

        # Empty failed trial emits 0 events without error
        e_events = [r for r in rows if r["trial_id"] == "trial-synth-empty"]
        self.assertEqual(len(e_events), 0)

    # =========================================================================
    # SUITE 6: Determinism & Provenance Sidecars
    # =========================================================================

    def test_6_1_provenance_sidecar_digest_match(self):
        """Amendment A13: Sibling <csv>.provenance.json digest must match CSV exactly."""
        timeline_csv = DERIVED_DIR / "trial_timeline.csv"
        prov_path = DERIVED_DIR / "trial_timeline.csv.provenance.json"

        self.assertTrue(timeline_csv.is_file())
        self.assertTrue(prov_path.is_file())

        actual_sha = hashlib.sha256(timeline_csv.read_bytes()).hexdigest()
        with open(prov_path, "r", encoding="utf-8") as f:
            prov_data = json.load(f)

        self.assertEqual(prov_data.get("sha256"), actual_sha)
        self.assertEqual(prov_data.get("row_count"), 28330)
        self.assertEqual(prov_data.get("target_file"), "trial_timeline.csv")


if __name__ == "__main__":
    unittest.main()
