#!/usr/bin/env python3
"""
Unit and regression tests for lab/build_submission_report.py
Validates Workstream G (Audit Finding #12): Fail-closed behavior for scientific evidence.
"""

import json
import tempfile
import unittest
from pathlib import Path

from lab.build_submission_report import load_derived_metrics


class TestBuildSubmissionReport(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_attempts_csv_fails_closed(self):
        """Missing attempts.csv must raise FileNotFoundError, not substitute fallbacks."""
        with self.assertRaises(FileNotFoundError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("attempts.csv", str(ctx.exception))

    def test_missing_s5_flow_dissection_csv_fails_closed(self):
        """Missing s5_flow_dissection.csv must raise FileNotFoundError, not substitute 95."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("validity_category,classification\nVALID_LIVE,DIRECT_IPV6\n")

        with self.assertRaises(FileNotFoundError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("s5_flow_dissection.csv", str(ctx.exception))

    def test_empty_attempts_csv_fails_closed(self):
        """Empty attempts.csv must raise ValueError."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("trial_id,family\nt1,IPv6\n")

        with self.assertRaises(ValueError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("empty or has no header", str(ctx.exception))

    def test_zero_rows_attempts_csv_fails_closed(self):
        """attempts.csv with only header and 0 data rows must raise ValueError."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("validity_category,classification\n")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("trial_id,family\nt1,IPv6\n")

        with self.assertRaises(ValueError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("contains 0 rows", str(ctx.exception))

    def test_missing_columns_attempts_csv_fails_closed(self):
        """attempts.csv missing required columns must raise ValueError."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("trial_id,duration\nt1,10.5\n")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("trial_id,family\nt1,IPv6\n")

        with self.assertRaises(ValueError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("missing columns", str(ctx.exception))

    def test_empty_s5_flow_dissection_csv_fails_closed(self):
        """Empty s5_flow_dissection.csv must raise ValueError."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("validity_category,classification\nVALID_LIVE,DIRECT_IPV6\n")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("")

        with self.assertRaises(ValueError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("empty or has no header", str(ctx.exception))

    def test_zero_rows_s5_flow_dissection_csv_fails_closed(self):
        """s5_flow_dissection.csv with 0 rows must raise ValueError."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("validity_category,classification\nVALID_LIVE,DIRECT_IPV6\n")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("trial_id,family\n")

        with self.assertRaises(ValueError) as ctx:
            load_derived_metrics(derived_dir=self.base_dir)
        self.assertIn("contains 0 rows", str(ctx.exception))

    def test_valid_files_derive_accurate_metrics(self):
        """Valid files derive exact counts from rows without substitution."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text(
            "validity_category,classification\n"
            "VALID_LIVE,DIRECT_IPV6\n"
            "VALID_LIVE,IPV6_TO_IPV4_FALLBACK\n"
            "VALID_LIVE,DIRECT_IPV6\n"
            "CLEANUP_FAILURE,CLEANUP_ERROR\n"
        )
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text(
            "trial_id,family,is_primary\n"
            "trial-1,IPv6,True\n"
            "trial-1,IPv6,False\n"
            "trial-2,IPv4,True\n"
        )
        metrics = load_derived_metrics(derived_dir=self.base_dir)

        self.assertEqual(metrics["total_attempts"], 4)
        self.assertEqual(metrics["valid_live"], 3)
        self.assertEqual(metrics["cleanup_failures"], 1)
        self.assertEqual(metrics["direct_ipv6"], 2)
        self.assertEqual(metrics["fallback_ipv4"], 1)
        self.assertEqual(metrics["s5_total_flows"], 3)
        self.assertEqual(metrics["s5_ipv6_wins"], 1)
        self.assertEqual(metrics["s5_ipv4_wins"], 1)

    def test_missing_test_record_marks_not_recorded(self):
        """When test_run_record.json is missing, test metrics are explicitly NOT_RECORDED."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("validity_category,classification\nVALID_LIVE,DIRECT_IPV6\n")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("trial_id,family\nt1,IPv6\n")

        metrics = load_derived_metrics(derived_dir=self.base_dir)
        self.assertEqual(metrics["unit_tests"], "NOT_RECORDED")
        self.assertEqual(metrics["synthetic_tests"], "NOT_RECORDED")
        self.assertEqual(metrics["total_tests"], "NOT_RECORDED")
        self.assertIsNone(metrics["test_run_metadata"])

    def test_valid_test_record_loads_metadata(self):
        """When test_run_record.json exists, metrics and provenance load directly from it."""
        attempts_csv = self.base_dir / "attempts.csv"
        attempts_csv.write_text("validity_category,classification\nVALID_LIVE,DIRECT_IPV6\n")
        s5_csv = self.base_dir / "s5_flow_dissection.csv"
        s5_csv.write_text("trial_id,family\nt1,IPv6\n")

        test_record = self.base_dir / "test_run_record.json"
        record_data = {
            "unit_tests": 788,
            "synthetic_tests": 93,
            "total_tests": 881,
            "unique_tests": 881,
            "duplicate_executions": 0,
            "tests_passed": 881,
            "tests_failed": 0,
            "tests_errors": 0,
            "focused_tests": 12,
            "test_command": "python3 -m unittest discover",
            "timestamp": "2026-11-14T12:00:00Z",
            "commit_sha": "a2b2c501386276b4f43837beb1d00270e4dc44a5",
            "environment": "linux-x86_64",
        }
        test_record.write_text(json.dumps(record_data))

        metrics = load_derived_metrics(derived_dir=self.base_dir, test_run_record_path=test_record)
        self.assertEqual(metrics["unit_tests"], 788)
        self.assertEqual(metrics["synthetic_tests"], 93)
        self.assertEqual(metrics["total_tests"], 881)
        self.assertEqual(metrics["tests_passed"], 881)
        self.assertIsNotNone(metrics["test_run_metadata"])
        self.assertEqual(metrics["test_run_metadata"]["commit_sha"], "a2b2c501386276b4f43837beb1d00270e4dc44a5")

    def test_scientific_presentation_claims_accuracy(self):
        """P1.8 & P1.6: Presentation deck and generator must avoid unsupported claims and qualify measurements."""
        repo_root = Path(__file__).resolve().parent.parent
        generator_file = repo_root / "lab" / "build_submission_report.py"
        deck_file = repo_root / "lab" / "derived" / "phase-c" / "presentation_deck.html"

        for file_path in (generator_file, deck_file):
            content = file_path.read_text(encoding="utf-8")
            self.assertNotIn(
                "microsecond delay injection",
                content,
                f"{file_path} must not claim unsupported microsecond delay injection",
            )
            self.assertNotIn(
                "Microsecond-Scale Dual-Stack Transport Racing",
                content,
                f"{file_path} must not claim unsupported microsecond transport racing",
            )
            self.assertNotIn(
                "aggressive sub-10ms fallback",
                content,
                f"{file_path} must not claim aggressive sub-10ms fallback as a standard deviation",
            )
            self.assertNotIn(
                "IPv6 Preference (§3):",
                content,
                f"{file_path} must not cite RFC 8305 §3 for IPv6 address preference",
            )
            self.assertIn(
                "Selected RFC 8305 Requirements Assessment",
                content,
                f"{file_path} must accurately describe work as selected requirements assessment",
            )
            self.assertIn(
                "IPv6 Preference (§2 / RFC 6724):",
                content,
                f"{file_path} must cite §2 and RFC 6724 for IPv6 preference",
            )
            self.assertIn(
                "nominal millisecond-valued per-family delay configuration",
                content,
                f"{file_path} must accurately qualify delay configuration",
            )
            self.assertIn(
                "Effective delay accuracy and scheduling jitter were not independently calibrated",
                content,
                f"{file_path} must note absence of independent microsecond calibration",
            )
            self.assertIn(
                "Packet observations included sub-10ms raw family-first-SYN offsets",
                content,
                f"{file_path} must preserve raw S2 observation context",
            )
            self.assertIn(
                "S2 remains NOT_ASSESSED against the 10ms mandatory floor",
                content,
                f"{file_path} must state S2 NOT_ASSESSED status",
            )
            self.assertNotIn(
                "881 unique",
                content.lower(),
                f"{file_path} must not contain outdated 881 unique tests claim",
            )
            self.assertNotIn(
                "866 passed",
                content.lower(),
                f"{file_path} must not contain outdated 866 passed tests claim",
            )
            self.assertNotIn(
                "4 failed",
                content.lower(),
                f"{file_path} must not contain outdated 4 failed tests claim",
            )
            self.assertNotIn(
                "11 errors",
                content.lower(),
                f"{file_path} must not contain outdated 11 errors claim",
            )
            self.assertNotIn(
                "788 in",
                content.lower(),
                f"{file_path} must not contain outdated 788 lab tests claim",
            )
            self.assertNotIn(
                "199 focused",
                content.lower(),
                f"{file_path} must not contain outdated 199 focused tests claim",
            )
            self.assertIn(
                "ee59362ac3f5",
                content,
                f"{file_path} must reference tested source commit ee59362ac3f5",
            )
            self.assertIn(
                "not configured",
                content.lower(),
                f"{file_path} must preserve explicit remote CI status as not configured / not recorded",
            )

        deck_content = deck_file.read_text(encoding="utf-8")
        self.assertIn(
            "929 unique",
            deck_content.lower(),
            "Presentation deck must document 929 unique automated tests",
        )
        self.assertIn(
            "805 in <code>lab/</code>",
            deck_content,
            "Presentation deck must document 805 lab unit tests",
        )
        self.assertIn(
            "93 in <code>tests/</code>",
            deck_content,
            "Presentation deck must document 93 integration tests",
        )
        self.assertIn(
            "31 frontend",
            deck_content,
            "Presentation deck must document 31 frontend unit tests",
        )
        self.assertIn(
            "16 static",
            deck_content.lower(),
            "Presentation deck must separate 16 static smoke checks",
        )
        self.assertIn(
            "53 assertions",
            deck_content.lower(),
            "Presentation deck must separate 53 browser assertions",
        )
        self.assertIn(
            "NOT CONFIGURED / NOT RECORDED",
            deck_content,
            "Presentation deck must explicitly state remote CI is NOT CONFIGURED / NOT RECORDED",
        )

        report_file = repo_root / "docs" / "PS028_FINAL_EXPERIMENTAL_REPORT.md"
        report_content = report_file.read_text(encoding="utf-8")
        self.assertIn(
            "601.045 ms — initial SYN to observed client final ACK transmission",
            report_content,
            "Final experimental report must use precise S4 final-ACK measurement terminology",
        )
        self.assertNotIn(
            "601.04 ms (handshake completion)",
            report_content,
            "Final experimental report must not equate wire timestamps with remote handshake completion",
        )



if __name__ == "__main__":
    unittest.main()
