#!/usr/bin/env python3
"""
Unit and regression tests for lab/build_submission_report.py
Validates Workstream G (Audit Finding #12): Fail-closed behavior for scientific evidence.
"""

import json
import tempfile
import unittest
from pathlib import Path

from lab.build_submission_report import (
    generate_presentation_html,
    load_derived_metrics,
    parse_p1_validation_record,
)


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
            "805 lab",
            deck_content,
            "Presentation deck must document 805 lab unit tests",
        )
        self.assertIn(
            "93 integration",
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
            "53-assertion",
            deck_content.lower(),
            "Presentation deck must separate 53 browser assertions",
        )
        self.assertIn(
            "not configured",
            deck_content.lower(),
            "Presentation deck must explicitly state remote CI is not configured / not recorded",
        )
        self.assertIn(
            "P1 validation snapshot",
            deck_content,
            "Presentation deck stat card must display dated P1 snapshot caption",
        )
        self.assertIn(
            "14 Nov 2026 · ee59362ac3f5",
            deck_content,
            "Presentation deck stat card must display date and commit",
        )
        self.assertIn(
            "SYN blackholing (S1) and IPv6 TCP RST rejection (S2)",
            deck_content,
            "Slide 2 must contain concise S1 and S2 fallback findings",
        )
        self.assertIn(
            "delayed AAAA DNS (S6, 500 ms)",
            deck_content,
            "Slide 2 must contain concise S6 DNS findings",
        )

        for m_str in ("M1", "M2 (Batch C1)", "M3 (C2 & C4)", "M4 (Batch C5)", "M5 (C3 & C6)", "M6 (Phase D)", "M7 (Phase E)"):
            self.assertIn(m_str, deck_content, f"Presentation deck must display {m_str}")

        p1_record_file = repo_root / "docs" / "phase-cd" / "p1-validation-record-2026-11-14.md"
        p1_record_content = p1_record_file.read_text(encoding="utf-8")
        self.assertIn(
            "Total Unique Automated Tests",
            p1_record_content,
            "P1 validation record must name the aggregate category 'Total Unique Automated Tests'",
        )
        self.assertNotIn(
            "Total Automated Unit Definitions",
            p1_record_content,
            "P1 validation record must not call the aggregate 'Total Automated Unit Definitions'",
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

    # --------------------------------------------------------------------------
    # Workstream Issue #12: Strict Fail-Closed P1 Validation Record Tests
    # --------------------------------------------------------------------------

    def _write_valid_p1_record(self, p1_path: Path, **overrides) -> Path:
        tested_sha = overrides.get("commit_sha", "ee59362ac3f53fad3bc01e65b5d90815697a93d4")
        lab_counts = overrides.get("lab", (805, 805, 0, 0, 0))
        int_counts = overrides.get("int", (93, 93, 0, 0, 0))
        fe_counts = overrides.get("fe", (31, 31, 0, 0, 0))
        tot_counts = overrides.get("tot", (929, 929, 0, 0, 0))
        smoke_str = overrides.get("smoke", "(16/16 checks verified; 0 failures)")
        browser_str = overrides.get("browser", "(8/8 stages passed; 53 assertions verified; 0 errors)")
        ci_str = overrides.get("ci", "Local validation completed; remote GitHub CI is not configured or recorded.")

        raw_table = overrides.get("raw_table")
        if raw_table is None:
            table_content = (
                "| Tier | Test Command | Module / File Scope | Discovered | Passed | Failed | Errors | Skipped | Duration |\n"
                "|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n"
                f"| **Python Lab Unit & Regression** | `lab` | 21 modules | **{lab_counts[0]}** | **{lab_counts[1]}** | {lab_counts[2]} | {lab_counts[3]} | {lab_counts[4]} | 43.79s |\n"
                f"| **Python Integration Tier** | `tests` | 2 modules | **{int_counts[0]}** | **{int_counts[1]}** | {int_counts[2]} | {int_counts[3]} | {int_counts[4]} | 0.35s |\n"
                f"| **Frontend Unit Tests** | `fe` | 1 module | **{fe_counts[0]}** | **{fe_counts[1]}** | {fe_counts[2]} | {fe_counts[3]} | {fe_counts[4]} | 0.67s |\n"
                f"| **Total Unique Automated Tests** | Disaggregated | Unique Tier | **{tot_counts[0]}** | **{tot_counts[1]}** | **{tot_counts[2]}** | **{tot_counts[3]}** | **{tot_counts[4]}** | **44.81s** |\n"
            )
        else:
            table_content = raw_table

        content = (
            f"# PS-028 Happy Eyeballs — P1 Validation Record (14 November 2026)\n\n"
            f"- **Tested P1 Source Commit SHA:** `{tested_sha}`\n"
            f"- **GitHub CI Status:** {ci_str}\n\n"
            f"{table_content}\n\n"
            f"### Static Smoke\n\n- Status: PASSED {smoke_str}\n\n"
            f"### Browser Acceptance\n\n- Status: PASSED {browser_str}\n"
        )
        p1_path.write_text(content, encoding="utf-8")
        return p1_path

    def test_missing_p1_validation_record_fails_closed(self):
        """Missing P1 validation record must raise FileNotFoundError, not substitute fallbacks."""
        nonexistent = self.base_dir / "nonexistent_p1_record.md"
        with self.assertRaises(FileNotFoundError) as ctx:
            parse_p1_validation_record(nonexistent)
        self.assertIn("nonexistent_p1_record.md", str(ctx.exception))

    def test_empty_p1_validation_record_fails_closed(self):
        """Empty P1 validation record must raise ValueError."""
        p1_file = self.base_dir / "empty_p1.md"
        p1_file.write_text("")
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("empty", str(ctx.exception).lower())

    def test_missing_tested_source_commit_sha_fails_closed(self):
        """P1 record missing Tested P1 Source Commit SHA must fail closed."""
        p1_file = self.base_dir / "missing_commit.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        # Remove commit line
        content = "\n".join(l for l in content.splitlines() if "Tested P1 Source Commit SHA" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Tested P1 Source Commit SHA", str(ctx.exception))

    def test_missing_lab_count_fails_closed(self):
        """P1 record missing lab count table row must fail closed."""
        p1_file = self.base_dir / "missing_lab.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        content = "\n".join(l for l in content.splitlines() if "Python Lab Unit & Regression" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Python Lab Unit & Regression", str(ctx.exception))

    def test_missing_integration_count_fails_closed(self):
        """P1 record missing integration tier table row must fail closed."""
        p1_file = self.base_dir / "missing_int.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        content = "\n".join(l for l in content.splitlines() if "Python Integration Tier" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Python Integration Tier", str(ctx.exception))

    def test_missing_frontend_count_fails_closed(self):
        """P1 record missing frontend unit tests table row must fail closed."""
        p1_file = self.base_dir / "missing_fe.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        content = "\n".join(l for l in content.splitlines() if "Frontend Unit Tests" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Frontend Unit Tests", str(ctx.exception))

    def test_missing_total_test_count_fails_closed(self):
        """P1 record missing total unique tests table row must fail closed."""
        p1_file = self.base_dir / "missing_tot.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        content = "\n".join(l for l in content.splitlines() if "Total Unique Automated Tests" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Total Unique Automated Tests", str(ctx.exception))

    def test_missing_passed_count_fails_closed(self):
        """P1 record with missing passed count in table row must fail closed."""
        p1_file = self.base_dir / "missing_passed.md"
        bad_table = (
            "| Tier | Test Command | Module / File Scope | Discovered | Passed | Failed | Errors | Skipped | Duration |\n"
            "|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n"
            "| **Python Lab Unit & Regression** | `lab` | 21 modules | **805** |  | 0 | 0 | 0 | 43.79s |\n"
            "| **Python Integration Tier** | `tests` | 2 modules | **93** | **93** | 0 | 0 | 0 | 0.35s |\n"
            "| **Frontend Unit Tests** | `fe` | 1 module | **31** | **31** | 0 | 0 | 0 | 0.67s |\n"
            "| **Total Unique Automated Tests** | Disaggregated | Unique Tier | **929** | **929** | **0** | **0** | **0** | **44.81s** |\n"
        )
        self._write_valid_p1_record(p1_file, raw_table=bad_table)
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Missing Passed count", str(ctx.exception))

    def test_missing_failed_error_skip_counts_fails_closed(self):
        """P1 record with missing failed/error/skip columns must fail closed."""
        p1_file = self.base_dir / "missing_cols.md"
        bad_table = (
            "| Tier | Test Command | Discovered | Passed |\n"
            "|:---|:---|:---:|:---:|\n"
            "| **Python Lab Unit & Regression** | `lab` | **805** | **805** |\n"
            "| **Python Integration Tier** | `tests` | **93** | **93** |\n"
            "| **Frontend Unit Tests** | `fe` | **31** | **31** |\n"
            "| **Total Unique Automated Tests** | Disaggregated | **929** | **929** |\n"
        )
        self._write_valid_p1_record(p1_file, raw_table=bad_table)
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Malformed table row", str(ctx.exception))

    def test_non_integer_counts_fails_closed(self):
        """P1 record containing non-integer count values must fail closed."""
        p1_file = self.base_dir / "non_integer.md"
        bad_table = (
            "| Tier | Test Command | Module / File Scope | Discovered | Passed | Failed | Errors | Skipped | Duration |\n"
            "|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n"
            "| **Python Lab Unit & Regression** | `lab` | 21 modules | **eight_hundred** | **805** | 0 | 0 | 0 | 43.79s |\n"
            "| **Python Integration Tier** | `tests` | 2 modules | **93** | **93** | 0 | 0 | 0 | 0.35s |\n"
            "| **Frontend Unit Tests** | `fe` | 1 module | **31** | **31** | 0 | 0 | 0 | 0.67s |\n"
            "| **Total Unique Automated Tests** | Disaggregated | Unique Tier | **929** | **929** | **0** | **0** | **0** | **44.81s** |\n"
        )
        self._write_valid_p1_record(p1_file, raw_table=bad_table)
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Invalid non-integer or negative", str(ctx.exception))

    def test_negative_counts_fails_closed(self):
        """P1 record containing negative count values must fail closed."""
        p1_file = self.base_dir / "negative_count.md"
        bad_table = (
            "| Tier | Test Command | Module / File Scope | Discovered | Passed | Failed | Errors | Skipped | Duration |\n"
            "|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|\n"
            "| **Python Lab Unit & Regression** | `lab` | 21 modules | **805** | **805** | -1 | 0 | 0 | 43.79s |\n"
            "| **Python Integration Tier** | `tests` | 2 modules | **93** | **93** | 0 | 0 | 0 | 0.35s |\n"
            "| **Frontend Unit Tests** | `fe` | 1 module | **31** | **31** | 0 | 0 | 0 | 0.67s |\n"
            "| **Total Unique Automated Tests** | Disaggregated | Unique Tier | **929** | **929** | **0** | **0** | **0** | **44.81s** |\n"
        )
        self._write_valid_p1_record(p1_file, raw_table=bad_table)
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Invalid non-integer or negative", str(ctx.exception))

    def test_inconsistent_category_sum_fails_closed(self):
        """When lab + integration + frontend != total, parser must fail closed."""
        p1_file = self.base_dir / "inconsistent_sum.md"
        # Total set to 999 while 805 + 93 + 31 = 929
        self._write_valid_p1_record(
            p1_file,
            lab=(805, 805, 0, 0, 0),
            int=(93, 93, 0, 0, 0),
            fe=(31, 31, 0, 0, 0),
            tot=(999, 999, 0, 0, 0),
        )
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Arithmetic inconsistency", str(ctx.exception))

    def test_inconsistent_pass_fail_error_skip_sum_fails_closed(self):
        """When passed + failed + errors + skipped != discovered, parser must fail closed."""
        p1_file = self.base_dir / "inconsistent_row_sum.md"
        # Lab discovered=805, but passed=800, failed=0, errors=0, skipped=0 (sums to 800)
        self._write_valid_p1_record(
            p1_file,
            lab=(805, 800, 0, 0, 0),
            tot=(929, 924, 0, 0, 0),
        )
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("breakdown does not sum to discovered count", str(ctx.exception))

    def test_malformed_markdown_table_fails_closed(self):
        """Malformed markdown table with corrupted rows must fail closed."""
        p1_file = self.base_dir / "malformed_table.md"
        p1_file.write_text(
            "# P1 Record\n\n"
            "- **Tested P1 Source Commit SHA:** `ee59362ac3f53fad3bc01e65b5d90815697a93d4`\n"
            "- **GitHub CI Status:** NOT CONFIGURED\n\n"
            "| not a real table row\n"
        )
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Missing required table row", str(ctx.exception))

    def test_missing_smoke_test_metadata_fails_closed(self):
        """Missing static smoke test metadata must fail closed."""
        p1_file = self.base_dir / "missing_smoke.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        content = "\n".join(l for l in content.splitlines() if "checks verified" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("smoke verification metadata", str(ctx.exception).lower())

    def test_missing_browser_stage_metadata_fails_closed(self):
        """Missing browser acceptance metadata must fail closed."""
        p1_file = self.base_dir / "missing_browser.md"
        self._write_valid_p1_record(p1_file)
        content = p1_file.read_text(encoding="utf-8")
        content = "\n".join(l for l in content.splitlines() if "stages passed" not in l)
        p1_file.write_text(content, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("browser acceptance metadata", str(ctx.exception).lower())

    def test_record_with_only_historical_commit_no_results_fails_closed(self):
        """A record that contains only the historical commit SHA but no test counts must fail closed."""
        p1_file = self.base_dir / "commit_only.md"
        p1_file.write_text(
            "# PS-028 P1 Validation Record\n\n"
            "- **Tested P1 Source Commit SHA:** `ee59362ac3f53fad3bc01e65b5d90815697a93d4`\n"
            "- **GitHub CI Status:** Local validation completed\n"
        )
        with self.assertRaises(ValueError) as ctx:
            parse_p1_validation_record(p1_file)
        self.assertIn("Missing required table row", str(ctx.exception))

    def test_renderer_invoked_with_incomplete_metrics_fails_closed(self):
        """generate_presentation_html must fail closed when validation keys are missing, never defaulting to 929."""
        incomplete_metrics = {
            "valid_live": 280,
            "direct_ipv6": 154,
            "fallback_ipv4": 126,
            # Missing all p1_* metrics
        }
        with self.assertRaises(KeyError) as ctx:
            generate_presentation_html(incomplete_metrics)
        self.assertIn("Required P1 validation metric", str(ctx.exception))

    def test_valid_historical_p1_record_produces_dated_snapshot(self):
        """Valid historical P1 validation record parses exact counts without substitution."""
        p1_file = self.base_dir / "valid_p1.md"
        self._write_valid_p1_record(p1_file)
        metrics = parse_p1_validation_record(p1_file)

        self.assertEqual(metrics["p1_commit_sha"], "ee59362ac3f53fad3bc01e65b5d90815697a93d4")
        self.assertEqual(metrics["p1_lab_tests"], 805)
        self.assertEqual(metrics["p1_integration_tests"], 93)
        self.assertEqual(metrics["p1_frontend_tests"], 31)
        self.assertEqual(metrics["p1_total_tests"], 929)
        self.assertEqual(metrics["p1_unique_tests"], 929)
        self.assertEqual(metrics["p1_tests_passed"], 929)
        self.assertEqual(metrics["p1_tests_failed"], 0)
        self.assertEqual(metrics["p1_tests_errors"], 0)
        self.assertEqual(metrics["p1_tests_skipped"], 0)
        self.assertEqual(metrics["p1_static_smoke_checks"], 16)
        self.assertEqual(metrics["p1_browser_stages"], 8)
        self.assertEqual(metrics["p1_browser_assertions"], 53)
        self.assertIn("not configured", metrics["p1_ci_status"].lower())



if __name__ == "__main__":
    unittest.main()
