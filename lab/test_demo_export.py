#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Demonstration Export Security & Fidelity Tests
Verifies spreadsheet formula-injection mitigation, numeric preservation, and path
containment defenses for lab/demo_export.py.
"""

import json
from pathlib import Path
import tempfile
import unittest

from lab.demo_export import (
    sanitize_formula_injection,
    validate_safe_path,
    filter_trials,
    export_trials_csv,
    export_trials_json,
    load_demo_bundle,
    DEFAULT_BUNDLE_PATH,
)


class TestDemoExportSecurity(unittest.TestCase):
    """Test suite for security sanitization and path validation in demo_export.py."""

    def test_formula_injection_sanitization_on_strings(self):
        """Formula trigger characters on untrusted non-numeric strings must be prefixed with single quote."""
        malicious_inputs = [
            "=SUM(A1:A10)",
            "+cmd|' /C calc'!A0",
            "-2+3+cmd",
            "@SUM(1,2)",
            "\tTAB_INJECTION",
            "\rCR_INJECTION",
        ]
        for inp in malicious_inputs:
            sanitized = sanitize_formula_injection(inp)
            self.assertTrue(
                sanitized.startswith("'"),
                f"Input {inp!r} was not sanitized! Result: {sanitized!r}",
            )
            self.assertEqual(sanitized[1:], inp)

    def test_formula_injection_sanitization_with_leading_whitespace_and_control_chars(self):
        """Correction 3: Strings with leading whitespace or control characters before formula triggers must be escaped."""
        malicious_inputs = [
            "   =SUM(A1:A10)",
            " \t=1+1",
            "\t=CMD()",
            "\r+cmd|' /C calc'!A0",
            " \x00=calc",
            "   @SUM(1,2)",
            "\n-2+3+cmd",
            "  \r\n=1337",
        ]
        for inp in malicious_inputs:
            sanitized = sanitize_formula_injection(inp)
            self.assertTrue(
                sanitized.startswith("'"),
                f"Input with leading whitespace/control chars {inp!r} was not sanitized! Result: {sanitized!r}",
            )
            self.assertEqual(sanitized[1:], inp)

        # Confirm legitimate numbers with leading whitespace are NOT escaped
        numeric_with_ws = [
            "  -10.5",
            "\t+42.0",
            "   0",
            " \n-5.25",
        ]
        for num_str in numeric_with_ws:
            sanitized = sanitize_formula_injection(num_str)
            self.assertFalse(
                str(sanitized).startswith("'"),
                f"Numeric string {num_str!r} with whitespace was falsely escaped! Result: {sanitized!r}",
            )

    def test_numeric_values_preserved_without_string_coercion(self):
        """Legitimate numbers (including negative numbers and floats) must NOT be escaped."""
        numeric_inputs = [
            -10,
            -10.5,
            0,
            0.0,
            250.75,
            "-5.25",
            "-0.71",
            "+10.0",
            "100",
        ]
        for num in numeric_inputs:
            sanitized = sanitize_formula_injection(num)
            if isinstance(num, (int, float)):
                self.assertEqual(sanitized, num, f"Numeric {num} was altered!")
                self.assertIsInstance(sanitized, (int, float))
            else:
                self.assertFalse(
                    str(sanitized).startswith("'"),
                    f"Numeric string {num!r} was falsely escaped as formula! Result: {sanitized!r}",
                )

    def test_path_containment_valid_subpaths(self):
        """Paths within allowed root must pass validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            valid_dest = validate_safe_path("sub/folder/file.csv", root)
            self.assertTrue(str(valid_dest).startswith(str(root.resolve())))

    def test_path_containment_directory_traversal_rejected(self):
        """Path traversal outside allowed root must raise PermissionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "exports"
            root.mkdir()
            with self.assertRaises(PermissionError):
                validate_safe_path("../outside.csv", root)
            with self.assertRaises(PermissionError):
                validate_safe_path("../../etc/passwd", root)

    def test_path_containment_symlink_escape_rejected(self):
        """Correction 3: Symlink pointing outside allowed root must raise PermissionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            allowed_root = tmp_path / "allowed_root"
            outside_dir = tmp_path / "outside_dir"
            allowed_root.mkdir()
            outside_dir.mkdir()

            # Create symlink inside allowed_root that points outside
            symlink_inside = allowed_root / "evil_symlink"
            symlink_inside.symlink_to(outside_dir)

            with self.assertRaises(PermissionError):
                validate_safe_path("evil_symlink/target.csv", allowed_root)

    def test_path_containment_protected_directories_rejected(self):
        """Correction 3: Attempts to target lab/campaigns or lab/derived/phase-c must be rejected."""
        repo_root = Path(__file__).resolve().parent.parent
        campaigns_dir = repo_root / "lab" / "campaigns"
        phase_c_dir = repo_root / "lab" / "derived" / "phase-c"

        with self.assertRaises(PermissionError):
            validate_safe_path("overwrite.pcap", campaigns_dir)

        with self.assertRaises(PermissionError):
            validate_safe_path("overwrite.csv", phase_c_dir)

        # Also verify absolute target pointing into protected directory from any root is blocked
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            with self.assertRaises(PermissionError):
                validate_safe_path(campaigns_dir / "ps028-a10-live-20261030-01" / "capture.pcap", temp_root)
            with self.assertRaises(PermissionError):
                validate_safe_path(phase_c_dir / "attempts.csv", temp_root)


class TestDemoExportFidelity(unittest.TestCase):
    """Test export filtering and output fidelity."""

    @classmethod
    def setUpClass(cls):
        cls.bundle = load_demo_bundle(DEFAULT_BUNDLE_PATH)
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.out_dir = Path(cls.temp_dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_filter_by_scenario_and_browser(self):
        """Filtering by scenario and browser isolates the exact 20 cohort trials."""
        trials = filter_trials(
            self.bundle["trials"],
            scenario="S1",
            browser="google-chrome",
        )
        self.assertEqual(len(trials), 20)
        for t in trials:
            self.assertEqual(t["scenario_id"], "S1")
            self.assertEqual(t["browser"], "google-chrome")

    def test_filter_by_trial_id(self):
        """Filtering by trial ID returns exactly one trial."""
        target_id = "trial-20261029205425-6cb90a54"
        trials = filter_trials(self.bundle["trials"], trial_id=target_id)
        self.assertEqual(len(trials), 1)
        self.assertEqual(trials[0]["trial_id"], target_id)

    def test_csv_export_structure(self):
        """CSV export must write valid header and exact row count."""
        trials = filter_trials(self.bundle["trials"], scenario="S0", browser="firefox")
        dest = self.out_dir / "s0_firefox.csv"
        export_trials_csv(trials, dest)
        self.assertTrue(dest.is_file())

        lines = dest.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 21)  # 1 header + 20 trials
        header = lines[0].split(",")
        self.assertIn("connection_attempt_delay_ms", header)
        self.assertIn("t_connect_ms", header)

    def test_json_export_numeric_preservation(self):
        """JSON export must preserve numbers as JSON numbers."""
        trials = filter_trials(self.bundle["trials"], scenario="S0", browser="google-chrome")
        dest = self.out_dir / "s0_chrome.json"
        export_trials_json(trials, dest)
        self.assertTrue(dest.is_file())

        with open(dest, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data), 20)
        first = data[0]
        self.assertIsInstance(first["metrics"]["t_connect_ms"], (int, float))


if __name__ == "__main__":
    unittest.main()
