#!/usr/bin/env python3
"""
Unit and regression tests for lab/build_technical_report_pdf.py.
Verifies markdown parsing, TOC extraction, HTML styling, fail-closed PDF validation,
and end-to-end PDF generation.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from lab.build_technical_report_pdf import (
    REPO_ROOT,
    SOURCE_MD,
    TARGET_PDF,
    build_full_html_document,
    build_technical_report_pdf,
    convert_markdown_to_html,
    find_browser_executable,
    validate_pdf_artifact,
)


class TestBuildTechnicalReportPDF(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ps028_pdf_test_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_browser_executable_detected(self):
        browser_bin = find_browser_executable()
        self.assertIsNotNone(browser_bin, "Chrome/Chromium binary should be detected in test environment")
        self.assertTrue(Path(browser_bin).is_file(), f"Detected browser {browser_bin} must exist")

    def test_convert_markdown_to_html_authoritative(self):
        title, toc_html, body_html = convert_markdown_to_html(SOURCE_MD)
        self.assertIn("PS-028", title)
        self.assertIn('<div class="toc-container">', toc_html)
        self.assertIn("Executive Summary", toc_html)
        self.assertIn("Happy Eyeballs", toc_html)
        self.assertIn("<table", body_html)
        self.assertIn('id="1--executive-summary"', body_html)

    def test_convert_markdown_to_html_missing_file_fails_closed(self):
        non_existent = Path(self.temp_dir) / "does_not_exist.md"
        with self.assertRaises(FileNotFoundError):
            convert_markdown_to_html(non_existent)

    def test_convert_markdown_to_html_empty_file_fails_closed(self):
        empty_md = Path(self.temp_dir) / "empty.md"
        empty_md.write_text("   \n", encoding="utf-8")
        with self.assertRaises(ValueError):
            convert_markdown_to_html(empty_md)

    def test_build_full_html_document_structure(self):
        title = "Test Technical Report"
        toc = '<div class="toc-container"><ul><li>Item</li></ul></div>'
        body = "<h2>Section</h2><p>Body text with $E = mc^2$.</p>"
        html = build_full_html_document(title, toc, body)

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn(title, html)
        self.assertIn(toc, html)
        self.assertIn(body, html)
        self.assertIn("katex", html.lower())
        self.assertIn("renderMathInElement", html)
        self.assertIn("@page {", html)

    def test_validate_pdf_artifact_nonexistent(self):
        fake_pdf = Path(self.temp_dir) / "nonexistent.pdf"
        valid, size, pages, msg = validate_pdf_artifact(fake_pdf)
        self.assertFalse(valid)
        self.assertIn("does not exist", msg)

    def test_validate_pdf_artifact_too_small(self):
        small_pdf = Path(self.temp_dir) / "small.pdf"
        small_pdf.write_bytes(b"%PDF-1.4 header but only 100 bytes long" + b"0" * 50)
        valid, size, pages, msg = validate_pdf_artifact(small_pdf)
        self.assertFalse(valid)
        self.assertIn("below threshold", msg)

    def test_validate_pdf_artifact_not_a_pdf(self):
        bad_magic_pdf = Path(self.temp_dir) / "bad_magic.pdf"
        bad_magic_pdf.write_bytes(b"NOT_A_PDF" * 50000)
        valid, size, pages, msg = validate_pdf_artifact(bad_magic_pdf)
        self.assertFalse(valid)
        self.assertIn("Missing %PDF- header magic", msg)

    def test_validate_pdf_artifact_too_few_pages(self):
        few_pages_pdf = Path(self.temp_dir) / "few_pages.pdf"
        # Create a file > 400KB with only 2 page objects
        content = b"%PDF-1.4\n" + b"/Type /Page\n" * 2 + b"stream\nendstream\n" * 15 + b"x" * 450000
        few_pages_pdf.write_bytes(content)
        valid, size, pages, msg = validate_pdf_artifact(few_pages_pdf)
        self.assertFalse(valid)
        self.assertIn("below minimum required", msg)

    def test_build_technical_report_pdf_end_to_end(self):
        temp_target = Path(self.temp_dir) / "test_report_output.pdf"
        ret = build_technical_report_pdf(target_path=temp_target)
        self.assertEqual(ret, 0, "build_technical_report_pdf should succeed with exit code 0")
        self.assertTrue(temp_target.is_file(), "Generated PDF target must exist")

        valid, size, pages, msg = validate_pdf_artifact(temp_target)
        self.assertTrue(valid, f"Generated PDF validation failed: {msg}")
        self.assertGreaterEqual(pages, 18, "Report must be at least 18 pages")
        self.assertGreaterEqual(size, 400_000, "Report must be at least 400KB")


if __name__ == "__main__":
    unittest.main()
