#!/usr/bin/env python3
"""
Unit and regression tests for lab/build_technical_report_pdf.py.
Verifies markdown parsing, TOC extraction, HTML styling, fail-closed PDF validation,
and end-to-end PDF generation.
"""

import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from lab.build_technical_report_pdf import (
    GITHUB_REPO_BLOB_BASE,
    REPO_ROOT,
    SOURCE_MD,
    TARGET_PDF,
    VERIFIED_COMMIT_SHA,
    build_full_html_document,
    build_technical_report_pdf,
    convert_markdown_to_html,
    find_browser_executable,
    get_verified_commit_sha,
    resolve_portable_hyperlinks,
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

    def test_resolve_portable_hyperlinks_valid_repo_file(self):
        source_md = REPO_ROOT / "docs" / "test.md"
        html = '<p>See <a href="../lab/scenarios.yaml">scenarios</a> config.</p>'
        res = resolve_portable_hyperlinks(html, source_md, REPO_ROOT, commit_sha=VERIFIED_COMMIT_SHA)
        expected_url = f"{GITHUB_REPO_BLOB_BASE}/{VERIFIED_COMMIT_SHA}/lab/scenarios.yaml"
        self.assertIn(f'href="{expected_url}"', res)
        self.assertNotIn("file://", res)
        self.assertIn("scenarios</a>", res)

    def test_resolve_portable_hyperlinks_unmappable_path_stripped(self):
        source_md = REPO_ROOT / "docs" / "test.md"
        html = '<p>Missing <a href="../non_existent_dir/missing_file.py">source text</a> here.</p>'
        res = resolve_portable_hyperlinks(html, source_md, REPO_ROOT, commit_sha=VERIFIED_COMMIT_SHA)
        self.assertNotIn("<a ", res)
        self.assertNotIn("</a>", res)
        self.assertIn("source text", res)

    def test_resolve_portable_hyperlinks_preserves_external_and_anchors(self):
        source_md = REPO_ROOT / "docs" / "test.md"
        html = (
            '<p><a href="#executive-summary">TOC</a> and '
            '<a href="https://example.com/spec">Spec</a>.</p>'
        )
        res = resolve_portable_hyperlinks(html, source_md, REPO_ROOT, commit_sha=VERIFIED_COMMIT_SHA)
        self.assertIn('href="#executive-summary"', res)
        self.assertIn('href="https://example.com/spec"', res)

    def test_authoritative_report_and_pdf_have_zero_file_uris(self):
        # 1. Authoritative markdown source must contain zero relative file links
        md_text = SOURCE_MD.read_text(encoding="utf-8")
        rel_links = [
            m.group(2)
            for m in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", md_text)
            if not m.group(2).startswith("http") and not m.group(2).startswith("#")
        ]
        self.assertEqual(
            rel_links,
            [],
            f"SOURCE_MD should have 0 relative file links, found: {rel_links}",
        )

        # 2. Authoritative HTML must have zero file:// links
        _, _, body_html = convert_markdown_to_html(SOURCE_MD)
        self.assertNotIn('href="file://', body_html)

        # 3. Target PDF must exist and contain zero file:// URIs
        if TARGET_PDF.is_file():
            data = TARGET_PDF.read_bytes().decode("latin1", errors="replace")
            uris = re.findall(r"/URI\s*\((.*?)\)", data)
            file_uris = [u for u in uris if u.startswith("file:")]
            self.assertEqual(
                file_uris,
                [],
                f"TARGET_PDF must contain 0 file:// URIs, found: {file_uris}",
            )
            github_uris = [u for u in uris if "github.com" in u]
            self.assertEqual(
                len(github_uris),
                11,
                f"TARGET_PDF expected 11 GitHub URIs, found {len(github_uris)}: {github_uris}",
            )


if __name__ == "__main__":
    unittest.main()
