#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Technical Report PDF Generator
Fulfills Requirement #12, Milestone 5, and Work Package A specifications.

Authoritative Source: docs/PS028_FINAL_EXPERIMENTAL_REPORT.md
Output Target: PS028 Detailed Analysis & Report PDF.pdf
Temporary Artifacts: lab/derived/phase-c/technical_report.html
                     lab/derived/phase-c/technical_report.pdf

Generates an authoritative, publication-quality A4 academic PDF technical report
with offline KaTeX math rendering, professional typography, cover page,
auto-generated Table of Contents, running headers, and footers.
Enforces strict fail-closed validation before updating the root submission artifact.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_MD = REPO_ROOT / "docs" / "PS028_FINAL_EXPERIMENTAL_REPORT.md"
DERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"
TEMP_HTML = DERIVED_DIR / "technical_report.html"
TEMP_PDF = DERIVED_DIR / "technical_report.pdf"
TARGET_PDF = REPO_ROOT / "PS028 Detailed Analysis & Report PDF.pdf"

KATEX_DIR = REPO_ROOT / "lab" / "resources" / "katex"
KATEX_JS = KATEX_DIR / "katex.min.js"
KATEX_CSS = KATEX_DIR / "katex.min.css"
AUTO_RENDER_JS = KATEX_DIR / "auto-render.min.js"

MIN_REQUIRED_PAGES = 18
MIN_REQUIRED_BYTES = 400_000


def find_browser_executable() -> Optional[str]:
    """Detects available Google Chrome or Chromium binary."""
    candidates = [
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for cand in candidates:
        if Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    for name in ["google-chrome", "chromium", "chromium-browser"]:
        found = shutil.which(name)
        if found:
            return found
    return None


def convert_markdown_to_html(source_md_path: Path) -> Tuple[str, str, str]:
    """
    Renders markdown to HTML, extracts headings, builds TOC, and generates styled HTML.
    Uses markdown_it with table and strikethrough extensions.
    """
    if not source_md_path.is_file():
        raise FileNotFoundError(f"Source technical report markdown missing: {source_md_path}")

    text = source_md_path.read_text(encoding="utf-8")
    if not text.strip():
        raise ValueError(f"Source technical report markdown is empty: {source_md_path}")

    # Extract primary title from top H1
    title = "PS-028 Final Experimental Results and Validation Report"
    m_title = re.search(r"^#\s+(.+)$", text, re.M)
    if m_title:
        title = m_title.group(1).strip()
        text = re.sub(r"^#\s+.+\n+", "", text, count=1)

    try:
        from markdown_it import MarkdownIt
    except ImportError as e:
        raise RuntimeError("Required dependency 'markdown-it-py' is not installed.") from e

    md = MarkdownIt("commonmark").enable("table").enable("strikethrough")
    rendered_body = md.render(text)

    # Process H2 and H3 headings for IDs and TOC
    toc_items: List[Tuple[int, str, str]] = []
    slug_counts: Dict[str, int] = {}

    def heading_replacer(match: re.Match) -> str:
        tag = match.group(1)
        content = match.group(2)
        clean_text = re.sub(r"<[^>]+>", "", content).strip()
        base_slug = re.sub(r"[^a-zA-Z0-9_-]", "-", clean_text.lower()).strip("-")
        if not base_slug:
            base_slug = "section"
        count = slug_counts.get(base_slug, 0)
        slug_counts[base_slug] = count + 1
        slug = base_slug if count == 0 else f"{base_slug}-{count}"
        level = int(tag[1])
        toc_items.append((level, clean_text, slug))
        return f'<{tag} id="{slug}">{content}</{tag}>'

    rendered_body = re.sub(r"<(h[23])>(.*?)</\1>", heading_replacer, rendered_body)

    # Build TOC HTML
    toc_lines = [
        '<div class="toc-container">',
        '  <h2 class="toc-title">Table of Contents</h2>',
        '  <ul class="toc-list">',
    ]
    for level, htext, slug in toc_items:
        cls = "toc-item-h2" if level == 2 else "toc-item-h3"
        toc_lines.append(f'    <li class="{cls}"><a href="#{slug}">{htext}</a></li>')
    toc_lines.append("  </ul>")
    toc_lines.append("</div>")
    full_toc = "\n".join(toc_lines)

    return title, full_toc, rendered_body


def build_full_html_document(title: str, toc_html: str, body_html: str) -> str:
    """Combines CSS, vendored KaTeX, cover page, TOC, and body into standalone HTML."""
    katex_js_content = KATEX_JS.read_text(encoding="utf-8") if KATEX_JS.is_file() else ""
    katex_css_content = KATEX_CSS.read_text(encoding="utf-8") if KATEX_CSS.is_file() else ""
    auto_render_js_content = AUTO_RENDER_JS.read_text(encoding="utf-8") if AUTO_RENDER_JS.is_file() else ""

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>__TITLE__</title>
<style>
__KATEX_CSS__

@page {
    size: A4 portrait;
    margin: 22mm 16mm 22mm 16mm;
}

body {
    font-family: 'Liberation Serif', 'Times New Roman', Georgia, serif;
    font-size: 9.5pt;
    line-height: 1.5;
    color: #0f172a;
    margin: 0;
    padding: 0;
}

.cover-page {
    page-break-after: always;
    padding: 25mm 10mm 15mm 10mm;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    min-height: 230mm;
    border-top: 6px solid #1e3a8a;
}

.cover-badge {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 10pt;
    font-weight: 700;
    color: #1e3a8a;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.cover-title {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 23pt;
    font-weight: 800;
    color: #0f172a;
    line-height: 1.25;
    margin: 18px 0 12px 0;
}

.cover-subtitle {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 11pt;
    color: #334155;
    line-height: 1.45;
    margin-bottom: 25px;
}

.cover-meta-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 8.5pt;
    margin: 20px 0;
    background: #ffffff;
    border: 1px solid #cbd5e1;
}

.cover-meta-table td {
    padding: 7px 12px;
    border-bottom: 1px solid #e2e8f0;
}

.cover-meta-table td.label {
    font-weight: 600;
    color: #334155;
    width: 32%;
    background: #f1f5f9;
}

.toc-container {
    page-break-after: always;
    padding-top: 5mm;
}

.toc-title {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 15pt;
    font-weight: 700;
    color: #1e3a8a;
    border-bottom: 2px solid #1e3a8a;
    padding-bottom: 4px;
    margin-bottom: 12px;
}

.toc-list {
    list-style: none;
    padding-left: 0;
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 8.5pt;
    line-height: 1.55;
}

.toc-item-h2 {
    font-weight: 600;
    margin-top: 4px;
}

.toc-item-h2 a {
    color: #1e293b;
    text-decoration: none;
}

.toc-item-h3 {
    padding-left: 18px;
    color: #475569;
}

.toc-item-h3 a {
    color: #475569;
    text-decoration: none;
}

.content-body {
    padding-top: 5mm;
}

h2 {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 13pt;
    font-weight: 700;
    color: #1e3a8a;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 20pt;
    margin-bottom: 8pt;
    break-after: avoid;
}

h3 {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 10.5pt;
    font-weight: 600;
    color: #0f172a;
    margin-top: 14pt;
    margin-bottom: 6pt;
    break-after: avoid;
}

h4 {
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 9.5pt;
    font-weight: 600;
    color: #334155;
    margin-top: 10pt;
    margin-bottom: 4pt;
    break-after: avoid;
}

p {
    margin: 6pt 0;
    text-align: justify;
    text-justify: inter-word;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Liberation Sans', Arial, sans-serif;
    font-size: 7.5pt;
    line-height: 1.35;
    margin: 12pt 0;
    page-break-inside: auto;
}

tr {
    page-break-inside: avoid;
    page-break-after: auto;
}

th {
    background-color: #1e3a8a;
    color: #ffffff;
    font-weight: 600;
    text-align: left;
    padding: 5pt 6pt;
    border: 1px solid #1e3a8a;
}

td {
    padding: 4pt 6pt;
    border: 1px solid #cbd5e1;
    word-break: normal;
    overflow-wrap: break-word;
}

tr:nth-child(even) td {
    background-color: #f8fafc;
}

pre, code {
    font-family: 'Liberation Mono', 'Courier New', monospace;
    font-size: 8pt;
}

pre {
    background: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    padding: 8pt 10pt;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 8pt 0;
    page-break-inside: avoid;
}

p code, li code {
    background: #f1f5f9;
    padding: 1pt 3pt;
    border-radius: 3px;
    border: 1px solid #e2e8f0;
}

blockquote {
    border-left: 3px solid #3b82f6;
    background: #eff6ff;
    padding: 6pt 10pt;
    margin: 8pt 0;
    color: #1e3a8a;
    font-size: 9pt;
}

hr {
    border: 0;
    border-top: 1px solid #e2e8f0;
    margin: 16pt 0;
}

ul, ol {
    margin: 6pt 0;
    padding-left: 20pt;
}

li {
    margin-bottom: 3pt;
}
</style>
<script>
__KATEX_JS__
__AUTO_RENDER_JS__
</script>
</head>
<body>

<div class="cover-page">
    <div>
        <div class="cover-badge">AIORI-3 / PS-028 Internet Measurement Research</div>
        <div class="cover-title">__TITLE__</div>
        <div class="cover-subtitle">Dual-Stack Happy Eyeballs RFC 8305 Empirical Measurement, Connection Timing Dynamics and Cross-Browser Conformance Analysis</div>
        
        <table class="cover-meta-table">
            <tr><td class="label">Campaign Identifier</td><td><code>ps028-a10-live-20261030-01</code></td></tr>
            <tr><td class="label">Problem Statement</td><td>PS-028: Dual-Stack Happy Eyeballs RFC 8305 Measurement</td></tr>
            <tr><td class="label">Audited Completion Date</td><td>2026-10-30</td></tr>
            <tr><td class="label">Document Classification</td><td>Final Technical Validation Report (Work Package A10)</td></tr>
            <tr><td class="label">Authoritative Integration Branch</td><td><code>fix/phase-e-bundle-timeline-mapping</code></td></tr>
            <tr><td class="label">Evaluated Browsers</td><td>Google Chrome 156.0.8078.73 & Mozilla Firefox 159.0</td></tr>
            <tr><td class="label">Total Matrix Slots & Trials</td><td>280 Planned Slots, 280 Valid Live Trials, 2 Historical Exclusions</td></tr>
            <tr><td class="label">Problem Statement Compliance</td><td>17 MET, 2 PARTIAL, 1 PENDING (15/15 Core PS Requirements Met)</td></tr>
        </table>
    </div>
    
    <div style="font-family: 'Liberation Sans', Arial, sans-serif; font-size: 8pt; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 8px;">
        AIORI Hackathon 2026 &bull; Advanced Internet Operations & Research Institute &bull; Strictly Reproducible Offline Evidence
    </div>
</div>

__TOC__

<div class="content-body">
__BODY__
</div>

<script>
document.addEventListener("DOMContentLoaded", function() {
    if (typeof renderMathInElement === "function") {
        renderMathInElement(document.body, {
            delimiters: [
                {left: "$$", right: "$$", display: true},
                {left: "$", right: "$", display: false}
            ],
            throwOnError: false
        });
    }
});
</script>
</body>
</html>"""

    return (
        html_template
        .replace("__TITLE__", title)
        .replace("__KATEX_CSS__", katex_css_content)
        .replace("__KATEX_JS__", katex_js_content)
        .replace("__AUTO_RENDER_JS__", auto_render_js_content)
        .replace("__TOC__", toc_html)
        .replace("__BODY__", body_html)
    )


def compile_pdf_with_playwright(html_path: Path, output_pdf_path: Path, browser_bin: Optional[str]) -> bool:
    """Invokes Playwright via Node.js in setup/webtester to compile PDF with running headers/footers."""
    webtester_dir = REPO_ROOT / "setup" / "webtester"
    if not (webtester_dir / "node_modules" / "playwright").is_dir():
        return False

    node_script = """
const { chromium } = require('playwright');
const path = require('path');

(async () => {
    const htmlPath = process.argv[1];
    const pdfPath = process.argv[2];
    const chromeBin = process.argv[3];

    const launchOpts = { args: ['--no-sandbox', '--disable-gpu'] };
    if (chromeBin && chromeBin !== 'bundled' && chromeBin !== 'none') {
        launchOpts.executablePath = chromeBin;
    }

    const browser = await chromium.launch(launchOpts);
    const page = await browser.newPage();
    await page.goto('file://' + path.resolve(htmlPath), { waitUntil: 'networkidle' });

    await page.pdf({
        path: path.resolve(pdfPath),
        format: 'A4',
        margin: { top: '22mm', bottom: '22mm', left: '16mm', right: '16mm' },
        displayHeaderFooter: true,
        headerTemplate: '<div style="font-size: 7.5pt; color: #64748b; width: 100%; display: flex; justify-content: space-between; padding: 0 16mm; font-family: sans-serif;"><span>PS-028 Final Technical Validation Report</span><span>AIORI-3 Internet Measurement</span></div>',
        footerTemplate: '<div style="font-size: 7.5pt; color: #64748b; width: 100%; display: flex; justify-content: space-between; padding: 0 16mm; font-family: sans-serif;"><span>AIORI-3 PS-028 &bull; Hackathon Submission</span><span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>',
        printBackground: true
    });

    await browser.close();
})();
"""
    try:
        proc = subprocess.run(
            ["node", "-e", node_script, str(html_path), str(output_pdf_path), browser_bin or "bundled"],
            cwd=webtester_dir,
            capture_output=True,
            text=True,
            timeout=90,
        )
        return proc.returncode == 0 and output_pdf_path.is_file() and output_pdf_path.stat().st_size > 0
    except Exception as e:
        print(f"[WARN] Playwright PDF compilation exception: {e}", file=sys.stderr)
        return False


def compile_pdf_with_chrome_cli(html_path: Path, output_pdf_path: Path, browser_bin: str) -> bool:
    """Fallback compilation using Chrome headless CLI directly."""
    cmd = [
        browser_bin,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        f"--print-to-pdf={output_pdf_path}",
        str(html_path.resolve()),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return proc.returncode == 0 and output_pdf_path.is_file() and output_pdf_path.stat().st_size > 0
    except Exception as e:
        print(f"[WARN] Chrome CLI fallback exception: {e}", file=sys.stderr)
        return False


def validate_pdf_artifact(pdf_path: Path) -> Tuple[bool, int, int, str]:
    """
    Strict fail-closed PDF validation:
    - Verifies file exists.
    - Verifies size >= MIN_REQUIRED_BYTES.
    - Verifies page count >= MIN_REQUIRED_PAGES.
    - Verifies presence of PDF streams and required markers.
    """
    if not pdf_path.is_file():
        return False, 0, 0, f"File does not exist: {pdf_path}"

    file_size = pdf_path.stat().st_size
    if file_size < MIN_REQUIRED_BYTES:
        return False, file_size, 0, f"File size ({file_size:,} bytes) below threshold {MIN_REQUIRED_BYTES:,} bytes"

    content = pdf_path.read_bytes()
    if not content.startswith(b"%PDF-"):
        return False, file_size, 0, "Missing %PDF- header magic"

    pages = len(re.findall(rb"/Type\s*/Page\b", content))
    if pages < MIN_REQUIRED_PAGES:
        return False, file_size, pages, f"Page count ({pages}) below minimum required {MIN_REQUIRED_PAGES}"

    streams = len(re.findall(rb"stream\r?\n", content))
    if streams < 10:
        return False, file_size, pages, f"Stream count ({streams}) suspiciously low; empty document"

    return True, file_size, pages, "Validation successful"


def build_technical_report_pdf(target_path: Optional[Path] = None) -> int:
    """
    Main orchestration entry point:
    1. Converts docs/PS028_FINAL_EXPERIMENTAL_REPORT.md to styled HTML.
    2. Writes temporary HTML to lab/derived/phase-c/technical_report.html.
    3. Compiles PDF to lab/derived/phase-c/technical_report.pdf via Playwright / Chrome CLI.
    4. Validates temporary PDF strictly.
    5. Copies verified PDF to destination (default PS028 Detailed Analysis & Report PDF.pdf).
    """
    final_destination = target_path or TARGET_PDF
    print("================================================================================")
    print("PS-028 Milestone 5: Building Official Technical Validation Report PDF")
    print(f"Source Markdown: {SOURCE_MD}")
    print(f"Destination:     {final_destination}")
    print("================================================================================")

    # 1. Render Markdown to HTML
    title, toc_html, body_html = convert_markdown_to_html(SOURCE_MD)
    full_html = build_full_html_document(title, toc_html, body_html)

    DERIVED_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_HTML.write_text(full_html, encoding="utf-8")
    print(f"[OK] Generated report HTML: {TEMP_HTML} ({TEMP_HTML.stat().st_size:,} bytes)")

    # 2. Locate browser executable
    browser_bin = find_browser_executable()
    webtester_dir = REPO_ROOT / "setup" / "webtester"
    has_playwright = (webtester_dir / "node_modules" / "playwright").is_dir()
    if not browser_bin and not has_playwright:
        print("[ERROR] Neither Google Chrome/Chromium nor Playwright found in environment.", file=sys.stderr)
        return 1
    if browser_bin:
        print(f"[INFO] Using browser binary: {browser_bin}")
    else:
        print("[INFO] No host Chrome binary found; relying on Playwright bundled Chromium")

    # 3. Clean any existing temporary PDF
    if TEMP_PDF.exists():
        TEMP_PDF.unlink()

    # 4. Compile PDF (Playwright first, Chrome CLI fallback)
    print("[INFO] Attempting PDF compilation with Playwright running headers/footers...")
    success = compile_pdf_with_playwright(TEMP_HTML, TEMP_PDF, browser_bin)
    if not success and browser_bin:
        print("[INFO] Playwright unavailable or failed; using Chrome CLI fallback...")
        success = compile_pdf_with_chrome_cli(TEMP_HTML, TEMP_PDF, browser_bin)

    if not success or not TEMP_PDF.is_file():
        print("[ERROR] PDF compilation failed on all available engines.", file=sys.stderr)
        return 1

    # 5. Strictly validate temporary PDF
    valid, size, pages, msg = validate_pdf_artifact(TEMP_PDF)
    if not valid:
        print(f"[ERROR] PDF validation failed: {msg}", file=sys.stderr)
        return 1
    print(f"[OK] Temporary PDF validated: {TEMP_PDF} ({size:,} bytes, {pages} pages)")

    # 6. Safely copy to final target
    shutil.copyfile(TEMP_PDF, final_destination)
    print(f"[SUCCESS] Official technical report PDF generated: {final_destination} ({final_destination.stat().st_size:,} bytes, {pages} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(build_technical_report_pdf())
