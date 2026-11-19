#!/usr/bin/env python3
"""
PS-028 Deterministic Markdown Relative Link and Target Checker

Inspects specified Markdown files for internal relative links (filesystem paths
and intra-document heading fragments). Reports file and line locations of any broken
targets. Ignores external URLs (http/https/mailto) by default.

Exit code 0 on all links valid; non-zero if broken links are discovered.
Non-destructive: read-only inspection.
"""

import sys
import re
import urllib.parse
from pathlib import Path

DEFAULT_FILES = [
    "README.md",
    "docs/README.md",
    "docs/PS028_REPRODUCIBILITY_RUNBOOK.md",
    "docs/phase-e/README.md",
    "setup/webtester/README.md",
    "src/README.md",
]

LINK_REGEX = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')
HEADING_REGEX = re.compile(r'^(#{1,6})\s+(.*)$', re.MULTILINE)


def github_slugify(heading_text: str) -> str:
    """Derive GitHub-compatible fragment slug from heading text."""
    # Remove markdown formatting, inline links, code backticks
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', heading_text)
    text = text.replace('`', '').strip().lower()
    # Replace whitespace and characters not allowed in GitHub anchor
    text = re.sub(r'[^\w\s-]', '', text)
    slug = re.sub(r'[-\s]+', '-', text).strip('-')
    return slug


def extract_headings(content: str) -> set[str]:
    """Extract set of heading slugs from markdown content."""
    slugs = set()
    for match in HEADING_REGEX.finditer(content):
        heading_text = match.group(2).strip()
        slug = github_slugify(heading_text)
        if slug:
            slugs.add(slug)
    return slugs


def check_markdown_file(file_path: Path, repo_root: Path) -> list[str]:
    """Check a single markdown file for broken internal links and anchors."""
    errors = []
    if not file_path.is_file():
        return [f"[MISSING SOURCE FILE] {file_path}"]

    content = file_path.read_text(encoding="utf-8")
    headings = extract_headings(content)
    base_dir = file_path.parent

    lines = content.splitlines()
    for line_num, line in enumerate(lines, start=1):
        for match in LINK_REGEX.finditer(line):
            text = match.group(1)
            raw_url = match.group(2).strip()

            # Ignore external protocols and non-navigational links
            if raw_url.startswith(("http://", "https://", "mailto:", "ftp://", "javascript:")):
                continue

            # Split path and fragment
            parts = raw_url.split("#", 1)
            rel_path_str = parts[0].strip()
            fragment = parts[1].strip() if len(parts) > 1 else ""

            # Check intra-document fragment link (#heading)
            if not rel_path_str:
                if fragment and fragment not in headings:
                    # Some markdown anchors may have slightly different slug rules;
                    # check normalized lower-case match
                    clean_frag = fragment.lower().strip()
                    if clean_frag not in {h.lower() for h in headings}:
                        errors.append(
                            f"{file_path}:{line_num}: broken anchor #{fragment} in [{text}]({raw_url})"
                        )
                continue

            # Decode URL-encoded characters (e.g. %20 -> space)
            decoded_path = urllib.parse.unquote(rel_path_str)
            target_path = (base_dir / decoded_path).resolve()

            if not target_path.exists():
                errors.append(
                    f"{file_path}:{line_num}: missing target '{target_path.relative_to(repo_root) if target_path.is_relative_to(repo_root) else target_path}' in [{text}]({raw_url})"
                )
            elif fragment and target_path.is_file() and target_path.suffix.lower() == ".md":
                # If target is another markdown file, check its fragment
                target_content = target_path.read_text(encoding="utf-8")
                target_headings = extract_headings(target_content)
                clean_frag = fragment.lower().strip()
                if clean_frag not in {h.lower() for h in target_headings}:
                    errors.append(
                        f"{file_path}:{line_num}: broken anchor #{fragment} in target {target_path.name} in [{text}]({raw_url})"
                    )

    return errors


def main():
    repo_root = Path(__file__).resolve().parent.parent
    files_to_check = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_FILES

    all_errors = []
    checked_count = 0

    print("=" * 80)
    print("PS-028 Deterministic Markdown Relative Link & Target Checker")
    print(f"Repository Root: {repo_root}")
    print("=" * 80)

    for file_str in files_to_check:
        target_file = (repo_root / file_str).resolve()
        checked_count += 1
        errors = check_markdown_file(target_file, repo_root)
        if errors:
            all_errors.extend(errors)
            print(f"[FAIL] {file_str}: {len(errors)} broken link(s)")
            for err in errors:
                print(f"       -> {err}")
        else:
            print(f"[PASS] {file_str}")

    print("=" * 80)
    if all_errors:
        print(f"[ERROR] Found {len(all_errors)} broken link(s) across {checked_count} file(s).")
        sys.exit(1)
    else:
        print(f"[SUCCESS] All internal relative links and targets verified across {checked_count} file(s).")
        sys.exit(0)


if __name__ == "__main__":
    main()
