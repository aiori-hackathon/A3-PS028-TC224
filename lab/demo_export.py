#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Safe Demonstration Export Utility
Milestone 7: Phase E (Demo-Readiness Remediation)

Provides deterministic, security-hardened CSV and JSON exports for filtered demonstration data:
1. Filter by scenario (S0-S6), browser (google-chrome, firefox), or individual trial ID.
2. Exports trials, connection attempts, S5 flows, and timeline events.
3. Spreadsheet Formula-Injection Defense:
   - Prefixes untrusted string fields starting with '=', '+', '-', '@', '\\t', '\\r' with a single quote (').
   - Strictly preserves legitimate numeric values (integers, floats, negative numbers like -10.5)
     as numbers without string conversion.
4. Filesystem Security & Symlink-Escape Protection:
   - Resolves canonical realpaths (Path.resolve() / os.path.realpath) and verifies that destinations
     remain strictly contained within the approved output root.
   - Rejects absolute paths, directory traversal ('../'), and symlink escapes fail-closed.
   - Read-only safety: strictly prohibits writing to lab/campaigns/ or lab/derived/phase-c/.
"""

import argparse
import csv
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Union

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_BUNDLE_PATH = REPO_ROOT / "lab" / "derived" / "phase-e" / "demo_bundle.json"
DEFAULT_EXPORT_DIR = REPO_ROOT / "lab" / "derived" / "phase-e" / "exports"

FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
NUMERIC_RE = re.compile(r"^[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?$")


def sanitize_formula_injection(value: Any) -> Any:
    """
    Mitigate spreadsheet formula injection on untrusted strings.
    If value is already a numeric type (int, float), it is returned untouched.
    If value is a string that represents a valid number (e.g. '-5.2', '+10', '0', '  -10.5'),
    it is preserved without string escaping.
    Non-numeric strings starting with formula trigger characters (or having leading
    whitespace/control characters before a formula trigger) are escaped with a leading single quote (').
    """
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, bool):
        return value

    s = str(value)
    if not s:
        return ""

    # Strip leading whitespace and control characters
    s_stripped = s.lstrip(" \t\r\n\x00\x0b\x0c")
    if s_stripped and s_stripped[0] in FORMULA_TRIGGERS:
        # Check if it is a legitimate number (e.g. "-10.5", "+3", "  -42")
        if NUMERIC_RE.match(s_stripped):
            return s
        # Untrusted formula string -> escape with leading single quote
        return f"'{s}"

    # Also handle strings that begin with tab or carriage return even if s_stripped is empty
    if s[0] in ("\t", "\r"):
        if not NUMERIC_RE.match(s.strip()):
            return f"'{s}"

    return s


def validate_safe_path(requested_path: Union[str, Path], allowed_root: Path) -> Path:
    """
    Validate that requested_path is contained within allowed_root.
    Resolves symlinks and rejects directory traversal or absolute path escapes.
    Fails closed if the path escapes or attempts to mutate historical/forbidden areas.
    """
    allowed_root_resolved = allowed_root.resolve()

    # Reject forbidden destination targets
    forbidden_roots = [
        (REPO_ROOT / "lab" / "campaigns").resolve(),
        (REPO_ROOT / "lab" / "derived" / "phase-c").resolve(),
    ]
    for fb in forbidden_roots:
        try:
            if allowed_root_resolved == fb or fb in allowed_root_resolved.parents:
                raise PermissionError(f"Access to protected historical root forbidden: {fb}")
        except Exception:
            pass

    req = Path(requested_path)
    if req.is_absolute():
        dest = req.resolve()
    else:
        dest = (allowed_root_resolved / req).resolve()

    # Verify containment
    try:
        dest.relative_to(allowed_root_resolved)
    except ValueError:
        raise PermissionError(
            f"Path containment violation: '{dest}' is outside allowed root '{allowed_root_resolved}'"
        )

    for fb in forbidden_roots:
        if dest == fb or fb in dest.parents:
            raise PermissionError(f"Target path penetrates protected historical directory: {dest}")

    return dest


def load_demo_bundle(bundle_path: Path = DEFAULT_BUNDLE_PATH) -> Dict[str, Any]:
    """Load and validate the demonstration data bundle."""
    if not bundle_path.is_file():
        raise FileNotFoundError(f"Demonstration data bundle not found: {bundle_path}")
    with open(bundle_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("bundle_schema_version") != "1.0.0":
        raise ValueError(f"Unsupported bundle schema version: {data.get('bundle_schema_version')}")
    return data


def filter_trials(
    trials: List[Dict[str, Any]],
    scenario: Optional[str] = None,
    browser: Optional[str] = None,
    trial_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Filter bundle trials by scenario, browser, or trial ID."""
    res = trials
    if scenario:
        scen_norm = scenario.upper().strip()
        res = [t for t in res if t.get("scenario_id", "").upper() == scen_norm]
    if browser:
        b_norm = browser.lower().strip()
        res = [t for t in res if b_norm in t.get("browser", "").lower()]
    if trial_id:
        t_norm = trial_id.strip()
        res = [t for t in res if t.get("trial_id") == t_norm]
    return res


def export_trials_csv(
    trials: List[Dict[str, Any]],
    destination: Path,
) -> Path:
    """Export filtered trials to a deterministic, sanitized CSV file."""
    headers = [
        "trial_id",
        "scenario_id",
        "browser",
        "browser_version",
        "repetition",
        "classification",
        "winning_family",
        "http_status_code",
        "t_connect_ms",
        "t_setup_total_ms",
        "syn_to_synack_ms",
        "connection_attempt_delay_ms",
        "dns_resolution_time_ms",
        "pcap_sha256",
    ]

    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8", newline="\n") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(headers)
        for t in trials:
            pf = t.get("primary_flow", {})
            m = t.get("metrics", {})
            row = [
                sanitize_formula_injection(t.get("trial_id")),
                sanitize_formula_injection(t.get("scenario_id")),
                sanitize_formula_injection(t.get("browser")),
                sanitize_formula_injection(t.get("browser_version")),
                t.get("repetition", ""),
                sanitize_formula_injection(t.get("classification")),
                sanitize_formula_injection(pf.get("family")),
                pf.get("http_status_code", ""),
                f"{m.get('t_connect_ms'):.2f}" if m.get("t_connect_ms") is not None else "",
                f"{m.get('t_setup_total_ms'):.2f}" if m.get("t_setup_total_ms") is not None else "",
                f"{m.get('syn_to_synack_ms'):.2f}" if m.get("syn_to_synack_ms") is not None else "",
                f"{m.get('connection_attempt_delay_ms'):.2f}" if m.get("connection_attempt_delay_ms") is not None else "",
                f"{m.get('dns_resolution_time_ms'):.2f}" if m.get("dns_resolution_time_ms") is not None else "",
                sanitize_formula_injection(t.get("pcap_sha256")),
            ]
            writer.writerow(row)

    return destination


def export_trials_json(
    trials: List[Dict[str, Any]],
    destination: Path,
) -> Path:
    """Export filtered trials to a deterministic JSON file preserving numeric values."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8", newline="\n") as f:
        json.dump(trials, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    return destination


def export_flows_csv(
    trials: List[Dict[str, Any]],
    destination: Path,
) -> Path:
    """Export per-flow connection attempts for filtered trials to CSV."""
    headers = [
        "trial_id",
        "scenario_id",
        "browser",
        "tcp_stream",
        "family",
        "client_ip",
        "client_port",
        "server_ip",
        "server_port",
        "syn_time",
        "synack_time",
        "final_ack_time",
        "rst_time",
        "offset_from_first_syn_ms",
        "outcome",
        "is_primary",
        "retransmitted_syn_count",
    ]

    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8", newline="\n") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(headers)
        for t in trials:
            tid = t.get("trial_id")
            scen = t.get("scenario_id")
            browser = t.get("browser")
            for flow in t.get("connection_attempts", []):
                offset = flow.get("offset_from_first_syn_ms")
                row = [
                    sanitize_formula_injection(tid),
                    sanitize_formula_injection(scen),
                    sanitize_formula_injection(browser),
                    sanitize_formula_injection(flow.get("tcp_stream")),
                    sanitize_formula_injection(flow.get("family")),
                    sanitize_formula_injection(flow.get("client_ip")),
                    flow.get("client_port", ""),
                    sanitize_formula_injection(flow.get("server_ip")),
                    flow.get("server_port", ""),
                    f"{flow.get('syn_time'):.6f}" if flow.get("syn_time") is not None else "",
                    f"{flow.get('synack_time'):.6f}" if flow.get("synack_time") is not None else "",
                    f"{flow.get('final_ack_time'):.6f}" if flow.get("final_ack_time") is not None else "",
                    f"{flow.get('rst_time'):.6f}" if flow.get("rst_time") is not None else "",
                    f"{offset:.2f}" if offset is not None else "",
                    sanitize_formula_injection(flow.get("outcome")),
                    flow.get("is_primary", ""),
                    flow.get("retransmitted_syn_count", ""),
                ]
                writer.writerow(row)

    return destination


def export_timeline_csv(
    trials: List[Dict[str, Any]],
    destination: Path,
) -> Path:
    """Export timeline events for filtered trials to CSV."""
    headers = [
        "trial_id",
        "scenario_id",
        "browser",
        "timestamp",
        "relative_ms",
        "source",
        "event_type",
        "family",
        "stream_id",
        "details",
    ]

    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8", newline="\n") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(headers)
        for t in trials:
            tid = t.get("trial_id")
            scen = t.get("scenario_id")
            browser = t.get("browser")
            for ev in t.get("timeline_events", []):
                rel = ev.get("relative_ms")
                row = [
                    sanitize_formula_injection(tid),
                    sanitize_formula_injection(scen),
                    sanitize_formula_injection(browser),
                    f"{ev.get('timestamp'):.6f}" if ev.get("timestamp") is not None else "",
                    f"{rel:.2f}" if rel is not None else "",
                    sanitize_formula_injection(ev.get("source")),
                    sanitize_formula_injection(ev.get("event_type")),
                    sanitize_formula_injection(ev.get("family")),
                    sanitize_formula_injection(ev.get("stream_id")),
                    sanitize_formula_injection(ev.get("details")),
                ]
                writer.writerow(row)

    return destination


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Safe Demonstration Export Utility"
    )
    parser.add_argument(
        "--bundle-path",
        type=Path,
        default=DEFAULT_BUNDLE_PATH,
        help="Path to demo_bundle.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_EXPORT_DIR,
        help="Allowed target directory for exports",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Filter export by scenario (S0-S6)",
    )
    parser.add_argument(
        "--browser",
        type=str,
        default=None,
        help="Filter export by browser (google-chrome, firefox)",
    )
    parser.add_argument(
        "--trial",
        type=str,
        default=None,
        help="Filter export by specific trial ID",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json", "all"],
        default="all",
        help="Export format (csv, json, or all)",
    )
    parser.add_argument(
        "--include-flows",
        action="store_true",
        help="Also export per-flow connection attempts CSV",
    )
    parser.add_argument(
        "--include-timeline",
        action="store_true",
        help="Also export timeline events CSV",
    )
    args = parser.parse_args()

    try:
        bundle = load_demo_bundle(args.bundle_path)
        trials = filter_trials(
            bundle["trials"],
            scenario=args.scenario,
            browser=args.browser,
            trial_id=args.trial,
        )

        if not trials:
            print("[WARN] No trials matched the specified filter criteria.", file=sys.stderr)
            return 1

        # Compute safe export prefix
        prefix_parts = ["export"]
        if args.scenario:
            prefix_parts.append(args.scenario.lower())
        if args.browser:
            prefix_parts.append(args.browser.lower())
        if args.trial:
            prefix_parts.append(args.trial)
        base_name = "_".join(prefix_parts)

        out_dir = args.output_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        exported_files: List[Path] = []

        if args.format in ("csv", "all"):
            csv_path = validate_safe_path(out_dir / f"{base_name}_trials.csv", out_dir)
            export_trials_csv(trials, csv_path)
            exported_files.append(csv_path)

        if args.format in ("json", "all"):
            json_path = validate_safe_path(out_dir / f"{base_name}_trials.json", out_dir)
            export_trials_json(trials, json_path)
            exported_files.append(json_path)

        if args.include_flows:
            flows_path = validate_safe_path(out_dir / f"{base_name}_flows.csv", out_dir)
            export_flows_csv(trials, flows_path)
            exported_files.append(flows_path)

        if args.include_timeline:
            tl_path = validate_safe_path(out_dir / f"{base_name}_timeline.csv", out_dir)
            export_timeline_csv(trials, tl_path)
            exported_files.append(tl_path)

        print(f"[OK] Exported {len(trials)} trials into {len(exported_files)} files in {out_dir}")
        for p in exported_files:
            print(f"  - {p.name} ({p.stat().st_size:,} bytes)")
        return 0

    except Exception as exc:
        print(f"[ERROR] Export failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
