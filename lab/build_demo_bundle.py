#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Deterministic Demonstration Data Bundle Builder
Milestone 7: Phase E (Demo-Readiness Remediation)

Generates schema-versioned, deterministic, byte-identical demonstration datasets:
1. lab/derived/phase-e/demo_bundle.json
   - Authoritative campaign metadata and environment specifications.
   - Scenario definitions (S0-S6) and browser cohorts (Chrome 156, Firefox 159).
   - 280 valid live trials with primary flow, connection attempts, timeline events, and metrics.
   - Canonical metric key preservation: 'connection_attempt_delay_ms' (CAD).
   - Separate view of the 2 preserved CLEANUP_FAILURE exclusions (never mixed with empirical trials).
   - Statistical summaries (median, IQR, p95, sample size, null counts and reasons) stratified by cohort.
   - Assessment checks from RFC 8305.
2. lab/derived/phase-e/demo_bundle.json.provenance.json
   - Amendment A13 compliant sibling provenance sidecar recording source input SHA-256 digests.
   - Zero volatile timestamps or machine-specific paths in scientific data payload or sidecar.
3. lab/derived/phase-e/metric_registry.json
   - Comprehensive machine-readable metric specifications derived from docs/phase-c-metric-contract.md.

Guarantees:
- Strict Phase D simulation exclusion: rejects lab/derived/phase-d/ inputs fail-closed.
- Deterministic byte-identical outputs on repeated execution.
- Native JSON numeric preservation (no float-to-string coercion in JSON).
- Strict fail-closed reconciliation against authoritative Phase C sources.
"""

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.analyze import (
    compute_continuous_stats,
    compute_percentile,
    TrialValidity,
    FallbackClassification,
)

DEFAULT_CAMPAIGN_DIR = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
DEFAULT_PHASE_C_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "lab" / "derived" / "phase-e"

BUNDLE_SCHEMA_VERSION = "1.0.0"
REGISTRY_SCHEMA_VERSION = "1.1.0"

EXPECTED_ATTEMPTS_COUNT = 282
EXPECTED_VALID_LIVE_COUNT = 280
EXPECTED_EXCLUSIONS_COUNT = 2
EXPECTED_TCP_FLOWS_COUNT = 765
EXPECTED_S5_FLOWS_COUNT = 95
EXPECTED_TIMELINE_EVENTS_COUNT = 28330
EXPECTED_COHORTS_COUNT = 14
EXPECTED_TRIALS_PER_COHORT = 20

CANONICAL_SCENARIOS = {
    "S0": {
        "scenario_id": "S0",
        "name": "healthy_baseline",
        "title": "S0: Dual-Stack Baseline",
        "description": "IPv4 and IPv6 RTT ~20ms; A and AAAA immediate; healthy control reference.",
        "controlled_condition": "Both paths available and healthy; IPv6 preferred per RFC 6724.",
        "target_family": "IPv6",
        "expected_fallback": False,
    },
    "S1": {
        "scenario_id": "S1",
        "name": "ipv6_syn_blackhole",
        "title": "S1: IPv6 SYN Blackhole",
        "description": "IPv6 TCP SYN silently dropped; client waits for CAD timer then connects over IPv4.",
        "controlled_condition": "Client-to-server IPv6 TCP SYN packets dropped via router nftables.",
        "target_family": "IPv4",
        "expected_fallback": True,
    },
    "S2": {
        "scenario_id": "S2",
        "name": "ipv6_tcp_rst",
        "title": "S2: IPv6 TCP RST Active Failure",
        "description": "IPv6 TCP SYN actively rejected with TCP RST; triggers fallback to IPv4.",
        "controlled_condition": "IPv6 TCP SYN rejected with immediate TCP RST via router nftables.",
        "target_family": "IPv4",
        "expected_fallback": True,
    },
    "S3": {
        "scenario_id": "S3",
        "name": "ipv6_rtt_150ms",
        "title": "S3: Moderate IPv6 Latency (150ms RTT)",
        "description": "IPv6 path has 150ms RTT; IPv4 has 20ms RTT; IPv6 completes before CAD timeout.",
        "controlled_condition": "75ms delay added in each direction on IPv6 link via tc netem.",
        "target_family": "IPv6",
        "expected_fallback": False,
    },
    "S4": {
        "scenario_id": "S4",
        "name": "ipv6_rtt_600ms",
        "title": "S4: Asymmetric Latency (600ms RTT)",
        "description": "IPv6 path has 600ms RTT; IPv4 attempt launched at CAD timer finishes first.",
        "controlled_condition": "300ms delay added in each direction on IPv6 link via tc netem.",
        "target_family": "IPv4",
        "expected_fallback": True,
    },
    "S5": {
        "scenario_id": "S5",
        "name": "ipv6_syn_loss_50pct",
        "title": "S5: 50% Random IPv6 SYN Loss",
        "description": "50% random loss on IPv6 TCP SYN; tests retransmission behavior and fallback racing.",
        "controlled_condition": "50% probability drop rule on initial IPv6 TCP SYN via router nftables.",
        "target_family": "DUAL_RACING",
        "expected_fallback": None,
    },
    "S6": {
        "scenario_id": "S6",
        "name": "delay_aaaa_500ms",
        "title": "S6: Delayed AAAA DNS Resolution (500ms)",
        "description": "A response is immediate; AAAA response delayed 500ms; tests DNS Resolution Delay.",
        "controlled_condition": "DNS authoritative server delays AAAA responses by 500ms.",
        "target_family": "IPv6",
        "expected_fallback": False,
    },
}

CANONICAL_BROWSERS = {
    "google-chrome": {
        "browser_id": "google-chrome",
        "name": "Google Chrome",
        "version": "156.0.8078.73",
        "display_name": "Google Chrome 156.0.8078.73",
    },
    "firefox": {
        "browser_id": "firefox",
        "name": "Mozilla Firefox",
        "version": "159.0",
        "display_name": "Mozilla Firefox 159.0",
    },
}

METRIC_REGISTRY = {
    "schema_version": REGISTRY_SCHEMA_VERSION,
    "governing_specification": "docs/phase-c-metric-contract.md",
    "vantage_point": "ps028-cl:ps028-cl-rt",
    "metrics": {
        "t_connect_ms": {
            "canonical_name": "t_connect_ms",
            "display_label": "Primary TCP Connect Time",
            "category": "PRIMARY",
            "unit": "ms",
            "definition": "Elapsed time from initial SYN to matching client final ACK on primary stream (RFC 9293 §3.5)",
            "mathematical_formula": "(t_final_ack,primary - t_initial_syn,primary) * 1000",
            "applicability": "All valid primary HTTP flows",
            "null_reasons": [
                "INDETERMINATE_NO_SYN",
                "INDETERMINATE_NO_SYNACK",
                "INDETERMINATE_NO_FINAL_ACK",
                "INDETERMINATE_NO_PRIMARY_FLOW",
            ],
            "limitations": "Measures transport handshake only; does not include application request/response transfer.",
        },
        "t_setup_total_ms": {
            "canonical_name": "t_setup_total_ms",
            "display_label": "Total Connection Setup Time",
            "category": "PRIMARY",
            "unit": "ms",
            "definition": "Elapsed time from first target-host SYN of any family to matching final ACK of primary stream",
            "mathematical_formula": "(t_final_ack,primary - min(t_first_syn,IPv4, t_first_syn,IPv6)) * 1000",
            "applicability": "All trials with completed primary HTTP flow",
            "null_reasons": [
                "INDETERMINATE_NO_PRIMARY_FLOW",
            ],
            "limitations": "Headline metric for user-visible fallback latency cost; includes CAD stall.",
        },
        "syn_to_synack_ms": {
            "canonical_name": "syn_to_synack_ms",
            "display_label": "Diagnostic SYN-to-SYN/ACK Interval",
            "category": "DIAGNOSTIC",
            "unit": "ms",
            "definition": "Elapsed time from primary initial SYN to matching server SYN/ACK segment",
            "mathematical_formula": "(t_synack,primary - t_initial_syn,primary) * 1000",
            "applicability": "Primary stream where server returned SYN/ACK",
            "null_reasons": [
                "INDETERMINATE_NO_SYNACK",
            ],
            "limitations": "Diagnostic proxy for network path RTT; historical legacy connection setup metric.",
        },
        "connection_attempt_delay_ms": {
            "canonical_name": "connection_attempt_delay_ms",
            "display_label": "Connection Attempt Delay (CAD)",
            "category": "PRIMARY",
            "unit": "ms",
            "definition": "Observed interval between initial IPv6 SYN and subsequent initial IPv4 SYN (RFC 8305 §5)",
            "mathematical_formula": "(t_first_syn,IPv4 - t_first_syn,IPv6) * 1000",
            "applicability": "Dual-stack connection racing where both IPv6 and IPv4 were initiated",
            "null_reasons": [
                "NOT_APPLICABLE_HEALTHY_PATH",
                "INVALID_FAMILY_CHRONOLOGY",
                "INDETERMINATE_NO_SYN",
            ],
            "limitations": "Defined only when IPv6 precedes IPv4; null when primary IPv6 wins without race.",
        },
        "dns_query_to_first_payload_ms": {
            "canonical_name": "dns_query_to_first_payload_ms",
            "display_label": "DNS Query to First Payload",
            "category": "DIAGNOSTIC",
            "unit": "ms",
            "definition": "Elapsed time from earliest DNS query (A or AAAA) to first server payload byte on primary stream",
            "mathematical_formula": "(t_first_payload,primary - min(t_query,A, t_query,AAAA)) * 1000",
            "applicability": "Trials with paired DNS and server application payload",
            "null_reasons": [
                "INDETERMINATE_UNPAIRABLE_DNS",
                "INDETERMINATE_NO_PAYLOAD",
            ],
            "limitations": "Covers full application readiness from name resolution start.",
        },
        "dns_last_positive_response_to_first_payload_ms": {
            "canonical_name": "dns_last_positive_response_to_first_payload_ms",
            "display_label": "Last DNS Response to First Payload",
            "category": "DIAGNOSTIC",
            "unit": "ms",
            "definition": "Elapsed time from latest positive DNS response to first server payload byte",
            "mathematical_formula": "(t_first_payload,primary - max(t_resp,A, t_resp,AAAA)) * 1000",
            "applicability": "Trials with positive DNS responses and server application payload",
            "null_reasons": [
                "INDETERMINATE_UNPAIRABLE_DNS",
                "INDETERMINATE_NO_PAYLOAD",
            ],
            "limitations": "Measures connection establishment and HTTP turnaround excluding resolution wait.",
        },
        "dns_resolution_time_ms": {
            "canonical_name": "dns_resolution_time_ms",
            "display_label": "Composite DNS Resolution Time",
            "category": "DIAGNOSTIC",
            "unit": "ms",
            "definition": "Total elapsed time across DNS transactions from earliest query to latest response",
            "mathematical_formula": "(max(t_resp,A, t_resp,AAAA) - min(t_query,A, t_query,AAAA)) * 1000",
            "applicability": "Paired DNS transactions",
            "null_reasons": [
                "INDETERMINATE_UNPAIRABLE_DNS",
            ],
            "limitations": "Encompasses both A and AAAA query/response windows.",
        },
        "dns_latency_a_ms": {
            "canonical_name": "dns_latency_a_ms",
            "display_label": "IPv4 (A) Resolution Latency",
            "category": "DIAGNOSTIC",
            "unit": "ms",
            "definition": "Elapsed duration for IPv4 A query/response transaction",
            "mathematical_formula": "(t_resp,A - t_query,A) * 1000",
            "applicability": "Paired IPv4 A DNS queries",
            "null_reasons": [
                "INDETERMINATE_UNPAIRABLE_DNS",
            ],
            "limitations": "Single-family resolution time.",
        },
        "dns_latency_aaaa_ms": {
            "canonical_name": "dns_latency_aaaa_ms",
            "display_label": "IPv6 (AAAA) Resolution Latency",
            "category": "DIAGNOSTIC",
            "unit": "ms",
            "definition": "Elapsed duration for IPv6 AAAA query/response transaction",
            "mathematical_formula": "(t_resp,AAAA - t_query,AAAA) * 1000",
            "applicability": "Paired IPv6 AAAA DNS queries",
            "null_reasons": [
                "INDETERMINATE_UNPAIRABLE_DNS",
            ],
            "limitations": "Reflects configured S6 DNS impairment delay.",
        },
    },
}


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 digest of a local file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def get_git_commit_sha(repo_root: Path, script_rel: Optional[str] = "lab/build_demo_bundle.py") -> str:
    """Retrieve generator git commit SHA without volatile timestamps."""
    if script_rel:
        try:
            proc = subprocess.run(
                ["git", "log", "-n", "1", "--pretty=format:%H", "--", script_rel],
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=True,
            )
            sha = proc.stdout.strip()
            if sha:
                return sha
        except Exception:
            pass
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def parse_float_or_none(val: Any) -> Optional[float]:
    """Parse float without truthiness fallback, preserving valid 0.0."""
    if val is None:
        return None
    val_str = str(val).strip()
    if val_str == "" or val_str.lower() == "none" or val_str.lower() == "null":
        return None
    try:
        f = float(val_str)
        return f if math.isfinite(f) else None
    except (ValueError, TypeError):
        return None


def parse_int_or_none(val: Any) -> Optional[int]:
    """Parse int preserving valid 0."""
    if val is None:
        return None
    val_str = str(val).strip()
    if val_str == "" or val_str.lower() == "none" or val_str.lower() == "null":
        return None
    try:
        return int(float(val_str))
    except (ValueError, TypeError):
        return None


def validate_strict_positive_int(val: Any, field_name: str, trial_id: str = "") -> int:
    """
    Strict integer validation for evidence frame identifiers.
    Rejects:
    - None
    - Booleans (True / False)
    - Floating point values (e.g. 10.9, 10.0)
    - Non-numeric strings (e.g. 'abc', '')
    - Strings containing decimal points (e.g. '10.9', '10.0')
    - Values <= 0
    Returns int > 0.
    """
    prefix = f"Trial {trial_id} " if trial_id else ""
    if val is None:
        raise ValueError(f"{prefix}{field_name} is missing or None")
    if isinstance(val, bool):
        raise ValueError(f"{prefix}{field_name} cannot be a boolean: {val}")
    if isinstance(val, float):
        raise ValueError(f"{prefix}{field_name} cannot be a floating-point number: {val}")
    if isinstance(val, int):
        if val <= 0:
            raise ValueError(f"{prefix}{field_name} must be a positive integer (> 0), got {val}")
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if not re.fullmatch(r"[0-9]+", val_str):
            raise ValueError(f"{prefix}{field_name} must be a positive integer string, got '{val}'")
        val_int = int(val_str)
        if val_int <= 0:
            raise ValueError(f"{prefix}{field_name} must be a positive integer (> 0), got {val_int}")
        return val_int
    raise ValueError(f"{prefix}{field_name} has invalid type {type(val).__name__}: {val}")


def validate_strict_http_status(val: Any, field_name: str, trial_id: str = "", expected_status: int = 200) -> int:
    """
    Strict integer validation for HTTP status code in evidence.
    Rejects:
    - None
    - Booleans (True / False)
    - Floating point values (e.g. 200.0, 200.9)
    - Non-numeric strings (e.g. 'abc', '')
    - Strings containing decimal points (e.g. '200.0')
    - Any status code other than expected_status (default 200)
    Returns int (200).
    """
    prefix = f"Trial {trial_id} " if trial_id else ""
    if val is None:
        raise ValueError(f"{prefix}{field_name} is missing or None")
    if isinstance(val, bool):
        raise ValueError(f"{prefix}{field_name} cannot be a boolean: {val}")
    if isinstance(val, float):
        raise ValueError(f"{prefix}{field_name} cannot be a floating-point number: {val}")
    if isinstance(val, int):
        if val != expected_status:
            raise ValueError(
                f"{prefix}{field_name} must be {expected_status}, got {val}"
            )
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if not re.fullmatch(r"[0-9]+", val_str):
            raise ValueError(
                f"{prefix}{field_name} must be a valid integer string, got '{val}'"
            )
        val_int = int(val_str)
        if val_int != expected_status:
            raise ValueError(
                f"{prefix}{field_name} must be {expected_status}, got {val_int}"
            )
        return val_int
    raise ValueError(f"{prefix}{field_name} has invalid type {type(val).__name__}: {val}")


VALID_SUCCESSFUL_CLASSIFICATIONS: Dict[str, str] = {
    "DIRECT_IPV6": "IPv6",
    "DIRECT_IPV4": "IPv4",
    "IPV6_TO_IPV4_FALLBACK": "IPv4",
    "IPV4_TO_IPV6_FALLBACK": "IPv6",
}


def validate_strict_repetition(val: Any, field_name: str, trial_id: str = "") -> int:
    """
    Strict integer validation for trial repetition identity.
    Enforces campaign repetition range: 1..20.
    Rejects:
    - None
    - Booleans (True / False)
    - Floating point values (e.g. 10.5, 10.0)
    - Non-numeric strings (e.g. 'abc', '')
    - Strings containing decimal points (e.g. '10.5', '10.0')
    - Values < 1 or > 20 (including 0, negative values, and values above 20)
    Returns int in range 1..20.
    """
    prefix = f"Trial {trial_id} " if trial_id else ""
    if val is None:
        raise ValueError(f"{prefix}{field_name} is missing or None")
    if isinstance(val, bool):
        raise ValueError(f"{prefix}{field_name} cannot be a boolean: {val}")
    if isinstance(val, float):
        raise ValueError(f"{prefix}{field_name} cannot be a floating-point number: {val}")
    if isinstance(val, int):
        if val < 1 or val > 20:
            raise ValueError(f"{prefix}{field_name} must be an integer between 1 and 20, got {val}")
        return val
    if isinstance(val, str):
        val_str = val.strip()
        if not re.fullmatch(r"[0-9]+", val_str):
            raise ValueError(f"{prefix}{field_name} must be a valid integer string, got '{val}'")
        val_int = int(val_str)
        if val_int < 1 or val_int > 20:
            raise ValueError(f"{prefix}{field_name} must be an integer between 1 and 20, got {val_int}")
        return val_int
    raise ValueError(f"{prefix}{field_name} has invalid type {type(val).__name__}: {val}")


TRIAL_ID_PATTERN = re.compile(r"trial-\d{14}-[0-9a-f]{8}")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def parse_canonical_checksum_manifest(checksum_file: Path) -> Dict[str, str]:
    """
    Parse campaign_dir/pcap_sha256_checksums.txt into a trial-ID-to-digest mapping.
    Fails closed on missing file, malformed lines, non-64-hex digests, missing trial IDs,
    or duplicate conflicting entries.
    """
    if not checksum_file.is_file():
        raise FileNotFoundError(f"Canonical checksum manifest missing: {checksum_file}")

    manifest: Dict[str, str] = {}
    with open(checksum_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(
                    f"Malformed checksum line {line_no} in {checksum_file}: '{line}'"
                )
            digest, path_str = parts[0].strip().lower(), parts[1].strip()
            if not HEX64_RE.match(digest):
                raise ValueError(
                    f"Malformed SHA-256 digest on line {line_no} in {checksum_file}: '{digest}'"
                )
            match = TRIAL_ID_PATTERN.search(path_str)
            if not match:
                raise ValueError(
                    f"No trial ID found in checksum path on line {line_no} in {checksum_file}: '{path_str}'"
                )
            trial_id = match.group(0)
            if trial_id in manifest and manifest[trial_id] != digest:
                raise ValueError(
                    f"Duplicate conflicting checksum entry for trial {trial_id} in {checksum_file}: "
                    f"'{manifest[trial_id]}' vs '{digest}'"
                )
            manifest[trial_id] = digest

    return manifest


def compute_deterministic_cohort_statistics(
    trial_records: List[Dict[str, Any]],
    metric_keys: List[str],
) -> Dict[str, Any]:
    """
    Calculate deterministic summary statistics (median, IQR, p95, sample size, null counts)
    for a homogeneous cohort of valid live trials.
    Native JSON numeric values are preserved.
    """
    n_total = len(trial_records)
    winning_counts = {"IPv6": 0, "IPv4": 0}
    class_counts: Dict[str, int] = {}

    for t in trial_records:
        fam = t.get("primary_flow", {}).get("family")
        if fam in winning_counts:
            winning_counts[fam] += 1
        cls_ = t.get("classification", "UNKNOWN")
        class_counts[cls_] = class_counts.get(cls_, 0) + 1

    stats_by_metric: Dict[str, Any] = {}

    for mkey in metric_keys:
        valid_vals: List[float] = []
        null_reasons_count: Dict[str, int] = {}
        n_null = 0

        for t in trial_records:
            m_dict = t.get("metrics", {})
            val = m_dict.get(mkey)
            if val is not None and isinstance(val, (int, float)) and math.isfinite(val):
                valid_vals.append(float(val))
            else:
                n_null += 1
                n_reasons = m_dict.get("null_reasons", {})
                reason = n_reasons.get(mkey, "MISSING_OR_UNAVAILABLE")
                null_reasons_count[reason] = null_reasons_count.get(reason, 0) + 1

        n_valid = len(valid_vals)

        if n_valid > 0:
            valid_vals.sort()
            stats_raw = compute_continuous_stats(valid_vals, confidence=0.95, seed=42)
            med = stats_raw.get("median")
            p95 = stats_raw.get("p95")
            iqr = stats_raw.get("iqr")
            q1 = stats_raw.get("q1")
            q3 = stats_raw.get("q3")
            min_v = round(valid_vals[0], 4)
            max_v = round(valid_vals[-1], 4)
        else:
            med, p95, iqr, q1, q3, min_v, max_v = None, None, None, None, None, None, None

        stats_by_metric[mkey] = {
            "n_valid": n_valid,
            "n_null": n_null,
            "null_reasons": null_reasons_count,
            "median": med,
            "iqr": iqr,
            "p95": p95,
            "q1": q1,
            "q3": q3,
            "min": min_v,
            "max": max_v,
        }

    return {
        "sample_size": n_total,
        "winning_family_counts": winning_counts,
        "classification_counts": class_counts,
        "metrics": stats_by_metric,
    }


def build_demonstration_bundle(
    campaign_dir: Path,
    phase_c_dir: Path,
    output_dir: Path,
    commit_sha_override: Optional[str] = None,
) -> Tuple[Path, Path, Path]:
    """
    Construct the deterministic demonstration data bundle, sibling provenance sidecar,
    and machine-readable metric registry.
    """
    # Fail-closed check: Ensure Phase D simulation directory is NEVER ingested
    if "phase-d" in str(campaign_dir).lower() or "phase-d" in str(phase_c_dir).lower():
        raise ValueError("CRITICAL: Ingestion of Phase D simulation data is prohibited by Rule R3.")

    # Validate source paths
    manifest_file = campaign_dir / "campaign_manifest.json"
    checksums_file = campaign_dir / "pcap_sha256_checksums.txt"
    attempts_file = phase_c_dir / "attempts.csv"
    conns_file = phase_c_dir / "connection_attempts.csv"
    s5_file = phase_c_dir / "s5_flow_dissection.csv"
    timeline_file = phase_c_dir / "trial_timeline.csv"
    reconcil_file = phase_c_dir / "reconciliation_report.csv"
    rederived_dir = phase_c_dir / "rederived_results"
    rfc8305_file = phase_c_dir / "rfc8305_assessment.csv"

    required_files = [
        manifest_file,
        checksums_file,
        attempts_file,
        conns_file,
        s5_file,
        timeline_file,
        reconcil_file,
        rfc8305_file,
    ]
    for rf in required_files:
        if not rf.is_file():
            raise FileNotFoundError(f"Authoritative source file missing: {rf}")

    # Compute source input digests for provenance sidecar
    source_digests: Dict[str, str] = {}
    for rf in required_files:
        rel_key = rf.name
        source_digests[rel_key] = compute_sha256(rf)

    # 1. Ingest campaign manifest
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    raw_campaign_id = manifest_data.get("campaign_id")
    if not raw_campaign_id or not isinstance(raw_campaign_id, str) or not raw_campaign_id.strip():
        raise ValueError(
            f"Campaign manifest {manifest_file} is missing or has empty 'campaign_id': {raw_campaign_id!r}"
        )
    campaign_id = raw_campaign_id.strip()

    # 2. Ingest attempts ledger
    with open(attempts_file, "r", encoding="utf-8") as f:
        attempts_rows = list(csv.DictReader(f))

    if len(attempts_rows) != EXPECTED_ATTEMPTS_COUNT:
        raise ValueError(
            f"Attempts row count mismatch: {len(attempts_rows)} != expected {EXPECTED_ATTEMPTS_COUNT}"
        )

    # 3. Index connection attempts by trial_id
    conns_by_trial: Dict[str, List[Dict[str, Any]]] = {}
    total_conns = 0
    with open(conns_file, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            total_conns += 1
            tid = r["trial_id"]
            conns_by_trial.setdefault(tid, []).append({
                "tcp_stream": r.get("tcp_stream"),
                "family": r.get("family"),
                "client_ip": r.get("client_ip"),
                "client_port": parse_int_or_none(r.get("client_port")),
                "server_ip": r.get("server_ip"),
                "server_port": parse_int_or_none(r.get("server_port")),
                "syn_time": parse_float_or_none(r.get("syn_time")),
                "synack_time": parse_float_or_none(r.get("synack_time")),
                "final_ack_time": parse_float_or_none(r.get("final_ack_time")),
                "rst_time": parse_float_or_none(r.get("rst_time")),
                "offset_from_first_syn_ms": parse_float_or_none(r.get("offset_from_first_syn_ms")),
                "outcome": r.get("outcome"),
                "is_primary": r.get("is_primary") == "True",
                "retransmitted_syn_count": parse_int_or_none(r.get("retransmitted_syn_count")),
            })

    if total_conns != EXPECTED_TCP_FLOWS_COUNT:
        raise ValueError(
            f"Connection attempts count mismatch: {total_conns} != expected {EXPECTED_TCP_FLOWS_COUNT}"
        )

    # 4. Index S5 flows by trial_id
    s5_by_trial: Dict[str, List[Dict[str, Any]]] = {}
    total_s5 = 0
    with open(s5_file, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            total_s5 += 1
            tid = r["trial_id"]
            s5_by_trial.setdefault(tid, []).append({
                "stream_id": r.get("stream_id"),
                "family": r.get("family"),
                "flow_role": r.get("flow_role"),
                "syn_count": parse_int_or_none(r.get("syn_count")),
                "syn_retransmissions": parse_int_or_none(r.get("syn_retransmissions")),
                "handshake_completed": r.get("handshake_completed") == "True",
                "outcome": r.get("outcome"),
                "first_syn_time": parse_float_or_none(r.get("first_syn_time")),
                "last_syn_time": parse_float_or_none(r.get("last_syn_time")),
                "final_ack_time": parse_float_or_none(r.get("final_ack_time")),
                "client_port": parse_int_or_none(r.get("client_port")),
                "is_primary_http": r.get("is_primary_http") == "True",
            })

    if total_s5 != EXPECTED_S5_FLOWS_COUNT:
        raise ValueError(
            f"S5 flows count mismatch: {total_s5} != expected {EXPECTED_S5_FLOWS_COUNT}"
        )

    # 5. Index timeline events by trial_id
    timeline_by_trial: Dict[str, List[Dict[str, Any]]] = {}
    total_events = 0
    with open(timeline_file, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            total_events += 1
            tid = r["trial_id"]
            timeline_by_trial.setdefault(tid, []).append({
                "event_index": parse_int_or_none(r.get("event_index")),
                "timestamp": parse_float_or_none(r.get("event_timestamp_epoch")),
                "relative_ms": parse_float_or_none(r.get("relative_ms")),  # Retain as null; Phase C CSV provides absolute epoch timestamps
                "source": r.get("event_source") or None,
                "event_type": r.get("event_type"),
                "family": r.get("address_family") or None,
                "stream_id": r.get("tcp_stream") or None,
                "frame_number": parse_int_or_none(r.get("frame_number")),
                "details": r.get("details"),
                "pcap_sha256": r.get("pcap_sha256") or None,
                "source_path": r.get("source_path") or None,
            })

    if total_events != EXPECTED_TIMELINE_EVENTS_COUNT:
        raise ValueError(
            f"Timeline events count mismatch: {total_events} != expected {EXPECTED_TIMELINE_EVENTS_COUNT}"
        )

    # Ingest RFC 8305 assessment checks
    with open(rfc8305_file, "r", encoding="utf-8") as f:
        rfc_rows = list(csv.DictReader(f))

    # Parse canonical PCAP checksum manifest into trial_id -> digest mapping
    manifest_checksums = parse_canonical_checksum_manifest(checksums_file)

    # 7. Process valid trials and exclusions separately
    valid_trials: List[Dict[str, Any]] = []
    exclusions: List[Dict[str, Any]] = []
    rederived_digests: Dict[str, str] = {}

    cohort_trial_records: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}

    for row in attempts_rows:
        tid = row["trial_id"]
        status = row["status"]
        validity = row["validity_category"]

        if validity == "CLEANUP_FAILURE":
            if status != "FAILED":
                raise ValueError(
                    f"Attempt {row.get('attempt_id')} has validity CLEANUP_FAILURE but unexpected status '{status}'"
                )
            exclusions.append({
                "attempt_id": row["attempt_id"],
                "slot_id": row["slot_id"],
                "slot_index": parse_int_or_none(row["slot_index"]),
                "scenario_id": row["scenario_id"],
                "browser": row["browser"],
                "repetition": parse_int_or_none(row["repetition"]),
                "attempt_number": parse_int_or_none(row["attempt_number"]),
                "trial_id": tid,
                "status": status,
                "validity_category": validity,
                "start_time": parse_float_or_none(row["start_time"]),
                "end_time": parse_float_or_none(row["end_time"]),
                "timeline_events": timeline_by_trial.get(tid, []),
            })
            continue

        if validity != "VALID_LIVE" or status != "COMPLETED":
            raise ValueError(
                f"Attempt {row.get('attempt_id')} has invalid validity '{validity}' or status '{status}' (must be VALID_LIVE and COMPLETED)"
            )

        # 1. Require attempts.csv campaign_id to equal the campaign manifest campaign_id
        ledger_campaign_id = row.get("campaign_id")
        if ledger_campaign_id != campaign_id:
            raise ValueError(
                f"Campaign ID mismatch for attempt {row.get('attempt_id')}: "
                f"attempts ledger has '{ledger_campaign_id}' but manifest has '{campaign_id}'"
            )

        # 2. Require trial present in canonical checksum manifest
        if tid not in manifest_checksums:
            raise ValueError(
                f"Valid live trial {tid} is missing from canonical checksum manifest {checksums_file}"
            )
        expected_manifest_digest = manifest_checksums[tid]

        # 3. Require attempts ledger PCAP digest is present, valid format, and matches manifest
        ledger_digest = row.get("pcap_sha256")
        if not ledger_digest or not HEX64_RE.match(str(ledger_digest)):
            raise ValueError(
                f"Attempts ledger has missing or malformed pcap_sha256 for trial {tid}: '{ledger_digest}'"
            )
        if ledger_digest.lower() != expected_manifest_digest:
            raise ValueError(
                f"Attempts ledger PCAP digest mismatch for trial {tid}: "
                f"'{ledger_digest}' != manifest '{expected_manifest_digest}'"
            )

        # 4. Valid live trial: load rederived JSON
        reder_file = rederived_dir / f"{tid}.json"
        if not reder_file.is_file():
            raise FileNotFoundError(f"Missing rederived JSON record: {reder_file}")

        rederived_digests[reder_file.name] = compute_sha256(reder_file)

        with open(reder_file, "r", encoding="utf-8") as f:
            reder = json.load(f)

        # Enforce execution mode and trial identity invariants against attempts ledger
        if reder.get("trial_id") != tid:
            raise ValueError(
                f"Trial ID mismatch for trial {tid}: rederived has '{reder.get('trial_id')}'"
            )
        if reder.get("campaign_id") != campaign_id:
            raise ValueError(
                f"Campaign ID mismatch for trial {tid}: rederived has '{reder.get('campaign_id')}'"
            )
        # Validate scenario_id in attempts ledger and rederived record against canonical scenarios
        ledger_scenario_id = row.get("scenario_id")
        if not ledger_scenario_id or not isinstance(ledger_scenario_id, str) or not ledger_scenario_id.strip():
            raise ValueError(
                f"Trial {tid} is missing or has empty scenario_id in attempts ledger: {ledger_scenario_id!r}"
            )
        ledger_scenario_id = ledger_scenario_id.strip()
        if ledger_scenario_id not in CANONICAL_SCENARIOS:
            raise ValueError(
                f"Unknown scenario ID '{ledger_scenario_id}' in attempts ledger for trial {tid} "
                f"(must be one of {sorted(list(CANONICAL_SCENARIOS.keys()))})"
            )

        reder_scenario_id = reder.get("scenario_id")
        if not reder_scenario_id or not isinstance(reder_scenario_id, str) or not reder_scenario_id.strip():
            raise ValueError(
                f"Trial {tid} is missing or has empty scenario_id in rederived record: {reder_scenario_id!r}"
            )
        reder_scenario_id = reder_scenario_id.strip()
        if reder_scenario_id != ledger_scenario_id:
            raise ValueError(
                f"Scenario mismatch for trial {tid}: attempts ledger has '{ledger_scenario_id}' but rederived has '{reder_scenario_id}'"
            )
        scen_id = ledger_scenario_id
        if reder.get("browser_name") != row["browser"]:
            raise ValueError(
                f"Browser mismatch for trial {tid}: attempts ledger has '{row['browser']}' but rederived has '{reder.get('browser_name')}'"
            )

        # Require attempts-ledger classification to equal rederived JSON classification
        ledger_cls = row.get("classification")
        reder_cls = reder.get("classification")
        if not ledger_cls:
            raise ValueError(f"Trial {tid} is missing classification in attempts ledger")
        if not reder_cls:
            raise ValueError(f"Trial {tid} is missing classification in rederived record")
        if ledger_cls != reder_cls:
            raise ValueError(
                f"Classification mismatch for trial {tid}: "
                f"attempts ledger has '{ledger_cls}' but rederived has '{reder_cls}'"
            )

        # Require classification to be a valid successful measurement classification
        if reder_cls not in VALID_SUCCESSFUL_CLASSIFICATIONS:
            raise ValueError(
                f"Trial {tid} has invalid or unsuccessful classification '{reder_cls}' "
                f"(must be one of {list(VALID_SUCCESSFUL_CLASSIFICATIONS.keys())}, not CONNECTION_FAILED or INCONCLUSIVE)"
            )

        # Validate browser version against canonical cohort specification
        browser_name = row["browser"]
        cohort_browser = CANONICAL_BROWSERS.get(browser_name)
        if not cohort_browser:
            raise ValueError(f"Unknown browser cohort '{browser_name}' for trial {tid}")
        reder_bver = reder.get("browser_version")
        if reder_bver != cohort_browser["display_name"] and reder_bver != cohort_browser["version"]:
            raise ValueError(
                f"Browser version mismatch for trial {tid}: rederived has '{reder_bver}', "
                f"expected '{cohort_browser['display_name']}' or '{cohort_browser['version']}'"
            )

        # Strict repetition identity: exact integer in range 1..20
        ledger_rep = validate_strict_repetition(row.get("repetition"), "attempts ledger repetition", tid)
        reder_rep_raw = reder.get("repetition")
        if reder_rep_raw is not None:
            reder_rep = validate_strict_repetition(reder_rep_raw, "rederived repetition", tid)
            if reder_rep != ledger_rep:
                raise ValueError(
                    f"Repetition mismatch for trial {tid}: attempts ledger has '{ledger_rep}' but rederived has '{reder_rep}'"
                )
        rep = ledger_rep

        if reder.get("validity_category") != "VALID_LIVE":
            raise ValueError(
                f"Validity category mismatch for trial {tid}: rederived has '{reder.get('validity_category')}' (expected 'VALID_LIVE')"
            )
        if reder.get("execution_mode") != "LIVE" or reder.get("is_simulation") is not False:
            raise ValueError(f"Trial {tid} is not authentic LIVE measurement")

        # Strict Primary Flow Evidence Validation
        reder_pf = reder.get("primary_flow")
        if not reder_pf or not isinstance(reder_pf, dict):
            raise ValueError(f"Trial {tid} missing or malformed primary_flow evidence object")

        pf_stream = reder_pf.get("stream_id")
        if pf_stream is None or str(pf_stream).strip() == "":
            raise ValueError(f"Trial {tid} primary_flow missing non-empty stream identifier")

        pf_family = reder_pf.get("family")
        if pf_family not in ("IPv4", "IPv6"):
            raise ValueError(f"Trial {tid} primary_flow invalid family: '{pf_family}' (must be IPv4 or IPv6)")

        # Check consistency between classification and primary-flow family:
        # DIRECT_IPV6 -> IPv6, DIRECT_IPV4 -> IPv4, IPV6_TO_IPV4_FALLBACK -> IPv4, IPV4_TO_IPV6_FALLBACK -> IPv6
        expected_family_for_cls = VALID_SUCCESSFUL_CLASSIFICATIONS[reder_cls]
        if pf_family != expected_family_for_cls:
            raise ValueError(
                f"Classification/family inconsistency for trial {tid}: "
                f"classification '{reder_cls}' requires primary flow family '{expected_family_for_cls}', "
                f"but primary_flow has family '{pf_family}'"
            )

        if reder_pf.get("handshake_completed") is not True:
            raise ValueError(f"Trial {tid} primary_flow TCP handshake not completed")

        syn_fr = validate_strict_positive_int(reder_pf.get("syn_frame"), "syn_frame", tid)
        final_ack_fr = validate_strict_positive_int(reder_pf.get("final_ack_frame"), "final_ack_frame", tid)
        http_req_fr = validate_strict_positive_int(reder_pf.get("http_request_frame"), "http_request_frame", tid)
        http_resp_fr = validate_strict_positive_int(reder_pf.get("http_response_frame"), "http_response_frame", tid)

        # Strict HTTP status validation: attempts ledger == rederived primary flow == 200
        ledger_http = validate_strict_http_status(row.get("http_status"), "attempts ledger http_status", tid, 200)
        reder_http = validate_strict_http_status(reder_pf.get("http_status_code"), "primary_flow http_status_code", tid, 200)
        if ledger_http != reder_http:
            raise ValueError(
                f"HTTP status mismatch for trial {tid}: "
                f"attempts ledger has {ledger_http} but rederived primary flow has {reder_http}"
            )
        http_status = reder_http

        reder_pcap_digest = reder_pf.get("pcap_sha256")
        if not reder_pcap_digest or not HEX64_RE.match(str(reder_pcap_digest)):
            raise ValueError(f"Trial {tid} primary_flow missing or malformed pcap_sha256 digest: '{reder_pcap_digest}'")
        if str(reder_pcap_digest).lower() != expected_manifest_digest:
            raise ValueError(
                f"Trial {tid} primary_flow PCAP digest mismatch: '{reder_pcap_digest}' != manifest '{expected_manifest_digest}'"
            )

        # Canonical metric preservation: connection_attempt_delay_ms must be retained
        m_in = reder.get("metrics", {})
        cad_val = parse_float_or_none(m_in.get("connection_attempt_delay_ms"))
        t_conn_val = parse_float_or_none(m_in.get("t_connect_ms"))
        t_setup_val = parse_float_or_none(m_in.get("t_setup_total_ms"))
        synack_val = parse_float_or_none(m_in.get("syn_to_synack_ms"))
        q2p_val = parse_float_or_none(m_in.get("dns_query_to_first_payload_ms"))
        resp2p_val = parse_float_or_none(m_in.get("dns_last_positive_response_to_first_payload_ms"))
        res_time_val = parse_float_or_none(m_in.get("dns_resolution_time_ms"))
        lat_a_val = parse_float_or_none(m_in.get("dns_latency_a_ms"))
        lat_aaaa_val = parse_float_or_none(m_in.get("dns_latency_aaaa_ms"))
        retx_v6 = parse_int_or_none(m_in.get("retransmitted_syn_count_ipv6"))
        retx_v4 = parse_int_or_none(m_in.get("retransmitted_syn_count_ipv4"))

        null_reasons_in = m_in.get("null_reasons", {})

        primary_flow_obj = {
            "stream_id": pf_stream,
            "family": pf_family,
            "winning_family": reder_pf.get("winning_family"),
            "client_endpoint": reder_pf.get("client_endpoint"),
            "server_endpoint": reder_pf.get("server_endpoint"),
            "pcap_sha256": expected_manifest_digest,
            "syn_frame": syn_fr,
            "syn_time": parse_float_or_none(reder_pf.get("syn_time")),
            "syn_ack_frame": parse_int_or_none(reder_pf.get("syn_ack_frame")),
            "syn_ack_time": parse_float_or_none(reder_pf.get("syn_ack_time")),
            "final_ack_frame": final_ack_fr,
            "final_ack_time": parse_float_or_none(reder_pf.get("final_ack_time")),
            "handshake_completed": True,
            "http_request_frame": http_req_fr,
            "http_response_frame": http_resp_fr,
            "http_status_code": http_status,
        }

        trial_obj: Dict[str, Any] = {
            "trial_id": tid,
            "scenario_id": scen_id,
            "browser": browser_name,
            "browser_version": reder_bver,
            "repetition": rep,
            "execution_mode": "LIVE",
            "is_simulation": False,
            "evidence_type": "HISTORICAL_LIVE",
            "validity_category": "VALID_LIVE",
            "classification": reder.get("classification"),
            "classification_reason": reder.get("classification_reason"),
            "pcap_sha256": expected_manifest_digest,
            "pcap_relpath": f"trials/{tid}/capture.pcap",
            "metrics": {
                "t_connect_ms": t_conn_val,
                "t_setup_total_ms": t_setup_val,
                "syn_to_synack_ms": synack_val,
                "connection_attempt_delay_ms": cad_val,  # Canonical metric preserved!
                "dns_query_to_first_payload_ms": q2p_val,
                "dns_last_positive_response_to_first_payload_ms": resp2p_val,
                "dns_resolution_time_ms": res_time_val,
                "dns_latency_a_ms": lat_a_val,
                "dns_latency_aaaa_ms": lat_aaaa_val,
                "retransmitted_syn_count_ipv6": retx_v6,  # Preserved as null when absent
                "retransmitted_syn_count_ipv4": retx_v4,  # Preserved as null when absent
                "null_reasons": null_reasons_in,
            },
            "primary_flow": primary_flow_obj,
            "dns_transactions": reder.get("dns_transactions", []),
            "https_svcb_queries": reder.get("https_svcb_queries", []),
            "connection_attempts": conns_by_trial.get(tid, []),
            "s5_flow_dissection": s5_by_trial.get(tid, []) if scen_id == "S5" else [],
            "timeline_events": timeline_by_trial.get(tid, []),
        }

        valid_trials.append(trial_obj)
        cohort_trial_records.setdefault((browser_name, scen_id), []).append(trial_obj)

    # Exact canonical cohort-key validation
    expected_cohort_keys = {
        (browser_name, scenario_id)
        for browser_name in CANONICAL_BROWSERS
        for scenario_id in CANONICAL_SCENARIOS
    }
    actual_cohort_keys = set(cohort_trial_records.keys())
    if actual_cohort_keys != expected_cohort_keys:
        missing_cohorts = expected_cohort_keys - actual_cohort_keys
        extra_cohorts = actual_cohort_keys - expected_cohort_keys
        raise ValueError(
            f"Cohort key mismatch against canonical specifications: "
            f"missing={sorted(missing_cohorts)}, extra={sorted(extra_cohorts)}"
        )

    # Reconciliation assertions
    if len(valid_trials) != EXPECTED_VALID_LIVE_COUNT:
        raise ValueError(
            f"Valid live trials mismatch: {len(valid_trials)} != {EXPECTED_VALID_LIVE_COUNT}"
        )
    if len(rederived_digests) != EXPECTED_VALID_LIVE_COUNT:
        raise ValueError(
            f"Rederived trial digests count mismatch: {len(rederived_digests)} != {EXPECTED_VALID_LIVE_COUNT}"
        )
    if len(exclusions) != EXPECTED_EXCLUSIONS_COUNT:
        raise ValueError(
            f"Exclusions count mismatch: {len(exclusions)} != {EXPECTED_EXCLUSIONS_COUNT}"
        )
    if len(cohort_trial_records) != EXPECTED_COHORTS_COUNT:
        raise ValueError(
            f"Cohort count mismatch: {len(cohort_trial_records)} != {EXPECTED_COHORTS_COUNT}"
        )

    expected_repetition_set = set(range(1, EXPECTED_TRIALS_PER_COHORT + 1))
    for cohort_key, c_trials in cohort_trial_records.items():
        if len(c_trials) != EXPECTED_TRIALS_PER_COHORT:
            raise ValueError(
                f"Cohort {cohort_key} count mismatch: {len(c_trials)} != {EXPECTED_TRIALS_PER_COHORT}"
            )
        reps = [t["repetition"] for t in c_trials]
        if len(set(reps)) != len(reps):
            seen = set()
            dups = sorted({r for r in reps if r in seen or seen.add(r)})
            raise ValueError(
                f"Cohort {cohort_key} contains duplicate repetition(s): {dups}"
            )
        missing_reps = expected_repetition_set - set(reps)
        if missing_reps:
            raise ValueError(
                f"Cohort {cohort_key} missing repetition(s): {sorted(missing_reps)}"
            )
        invalid_reps = set(reps) - expected_repetition_set
        if invalid_reps:
            raise ValueError(
                f"Cohort {cohort_key} contains invalid repetition(s) outside 1-20: {sorted(invalid_reps)}"
            )

    # Stable sorting
    valid_trials.sort(key=lambda t: t["trial_id"])
    exclusions.sort(key=lambda e: e["attempt_id"])

    # 8. Compute cohort summaries
    metric_keys_for_stats = [
        "t_connect_ms",
        "t_setup_total_ms",
        "syn_to_synack_ms",
        "connection_attempt_delay_ms",
        "dns_query_to_first_payload_ms",
        "dns_last_positive_response_to_first_payload_ms",
        "dns_resolution_time_ms",
        "dns_latency_a_ms",
        "dns_latency_aaaa_ms",
    ]

    statistical_summaries: Dict[str, Dict[str, Any]] = {}
    for (b_name, s_id) in sorted(cohort_trial_records.keys()):
        key_str = f"{b_name}:{s_id}"
        c_trials = cohort_trial_records[(b_name, s_id)]
        statistical_summaries[key_str] = compute_deterministic_cohort_statistics(
            trial_records=c_trials,
            metric_keys=metric_keys_for_stats,
        )

    # 9. Assemble unified data bundle
    demo_bundle = {
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "evidence_type": "HISTORICAL_LIVE",
        "reconciliation_summary": {
            "total_attempts": EXPECTED_ATTEMPTS_COUNT,
            "valid_live_trials": EXPECTED_VALID_LIVE_COUNT,
            "cleanup_failure_exclusions": EXPECTED_EXCLUSIONS_COUNT,
            "scenario_count": len(CANONICAL_SCENARIOS),
            "browser_cohort_count": len(CANONICAL_BROWSERS),
            "trials_per_cohort": EXPECTED_TRIALS_PER_COHORT,
            "connection_attempts_count": EXPECTED_TCP_FLOWS_COUNT,
            "s5_flows_count": EXPECTED_S5_FLOWS_COUNT,
            "timeline_events_count": EXPECTED_TIMELINE_EVENTS_COUNT,
        },
        "scenario_definitions": CANONICAL_SCENARIOS,
        "browser_cohorts": CANONICAL_BROWSERS,
        "trials": valid_trials,
        "exclusions": exclusions,
        "statistical_summaries": statistical_summaries,
        "rfc8305_assessment": rfc_rows,
    }

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_file = output_dir / "demo_bundle.json"
    provenance_file = output_dir / "demo_bundle.json.provenance.json"
    registry_file = output_dir / "metric_registry.json"

    # Write demo_bundle.json deterministically (reject NaN/Infinity, UTF-8, LF line endings)
    with open(bundle_file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(demo_bundle, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")

    # Determine generator commit SHA (deterministic, zero volatile timestamps)
    commit_sha = commit_sha_override or get_git_commit_sha(REPO_ROOT)

    provenance_sidecar = {
        "generator_script": "lab/build_demo_bundle.py",
        "generator_version": "1.0.0",
        "generator_commit": commit_sha,
        "campaign_id": campaign_id,
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "evidence_type": "HISTORICAL_LIVE",
        "input_files_sha256": source_digests,
        "rederived_trials_sha256": rederived_digests,
        "output_bundle_sha256": compute_sha256(bundle_file),
    }

    with open(provenance_file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(provenance_sidecar, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")

    with open(registry_file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(METRIC_REGISTRY, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")

    return bundle_file, provenance_file, registry_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Deterministic Demonstration Data Bundle Builder"
    )
    parser.add_argument(
        "--campaign-dir",
        type=Path,
        default=DEFAULT_CAMPAIGN_DIR,
        help="Path to authoritative campaign directory",
    )
    parser.add_argument(
        "--phase-c-dir",
        type=Path,
        default=DEFAULT_PHASE_C_DIR,
        help="Path to Phase C derived data directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Target output directory for demo bundle and registry",
    )
    parser.add_argument(
        "--commit-sha",
        type=str,
        default=None,
        help="Override generator commit SHA for deterministic testing",
    )
    args = parser.parse_args()

    try:
        b_file, p_file, r_file = build_demonstration_bundle(
            campaign_dir=args.campaign_dir,
            phase_c_dir=args.phase_c_dir,
            output_dir=args.output_dir,
            commit_sha_override=args.commit_sha,
        )
        print("================================================================================")
        print("PS-028 DEMONSTRATION DATA BUNDLE BUILT SUCCESSFULLY")
        print("================================================================================")
        print(f"Data Bundle:       {b_file} ({b_file.stat().st_size:,} bytes)")
        print(f"Sibling Sidecar:   {p_file}")
        print(f"Metric Registry:   {r_file}")
        print("Reconciliation:    280 valid live trials, 2 exclusions, 765 flows, 95 S5 flows")
        print("Determinism:       Byte-identical repeated generation guaranteed.")
        print("================================================================================")
        return 0
    except Exception as exc:
        print(f"[ERROR] Bundle generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
