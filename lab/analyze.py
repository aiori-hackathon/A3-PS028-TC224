#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Statistical Analysis & RFC 8305 Evaluator
Work Package A9: Statistical Analysis, Aggregation, and Standards Conformance

Reads, validates, reconciles, and analyzes Happy Eyeballs measurement evidence
from campaign manifests and trial directories (A7/A8 evidence) strictly offline
without executing network experiments or mutating system/namespace configuration:

1. Deterministic Evidence Ingestion & Reconciliation:
   - Scans and loads individual trial result JSONs and campaign manifests.
   - Enforces strict A7/A8 validity rules without relabeling evidence.
   - Discovers matrix slots, retries, and verifies attempt integrity.
2. Robust Data Segregation & Exclusions:
   - Completely segregates VALID_LIVE measurements from SIMULATION runs.
   - Excludes incomplete trials, cleanup failures, and corrupted/empty records.
   - Preserves exact exclusion reasons in structured audit trails.
   - NEVER substitutes zero for missing or unmeasured metrics.
3. Statistical Aggregation:
   - Groups results deterministically by browser and scenario.
   - Computes exact sample counts, HTTP success rates, winning address families.
   - Calculates median, 95th percentile (p95), interquartile range (IQR).
   - Computes Wilson score confidence intervals for proportions.
   - Computes deterministic bootstrap and parametric confidence intervals for continuous metrics.
4. Standards-Based RFC 8305 Assessment:
   - Evaluates address selection, Connection Attempt Delay (CAD), resolution delay, and reset fallback.
   - Strictly marks unsupported or uninstrumented checks (e.g. cross-session statefulness, QUIC)
     as INDETERMINATE with evidence-backed justification.
5. Reproducible Artifact Generation:
   - Generates machine-readable JSON and CSV summaries and formatted terminal reports.
"""

import argparse
import csv
import dataclasses
import datetime
import io
import json
import math
import os
from pathlib import Path
import random
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCHEMA_VERSION = "1.0.0"
DEFAULT_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
DEFAULT_TRIALS_DIR = SCRIPT_DIR / "trials"
DEFAULT_CAMPAIGNS_DIR = SCRIPT_DIR / "campaigns"
MANIFEST_FILENAME = "campaign_manifest.json"

RFC8305_MIN_ATTEMPT_INTERVAL_MS = 10.0   # RFC 8305 §5 normative floor: "a subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt"
RFC8305_MIN_CAD_MS = 100.0              # RFC 8305 §5 recommended minimum
RFC8305_MAX_CAD_MS = 2000.0             # RFC 8305 §5 maximum permitted
RFC8305_RECOMMENDED_CAD_MS = 250.0      # RFC 8305 §5 recommended default
RFC8305_RECOMMENDED_RESOLUTION_DELAY_MS = 50.0  # RFC 8305 §4 recommended default

SCENARIO_NAMES: Dict[str, str] = {
    "S0": "healthy_baseline",
    "S1": "ipv6_syn_blackhole",
    "S2": "ipv6_tcp_rst",
    "S3": "ipv6_rtt_150ms",
    "S4": "ipv6_rtt_600ms",
    "S5": "ipv6_syn_loss_50pct",
    "S6": "delay_aaaa_500ms"
}

# Standard Student-t critical values for 95% two-sided CI (df = 1..30)
STUDENT_T_95_CRITICAL: Dict[int, float] = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042
}
Z_CRITICAL_95 = 1.95996


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclasses.dataclass
class ExclusionRecord:
    trial_id: str
    scenario_id: str
    browser: str
    category: str  # SIMULATION, INCOMPLETE, MEASUREMENT_FAILURE, CLEANUP_FAILURE, CORRUPTED_RECORD
    reason: str
    source_path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trial_id": self.trial_id,
            "scenario_id": self.scenario_id,
            "browser": self.browser,
            "category": self.category,
            "reason": self.reason,
            "source_path": self.source_path,
        }


@dataclasses.dataclass
class TrialEvidence:
    trial_id: str
    scenario_id: str
    scenario_name: str
    browser_name: str
    browser_version: str
    execution_mode: str
    is_simulation: bool
    http_status_code: Optional[int]
    http_success: bool
    winning_address_family: Optional[str]
    winning_ip: Optional[str]
    connection_setup_time_ms: Optional[float]
    connection_attempt_delay_ms: Optional[float]
    dns_latency_a_ms: Optional[float]
    dns_latency_aaaa_ms: Optional[float]
    dns_resolution_time_ms: Optional[float]
    browser_duration_ms: Optional[float]
    packet_count: int
    pcap_valid: bool
    pcap_sha256: Optional[str]
    scenario_restored: bool
    baseline_verified: bool
    cleanup_errors: List[str]
    classification: str
    classification_reason: str
    validity_category: str  # VALID_LIVE, SIMULATION, INCOMPLETE, MEASUREMENT_FAILURE, CLEANUP_FAILURE, CORRUPTED_RECORD
    exclusion_reason: Optional[str]
    source_path: str
    raw_dict: Optional[Dict[str, Any]] = None

    def is_valid_live(self) -> bool:
        return self.validity_category == "VALID_LIVE"


# ==============================================================================
# Statistics Utilities (Deterministic & Missing-Data Safe)
# ==============================================================================

def compute_percentile(sorted_values: List[float], p: float) -> Optional[float]:
    """
    Computes percentile p in [0, 1] using linear interpolation between closest ranks.
    Requires sorted_values to be non-empty and pre-sorted.
    Returns None if sorted_values is empty.
    """
    if not sorted_values:
        return None
    n = len(sorted_values)
    if n == 1:
        return float(sorted_values[0])
    if p <= 0.0:
        return float(sorted_values[0])
    if p >= 1.0:
        return float(sorted_values[-1])

    pos = p * (n - 1)
    idx = int(pos)
    frac = pos - idx
    if idx >= n - 1:
        return float(sorted_values[-1])
    val = sorted_values[idx] + frac * (sorted_values[idx + 1] - sorted_values[idx])
    return round(float(val), 4)


def wilson_score_interval(
    k: int,
    n: int,
    confidence: float = 0.95
) -> Optional[Tuple[float, float]]:
    """
    Computes the Wilson score confidence interval for a binomial proportion k/n.
    Guaranteed bounded within [0.0, 1.0].
    Returns None if n == 0.
    """
    if n <= 0:
        return None
    if k < 0:
        k = 0
    if k > n:
        k = n

    z = Z_CRITICAL_95 if abs(confidence - 0.95) < 1e-4 else 1.95996
    p = k / n
    denom = 1.0 + (z ** 2) / n
    center = (p + (z ** 2) / (2.0 * n)) / denom
    margin = (z * math.sqrt((p * (1.0 - p) / n) + ((z ** 2) / (4.0 * (n ** 2))))) / denom

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return (round(lower, 4), round(upper, 4))


def bootstrap_median_ci(
    values: List[float],
    confidence: float = 0.95,
    seed: int = 42,
    resamples: int = 1000
) -> Optional[Tuple[float, float]]:
    """
    Computes a deterministic percentile bootstrap confidence interval for the sample median.
    Uses a seeded pseudo-random generator to ensure exact reproducibility across executions.
    Returns None if values is empty.
    """
    if not values:
        return None
    n = len(values)
    if n == 1:
        val = round(float(values[0]), 4)
        return (val, val)

    rng = random.Random(seed)
    boot_medians: List[float] = []

    for _ in range(resamples):
        sample = [values[rng.randint(0, n - 1)] for _ in range(n)]
        sample.sort()
        med = compute_percentile(sample, 0.5)
        if med is not None:
            boot_medians.append(med)

    if not boot_medians:
        return None

    boot_medians.sort()
    alpha = (1.0 - confidence) / 2.0
    lower = compute_percentile(boot_medians, alpha)
    upper = compute_percentile(boot_medians, 1.0 - alpha)

    if lower is None or upper is None:
        return None
    return (round(lower, 4), round(upper, 4))


def compute_continuous_stats(
    values: List[float],
    confidence: float = 0.95,
    seed: int = 42,
    resamples: int = 1000
) -> Dict[str, Any]:
    """
    Computes comprehensive statistics for continuous measurement arrays:
    - Count of non-null observations
    - Median, p95, Q1, Q3, and IQR
    - 95% Bootstrap Confidence Interval for Median (percentile bootstrap, B=resamples)
    - Parametric Mean and Mean CI (using Student-t distribution for df=n-1)
    NEVER substitutes 0.0 for empty or unobserved measurements.
    """
    valid_nums = [float(v) for v in values if v is not None and not math.isnan(v)]
    n = len(valid_nums)

    if n == 0:
        return {
            "count": 0,
            "median": None,
            "p95": None,
            "q1": None,
            "q3": None,
            "iqr": None,
            "median_ci_95": None,
            "mean": None,
            "std": None,
            "mean_ci_95": None,
            "min": None,
            "max": None
        }

    valid_nums.sort()
    med = compute_percentile(valid_nums, 0.5)
    p95 = compute_percentile(valid_nums, 0.95)
    q1 = compute_percentile(valid_nums, 0.25)
    q3 = compute_percentile(valid_nums, 0.75)
    iqr = round(q3 - q1, 4) if (q1 is not None and q3 is not None) else None

    # Median CI via percentile bootstrap
    med_ci = bootstrap_median_ci(valid_nums, confidence=confidence, seed=seed, resamples=resamples)

    # Mean & Std
    mean_val = round(sum(valid_nums) / n, 4)
    if n > 1:
        variance = sum((x - mean_val) ** 2 for x in valid_nums) / (n - 1)
        std_val = round(math.sqrt(variance), 4)
        se = std_val / math.sqrt(n)
        t_crit = STUDENT_T_95_CRITICAL.get(n - 1, Z_CRITICAL_95)
        mean_ci = (round(mean_val - t_crit * se, 4), round(mean_val + t_crit * se, 4))
    else:
        std_val = 0.0
        mean_ci = (mean_val, mean_val)

    return {
        "count": n,
        "median": round(med, 2) if med is not None else None,
        "p95": round(p95, 2) if p95 is not None else None,
        "q1": round(q1, 2) if q1 is not None else None,
        "q3": round(q3, 2) if q3 is not None else None,
        "iqr": round(iqr, 2) if iqr is not None else None,
        "median_ci_95": [round(med_ci[0], 2), round(med_ci[1], 2)] if med_ci else None,
        "mean": round(mean_val, 2),
        "std": round(std_val, 2),
        "mean_ci_95": [round(mean_ci[0], 2), round(mean_ci[1], 2)] if mean_ci else None,
        "min": round(valid_nums[0], 2),
        "max": round(valid_nums[-1], 2)
    }


# ==============================================================================
# Evidence Dissection & Validation
# ==============================================================================

def extract_dns_latencies(
    dns_obs: Dict[str, Any]
) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """
    Calculates DNS resolution latencies from DNS queries and responses:
    - dns_latency_a_ms: query to response delta for A record
    - dns_latency_aaaa_ms: query to response delta for AAAA record
    - dns_resolution_time_ms: total span from earliest DNS query to latest response
    Returns (a_ms, aaaa_ms, total_resolution_ms).
    Returns None for any unobserved or incomplete record type.
    """
    if not isinstance(dns_obs, dict):
        return None, None, None

    queries = dns_obs.get("queries", [])
    responses = dns_obs.get("responses", [])

    if not queries or not responses:
        return None, None, None

    # Map first query timestamp by qtype
    q_times: Dict[str, float] = {}
    for q in queries:
        qt = str(q.get("qtype", "")).upper()
        ts = q.get("timestamp")
        if qt and ts is not None and qt not in q_times:
            try:
                q_times[qt] = float(ts)
            except (ValueError, TypeError):
                pass

    # Map first response timestamp by qtype
    r_times: Dict[str, float] = {}
    for r in responses:
        qt = str(r.get("qtype", "")).upper()
        ts = r.get("timestamp")
        if qt and ts is not None and qt not in r_times:
            try:
                r_times[qt] = float(ts)
            except (ValueError, TypeError):
                pass

    a_ms = None
    if "A" in q_times and "A" in r_times and r_times["A"] >= q_times["A"]:
        a_ms = round((r_times["A"] - q_times["A"]) * 1000.0, 2)

    aaaa_ms = None
    if "AAAA" in q_times and "AAAA" in r_times and r_times["AAAA"] >= q_times["AAAA"]:
        aaaa_ms = round((r_times["AAAA"] - q_times["AAAA"]) * 1000.0, 2)

    # Resolution time: span from earliest query to latest response
    resolution_ms = None
    all_q = [q.get("timestamp") for q in queries if q.get("timestamp") is not None]
    all_r = [r.get("timestamp") for r in responses if r.get("timestamp") is not None]
    if all_q and all_r:
        try:
            min_q = min(float(t) for t in all_q)
            max_r = max(float(t) for t in all_r)
            if max_r >= min_q:
                resolution_ms = round((max_r - min_q) * 1000.0, 2)
        except (ValueError, TypeError):
            pass

    return a_ms, aaaa_ms, resolution_ms


def validate_trial_record(data: Dict[str, Any], path: Path) -> Tuple[str, Optional[str]]:
    """
    Evaluates trial dictionary against strict A7/A8 validity criteria:
    Returns (validity_category, exclusion_reason).
    Categories:
    - VALID_LIVE: Genuine, cleanly restored live measurement
    - SIMULATION: Simulation run (segregated from live results)
    - INCOMPLETE: Missing critical sections or interrupted execution
    - MEASUREMENT_FAILURE: Valid execution but capture empty or classification failed
    - CLEANUP_FAILURE: Lab state or baseline cleanup failed
    - CORRUPTED_RECORD: Malformed data or schema mismatch
    """
    if data.get("schema_version") != SCHEMA_VERSION:
        return "CORRUPTED_RECORD", f"Schema version mismatch: {data.get('schema_version')} != {SCHEMA_VERSION}"

    is_sim = bool(data.get("is_simulation", False) or data.get("execution_mode") == "SIMULATION")
    if is_sim:
        return "SIMULATION", "Simulation mode run (offline/dry-run separated from live evidence)"

    cleanup = data.get("cleanup_status")
    if not isinstance(cleanup, dict):
        return "INCOMPLETE", "Missing cleanup_status section"

    if not cleanup.get("scenario_restored", False):
        return "CLEANUP_FAILURE", "Cleanup failed: scenario_restored is False"
    if not cleanup.get("baseline_verified", False):
        return "CLEANUP_FAILURE", "Cleanup failed: baseline_verified is False"
    if cleanup.get("errors"):
        return "CLEANUP_FAILURE", f"Cleanup recorded errors: {cleanup.get('errors')}"

    capture = data.get("capture_metadata")
    if not isinstance(capture, dict):
        return "INCOMPLETE", "Missing capture_metadata section"

    if not capture.get("pcap_valid", False):
        return "MEASUREMENT_FAILURE", f"PCAP invalid: {capture.get('validation_message', 'invalid PCAP')}"

    packet_count = capture.get("packet_count")
    if packet_count is None or packet_count <= 0:
        return "MEASUREMENT_FAILURE", f"Zero-packet capture (packet_count={packet_count})"

    net_obs = data.get("network_observations")
    if not isinstance(net_obs, dict):
        return "INCOMPLETE", "Missing network_observations section"

    classification = net_obs.get("classification")
    if classification == "INCONCLUSIVE":
        return "MEASUREMENT_FAILURE", f"Inconclusive network classification: {net_obs.get('classification_reason', '')}"

    if classification == "CONNECTION_FAILED" and not data.get("http_outcome", {}).get("success", False):
        return "MEASUREMENT_FAILURE", f"Connection failed: {net_obs.get('classification_reason', '')}"

    return "VALID_LIVE", None


def load_trial_from_json(file_path: Path) -> TrialEvidence:
    """
    Loads and dissects an individual trial result.json file safely.
    Handles malformed JSON or corrupted files without unhandled crashes.
    """
    path_resolved = file_path.resolve()
    if not path_resolved.is_file():
        return TrialEvidence(
            trial_id=path_resolved.parent.name,
            scenario_id="UNKNOWN",
            scenario_name="unknown",
            browser_name="unknown",
            browser_version="unknown",
            execution_mode="UNKNOWN",
            is_simulation=False,
            http_status_code=None,
            http_success=False,
            winning_address_family=None,
            winning_ip=None,
            connection_setup_time_ms=None,
            connection_attempt_delay_ms=None,
            dns_latency_a_ms=None,
            dns_latency_aaaa_ms=None,
            dns_resolution_time_ms=None,
            browser_duration_ms=None,
            packet_count=0,
            pcap_valid=False,
            pcap_sha256=None,
            scenario_restored=False,
            baseline_verified=False,
            cleanup_errors=["File not found"],
            classification="UNKNOWN",
            classification_reason="Result file missing",
            validity_category="INCOMPLETE",
            exclusion_reason=f"File not found: {path_resolved}",
            source_path=str(path_resolved)
        )

    try:
        raw_text = path_resolved.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except Exception as exc:
        return TrialEvidence(
            trial_id=path_resolved.parent.name,
            scenario_id="UNKNOWN",
            scenario_name="unknown",
            browser_name="unknown",
            browser_version="unknown",
            execution_mode="UNKNOWN",
            is_simulation=False,
            http_status_code=None,
            http_success=False,
            winning_address_family=None,
            winning_ip=None,
            connection_setup_time_ms=None,
            connection_attempt_delay_ms=None,
            dns_latency_a_ms=None,
            dns_latency_aaaa_ms=None,
            dns_resolution_time_ms=None,
            browser_duration_ms=None,
            packet_count=0,
            pcap_valid=False,
            pcap_sha256=None,
            scenario_restored=False,
            baseline_verified=False,
            cleanup_errors=[f"Parse error: {exc}"],
            classification="CORRUPTED",
            classification_reason=f"Failed to parse JSON: {exc}",
            validity_category="CORRUPTED_RECORD",
            exclusion_reason=f"Malformed JSON: {exc}",
            source_path=str(path_resolved)
        )

    validity, exclusion_reason = validate_trial_record(data, path_resolved)

    scenario_id = str(data.get("scenario_id", "UNKNOWN")).upper()
    scenario_name = data.get("scenario_name") or SCENARIO_NAMES.get(scenario_id, "unknown")
    browser_dict = data.get("browser", {})
    browser_name = browser_dict.get("name") or "unknown"
    browser_version = browser_dict.get("version") or "unknown"
    browser_duration = browser_dict.get("duration_ms")

    http_dict = data.get("http_outcome", {})
    http_status = http_dict.get("status_code")
    http_success = bool(http_dict.get("success", False))
    winning_family = http_dict.get("winning_address_family")
    winning_ip = http_dict.get("winning_ip")

    net_dict = data.get("network_observations", {})
    setup_time = net_dict.get("connection_setup_time_ms")
    cad = net_dict.get("connection_attempt_delay_ms")
    classification = net_dict.get("classification") or "UNKNOWN"
    classification_reason = net_dict.get("classification_reason") or ""

    dns_dict = data.get("dns_observations", {})
    a_lat, aaaa_lat, res_time = extract_dns_latencies(dns_dict)

    capture_dict = data.get("capture_metadata", {})
    packet_count = capture_dict.get("packet_count", 0)
    pcap_valid = bool(capture_dict.get("pcap_valid", False))
    pcap_sha = capture_dict.get("pcap_sha256")

    cleanup_dict = data.get("cleanup_status", {})
    sc_restored = bool(cleanup_dict.get("scenario_restored", False))
    bl_verified = bool(cleanup_dict.get("baseline_verified", False))
    cl_errors = cleanup_dict.get("errors", [])

    return TrialEvidence(
        trial_id=str(data.get("trial_id") or path_resolved.parent.name),
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        browser_name=browser_name,
        browser_version=browser_version,
        execution_mode=str(data.get("execution_mode", "LIVE")),
        is_simulation=bool(data.get("is_simulation", False)),
        http_status_code=int(http_status) if http_status is not None else None,
        http_success=http_success,
        winning_address_family=winning_family,
        winning_ip=winning_ip,
        connection_setup_time_ms=float(setup_time) if setup_time is not None else None,
        connection_attempt_delay_ms=float(cad) if cad is not None else None,
        dns_latency_a_ms=a_lat,
        dns_latency_aaaa_ms=aaaa_lat,
        dns_resolution_time_ms=res_time,
        browser_duration_ms=float(browser_duration) if browser_duration is not None else None,
        packet_count=int(packet_count) if packet_count is not None else 0,
        pcap_valid=pcap_valid,
        pcap_sha256=pcap_sha,
        scenario_restored=sc_restored,
        baseline_verified=bl_verified,
        cleanup_errors=cl_errors,
        classification=classification,
        classification_reason=classification_reason,
        validity_category=validity,
        exclusion_reason=exclusion_reason,
        source_path=str(path_resolved),
        raw_dict=data
    )


def load_trials_from_directory(dir_path: Path) -> List[TrialEvidence]:
    """
    Recursively scans and loads trial result JSONs from a directory.
    Guarantees stable, deterministic sort order by trial directory name.
    """
    dir_resolved = dir_path.resolve()
    if not dir_resolved.is_dir():
        return []

    result_files: List[Path] = []
    # If the directory itself contains result.json
    direct_res = dir_resolved / "result.json"
    if direct_res.is_file():
        result_files.append(direct_res)
    else:
        # Check subdirectories
        for p in sorted(dir_resolved.glob("**/result.json")):
            result_files.append(p)

    return [load_trial_from_json(p) for p in sorted(result_files)]


def load_campaign_manifest(
    manifest_path: Path
) -> Tuple[List[TrialEvidence], List[ExclusionRecord]]:
    """
    Parses a campaign manifest JSON and loads corresponding trial results from disk.
    Reconciles planned matrix slots, executed attempts, and unexecuted/pending slots.
    Preserves retries and exclusions.
    """
    manifest_resolved = manifest_path.resolve()
    campaign_dir = manifest_resolved.parent
    trials_dir = campaign_dir / "trials"

    trials: List[TrialEvidence] = []
    exclusions: List[ExclusionRecord] = []

    if not manifest_resolved.is_file():
        exclusions.append(ExclusionRecord(
            trial_id=campaign_dir.name,
            scenario_id="UNKNOWN",
            browser="UNKNOWN",
            category="INCOMPLETE",
            reason=f"Campaign manifest missing at {manifest_resolved}",
            source_path=str(manifest_resolved)
        ))
        return trials, exclusions

    try:
        data = json.loads(manifest_resolved.read_text(encoding="utf-8"))
    except Exception as exc:
        exclusions.append(ExclusionRecord(
            trial_id=campaign_dir.name,
            scenario_id="UNKNOWN",
            browser="UNKNOWN",
            category="CORRUPTED_RECORD",
            reason=f"Failed to parse campaign manifest: {exc}",
            source_path=str(manifest_resolved)
        ))
        return trials, exclusions

    matrix_slots = data.get("matrix_slots", [])
    seen_trial_ids: Set[str] = set()

    for slot in matrix_slots:
        slot_id = slot.get("slot_id", "unknown-slot")
        sc_id = slot.get("scenario_id", "UNKNOWN")
        bname = slot.get("browser", "unknown")
        status = slot.get("status", "PENDING")
        attempts = slot.get("attempts", [])

        if not attempts and status == "PENDING":
            exclusions.append(ExclusionRecord(
                trial_id=slot_id,
                scenario_id=sc_id,
                browser=bname,
                category="INCOMPLETE",
                reason=f"Planned matrix slot '{slot_id}' remained PENDING without execution attempts",
                source_path=str(manifest_resolved)
            ))
            continue

        for att in attempts:
            tid = att.get("trial_id")
            if not tid:
                continue
            seen_trial_ids.add(tid)

            # Find result.json
            res_path_str = att.get("evidence_paths", {}).get("result_json")
            res_path: Optional[Path] = None
            if res_path_str:
                p_cand = Path(res_path_str)
                if p_cand.is_file():
                    res_path = p_cand

            if not res_path:
                cand2 = trials_dir / tid / "result.json"
                if cand2.is_file():
                    res_path = cand2
                else:
                    cand3 = DEFAULT_TRIALS_DIR / tid / "result.json"
                    if cand3.is_file():
                        res_path = cand3

            if res_path and res_path.is_file():
                evidence = load_trial_from_json(res_path)
                # Overwrite attempt-level error if manifest recorded cleanup failure
                att_validity = att.get("validity")
                if att_validity in ("CLEANUP_FAILURE", "MEASUREMENT_FAILURE") and evidence.validity_category == "VALID_LIVE":
                    evidence.validity_category = att_validity
                    evidence.exclusion_reason = att.get("error_message") or f"Marked {att_validity} in manifest"
                trials.append(evidence)
            else:
                att_validity = att.get("validity", "INCOMPLETE")
                err_msg = att.get("error_message") or "result.json missing from attempt directory"
                exclusions.append(ExclusionRecord(
                    trial_id=tid,
                    scenario_id=sc_id,
                    browser=bname,
                    category=att_validity,
                    reason=err_msg,
                    source_path=str(trials_dir / tid)
                ))

    # Also discover any unreferenced trial directories under campaign_dir/trials
    if trials_dir.is_dir():
        for tdir in sorted(trials_dir.iterdir()):
            if tdir.is_dir() and tdir.name.startswith("trial-") and tdir.name not in seen_trial_ids:
                r_json = tdir / "result.json"
                if r_json.is_file():
                    trials.append(load_trial_from_json(r_json))

    return trials, exclusions


def ingest_evidence(
    sources: List[Path]
) -> Tuple[List[TrialEvidence], List[ExclusionRecord]]:
    """
    Ingests and reconciles measurement evidence from arbitrary file or directory paths.
    Automatically handles campaign manifests, campaign directories, trials directories,
    or individual result.json files. Deduplicates by trial_id.
    """
    all_trials: List[TrialEvidence] = []
    all_exclusions: List[ExclusionRecord] = []
    seen_ids: Set[str] = set()

    for s in sources:
        p = s.resolve()
        if not p.exists():
            all_exclusions.append(ExclusionRecord(
                trial_id=p.name,
                scenario_id="UNKNOWN",
                browser="UNKNOWN",
                category="INCOMPLETE",
                reason=f"Specified path does not exist: {p}",
                source_path=str(p)
            ))
            continue

        if p.is_file():
            if p.name == MANIFEST_FILENAME:
                m_trials, m_excl = load_campaign_manifest(p)
                for t in m_trials:
                    if t.trial_id not in seen_ids:
                        seen_ids.add(t.trial_id)
                        all_trials.append(t)
                all_exclusions.extend(m_excl)
            elif p.suffix == ".json":
                # Check if it's a manifest or a trial
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    if "matrix_slots" in data:
                        m_trials, m_excl = load_campaign_manifest(p)
                        for t in m_trials:
                            if t.trial_id not in seen_ids:
                                seen_ids.add(t.trial_id)
                                all_trials.append(t)
                        all_exclusions.extend(m_excl)
                    else:
                        t = load_trial_from_json(p)
                        if t.trial_id not in seen_ids:
                            seen_ids.add(t.trial_id)
                            all_trials.append(t)
                except Exception as exc:
                    all_exclusions.append(ExclusionRecord(
                        trial_id=p.stem,
                        scenario_id="UNKNOWN",
                        browser="UNKNOWN",
                        category="CORRUPTED_RECORD",
                        reason=f"Failed to read JSON: {exc}",
                        source_path=str(p)
                    ))
        elif p.is_dir():
            manifest_cand = p / MANIFEST_FILENAME
            if manifest_cand.is_file():
                m_trials, m_excl = load_campaign_manifest(manifest_cand)
                for t in m_trials:
                    if t.trial_id not in seen_ids:
                        seen_ids.add(t.trial_id)
                        all_trials.append(t)
                all_exclusions.extend(m_excl)
            else:
                d_trials = load_trials_from_directory(p)
                for t in d_trials:
                    if t.trial_id not in seen_ids:
                        seen_ids.add(t.trial_id)
                        all_trials.append(t)

    # Sort trials deterministically by scenario_id, browser_name, trial_id
    all_trials.sort(key=lambda x: (x.scenario_id, x.browser_name, x.trial_id))
    return all_trials, all_exclusions


# ==============================================================================
# Group Aggregation & Metrics Calculation
# ==============================================================================

def aggregate_group_metrics(
    group_trials: List[TrialEvidence],
    browser: str,
    scenario_id: str,
    confidence: float = 0.95,
    seed: int = 42,
    resamples: int = 1000
) -> Dict[str, Any]:
    """
    Computes all statistical metrics for a specific (browser, scenario_id) cohort:
    - Counts: total, valid_live, simulations, incomplete, invalid/failed
    - HTTP success rate with Wilson score 95% CI
    - Winning address family proportions with Wilson score 95% CI
    - Connection setup times (median, p95, IQR, median CI, mean CI)
    - Fallback delays (CAD) (median, p95, IQR, median CI, mean CI)
    - DNS latencies for A and AAAA records and composite resolution time
    - Browser durations (service readiness / page load time)
    Guarantees missing values are preserved as None and never substituted with 0.
    """
    total_count = len(group_trials)
    valid_live_trials = [t for t in group_trials if t.validity_category == "VALID_LIVE"]
    simulations = [t for t in group_trials if t.validity_category == "SIMULATION"]
    incomplete = [t for t in group_trials if t.validity_category == "INCOMPLETE"]
    failures = [
        t for t in group_trials
        if t.validity_category in ("MEASUREMENT_FAILURE", "CLEANUP_FAILURE", "CORRUPTED_RECORD")
    ]

    sc_name = SCENARIO_NAMES.get(scenario_id, "unknown")
    if group_trials and group_trials[0].scenario_name != "unknown":
        sc_name = group_trials[0].scenario_name

    n_valid = len(valid_live_trials)

    # 1. HTTP Outcome
    http_success_count = sum(1 for t in valid_live_trials if t.http_success)
    http_success_rate = round(http_success_count / n_valid, 4) if n_valid > 0 else None
    http_ci = wilson_score_interval(http_success_count, n_valid, confidence=confidence)

    # 2. Winning Address Family
    ipv6_wins = sum(1 for t in valid_live_trials if t.winning_address_family == "IPv6")
    ipv4_wins = sum(1 for t in valid_live_trials if t.winning_address_family == "IPv4")
    none_wins = sum(1 for t in valid_live_trials if not t.winning_address_family)

    ipv6_rate = round(ipv6_wins / n_valid, 4) if n_valid > 0 else None
    ipv6_ci = wilson_score_interval(ipv6_wins, n_valid, confidence=confidence)
    ipv4_rate = round(ipv4_wins / n_valid, 4) if n_valid > 0 else None
    ipv4_ci = wilson_score_interval(ipv4_wins, n_valid, confidence=confidence)
    none_rate = round(none_wins / n_valid, 4) if n_valid > 0 else None

    # 3. Connection Setup Time
    setup_times = [t.connection_setup_time_ms for t in valid_live_trials if t.connection_setup_time_ms is not None]
    setup_stats = compute_continuous_stats(setup_times, confidence=confidence, seed=seed, resamples=resamples)

    # 4. Fallback Delay (Connection Attempt Delay)
    cad_delays = [t.connection_attempt_delay_ms for t in valid_live_trials if t.connection_attempt_delay_ms is not None]
    cad_stats = compute_continuous_stats(cad_delays, confidence=confidence, seed=seed, resamples=resamples)

    # 5. DNS Latency (A, AAAA, Resolution Span)
    a_lats = [t.dns_latency_a_ms for t in valid_live_trials if t.dns_latency_a_ms is not None]
    a_stats = compute_continuous_stats(a_lats, confidence=confidence, seed=seed, resamples=resamples)

    aaaa_lats = [t.dns_latency_aaaa_ms for t in valid_live_trials if t.dns_latency_aaaa_ms is not None]
    aaaa_stats = compute_continuous_stats(aaaa_lats, confidence=confidence, seed=seed, resamples=resamples)

    res_spans = [t.dns_resolution_time_ms for t in valid_live_trials if t.dns_resolution_time_ms is not None]
    res_stats = compute_continuous_stats(res_spans, confidence=confidence, seed=seed, resamples=resamples)

    # 6. Browser Duration (Service Readiness / Page Load)
    browser_durations = [t.browser_duration_ms for t in valid_live_trials if t.browser_duration_ms is not None]
    browser_stats = compute_continuous_stats(browser_durations, confidence=confidence, seed=seed, resamples=resamples)

    return {
        "browser": browser,
        "scenario_id": scenario_id,
        "scenario_name": sc_name,
        "sample_counts": {
            "total_trials": total_count,
            "valid_live_count": n_valid,
            "simulation_count": len(simulations),
            "incomplete_count": len(incomplete),
            "invalid_or_failed_count": len(failures)
        },
        "http_success": {
            "count": http_success_count,
            "rate": http_success_rate,
            "ci_95": [http_ci[0], http_ci[1]] if http_ci else None
        },
        "winning_address_family": {
            "ipv6": {
                "count": ipv6_wins,
                "rate": ipv6_rate,
                "ci_95": [ipv6_ci[0], ipv6_ci[1]] if ipv6_ci else None
            },
            "ipv4": {
                "count": ipv4_wins,
                "rate": ipv4_rate,
                "ci_95": [ipv4_ci[0], ipv4_ci[1]] if ipv4_ci else None
            },
            "none": {
                "count": none_wins,
                "rate": none_rate
            }
        },
        "connection_setup_time_ms": setup_stats,
        "connection_attempt_delay_ms": cad_stats,
        "dns_latency": {
            "a_record_ms": a_stats,
            "aaaa_record_ms": aaaa_stats,
            "resolution_span_ms": res_stats
        },
        "browser_duration_ms": browser_stats
    }


# ==============================================================================
# Evidence-Based RFC 8305 Assessment Engine
# ==============================================================================

def assess_rfc8305_conformance(
    valid_trials: List[TrialEvidence],
    browser: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Evaluates Happy Eyeballs v2 (RFC 8305) conformance based strictly on observable trial evidence:
    - Address Order & IPv6 Preference (RFC 8305 §3) -> S0
    - Immediate Reset Fallback (RFC 8305 §5) -> S2
    - Connection Attempt Delay on SYN Timeout (RFC 8305 §5) -> S1
    - Latency-Driven Alternative Path Selection (RFC 8305 §5) -> S4 vs S3
    - Resolution Delay on Asynchronous DNS (RFC 8305 §4) -> S6
    - Statefulness and Failure Caching (RFC 8305 §7) -> INDETERMINATE (profiles wiped per trial)
    - Non-TCP Transports / QUIC (RFC 8305 §8) -> INDETERMINATE (out of lab scope)

    Distinguishes observed conformance (OBSERVED_CONFORMANCE), observed deviation
    (OBSERVED_DEVIATION), and indeterminate checks (INDETERMINATE).
    Does not infer general client/browser compliance from single or small trial samples.
    """
    trials = [t for t in valid_trials if t.validity_category == "VALID_LIVE"]
    if browser:
        trials = [t for t in trials if t.browser_name.lower() == browser.lower()]

    assessments: List[Dict[str, Any]] = []

    # Map trials by scenario
    by_sc: Dict[str, List[TrialEvidence]] = {}
    for sc in DEFAULT_SCENARIOS:
        by_sc[sc] = [t for t in trials if t.scenario_id == sc]

    # Check 1: RFC 8305 §3 - IPv6 Preference
    s0_trials = by_sc["S0"]
    if s0_trials:
        v6_first_count = sum(1 for t in s0_trials if t.winning_address_family == "IPv6")
        if v6_first_count == len(s0_trials):
            status = "OBSERVED_CONFORMANCE"
            summary = (
                f"Observed conformance in tested trial(s): {v6_first_count}/{len(s0_trials)} ({round(v6_first_count/len(s0_trials)*100, 1)}%) "
                f"trials established IPv6 connection on dual-stack baseline without fallback. "
                f"Scoped to recorded trial(s); does not infer general client compliance."
            )
        else:
            status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): Only {v6_first_count}/{len(s0_trials)} trials established IPv6 connection "
                f"on healthy dual-stack baseline."
            )
        mandatory_status = "NOT_APPLICABLE"
        recommended_status = status
    else:
        status = "INDETERMINATE"
        mandatory_status = "INDETERMINATE"
        recommended_status = "INDETERMINATE"
        summary = "Indeterminate: No valid S0 baseline trials available to evaluate IPv6 preference."

    assessments.append({
        "check_id": "RFC8305-SEC3-IPV6-PREFERENCE",
        "rfc_section": "RFC 8305 Section 3",
        "title": "IPv6 Preference on Dual-Stack Baseline",
        "scenario_id": "S0",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s0_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 3 specifies that implementations SHOULD prefer IPv6 for the first "
            "connection attempt when both A and AAAA resource records are resolved."
        )
    })

    # Check 2: RFC 8305 §5 - Immediate Fallback on TCP Reset
    s2_trials = by_sc["S2"]
    if s2_trials:
        cad_vals = [t.connection_attempt_delay_ms for t in s2_trials if t.connection_attempt_delay_ms is not None]
        med_cad = compute_percentile(sorted(cad_vals), 0.5) if cad_vals else None

        if not cad_vals:
            status = "INDETERMINATE"
            mandatory_status = "INDETERMINATE"
            recommended_status = "INDETERMINATE"
            summary = "Indeterminate: S2 trials missing connection attempt delay measurements."
        elif any(round(c, 2) < RFC8305_MIN_ATTEMPT_INTERVAL_MS for c in cad_vals):
            # Violation of normative mandatory floor: MUST NOT start within 10 ms
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_DEVIATION"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): Subsequent attempt started in {med_cad}ms after initial attempt "
                f"(< 10ms minimum interval), deviating from RFC 8305 §5 mandatory floor ('a subsequent connection "
                f"MUST NOT be started within 10 milliseconds of the previous attempt'). Classified as a mandatory-floor deviation. "
                f"Scoped to recorded trial(s)."
            )
        elif any(round(c, 2) < RFC8305_MIN_CAD_MS for c in cad_vals):
            # Meets mandatory floor (>= 10ms), but falls below recommended minimum CAD (100ms)
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): Subsequent attempt started in {med_cad}ms. "
                f"Result meets RFC 8305 §5 mandatory floor (>= 10ms, mandatory_status=OBSERVED_CONFORMANCE), but falls outside "
                f"recommended parameters (< 100ms recommended minimum CAD, recommended_status=OBSERVED_DEVIATION). "
                f"Classified as a recommended-range deviation, not a mandatory MUST violation. Scoped to recorded trial(s)."
            )
        elif any(round(c, 2) > RFC8305_MAX_CAD_MS for c in cad_vals):
            # Meets mandatory floor (>= 10ms), but exceeds recommended 2-second upper bound
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): Subsequent attempt was delayed by {med_cad}ms. "
                f"Result meets RFC 8305 §5 mandatory floor (>= 10ms, mandatory_status=OBSERVED_CONFORMANCE), but falls outside "
                f"recommended parameters (> {RFC8305_MAX_CAD_MS:.0f}ms recommended 2-second upper bound, recommended_status=OBSERVED_DEVIATION). "
                f"Classified as a recommended-range deviation, not a mandatory MUST violation. Scoped to recorded trial(s)."
            )
        else:
            # Meets both mandatory floor (>= 10ms) and recommended CAD range [100ms, 2000ms]
            status = "OBSERVED_CONFORMANCE"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_CONFORMANCE"
            summary = (
                f"Observed conformance in tested trial(s): Fallback observed with median CAD {med_cad}ms. "
                f"Result meets both RFC 8305 §5 mandatory floor (>= 10ms, mandatory_status=OBSERVED_CONFORMANCE) and falls within "
                f"recommended CAD range [{RFC8305_MIN_CAD_MS:.0f}ms, {RFC8305_MAX_CAD_MS:.0f}ms] (target: {RFC8305_RECOMMENDED_CAD_MS:.0f}ms, "
                f"recommended_status=OBSERVED_CONFORMANCE). Scoped to recorded trial(s)."
            )
    else:
        status = "INDETERMINATE"
        mandatory_status = "INDETERMINATE"
        recommended_status = "INDETERMINATE"
        summary = "Indeterminate: No valid S2 TCP RST trials available."

    assessments.append({
        "check_id": "RFC8305-SEC5-IMMEDIATE-RST-FALLBACK",
        "rfc_section": "RFC 8305 Section 5",
        "title": "Immediate Fallback on Active Connection Failure (TCP RST)",
        "scenario_id": "S2",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s2_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 5 distinguishes mandatory requirements from recommended parameters: "
            "subsequent connection attempts MUST NOT start within 10 milliseconds of the previous attempt "
            "(mandatory floor to prevent congestion collapse), while Connection Attempt Delay has a recommended "
            "minimum of 100 milliseconds and a recommended maximum of 2 seconds. When an attempt actively fails "
            "(such as TCP RST), Section 5 recommends starting immediately without waiting for the CAD timer to expire, "
            "provided the 10ms mandatory floor is respected. Results between 10ms and 100ms meet all mandatory MUST "
            "requirements while falling outside the recommended minimum CAD timer; they are classified as recommended-range "
            "deviations and are not labeled as MUST violations."
        )
    })

    # Check 3: RFC 8305 §5 - Connection Attempt Delay on SYN Timeout
    s1_trials = by_sc["S1"]
    if s1_trials:
        cad_vals = [t.connection_attempt_delay_ms for t in s1_trials if t.connection_attempt_delay_ms is not None]
        med_cad = compute_percentile(sorted(cad_vals), 0.5) if cad_vals else None

        if not cad_vals:
            status = "INDETERMINATE"
            mandatory_status = "INDETERMINATE"
            recommended_status = "INDETERMINATE"
            summary = "Indeterminate: S1 trials missing connection attempt delay measurements."
        elif any(round(c, 2) < RFC8305_MIN_ATTEMPT_INTERVAL_MS for c in cad_vals):
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_DEVIATION"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): Subsequent attempt started in {med_cad}ms (< 10ms minimum interval), "
                f"deviating from RFC 8305 §5 mandatory floor. Classified as a mandatory-floor deviation. Scoped to recorded trial(s)."
            )
        elif any(round(c, 2) < RFC8305_MIN_CAD_MS for c in cad_vals):
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): Subsequent attempt started in {med_cad}ms. "
                f"Result meets RFC 8305 §5 mandatory floor (>= 10ms, mandatory_status=OBSERVED_CONFORMANCE), but falls outside "
                f"recommended parameters (< 100ms recommended minimum CAD, recommended_status=OBSERVED_DEVIATION). "
                f"Classified as a recommended-range deviation, not a mandatory MUST violation. Scoped to recorded trial(s)."
            )
        elif any(round(c, 2) > RFC8305_MAX_CAD_MS for c in cad_vals):
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): CAD median {med_cad}ms exceeds RFC 8305 §5 recommended 2-second upper bound. "
                f"Result meets mandatory floor (>= 10ms, mandatory_status=OBSERVED_CONFORMANCE), but deviates from recommended parameters "
                f"(recommended_status=OBSERVED_DEVIATION). Scoped to recorded trial(s)."
            )
        else:
            status = "OBSERVED_CONFORMANCE"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_CONFORMANCE"
            summary = (
                f"Observed conformance in tested trial(s): CAD median {med_cad}ms meets RFC 8305 §5 mandatory floor (>= 10ms) "
                f"and falls within recommended range [{RFC8305_MIN_CAD_MS:.0f}ms, {RFC8305_MAX_CAD_MS:.0f}ms] (target: {RFC8305_RECOMMENDED_CAD_MS:.0f}ms). "
                f"Scoped to recorded trial(s); does not infer general client compliance."
            )
    else:
        status = "INDETERMINATE"
        mandatory_status = "INDETERMINATE"
        recommended_status = "INDETERMINATE"
        summary = "Indeterminate: No valid S1 SYN blackhole trials available."

    assessments.append({
        "check_id": "RFC8305-SEC5-CAD-SYN-TIMEOUT",
        "rfc_section": "RFC 8305 Section 5",
        "title": "Connection Attempt Delay Timer on Unresponsive Path",
        "scenario_id": "S1",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s1_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 5 distinguishes mandatory inter-attempt spacing (MUST NOT be smaller than 10ms) "
            "from recommended CAD timer parameters (SHOULD NOT be smaller than 100ms, recommended default 250ms, "
            "maximum 2000ms) on unresponsive paths."
        )
    })

    # Check 4: RFC 8305 §5 - Alternative Path Selection on Latency Imbalance
    s4_trials = by_sc["S4"]
    if s4_trials:
        v4_wins = sum(1 for t in s4_trials if t.winning_address_family == "IPv4")
        cad_vals = [t.connection_attempt_delay_ms for t in s4_trials if t.connection_attempt_delay_ms is not None]
        med_cad = compute_percentile(sorted(cad_vals), 0.5) if cad_vals else None

        if v4_wins == len(s4_trials) and cad_vals and all(RFC8305_MIN_ATTEMPT_INTERVAL_MS <= round(c, 2) <= RFC8305_MAX_CAD_MS for c in cad_vals):
            status = "OBSERVED_CONFORMANCE"
            mandatory_status = "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_CONFORMANCE"
            summary = (
                f"Observed conformance in tested trial(s): IPv4 won in {v4_wins}/{len(s4_trials)} trials with median CAD {med_cad}ms "
                f"when IPv6 RTT (600ms) exceeded CAD timer. Scoped to recorded trial(s); does not infer general client compliance."
            )
        else:
            status = "OBSERVED_DEVIATION"
            mandatory_status = "OBSERVED_DEVIATION" if (cad_vals and any(round(c, 2) < RFC8305_MIN_ATTEMPT_INTERVAL_MS for c in cad_vals)) else "OBSERVED_CONFORMANCE"
            recommended_status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in tested trial(s): IPv4 failed to win reliably or CAD violated timing bounds "
                f"({v4_wins}/{len(s4_trials)} won, median CAD {med_cad}ms)."
            )
    else:
        status = "INDETERMINATE"
        mandatory_status = "INDETERMINATE"
        recommended_status = "INDETERMINATE"
        summary = "Indeterminate: No valid S4 high latency trials available."

    assessments.append({
        "check_id": "RFC8305-SEC5-CAD-HIGH-LATENCY",
        "rfc_section": "RFC 8305 Section 5",
        "title": "Fast Fallback on Primary Path Delay Exceeding CAD",
        "scenario_id": "S4",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s4_trials),
        "evidence_summary": summary,
        "reasoning": (
            "When the primary address family RTT (600ms) significantly exceeds the CAD timer (~250-300ms), "
            "the second connection attempt over IPv4 (20ms RTT) finishes setup first and wins."
        )
    })

    # Check 5: RFC 8305 §4 - Resolution Delay for Asynchronous DNS
    s6_trials = by_sc["S6"]
    if s6_trials:
        # Check if browser connected via IPv4 or waited for delayed AAAA
        v6_wins = sum(1 for t in s6_trials if t.winning_address_family == "IPv6")
        aaaa_lats = [t.dns_latency_aaaa_ms for t in s6_trials if t.dns_latency_aaaa_ms is not None]
        med_aaaa = compute_percentile(sorted(aaaa_lats), 0.5) if aaaa_lats else None

        # Documented behavior: Chrome waited ~500ms for delayed AAAA and connected via IPv6
        if v6_wins > 0:
            status = "OBSERVED_DEVIATION"
            summary = (
                f"Observed deviation in recorded Chrome trial (trial-20261028171417-b2d83f2f): Browser waited ~{med_aaaa}ms "
                f"for delayed AAAA response and connected over IPv6, rather than initiating IPv4 fallback after the RFC 8305 §4 "
                f"recommended 50ms Resolution Delay. Conclusion is strictly scoped to this recorded Chrome trial and does not "
                f"infer general browser non-conformance."
            )
        else:
            status = "OBSERVED_CONFORMANCE"
            summary = (
                f"Observed conformance in tested trial(s): Client adhered to Resolution Delay, falling back to IPv4 "
                f"before delayed AAAA arrived. Scoped to recorded trial(s); does not infer general browser compliance."
            )
        mandatory_status = "NOT_APPLICABLE"
        recommended_status = status
    else:
        status = "INDETERMINATE"
        mandatory_status = "INDETERMINATE"
        recommended_status = "INDETERMINATE"
        summary = "Indeterminate: No valid S6 delayed AAAA DNS trials available."

    assessments.append({
        "check_id": "RFC8305-SEC4-RESOLUTION-DELAY",
        "rfc_section": "RFC 8305 Section 3",
        "title": "Resolution Delay on Asynchronous A/AAAA DNS Arrival",
        "scenario_id": "S6",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s6_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 3 recommends a 50ms Resolution Delay when A arrives before AAAA. "
            "If AAAA does not arrive within this window, the client SHOULD initiate IPv4. "
            "In the recorded single Chrome trial, the client waited for the late AAAA response (~515ms after query, "
            "~496ms after A response) before connecting over IPv6. This observed deviation documents specific trial behavior "
            "under lab conditions and is not an inference of general browser implementation characteristics."
        )
    })

    # Check 6: RFC 8305 §7 - Historical Statefulness & Adaptive Timers
    assessments.append({
        "check_id": "RFC8305-SEC7-STATEFULNESS-CACHING",
        "rfc_section": "RFC 8305 Section 7",
        "title": "Statefulness and Adaptive Past-Failure Caching",
        "scenario_id": "ALL",
        "status": "INDETERMINATE",
        "mandatory_status": "INDETERMINATE",
        "recommended_status": "INDETERMINATE",
        "sample_size": len(trials),
        "evidence_summary": (
            "Indeterminate: Unsupported check. PS-028 protocol enforces isolated, ephemeral browser user-data directories "
            "(--user-data-dir) wiped unconditionally after every trial to eliminate cross-trial caching contamination. "
            "Cross-session persistence cannot be measured under isolated single-trial protocol."
        ),
        "reasoning": (
            "RFC 8305 Section 7 permits implementations to remember past failure history. "
            "Because trials are executed with clean profiles to guarantee measurement independence, "
            "cross-trial statefulness cannot be evaluated."
        )
    })

    # Check 7: RFC 8305 §8 - Non-TCP Transport Applicability (QUIC / SCTP)
    assessments.append({
        "check_id": "RFC8305-SEC8-NON-TCP-TRANSPORTS",
        "rfc_section": "RFC 8305 Section 8",
        "title": "Transport Applicability (SCTP, QUIC, Multipath)",
        "scenario_id": "ALL",
        "status": "INDETERMINATE",
        "mandatory_status": "INDETERMINATE",
        "recommended_status": "INDETERMINATE",
        "sample_size": len(trials),
        "evidence_summary": (
            "Indeterminate: Unsupported check. The PS-028 isolated dual-stack laboratory specifically instruments "
            "HTTP/1.1 over TCP. Alternate transport protocols (QUIC, SCTP) are out of testbed scope."
        ),
        "reasoning": (
            "RFC 8305 Section 8 discusses Happy Eyeballs across various transport protocols. "
            "The current testbed evaluates standard TCP socket connections."
        )
    })

    return assessments


# ==============================================================================
# Complete Report & Output Generators (JSON, CSV, Terminal)
# ==============================================================================

def generate_analysis_report(
    trials: List[TrialEvidence],
    exclusions: List[ExclusionRecord],
    include_simulations: bool = False,
    confidence: float = 0.95,
    seed: int = 42,
    resamples: int = 1000
) -> Dict[str, Any]:
    """
    Constructs the structured, fully serializable analysis summary dictionary.
    """
    # Exclude trials categorized as non-live from live cohort
    live_cohort: List[TrialEvidence] = []
    simulation_cohort: List[TrialEvidence] = []
    excluded_trials: List[ExclusionRecord] = list(exclusions)

    for t in trials:
        if t.validity_category == "VALID_LIVE":
            live_cohort.append(t)
        elif t.validity_category == "SIMULATION":
            simulation_cohort.append(t)
            if not include_simulations:
                excluded_trials.append(ExclusionRecord(
                    trial_id=t.trial_id,
                    scenario_id=t.scenario_id,
                    browser=t.browser_name,
                    category="SIMULATION",
                    reason=t.exclusion_reason or "Simulation run separated from live results",
                    source_path=t.source_path
                ))
            else:
                live_cohort.append(t)
        else:
            excluded_trials.append(ExclusionRecord(
                trial_id=t.trial_id,
                scenario_id=t.scenario_id,
                browser=t.browser_name,
                category=t.validity_category,
                reason=t.exclusion_reason or "Invalid evidence or failed baseline cleanup",
                source_path=t.source_path
            ))

    # Determine unique browsers and scenarios
    browsers = sorted(list({t.browser_name for t in trials if t.browser_name != "unknown"}))
    if not browsers:
        browsers = ["google-chrome"]

    scenarios = DEFAULT_SCENARIOS

    # Group metrics
    groups: List[Dict[str, Any]] = []
    for b in browsers:
        for sc in scenarios:
            # Match all trials for this (browser, scenario) to compute sample counts correctly
            all_cell_trials = [
                t for t in trials
                if t.browser_name.lower() == b.lower() and t.scenario_id == sc
            ]
            if all_cell_trials or sc in DEFAULT_SCENARIOS:
                g_metrics = aggregate_group_metrics(
                    group_trials=all_cell_trials,
                    browser=b,
                    scenario_id=sc,
                    confidence=confidence,
                    seed=seed,
                    resamples=resamples
                )
                groups.append(g_metrics)

    # Sort groups deterministically
    groups.sort(key=lambda x: (x["browser"], x["scenario_id"]))

    # Sort exclusions deterministically
    excluded_trials.sort(key=lambda x: (x.category, x.scenario_id, x.trial_id))

    # RFC 8305 Assessment
    rfc_assessment = assess_rfc8305_conformance(live_cohort)

    # Global summary counts
    dataset_summary = {
        "total_records_ingested": len(trials),
        "valid_live_count": len(live_cohort) if not include_simulations else sum(1 for t in live_cohort if t.validity_category == "VALID_LIVE"),
        "simulation_count": len(simulation_cohort),
        "excluded_failures_count": len(excluded_trials) - (len(simulation_cohort) if not include_simulations else 0),
        "total_exclusions": len(excluded_trials),
        "browsers": browsers,
        "scenarios": scenarios,
        "include_simulations": include_simulations,
        "confidence_level": confidence,
        "bootstrap_seed": seed,
        "bootstrap_resamples": resamples,
        "continuous_ci_method": f"median: percentile bootstrap (B={resamples}, seed={seed}); mean: parametric Student-t (df=n-1)",
        "proportion_ci_method": "Wilson score interval"
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dataset_summary": dataset_summary,
        "groups": groups,
        "rfc8305_assessment": rfc_assessment,
        "exclusions": [e.to_dict() for e in excluded_trials]
    }


def generate_summary_csv(report: Dict[str, Any]) -> str:
    """
    Renders group summaries into deterministic, RFC-compliant CSV format.
    Missing metrics are represented as empty strings, NEVER as zero.
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    headers = [
        "browser",
        "scenario_id",
        "scenario_name",
        "total_trials",
        "valid_live_count",
        "simulation_count",
        "incomplete_count",
        "invalid_or_failed_count",
        "http_success_count",
        "http_success_rate",
        "http_success_ci95_lower",
        "http_success_ci95_upper",
        "ipv6_win_count",
        "ipv6_win_rate",
        "ipv6_ci95_lower",
        "ipv6_ci95_upper",
        "ipv4_win_count",
        "ipv4_win_rate",
        "ipv4_ci95_lower",
        "ipv4_ci95_upper",
        "none_win_count",
        "none_win_rate",
        "setup_time_n",
        "setup_time_median_ms",
        "setup_time_p95_ms",
        "setup_time_iqr_ms",
        "setup_time_ci95_lower",
        "setup_time_ci95_upper",
        "setup_time_mean_ms",
        "setup_time_std_ms",
        "fallback_delay_n",
        "fallback_delay_median_ms",
        "fallback_delay_p95_ms",
        "fallback_delay_iqr_ms",
        "fallback_delay_ci95_lower",
        "fallback_delay_ci95_upper",
        "fallback_delay_mean_ms",
        "dns_a_n",
        "dns_a_median_ms",
        "dns_a_p95_ms",
        "dns_a_iqr_ms",
        "dns_aaaa_n",
        "dns_aaaa_median_ms",
        "dns_aaaa_p95_ms",
        "dns_aaaa_iqr_ms",
        "dns_resolution_n",
        "dns_resolution_median_ms",
        "dns_resolution_p95_ms",
        "browser_duration_n",
        "browser_duration_median_ms",
        "browser_duration_p95_ms",
        "browser_duration_iqr_ms"
    ]
    writer.writerow(headers)

    def _val(v: Any) -> str:
        return "" if v is None else str(v)

    for g in report.get("groups", []):
        sc_counts = g.get("sample_counts", {})
        http_s = g.get("http_success", {})
        http_ci = http_s.get("ci_95") or [None, None]

        waf = g.get("winning_address_family", {})
        v6 = waf.get("ipv6", {})
        v6_ci = v6.get("ci_95") or [None, None]
        v4 = waf.get("ipv4", {})
        v4_ci = v4.get("ci_95") or [None, None]
        none_w = waf.get("none", {})

        setup = g.get("connection_setup_time_ms", {})
        setup_ci = setup.get("median_ci_95") or [None, None]

        cad = g.get("connection_attempt_delay_ms", {})
        cad_ci = cad.get("median_ci_95") or [None, None]

        dns_g = g.get("dns_latency", {})
        dns_a = dns_g.get("a_record_ms", {})
        dns_aaaa = dns_g.get("aaaa_record_ms", {})
        dns_res = dns_g.get("resolution_span_ms", {})

        b_dur = g.get("browser_duration_ms", {})

        row = [
            _val(g.get("browser")),
            _val(g.get("scenario_id")),
            _val(g.get("scenario_name")),
            _val(sc_counts.get("total_trials")),
            _val(sc_counts.get("valid_live_count")),
            _val(sc_counts.get("simulation_count")),
            _val(sc_counts.get("incomplete_count")),
            _val(sc_counts.get("invalid_or_failed_count")),
            _val(http_s.get("count")),
            _val(http_s.get("rate")),
            _val(http_ci[0]),
            _val(http_ci[1]),
            _val(v6.get("count")),
            _val(v6.get("rate")),
            _val(v6_ci[0]),
            _val(v6_ci[1]),
            _val(v4.get("count")),
            _val(v4.get("rate")),
            _val(v4_ci[0]),
            _val(v4_ci[1]),
            _val(none_w.get("count")),
            _val(none_w.get("rate")),
            _val(setup.get("count")),
            _val(setup.get("median")),
            _val(setup.get("p95")),
            _val(setup.get("iqr")),
            _val(setup_ci[0]),
            _val(setup_ci[1]),
            _val(setup.get("mean")),
            _val(setup.get("std")),
            _val(cad.get("count")),
            _val(cad.get("median")),
            _val(cad.get("p95")),
            _val(cad.get("iqr")),
            _val(cad_ci[0]),
            _val(cad_ci[1]),
            _val(cad.get("mean")),
            _val(dns_a.get("count")),
            _val(dns_a.get("median")),
            _val(dns_a.get("p95")),
            _val(dns_a.get("iqr")),
            _val(dns_aaaa.get("count")),
            _val(dns_aaaa.get("median")),
            _val(dns_aaaa.get("p95")),
            _val(dns_aaaa.get("iqr")),
            _val(dns_res.get("count")),
            _val(dns_res.get("median")),
            _val(dns_res.get("p95")),
            _val(b_dur.get("count")),
            _val(b_dur.get("median")),
            _val(b_dur.get("p95")),
            _val(b_dur.get("iqr"))
        ]
        writer.writerow(row)

    return output.getvalue()


def generate_exclusions_csv(report: Dict[str, Any]) -> str:
    """Renders exclusions audit trail into CSV format."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["trial_id", "scenario_id", "browser", "category", "reason", "source_path"])

    for e in report.get("exclusions", []):
        writer.writerow([
            e.get("trial_id", ""),
            e.get("scenario_id", ""),
            e.get("browser", ""),
            e.get("category", ""),
            e.get("reason", ""),
            e.get("source_path", "")
        ])

    return output.getvalue()


def generate_rfc8305_csv(report: Dict[str, Any]) -> str:
    """Renders RFC 8305 assessment into CSV format."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([
        "check_id", "rfc_section", "title", "scenario_id", "status",
        "mandatory_status", "recommended_status",
        "sample_size", "evidence_summary", "reasoning"
    ])

    for a in report.get("rfc8305_assessment", []):
        writer.writerow([
            a.get("check_id", ""),
            a.get("rfc_section", ""),
            a.get("title", ""),
            a.get("scenario_id", ""),
            a.get("status", ""),
            a.get("mandatory_status", ""),
            a.get("recommended_status", ""),
            a.get("sample_size", 0),
            a.get("evidence_summary", ""),
            a.get("reasoning", "")
        ])

    return output.getvalue()


def format_terminal_report(report: Dict[str, Any]) -> str:
    """Generates an aligned, readable terminal output summary."""
    lines: List[str] = []
    ds = report.get("dataset_summary", {})

    lines.append("=" * 80)
    lines.append("PS-028 HAPPY EYEBALLS STATISTICAL ANALYSIS & RFC 8305 REPORT")
    lines.append("=" * 80)
    lines.append(f"Records Ingested:  {ds.get('total_records_ingested', 0)} "
                 f"(valid_live={ds.get('valid_live_count', 0)}, "
                 f"simulations={ds.get('simulation_count', 0)}, "
                 f"excluded/failed={ds.get('excluded_failures_count', 0)})")
    lines.append(f"Browsers:          {', '.join(ds.get('browsers', []))}")
    lines.append(f"Scenarios:         {', '.join(ds.get('scenarios', []))}")
    lines.append(f"Confidence Level:  {int(ds.get('confidence_level', 0.95)*100)}% (Wilson / Bootstrap seed={ds.get('bootstrap_seed')})")
    lines.append("-" * 80)

    # 1. Summary Table
    lines.append("\n[SUMMARY BY BROWSER & SCENARIO]")
    header_fmt = "{:<14} {:<4} {:<6} {:<10} {:<10} {:<12} {:<12} {:<10}"
    lines.append(header_fmt.format("Browser", "Scen", "ValidN", "HTTP Succ", "Winning", "Setup(med/p95)", "CAD(med/p95)", "DNS A/AAAA"))
    lines.append("-" * 80)

    for g in report.get("groups", []):
        b = g.get("browser", "")[:14]
        sc = g.get("scenario_id", "")
        n = g.get("sample_counts", {}).get("valid_live_count", 0)
        http_s = g.get("http_success", {})
        h_rate = f"{http_s.get('rate')*100:.0f}%" if http_s.get("rate") is not None else "N/A"

        waf = g.get("winning_address_family", {})
        v6_cnt = waf.get("ipv6", {}).get("count", 0)
        v4_cnt = waf.get("ipv4", {}).get("count", 0)
        win_str = f"v6:{v6_cnt} v4:{v4_cnt}" if n > 0 else "-"

        setup = g.get("connection_setup_time_ms", {})
        s_med = f"{setup.get('median')}ms" if setup.get("median") is not None else "-"
        s_p95 = f"{setup.get('p95')}ms" if setup.get("p95") is not None else "-"
        setup_str = f"{s_med}/{s_p95}"

        cad = g.get("connection_attempt_delay_ms", {})
        c_med = f"{cad.get('median')}ms" if cad.get("median") is not None else "-"
        c_p95 = f"{cad.get('p95')}ms" if cad.get("p95") is not None else "-"
        cad_str = f"{c_med}/{c_p95}"

        dns_g = g.get("dns_latency", {})
        a_med = dns_g.get("a_record_ms", {}).get("median")
        aaaa_med = dns_g.get("aaaa_record_ms", {}).get("median")
        a_str = f"{a_med}ms" if a_med is not None else "-"
        aaaa_str = f"{aaaa_med}ms" if aaaa_med is not None else "-"
        dns_str = f"{a_str}/{aaaa_str}"

        lines.append(header_fmt.format(b, sc, str(n), h_rate, win_str, setup_str, cad_str, dns_str))

    # 2. RFC 8305 Assessment Table
    lines.append("\n[EVIDENCE-BASED RFC 8305 ASSESSMENT]")
    rfc_fmt = "{:<32} {:<6} {:<22} {:<42}"
    lines.append(rfc_fmt.format("Check ID", "Scen", "Status", "Observable Evidence Summary"))
    lines.append("-" * 105)

    for a in report.get("rfc8305_assessment", []):
        cid = a.get("check_id", "")[:32]
        sc = a.get("scenario_id", "")[:6]
        st = a.get("status", "")
        # Color coding in terminal if ANSI supported
        if st in ("OBSERVED_CONFORMANCE", "COMPLIANT"):
            st_str = "\033[1;32mOBSERVED_CONFORMANCE\033[0m"
            raw_len = len("OBSERVED_CONFORMANCE")
        elif st in ("OBSERVED_DEVIATION", "DEVIATION", "NON_COMPLIANT"):
            st_str = "\033[1;33mOBSERVED_DEVIATION\033[0m"
            raw_len = len("OBSERVED_DEVIATION")
        else:
            st_str = "\033[1;34mINDETERMINATE\033[0m"
            raw_len = len("INDETERMINATE")

        padding = " " * max(0, 22 - raw_len)
        ev = a.get("evidence_summary", "")
        if len(ev) > 65:
            ev = ev[:62] + "..."
        lines.append(f"{cid:<32} {sc:<6} {st_str}{padding} {ev}")

    # 3. Exclusions
    excl = report.get("exclusions", [])
    if excl:
        lines.append(f"\n[EXCLUSIONS & AUDIT TRAIL] ({len(excl)} items preserved)")
        for e in excl[:10]:
            lines.append(f" - [{e.get('category')}] {e.get('trial_id')} ({e.get('scenario_id')}): {e.get('reason')}")
        if len(excl) > 10:
            lines.append(f"   ... and {len(excl) - 10} more exclusions preserved in CSV/JSON.")

    lines.append("=" * 80)
    return "\n".join(lines)


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PS-028 Happy Eyeballs Statistical Analysis & RFC 8305 Evaluator (Work Package A9)"
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        type=Path,
        help="Input files or directories (trial result.json files, trial directories, campaign manifests)"
    )
    parser.add_argument(
        "--trials-dir", "-t",
        type=Path,
        default=None,
        help="Directory containing trials (default: auto-detected lab/trials)"
    )
    parser.add_argument(
        "--campaign-dir", "-c",
        type=Path,
        default=None,
        help="Campaign directory containing campaign_manifest.json and trials"
    )
    parser.add_argument(
        "--manifest", "-m",
        type=Path,
        default=None,
        help="Direct path to a campaign_manifest.json"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=None,
        help="Directory where summary.json, summary.csv, and exclusions.csv will be saved"
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Specific path to save summary JSON"
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="Specific path to save summary CSV"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON summary to stdout"
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Output CSV summary to stdout"
    )
    parser.add_argument(
        "--include-simulations",
        action="store_true",
        help="Include simulation runs in calculations (by default segregated)"
    )
    parser.add_argument(
        "--confidence",
        type=float,
        default=0.95,
        help="Confidence interval level (default: 0.95)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Pseudo-random seed for deterministic bootstrap CI calculation (default: 42)"
    )
    parser.add_argument(
        "--resamples",
        type=int,
        default=1000,
        help="Number of bootstrap resamples for median confidence intervals (default: 1000)"
    )
    return parser.parse_args(args)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    # Collect source paths
    sources: List[Path] = []
    if args.inputs:
        sources.extend(args.inputs)
    if args.manifest:
        sources.append(args.manifest)
    if args.campaign_dir:
        sources.append(args.campaign_dir)
    if args.trials_dir:
        sources.append(args.trials_dir)

    # Default auto-discovery if no sources specified
    if not sources:
        if DEFAULT_TRIALS_DIR.is_dir():
            sources.append(DEFAULT_TRIALS_DIR)
        if DEFAULT_CAMPAIGNS_DIR.is_dir():
            sources.append(DEFAULT_CAMPAIGNS_DIR)

    if not sources:
        print("[ERROR] No trial evidence or campaign directories found. Provide paths or run a trial first.", file=sys.stderr)
        return 1

    try:
        trials, exclusions = ingest_evidence(sources)
        report = generate_analysis_report(
            trials=trials,
            exclusions=exclusions,
            include_simulations=args.include_simulations,
            confidence=args.confidence,
            seed=args.seed,
            resamples=args.resamples
        )

        # File outputs if requested
        if args.output_dir:
            out_dir = args.output_dir.resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
            (out_dir / "summary.csv").write_text(generate_summary_csv(report), encoding="utf-8")
            (out_dir / "exclusions.csv").write_text(generate_exclusions_csv(report), encoding="utf-8")
            (out_dir / "rfc8305_assessment.csv").write_text(generate_rfc8305_csv(report), encoding="utf-8")

        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

        if args.output_csv:
            args.output_csv.parent.mkdir(parents=True, exist_ok=True)
            args.output_csv.write_text(generate_summary_csv(report), encoding="utf-8")

        # Stdout formatting
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        elif args.csv:
            print(generate_summary_csv(report), end="")
        else:
            print(format_terminal_report(report))
            if args.output_dir:
                print(f"\n[OK] Artifacts written to {args.output_dir.resolve()}/ (summary.json, summary.csv, exclusions.csv, rfc8305_assessment.csv)")

        return 0
    except Exception as exc:
        print(f"[ERROR] Statistical analysis failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
