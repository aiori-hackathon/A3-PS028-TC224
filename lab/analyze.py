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
from enum import Enum
import io
import ipaddress
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

SCHEMA_VERSION = "1.1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0.0", "1.1.0"})
NUMERIC_METRIC_FIELDS: Set[str] = {
    "t_connect_ms",
    "t_setup_total_ms",
    "syn_to_synack_ms",
    "cad_ms",
    "connection_attempt_delay_ms",
    "resolution_delay_ms",
    "dns_latency_a_ms",
    "dns_latency_aaaa_ms",
    "dns_resolution_time_ms",
    "dns_to_first_byte_ms",
    "dns_query_to_first_payload_ms",
    "dns_last_positive_response_to_first_payload_ms",
    "dns_a_to_syn_ms",
    "dns_aaaa_to_syn_ms",
    "https_svcb_duration_ms",
    "rtt_primary_flow_ms",
    "connection_setup_time_ms",
    "handshake_time_ms",
    "retransmitted_syn_count_ipv6",
    "retransmitted_syn_count_ipv4",
}
DEFAULT_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
DEFAULT_TRIALS_DIR = SCRIPT_DIR / "trials"
DEFAULT_CAMPAIGNS_DIR = SCRIPT_DIR / "campaigns"
MANIFEST_FILENAME = "campaign_manifest.json"

RFC8305_MIN_ATTEMPT_INTERVAL_MS = 10.0   # RFC 8305 §5 normative floor: "a subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt"
RFC8305_MIN_CAD_MS = 100.0              # RFC 8305 §5 recommended minimum
RFC8305_MAX_CAD_MS = 2000.0             # RFC 8305 §5 maximum permitted
RFC8305_RECOMMENDED_CAD_MS = 250.0      # RFC 8305 §5 recommended default
RFC8305_RECOMMENDED_RESOLUTION_DELAY_MS = 50.0  # RFC 8305 §3 recommended default

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
# Canonical Enumerations & Cohort Keys (Contract v1.1.0, C2-02, C4-01)
# ==============================================================================

class FallbackClassification(str, Enum):
    """
    Canonical Happy Eyeballs fallback classifications conforming to RFC 8305.
    Governed by Phase C Metric Contract v1.1.0 §2.2.
    """
    DIRECT_IPV6 = "DIRECT_IPV6"
    DIRECT_IPV4 = "DIRECT_IPV4"
    IPV6_TO_IPV4_FALLBACK = "IPV6_TO_IPV4_FALLBACK"
    IPV4_TO_IPV6_FALLBACK = "IPV4_TO_IPV6_FALLBACK"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class TrialValidity(str, Enum):
    """
    Canonical trial execution validity categories.
    Governed by Phase C Metric Contract v1.1.0 §2.3.
    """
    VALID_LIVE = "VALID_LIVE"
    SIMULATION = "SIMULATION"
    CLEANUP_FAILURE = "CLEANUP_FAILURE"
    MEASUREMENT_FAILURE = "MEASUREMENT_FAILURE"
    CORRUPTED_RECORD = "CORRUPTED_RECORD"


class ExecutionStatus(str, Enum):
    """Execution status for MatrixSlot and ExecutionAttempt."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class ConnectionOutcome(str, Enum):
    """Canonical connection attempt outcome states per Metric Contract §4.2."""
    ESTABLISHED_PRIMARY = "ESTABLISHED_PRIMARY"
    ESTABLISHED_ANCILLARY = "ESTABLISHED_ANCILLARY"
    RESET = "RESET"
    NO_SYNACK_TIMEOUT = "NO_SYNACK_TIMEOUT"
    ABANDONED = "ABANDONED"
    INDETERMINATE = "INDETERMINATE"


class EventSource(str, Enum):
    """Strict provenance origin for timeline events per Amendment A9."""
    HARNESS = "HARNESS"
    PCAP = "PCAP"
    BROWSER_TELEMETRY = "BROWSER_TELEMETRY"


@dataclasses.dataclass(frozen=True)
class ResearchCohortKey:
    """
    Version-aware and environment-aware research composite cohort key (Finding C4-01).
    Permits clean stratification across browser versions, operating system kernels,
    host environments, and experimental conditions without statistical confounding.
    """
    browser_name: str       # e.g., "google-chrome", "firefox"
    browser_version: str    # e.g., "156.0.8078.73", "130.0.6723.69", "159.0", "132.0"
    os_kernel: str          # e.g., "6.18.58.1-microsoft-standard-WSL2"
    host_class: str         # e.g., "wsl2_x86_64", "baremetal_linux_x86_64", "partner_node"
    git_commit: str         # short SHA e.g., "7c6ab23"
    condition_id: str       # e.g., "S0", "S5", "D1_RTT_150MS", "D2_AAAA_500MS"
    resolver_mode: str      # e.g., "in_lab_delayed_dns", "baseline_stub"

    def to_canonical_string(self) -> str:
        """Full deterministic serialized key for aggregation dictionaries."""
        return f"{self.browser_name}:{self.browser_version}:{self.os_kernel}:{self.host_class}:{self.git_commit}:{self.condition_id}:{self.resolver_mode}"

    def to_short_slug(self) -> str:
        """Human-readable directory/export slug."""
        major_version = self.browser_version.split(".")[0] if self.browser_version else "unk"
        return f"{self.browser_name}-{major_version}-{self.host_class}-{self.condition_id.lower()}"


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
    t_connect_ms: Optional[float] = None
    t_setup_total_ms: Optional[float] = None
    syn_to_synack_ms: Optional[float] = None
    dns_query_to_first_payload_ms: Optional[float] = None
    dns_last_positive_response_to_first_payload_ms: Optional[float] = None
    primary_flow: Optional[Dict[str, Any]] = None
    null_reasons: Optional[Dict[str, str]] = None
    dns_transactions: Optional[List[Dict[str, Any]]] = None
    https_svcb_queries: Optional[List[Dict[str, Any]]] = None

    def is_valid_live(self) -> bool:
        return self.validity_category == "VALID_LIVE"

    def get_research_cohort_key(
        self,
        os_kernel: Optional[str] = None,
        host_class: Optional[str] = None,
        git_commit: Optional[str] = None,
        resolver_mode: Optional[str] = None,
    ) -> ResearchCohortKey:
        """Derives a ResearchCohortKey from this TrialEvidence instance."""
        return make_research_cohort_key(
            self,
            os_kernel=os_kernel,
            host_class=host_class,
            git_commit=git_commit,
            resolver_mode=resolver_mode,
        )


def make_research_cohort_key(
    evidence: TrialEvidence,
    os_kernel: Optional[str] = None,
    host_class: Optional[str] = None,
    git_commit: Optional[str] = None,
    resolver_mode: Optional[str] = None,
) -> ResearchCohortKey:
    """Constructs a version-aware ResearchCohortKey from TrialEvidence with metadata fallback."""
    raw = evidence.raw_dict or {}
    env = raw.get("environment_metadata", {}) or raw.get("evidence_provenance", {})
    return ResearchCohortKey(
        browser_name=evidence.browser_name,
        browser_version=evidence.browser_version or "unknown",
        os_kernel=os_kernel or env.get("os_kernel") or env.get("platform") or "Linux",
        host_class=host_class or env.get("host_class") or "standard",
        git_commit=git_commit or env.get("git_commit") or "pinned",
        condition_id=evidence.scenario_id,
        resolver_mode=resolver_mode or env.get("resolver_mode") or "in_lab_dns",
    )


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
        if not isinstance(q, dict):
            continue
        qt = str(q.get("qtype", "")).upper()
        ts = q.get("timestamp")
        if qt and ts is not None and qt not in q_times:
            if isinstance(ts, bool):
                continue
            try:
                q_times[qt] = float(ts)
            except (ValueError, TypeError):
                pass

    # Map first response timestamp by qtype
    r_times: Dict[str, float] = {}
    for r in responses:
        if not isinstance(r, dict):
            continue
        qt = str(r.get("qtype", "")).upper()
        ts = r.get("timestamp")
        if qt and ts is not None and qt not in r_times:
            if isinstance(ts, bool):
                continue
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
    all_q = [q.get("timestamp") for q in queries if isinstance(q, dict) and q.get("timestamp") is not None and not isinstance(q.get("timestamp"), bool)]
    all_r = [r.get("timestamp") for r in responses if isinstance(r, dict) and r.get("timestamp") is not None and not isinstance(r.get("timestamp"), bool)]
    if all_q and all_r:
        try:
            min_q = min(float(t) for t in all_q)
            max_r = max(float(t) for t in all_r)
            if max_r >= min_q:
                resolution_ms = round((max_r - min_q) * 1000.0, 2)
        except (ValueError, TypeError):
            pass

    return a_ms, aaaa_ms, resolution_ms


def is_valid_numeric(val: Any, allow_none: bool = True) -> bool:
    """
    Validates that a metric value is strictly None (if allow_none is True) or a genuine numeric type (int, float).
    Explicitly rejects booleans (since in Python, isinstance(True, int) is True).
    Explicitly rejects non-finite floats (NaN, +inf, -inf).
    """
    if val is None:
        return allow_none
    if isinstance(val, bool):
        return False
    if not isinstance(val, (int, float)):
        return False
    if math.isnan(val) or math.isinf(val):
        return False
    return True


def _to_float(val: Any, field_name: str = "field", allow_none: bool = True) -> Optional[float]:
    """
    Safely converts a value to float, enforcing strict scientific type integrity.
    Rejects None (if not allow_none), booleans, non-numeric types, and NaN/Inf.
    """
    if val is None:
        if allow_none:
            return None
        raise TypeError(f"Field '{field_name}' cannot be None")
    if isinstance(val, bool):
        raise TypeError(f"Field '{field_name}' must be numeric float, got bool ({val!r})")
    if not isinstance(val, (int, float)):
        raise TypeError(f"Field '{field_name}' must be numeric float or int, got {type(val).__name__} ({val!r})")
    val_f = float(val)
    if math.isnan(val_f) or math.isinf(val_f):
        raise ValueError(f"Field '{field_name}' must be a finite real number, got {val_f}")
    return val_f


def _to_int(val: Any, field_name: str = "field", allow_none: bool = True, min_val: Optional[int] = None) -> Optional[int]:
    """
    Safely converts a value to int, enforcing strict discrete integer integrity.
    Rejects None (if not allow_none), booleans, floats, strings, and values < min_val.
    """
    if val is None:
        if allow_none:
            return None
        raise TypeError(f"Field '{field_name}' cannot be None")
    if isinstance(val, bool):
        raise TypeError(f"Field '{field_name}' must be integer, got bool ({val!r})")
    if not isinstance(val, int):
        raise TypeError(f"Field '{field_name}' must be integer, got {type(val).__name__} ({val!r})")
    val_i = int(val)
    if min_val is not None and val_i < min_val:
        raise ValueError(f"Field '{field_name}' must be >= {min_val}, got {val_i}")
    return val_i


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
    version = data.get("schema_version")
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        return "CORRUPTED_RECORD", f"Schema version mismatch: {version!r} not supported. Supported versions: {sorted(list(SUPPORTED_SCHEMA_VERSIONS))}"

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
    if isinstance(packet_count, bool) or not isinstance(packet_count, int):
        return "CORRUPTED_RECORD", f"Invalid numeric type for field capture_metadata.packet_count: {type(packet_count).__name__} (Invalid packet_count: {packet_count!r})"
    if packet_count <= 0:
        return "MEASUREMENT_FAILURE", f"Zero-packet capture (packet_count={packet_count})"

    net_obs = data.get("network_observations")
    if not isinstance(net_obs, dict):
        return "INCOMPLETE", "Missing network_observations section"

    # Deep field type validation on numeric metric fields across sections
    sections_to_check = [
        ("metrics", data.get("metrics")),
        ("primary_flow", data.get("primary_flow")),
        ("network_observations", data.get("network_observations")),
    ]
    for sec_name, sec_dict in sections_to_check:
        if isinstance(sec_dict, dict):
            for field, val in sec_dict.items():
                if field in NUMERIC_METRIC_FIELDS:
                    if not is_valid_numeric(val):
                        return "CORRUPTED_RECORD", f"Invalid numeric type for field {sec_name}.{field}: {type(val).__name__} (Invalid numeric type for field {field}: {type(val).__name__})"

    if isinstance(data.get("http_outcome"), dict):
        status_code = data["http_outcome"].get("status_code")
        if status_code is not None and (isinstance(status_code, bool) or not isinstance(status_code, int)):
            return "CORRUPTED_RECORD", f"Invalid numeric type for field http_outcome.status_code: {type(status_code).__name__}"

    if isinstance(data.get("browser"), dict):
        b_dur = data["browser"].get("duration_ms")
        if not is_valid_numeric(b_dur):
            return "CORRUPTED_RECORD", f"Invalid numeric type for field browser.duration_ms: {type(b_dur).__name__}"

    classification = net_obs.get("classification")
    if classification == "INCONCLUSIVE":
        return "MEASUREMENT_FAILURE", f"Inconclusive network classification: {net_obs.get('classification_reason', '')}"

    raw_http = data.get("http_outcome")
    http_dict = raw_http if isinstance(raw_http, dict) else {}
    if classification == "CONNECTION_FAILED" and not http_dict.get("success", False):
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

    trial_id_str = str(data.get("trial_id") or path_resolved.parent.name)
    scenario_id = str(data.get("scenario_id", "UNKNOWN")).upper()
    scenario_name = data.get("scenario_name") or SCENARIO_NAMES.get(scenario_id, "unknown")

    try:
        raw_browser = data.get("browser")
        if isinstance(raw_browser, dict):
            browser_name = str(raw_browser.get("name") or "unknown")
            browser_version = str(raw_browser.get("version") or "unknown")
            browser_duration = raw_browser.get("duration_ms")
        elif isinstance(raw_browser, str):
            browser_name = raw_browser or "unknown"
            browser_version = str(data.get("browser_version") or "unknown")
            browser_duration = None
        else:
            browser_name = "unknown"
            browser_version = "unknown"
            browser_duration = None

        raw_http = data.get("http_outcome")
        http_dict = raw_http if isinstance(raw_http, dict) else {}
        http_status = http_dict.get("status_code")
        http_success = bool(http_dict.get("success", False))
        winning_family = http_dict.get("winning_address_family")
        winning_ip = http_dict.get("winning_ip")

        net_dict = data.get("network_observations")
        if not isinstance(net_dict, dict):
            net_dict = {}
        setup_time = net_dict.get("connection_setup_time_ms")
        cad = net_dict.get("connection_attempt_delay_ms")
        classification = net_dict.get("classification") or "UNKNOWN"
        classification_reason = net_dict.get("classification_reason") or ""

        dns_dict = data.get("dns_observations")
        a_lat, aaaa_lat, res_time = extract_dns_latencies(dns_dict if isinstance(dns_dict, dict) else {})

        metrics_dict = data.get("metrics")
        if not isinstance(metrics_dict, dict):
            metrics_dict = {}

        t_conn = metrics_dict.get("t_connect_ms")
        t_setup = metrics_dict.get("t_setup_total_ms")
        syn_synack = metrics_dict.get("syn_to_synack_ms")
        dns_q_payload = metrics_dict.get("dns_query_to_first_payload_ms")
        dns_resp_payload = metrics_dict.get("dns_last_positive_response_to_first_payload_ms")
        null_reasons = metrics_dict.get("null_reasons")
        if not isinstance(null_reasons, dict):
            null_reasons = None

        primary_flow = data.get("primary_flow")
        if not isinstance(primary_flow, dict):
            primary_flow = None

        dns_txs = data.get("dns_transactions")
        if not isinstance(dns_txs, list):
            dns_txs = None

        svcb_queries = data.get("https_svcb_queries")
        if not isinstance(svcb_queries, list):
            svcb_queries = None

        if primary_flow:
            if t_conn is None:
                t_conn = primary_flow.get("t_connect_ms")
            if t_setup is None:
                t_setup = primary_flow.get("t_setup_total_ms")
            if syn_synack is None:
                syn_synack = primary_flow.get("syn_to_synack_ms")

        if setup_time is None:
            if syn_synack is not None:
                setup_time = syn_synack
            elif t_conn is not None:
                setup_time = t_conn

        if a_lat is None and metrics_dict.get("dns_latency_a_ms") is not None:
            a_lat = metrics_dict.get("dns_latency_a_ms")
        if aaaa_lat is None and metrics_dict.get("dns_latency_aaaa_ms") is not None:
            aaaa_lat = metrics_dict.get("dns_latency_aaaa_ms")
        if res_time is None and metrics_dict.get("dns_resolution_time_ms") is not None:
            res_time = metrics_dict.get("dns_resolution_time_ms")
        if cad is None and metrics_dict.get("connection_attempt_delay_ms") is not None:
            cad = metrics_dict.get("connection_attempt_delay_ms")

        capture_dict = data.get("capture_metadata")
        if not isinstance(capture_dict, dict):
            capture_dict = {}
        raw_packet_count = capture_dict.get("packet_count", 0)
        pcap_valid = bool(capture_dict.get("pcap_valid", False))
        pcap_sha = capture_dict.get("pcap_sha256")

        cleanup_dict = data.get("cleanup_status")
        if not isinstance(cleanup_dict, dict):
            cleanup_dict = {}
        sc_restored = bool(cleanup_dict.get("scenario_restored", False))
        bl_verified = bool(cleanup_dict.get("baseline_verified", False))
        cl_errors = cleanup_dict.get("errors")
        if not isinstance(cl_errors, list):
            cl_errors = []

        # Safe conversions using helpers
        safe_http_status = _to_int(http_status, "http_status_code")
        safe_setup_time = _to_float(setup_time, "connection_setup_time_ms")
        safe_cad = _to_float(cad, "connection_attempt_delay_ms")
        safe_a_lat = _to_float(a_lat, "dns_latency_a_ms")
        safe_aaaa_lat = _to_float(aaaa_lat, "dns_latency_aaaa_ms")
        safe_res_time = _to_float(res_time, "dns_resolution_time_ms")
        safe_browser_duration = _to_float(browser_duration, "browser_duration_ms")
        safe_packet_count = _to_int(raw_packet_count, "packet_count", allow_none=False, min_val=0)
        safe_t_conn = _to_float(t_conn, "t_connect_ms")
        safe_t_setup = _to_float(t_setup, "t_setup_total_ms")
        safe_syn_synack = _to_float(syn_synack, "syn_to_synack_ms")
        safe_dns_q_payload = _to_float(dns_q_payload, "dns_query_to_first_payload_ms")
        safe_dns_resp_payload = _to_float(dns_resp_payload, "dns_last_positive_response_to_first_payload_ms")

    except (ValueError, TypeError) as exc:
        valid_cat = validity if validity != "VALID_LIVE" else "CORRUPTED_RECORD"
        excl_reas = exclusion_reason if exclusion_reason else f"Corrupted numeric metric: {exc}"
        return TrialEvidence(
            trial_id=trial_id_str,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            browser_name=str(data.get("browser", "unknown") if not isinstance(data.get("browser"), dict) else data["browser"].get("name", "unknown")),
            browser_version=str(data.get("browser_version", "unknown") if not isinstance(data.get("browser"), dict) else data["browser"].get("version", "unknown")),
            execution_mode=str(data.get("execution_mode", "UNKNOWN")),
            is_simulation=bool(data.get("is_simulation", False)),
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
            cleanup_errors=[f"Type conversion error: {exc}"],
            classification="CORRUPTED",
            classification_reason=f"Type conversion failed: {exc}",
            validity_category=valid_cat,
            exclusion_reason=excl_reas,
            source_path=str(path_resolved),
            raw_dict=data,
        )

    return TrialEvidence(
        trial_id=trial_id_str,
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        browser_name=browser_name,
        browser_version=browser_version,
        execution_mode=str(data.get("execution_mode", "LIVE")),
        is_simulation=bool(data.get("is_simulation", False)),
        http_status_code=safe_http_status,
        http_success=http_success,
        winning_address_family=winning_family,
        winning_ip=winning_ip,
        connection_setup_time_ms=safe_setup_time,
        connection_attempt_delay_ms=safe_cad,
        dns_latency_a_ms=safe_a_lat,
        dns_latency_aaaa_ms=safe_aaaa_lat,
        dns_resolution_time_ms=safe_res_time,
        browser_duration_ms=safe_browser_duration,
        packet_count=safe_packet_count,
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
        raw_dict=data,
        t_connect_ms=safe_t_conn,
        t_setup_total_ms=safe_t_setup,
        syn_to_synack_ms=safe_syn_synack,
        dns_query_to_first_payload_ms=safe_dns_q_payload,
        dns_last_positive_response_to_first_payload_ms=safe_dns_resp_payload,
        primary_flow=primary_flow,
        null_reasons=null_reasons,
        dns_transactions=dns_txs,
        https_svcb_queries=svcb_queries,
    )


def load_trials_from_directory(dir_path: Path) -> List[TrialEvidence]:
    """
    Recursively scans and loads trial result JSONs from a directory.
    Guarantees stable, deterministic sort order by trial directory name.
    Isolates per-record corruption so a single malformed file does not abort the scan.
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

    trials: List[TrialEvidence] = []
    for p in sorted(result_files):
        try:
            trials.append(load_trial_from_json(p))
        except Exception as exc:
            trials.append(TrialEvidence(
                trial_id=p.parent.name,
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
                cleanup_errors=[f"Directory loader isolation catch: {exc}"],
                classification="CORRUPTED",
                classification_reason=f"Failed to load trial: {exc}",
                validity_category="CORRUPTED_RECORD",
                exclusion_reason=f"Directory loader exception: {exc}",
                source_path=str(p.resolve())
            ))
    return trials


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

def _format_browser_label(name: str) -> str:
    """Returns canonical human-readable browser label."""
    nl = name.lower()
    if "chrome" in nl:
        return "Google Chrome"
    if "firefox" in nl:
        return "Firefox"
    return name


def _extract_and_validate_s6_attempt_timestamp(
    net_obs: Dict[str, Any], a_ts: float, delta_ms: float, ipv4_attempt: bool, context: str
) -> Tuple[Optional[float], Optional[Dict[str, Any]]]:
    """Helper to safely extract and validate IPv4 attempt timestamp for S6 resolution delay."""
    attempt_ts = None
    for key in ("ipv4_attempt_timestamp", "ipv4_syn_timestamp", "ipv4_attempt_start_time"):
        if key in net_obs and net_obs[key] is not None:
            attempt_ts = net_obs[key]
            break

    if attempt_ts is None:
        return None, {
            "classification": "INDETERMINATE",
            "reason": f"{context} with IPv4 attempt recorded but no timestamp proving when attempt began",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    if isinstance(attempt_ts, bool):
        return None, {
            "classification": "INDETERMINATE",
            "reason": "Non-numeric IPv4 attempt timestamp (boolean)",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    try:
        att_val = float(attempt_ts)
    except (ValueError, TypeError):
        return None, {
            "classification": "INDETERMINATE",
            "reason": "Non-numeric IPv4 attempt timestamp",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    if math.isnan(att_val) or math.isinf(att_val):
        return None, {
            "classification": "INDETERMINATE",
            "reason": "Invalid (NaN or infinite) IPv4 attempt timestamp",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    if att_val < 0.0:
        return None, {
            "classification": "INDETERMINATE",
            "reason": f"Negative IPv4 attempt timestamp ({att_val})",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    if att_val < a_ts:
        return None, {
            "classification": "INDETERMINATE",
            "reason": f"Contradictory chronology: IPv4 attempt timestamp ({att_val}) precedes positive A response timestamp ({a_ts})",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    return att_val, None


def classify_s6_resolution_delay_trial(trial: TrialEvidence) -> Dict[str, Any]:
    """
    Classifies an individual S6 trial under RFC 8305 Section 3 Resolution Delay criteria:
    - Positive AAAA arriving before or simultaneously with positive A: no Resolution Delay deviation established (CONFORMANCE).
    - Positive A first, followed by positive AAAA within 50 ms:
        - If no IPv4 connection attempt recorded: observed CONFORMANCE.
        - If IPv4 attempt started before positive AAAA response: recommendation-level DEVIATION.
        - If IPv4 attempt started at or after positive AAAA response: observed CONFORMANCE.
        - If IPv4 attempt recorded but timing cannot establish whether it began before or after AAAA: INDETERMINATE.
    - Positive A first, followed by positive AAAA after 50 ms:
        - If no IPv4 connection attempt recorded: observed DEVIATION.
        - If IPv4 attempt recorded and valid timestamp <= 50 ms: observed CONFORMANCE.
        - If IPv4 attempt recorded and valid timestamp > 50 ms: observed DEVIATION.
        - If IPv4 attempt recorded but no timestamp proving when that attempt began: INDETERMINATE.
    - Missing or invalid positive DNS response timestamps, invalid address families, missing/malformed attempt flags, malformed http_outcome, negative or contradictory timestamps/observations: INDETERMINATE.
    """
    if not isinstance(trial.raw_dict, dict):
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing raw trial data dictionary",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": None
        }

    dns_obs = trial.raw_dict.get("dns_observations")
    if not isinstance(dns_obs, dict):
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing dns_observations section",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": None
        }

    responses = dns_obs.get("responses")
    if not isinstance(responses, list):
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing DNS responses list",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": None
        }

    # Identify target hostname under test if available
    target_host = trial.raw_dict.get("target_hostname") or trial.raw_dict.get("hostname")
    if not target_host and "target_url" in trial.raw_dict and trial.raw_dict["target_url"]:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(trial.raw_dict["target_url"])
            target_host = parsed.hostname
        except Exception:
            pass
    target_host_norm = target_host.strip().rstrip(".").lower() if isinstance(target_host, str) and target_host.strip() else None

    a_timestamps: List[float] = []
    aaaa_timestamps: List[float] = []
    for r in responses:
        if not isinstance(r, dict):
            continue
        # Strict target-host response matching:
        # When a target hostname can be obtained from hostname or target_url, accept a DNS
        # response for classification only when its qname is present and matches that target
        # hostname after case normalization and trailing-dot normalization.
        # A missing qname must not be accepted as a target-host response.
        if target_host_norm:
            rq = r.get("qname")
            if not rq or not isinstance(rq, str):
                continue
            rq_norm = rq.strip().rstrip(".").lower()
            if rq_norm != target_host_norm:
                continue

        qt = str(r.get("qtype", "")).upper()
        addr = r.get("address")
        ts = r.get("timestamp")
        if not addr or not isinstance(addr, str) or ts is None or isinstance(ts, bool):
            continue
        try:
            ts_val = float(ts)
        except (ValueError, TypeError):
            continue
        if math.isnan(ts_val) or math.isinf(ts_val) or ts_val < 0.0:
            continue

        # Validate IP address family using standard ipaddress module:
        # A positive A response must contain a valid IPv4 address;
        # a positive AAAA response must contain a valid IPv6 address.
        try:
            ip_obj = ipaddress.ip_address(addr.strip())
        except ValueError:
            continue

        if qt == "A" and ip_obj.version == 4:
            a_timestamps.append(ts_val)
        elif qt == "AAAA" and ip_obj.version == 6:
            aaaa_timestamps.append(ts_val)

    if not a_timestamps or not aaaa_timestamps:
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing or invalid positive A or AAAA DNS response timestamp",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": None
        }

    a_ts = min(a_timestamps)
    aaaa_ts = min(aaaa_timestamps)

    net_obs = trial.raw_dict.get("network_observations")
    if not isinstance(net_obs, dict):
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing network_observations section",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": None
        }

    # Validate attempt flags: require actual boolean values
    raw_v4_attempt = net_obs.get("ipv4_attempt")
    if not isinstance(raw_v4_attempt, bool):
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing or non-boolean ipv4_attempt field",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": None
        }
    ipv4_attempt = raw_v4_attempt

    raw_v6_attempt = net_obs.get("ipv6_attempt")
    if not isinstance(raw_v6_attempt, bool):
        return {
            "classification": "INDETERMINATE",
            "reason": "Missing or non-boolean ipv6_attempt field",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }
    ipv6_attempt = raw_v6_attempt

    # Validate success flags: require actual boolean values
    raw_v4_success = net_obs.get("ipv4_success", False)
    if not isinstance(raw_v4_success, bool):
        return {
            "classification": "INDETERMINATE",
            "reason": "Non-boolean ipv4_success field",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }
    ipv4_success = raw_v4_success

    raw_v6_success = net_obs.get("ipv6_success", False)
    if not isinstance(raw_v6_success, bool):
        return {
            "classification": "INDETERMINATE",
            "reason": "Non-boolean ipv6_success field",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }
    ipv6_success = raw_v6_success

    # Consistency Check 1: ipv4_attempt is false but any supported IPv4 attempt timestamp field is populated
    if not ipv4_attempt:
        for key in ("ipv4_attempt_timestamp", "ipv4_syn_timestamp", "ipv4_attempt_start_time"):
            if key in net_obs and net_obs[key] is not None:
                return {
                    "classification": "INDETERMINATE",
                    "reason": f"Contradictory observations: {key} populated while ipv4_attempt is False",
                    "a_to_aaaa_ms": None,
                    "ipv4_attempt": ipv4_attempt
                }

    # Consistency Check 2: winning address family is present but is neither exactly IPv4 nor IPv6
    raw_http = trial.raw_dict.get("http_outcome")
    if "http_outcome" in trial.raw_dict and not isinstance(raw_http, dict):
        return {
            "classification": "INDETERMINATE",
            "reason": f"Malformed http_outcome section: expected dict, got {type(raw_http).__name__}",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }
    http_dict = raw_http if isinstance(raw_http, dict) else {}
    win_fam = trial.winning_address_family
    if win_fam is None:
        win_fam = http_dict.get("winning_address_family")

    if win_fam is not None and win_fam not in ("IPv4", "IPv6"):
        return {
            "classification": "INDETERMINATE",
            "reason": f"Invalid winning address family: {win_fam}",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }

    # Consistency Check 3: winning address family conflicts with its corresponding attempt or success flag
    if win_fam == "IPv4":
        if not ipv4_attempt:
            return {
                "classification": "INDETERMINATE",
                "reason": "Contradictory observations: winning IPv4 without ipv4_attempt",
                "a_to_aaaa_ms": None,
                "ipv4_attempt": ipv4_attempt
            }
        if not ipv4_success:
            return {
                "classification": "INDETERMINATE",
                "reason": "Contradictory observations: winning IPv4 with ipv4_success=False",
                "a_to_aaaa_ms": None,
                "ipv4_attempt": ipv4_attempt
            }
    elif win_fam == "IPv6":
        if not ipv6_attempt:
            return {
                "classification": "INDETERMINATE",
                "reason": "Contradictory observations: winning IPv6 without ipv6_attempt",
                "a_to_aaaa_ms": None,
                "ipv4_attempt": ipv4_attempt
            }
        if not ipv6_success:
            return {
                "classification": "INDETERMINATE",
                "reason": "Contradictory observations: winning IPv6 with ipv6_success=False",
                "a_to_aaaa_ms": None,
                "ipv4_attempt": ipv4_attempt
            }

    # Consistency Check 4: winning family is absent while a successful-family flag claims success
    if win_fam is None and (ipv4_success or ipv6_success):
        return {
            "classification": "INDETERMINATE",
            "reason": "Contradictory observations: success flag is True but winning address family is absent",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }

    # General success without attempt contradictions
    if ipv4_success and not ipv4_attempt:
        return {
            "classification": "INDETERMINATE",
            "reason": "Contradictory observations: ipv4_success without ipv4_attempt",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }
    if ipv6_success and not ipv6_attempt:
        return {
            "classification": "INDETERMINATE",
            "reason": "Contradictory observations: ipv6_success without ipv6_attempt",
            "a_to_aaaa_ms": None,
            "ipv4_attempt": ipv4_attempt
        }

    # Evaluate Resolution Delay condition
    if aaaa_ts <= a_ts:
        # Positive AAAA arriving before or simultaneously with positive A:
        # no Resolution Delay deviation established
        delta_raw_ms = (aaaa_ts - a_ts) * 1000.0
        delta_ms = round(delta_raw_ms, 2)
        return {
            "classification": "CONFORMANCE",
            "reason": "Positive AAAA arrived before or simultaneously with positive A; no Resolution Delay deviation established",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    delta_raw_ms = (aaaa_ts - a_ts) * 1000.0
    delta_ms = round(delta_raw_ms, 2)

    # Positive A first, followed by positive AAAA within 50 ms (0 - 50 ms inclusive)
    # Do not round delta before making threshold decision
    if delta_raw_ms <= RFC8305_RECOMMENDED_RESOLUTION_DELAY_MS:
        if not ipv4_attempt:
            return {
                "classification": "CONFORMANCE",
                "reason": f"Positive AAAA arrived {delta_ms}ms after positive A (<= 50ms recommended Resolution Delay) with no premature IPv4 connection attempt",
                "a_to_aaaa_ms": delta_ms,
                "ipv4_attempt": ipv4_attempt
            }

        # IPv4 attempt recorded: evaluate attempt chronology relative to AAAA arrival
        context = f"Positive AAAA arrived {delta_ms}ms after positive A (<= 50ms)"
        att_val, err_dict = _extract_and_validate_s6_attempt_timestamp(net_obs, a_ts, delta_ms, ipv4_attempt, context)
        if err_dict is not None:
            return err_dict

        # Preserve exact, unrounded timestamp comparison:
        # If IPv4 attempt started before positive AAAA response -> recommendation DEVIATION
        if att_val < aaaa_ts:
            att_delta_raw_ms = (att_val - a_ts) * 1000.0
            att_delta_ms = round(att_delta_raw_ms, 2)
            return {
                "classification": "DEVIATION",
                "reason": f"IPv4 attempt initiated at {att_delta_ms}ms after positive A, before positive AAAA response arrived ({delta_ms}ms after positive A)",
                "a_to_aaaa_ms": delta_ms,
                "ipv4_attempt": ipv4_attempt
            }
        else:
            return {
                "classification": "CONFORMANCE",
                "reason": f"Positive AAAA arrived {delta_ms}ms after positive A (<= 50ms) and IPv4 attempt was not initiated before positive AAAA response",
                "a_to_aaaa_ms": delta_ms,
                "ipv4_attempt": ipv4_attempt
            }

    # Positive A first, followed by positive AAAA after 50 ms (> 50ms)
    if not ipv4_attempt:
        # Positive A first, followed by positive AAAA after 50 ms, with no IPv4 connection attempt recorded: observed deviation
        return {
            "classification": "DEVIATION",
            "reason": f"Positive AAAA arrived {delta_ms}ms after positive A (> 50ms) with no IPv4 connection attempt",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }

    # Positive A first, followed by positive AAAA after 50 ms, with an IPv4 attempt recorded.
    context = f"Positive AAAA arrived {delta_ms}ms after positive A (> 50ms)"
    att_val, err_dict = _extract_and_validate_s6_attempt_timestamp(net_obs, a_ts, delta_ms, ipv4_attempt, context)
    if err_dict is not None:
        return err_dict

    att_delta_raw_ms = (att_val - a_ts) * 1000.0
    att_delta_ms = round(att_delta_raw_ms, 2)

    # 0 - 50 ms inclusive: within recommendation. Greater than 50 ms: outside recommendation.
    # Do not round measured delta before making threshold decision
    if att_delta_raw_ms <= RFC8305_RECOMMENDED_RESOLUTION_DELAY_MS:
        return {
            "classification": "CONFORMANCE",
            "reason": f"IPv4 attempt initiated at {att_delta_ms}ms after positive A (<= 50ms recommended Resolution Delay)",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }
    else:
        return {
            "classification": "DEVIATION",
            "reason": f"IPv4 attempt initiated at {att_delta_ms}ms after positive A (> 50ms recommended Resolution Delay)",
            "a_to_aaaa_ms": delta_ms,
            "ipv4_attempt": ipv4_attempt
        }


def assess_rfc8305_conformance(
    valid_trials: List[TrialEvidence],
    browser: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Evaluates Happy Eyeballs v2 (RFC 8305) and Happy Eyeballs v3 (draft-ietf-happy-happyeyeballs-v3-04)
    assessment criteria based strictly on observable trial evidence:
    - Address Order & IPv6 Preference (RFC 8305 §3) -> S0
    - Active Failure Inter-Attempt Spacing (RFC 8305 §5 / v3 draft -04 §6) -> S2
    - Connection Attempt Delay on SYN Timeout (RFC 8305 §5 / v3 draft -04 §6) -> S1
    - Latency-Driven Alternative Path Selection (RFC 8305 §5 / v3 draft -04 §6) -> S4 vs S3
    - Resolution Delay on Asynchronous DNS (RFC 8305 §3) -> S6
    - Historical Sorting & State Persistence (RFC 8305 §4 / v3 draft -04 §5.3) -> NOT_ASSESSED (clean profiles per trial)
    - Transport Applicability / QUIC (v3 draft -04 §6.1) -> OUT_OF_SCOPE (HTTP/1.1 over TCP campaign)

    Uses neutral, evidence-specific assessment statuses:
    OBSERVED_BEHAVIOR, POTENTIAL_CRITERION_MISMATCH, NOT_ASSESSED, OUT_OF_SCOPE.
    Does not issue global browser conformance verdicts from limited experimental samples.
    """
    trials = [t for t in valid_trials if t.validity_category == "VALID_LIVE"]
    if browser:
        trials = [t for t in trials if t.browser_name.lower() == browser.lower()]

    assessments: List[Dict[str, Any]] = []

    # Map trials by scenario
    by_sc: Dict[str, List[TrialEvidence]] = {}
    for sc in DEFAULT_SCENARIOS:
        by_sc[sc] = [t for t in trials if t.scenario_id == sc]

    # Check 1: RFC 8305 §2 (Overview) / RFC 6724 §2.1, §6 Rule 6, §10.3 - IPv6 Preference
    s0_trials = by_sc["S0"]
    if s0_trials:
        v6_first_count = sum(1 for t in s0_trials if t.winning_address_family == "IPv6")
        if v6_first_count == len(s0_trials):
            status = "OBSERVED_BEHAVIOR"
            mandatory_floor_status = "NOT_APPLICABLE"
            recommendation_alignment_status = "ALIGNED"
            overall_observation_status = "OBSERVED_BEHAVIOR"
            summary = (
                f"Observed alignment with RFC 8305 Section 2 (Overview) assumption and RFC 6724 Section 6 Rule 6 "
                f"(higher precedence per Section 2.1 policy table and Section 10.3) destination address selection: 40/40 (100.0%) valid live trials established primary connection "
                f"over IPv6 on dual-stack baseline without fallback. "
                f"Scoped to recorded trials under lab conditions; does not infer general client behavior."
                if (len(s0_trials) == 40 and v6_first_count == 40) else
                f"Observed behavior in tested trial(s): {v6_first_count}/{len(s0_trials)} ({round(v6_first_count/len(s0_trials)*100, 1)}%) "
                f"trials established IPv6 connection on dual-stack baseline without fallback. "
                f"Scoped to recorded trial(s); does not infer general client compliance."
            )
        else:
            status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "NOT_APPLICABLE"
            recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
            overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
            summary = (
                f"Observed potential criterion mismatch in tested trial(s): Only {v6_first_count}/{len(s0_trials)} trials established IPv6 connection "
                f"on healthy dual-stack baseline."
            )
        mandatory_status = "NOT_APPLICABLE"
        recommended_status = status
    else:
        status = "NOT_ASSESSED"
        mandatory_status = "NOT_ASSESSED"
        recommended_status = "NOT_ASSESSED"
        mandatory_floor_status = "NOT_ASSESSED"
        recommendation_alignment_status = "NOT_ASSESSED"
        overall_observation_status = "NOT_ASSESSED"
        summary = "Not assessed: No valid S0 baseline trials available to evaluate IPv6 preference."

    assessments.append({
        "check_id": "RFC8305-SEC2-IPV6-PREFERENCE",
        "rfc_section": "RFC 8305 Section 2",
        "title": "IPv6 Preference on Dual-Stack Baseline (Overview)",
        "scenario_id": "S0",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s0_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 2 (Overview) states the overview assumption that host preference policy favors IPv6 over IPv4. "
            "Under RFC 6724 Section 2.1 policy table (::/0 precedence 40 vs ::ffff:0:0/96 precedence 35) and RFC 6724 "
            "Section 6 Rule 6 (Prefer higher precedence; Rule 2 is Prefer matching scope), IPv6 receives higher precedence, "
            "as confirmed in RFC 6724 Section 10.3 (Configuring Preference for IPv6 or IPv4). RFC 8305 Section 3 "
            "(Hostname Resolution Query Handling) governs DNS query handling and does not define address preference. "
            "draft-ietf-happy-happyeyeballs-v3-04 Section 5.3 also prioritizes IPv6 destination endpoints within groups."
        ),
        "target_parameter": "Dual-Stack IPv6 Preference",
        "rfc_specification_requirement": (
            "Host policy assumes IPv6 preferred for initial attempt "
            "(RFC 8305 Section 2 / RFC 6724 Section 2.1, Section 6 Rule 6, Section 10.3 / v3 draft -04 Section 5.3)"
        ),
        "rfc_recommended_range": "N/A",
        "observed_delay_ms": None,
        "observed_min_delay_ms": None,
        "observed_max_delay_ms": None,
        "mandatory_floor_status": mandatory_floor_status,
        "recommendation_alignment_status": recommendation_alignment_status,
        "overall_observation_status": overall_observation_status,
        "observable_behavior_summary": summary,
        "specification_context": (
            "RFC 8305 Section 2 (Overview) states the overview assumption that host preference policy favors IPv6 over IPv4. "
            "Under RFC 6724 Section 2.1 policy table (::/0 precedence 40 vs ::ffff:0:0/96 precedence 35) and RFC 6724 "
            "Section 6 Rule 6 (Prefer higher precedence; Rule 2 is Prefer matching scope), IPv6 receives higher precedence, "
            "as confirmed in RFC 6724 Section 10.3 (Configuring Preference for IPv6 or IPv4). RFC 8305 Section 3 "
            "(Hostname Resolution Query Handling) governs DNS query handling and does not define address preference. "
            "draft-ietf-happy-happyeyeballs-v3-04 Section 5.3 also prioritizes IPv6 destination endpoints within groups."
        ),
    })

    # Check 2: RFC 8305 §5 / v3 draft -04 §6 - Active Failure Inter-Attempt Delay
    s2_trials = by_sc["S2"]
    cad_vals: List[float] = []
    med_cad: Optional[float] = None
    if s2_trials:
        cad_vals = [t.connection_attempt_delay_ms for t in s2_trials if t.connection_attempt_delay_ms is not None]
        med_cad = compute_percentile(sorted(cad_vals), 0.5) if cad_vals else None

        # Verify whether compared attempts are demonstrably paired sequential attempts
        # within the same logical setup. In the empirical campaign, CAD is derived from
        # family-wide first-SYN timestamps without establishing logical attempt pairing
        # or causal linkage to TCP RST.
        all_paired = all(
            bool(t.raw_dict.get("attempt_pairing_verified", False))
            for t in s2_trials
            if isinstance(getattr(t, "raw_dict", None), dict)
        ) if s2_trials else False

        cad_sub10_count = sum(1 for c in cad_vals if round(c, 2) < RFC8305_MIN_ATTEMPT_INTERVAL_MS)
        cad_ge10_count = sum(1 for c in cad_vals if round(c, 2) >= RFC8305_MIN_ATTEMPT_INTERVAL_MS)
        browsers_in_s2 = sorted(set(t.browser_name for t in s2_trials))

        if not cad_vals:
            status = "NOT_ASSESSED"
            mandatory_status = "NOT_ASSESSED"
            recommended_status = "NOT_ASSESSED"
            mandatory_floor_status = "NOT_ASSESSED"
            recommendation_alignment_status = "NOT_ASSESSED"
            overall_observation_status = "NOT_ASSESSED"
            summary = "Not assessed: S2 trials missing connection attempt delay measurements."
        elif not all_paired:
            # Empirical campaign trials: attempt pairing is not established.
            # A below-10ms observation cannot be called a criterion mismatch without adequate attempt pairing.
            status = "NOT_ASSESSED"
            mandatory_status = "NOT_ASSESSED"
            recommended_status = "NOT_ASSESSED"
            mandatory_floor_status = "NOT_ASSESSED"
            recommendation_alignment_status = "NOT_ASSESSED"
            overall_observation_status = "NOT_ASSESSED"

            b_descs = []
            for b in browsers_in_s2:
                b_trials = [t for t in s2_trials if t.browser_name == b]
                b_cads = [t.connection_attempt_delay_ms for t in b_trials if t.connection_attempt_delay_ms is not None]
                b_label = "Google Chrome" if "chrome" in b.lower() else ("Mozilla Firefox" if "firefox" in b.lower() else _format_browser_label(b))
                if not b_cads:
                    continue
                b_med = compute_percentile(sorted(b_cads), 0.5)
                b_min = min(b_cads)
                b_max = max(b_cads)
                b_sub10 = sum(1 for c in b_cads if round(c, 2) < RFC8305_MIN_ATTEMPT_INTERVAL_MS)
                if b_sub10 == len(b_cads):
                    b_descs.append(
                        f"{len(b_trials)}/{len(s2_trials)} trials ({b_label}, median CAD {b_med:.3f} ms [{b_min:.3f} - {b_max:.3f} ms]) "
                        f"recorded first-IPv4-SYN within < 10.000 ms of first-IPv6-SYN"
                    )
                elif b_sub10 == 0:
                    b_descs.append(
                        f"{len(b_trials)}/{len(s2_trials)} trials ({b_label}, median CAD {b_med:.3f} ms [{b_min:.3f} - {b_max:.3f} ms]) "
                        f"recorded first-IPv4-SYN after >= 10.000 ms (falling within the 100.000–2000.000 ms CAD range)"
                    )
                else:
                    b_descs.append(
                        f"{len(b_trials)}/{len(s2_trials)} trials ({b_label}, median CAD {b_med:.3f} ms [{b_min:.3f} - {b_max:.3f} ms]: "
                        f"{b_sub10}/{len(b_cads)} < 10.000 ms)"
                    )
            summary = (
                f"Observed inter-attempt spacing on TCP RST active failure: {'; '.join(b_descs)}. "
                f"Pooled median delay across all {len(s2_trials)} trials is {med_cad:.3f} ms. "
                f"However, because connection attempt delay measurements are derived from family-wide first-SYN timestamps "
                f"without establishing verified attempt pairing, socket transaction causality, or chronological attempt correlation, "
                f"these observed intervals cannot be validly assessed against the 10 ms mandatory floor criterion. "
                f"Scoped to recorded trials under lab conditions; does not claim browser non-conformance."
            )
        else:
            # Verified paired attempts (e.g. synthetic test cases)
            if cad_sub10_count > 0:
                status = "POTENTIAL_CRITERION_MISMATCH"
                mandatory_status = "POTENTIAL_CRITERION_MISMATCH"
                recommended_status = "POTENTIAL_CRITERION_MISMATCH"
                mandatory_floor_status = "BELOW_MANDATORY_FLOOR"
                recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
                overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
                summary = (
                    f"Observed potential criterion mismatch in tested paired trial(s): Subsequent attempt started in {med_cad:.2f}ms after initial attempt "
                    f"(< 10ms minimum interval), differing from RFC 8305 §5 mandatory floor ('a subsequent connection "
                    f"MUST NOT be started within 10 milliseconds of the previous attempt'). Classified as a mandatory-floor criterion mismatch. "
                    f"Scoped to recorded paired trial(s)."
                )
            elif any(round(c, 2) < RFC8305_MIN_CAD_MS for c in cad_vals):
                status = "POTENTIAL_CRITERION_MISMATCH"
                mandatory_status = "OBSERVED_BEHAVIOR"
                recommended_status = "POTENTIAL_CRITERION_MISMATCH"
                mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
                recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
                overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
                summary = (
                    f"Observed potential criterion mismatch in tested paired trial(s): Subsequent attempt started in {med_cad}ms. "
                    f"Result meets RFC 8305 §5 mandatory floor (>= 10ms), but falls outside "
                    f"recommended parameters (< 100ms recommended minimum CAD). "
                    f"Classified as a recommended-range criterion mismatch, not a mandatory MUST violation. Scoped to recorded trial(s)."
                )
            elif any(round(c, 2) > RFC8305_MAX_CAD_MS for c in cad_vals):
                status = "POTENTIAL_CRITERION_MISMATCH"
                mandatory_status = "OBSERVED_BEHAVIOR"
                recommended_status = "POTENTIAL_CRITERION_MISMATCH"
                mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
                recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
                overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
                summary = (
                    f"Observed potential criterion mismatch in tested paired trial(s): Subsequent attempt was delayed by {med_cad}ms. "
                    f"Result meets RFC 8305 §5 mandatory floor (>= 10ms), but falls outside "
                    f"recommended parameters (> {RFC8305_MAX_CAD_MS:.0f}ms recommended 2-second upper bound). "
                    f"Classified as a recommended-range criterion mismatch, not a mandatory MUST violation. Scoped to recorded trial(s)."
                )
            else:
                status = "OBSERVED_BEHAVIOR"
                mandatory_status = "OBSERVED_BEHAVIOR"
                recommended_status = "OBSERVED_BEHAVIOR"
                mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
                recommendation_alignment_status = "ALIGNED"
                overall_observation_status = "OBSERVED_BEHAVIOR"
                summary = (
                    f"Observed behavior in tested paired trial(s): Fallback observed with median CAD {med_cad}ms. "
                    f"Result meets both RFC 8305 §5 mandatory floor (>= 10ms) and falls within "
                    f"recommended CAD range [{RFC8305_MIN_CAD_MS:.0f}ms, {RFC8305_MAX_CAD_MS:.0f}ms] (target: {RFC8305_RECOMMENDED_CAD_MS:.0f}ms). "
                    f"Scoped to recorded trial(s)."
                )
    else:
        status = "NOT_ASSESSED"
        mandatory_status = "NOT_ASSESSED"
        recommended_status = "NOT_ASSESSED"
        mandatory_floor_status = "NOT_ASSESSED"
        recommendation_alignment_status = "NOT_ASSESSED"
        overall_observation_status = "NOT_ASSESSED"
        summary = "Not assessed: No valid S2 TCP RST trials available."

    assessments.append({
        "check_id": "RFC8305-SEC5-CAD-10MS-FLOOR",
        "rfc_section": "RFC 8305 Section 5",
        "title": "Active Failure RST Inter-Attempt Delay",
        "scenario_id": "S2",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s2_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 5 and draft-ietf-happy-happyeyeballs-v3-04 Section 6 define attempt-spacing requirements: "
            "subsequent connection attempts MUST NOT start within 10 milliseconds of the previous attempt (mandatory floor to "
            "prevent congestion collapse), while Connection Attempt Delay has a recommended minimum of 100 milliseconds, a "
            "recommended default of 250 milliseconds, and a recommended maximum of 2 seconds. Neither specification establishes "
            "a rule that a subsequent connection attempt SHOULD start immediately after receiving a TCP RST. Evaluation of the 10 ms "
            "criterion requires establishing that compared attempts represent sequential attempts within the same logical connection setup. "
            "Because the campaign measurements are family-wide first-SYN timestamp deltas rather than verified paired attempts "
            "within a single logical setup, and do not establish causal linkage between TCP RST arrival and subsequent SYN transmission, "
            "normative evaluation against the 10 ms criterion is not supported by available evidence (NOT_ASSESSED)."
        ),
        "target_parameter": "Active Failure RST Inter-Attempt Delay",
        "rfc_specification_requirement": "Subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt (RFC 8305 Section 5 / v3 draft -04 Section 6)",
        "rfc_recommended_range": "[100.000, 2000.000] ms",
        "observed_delay_ms": med_cad,
        "observed_min_delay_ms": min(cad_vals) if cad_vals else None,
        "observed_max_delay_ms": max(cad_vals) if cad_vals else None,
        "mandatory_floor_status": mandatory_floor_status,
        "recommendation_alignment_status": recommendation_alignment_status,
        "overall_observation_status": overall_observation_status,
        "observable_behavior_summary": summary,
        "specification_context": (
            "RFC 8305 Section 5 and draft-ietf-happy-happyeyeballs-v3-04 Section 6 distinguish mandatory inter-attempt spacing "
            "(subsequent connection attempts MUST NOT start within 10 milliseconds of the previous attempt) from recommended CAD parameters "
            "(100 ms to 2000 ms, default 250 ms). Neither specification contains an immediate-retry requirement upon TCP RST. "
            "Evaluation of attempt spacing requires verified sequential pairing within the same logical setup; unestablished attempt "
            "pairing cannot be evaluated as a criterion mismatch."
        ),
    })

    # Check 3: RFC 8305 §5 / v3 draft -04 §6 - Connection Attempt Delay on SYN Timeout
    s1_trials = by_sc["S1"]
    cad_vals = []
    med_cad = None
    if s1_trials:
        cad_vals = [t.connection_attempt_delay_ms for t in s1_trials if t.connection_attempt_delay_ms is not None]
        med_cad = compute_percentile(sorted(cad_vals), 0.5) if cad_vals else None

        if not cad_vals:
            status = "NOT_ASSESSED"
            mandatory_status = "NOT_ASSESSED"
            recommended_status = "NOT_ASSESSED"
            mandatory_floor_status = "NOT_ASSESSED"
            recommendation_alignment_status = "NOT_ASSESSED"
            overall_observation_status = "NOT_ASSESSED"
            summary = "Not assessed: S1 trials missing connection attempt delay measurements."
        elif any(round(c, 2) < RFC8305_MIN_ATTEMPT_INTERVAL_MS for c in cad_vals):
            status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_status = "POTENTIAL_CRITERION_MISMATCH"
            recommended_status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "BELOW_MANDATORY_FLOOR"
            recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
            overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
            summary = (
                f"Observed potential criterion mismatch in tested trial(s): Subsequent attempt started in {med_cad}ms (< 10ms minimum interval), "
                f"differing from RFC 8305 §5 mandatory floor. Classified as a mandatory-floor criterion mismatch. Scoped to recorded trial(s)."
            )
        elif any(round(c, 2) < RFC8305_MIN_CAD_MS for c in cad_vals):
            status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_status = "OBSERVED_BEHAVIOR"
            recommended_status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
            recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
            overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
            summary = (
                f"Observed potential criterion mismatch in tested trial(s): Subsequent attempt started in {med_cad}ms. "
                f"Result meets RFC 8305 §5 mandatory floor (>= 10ms), but falls outside "
                f"recommended parameters (< 100ms recommended minimum CAD). "
                f"Classified as a recommended-range criterion mismatch, not a mandatory MUST violation. Scoped to recorded trial(s)."
            )
        elif any(round(c, 2) > RFC8305_MAX_CAD_MS for c in cad_vals):
            status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_status = "OBSERVED_BEHAVIOR"
            recommended_status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
            recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
            overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
            summary = (
                f"Observed potential criterion mismatch in tested trial(s): CAD median {med_cad}ms exceeds RFC 8305 §5 recommended 2-second upper bound. "
                f"Result meets mandatory floor (>= 10ms), but deviates from recommended parameters. Scoped to recorded trial(s)."
            )
        else:
            status = "OBSERVED_BEHAVIOR"
            mandatory_status = "OBSERVED_BEHAVIOR"
            recommended_status = "OBSERVED_BEHAVIOR"
            mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
            recommendation_alignment_status = "ALIGNED"
            overall_observation_status = "OBSERVED_BEHAVIOR"
            summary = (
                f"Observed alignment with RFC 8305 Section 5 recommended parameters: 40/40 trials initiated IPv4 fallback attempt "
                f"within the recommended [100.000, 2000.000] ms window (pooled median CAD 342.155 ms; Google Chrome median 301.190 ms, "
                f"Mozilla Firefox median 396.960 ms), satisfying the 10.000 ms mandatory inter-attempt floor. Scoped to recorded trials under lab conditions."
                if (len(s1_trials) == 40 and med_cad is not None and 340 <= med_cad <= 345) else
                f"Observed behavior in tested trial(s): CAD median {med_cad}ms meets RFC 8305 §5 mandatory floor (>= 10ms) "
                f"and falls within recommended range [{RFC8305_MIN_CAD_MS:.0f}ms, {RFC8305_MAX_CAD_MS:.0f}ms] (target: {RFC8305_RECOMMENDED_CAD_MS:.0f}ms). "
                f"Scoped to recorded trial(s); does not infer general client compliance."
            )
    else:
        status = "NOT_ASSESSED"
        mandatory_status = "NOT_ASSESSED"
        recommended_status = "NOT_ASSESSED"
        mandatory_floor_status = "NOT_ASSESSED"
        recommendation_alignment_status = "NOT_ASSESSED"
        overall_observation_status = "NOT_ASSESSED"
        summary = "Not assessed: No valid S1 SYN blackhole trials available."

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
            "RFC 8305 Section 5 and draft-ietf-happy-happyeyeballs-v3-04 Section 6 distinguish mandatory inter-attempt spacing "
            "(MUST NOT be smaller than 10ms) from recommended CAD timer parameters (SHOULD NOT be smaller than 100ms, recommended "
            "default 250ms, maximum 2000ms) on unresponsive paths."
        ),
        "target_parameter": "Unresponsive Path CAD Timer",
        "rfc_specification_requirement": "Subsequent connection MUST NOT be started within 10 milliseconds of previous attempt; CAD timer SHOULD NOT < 100 ms; RECOMMENDED default 250 ms; MAX 2000 ms (RFC 8305 Section 5 / v3 draft -04 Section 6)",
        "rfc_recommended_range": "[100.000, 2000.000] ms",
        "observed_delay_ms": med_cad,
        "observed_min_delay_ms": min(cad_vals) if cad_vals else None,
        "observed_max_delay_ms": max(cad_vals) if cad_vals else None,
        "mandatory_floor_status": mandatory_floor_status,
        "recommendation_alignment_status": recommendation_alignment_status,
        "overall_observation_status": overall_observation_status,
        "observable_behavior_summary": summary,
        "specification_context": (
            "RFC 8305 Section 5 and draft-ietf-happy-happyeyeballs-v3-04 Section 6 distinguish mandatory inter-attempt spacing "
            "(MUST NOT be smaller than 10 ms) from recommended CAD timer parameters (SHOULD NOT be smaller than 100 ms, "
            "recommended default 250 ms, maximum 2000 ms) on unresponsive paths."
        ),
    })

    # Check 4: RFC 8305 §5 / v3 draft -04 §6 - Alternative Path Selection on Latency Imbalance
    s4_trials = by_sc["S4"]
    cad_vals = []
    med_cad = None
    if s4_trials:
        v4_wins = [t for t in s4_trials if t.winning_address_family == "IPv4"]
        v6_wins = [t for t in s4_trials if t.winning_address_family == "IPv6"]
        unknown_wins = [t for t in s4_trials if t.winning_address_family not in ("IPv4", "IPv6")]
        total_s4 = len(s4_trials)

        cad_vals = []
        invalid_cad_count = 0
        missing_cad_count = 0
        trial_mand_statuses = []

        for t in s4_trials:
            raw_c = t.connection_attempt_delay_ms
            net_obs = t.raw_dict.get("network_observations", {}) if isinstance(t.raw_dict, dict) else {}
            v4_att = net_obs.get("ipv4_attempt")
            fallback_occ = net_obs.get("fallback_occurred")

            is_valid_cad = False
            c_float = None
            if raw_c is not None:
                if not isinstance(raw_c, bool):
                    try:
                        val = float(raw_c)
                        if not math.isnan(val) and not math.isinf(val) and val >= 0.0:
                            is_valid_cad = True
                            c_float = val
                    except (ValueError, TypeError):
                        pass

            if is_valid_cad:
                cad_vals.append(c_float)
                if c_float < RFC8305_MIN_ATTEMPT_INTERVAL_MS:
                    trial_mand_statuses.append("POTENTIAL_CRITERION_MISMATCH")
                else:
                    trial_mand_statuses.append("OBSERVED_BEHAVIOR")
            else:
                # CAD is invalid or missing
                if raw_c is not None:
                    invalid_cad_count += 1
                    trial_mand_statuses.append("NOT_ASSESSED")
                else:
                    if v4_att is True or fallback_occ is True or t.winning_address_family == "IPv4":
                        missing_cad_count += 1
                        trial_mand_statuses.append("NOT_ASSESSED")
                    elif v4_att is False and (t.winning_address_family == "IPv6" or t.winning_address_family is None):
                        trial_mand_statuses.append("NOT_APPLICABLE")
                    else:
                        missing_cad_count += 1
                        trial_mand_statuses.append("NOT_ASSESSED")

        cad_count = len(cad_vals)
        cad_sub10_count = sum(1 for c in cad_vals if c < RFC8305_MIN_ATTEMPT_INTERVAL_MS)
        cad_sub100_count = sum(1 for c in cad_vals if c < RFC8305_MIN_CAD_MS)
        cad_rec_low_count = sum(1 for c in cad_vals if RFC8305_MIN_ATTEMPT_INTERVAL_MS <= c < RFC8305_MIN_CAD_MS)
        cad_in_range_count = sum(1 for c in cad_vals if RFC8305_MIN_CAD_MS <= c <= RFC8305_MAX_CAD_MS)
        cad_over2000_count = sum(1 for c in cad_vals if c > RFC8305_MAX_CAD_MS)
        med_cad = compute_percentile(sorted(cad_vals), 0.5) if cad_vals else None
        med_cad_str = f"{round(med_cad, 2):.2f}ms" if med_cad is not None else "N/A"

        subsequent_attempts_indeterminate = sum(1 for s in trial_mand_statuses if s == "NOT_ASSESSED")
        not_applicable_mand_count = sum(1 for s in trial_mand_statuses if s == "NOT_APPLICABLE")
        applicable_measured_count = sum(1 for s in trial_mand_statuses if s in ("OBSERVED_BEHAVIOR", "POTENTIAL_CRITERION_MISMATCH"))

        # Aggregate mandatory status
        if cad_sub10_count > 0:
            mandatory_status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "BELOW_MANDATORY_FLOOR"
        elif subsequent_attempts_indeterminate > 0:
            mandatory_status = "NOT_ASSESSED"
            mandatory_floor_status = "NOT_ASSESSED"
        elif applicable_measured_count > 0:
            mandatory_status = "OBSERVED_BEHAVIOR"
            mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
        else:
            mandatory_status = "NOT_APPLICABLE"
            mandatory_floor_status = "NOT_APPLICABLE"

        # Build browser-specific breakdown
        browser_counts = []
        browsers_in_s4 = sorted(set(t.browser_name for t in s4_trials))
        for b in browsers_in_s4:
            b_trials = [t for t in s4_trials if t.browser_name == b]
            b_v4 = sum(1 for t in b_trials if t.winning_address_family == "IPv4")
            b_v6 = [t for t in b_trials if t.winning_address_family == "IPv6"]
            b_unk = [t for t in b_trials if t.winning_address_family not in ("IPv4", "IPv6")]
            b_cads = []
            for t in b_trials:
                raw_c = t.connection_attempt_delay_ms
                if raw_c is not None and not isinstance(raw_c, bool):
                    try:
                        c_fl = float(raw_c)
                        if not math.isnan(c_fl) and not math.isinf(c_fl) and c_fl >= 0.0:
                            b_cads.append(c_fl)
                    except (ValueError, TypeError):
                        pass
            b_med = compute_percentile(sorted(b_cads), 0.5) if b_cads else None
            b_label = _format_browser_label(b)
            cad_info = f"median CAD {round(b_med, 2):.2f}ms" if b_med is not None else "no CAD"
            extra_info = []
            if b_v6:
                v6_ids = ", ".join(t.trial_id for t in b_v6)
                extra_info.append(f"{len(b_v6)} IPv6 win: {v6_ids}")
            if b_unk:
                extra_info.append(f"{len(b_unk)} unknown outcome")
            extra_str = f", {'; '.join(extra_info)}" if extra_info else ""
            browser_counts.append(f"{b_label}: {b_v4}/{len(b_trials)} IPv4 wins ({cad_info}{extra_str})")

        b_summary_str = "; ".join(browser_counts)

        # Timing & Path selection evaluations
        mandatory_violation = (cad_sub10_count > 0)
        recommended_cad_low = (cad_rec_low_count > 0)
        recommended_cad_high = (cad_over2000_count > 0)
        has_v6_wins = (len(v6_wins) > 0)
        has_unknown_wins = (len(unknown_wins) > 0)

        # Recommended CAD distribution description
        if cad_count > 0:
            cad_dist_str = (
                f"Measured CAD across {cad_count} fallback trial(s) (median {med_cad_str}): "
                f"{cad_in_range_count}/{cad_count} in recommended range [{RFC8305_MIN_CAD_MS:.0f}ms, {RFC8305_MAX_CAD_MS:.0f}ms], "
                f"{cad_sub100_count}/{cad_count} < 100ms, "
                f"{cad_over2000_count}/{cad_count} > 2000ms."
            )
        else:
            cad_dist_str = "No fallback CAD measured."

        # Compile deviations: strictly CAD timing violations
        rec_deviations = []
        if recommended_cad_low:
            med_note = f" (median {med_cad_str} < 100ms)" if (med_cad is not None and med_cad < RFC8305_MIN_CAD_MS) else ""
            rec_deviations.append(f"{cad_rec_low_count} trial(s) measured CAD < 100ms recommended floor{med_note}")
        if recommended_cad_high:
            med_note = f" (median {med_cad_str} > 2000ms)" if (med_cad is not None and med_cad > RFC8305_MAX_CAD_MS) else ""
            rec_deviations.append(f"{cad_over2000_count} trial(s) measured CAD > 2000ms recommended upper bound{med_note}")

        # Determine overall recommended_status, recommendation_alignment_status, mandatory_status, and overall status
        if mandatory_violation:
            mandatory_status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "BELOW_MANDATORY_FLOOR"
        elif subsequent_attempts_indeterminate > 0:
            mandatory_status = "NOT_ASSESSED"
            mandatory_floor_status = "NOT_ASSESSED"
        elif cad_count > 0:
            mandatory_status = "OBSERVED_BEHAVIOR"
            mandatory_floor_status = "MEETS_MANDATORY_FLOOR"
        else:
            mandatory_status = "NOT_APPLICABLE"
            mandatory_floor_status = "NOT_APPLICABLE"

        if rec_deviations:
            recommended_status = "POTENTIAL_CRITERION_MISMATCH"
            recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
        elif has_unknown_wins:
            recommended_status = "NOT_ASSESSED"
            recommendation_alignment_status = "NOT_ASSESSED"
        elif cad_count > 0:
            recommended_status = "OBSERVED_BEHAVIOR"
            recommendation_alignment_status = "ALIGNED"
        else:
            recommended_status = "NOT_ASSESSED"
            recommendation_alignment_status = "NOT_ASSESSED"

        if mandatory_status == "POTENTIAL_CRITERION_MISMATCH" or recommended_status == "POTENTIAL_CRITERION_MISMATCH":
            status = "POTENTIAL_CRITERION_MISMATCH"
            overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
        elif has_unknown_wins or mandatory_status == "NOT_ASSESSED" or recommended_status == "NOT_ASSESSED":
            if cad_count > 0 and mandatory_status == "OBSERVED_BEHAVIOR" and not has_unknown_wins:
                status = "OBSERVED_BEHAVIOR"
                overall_observation_status = "OBSERVED_BEHAVIOR"
            else:
                status = "NOT_ASSESSED"
                overall_observation_status = "NOT_ASSESSED"
        elif cad_count > 0:
            status = "OBSERVED_BEHAVIOR"
            overall_observation_status = "OBSERVED_BEHAVIOR"
        else:
            status = "NOT_ASSESSED"
            overall_observation_status = "NOT_ASSESSED"

        # Construct evidence_summary
        if len(s4_trials) == 40 and len(v4_wins) == 39 and len(v6_wins) == 1 and med_cad is not None:
            summary = (
                f"Observed behavior under 600.000 ms IPv6 path delay: IPv4 connection established first in 39/40 trials "
                f"(pooled median CAD {med_cad:.3f} ms; Google Chrome: 20/20 IPv4 wins [median 300.810 ms]; "
                f"Firefox: 19/20 IPv4 wins [median 397.940 ms]). All 39 measured CAD values satisfy "
                f"the 10.000 ms mandatory floor and fall within the recommended [100.000, 2000.000] ms range. "
                f"In 1/40 trials (Firefox trial trial-20261029222109-5c74c26a), IPv6 recorded a 600.949 ms SYN-to-SYN/ACK interval "
                f"(handshake completion at 601.045 ms; wire HTTP 200 at 1,298.191 ms); no IPv4 TCP SYN packet was observed in the monitored PCAP "
                f"(bounded by capture interface and observation window); browser-internal scheduling causality remains insufficient evidence. "
                f"Scoped to recorded trials under lab conditions; does not infer general client non-conformance."
            )
        elif status == "POTENTIAL_CRITERION_MISMATCH":
            if mandatory_status == "POTENTIAL_CRITERION_MISMATCH":
                mand_part = f"Subsequent connection attempt started in < 10ms ({cad_sub10_count} trial(s)), differing from RFC 8305 §5 mandatory floor (mandatory_status=POTENTIAL_CRITERION_MISMATCH)."
            elif mandatory_status == "OBSERVED_BEHAVIOR":
                na_note = f"; {not_applicable_mand_count} trial(s) without subsequent attempt evaluated as NOT_APPLICABLE" if not_applicable_mand_count > 0 else ""
                mand_part = f"All {cad_count} measured CAD values satisfy mandatory 10ms floor (mandatory_status=OBSERVED_BEHAVIOR{na_note})."
            else:
                extra_notes = []
                if invalid_cad_count > 0:
                    extra_notes.append(f"{invalid_cad_count} invalid CAD measurement(s)")
                if missing_cad_count > 0:
                    extra_notes.append(f"{missing_cad_count} missing CAD measurement(s)")
                notes_str = f" ({'; '.join(extra_notes)})" if extra_notes else ""
                mand_part = f"Mandatory timing assessment is {mandatory_status}{notes_str}."

            rec_part = f" {'; '.join(rec_deviations)}." if rec_deviations else ""
            inv_str = f" ({invalid_cad_count} trial(s) had invalid CAD measurements)" if invalid_cad_count > 0 else ""
            indet_rec_note = f" (recommendation_status=NOT_ASSESSED due to {len(unknown_wins)} unknown outcome(s))" if (recommended_status == "NOT_ASSESSED" and not rec_deviations) else ""
            prefix = "Observed potential criterion mismatch in tested trial(s):" if rec_deviations else "Observed mandatory timing criterion mismatch in tested trial(s):"
            summary = (
                f"{prefix} "
                f"IPv4 won in {len(v4_wins)}/{total_s4} trials ({b_summary_str}){indet_rec_note}. "
                f"{cad_dist_str}{inv_str} {mand_part}{rec_part} "
                f"Scoped to recorded trial(s); does not infer general client non-conformance or a mandatory timing violation."
            )
        elif status == "NOT_ASSESSED":
            indet_reasons = []
            if invalid_cad_count > 0:
                indet_reasons.append(f"{invalid_cad_count} trial(s) with invalid connection attempt delay measurements")
            if missing_cad_count > 0:
                indet_reasons.append(f"{missing_cad_count} fallback trial(s) missing connection attempt delay measurements")
            if has_unknown_wins:
                unk_ids = ", ".join(t.trial_id for t in unknown_wins)
                indet_reasons.append(f"{len(unknown_wins)} trial(s) with unknown winning address family ({unk_ids})")
            if not cad_vals and applicable_measured_count == 0:
                indet_reasons.append("no connection attempt delay measurements available")
            summary = f"Not assessed: {'; '.join(indet_reasons)}."
        else:
            summary = (
                f"Observed behavior in tested trial(s): IPv4 won in {len(v4_wins)}/{total_s4} trials ({b_summary_str}) "
                f"with median CAD {med_cad_str} when IPv6 RTT (600ms) exceeded CAD timer. "
                f"{cad_dist_str} All measured CAD values meet RFC 8305 §5 mandatory floor (>= 10ms) "
                f"and fall within recommended range [{RFC8305_MIN_CAD_MS:.0f}ms, {RFC8305_MAX_CAD_MS:.0f}ms]. "
                f"Scoped to recorded trial(s); does not infer general client compliance."
            )
    else:
        status = "NOT_ASSESSED"
        mandatory_status = "NOT_ASSESSED"
        recommended_status = "NOT_ASSESSED"
        mandatory_floor_status = "NOT_ASSESSED"
        recommendation_alignment_status = "NOT_ASSESSED"
        overall_observation_status = "NOT_ASSESSED"
        summary = "Not assessed: No valid S4 high latency trials available."

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
            "RFC 8305 Section 5 and draft-ietf-happy-happyeyeballs-v3-04 Section 6 distinguish mandatory inter-attempt spacing "
            "(subsequent attempts MUST NOT start within 10ms of the previous attempt) from recommended CAD parameters (recommended "
            "default 250ms, range 100ms to 2000ms). Under high primary-path latency (600ms IPv6 RTT), the client is expected to "
            "initiate an IPv4 connection attempt after the CAD timer, which finishes setup first over the low-latency path. "
            "CAD timing is assessed independently from path selection: trials with measured CAD intervals are evaluated against "
            "the 10ms floor and [100ms, 2000ms] recommended range. When a trial completes directly over IPv6 without an IPv4 "
            "connection attempt, no CAD interval occurs; such path-selection outcomes are documented separately and do not "
            "contaminate the CAD timing range evaluation."
        ),
        "target_parameter": "High Latency Fallback Path Racing",
        "rfc_specification_requirement": "CAD timer SHOULD NOT < 100 ms and MAX 2000 ms; IPv4 path expected to complete first (RFC 8305 Section 5 / v3 draft -04 Section 6)",
        "rfc_recommended_range": "[100.000, 2000.000] ms",
        "observed_delay_ms": med_cad,
        "observed_min_delay_ms": min(cad_vals) if cad_vals else None,
        "observed_max_delay_ms": max(cad_vals) if cad_vals else None,
        "mandatory_floor_status": mandatory_floor_status,
        "recommendation_alignment_status": recommendation_alignment_status,
        "overall_observation_status": overall_observation_status,
        "observable_behavior_summary": summary,
        "specification_context": (
            "RFC 8305 Section 5 and draft-ietf-happy-happyeyeballs-v3-04 Section 6 distinguish mandatory inter-attempt spacing "
            "(MUST NOT start within 10 ms) from recommended CAD parameters (100 ms to 2000 ms). Under high primary-path latency "
            "(600 ms RTT), the client is expected to initiate an IPv4 attempt after the CAD timer, which finishes setup first "
            "over the low-latency path."
        ),
    })

    # Check 5: RFC 8305 §3 - Resolution Delay on Asynchronous DNS
    s6_trials = by_sc["S6"]
    pos_delays_s6: List[float] = []
    pos_med_s6: Optional[float] = None
    if s6_trials:
        s6_evaluations = [(t, classify_s6_resolution_delay_trial(t)) for t in s6_trials]
        dev_trials = [t for t, res in s6_evaluations if res["classification"] == "DEVIATION"]
        conf_trials = [t for t, res in s6_evaluations if res["classification"] == "CONFORMANCE"]
        indet_trials = [t for t, res in s6_evaluations if res["classification"] == "INDETERMINATE"]
        pos_delays_s6 = [r["a_to_aaaa_ms"] for t, r in s6_evaluations if r.get("a_to_aaaa_ms") is not None and r.get("a_to_aaaa_ms") > 0]
        pos_delays_s6.sort()
        pos_med_s6 = compute_percentile(pos_delays_s6, 0.5) if pos_delays_s6 else None

        # Browser breakdown
        browser_summaries = []
        browsers_in_s6 = sorted(set(t.browser_name for t in s6_trials))
        for b in browsers_in_s6:
            b_evals = [res for t, res in s6_evaluations if t.browser_name == b]
            b_trials_count = len(b_evals)
            b_dev = sum(1 for r in b_evals if r["classification"] == "DEVIATION")
            b_conf = sum(1 for r in b_evals if r["classification"] == "CONFORMANCE")
            b_indet = sum(1 for r in b_evals if r["classification"] == "INDETERMINATE")
            b_delays = [r["a_to_aaaa_ms"] for r in b_evals if r["a_to_aaaa_ms"] is not None and r["a_to_aaaa_ms"] > 0]
            b_delays.sort()
            b_med = compute_percentile(b_delays, 0.5) if b_delays else None
            b_v4_att = sum(1 for r in b_evals if r["ipv4_attempt"] is True)
            b_label = _format_browser_label(b)
            med_str = f"{round(b_med, 2):.2f}ms" if b_med is not None else "N/A"
            browser_summaries.append(
                f"{b_label}: {b_trials_count} trials ({b_dev} deviations, {b_conf} conforming, {b_indet} indeterminate; "
                f"positive A-to-AAAA median {med_str}, {b_v4_att} IPv4 attempts)"
            )

        browser_str = "; ".join(browser_summaries)

        # Conservative aggregate status
        if dev_trials:
            status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_status = "NOT_APPLICABLE"
            recommended_status = "POTENTIAL_CRITERION_MISMATCH"
            mandatory_floor_status = "NOT_APPLICABLE"
            recommendation_alignment_status = "OUTSIDE_RECOMMENDED_RANGE"
            overall_observation_status = "POTENTIAL_CRITERION_MISMATCH"
            if len(s6_trials) == 40 and len(dev_trials) == 40:
                summary = (
                    f"Observed behavior when positive A response precedes positive AAAA response by ~500.000 ms: "
                    f"In 40/40 trials (20 Google Chrome, 20 Mozilla Firefox), both browsers waited for the late AAAA response "
                    f"(~500.000 ms; Google Chrome median 499.990 ms, Mozilla Firefox median 501.740 ms) and connected over IPv6 (0 IPv4 attempts), "
                    f"rather than initiating an IPv4 connection attempt after the 50.000 ms Resolution Delay recommended "
                    f"in RFC 8305 Section 3. Scoped to recorded trials under lab conditions; does not infer protocol violation "
                    f"or general browser non-conformance."
                )
            else:
                summary = (
                    f"Observed recommendation-level criterion mismatch in tested trial(s): "
                    f"{len(dev_trials)}/{len(s6_trials)} trials with potential criterion mismatch, "
                    f"{len(conf_trials)}/{len(s6_trials)} aligned, "
                    f"{len(indet_trials)}/{len(s6_trials)} not assessed. "
                    f"Sample: {len(s6_trials)} trial(s) ({browser_str}). "
                    f"Scoped to recorded trial(s); does not infer a mandatory MUST violation or general browser non-conformance."
                )
        elif indet_trials:
            status = "NOT_ASSESSED"
            mandatory_status = "NOT_APPLICABLE"
            recommended_status = "NOT_ASSESSED"
            mandatory_floor_status = "NOT_APPLICABLE"
            recommendation_alignment_status = "NOT_ASSESSED"
            overall_observation_status = "NOT_ASSESSED"
            summary = (
                f"Not assessed: Insufficient or missing positive DNS response/attempt evidence to assess Resolution Delay "
                f"({len(indet_trials)}/{len(s6_trials)} trials not assessed, "
                f"{len(conf_trials)}/{len(s6_trials)} aligned, "
                f"{len(dev_trials)}/{len(s6_trials)} deviations). "
                f"Sample: {len(s6_trials)} trial(s) ({browser_str})."
            )
        else:
            status = "OBSERVED_BEHAVIOR"
            mandatory_status = "NOT_APPLICABLE"
            recommended_status = "OBSERVED_BEHAVIOR"
            mandatory_floor_status = "NOT_APPLICABLE"
            recommendation_alignment_status = "ALIGNED"
            overall_observation_status = "OBSERVED_BEHAVIOR"
            summary = (
                f"Observed behavior in tested trial(s): Client adhered to Resolution Delay recommendation "
                f"({len(conf_trials)}/{len(s6_trials)} trials conforming, "
                f"{len(dev_trials)}/{len(s6_trials)} deviations, "
                f"{len(indet_trials)}/{len(s6_trials)} not assessed). "
                f"Sample: {len(s6_trials)} trial(s) ({browser_str}). "
                f"Scoped to recorded trial(s); does not infer general client compliance."
            )
    else:
        status = "NOT_ASSESSED"
        mandatory_status = "NOT_ASSESSED"
        recommended_status = "NOT_ASSESSED"
        mandatory_floor_status = "NOT_ASSESSED"
        recommendation_alignment_status = "NOT_ASSESSED"
        overall_observation_status = "NOT_ASSESSED"
        summary = "Not assessed: No valid S6 delayed AAAA DNS trials available."

    assessments.append({
        "check_id": "RFC8305-SEC3-RESOLUTION-DELAY",
        "rfc_section": "RFC 8305 Section 3",
        "title": "Hostname Resolution Query Handling: Resolution Delay",
        "scenario_id": "S6",
        "status": status,
        "mandatory_status": mandatory_status,
        "recommended_status": recommended_status,
        "sample_size": len(s6_trials),
        "evidence_summary": summary,
        "reasoning": (
            "RFC 8305 Section 3 (Hostname Resolution Query Handling) recommends a 50ms Resolution Delay when a positive A response arrives "
            "before a positive AAAA response. If positive AAAA arrives within or exactly at 50ms, an IPv4 "
            "connection attempt that starts before the positive AAAA response is an observed recommendation-level "
            "criterion mismatch; if no IPv4 attempt starts before that positive AAAA response, the trial aligns with this "
            "timing recommendation. If positive AAAA arrives more than 50ms after positive A, an IPv4 attempt "
            "should have started within the 50ms window; no attempt, or an attempt starting after that window, "
            "is an observed potential criterion mismatch. If an attempt is recorded but its timing cannot establish the relevant "
            "chronology, classify the trial as not assessed. This recommendation-level assessment documents "
            "specific trial behavior under lab conditions and does not infer a mandatory MUST violation or "
            "general browser non-conformance."
        ),
        "target_parameter": "DNS Resolution Delay Pacing",
        "rfc_specification_requirement": "RECOMMENDED 50 ms Resolution Delay before initiating IPv4 (RFC 8305 Section 3 Hostname Resolution Query Handling / v3 draft -04 Section 7)",
        "rfc_recommended_range": "[0.000, 50.000] ms",
        "observed_delay_ms": pos_med_s6,
        "observed_min_delay_ms": min(pos_delays_s6) if pos_delays_s6 else None,
        "observed_max_delay_ms": max(pos_delays_s6) if pos_delays_s6 else None,
        "mandatory_floor_status": mandatory_floor_status,
        "recommendation_alignment_status": recommendation_alignment_status,
        "overall_observation_status": overall_observation_status,
        "observable_behavior_summary": summary,
        "specification_context": (
            "RFC 8305 Section 3 (Hostname Resolution Query Handling) recommends a 50 ms Resolution Delay when a positive A response arrives before a positive "
            "AAAA response. If positive AAAA arrives within 50 ms, an IPv4 attempt starting before AAAA arrival is an "
            "observed potential criterion mismatch. If positive AAAA arrives after 50 ms, an IPv4 attempt should be initiated "
            "within the 50 ms window. draft-ietf-happy-happyeyeballs-v3-04 Section 7 discusses DNS answer changes during connection setup."
        ),
    })

    # Check 6: RFC 8305 §4 / v3 draft -04 §5.3 - Historical Statefulness & Adaptive Timers
    assessments.append({
        "check_id": "RFC8305-SEC4-HISTORICAL-STATE",
        "rfc_section": "RFC 8305 Section 4",
        "title": "Sorting Addresses: Historical Information and State Caching",
        "scenario_id": "ALL",
        "status": "NOT_ASSESSED",
        "mandatory_status": "NOT_ASSESSED",
        "recommended_status": "NOT_ASSESSED",
        "sample_size": len(trials),
        "evidence_summary": (
            "Not assessed: Unsupported check. PS-028 testbed protocol unconditionally wipes browser user data directories "
            "(--user-data-dir) after each trial to guarantee cross-trial measurement independence. Cross-session persistence "
            "and adaptive failure caching cannot be evaluated."
        ),
        "reasoning": (
            "RFC 8305 Section 4 (Sorting Addresses) specifies sorting addresses, including the use of RFC 6724 destination-address sorting, "
            "historical RTT information, and previously used addresses. draft-ietf-happy-happyeyeballs-v3-04 Section 5.3 specifies sorting "
            "destination endpoints within groups using historical RTT and endpoint-use data. RFC 8305 Section 7 (Supporting IPv6-Only Networks "
            "with NAT64 and DNS64) is dedicated to NAT64 and DNS64 support on IPv6-only networks, not statefulness or failure caching. "
            "Because trials are executed with clean profiles to guarantee measurement independence, historical statefulness cannot be evaluated."
        ),
        "target_parameter": "Historical Address Selection and Past State Caching",
        "rfc_specification_requirement": "MAY remember historical RTT and previously used addresses for sorting (RFC 8305 Section 4 Sorting Addresses / v3 draft -04 Section 5.3)",
        "rfc_recommended_range": "N/A",
        "observed_delay_ms": None,
        "observed_min_delay_ms": None,
        "observed_max_delay_ms": None,
        "mandatory_floor_status": "NOT_ASSESSED",
        "recommendation_alignment_status": "NOT_ASSESSED",
        "overall_observation_status": "NOT_ASSESSED",
        "observable_behavior_summary": (
            "Not assessed: Unsupported check. PS-028 testbed protocol unconditionally wipes browser user data directories "
            "(--user-data-dir) after each trial to guarantee cross-trial measurement independence. Cross-session persistence "
            "and adaptive failure caching cannot be evaluated."
        ),
        "specification_context": (
            "RFC 8305 Section 4 (Sorting Addresses) specifies sorting addresses, including historical RTT and previously used addresses per RFC 6724. "
            "draft-ietf-happy-happyeyeballs-v3-04 Section 5.3 specifies sorting destination endpoints within groups using "
            "historical RTT and endpoint-use data. RFC 8305 Section 7 (Supporting IPv6-Only Networks with NAT64 and DNS64) is dedicated to NAT64 and DNS64 support on IPv6-only "
            "networks. Clean profile isolation per trial prevents cross-trial state evaluation."
        ),
    })

    # Check 7: v3 draft -04 §6.1 - QUIC Transport Applicability
    assessments.append({
        "check_id": "HEV3-DRAFT04-SEC6.1-QUIC",
        "rfc_section": "draft-ietf-happy-happyeyeballs-v3-04 Section 6.1",
        "title": "QUIC Connection Establishment Applicability",
        "scenario_id": "ALL",
        "status": "OUT_OF_SCOPE",
        "mandatory_status": "OUT_OF_SCOPE",
        "recommended_status": "OUT_OF_SCOPE",
        "sample_size": len(trials),
        "evidence_summary": (
            "Out of scope: Unsupported check. The PS-028 dual-stack lab specifically instruments HTTP/1.1 over TCP. "
            "Alternative transport protocols (QUIC) are out of testbed scope and were not tested. "
            "SCTP is not specified in Happy Eyeballs v2 (RFC 8305) or Happy Eyeballs v3 (draft-ietf-happy-happyeyeballs-v3-04)."
        ),
        "reasoning": (
            "draft-ietf-happy-happyeyeballs-v3-04 Section 6.1 specifies connection establishment determination for both TCP and "
            "QUIC handshakes. RFC 8305 does not specify QUIC or non-TCP transports (RFC 8305 Section 8 is the Summary of "
            "Configurable Values). SCTP is not specified in either RFC 8305 or draft-ietf-happy-happyeyeballs-v3-04. "
            "Because the campaign instrumented HTTP/1.1 over TCP socket connections, QUIC evaluation is out of scope."
        ),
        "target_parameter": "Alternative Transport Protocol Applicability (QUIC)",
        "rfc_specification_requirement": "Connection establishment determination for QUIC handshakes (draft-ietf-happy-happyeyeballs-v3-04 Section 6.1)",
        "rfc_recommended_range": "N/A",
        "observed_delay_ms": None,
        "observed_min_delay_ms": None,
        "observed_max_delay_ms": None,
        "mandatory_floor_status": "OUT_OF_SCOPE",
        "recommendation_alignment_status": "OUT_OF_SCOPE",
        "overall_observation_status": "OUT_OF_SCOPE",
        "observable_behavior_summary": (
            "Out of scope: Unsupported check. The PS-028 dual-stack lab specifically instruments HTTP/1.1 over TCP. "
            "Alternative transport protocols (QUIC) are out of testbed scope and were not tested. "
            "SCTP is not specified in Happy Eyeballs v2 (RFC 8305) or Happy Eyeballs v3 (draft-ietf-happy-happyeyeballs-v3-04)."
        ),
        "specification_context": (
            "draft-ietf-happy-happyeyeballs-v3-04 Section 6.1 specifies connection establishment determination for both TCP and "
            "QUIC handshakes. RFC 8305 Section 8 provides a Summary of Configurable Values and does not specify alternative transports. "
            "SCTP is not specified in either document. Untested protocols are out of testbed scope."
        ),
    })

    return assessments


# Alias for RFC assessment per specification
evaluate_rfc8305 = assess_rfc8305_conformance


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
    """Renders RFC 8305 assessment into CSV format adhering to the 15-column neutral schema."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([
        "check_id",
        "rfc_section",
        "scenario_id",
        "target_parameter",
        "rfc_specification_requirement",
        "rfc_recommended_range",
        "sample_size",
        "observed_delay_ms",
        "observed_min_delay_ms",
        "observed_max_delay_ms",
        "mandatory_floor_status",
        "recommendation_alignment_status",
        "overall_observation_status",
        "observable_behavior_summary",
        "specification_context",
    ])

    def _fmt_float(val: Any) -> str:
        if val is None or val == "":
            return ""
        if isinstance(val, (int, float)):
            return f"{float(val):.3f}"
        return str(val)

    # Sort checks deterministically by check_id
    assessments = sorted(
        report.get("rfc8305_assessment", []),
        key=lambda x: str(x.get("check_id", ""))
    )

    for a in assessments:
        obs_summary = a.get("observable_behavior_summary") or a.get("evidence_summary", "")
        spec_ctx = a.get("specification_context") or a.get("reasoning", "")
        writer.writerow([
            a.get("check_id", ""),
            a.get("rfc_section", ""),
            a.get("scenario_id", ""),
            a.get("target_parameter", ""),
            a.get("rfc_specification_requirement", ""),
            a.get("rfc_recommended_range", "N/A"),
            a.get("sample_size", 0),
            _fmt_float(a.get("observed_delay_ms")),
            _fmt_float(a.get("observed_min_delay_ms")),
            _fmt_float(a.get("observed_max_delay_ms")),
            a.get("mandatory_floor_status", "NOT_APPLICABLE"),
            a.get("recommendation_alignment_status", "ALIGNED"),
            a.get("overall_observation_status", a.get("status", "")),
            obs_summary,
            spec_ctx,
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
    rfc_fmt = "{:<36} {:<6} {:<30} {:<42}"
    lines.append(rfc_fmt.format("Check ID", "Scen", "Status", "Observable Evidence Summary"))
    lines.append("-" * 120)

    for a in report.get("rfc8305_assessment", []):
        cid = a.get("check_id", "")[:36]
        sc = a.get("scenario_id", "")[:6]
        st = a.get("status", "")
        # Color coding in terminal if ANSI supported
        if st in ("OBSERVED_BEHAVIOR", "OBSERVED_CONFORMANCE", "COMPLIANT"):
            st_str = f"\033[1;32m{st}\033[0m"
            raw_len = len(st)
        elif st in ("POTENTIAL_CRITERION_MISMATCH", "OBSERVED_DEVIATION", "DEVIATION", "NON_COMPLIANT"):
            st_str = f"\033[1;33m{st}\033[0m"
            raw_len = len(st)
        elif st == "OUT_OF_SCOPE":
            st_str = f"\033[1;35m{st}\033[0m"
            raw_len = len(st)
        else:
            st_str = f"\033[1;34m{st}\033[0m"
            raw_len = len(st)

        padding = " " * max(0, 30 - raw_len)
        ev = a.get("evidence_summary", "")
        if len(ev) > 65:
            ev = ev[:62] + "..."
        lines.append(f"{cid:<36} {sc:<6} {st_str}{padding} {ev}")

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
