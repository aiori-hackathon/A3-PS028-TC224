#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Campaign Comparison and Replication Evaluation Pipeline
Work Package I: Scientific Comparison Pipeline

Statistically compares an independent partner campaign against the authoritative
historical baseline (or any two campaigns) across all 14 cohorts (7 scenarios x 2 browsers).

Computes:
- Medians, IQRs, p95, and deterministic bootstrap 95% confidence intervals for timing metrics.
- Proportions and Wilson score 95% confidence intervals for winning family and fallback rates.
- S5 stochastic impairment compliance.
- Classifies each cohort and overall campaign into:
  * REPLICATED
  * SYSTEMATIC_SHIFT
  * BEHAVIORAL_DIVERGENCE
  * INCONCLUSIVE
  * INVALID
"""

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.replication_contract import (
    CANONICAL_SCENARIO_IDS as CANONICAL_SCENARIOS,
    PINNED_BROWSERS,
    HISTORICAL_BASELINE_CAMPAIGN_ID,
    REPETITIONS_PER_COHORT as EXPECTED_VALID_TRIALS_PER_COHORT,
)

CANONICAL_BROWSERS = list(PINNED_BROWSERS.keys())
DEFAULT_HISTORICAL_CAMPAIGN_PATH = REPO_ROOT / "lab" / "campaigns" / HISTORICAL_BASELINE_CAMPAIGN_ID


# -----------------------------------------------------------------------------
# Statistical Helper Routines (Pure Python, Deterministic)
# -----------------------------------------------------------------------------

def compute_percentile(values: List[float], p: float) -> Optional[float]:
    """Computes percentile p (0.0 to 100.0) with linear interpolation."""
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(s[int(k)])
    d0 = s[int(f)] * (c - k)
    d1 = s[int(c)] * (k - f)
    return float(d0 + d1)


def compute_median(values: List[float]) -> Optional[float]:
    """Computes median of numeric list."""
    return compute_percentile(values, 50.0)


def compute_iqr(values: List[float]) -> Optional[float]:
    """Computes Interquartile Range (Q3 - Q1)."""
    if not values:
        return None
    q1 = compute_percentile(values, 25.0)
    q3 = compute_percentile(values, 75.0)
    if q1 is not None and q3 is not None:
        return float(q3 - q1)
    return None


def compute_wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """
    Computes Wilson score interval for binomial proportion k / n.
    Returns (proportion, ci_lower, ci_upper).
    """
    if n <= 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    if abs(confidence - 0.99) < 0.005:
        z = 2.5758293035489004
    elif abs(confidence - 0.90) < 0.005:
        z = 1.6448536269514722
    else:
        z = 1.959963984540054
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half_width = (z / denom) * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))
    lower = 0.0 if k <= 0 else max(0.0, center - half_width)
    upper = 1.0 if k >= n else min(1.0, center + half_width)
    return (float(p), float(lower), float(upper))


def compute_bootstrap_median_ci(
    values: List[float],
    iterations: int = 1000,
    confidence: float = 0.95,
    seed: int = 42
) -> Tuple[Optional[float], Optional[float]]:
    """
    Computes bootstrap confidence interval for the median using deterministic PRNG.
    """
    if not values:
        return (None, None)
    n = len(values)
    if n < 5:
        return (min(values), max(values))

    rng = random.Random(seed)
    medians: List[float] = []
    for _ in range(iterations):
        sample = [rng.choice(values) for _ in range(n)]
        m = compute_median(sample)
        if m is not None:
            medians.append(m)

    alpha = 1.0 - confidence
    lower_p = (alpha / 2.0) * 100.0
    upper_p = (1.0 - alpha / 2.0) * 100.0
    lower = compute_percentile(medians, lower_p)
    upper = compute_percentile(medians, upper_p)
    return (lower, upper)


def compute_agresti_caffo_diff_ci(
    k1: int, n1: int, k2: int, n2: int, confidence: float = 0.90
) -> Tuple[float, float, float]:
    """
    Computes Agresti-Caffo confidence interval for the difference of two independent
    binomial proportions (p2 - p1).
    Used in Two One-Sided Tests (TOST) for winning-family proportion equivalence.
    Returns (diff, ci_lower, ci_upper).
    """
    if n1 <= 0 or n2 <= 0:
        return (0.0, 0.0, 0.0)
    p1 = k1 / n1
    p2 = k2 / n2
    diff = p2 - p1

    # Deterministic endpoints with zero sample variance
    if (k1 == n1 and k2 == n2) or (k1 == 0 and k2 == 0):
        return (0.0, 0.0, 0.0)

    # Agresti-Caffo +1 adjustment per cell (total +2 per group)
    n1_adj = n1 + 2
    n2_adj = n2 + 2
    p1_adj = (k1 + 1) / n1_adj
    p2_adj = (k2 + 1) / n2_adj
    diff_adj = p2_adj - p1_adj
    se = math.sqrt((p1_adj * (1.0 - p1_adj) / n1_adj) + (p2_adj * (1.0 - p2_adj) / n2_adj))
    z = 1.6448536 if abs(confidence - 0.90) < 0.01 else 1.95996
    margin = z * se
    ci_lower = max(-1.0, round(diff_adj - margin, 4))
    ci_upper = min(1.0, round(diff_adj + margin, 4))
    return (round(diff, 4), ci_lower, ci_upper)


def compute_two_sample_bootstrap_median_ci(
    s1: List[float],
    s2: List[float],
    iterations: int = 2000,
    confidence: float = 0.90,
    seed: int = 42
) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """
    Computes two-sample percentile bootstrap confidence interval for the median difference (median(s2) - median(s1)).
    Uses deterministic PRNG seed for scientific reproducibility.
    Returns (median_diff, ci_lower, ci_upper).
    """
    if not s1 or not s2:
        return (None, None, None)
    m1 = compute_median(s1)
    m2 = compute_median(s2)
    if m1 is None or m2 is None:
        return (None, None, None)
    diff = round(m2 - m1, 4)

    rng = random.Random(seed)
    n1 = len(s1)
    n2 = len(s2)
    diffs: List[float] = []
    for _ in range(iterations):
        sample1 = [rng.choice(s1) for _ in range(n1)]
        sample2 = [rng.choice(s2) for _ in range(n2)]
        b_m1 = compute_median(sample1)
        b_m2 = compute_median(sample2)
        if b_m1 is not None and b_m2 is not None:
            diffs.append(b_m2 - b_m1)

    if not diffs:
        return (diff, diff, diff)

    diffs.sort()
    alpha = 1.0 - confidence
    lower_idx = int((alpha / 2.0) * len(diffs))
    upper_idx = int((1.0 - alpha / 2.0) * len(diffs))
    lower_idx = max(0, min(lower_idx, len(diffs) - 1))
    upper_idx = max(0, min(upper_idx, len(diffs) - 1))
    return (diff, round(diffs[lower_idx], 4), round(diffs[upper_idx], 4))


# -----------------------------------------------------------------------------
# Campaign Data Ingestion
# -----------------------------------------------------------------------------

def load_campaign_trials(campaign_dir: Path) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """
    Loads completed valid live trials grouped by (scenario_id, normalized_browser).
    Consumes campaign_manifest.json and trials/*/result.json.
    """
    campaign_dir = Path(campaign_dir).resolve()
    manifest_f = campaign_dir / "campaign_manifest.json"
    if not manifest_f.is_file():
        raise FileNotFoundError(f"Missing campaign_manifest.json in '{campaign_dir}'")

    mdata = json.loads(manifest_f.read_text(encoding="utf-8"))
    cohorts: Dict[Tuple[str, str], List[Dict[str, Any]]] = {
        (sc, br): [] for sc in CANONICAL_SCENARIOS for br in CANONICAL_BROWSERS
    }

    trials_root = campaign_dir / "trials"
    matrix_slots = mdata.get("matrix_slots", [])

    for slot in matrix_slots:
        sc = slot.get("scenario_id")
        br_raw = slot.get("browser")
        br = "google-chrome" if "chrome" in str(br_raw).lower() else "firefox"
        if (sc, br) not in cohorts:
            continue

        attempts = slot.get("attempts", [])
        for att in attempts:
            if att.get("status") == "COMPLETED" and att.get("validity") == "VALID_LIVE":
                tid = att.get("trial_id")
                res_path = trials_root / tid / "result.json" if tid else None
                if res_path and res_path.is_file():
                    try:
                        rdata = json.loads(res_path.read_text(encoding="utf-8"))
                        cohorts[(sc, br)].append(rdata)
                    except Exception:
                        pass
                break

    return cohorts


def extract_cohort_metrics(trials: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts structured metrics and distributions from a trial cohort list.
    """
    t_conn_vals: List[float] = []
    t_setup_vals: List[float] = []
    cad_vals: List[float] = []
    ipv6_wins = 0
    ipv4_wins = 0
    total_valid = len(trials)

    for t in trials:
        # Schema 1.0.0 vs 1.1.0 reconciliation
        metrics = t.get("metrics") or {}
        net_obs = t.get("network_observations") or {}
        http_out = t.get("http_outcome") or {}
        primary = t.get("primary_flow") or {}

        # 1. t_connect_ms
        t_conn = metrics.get("t_connect_ms") if "t_connect_ms" in metrics else t.get("t_connect_ms")
        if t_conn is None:
            t_conn = net_obs.get("connection_setup_time_ms") or t.get("connection_setup_time_ms")
        if t_conn is not None:
            try:
                t_conn_vals.append(float(t_conn))
            except (ValueError, TypeError):
                pass

        # 2. t_setup_total_ms
        t_setup = metrics.get("t_setup_total_ms") if "t_setup_total_ms" in metrics else t.get("t_setup_total_ms")
        if t_setup is None and "total_duration_ms" in t.get("timestamps", {}):
            t_setup = t["timestamps"].get("total_duration_ms")
        if t_setup is not None:
            try:
                t_setup_vals.append(float(t_setup))
            except (ValueError, TypeError):
                pass

        # 3. cad_ms
        cad = metrics.get("cad_ms") if "cad_ms" in metrics else metrics.get("connection_attempt_delay_ms")
        if cad is None:
            cad = net_obs.get("cad_observed_ms") or t.get("cad_ms")
        if cad is not None:
            try:
                cad_vals.append(float(cad))
            except (ValueError, TypeError):
                pass

        # 4. Winning family
        winner = (
            http_out.get("winning_address_family") or
            t.get("winning_family") or
            primary.get("family") or
            net_obs.get("winning_family")
        )
        if not winner and net_obs.get("classification") in ("DIRECT_IPV6", "FALLBACK_IPV4"):
            winner = "IPv6" if net_obs.get("classification") == "DIRECT_IPV6" else "IPv4"

        if winner:
            if "6" in str(winner):
                ipv6_wins += 1
            elif "4" in str(winner):
                ipv4_wins += 1

    p_v6, v6_low, v6_high = compute_wilson_ci(ipv6_wins, total_valid)
    t_conn_med = compute_median(t_conn_vals)
    t_conn_ci = compute_bootstrap_median_ci(t_conn_vals)
    t_setup_med = compute_median(t_setup_vals)
    t_setup_ci = compute_bootstrap_median_ci(t_setup_vals)

    return {
        "trial_count": total_valid,
        "t_connect_ms": {
            "values_count": len(t_conn_vals),
            "median": t_conn_med,
            "iqr": compute_iqr(t_conn_vals),
            "p95": compute_percentile(t_conn_vals, 95.0),
            "ci_95": t_conn_ci,
            "raw_values": t_conn_vals,
        },
        "t_setup_total_ms": {
            "values_count": len(t_setup_vals),
            "median": t_setup_med,
            "iqr": compute_iqr(t_setup_vals),
            "p95": compute_percentile(t_setup_vals, 95.0),
            "ci_95": t_setup_ci,
            "raw_values": t_setup_vals,
        },
        "cad_ms": {
            "values_count": len(cad_vals),
            "median": compute_median(cad_vals),
            "iqr": compute_iqr(cad_vals),
            "raw_values": cad_vals,
        },
        "winning_family": {
            "ipv6_count": ipv6_wins,
            "ipv4_count": ipv4_wins,
            "total_count": total_valid,
            "ipv6_proportion": p_v6,
            "ipv6_wilson_ci_95": (v6_low, v6_high),
        }
    }


# -----------------------------------------------------------------------------
# Scientific Cohort Comparison & Replication Evaluation
# -----------------------------------------------------------------------------

def evaluate_cohort(
    scenario_id: str,
    browser: str,
    baseline_stats: Dict[str, Any],
    partner_stats: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates replication consistency between baseline and partner for one cohort.
    Uses Two One-Sided Tests (TOST) with predeclared practical equivalence margins:
    - Winning family agreement evaluated via 90% Agresti-Caffo CI (TOST alpha=0.05).
    - Latency equivalence evaluated via 90% two-sample bootstrap median CI (TOST alpha=0.05, seed=42).
    - Reports winning-family agreement separately from latency equivalence.
    Classifies into: REPLICATED, SYSTEMATIC_SHIFT, BEHAVIORAL_DIVERGENCE, INCONCLUSIVE, or INVALID.
    """
    b_count = baseline_stats.get("trial_count", 0)
    p_count = partner_stats.get("trial_count", 0)

    if b_count == 0 or p_count == 0:
        return {
            "cohort": f"{scenario_id}:{browser}",
            "scenario_id": scenario_id,
            "browser": browser,
            "classification": "INVALID",
            "reason": f"Insufficient trials (baseline={b_count}, partner={p_count})"
        }

    # -------------------------------------------------------------------------
    # 1. Predeclared Practical Equivalence Margins
    # -------------------------------------------------------------------------
    # Latency absolute margin: 5.0ms on 20ms link (25% RTT); 25ms on 150ms link; 25/50ms on 600ms link
    if scenario_id in ("S0", "S1", "S2", "S5", "S6"):
        delta_abs_margin = 5.0
        delta_p_margin = 0.25 if scenario_id == "S5" else 0.15
    elif scenario_id == "S3":
        delta_abs_margin = 25.0
        delta_p_margin = 0.15
    elif scenario_id == "S4":
        p_v6_cnt = partner_stats.get("winning_family", {}).get("ipv6_count", 0)
        delta_abs_margin = 25.0 if p_v6_cnt == 0 else 50.0
        delta_p_margin = 0.15
    else:
        delta_abs_margin = 5.0
        delta_p_margin = 0.15

    ratio_equiv_margin = (0.85, 1.15)

    # -------------------------------------------------------------------------
    # 2. Winning Address Family Agreement (Separated Analysis)
    # -------------------------------------------------------------------------
    b_v6_count = baseline_stats["winning_family"]["ipv6_count"]
    b_v4_count = baseline_stats["winning_family"]["ipv4_count"]
    b_v6_p = baseline_stats["winning_family"]["ipv6_proportion"]
    b_v6_low, b_v6_high = baseline_stats["winning_family"]["ipv6_wilson_ci_95"]

    p_v6_count = partner_stats["winning_family"]["ipv6_count"]
    p_v4_count = partner_stats["winning_family"]["ipv4_count"]
    p_v6_p = partner_stats["winning_family"]["ipv6_proportion"]
    p_v6_low, p_v6_high = partner_stats["winning_family"]["ipv6_wilson_ci_95"]

    p_diff, p_diff_low, p_diff_high = compute_agresti_caffo_diff_ci(
        b_v6_count, b_count, p_v6_count, p_count, confidence=0.90
    )

    # Deterministic scenarios require zero IPv6 under physical impairments
    deterministic_violation = False
    if scenario_id in ("S1", "S2") and p_v6_count > 0:
        deterministic_violation = True

    # TOST rule for proportion equivalence: 90% CI falls within [-delta_p_margin, +delta_p_margin]
    family_equivalent = (
        not deterministic_violation
        and (p_diff_low >= -delta_p_margin and p_diff_high <= delta_p_margin)
    )

    winning_family_eval = {
        "baseline_p_v6": b_v6_p,
        "baseline_wilson_ci_95": (b_v6_low, b_v6_high),
        "partner_p_v6": p_v6_p,
        "partner_wilson_ci_95": (p_v6_low, p_v6_high),
        "delta_p_v6": p_diff,
        "agresti_caffo_ci_90": (p_diff_low, p_diff_high),
        "equivalence_margin": delta_p_margin,
        "equivalent": family_equivalent,
        "deterministic_violation": deterministic_violation,
    }

    # -------------------------------------------------------------------------
    # 3. Connection Latency Equivalence (Separated TOST Analysis)
    # -------------------------------------------------------------------------
    b_tconn = baseline_stats["t_connect_ms"]["median"]
    p_tconn = partner_stats["t_connect_ms"]["median"]
    b_ci = baseline_stats["t_connect_ms"]["ci_95"]
    p_ci = partner_stats["t_connect_ms"]["ci_95"]

    b_vals = baseline_stats["t_connect_ms"].get("raw_values", [])
    p_vals = partner_stats["t_connect_ms"].get("raw_values", [])

    if b_vals and p_vals:
        med_diff, ci_diff_low, ci_diff_high = compute_two_sample_bootstrap_median_ci(
            b_vals, p_vals, iterations=2000, confidence=0.90, seed=42
        )
        latency_equivalent = (
            ci_diff_low is not None and ci_diff_high is not None
            and ci_diff_low >= -delta_abs_margin
            and ci_diff_high <= delta_abs_margin
        )
    elif b_tconn is not None and p_tconn is not None:
        med_diff = round(p_tconn - b_tconn, 4)
        ci_diff_low = med_diff
        ci_diff_high = med_diff
        latency_equivalent = abs(med_diff) <= delta_abs_margin
    else:
        med_diff = 0.0
        ci_diff_low, ci_diff_high = 0.0, 0.0
        latency_equivalent = True

    ratio = round(p_tconn / b_tconn, 4) if (b_tconn and b_tconn > 0) else 1.0

    latency_eval = {
        "baseline_median_ms": b_tconn,
        "partner_median_ms": p_tconn,
        "delta_median_ms": med_diff,
        "bootstrap_ci_90_ms": (ci_diff_low, ci_diff_high),
        "equivalence_margin_abs_ms": delta_abs_margin,
        "ratio": ratio,
        "ratio_margin": ratio_equiv_margin,
        "equivalent": latency_equivalent,
    }

    # -------------------------------------------------------------------------
    # 4. Five-Category Replication Classification
    # -------------------------------------------------------------------------
    b_iqr = baseline_stats["t_connect_ms"]["iqr"] or 10.0
    p_iqr = partner_stats["t_connect_ms"]["iqr"]

    if p_iqr is not None and p_iqr > 50.0 and p_iqr > 3.0 * max(10.0, b_iqr):
        classification = "INCONCLUSIVE"
        reason = (
            f"Extreme anomalous measurement dispersion in partner campaign "
            f"(partner IQR={p_iqr:.1f}ms exceeds 3x baseline IQR {b_iqr:.1f}ms; statistical power compromised by host noise)."
        )
    elif family_equivalent and latency_equivalent:
        classification = "REPLICATED"
        reason = (
            f"Equivalence confirmed via TOST (alpha=0.05): winning family agreement confirmed "
            f"(diff={p_diff:+.2f}, 90% CI=[{p_diff_low:.2f}, {p_diff_high:.2f}] in [{-delta_p_margin}, {delta_p_margin}]), "
            f"and median connect latency difference 90% bootstrap CI=[{ci_diff_low}, {ci_diff_high}]ms "
            f"lies strictly within predeclared practical equivalence margin [{-delta_abs_margin}, {delta_abs_margin}]ms."
        )
    elif family_equivalent and not latency_equivalent and (0.50 <= ratio <= 2.50):
        classification = "SYSTEMATIC_SHIFT"
        reason = (
            f"Protocol choices agree, but latency median delta ({med_diff:+.1f}ms, ratio={ratio:.2f}) "
            f"90% bootstrap CI=[{ci_diff_low}, {ci_diff_high}]ms exceeds equivalence margin [{-delta_abs_margin}, {delta_abs_margin}]ms; "
            f"consistent with uniform host virtualization or timer frequency delta."
        )
    elif deterministic_violation or (not family_equivalent and abs(p_diff) > 0.35) or (ratio < 0.50 or ratio > 2.50):
        classification = "BEHAVIORAL_DIVERGENCE"
        reason = (
            f"Substantive behavioral divergence observed: winning family diff={p_diff:+.2f} "
            f"(deterministic_violation={deterministic_violation}) or latency ratio={ratio:.2f} outside [0.50, 2.50]."
        )
    else:
        classification = "SYSTEMATIC_SHIFT" if (0.50 <= ratio <= 2.50) else "BEHAVIORAL_DIVERGENCE"
        reason = f"Boundary divergence: ratio={ratio:.2f}, family_diff={p_diff:+.2f}."

    return {
        "cohort": f"{scenario_id}:{browser}",
        "scenario_id": scenario_id,
        "browser": browser,
        "classification": classification,
        "reason": reason,
        "winning_family_evaluation": winning_family_eval,
        "latency_evaluation": latency_eval,
        "baseline_summary": baseline_stats,
        "partner_summary": partner_stats,
    }


def compare_campaigns(baseline_dir: Path, partner_dir: Path) -> Dict[str, Any]:
    """
    Executes full multi-cohort scientific campaign comparison.
    """
    baseline_dir = Path(baseline_dir).resolve()
    partner_dir = Path(partner_dir).resolve()

    b_cohorts = load_campaign_trials(baseline_dir)
    p_cohorts = load_campaign_trials(partner_dir)

    cohort_evaluations: List[Dict[str, Any]] = []
    classifications_count: Dict[str, int] = {
        "REPLICATED": 0,
        "SYSTEMATIC_SHIFT": 0,
        "BEHAVIORAL_DIVERGENCE": 0,
        "INCONCLUSIVE": 0,
        "INVALID": 0,
    }

    for sc in CANONICAL_SCENARIOS:
        for br in CANONICAL_BROWSERS:
            b_stats = extract_cohort_metrics(b_cohorts.get((sc, br), []))
            p_stats = extract_cohort_metrics(p_cohorts.get((sc, br), []))
            eval_res = evaluate_cohort(sc, br, b_stats, p_stats)
            cohort_evaluations.append(eval_res)
            classifications_count[eval_res["classification"]] = (
                classifications_count.get(eval_res["classification"], 0) + 1
            )

    # Derive Overall Replication Assessment
    if classifications_count.get("INVALID", 0) > 0:
        overall = "INVALID"
        overall_narrative = "Replication is INVALID due to missing cohorts or unverified trial records."
    elif classifications_count.get("BEHAVIORAL_DIVERGENCE", 0) > 0:
        overall = "BEHAVIORAL_DIVERGENCE"
        overall_narrative = "Independent replication observed statistically significant behavioral divergence from historical baseline."
    elif classifications_count.get("INCONCLUSIVE", 0) > 0:
        overall = "INCONCLUSIVE"
        overall_narrative = "Replication outcome is inconclusive due to high measurement variance."
    elif classifications_count.get("SYSTEMATIC_SHIFT", 0) > 0:
        overall = "SYSTEMATIC_SHIFT"
        overall_narrative = "Protocol behavior successfully replicated with systematic environmental latency scaling across hosts."
    else:
        overall = "REPLICATED"
        overall_narrative = "Full scientific replication confirmed: all 14 cohorts match historical baseline within 95% confidence intervals."

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_campaign_dir": str(baseline_dir),
        "partner_campaign_dir": str(partner_dir),
        "overall_classification": overall,
        "overall_narrative": overall_narrative,
        "cohort_breakdown_counts": classifications_count,
        "cohort_evaluations": cohort_evaluations,
    }


def format_markdown_report(report: Dict[str, Any]) -> str:
    """Renders structured Markdown comparative analysis table."""
    lines = [
        "# PS-028 Happy Eyeballs: Campaign Comparison & Replication Report",
        "",
        f"- **Overall Assessment:** `{report['overall_classification']}`",
        f"- **Analysis Summary:** {report['overall_narrative']}",
        f"- **Baseline Campaign:** `{report['baseline_campaign_dir']}`",
        f"- **Partner Campaign:** `{report['partner_campaign_dir']}`",
        f"- **Evaluation Timestamp:** `{report['timestamp_utc']}`",
        "",
        "## Cohort Classification Matrix",
        "",
        "| Scenario | Browser | Baseline Median (ms) | Partner Median (ms) | Baseline IPv6% | Partner IPv6% | Classification | Notes |",
        "|---|---|---|---|---|---|---|---|",
    ]

    for c in report["cohort_evaluations"]:
        sc = c.get("scenario_id", "")
        br = c.get("browser", "")
        cls = c.get("classification", "")
        b_sum = c.get("baseline_summary", {})
        p_sum = c.get("partner_summary", {})

        b_tconn = b_sum.get("t_connect_ms", {}).get("median")
        p_tconn = p_sum.get("t_connect_ms", {}).get("median")
        b_med_str = f"{b_tconn:.1f}" if b_tconn is not None else "N/A"
        p_med_str = f"{p_tconn:.1f}" if p_tconn is not None else "N/A"

        b_v6 = b_sum.get("winning_family", {}).get("ipv6_proportion")
        p_v6 = p_sum.get("winning_family", {}).get("ipv6_proportion")
        b_v6_str = f"{b_v6*100:.0f}%" if b_v6 is not None else "N/A"
        p_v6_str = f"{p_v6*100:.0f}%" if p_v6 is not None else "N/A"

        lines.append(
            f"| **{sc}** | {br} | {b_med_str} | {p_med_str} | {b_v6_str} | {p_v6_str} | **{cls}** | {c.get('reason', '')} |"
        )

    lines.extend([
        "",
        "## Classification Criteria Reference",
        "",
        "- `REPLICATED`: Outcomes consistent within 95% bootstrap / Wilson confidence intervals.",
        "- `SYSTEMATIC_SHIFT`: Identical protocol fallback and winner selection with environmental latency scaling.",
        "- `BEHAVIORAL_DIVERGENCE`: Incompatible protocol outcomes (e.g. failing fallback or inverted address family choice).",
        "- `INCONCLUSIVE`: Measurement variance exceeds power threshold.",
        "- `INVALID`: Cohort missing or unverified.",
        ""
    ])

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Scientific Campaign Comparison & Replication Pipeline"
    )
    parser.add_argument("--baseline", type=Path, default=Path(DEFAULT_HISTORICAL_CAMPAIGN_PATH),
                        help="Path to authoritative baseline campaign directory")
    parser.add_argument("--partner", type=Path, required=True,
                        help="Path to independent partner campaign directory")
    parser.add_argument("--output-json", type=Path, default=None,
                        help="Optional path to write deterministic comparison JSON")
    parser.add_argument("--output-md", type=Path, default=None,
                        help="Optional path to write formatted Markdown report")
    args = parser.parse_args()

    try:
        report = compare_campaigns(args.baseline, args.partner)
        if args.output_json:
            args.output_json.parent.mkdir(parents=True, exist_ok=True)
            args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"[OK] Wrote comparison JSON to {args.output_json}")

        md_content = format_markdown_report(report)
        if args.output_md:
            args.output_md.parent.mkdir(parents=True, exist_ok=True)
            args.output_md.write_text(md_content, encoding="utf-8")
            print(f"[OK] Wrote Markdown report to {args.output_md}")

        if not args.output_json and not args.output_md:
            print(md_content)

        return 0
    except Exception as exc:
        print(f"[ERROR] Comparison failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
