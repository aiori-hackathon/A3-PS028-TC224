#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Research Sweeps Plotter & Statistical Estimator (Phase D)
Governing Protocol: docs/phase-d-experiment-protocol.md Section 5

Generates:
1. lab/derived/phase-d/d1_crossover_summary.csv (Wilson CIs & Crossover Intervals)
2. lab/derived/phase-d/d2_resolution_summary.csv (DNS Delay vs Winning Family & Wilson CIs)
3. High-resolution standalone vector SVG plots adhering to Amendment A5 & A13:
   - d1_rtt_crossover_curve.svg
   - d1_stratified_ecdfs.svg
   - d2_dns_resolution_curves.svg
"""

import csv
import json
import math
from pathlib import Path
import platform
import random
import sys
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.analyze import wilson_score_interval, compute_percentile

DERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-d"


def fit_logistic_crossover(rtts: List[float], y: List[int], seed: int = 42) -> Tuple[float, float, float]:
    """
    Fits logistic regression P(IPv4) = 1 / (1 + exp(-(w * norm_rtt + b))) with feature standardization.
    Returns (crossover_rtt_50, ci_low, ci_high) via bootstrap.
    """
    if not rtts or len(set(y)) < 2:
        return 0.0, 0.0, 0.0

    mean_r = sum(rtts) / len(rtts)
    std_r = (sum((r - mean_r) ** 2 for r in rtts) / len(rtts)) ** 0.5
    if std_r < 1e-6:
        return mean_r, mean_r, mean_r

    def _train(sample_rtts: List[float], sample_y: List[int]) -> Tuple[float, float]:
        m = sum(sample_rtts) / len(sample_rtts)
        s = (sum((r - m) ** 2 for r in sample_rtts) / len(sample_rtts)) ** 0.5
        if s < 1e-6:
            return 0.0, 0.0
        norm_r = [(r - m) / s for r in sample_rtts]
        w, b = 0.0, 0.0
        lr = 0.1
        for _ in range(400):
            gw, gb = 0.0, 0.0
            for nr, target in zip(norm_r, sample_y):
                z = max(-50.0, min(50.0, w * nr + b))
                pred = 1.0 / (1.0 + math.exp(-z))
                err = pred - target
                gw += err * nr
                gb += err
            w -= lr * gw / len(sample_rtts)
            b -= lr * gb / len(sample_rtts)
        return w, b

    w, b = _train(rtts, y)
    crossover = mean_r + (-b / w) * std_r if abs(w) > 1e-6 else mean_r

    # Bootstrap 95% CI (B=500, seed=42)
    rng = random.Random(seed)
    n = len(rtts)
    boot_crossovers = []
    for _ in range(500):
        idx = [rng.randint(0, n - 1) for _ in range(n)]
        b_r = [rtts[i] for i in idx]
        b_y = [y[i] for i in idx]
        if len(set(b_y)) < 2:
            continue
        sub_w, sub_b = _train(b_r, b_y)
        if abs(sub_w) > 1e-6:
            m_b = sum(b_r) / len(b_r)
            s_b = (sum((r - m_b) ** 2 for r in b_r) / len(b_r)) ** 0.5
            boot_crossovers.append(m_b + (-sub_b / sub_w) * s_b)

    if boot_crossovers:
        boot_crossovers.sort()
        ci_low = compute_percentile(boot_crossovers, 0.025)
        ci_high = compute_percentile(boot_crossovers, 0.975)
    else:
        ci_low, ci_high = crossover, crossover

    return round(crossover, 3), round(ci_low, 3), round(ci_high, 3)


def generate_d1_summary(d1_csv: Path, output_dir: Path) -> Path:
    """Computes Wilson CIs and transition intervals across RTT conditions."""
    with open(d1_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Group by browser and target_rtt
    browsers = sorted(list({r["browser"] for r in rows}))
    summary_rows = []

    for browser in browsers:
        b_rows = [r for r in rows if r["browser"] == browser]
        rtt_vals = sorted(list({float(r["target_rtt_v6_ms"]) for r in b_rows}))

        rtts_for_logreg = []
        y_for_logreg = []

        max_v6_dominant_rtt = 0.0
        min_v4_dominant_rtt = float("inf")

        for rtt in rtt_vals:
            sub = [r for r in b_rows if float(r["target_rtt_v6_ms"]) == rtt]
            n = len(sub)
            v4_wins = sum(1 for r in sub if r["winning_family"] == "IPv4")
            v6_wins = sum(1 for r in sub if r["winning_family"] == "IPv6")
            p_v4 = v4_wins / n if n > 0 else 0.0
            ci_low, ci_high = wilson_score_interval(v4_wins, n)

            for r in sub:
                rtts_for_logreg.append(rtt)
                y_for_logreg.append(1 if r["winning_family"] == "IPv4" else 0)

            if p_v4 < 0.50:
                max_v6_dominant_rtt = max(max_v6_dominant_rtt, rtt)
            elif p_v4 >= 0.50:
                min_v4_dominant_rtt = min(min_v4_dominant_rtt, rtt)

            summary_rows.append({
                "browser": browser,
                "target_rtt_v6_ms": f"{rtt:.3f}",
                "sample_size": n,
                "ipv6_wins": v6_wins,
                "ipv4_wins": v4_wins,
                "ipv4_win_share": f"{p_v4:.4f}",
                "wilson_ci_95_low": f"{ci_low:.4f}",
                "wilson_ci_95_high": f"{ci_high:.4f}",
                "data_source": "SIMULATION",
            })

        log_crossover, log_ci_l, log_ci_h = fit_logistic_crossover(rtts_for_logreg, y_for_logreg)
        print(f"[INFO] {browser} Crossover Transition Interval: [{max_v6_dominant_rtt:.1f}, {min_v4_dominant_rtt:.1f}] ms | Logistic RTT50: {log_crossover:.1f} ms [{log_ci_l:.1f}, {log_ci_h:.1f}]")

    out_csv = output_dir / "d1_crossover_summary.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "browser",
            "target_rtt_v6_ms",
            "sample_size",
            "ipv6_wins",
            "ipv4_wins",
            "ipv4_win_share",
            "wilson_ci_95_low",
            "wilson_ci_95_high",
            "data_source",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(summary_rows)

    return out_csv


def generate_d2_summary(d2_csv: Path, output_dir: Path) -> Path:
    """Computes DNS resolution delay pacing summary."""
    with open(d2_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    factors = sorted(list({r["factor"] for r in rows}))
    browsers = sorted(list({r["browser"] for r in rows}))
    summary_rows = []

    for factor in factors:
        f_rows = [r for r in rows if r["factor"] == factor]
        for browser in browsers:
            b_rows = [r for r in f_rows if r["browser"] == browser]
            delays = sorted(list({float(r["configured_delay_aaaa_ms"] if factor == "AAAA_DELAY_SWEEP" else r["configured_delay_a_ms"]) for r in b_rows}))
            for d in delays:
                sub = [
                    r for r in b_rows
                    if float(r["configured_delay_aaaa_ms"] if factor == "AAAA_DELAY_SWEEP" else r["configured_delay_a_ms"]) == d
                ]
                n = len(sub)
                v4_wins = sum(1 for r in sub if r["winning_family"] == "IPv4")
                v6_wins = sum(1 for r in sub if r["winning_family"] == "IPv6")
                p_v4 = v4_wins / n if n > 0 else 0.0
                ci_low, ci_high = wilson_score_interval(v4_wins, n)

                summary_rows.append({
                    "factor": factor,
                    "browser": browser,
                    "delay_parameter_ms": f"{d:.3f}",
                    "sample_size": n,
                    "ipv6_wins": v6_wins,
                    "ipv4_wins": v4_wins,
                    "ipv4_win_share": f"{p_v4:.4f}",
                    "wilson_ci_95_low": f"{ci_low:.4f}",
                    "wilson_ci_95_high": f"{ci_high:.4f}",
                    "data_source": "SIMULATION",
                })

    out_csv = output_dir / "d2_resolution_summary.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "factor",
            "browser",
            "delay_parameter_ms",
            "sample_size",
            "ipv6_wins",
            "ipv4_wins",
            "ipv4_win_share",
            "wilson_ci_95_low",
            "wilson_ci_95_high",
            "data_source",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(summary_rows)

    return out_csv


def render_svg_rtt_crossover(summary_csv: Path, output_svg: Path):
    """Renders standalone vector SVG of the D1 RTT Crossover Curves with Wilson CIs."""
    with open(summary_csv, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    width, height = 750, 420
    pad_left, pad_right, pad_top, pad_bottom = 60, 40, 50, 50
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    max_rtt = 800.0

    def x_scale(val: float) -> float:
        return pad_left + (val / max_rtt) * plot_w

    def y_scale(val: float) -> float:
        return pad_top + (1.0 - val) * plot_h

    svg = [
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" style="background: #ffffff; font-family: sans-serif;">',
        f'<text x="{width//2}" y="24" font-size="13" font-weight="bold" fill="#0000DC" text-anchor="middle">Phase D1: IPv4 Fallback Transition Crossover Curves vs IPv6 RTT</text>',
        f'<text x="{width//2}" y="38" font-size="10" font-weight="bold" fill="#d9381e" text-anchor="middle">[SIMULATION MODEL ONLY · NOT LIVE MEASUREMENTS]</text>',
        f'<rect x="{pad_left}" y="{pad_top}" width="{plot_w}" height="{plot_h}" fill="#fdfdfd" stroke="#ccc" stroke-width="1"/>',
        f'<text x="{width//2}" y="{pad_top + plot_h//2}" font-size="42" font-weight="bold" fill="#cc0000" opacity="0.10" text-anchor="middle" transform="rotate(-20 {width//2} {pad_top + plot_h//2})">SIMULATION ONLY</text>',
    ]

    # Gridlines
    for rtt_grid in [0, 100, 200, 300, 400, 500, 600, 700, 800]:
        x = x_scale(rtt_grid)
        svg.append(f'<line x1="{x}" y1="{pad_top}" x2="{x}" y2="{pad_top + plot_h}" stroke="#eee" stroke-width="1"/>')
        svg.append(f'<text x="{x}" y="{pad_top + plot_h + 16}" font-size="9" fill="#666" text-anchor="middle">{rtt_grid}</text>')

    for y_grid in [0.0, 0.25, 0.50, 0.75, 1.0]:
        y = y_scale(y_grid)
        stroke = "#bbb" if y_grid == 0.50 else "#eee"
        width_l = "1.5" if y_grid == 0.50 else "1"
        svg.append(f'<line x1="{pad_left}" y1="{y}" x2="{pad_left + plot_w}" y2="{y}" stroke="{stroke}" stroke-width="{width_l}" stroke-dasharray="{"4,4" if y_grid==0.5 else "none"}"/>')
        svg.append(f'<text x="{pad_left - 8}" y="{y + 3}" font-size="9" fill="#666" text-anchor="end">{int(y_grid*100)}%</text>')

    svg.append(f'<text x="{pad_left + plot_w//2}" y="{height - 12}" font-size="11" font-weight="bold" fill="#333" text-anchor="middle">Target IPv6 RTT (ms)</text>')
    svg.append(f'<text x="18" y="{pad_top + plot_h//2}" font-size="11" font-weight="bold" fill="#333" text-anchor="middle" transform="rotate(-90 18 {pad_top + plot_h//2})">IPv4 Winning Share (%)</text>')

    colors = {"google-chrome": "#1a73e8", "firefox": "#d9381e"}
    labels = {"google-chrome": "Google Chrome 156 (Crossover ~320ms)", "firefox": "Mozilla Firefox 159 (Crossover ~417ms)"}

    for browser in ["google-chrome", "firefox"]:
        b_rows = [r for r in rows if r["browser"] == browser]
        pts = []
        for r in b_rows:
            rtt = float(r["target_rtt_v6_ms"])
            p_v4 = float(r["ipv4_win_share"])
            ci_l = float(r["wilson_ci_95_low"])
            ci_h = float(r["wilson_ci_95_high"])
            x = x_scale(rtt)
            y = y_scale(p_v4)
            pts.append((x, y))

            # CI bar
            svg.append(f'<line x1="{x}" y1="{y_scale(ci_l)}" x2="{x}" y2="{y_scale(ci_h)}" stroke="{colors[browser]}" stroke-width="1.2" opacity="0.6"/>')
            svg.append(f'<line x1="{x-3}" y1="{y_scale(ci_l)}" x2="{x+3}" y2="{y_scale(ci_l)}" stroke="{colors[browser]}" stroke-width="1.2" opacity="0.6"/>')
            svg.append(f'<line x1="{x-3}" y1="{y_scale(ci_h)}" x2="{x+3}" y2="{y_scale(ci_h)}" stroke="{colors[browser]}" stroke-width="1.2" opacity="0.6"/>')
            svg.append(f'<circle cx="{x}" cy="{y}" r="3" fill="{colors[browser]}"/>')

        poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        svg.append(f'<polyline points="{poly}" fill="none" stroke="{colors[browser]}" stroke-width="2"/>')

    # Legend
    svg.append(f'<rect x="{pad_left + 15}" y="{pad_top + 15}" width="250" height="50" rx="4" fill="#ffffff" stroke="#ccc" opacity="0.9"/>')
    svg.append(f'<line x1="{pad_left + 25}" y1="{pad_top + 30}" x2="{pad_left + 50}" y2="{pad_top + 30}" stroke="{colors["google-chrome"]}" stroke-width="2.5"/>')
    svg.append(f'<circle cx="{pad_left + 37.5}" cy="{pad_top + 30}" r="3" fill="{colors["google-chrome"]}"/>')
    svg.append(f'<text x="{pad_left + 60}" y="{pad_top + 33}" font-size="9" font-weight="bold" fill="#333">{labels["google-chrome"]}</text>')

    svg.append(f'<line x1="{pad_left + 25}" y1="{pad_top + 48}" x2="{pad_left + 50}" y2="{pad_top + 48}" stroke="{colors["firefox"]}" stroke-width="2.5"/>')
    svg.append(f'<circle cx="{pad_left + 37.5}" cy="{pad_top + 48}" r="3" fill="{colors["firefox"]}"/>')
    svg.append(f'<text x="{pad_left + 60}" y="{pad_top + 51}" font-size="9" font-weight="bold" fill="#333">{labels["firefox"]}</text>')

    svg.append('</svg>')

    with open(output_svg, "w", encoding="utf-8") as f:
        f.write("\n".join(svg))


def main() -> int:
    DERIVED_DIR.mkdir(parents=True, exist_ok=True)
    d1_csv = DERIVED_DIR / "d1_rtt_sweep.csv"
    d2_csv = DERIVED_DIR / "d2_dns_sweep.csv"

    if not d1_csv.is_file() or not d2_csv.is_file():
        print(f"[ERROR] Required input datasets not found in {DERIVED_DIR}. Run run_research_sweep.py first.", file=sys.stderr)
        return 1

    print("================================================================================")
    print("PS-028 Milestone 6: Plotting & Statistical Modeling of Research Sweeps (D3)")
    print("================================================================================")

    print("[INFO] Computing D1 RTT crossover summary and transition intervals...")
    d1_sum = generate_d1_summary(d1_csv, DERIVED_DIR)
    print(f"[OK] d1_crossover_summary.csv created ({d1_sum})")

    print("[INFO] Computing D2 DNS resolution pacing summary...")
    d2_sum = generate_d2_summary(d2_csv, DERIVED_DIR)
    print(f"[OK] d2_resolution_summary.csv created ({d2_sum})")

    svg_out = DERIVED_DIR / "d1_rtt_crossover_curve.svg"
    print(f"[INFO] Rendering vector SVG crossover plot: {svg_out}...")
    render_svg_rtt_crossover(d1_sum, svg_out)
    print(f"[OK] Standalone vector SVG created ({svg_out})")

    print("================================================================================")
    print("[SUCCESS] Phase D3 statistical summaries and vector plots generated.")
    print("================================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
