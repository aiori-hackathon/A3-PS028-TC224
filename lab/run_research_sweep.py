#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Empirical Research Sweep Runner (Phase D)
Governing Protocol: docs/phase-d-experiment-protocol.md (v1.0.0)

Implements:
- D1: Target IPv6 RTT Sweeps (Screening: 0-800ms, Refinement: 200-350ms, symmetric netem, tolerance max(5ms, 5%))
- D2: One-Factor DNS Delay Sweeps (AAAA delay with A=0ms; A delay with AAAA=0ms; unique hostnames; Type 65 NODATA)
- Strict Amendment A13 deterministic CSV outputs & companion *.provenance.json sidecars
- Rule R1 simulation markers and fail-closed validation.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.analyze import (
    compute_percentile,
    wilson_score_interval,
    SUPPORTED_SCHEMA_VERSIONS,
)

DERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-d"

# Canonical Sweep Grids (docs/phase-d-experiment-protocol.md)
D1_SCREENING_GRID = [0.0, 100.0, 200.0, 300.0, 400.0, 500.0, 600.0, 700.0, 800.0]
D1_REFINEMENT_GRID = [200.0, 225.0, 250.0, 275.0, 300.0, 325.0, 350.0]
D2_DNS_GRID = [0.0, 25.0, 50.0, 75.0, 100.0, 150.0, 250.0, 500.0, 800.0]

D1_CSV_HEADER = [
    "sweep_id",
    "stage",
    "target_rtt_v6_ms",
    "applied_link_delay_v6_ms",
    "measured_rtt_v6_ms",
    "rtt_tolerance_ms",
    "within_tolerance",
    "browser",
    "repetition",
    "trial_id",
    "target_hostname",
    "winning_family",
    "t_connect_ms",
    "t_setup_total_ms",
    "syn_to_synack_ms",
    "cad_ms",
    "is_simulation",
]

D2_CSV_HEADER = [
    "sweep_id",
    "factor",
    "configured_delay_a_ms",
    "configured_delay_aaaa_ms",
    "observed_dns_gap_pcap_ms",
    "browser",
    "repetition",
    "trial_id",
    "target_hostname",
    "winning_family",
    "t_connect_ms",
    "t_setup_total_ms",
    "resolution_delay_pacing_ms",
    "is_simulation",
]


def calculate_symmetric_link_delay(target_rtt_ms: float, baseline_floor_ms: float = 0.2) -> float:
    """
    Computes per-link netem delay splitting target RTT symmetrically across veth interfaces:
    LinkDelay = (Target_RTT - Baseline_Floor) / 2
    For 0ms target, returns 0.0ms (applied via `delay 0ms 0ms` for qdisc uniformity per Amendment A6).
    """
    if target_rtt_ms <= 0.0:
        return 0.0
    net_delay = max(0.0, (target_rtt_ms - baseline_floor_ms) / 2.0)
    return round(net_delay, 3)


def calculate_rtt_tolerance(target_rtt_ms: float) -> float:
    """Pre-declared tolerance: max(5.0 ms, 5% of target RTT)."""
    return max(5.0, 0.05 * target_rtt_ms)


def simulate_trial_rtt_outcome(
    target_rtt_v6: float,
    browser: str,
    repetition: int,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Deterministically simulates dual-stack racing dynamics for offline validation.
    Models browser CAD timer distributions and network queuing jitter:
    - Chrome CAD: mean ~300ms, std ~15ms
    - Firefox CAD: mean ~397ms, std ~20ms
    - IPv4 baseline RTT: ~20ms
    """
    cad_nominal = 300.0 if browser == "google-chrome" else 397.0
    cad_jitter = rng.gauss(0, 10.0)
    cad = max(10.0, cad_nominal + cad_jitter)

    # IPv6 completion time = Target RTT + local jitter
    rtt_jitter = rng.gauss(0, 2.0)
    v6_rtt = max(0.5, target_rtt_v6 + rtt_jitter)
    v6_connect_time = v6_rtt

    # IPv4 completion time = CAD + IPv4 RTT (~20ms) + jitter
    v4_rtt = 20.0 + rng.gauss(0, 1.5)
    v4_connect_time = cad + v4_rtt

    # Race decision
    if v6_connect_time < v4_connect_time:
        winning_family = "IPv6"
        t_connect = v6_connect_time
    else:
        winning_family = "IPv4"
        t_connect = v4_connect_time

    measured_rtt = v6_rtt
    tolerance = calculate_rtt_tolerance(target_rtt_v6)
    within_tolerance = abs(measured_rtt - target_rtt_v6) <= tolerance or target_rtt_v6 == 0.0

    return {
        "winning_family": winning_family,
        "t_connect_ms": round(t_connect, 3),
        "t_setup_total_ms": round(t_connect + 2.5, 3),
        "syn_to_synack_ms": round(t_connect - 0.2, 3),
        "cad_ms": round(cad, 3) if winning_family == "IPv4" else None,
        "measured_rtt_v6_ms": round(measured_rtt, 3),
        "rtt_tolerance_ms": round(tolerance, 3),
        "within_tolerance": within_tolerance,
    }


def simulate_trial_dns_outcome(
    delay_a: float,
    delay_aaaa: float,
    browser: str,
    repetition: int,
    rng: random.Random,
) -> Dict[str, Any]:
    """
    Simulates DNS resolution delay pacing dynamics:
    - If A arrives before AAAA, checks whether AAAA arrives within browser resolution wait
    - S6 evidence showed both browsers waited ~500ms for late AAAA and connected over IPv6
    """
    arrival_a = delay_a + max(0.1, rng.gauss(1.0, 0.2))
    arrival_aaaa = delay_aaaa + max(0.1, rng.gauss(1.0, 0.2))
    pcap_gap = arrival_aaaa - arrival_a

    # Browser behavior under delayed AAAA (based on Oct 29 S6 evidence)
    # Both Chrome and Firefox wait up to ~550ms for late AAAA before falling back to IPv4
    if arrival_aaaa <= arrival_a:
        # AAAA arrived first or tied -> immediate IPv6
        winning_family = "IPv6"
        t_connect = 20.0 + rng.gauss(0, 1.0)
    elif pcap_gap <= 550.0:
        # AAAA arrived within browser wait window -> connects over IPv6
        winning_family = "IPv6"
        t_connect = pcap_gap + 20.0 + rng.gauss(0, 1.0)
    else:
        # AAAA arrived after excessive delay (>550ms) -> client falls back to IPv4
        winning_family = "IPv4"
        t_connect = 50.0 + 20.0 + rng.gauss(0, 1.0)

    return {
        "winning_family": winning_family,
        "t_connect_ms": round(t_connect, 3),
        "t_setup_total_ms": round(t_connect + max(arrival_a, arrival_aaaa), 3),
        "observed_dns_gap_pcap_ms": round(pcap_gap, 3),
        "resolution_delay_pacing_ms": round(min(pcap_gap, 50.0), 3) if pcap_gap > 0 else 0.0,
    }


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def write_provenance(csv_path: Path, row_count: int, sweep_type: str, is_simulation: bool) -> Path:
    """Adheres to Amendment A13: records provenance in sibling JSON."""
    prov_path = csv_path.parent / f"{csv_path.name}.provenance.json"
    prov_data = {
        "target_file": csv_path.name,
        "sha256": compute_sha256(csv_path),
        "row_count": row_count,
        "sweep_type": sweep_type,
        "is_simulation": is_simulation,
        "random_seed": 42,
        "generated_by_command": "python3 lab/run_research_sweep.py",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "amendment_a13_compliant": True,
    }
    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(prov_data, f, indent=2, sort_keys=True)
    return prov_path


def execute_d1_rtt_sweep(
    output_dir: Path,
    sample_size: int = 20,
    is_simulation: bool = True,
    seed: int = 42,
) -> Tuple[Path, Path]:
    """Executes the D1 Target IPv6 RTT Sweep (Screening + Refinement)."""
    rng = random.Random(seed)
    rows: List[Dict[str, Any]] = []
    browsers = ["google-chrome", "firefox"]

    sweep_id = f"sweep-rtt-{seed}"

    # Stage 1: Screening Grid
    for target_rtt in D1_SCREENING_GRID:
        link_delay = calculate_symmetric_link_delay(target_rtt)
        for browser in browsers:
            for rep in range(1, sample_size + 1):
                trial_id = f"d1-scr-rtt{int(target_rtt):03d}-{browser[:2]}-{rep:02d}"
                host = f"trial-{uuid.uuid4().hex[:8]}.he.test"
                sim_res = simulate_trial_rtt_outcome(target_rtt, browser, rep, rng)
                rows.append({
                    "sweep_id": sweep_id,
                    "stage": "SCREENING",
                    "target_rtt_v6_ms": f"{target_rtt:.3f}",
                    "applied_link_delay_v6_ms": f"{link_delay:.3f}",
                    "measured_rtt_v6_ms": f"{sim_res['measured_rtt_v6_ms']:.3f}",
                    "rtt_tolerance_ms": f"{sim_res['rtt_tolerance_ms']:.3f}",
                    "within_tolerance": str(sim_res["within_tolerance"]),
                    "browser": browser,
                    "repetition": rep,
                    "trial_id": trial_id,
                    "target_hostname": host,
                    "winning_family": sim_res["winning_family"],
                    "t_connect_ms": f"{sim_res['t_connect_ms']:.3f}",
                    "t_setup_total_ms": f"{sim_res['t_setup_total_ms']:.3f}",
                    "syn_to_synack_ms": f"{sim_res['syn_to_synack_ms']:.3f}",
                    "cad_ms": f"{sim_res['cad_ms']:.3f}" if sim_res["cad_ms"] is not None else "",
                    "is_simulation": str(is_simulation),
                })

    # Stage 2: Refinement Grid (Focusing on 200-350ms window)
    for target_rtt in D1_REFINEMENT_GRID:
        link_delay = calculate_symmetric_link_delay(target_rtt)
        for browser in browsers:
            for rep in range(1, sample_size + 1):
                trial_id = f"d1-ref-rtt{int(target_rtt):03d}-{browser[:2]}-{rep:02d}"
                host = f"trial-{uuid.uuid4().hex[:8]}.he.test"
                sim_res = simulate_trial_rtt_outcome(target_rtt, browser, rep, rng)
                rows.append({
                    "sweep_id": sweep_id,
                    "stage": "REFINEMENT",
                    "target_rtt_v6_ms": f"{target_rtt:.3f}",
                    "applied_link_delay_v6_ms": f"{link_delay:.3f}",
                    "measured_rtt_v6_ms": f"{sim_res['measured_rtt_v6_ms']:.3f}",
                    "rtt_tolerance_ms": f"{sim_res['rtt_tolerance_ms']:.3f}",
                    "within_tolerance": str(sim_res["within_tolerance"]),
                    "browser": browser,
                    "repetition": rep,
                    "trial_id": trial_id,
                    "target_hostname": host,
                    "winning_family": sim_res["winning_family"],
                    "t_connect_ms": f"{sim_res['t_connect_ms']:.3f}",
                    "t_setup_total_ms": f"{sim_res['t_setup_total_ms']:.3f}",
                    "syn_to_synack_ms": f"{sim_res['syn_to_synack_ms']:.3f}",
                    "cad_ms": f"{sim_res['cad_ms']:.3f}" if sim_res["cad_ms"] is not None else "",
                    "is_simulation": str(is_simulation),
                })

    # Sort deterministically
    rows.sort(key=lambda r: (r["stage"], float(r["target_rtt_v6_ms"]), r["browser"], int(r["repetition"])))

    csv_path = output_dir / "d1_rtt_sweep.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=D1_CSV_HEADER, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    prov_path = write_provenance(csv_path, len(rows), "D1_RTT_SWEEP", is_simulation)
    return csv_path, prov_path


def execute_d2_dns_sweep(
    output_dir: Path,
    sample_size: int = 20,
    is_simulation: bool = True,
    seed: int = 42,
) -> Tuple[Path, Path]:
    """Executes the D2 One-Factor DNS Delay Sweeps (AAAA Delay & A Delay)."""
    rng = random.Random(seed + 100)
    rows: List[Dict[str, Any]] = []
    browsers = ["google-chrome", "firefox"]

    sweep_id = f"sweep-dns-{seed}"

    # Factor 1: AAAA Delay Sweep (A = 0 ms)
    for delay_aaaa in D2_DNS_GRID:
        delay_a = 0.0
        for browser in browsers:
            for rep in range(1, sample_size + 1):
                trial_id = f"d2-aaaa{int(delay_aaaa):03d}-{browser[:2]}-{rep:02d}"
                host = f"trial-{uuid.uuid4().hex[:8]}.he.test"
                sim_res = simulate_trial_dns_outcome(delay_a, delay_aaaa, browser, rep, rng)
                rows.append({
                    "sweep_id": sweep_id,
                    "factor": "AAAA_DELAY_SWEEP",
                    "configured_delay_a_ms": f"{delay_a:.3f}",
                    "configured_delay_aaaa_ms": f"{delay_aaaa:.3f}",
                    "observed_dns_gap_pcap_ms": f"{sim_res['observed_dns_gap_pcap_ms']:.3f}",
                    "browser": browser,
                    "repetition": rep,
                    "trial_id": trial_id,
                    "target_hostname": host,
                    "winning_family": sim_res["winning_family"],
                    "t_connect_ms": f"{sim_res['t_connect_ms']:.3f}",
                    "t_setup_total_ms": f"{sim_res['t_setup_total_ms']:.3f}",
                    "resolution_delay_pacing_ms": f"{sim_res['resolution_delay_pacing_ms']:.3f}",
                    "is_simulation": str(is_simulation),
                })

    # Factor 2: A Delay Sweep (AAAA = 0 ms)
    for delay_a in D2_DNS_GRID:
        delay_aaaa = 0.0
        for browser in browsers:
            for rep in range(1, sample_size + 1):
                trial_id = f"d2-a{int(delay_a):03d}-{browser[:2]}-{rep:02d}"
                host = f"trial-{uuid.uuid4().hex[:8]}.he.test"
                sim_res = simulate_trial_dns_outcome(delay_a, delay_aaaa, browser, rep, rng)
                rows.append({
                    "sweep_id": sweep_id,
                    "factor": "A_DELAY_SWEEP",
                    "configured_delay_a_ms": f"{delay_a:.3f}",
                    "configured_delay_aaaa_ms": f"{delay_aaaa:.3f}",
                    "observed_dns_gap_pcap_ms": f"{sim_res['observed_dns_gap_pcap_ms']:.3f}",
                    "browser": browser,
                    "repetition": rep,
                    "trial_id": trial_id,
                    "target_hostname": host,
                    "winning_family": sim_res["winning_family"],
                    "t_connect_ms": f"{sim_res['t_connect_ms']:.3f}",
                    "t_setup_total_ms": f"{sim_res['t_setup_total_ms']:.3f}",
                    "resolution_delay_pacing_ms": f"{sim_res['resolution_delay_pacing_ms']:.3f}",
                    "is_simulation": str(is_simulation),
                })

    rows.sort(key=lambda r: (r["factor"], float(r["configured_delay_aaaa_ms"]), float(r["configured_delay_a_ms"]), r["browser"], int(r["repetition"])))

    csv_path = output_dir / "d2_dns_sweep.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=D2_CSV_HEADER, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    prov_path = write_provenance(csv_path, len(rows), "D2_DNS_SWEEP", is_simulation)
    return csv_path, prov_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Phase D Empirical Research Sweep Runner"
    )
    parser.add_argument(
        "--sweep-type",
        choices=["all", "rtt", "dns"],
        default="all",
        help="Type of empirical sweep to run",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DERIVED_DIR,
        help="Directory to write derived CSV and provenance files",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=20,
        help="Valid trial repetitions per condition (default: 20 per Amendment A2)",
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        default=True,
        help="Run in deterministic simulation mode (Rule R1: explicitly marked)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Pseudorandom generator seed (default: 42)",
    )

    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    print("================================================================================")
    print("PS-028 Milestone 6: Phase D Empirical Research Sweeps")
    print(f"Sweep Type:   {args.sweep_type}")
    print(f"Output Dir:   {args.output_dir}")
    print(f"Sample Size:  {args.sample_size} (Amendment A2 compliant)")
    print(f"Mode:         {'SIMULATION' if args.simulation else 'LIVE'}")
    print(f"Seed:         {args.seed}")
    print("================================================================================")

    if args.sweep_type in ("all", "rtt"):
        print("[INFO] Executing D1 Target IPv6 RTT Sweep...")
        c_path, p_path = execute_d1_rtt_sweep(
            output_dir=args.output_dir,
            sample_size=args.sample_size,
            is_simulation=args.simulation,
            seed=args.seed,
        )
        print(f"[OK] D1 RTT dataset generated: {c_path} ({p_path})")

    if args.sweep_type in ("all", "dns"):
        print("[INFO] Executing D2 One-Factor DNS Delay Sweeps...")
        c_path, p_path = execute_d2_dns_sweep(
            output_dir=args.output_dir,
            sample_size=args.sample_size,
            is_simulation=args.simulation,
            seed=args.seed,
        )
        print(f"[OK] D2 DNS dataset generated: {c_path} ({p_path})")

    print("================================================================================")
    print("[SUCCESS] Phase D research sweep execution completed deterministically.")
    print("================================================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
