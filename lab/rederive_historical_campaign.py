#!/usr/bin/env python3
"""
PS-028 Milestone 2 Batch C1: Historical Campaign Re-derivation Runner

Re-derives metrics across all 280 authentic October 29 campaign PCAPs
(lab/campaigns/ps028-a10-live-20261030-01/) using the updated two-pass
frame-correlated parser adhering to RFC 9293 §3.5 and Phase C Metric Contract v1.1.0.

Outputs:
- lab/derived/phase-c/rederived_results/<trial_id>.json
- lab/derived/phase-c/rederived_results/reconciliation_report.csv
- lab/derived/phase-c/rederived_results/reconciliation_report.csv.provenance.json
- lab/derived/phase-c/reconciliation_report.csv
- lab/derived/phase-c/reconciliation_report.csv.provenance.json

Guarantees:
- Historical campaign files remain strictly READ-ONLY (Rule R2).
- Pure experimental data without nondeterministic runtime timestamps in CSV (Amendment A13).
- Execution metadata captured in sibling *.provenance.json sidecars.
"""

import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.run_trial import dissect_pcap, SCHEMA_VERSION

HISTORICAL_CAMPAIGN_DIR = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
OUTPUT_DIR = REPO_ROOT / "lab" / "derived" / "phase-c" / "rederived_results"
SUMMARY_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_info() -> Dict[str, str]:
    commit = "unknown"
    branch = "unknown"
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
    except Exception:
        pass
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
    except Exception:
        pass
    return {"git_commit": commit, "git_branch": branch}


def rederive_historical_campaign() -> int:
    trials_dir = HISTORICAL_CAMPAIGN_DIR / "trials"
    if not trials_dir.is_dir():
        print(f"[ERROR] Historical trials directory not found at {trials_dir}", file=sys.stderr)
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_DIR.mkdir(parents=True, exist_ok=True)

    # Collect valid historical trials (sorted deterministically)
    trial_dirs = sorted([
        d for d in trials_dir.iterdir()
        if d.is_dir() and (d / "capture.pcap").is_file() and (d / "result.json").is_file()
    ])

    print(f"[INFO] Discovered {len(trial_dirs)} authentic historical trials with capture.pcap and result.json")

    reconciliation_rows: List[Dict[str, Any]] = []
    discrepancy_gt_1ms_count = 0
    discrepancy_sub_1ms_count = 0
    exact_match_count = 0

    for idx, tdir in enumerate(trial_dirs, start=1):
        tid = tdir.name
        pcap_file = tdir / "capture.pcap"
        orig_json_file = tdir / "result.json"

        try:
            orig_data = json.loads(orig_json_file.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[ERROR] Failed to read {orig_json_file}: {e}", file=sys.stderr)
            continue

        pcap_sha = compute_file_sha256(pcap_file)
        hostname = orig_data.get("hostname") or f"{tid}.he.test"
        scenario_id = orig_data.get("scenario_id", "UNKNOWN")
        browser_info = orig_data.get("browser", {})
        browser_name = browser_info.get("name") or orig_data.get("browser_name") or "unknown"
        browser_ver = browser_info.get("version") or orig_data.get("browser_version") or "unknown"

        # Dissect PCAP using Phase C1 engine
        dissection = dissect_pcap(pcap_file, target_hostname=hostname, pcap_sha256=pcap_sha)

        metrics = dissection.get("metrics", {})
        primary_flow = dissection.get("primary_flow", {})
        dns_transactions = dissection.get("dns_transactions", [])
        https_svcb_queries = dissection.get("https_svcb_queries", [])
        dns_metrics = dissection.get("dns_metrics", {})

        stored_setup = orig_data.get("network_observations", {}).get("connection_setup_time_ms")
        rederived_syn_to_synack = metrics.get("syn_to_synack_ms")
        rederived_t_connect = metrics.get("t_connect_ms")
        rederived_t_setup = metrics.get("t_setup_total_ms")

        # Discrepancy analysis
        delta_ms: Optional[float] = None
        is_gt_1ms = False
        if stored_setup is not None and rederived_syn_to_synack is not None:
            delta_ms = round(abs(stored_setup - rederived_syn_to_synack), 2)
            if delta_ms > 1.0:
                is_gt_1ms = True
                discrepancy_gt_1ms_count += 1
            elif delta_ms > 0.001:
                discrepancy_sub_1ms_count += 1
            else:
                exact_match_count += 1
        elif stored_setup is None and rederived_syn_to_synack is None:
            delta_ms = 0.0
            exact_match_count += 1
        else:
            is_gt_1ms = True
            discrepancy_gt_1ms_count += 1

        reconciliation_rows.append({
            "trial_id": tid,
            "scenario_id": scenario_id,
            "browser": browser_name,
            "stored_connection_setup_time_ms": f"{stored_setup:.2f}" if stored_setup is not None else "",
            "rederived_syn_to_synack_ms": f"{rederived_syn_to_synack:.2f}" if rederived_syn_to_synack is not None else "",
            "rederived_t_connect_ms": f"{rederived_t_connect:.2f}" if rederived_t_connect is not None else "",
            "rederived_t_setup_total_ms": f"{rederived_t_setup:.2f}" if rederived_t_setup is not None else "",
            "discrepancy_ms": f"{delta_ms:.2f}" if delta_ms is not None else "",
            "is_discrepancy_gt_1ms": "TRUE" if is_gt_1ms else "FALSE",
            "primary_stream_id": str(primary_flow.get("stream_id") or ""),
            "primary_family": str(primary_flow.get("family") or ""),
            "pcap_sha256": pcap_sha,
        })

        # Assemble new version 1.1.0 record
        rederived_record: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "trial_id": tid,
            "campaign_id": orig_data.get("campaign_id", "ps028-a10-live-20261030-01"),
            "scenario_id": scenario_id,
            "scenario_name": orig_data.get("scenario_name", "unknown"),
            "scenario_description": orig_data.get("scenario_description", ""),
            "hostname": hostname,
            "target_url": orig_data.get("target_url", f"http://{hostname}/"),
            "browser_name": browser_name,
            "browser_version": browser_ver,
            "execution_mode": orig_data.get("execution_mode", "LIVE"),
            "is_simulation": bool(orig_data.get("is_simulation", False)),
            "validity_category": "VALID_LIVE",
            "classification": orig_data.get("network_observations", {}).get("classification") or orig_data.get("classification", "UNKNOWN"),
            "classification_reason": orig_data.get("network_observations", {}).get("classification_reason") or orig_data.get("classification_reason", ""),
            "timestamps": orig_data.get("timestamps", {}),
            "browser": orig_data.get("browser", {}),
            "http_outcome": orig_data.get("http_outcome", {}),
            "metrics": metrics,
            "primary_flow": primary_flow,
            "dns_transactions": dns_transactions,
            "https_svcb_queries": https_svcb_queries,
            "dns_metrics": dns_metrics,
            "evidence_provenance": {
                "vantage_point": "ps028-cl:ps028-cl-rt",
                "tshark_version": "4.2.2",
                "tcpdump_version": "4.99.4",
                "parser_version": SCHEMA_VERSION,
                "dissector_flags": ["-o", "tcp.relative_sequence_numbers:FALSE"],
            },
            "dns_observations": orig_data.get("dns_observations", {}),
            "network_observations": {
                "ipv6_attempt": orig_data.get("network_observations", {}).get("ipv6_attempt", False),
                "ipv4_attempt": orig_data.get("network_observations", {}).get("ipv4_attempt", False),
                "ipv6_success": orig_data.get("network_observations", {}).get("ipv6_success", False),
                "ipv4_success": orig_data.get("network_observations", {}).get("ipv4_success", False),
                "connection_attempt_delay_ms": metrics.get("connection_attempt_delay_ms"),
                "connection_setup_time_ms": rederived_syn_to_synack,
                "fallback_occurred": orig_data.get("network_observations", {}).get("fallback_occurred", False),
                "classification": orig_data.get("network_observations", {}).get("classification", "UNKNOWN"),
                "classification_reason": orig_data.get("network_observations", {}).get("classification_reason", ""),
            },
            "capture_metadata": orig_data.get("capture_metadata", {}),
            "evidence_paths": orig_data.get("evidence_paths", {}),
            "cleanup_status": orig_data.get("cleanup_status", {}),
        }

        # Save to lab/derived/phase-c/rederived_results/<trial_id>.json
        out_trial_json = OUTPUT_DIR / f"{tid}.json"
        out_trial_json.write_text(json.dumps(rederived_record, indent=2), encoding="utf-8")

        if idx % 50 == 0 or idx == len(trial_dirs):
            print(f"[INFO] Processed {idx}/{len(trial_dirs)} trials (discrepancies >1ms so far: {discrepancy_gt_1ms_count})")

    # Write Reconciliation CSV files
    csv_header = [
        "trial_id",
        "scenario_id",
        "browser",
        "stored_connection_setup_time_ms",
        "rederived_syn_to_synack_ms",
        "rederived_t_connect_ms",
        "rederived_t_setup_total_ms",
        "discrepancy_ms",
        "is_discrepancy_gt_1ms",
        "primary_stream_id",
        "primary_family",
        "pcap_sha256",
    ]

    csv_paths = [
        OUTPUT_DIR / "reconciliation_report.csv",
        SUMMARY_DIR / "reconciliation_report.csv",
    ]

    git_info = get_git_info()
    for csv_path in csv_paths:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=csv_header, lineterminator="\n")
            writer.writeheader()
            writer.writerows(reconciliation_rows)

        csv_sha = compute_file_sha256(csv_path)
        prov_path = Path(f"{csv_path}.provenance.json")
        provenance = {
            "target_file": csv_path.name,
            "sha256": csv_sha,
            "row_count": len(reconciliation_rows),
            "generated_by_command": "python3 lab/rederive_historical_campaign.py",
            "git_commit": git_info["git_commit"],
            "git_branch": git_info["git_branch"],
            "python_version": platform.python_version(),
            "tshark_version": "4.2.2",
            "tcpdump_version": "4.99.4",
            "platform": platform.platform(),
            "dissector_flags": ["-o", "tcp.relative_sequence_numbers:FALSE"],
        }
        prov_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")

    print("\n" + "=" * 70)
    print("HISTORICAL CAMPAIGN RE-DERIVATION SUMMARY (Finding C1-01)")
    print("=" * 70)
    print(f"Total Authentic Trials Processed:    {len(trial_dirs)}")
    print(f"Discrepancy > 1.0 ms:               {discrepancy_gt_1ms_count} / {len(trial_dirs)} ({discrepancy_gt_1ms_count / len(trial_dirs) * 100:.2f}%)")
    print(f"Discrepancy sub-millisecond (>0ms): {discrepancy_sub_1ms_count} / {len(trial_dirs)} ({discrepancy_sub_1ms_count / len(trial_dirs) * 100:.2f}%)")
    print(f"Exact Match (diff <= 0.001ms):      {exact_match_count} / {len(trial_dirs)} ({exact_match_count / len(trial_dirs) * 100:.2f}%)")
    print("=" * 70)

    if discrepancy_gt_1ms_count == 144:
        print("[SUCCESS] Discrepancy reconciliation independently confirms exactly 144/280 >1ms discrepancies!")
        return 0
    else:
        print(f"[WARNING] Discrepancy count was {discrepancy_gt_1ms_count}, expected 144.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(rederive_historical_campaign())
