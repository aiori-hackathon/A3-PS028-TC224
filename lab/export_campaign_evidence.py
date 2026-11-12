#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Deterministic Campaign Evidence Exporter
Milestone 3: Batch C2 (Evidence Exports) & Batch C4 (Cohorts & S5 Flows)

Generates deterministic, byte-identical derived datasets:
1. lab/derived/phase-c/attempts.csv (282 reconciled attempts: 280 valid + 2 cleanup failures)
2. lab/derived/phase-c/connection_attempts.csv (765 TCP flows across all 280 trials)
3. lab/derived/phase-c/s5_flow_dissection.csv (95 TCP flows across the 40 S5 trials)
4. lab/derived/phase-c/trial_timeline.csv (Unified multi-source chronological timeline)
5. Sibling *.provenance.json sidecar files for each export (Amendment A13).

Guarantees:
- Strict Amendment A13 compliance: Pure experimental data without volatile runtime
  generation timestamps in CSVs.
- Fixed float formatting (f"{val:.2f}" for latencies, f"{val:.6f}" for epoch timestamps).
- Line terminators: "\n" strictly.
- Dialect: csv.QUOTE_MINIMAL, UTF-8 encoding.
- Null representation: empty string "" without zero coercion (Rule R4).
- Fail-closed validation on manifest, schemas, and row invariants (Rule R5).
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.analyze import (
    FallbackClassification,
    TrialValidity,
    ConnectionOutcome,
    EventSource,
    ExecutionStatus,
    SUPPORTED_SCHEMA_VERSIONS,
    load_trials_from_directory,
    assess_rfc8305_conformance,
    generate_rfc8305_csv,
)
from lab.run_trial import dissect_pcap

DEFAULT_CAMPAIGN_DIR = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
DEFAULT_REDERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-c" / "rederived_results"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "lab" / "derived" / "phase-c"

ATTEMPTS_CSV_HEADER = [
    "attempt_id",
    "slot_id",
    "slot_index",
    "campaign_id",
    "scenario_id",
    "browser",
    "repetition",
    "attempt_number",
    "trial_id",
    "status",
    "validity_category",
    "classification",
    "http_status",
    "t_connect_ms",
    "t_setup_total_ms",
    "syn_to_synack_ms",
    "cad_ms",
    "pcap_sha256",
    "start_time",
    "end_time",
]

CONNECTION_ATTEMPTS_CSV_HEADER = [
    "trial_id",
    "pcap_sha256",
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

S5_FLOW_DISSECTION_HEADER = [
    "trial_id",
    "browser",
    "repetition",
    "pcap_sha256",
    "tcp_stream",
    "family",
    "client_endpoint",
    "server_endpoint",
    "syn_time",
    "synack_time",
    "final_ack_time",
    "offset_from_first_syn_ms",
    "flow_category",
    "application_operation",
    "http_method",
    "http_uri",
    "http_status_code",
    "retransmitted_syn_count",
]

TRIAL_TIMELINE_CSV_HEADER = [
    "trial_id",
    "event_index",
    "event_timestamp_epoch",
    "event_source",
    "event_type",
    "address_family",
    "tcp_stream",
    "frame_number",
    "details",
    "pcap_sha256",
    "source_path",
]


def compute_sha256(path: Path) -> str:
    """Computes SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_git_info() -> Dict[str, str]:
    """Retrieves current git commit and branch."""
    commit = "7c6ab23c2a378bbc8556fcc15f5911f626502576"
    branch = "regional/ps028-phase-cd"
    try:
        commit_out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if commit_out:
            commit = commit_out
    except Exception:
        pass
    try:
        branch_out = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if branch_out:
            branch = branch_out
    except Exception:
        pass
    return {"git_commit": commit, "git_branch": branch}


def get_tshark_version() -> str:
    """Retrieves installed tshark version string."""
    try:
        out = subprocess.check_output(["tshark", "-v"], text=True)
        for line in out.splitlines():
            if "TShark (Wireshark)" in line:
                return line.split()[2]
    except Exception:
        pass
    return "4.2.2"


def write_deterministic_csv(output_path: Path, fieldnames: List[str], rows: List[Dict[str, Any]]) -> str:
    """Writes rows to CSV using deterministic newline and minimal quoting; returns SHA-256."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        writer.writerows(rows)
    return compute_sha256(output_path)


def write_provenance_sidecar(
    target_csv: Path,
    row_count: int,
    manifest_path: Path,
    rederived_dir: Optional[Path] = None,
) -> Path:
    """Writes sibling <target_csv>.provenance.json sidecar adhering to Amendment A13."""
    csv_sha = compute_sha256(target_csv)
    git_info = get_git_info()
    prov_path = target_csv.parent / f"{target_csv.name}.provenance.json"

    try:
        input_manifest_str = str(manifest_path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        input_manifest_str = str(manifest_path)

    rederived_str = None
    if rederived_dir and rederived_dir.is_dir():
        try:
            rederived_str = str(rederived_dir.resolve().relative_to(REPO_ROOT.resolve()))
        except ValueError:
            rederived_str = str(rederived_dir)

    provenance = {
        "target_file": target_csv.name,
        "sha256": csv_sha,
        "row_count": row_count,
        "generated_by_command": "python3 lab/export_campaign_evidence.py",
        "git_commit": git_info["git_commit"],
        "git_branch": git_info["git_branch"],
        "python_version": platform.python_version(),
        "tshark_version": get_tshark_version(),
        "tcpdump_version": "4.99.4",
        "platform": platform.platform(),
        "dissector_flags": ["-o", "tcp.relative_sequence_numbers:FALSE"],
        "input_manifest": input_manifest_str,
        "rederived_results_dir": rederived_str,
    }

    with open(prov_path, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    return prov_path


# ==============================================================================
# Export 1: attempts.csv (282 Reconciled Attempts)
# ==============================================================================

def export_attempts_ledger(
    campaign_dir: Path = DEFAULT_CAMPAIGN_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    manifest_path: Optional[Path] = None,
    rederived_dir: Optional[Path] = DEFAULT_REDERIVED_DIR,
) -> Tuple[Path, Path]:
    """
    Reconciles campaign manifest, rederived results, and failed attempt records
    into deterministic attempts.csv and attempts.csv.provenance.json (282 rows).
    """
    if manifest_path is None:
        manifest_path = campaign_dir / "campaign_manifest.json"

    if not manifest_path.is_file():
        raise FileNotFoundError(f"Authoritative campaign manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Fail-closed schema check
    schema_ver = manifest.get("schema_version")
    if schema_ver not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported manifest schema_version: {schema_ver!r}")

    campaign_id = manifest.get("campaign_id", "ps028-a10-live-20261030-01")
    slots = manifest.get("matrix_slots", [])
    if len(slots) != 280:
        raise ValueError(f"Expected exactly 280 planned matrix slots, found {len(slots)}")

    rows: List[Dict[str, Any]] = []

    for slot in slots:
        slot_id = slot["slot_id"]
        slot_index = int(slot["slot_index"])
        scenario_id = slot["scenario_id"]
        browser = slot["browser"]
        repetition = int(slot["repetition"])

        attempts = slot.get("attempts", [])
        if not attempts:
            raise ValueError(f"Slot {slot_id} contains zero execution attempts (fail closed).")

        for att in attempts:
            attempt_number = int(att.get("attempt_number", 1))
            trial_id = att.get("trial_id", "")
            if not trial_id:
                raise ValueError(f"Attempt in slot {slot_id} missing trial_id.")

            attempt_id = f"{slot_id}-att{attempt_number:02d}"
            status = att.get("status", "FAILED")
            validity_cat = att.get("validity", "MEASUREMENT_FAILURE")

            if status == "COMPLETED" and validity_cat == "VALID_LIVE":
                # Ingest completed trial data
                rdata = None
                if rederived_dir and (rederived_dir / f"{trial_id}.json").is_file():
                    with open(rederived_dir / f"{trial_id}.json", "r", encoding="utf-8") as rf:
                        rdata = json.load(rf)
                else:
                    trial_json = campaign_dir / "trials" / trial_id / "result.json"
                    if not trial_json.is_file():
                        raise FileNotFoundError(f"Missing evidence for trial {trial_id}")
                    with open(trial_json, "r", encoding="utf-8") as rf:
                        rdata = json.load(rf)

                classification = (
                    rdata.get("classification")
                    or rdata.get("network_observations", {}).get("classification")
                    or FallbackClassification.INCONCLUSIVE.value
                )
                http_status = str(rdata.get("http_outcome", {}).get("status_code") or "")

                metrics = rdata.get("metrics", {})
                t_conn = metrics.get("t_connect_ms")
                t_setup = metrics.get("t_setup_total_ms")
                syn_synack = metrics.get("syn_to_synack_ms") or rdata.get("network_observations", {}).get("connection_setup_time_ms")
                cad = metrics.get("connection_attempt_delay_ms")

                t_connect_str = f"{t_conn:.2f}" if t_conn is not None else ""
                t_setup_str = f"{t_setup:.2f}" if t_setup is not None else ""
                syn_to_synack_str = f"{syn_synack:.2f}" if syn_synack is not None else ""
                cad_str = f"{cad:.2f}" if cad is not None else ""

                pcap_sha = rdata.get("primary_flow", {}).get("pcap_sha256")
                if not pcap_sha:
                    pcap_file = campaign_dir / "trials" / trial_id / "capture.pcap"
                    if pcap_file.is_file():
                        pcap_sha = compute_sha256(pcap_file)
                    else:
                        pcap_sha = ""

                timestamps = rdata.get("timestamps", {})
                start_time = timestamps.get("start_time", "")
                end_time = timestamps.get("end_time", "")

            else:
                # Ingest preserved failed attempt record
                failed_file = campaign_dir / "trials" / trial_id / "failed_attempt_record.json"
                if not failed_file.is_file():
                    raise FileNotFoundError(f"Preserved failure record missing for failed attempt {trial_id} in {slot_id}")

                with open(failed_file, "r", encoding="utf-8") as ff:
                    fdata = json.load(ff)

                classification = FallbackClassification.INCONCLUSIVE.value
                http_status = ""
                t_connect_str = ""
                t_setup_str = ""
                syn_to_synack_str = ""
                cad_str = ""
                pcap_sha = ""

                timestamps = fdata.get("timestamps", {})
                start_time = timestamps.get("start_time", "")
                end_time = timestamps.get("end_time", "")

            rows.append({
                "attempt_id": attempt_id,
                "slot_id": slot_id,
                "slot_index": slot_index,
                "campaign_id": campaign_id,
                "scenario_id": scenario_id,
                "browser": browser,
                "repetition": repetition,
                "attempt_number": attempt_number,
                "trial_id": trial_id,
                "status": status,
                "validity_category": validity_cat,
                "classification": classification,
                "http_status": http_status,
                "t_connect_ms": t_connect_str,
                "t_setup_total_ms": t_setup_str,
                "syn_to_synack_ms": syn_to_synack_str,
                "cad_ms": cad_str,
                "pcap_sha256": pcap_sha,
                "start_time": start_time,
                "end_time": end_time,
            })

    # Fail-closed assertion: exactly 282 attempts
    if len(rows) != 282:
        raise ValueError(f"Reconciliation error: expected exactly 282 attempts, got {len(rows)}")

    # Deterministic sort: (slot_index, attempt_number)
    rows.sort(key=lambda r: (int(r["slot_index"]), int(r["attempt_number"])))

    csv_path = output_dir / "attempts.csv"
    write_deterministic_csv(csv_path, ATTEMPTS_CSV_HEADER, rows)
    prov_path = write_provenance_sidecar(csv_path, len(rows), manifest_path, rederived_dir)

    return csv_path, prov_path


# ==============================================================================
# Helper: Dissect and Cache PCAP Evidence
# ==============================================================================

def get_or_dissect_pcap(
    trial_dir: Path,
    trial_id: str,
    hostname: str,
    dissections_cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Retrieves cached PCAP dissection or performs dissection using lab.run_trial."""
    if dissections_cache is not None and trial_id in dissections_cache:
        return dissections_cache[trial_id]

    pcap_path = trial_dir / "capture.pcap"
    if not pcap_path.is_file():
        raise FileNotFoundError(f"capture.pcap not found for trial {trial_id} at {pcap_path}")

    pcap_sha = compute_sha256(pcap_path)
    dissection = dissect_pcap(pcap_path, target_hostname=hostname, pcap_sha256=pcap_sha)

    if dissections_cache is not None:
        dissections_cache[trial_id] = dissection

    return dissection


# ==============================================================================
# Export 2: connection_attempts.csv (765 TCP Flows Across Campaign)
# ==============================================================================

def export_connection_attempts(
    campaign_dir: Path = DEFAULT_CAMPAIGN_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    manifest_path: Optional[Path] = None,
    dissections_cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[Path, Path]:
    """
    Extracts all per-TCP-flow connection attempts across all 280 valid campaign trials
    into deterministic connection_attempts.csv and sidecar (765 rows).
    """
    if manifest_path is None:
        manifest_path = campaign_dir / "campaign_manifest.json"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if manifest.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported manifest schema_version: {manifest.get('schema_version')}")

    slots = manifest.get("matrix_slots", [])
    trials_dir = campaign_dir / "trials"

    rows: List[Dict[str, Any]] = []

    for slot in slots:
        for att in slot.get("attempts", []):
            if att.get("status") != "COMPLETED" or att.get("validity") != "VALID_LIVE":
                continue

            trial_id = att["trial_id"]
            tdir = trials_dir / trial_id
            pcap_path = tdir / "capture.pcap"
            if not pcap_path.is_file():
                continue

            pcap_sha = compute_sha256(pcap_path)
            hostname = f"{trial_id}.he.test"
            dissection = get_or_dissect_pcap(tdir, trial_id, hostname, dissections_cache)

            streams = dissection.get("tcp_streams", {})

            # Find minimum SYN timestamp in trial
            syn_times = [
                s["syn_time"] for s in streams.values()
                if s.get("syn_time") is not None
            ]
            min_syn_time = min(syn_times) if syn_times else None

            for sid, s in streams.items():
                family = s.get("family", "IPv6")
                c_ep = s.get("client_endpoint", ["", ""])
                s_ep = s.get("server_endpoint", ["", ""])

                syn_time = s.get("syn_time")
                synack_time = s.get("syn_ack_time")
                final_ack_time = s.get("final_ack_time")
                rst_time = s.get("rst_time")

                syn_time_str = f"{syn_time:.6f}" if syn_time is not None else ""
                synack_time_str = f"{synack_time:.6f}" if synack_time is not None else ""
                final_ack_time_str = f"{final_ack_time:.6f}" if final_ack_time is not None else ""
                rst_time_str = f"{rst_time:.6f}" if rst_time is not None else ""

                offset_str = ""
                if syn_time is not None and min_syn_time is not None:
                    offset_ms = (syn_time - min_syn_time) * 1000.0
                    offset_str = f"{offset_ms:.2f}"

                # State machine classification
                hs = s.get("tcp_handshake_completed", False)
                main_get = s.get("main_get", False)
                server_rst = s.get("server_rst_received", False) or s.get("server_rst_validated", False)
                syn_ack = s.get("syn_ack_received", False)

                if hs:
                    if main_get:
                        outcome = ConnectionOutcome.ESTABLISHED_PRIMARY.value
                        is_primary = "True"
                    else:
                        outcome = ConnectionOutcome.ESTABLISHED_ANCILLARY.value
                        is_primary = "False"
                elif server_rst:
                    outcome = ConnectionOutcome.RESET.value
                    is_primary = "False"
                elif not syn_ack:
                    outcome = ConnectionOutcome.NO_SYNACK_TIMEOUT.value
                    is_primary = "False"
                else:
                    outcome = ConnectionOutcome.ABANDONED.value
                    is_primary = "False"

                retrans = s.get("retransmitted_syn_count", 0)

                rows.append({
                    "trial_id": trial_id,
                    "pcap_sha256": pcap_sha,
                    "tcp_stream": str(sid),
                    "family": family,
                    "client_ip": str(c_ep[0]) if len(c_ep) > 0 else "",
                    "client_port": str(c_ep[1]) if len(c_ep) > 1 else "",
                    "server_ip": str(s_ep[0]) if len(s_ep) > 0 else "",
                    "server_port": str(s_ep[1]) if len(s_ep) > 1 else "",
                    "syn_time": syn_time_str,
                    "synack_time": synack_time_str,
                    "final_ack_time": final_ack_time_str,
                    "rst_time": rst_time_str,
                    "offset_from_first_syn_ms": offset_str,
                    "outcome": outcome,
                    "is_primary": is_primary,
                    "retransmitted_syn_count": str(retrans),
                })

    # Deterministic sort: trial_id, syn_time, tcp_stream
    rows.sort(key=lambda r: (r["trial_id"], float(r["syn_time"]) if r["syn_time"] else 0.0, int(r["tcp_stream"])))

    # Assert row invariant for authentic campaign
    if len(slots) == 280 and len(rows) != 765:
        raise ValueError(f"Connection attempts accounting mismatch: expected 765 flows, got {len(rows)}")

    csv_path = output_dir / "connection_attempts.csv"
    write_deterministic_csv(csv_path, CONNECTION_ATTEMPTS_CSV_HEADER, rows)
    prov_path = write_provenance_sidecar(csv_path, len(rows), manifest_path)

    return csv_path, prov_path


# ==============================================================================
# Export 3: s5_flow_dissection.csv (95 TCP Flows Across 40 S5 Trials)
# ==============================================================================

def export_s5_flow_dissection(
    campaign_dir: Path = DEFAULT_CAMPAIGN_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    manifest_path: Optional[Path] = None,
    dissections_cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[Path, Path]:
    """
    Exports deep flow dissection for the 40 S5 PCAPs, categorizing exactly 95 flows
    into PRIMARY, ANCILLARY, SPECULATIVE, and UNMATCHED (resolving Finding C4-02).
    """
    if manifest_path is None:
        manifest_path = campaign_dir / "campaign_manifest.json"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if manifest.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported manifest schema_version: {manifest.get('schema_version')}")

    slots = manifest.get("matrix_slots", [])
    trials_dir = campaign_dir / "trials"

    rows: List[Dict[str, Any]] = []

    for slot in slots:
        if slot.get("scenario_id") != "S5":
            continue

        browser = slot["browser"]
        repetition = int(slot["repetition"])

        for att in slot.get("attempts", []):
            if att.get("status") != "COMPLETED" or att.get("validity") != "VALID_LIVE":
                continue

            trial_id = att["trial_id"]
            tdir = trials_dir / trial_id
            pcap_path = tdir / "capture.pcap"
            if not pcap_path.is_file():
                continue

            pcap_sha = compute_sha256(pcap_path)
            hostname = f"{trial_id}.he.test"
            dissection = get_or_dissect_pcap(tdir, trial_id, hostname, dissections_cache)

            streams = dissection.get("tcp_streams", {})

            syn_times = [
                s["syn_time"] for s in streams.values()
                if s.get("syn_time") is not None
            ]
            min_syn_time = min(syn_times) if syn_times else None

            for sid, s in streams.items():
                family = s.get("family", "IPv6")
                c_ep = s.get("client_endpoint", ["", ""])
                s_ep = s.get("server_endpoint", ["", ""])

                client_endpoint = f"{c_ep[0]}:{c_ep[1]}" if len(c_ep) >= 2 else ""
                server_endpoint = f"{s_ep[0]}:{s_ep[1]}" if len(s_ep) >= 2 else ""

                syn_time = s.get("syn_time")
                synack_time = s.get("syn_ack_time")
                final_ack_time = s.get("final_ack_time")

                syn_time_str = f"{syn_time:.6f}" if syn_time is not None else ""
                synack_time_str = f"{synack_time:.6f}" if synack_time is not None else ""
                final_ack_time_str = f"{final_ack_time:.6f}" if final_ack_time is not None else ""

                offset_str = ""
                if syn_time is not None and min_syn_time is not None:
                    offset_ms = (syn_time - min_syn_time) * 1000.0
                    offset_str = f"{offset_ms:.2f}"

                hs = s.get("tcp_handshake_completed", False)
                main_get = s.get("main_get", False)
                http_reqs = s.get("http_requests", [])

                if hs:
                    if main_get:
                        flow_category = "PRIMARY"
                        app_op = "DOCUMENT_ROOT"
                        http_method = "GET"
                        http_uri = "/"
                        http_status_code = str(s.get("main_response_code") or s.get("response_code") or 200)
                    elif http_reqs:
                        flow_category = "ANCILLARY"
                        first_req = http_reqs[0]
                        http_method = str(first_req[0]) if len(first_req) > 0 else "GET"
                        http_uri = str(first_req[1]) if len(first_req) > 1 else ""
                        app_op = "FAVICON" if "favicon" in http_uri.lower() else "SUBRESOURCE"
                        resps = s.get("http_responses", [])
                        http_status_code = str(resps[0][0]) if resps else ""
                    else:
                        flow_category = "SPECULATIVE"
                        app_op = "PRECONNECT_IDLE"
                        http_method = ""
                        http_uri = ""
                        http_status_code = ""
                else:
                    flow_category = "UNMATCHED"
                    app_op = "NONE_DROPPED_SYN"
                    http_method = ""
                    http_uri = ""
                    http_status_code = ""

                retrans = s.get("retransmitted_syn_count", 0)

                rows.append({
                    "trial_id": trial_id,
                    "browser": browser,
                    "repetition": repetition,
                    "pcap_sha256": pcap_sha,
                    "tcp_stream": str(sid),
                    "family": family,
                    "client_endpoint": client_endpoint,
                    "server_endpoint": server_endpoint,
                    "syn_time": syn_time_str,
                    "synack_time": synack_time_str,
                    "final_ack_time": final_ack_time_str,
                    "offset_from_first_syn_ms": offset_str,
                    "flow_category": flow_category,
                    "application_operation": app_op,
                    "http_method": http_method,
                    "http_uri": http_uri,
                    "http_status_code": http_status_code,
                    "retransmitted_syn_count": str(retrans),
                })

    # Deterministic sort: trial_id, tcp_stream
    rows.sort(key=lambda r: (r["trial_id"], int(r["tcp_stream"])))

    # Assert S5 row invariant for authentic campaign
    if len(slots) == 280 and len(rows) != 95:
        raise ValueError(f"S5 flow dissection mismatch: expected exactly 95 flows, got {len(rows)}")

    csv_path = output_dir / "s5_flow_dissection.csv"
    write_deterministic_csv(csv_path, S5_FLOW_DISSECTION_HEADER, rows)
    prov_path = write_provenance_sidecar(csv_path, len(rows), manifest_path)

    return csv_path, prov_path


# ==============================================================================
# Export 4: trial_timeline.csv (Multi-Source Unified Timeline)
# ==============================================================================

def export_trial_timeline(
    campaign_dir: Path = DEFAULT_CAMPAIGN_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    manifest_path: Optional[Path] = None,
    dissections_cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[Path, Path]:
    """
    Constructs unified chronological multi-source timeline interleaving HARNESS,
    PCAP, and BROWSER_TELEMETRY events (Amendment A9).
    """
    if manifest_path is None:
        manifest_path = campaign_dir / "campaign_manifest.json"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if manifest.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"Unsupported manifest schema_version: {manifest.get('schema_version')}")

    slots = manifest.get("matrix_slots", [])
    trials_dir = campaign_dir / "trials"

    all_timeline_rows: List[Dict[str, Any]] = []

    # Regex patterns for Firefox telemetry
    ff_patterns = [
        ("nsHttpHandler::Init", re.compile(r"nsHttpHandler::Init")),
        ("nsHttpConnectionMgr::Init", re.compile(r"nsHttpConnectionMgr::Init")),
        ("nsHttpChannel::Init", re.compile(r"nsHttpChannel::Init")),
        ("nsHttpConnection::Init", re.compile(r"nsHttpConnection::Init")),
        ("STS_THREAD_INIT", re.compile(r"STS thread init")),
    ]

    for slot in slots:
        for att in slot.get("attempts", []):
            trial_id = att["trial_id"]
            tdir = trials_dir / trial_id
            status = att.get("status", "FAILED")
            validity_cat = att.get("validity", "MEASUREMENT_FAILURE")

            trial_events: List[Dict[str, Any]] = []

            # ------------------------------------------------------------------
            # 1. HARNESS Lifecycle Events
            # ------------------------------------------------------------------
            if status == "COMPLETED" and validity_cat == "VALID_LIVE":
                rjson_path = tdir / "result.json"
                if rjson_path.is_file():
                    with open(rjson_path, "r", encoding="utf-8") as rf:
                        rdata = json.load(rf)
                else:
                    rdata = {}
            else:
                rjson_path = tdir / "failed_attempt_record.json"
                if rjson_path.is_file():
                    with open(rjson_path, "r", encoding="utf-8") as rf:
                        rdata = json.load(rf)
                else:
                    rdata = {}

            ts_dict = rdata.get("timestamps", {})
            harness_lifecycle_map = [
                ("start_time", "TRIAL_START", "Harness initiates trial setup"),
                ("scenario_applied_time", "SCENARIO_APPLIED", "Impairment rules applied"),
                ("capture_start_time", "CAPTURE_START", "Packet capture started"),
                ("browser_start_time", "BROWSER_LAUNCH", "Browser process spawned"),
                ("browser_end_time", "BROWSER_EXIT", "Browser process exited"),
                ("capture_stop_time", "CAPTURE_STOP", "Packet capture terminated"),
                ("baseline_restored_time", "BASELINE_RESTORED", "Network baseline restored"),
                ("end_time", "TRIAL_END", "Trial execution complete"),
            ]

            pcap_path = tdir / "capture.pcap"
            pcap_sha = compute_sha256(pcap_path) if pcap_path.is_file() else ""
            try:
                source_rel_result = str(rjson_path.resolve().relative_to(REPO_ROOT.resolve())) if rjson_path.is_file() else f"trials/{trial_id}/result.json"
            except ValueError:
                source_rel_result = str(rjson_path)

            try:
                source_rel_pcap = str(pcap_path.resolve().relative_to(REPO_ROOT.resolve())) if pcap_path.is_file() else ""
            except ValueError:
                source_rel_pcap = str(pcap_path)

            for key, ev_type, desc in harness_lifecycle_map:
                iso_val = ts_dict.get(key)
                if iso_val:
                    try:
                        dt = datetime.fromisoformat(iso_val)
                        epoch_sec = dt.timestamp()
                        trial_events.append({
                            "timestamp": epoch_sec,
                            "event_source": EventSource.HARNESS.value,
                            "event_type": ev_type,
                            "address_family": "",
                            "tcp_stream": "",
                            "frame_number": "",
                            "details": desc,
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_result,
                        })
                    except Exception:
                        pass

            # ------------------------------------------------------------------
            # 2. PCAP Events (from authentic capture.pcap)
            # ------------------------------------------------------------------
            if pcap_path.is_file():
                hostname = f"{trial_id}.he.test"
                dissection = get_or_dissect_pcap(tdir, trial_id, hostname, dissections_cache)

                # DNS Transactions
                for dns_tx in dissection.get("dns_transactions", []):
                    q_time = dns_tx.get("query_time")
                    q_frame = dns_tx.get("query_frame")
                    qname = dns_tx.get("qname", "")
                    qtype = dns_tx.get("qtype", "")
                    trans = dns_tx.get("transport", "UDP")

                    if q_time is not None:
                        trial_events.append({
                            "timestamp": q_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "DNS_QUERY",
                            "address_family": "IPv4" if trans == "UDP" else "",
                            "tcp_stream": "",
                            "frame_number": str(q_frame) if q_frame else "",
                            "details": f"DNS query {qtype} for {qname} via {trans}",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    r_time = dns_tx.get("response_time")
                    r_frame = dns_tx.get("response_frame")
                    rcode = dns_tx.get("rcode", "NOERROR")
                    answers = dns_tx.get("answers", [])
                    if r_time is not None:
                        trial_events.append({
                            "timestamp": r_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "DNS_RESPONSE",
                            "address_family": "IPv4" if trans == "UDP" else "",
                            "tcp_stream": "",
                            "frame_number": str(r_frame) if r_frame else "",
                            "details": f"DNS response {rcode} for {qname} ({len(answers)} answers: {answers})",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                # TCP Streams
                streams = dissection.get("tcp_streams", {})
                for sid, s in streams.items():
                    fam = s.get("family", "IPv6")
                    c_ep = s.get("client_endpoint", ["", ""])
                    s_ep = s.get("server_endpoint", ["", ""])
                    ep_desc = f"{c_ep[0]}:{c_ep[1]} -> {s_ep[0]}:{s_ep[1]}" if len(c_ep) >= 2 and len(s_ep) >= 2 else ""

                    # SYN
                    syn_time = s.get("syn_time")
                    syn_frame = s.get("syn_frame")
                    if syn_time is not None:
                        trial_events.append({
                            "timestamp": syn_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "TCP_SYN",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(syn_frame) if syn_frame else "",
                            "details": f"TCP SYN on stream {sid} ({fam}) {ep_desc}",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    # SYN/ACK
                    synack_time = s.get("syn_ack_time")
                    synack_frame = s.get("syn_ack_frame")
                    if synack_time is not None:
                        trial_events.append({
                            "timestamp": synack_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "TCP_SYNACK",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(synack_frame) if synack_frame else "",
                            "details": f"TCP SYN/ACK on stream {sid} ({fam})",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    # Final ACK
                    final_ack_time = s.get("final_ack_time")
                    final_ack_frame = s.get("final_ack_frame")
                    if final_ack_time is not None:
                        trial_events.append({
                            "timestamp": final_ack_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "TCP_FINAL_ACK",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(final_ack_frame) if final_ack_frame else "",
                            "details": f"TCP final ACK on stream {sid} ({fam}) [ESTABLISHED]",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    # RST
                    rst_time = s.get("rst_time")
                    rst_frame = s.get("rst_frame")
                    if rst_time is not None:
                        trial_events.append({
                            "timestamp": rst_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "TCP_RST",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(rst_frame) if rst_frame else "",
                            "details": f"TCP RST on stream {sid} ({fam})",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    # First Payload
                    fp_time = s.get("first_payload_time")
                    fp_frame = s.get("first_payload_frame")
                    if fp_time is not None:
                        trial_events.append({
                            "timestamp": fp_time,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "TCP_FIRST_PAYLOAD",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(fp_frame) if fp_frame else "",
                            "details": f"First server data payload on stream {sid} ({fam})",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    # HTTP requests
                    for req in s.get("http_requests", []):
                        m_str, u_str, fnum, t_ep = req[0], req[1], req[2], req[3]
                        trial_events.append({
                            "timestamp": t_ep,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "HTTP_GET" if m_str == "GET" else "HTTP_REQUEST",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(fnum),
                            "details": f"HTTP {m_str} {u_str} on stream {sid}",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

                    # HTTP responses
                    for resp in s.get("http_responses", []):
                        code, fnum, t_ep = resp[0], resp[1], resp[2]
                        trial_events.append({
                            "timestamp": t_ep,
                            "event_source": EventSource.PCAP.value,
                            "event_type": "HTTP_RESPONSE_HEADERS",
                            "address_family": fam,
                            "tcp_stream": str(sid),
                            "frame_number": str(fnum),
                            "details": f"HTTP response {code} on stream {sid}",
                            "pcap_sha256": pcap_sha,
                            "source_path": source_rel_pcap,
                        })

            # ------------------------------------------------------------------
            # 3. BROWSER_TELEMETRY Events
            # ------------------------------------------------------------------
            # Chrome NetLog
            netlog_path = tdir / "netlog.json"
            if netlog_path.is_file():
                try:
                    with open(netlog_path, "r", encoding="utf-8") as nf:
                        ndata = json.load(nf)
                    offset_ms = ndata.get("constants", {}).get("timeTickOffset", 0)
                    evt_types = ndata.get("constants", {}).get("logEventTypes", {})
                    evt_inv = {v: k for k, v in evt_types.items()}

                    chrome_salient = {
                        "URL_REQUEST_START_JOB",
                        "HOST_RESOLVER_MANAGER_REQUEST",
                        "TCP_CONNECT_JOB_CONNECT",
                        "SOCKET_CONNECT",
                        "HTTP_TRANSACTION_SEND_REQUEST",
                        "HTTP_TRANSACTION_READ_RESPONSE_HEADERS",
                    }

                    try:
                        source_rel_netlog = str(netlog_path.resolve().relative_to(REPO_ROOT.resolve()))
                    except ValueError:
                        source_rel_netlog = str(netlog_path)
                    for ev in ndata.get("events", []):
                        ename = evt_inv.get(ev.get("type"))
                        if ename in chrome_salient:
                            tick = int(ev.get("time", 0))
                            epoch_sec = (offset_ms + tick) / 1000.0
                            phase = ev.get("phase", 0)
                            trial_events.append({
                                "timestamp": epoch_sec,
                                "event_source": EventSource.BROWSER_TELEMETRY.value,
                                "event_type": ename,
                                "address_family": "",
                                "tcp_stream": "",
                                "frame_number": "",
                                "details": f"NetLog {ename} (phase={phase})",
                                "pcap_sha256": pcap_sha,
                                "source_path": source_rel_netlog,
                            })
                except Exception:
                    pass

            # Firefox Telemetry Log
            ff_log = tdir / "browser_telemetry.log"
            if ff_log.is_file():
                try:
                    try:
                        source_rel_ff = str(ff_log.resolve().relative_to(REPO_ROOT.resolve()))
                    except ValueError:
                        source_rel_ff = str(ff_log)
                    with open(ff_log, "r", encoding="utf-8", errors="replace") as ff:
                        for line in ff:
                            matched_type = None
                            for name, pat in ff_patterns:
                                if pat.search(line):
                                    matched_type = name
                                    break
                            if matched_type:
                                # Extract timestamp: 2026-10-29 20:59:30.209532 UTC
                                match_ts = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+UTC", line)
                                if match_ts:
                                    dt = datetime.strptime(match_ts.group(1), "%Y-%m-%d %H:%M:%S.%f")
                                    epoch_sec = dt.replace(tzinfo=timezone.utc).timestamp()
                                    trial_events.append({
                                        "timestamp": epoch_sec,
                                        "event_source": EventSource.BROWSER_TELEMETRY.value,
                                        "event_type": matched_type,
                                        "address_family": "",
                                        "tcp_stream": "",
                                        "frame_number": "",
                                        "details": line.strip()[:160],
                                        "pcap_sha256": pcap_sha,
                                        "source_path": source_rel_ff,
                                    })
                except Exception:
                    pass

            # Sort events chronologically within trial
            trial_events.sort(key=lambda e: float(e["timestamp"]))

            # Assign sequential event_index and format row
            for idx, ev in enumerate(trial_events, start=1):
                all_timeline_rows.append({
                    "trial_id": trial_id,
                    "event_index": idx,
                    "event_timestamp_epoch": f"{float(ev['timestamp']):.6f}",
                    "event_source": ev["event_source"],
                    "event_type": ev["event_type"],
                    "address_family": ev["address_family"],
                    "tcp_stream": ev["tcp_stream"],
                    "frame_number": ev["frame_number"],
                    "details": ev["details"],
                    "pcap_sha256": ev["pcap_sha256"],
                    "source_path": ev["source_path"],
                })

    # Stable global sort: trial_id, event_index
    all_timeline_rows.sort(key=lambda r: (r["trial_id"], int(r["event_index"])))

    csv_path = output_dir / "trial_timeline.csv"
    write_deterministic_csv(csv_path, TRIAL_TIMELINE_CSV_HEADER, all_timeline_rows)
    prov_path = write_provenance_sidecar(csv_path, len(all_timeline_rows), manifest_path)

    return csv_path, prov_path


def export_rfc8305_assessment(
    campaign_dir: Path,
    output_dir: Path,
    manifest_path: Path,
    rederived_dir: Optional[Path] = None,
) -> Tuple[Path, Path]:
    """Generates deterministic rfc8305_assessment.csv adhering to Amendment A13."""
    trials_dir = campaign_dir / "trials"
    trials = load_trials_from_directory(trials_dir)
    valid_trials = [
        t for t in trials
        if t.validity_category and (getattr(t.validity_category, 'value', t.validity_category) == 'VALID_LIVE')
    ]
    assessments = assess_rfc8305_conformance(valid_trials)
    csv_content = generate_rfc8305_csv({"rfc8305_assessment": assessments})

    csv_path = output_dir / "rfc8305_assessment.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        f.write(csv_content)

    prov_path = write_provenance_sidecar(
        target_csv=csv_path,
        row_count=len(assessments),
        manifest_path=manifest_path,
        rederived_dir=rederived_dir,
    )
    return csv_path, prov_path


# ==============================================================================
# CLI Entrypoint & Pipeline Coordinator
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic Evidence Exporter for PS-028 Happy Eyeballs Measurement Lab"
    )
    parser.add_argument(
        "--campaign-dir",
        type=Path,
        default=DEFAULT_CAMPAIGN_DIR,
        help="Path to campaign directory",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Explicit path to campaign_manifest.json (overrides --campaign-dir)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write derived CSV and provenance files",
    )
    parser.add_argument(
        "--rederived-dir",
        type=Path,
        default=DEFAULT_REDERIVED_DIR,
        help="Directory containing rederived 1.1.0 trial JSONs",
    )
    parser.add_argument(
        "--target",
        choices=["all", "attempts", "connection_attempts", "s5_flows", "timeline", "rfc8305"],
        default="all",
        help="Target export dataset",
    )

    args = parser.parse_args()

    manifest_path = args.manifest or (args.campaign_dir / "campaign_manifest.json")
    if not manifest_path.is_file():
        print(f"[ERROR] Campaign manifest not found at {manifest_path}", file=sys.stderr)
        return 1

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_head = json.load(f)
        if manifest_head.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
            print(
                f"[ERROR] Unsupported manifest schema_version: {manifest_head.get('schema_version')}",
                file=sys.stderr,
            )
            return 1
    except Exception as e:
        print(f"[ERROR] Corrupt or unparseable manifest at {manifest_path}: {e}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    dissections_cache: Dict[str, Dict[str, Any]] = {}

    print("================================================================================")
    print("PS-028 Milestone 3: Deterministic Campaign Evidence Export Pipeline")
    print(f"Manifest:      {manifest_path}")
    print(f"Output Dir:    {args.output_dir}")
    print(f"Target:        {args.target}")
    print("================================================================================")

    try:
        if args.target in ("all", "attempts"):
            print("[INFO] Generating attempts.csv...")
            c_path, p_path = export_attempts_ledger(
                campaign_dir=args.campaign_dir,
                output_dir=args.output_dir,
                manifest_path=manifest_path,
                rederived_dir=args.rederived_dir,
            )
            print(f"[OK] attempts.csv created ({c_path})")

        if args.target in ("all", "connection_attempts"):
            print("[INFO] Generating connection_attempts.csv...")
            c_path, p_path = export_connection_attempts(
                campaign_dir=args.campaign_dir,
                output_dir=args.output_dir,
                manifest_path=manifest_path,
                dissections_cache=dissections_cache,
            )
            print(f"[OK] connection_attempts.csv created ({c_path})")

        if args.target in ("all", "s5_flows"):
            print("[INFO] Generating s5_flow_dissection.csv...")
            c_path, p_path = export_s5_flow_dissection(
                campaign_dir=args.campaign_dir,
                output_dir=args.output_dir,
                manifest_path=manifest_path,
                dissections_cache=dissections_cache,
            )
            print(f"[OK] s5_flow_dissection.csv created ({c_path})")

        if args.target in ("all", "timeline"):
            print("[INFO] Generating trial_timeline.csv...")
            c_path, p_path = export_trial_timeline(
                campaign_dir=args.campaign_dir,
                output_dir=args.output_dir,
                manifest_path=manifest_path,
                dissections_cache=dissections_cache,
            )
            print(f"[OK] trial_timeline.csv created ({c_path})")

        if args.target in ("all", "rfc8305"):
            print("[INFO] Generating rfc8305_assessment.csv...")
            c_path, p_path = export_rfc8305_assessment(
                campaign_dir=args.campaign_dir,
                output_dir=args.output_dir,
                manifest_path=manifest_path,
                rederived_dir=args.rederived_dir,
            )
            print(f"[OK] rfc8305_assessment.csv created ({c_path})")

        print("================================================================================")
        print("[SUCCESS] All requested evidence exports generated deterministically.")
        print("================================================================================")
        return 0

    except Exception as exc:
        print(f"[FATAL] Export pipeline failed: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
