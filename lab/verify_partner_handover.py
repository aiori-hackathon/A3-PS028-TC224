#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Independent Partner Handover Evidence Verifier
Workstream C: Partner Replication Readiness

Validates partner replication campaign archives and directories against
PS-028 engineering and evidence rules:
1. Manifest Schema: Require supported manifest schema version ("1.0.0" or "1.1.0").
2. Live Authenticity: Require explicit is_simulation=false and execution_mode=LIVE.
3. Status: Require campaign status COMPLETED.
4. Matrix Rigor: 7 canonical scenarios (S0-S6), 2 pinned browsers (google-chrome, firefox),
   20 repetitions per pair = exactly 280 planned matrix slots.
5. Slots & Attempts: Validate actual matrix_slots and attempts schema produced by CampaignRunner.
6. Slot Validation: Count only attempts with status COMPLETED and validity VALID_LIVE.
7. Rejection Policy: Reject simulation, measurement failures, cleanup failures, duplicate
   trial IDs, missing attempts, and incomplete slots.
8. Historical Failure Preservation: Preserve failed-attempt history (e.g. retried slots);
   do not silently relabel failures.
9. Layout Validation: Validate result.json and capture.pcap under trials/<trial_id>/.
10. Trial Telemetry: Verify scenario, browser, trial ID, live execution mode, cleanup status,
    PCAP magic, packet count (> 0), and SHA-256 digests.
11. Portable Paths: Resolve paths portably relative to the campaign directory; never trust
    original host absolute paths from evidence_paths.
12. Archive Extraction Safety: Enforce path traversal prevention, reject absolute paths,
    reject unsafe symlinks/hardlinks, reject device nodes.
13. Provenance Sidecars: Require derived provenance sidecars to be VERIFIED and enforce clean
    source provenance (git_dirty=False, git_status=VERIFIED) and matching ledger hashes.
14. Derived Ledgers: Verify required derived ledgers (attempts.csv, connection_attempts.csv,
    trial_timeline.csv) and their relationship to the campaign.
15. Fail-Closed: Make missing archive checksums or missing explicitly requested derived
    directories fail closed.
16. Baseline Preservation: Strictly prevent modification or substitution of the historical baseline campaign.
"""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.run_trial as run_trial

SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0.0", "1.1.0"})
CANONICAL_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
CANONICAL_BROWSERS = ["google-chrome", "firefox"]
EXPECTED_REPETITIONS_PER_PAIR = 20
EXPECTED_TOTAL_SLOTS = 280
EXPECTED_VALID_TRIALS = 280
HISTORICAL_CAMPAIGN_ID = "ps028-a10-live-20261030-01"
REQUIRED_DERIVED_LEDGERS = ["attempts.csv", "connection_attempts.csv", "trial_timeline.csv"]

VALID_PCAP_MAGICS = [
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (identical endian)
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (swapped endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP swapped
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG
]


class VerificationError(Exception):
    """Raised when partner evidence violates validation rules."""
    pass


def sha256_file(path: Path) -> str:
    """Computes SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _parse_strict_int(
    val: Any,
    field_name: str,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None
) -> int:
    """
    Strictly validates that val is a non-empty, valid integer representation:
    - Rejects None, empty string, non-strings that are not int, floats, scientific notation,
      and strings with decimal points or trailing non-digit characters.
    - Validates bounds if min_val or max_val are specified.
    """
    if val is None or (isinstance(val, str) and not val.strip()):
        raise VerificationError(f"Field '{field_name}' is missing or empty")

    s_val = str(val).strip()
    if not re.fullmatch(r"[+-]?[0-9]+", s_val):
        raise VerificationError(f"Field '{field_name}' must be a valid integer, got '{val}'")

    try:
        int_val = int(s_val)
    except ValueError as exc:
        raise VerificationError(f"Field '{field_name}' failed integer conversion: {exc}") from exc

    if min_val is not None and int_val < min_val:
        raise VerificationError(f"Field '{field_name}' value {int_val} is below minimum {min_val}")
    if max_val is not None and int_val > max_val:
        raise VerificationError(f"Field '{field_name}' value {int_val} exceeds maximum {max_val}")

    return int_val


def _normalize_browser_name(raw: str) -> str:
    """Normalizes browser name to canonical 'google-chrome' or 'firefox'."""
    lower = raw.strip().lower()
    if "chrome" in lower:
        return "google-chrome"
    if "firefox" in lower:
        return "firefox"
    return raw.strip()


def _verify_pcap(pcap_path: Path, expected_sha: Optional[str] = None) -> Tuple[str, int]:
    """
    Rigorously validates PCAP header magic bytes, size, SHA-256 match,
    and audits packet record boundaries using run_trial.validate_pcap_file.
    Returns (sha256_hex, packet_count).
    """
    if not pcap_path.is_file():
        raise VerificationError(f"PCAP file does not exist: '{pcap_path}'")

    data = pcap_path.read_bytes()
    size = len(data)
    if size < 24:
        raise VerificationError(
            f"PCAP file '{pcap_path.name}' is too small ({size} bytes, expected >= 24 bytes header)"
        )

    magic = data[:4]
    if magic not in VALID_PCAP_MAGICS:
        raise VerificationError(f"Invalid PCAP header magic in '{pcap_path.name}': {magic.hex()}")

    calc_sha = hashlib.sha256(data).hexdigest()

    if expected_sha and calc_sha.lower() != expected_sha.lower():
        raise VerificationError(
            f"PCAP SHA-256 mismatch for '{pcap_path.name}': recorded {expected_sha}, computed {calc_sha}"
        )

    valid, _, _, pkt_count, msg = run_trial.validate_pcap_file(
        pcap_path, min_packets=1
    )
    if not valid:
        raise VerificationError(f"PCAP validation failed for '{pcap_path.name}': {msg}")

    if pkt_count < 1:
        raise VerificationError(
            f"PCAP file '{pcap_path.name}' contains 0 packets; live trials must record real network traffic"
        )

    return calc_sha, pkt_count


def _verify_trial_evidence(
    campaign_dir: Path,
    slot_id: str,
    scenario_id: str,
    browser: str,
    attempt: Dict[str, Any],
    is_valid_live: bool
) -> None:
    """
    Validates physical trial evidence under trials/<trial_id>/.
    Portably resolves paths strictly relative to campaign_dir / 'trials' / trial_id.
    Never follows or trusts absolute paths from original host evidence_paths.
    """
    trial_id = attempt.get("trial_id")
    if not trial_id:
        raise VerificationError(f"Slot '{slot_id}' attempt missing 'trial_id'")

    trial_dir = campaign_dir / "trials" / trial_id
    if not trial_dir.is_dir():
        raise VerificationError(
            f"Missing trial directory '{trial_dir}' for attempt '{trial_id}' in slot '{slot_id}'"
        )

    if is_valid_live:
        # 1. result.json
        result_json_path = trial_dir / "result.json"
        if not result_json_path.is_file():
            raise VerificationError(f"Missing result.json in '{trial_dir}' for trial '{trial_id}'")
        if result_json_path.stat().st_size == 0:
            raise VerificationError(f"Empty result.json in '{trial_dir}' for trial '{trial_id}'")

        try:
            rdata = json.loads(result_json_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise VerificationError(f"Malformed result.json for trial '{trial_id}': {exc}") from exc

        r_schema = rdata.get("schema_version")
        if r_schema not in SUPPORTED_SCHEMA_VERSIONS:
            raise VerificationError(
                f"Trial '{trial_id}' result.json schema_version '{r_schema}' not in supported versions {sorted(list(SUPPORTED_SCHEMA_VERSIONS))}"
            )

        if rdata.get("trial_id") != trial_id:
            raise VerificationError(
                f"Trial ID mismatch in result.json: expected '{trial_id}', got '{rdata.get('trial_id')}'"
            )

        if rdata.get("scenario_id") != scenario_id:
            raise VerificationError(
                f"Scenario mismatch in result.json for trial '{trial_id}': expected '{scenario_id}', got '{rdata.get('scenario_id')}'"
            )

        r_browser_field = rdata.get("browser")
        if isinstance(r_browser_field, dict):
            r_browser = r_browser_field.get("name", "")
        elif isinstance(r_browser_field, str):
            r_browser = r_browser_field
        else:
            r_browser = ""
        r_browser_norm = _normalize_browser_name(r_browser)
        if r_browser_norm != browser:
            raise VerificationError(
                f"Browser mismatch in result.json for trial '{trial_id}': expected '{browser}', got '{r_browser_norm}'"
            )

        if rdata.get("is_simulation") is not False:
            raise VerificationError(
                f"Trial '{trial_id}' result.json declares is_simulation={rdata.get('is_simulation')}. "
                "Simulated trials are strictly forbidden as authentic partner evidence."
            )

        if rdata.get("execution_mode") != "LIVE":
            raise VerificationError(
                f"Trial '{trial_id}' result.json declares execution_mode='{rdata.get('execution_mode')}', expected 'LIVE'"
            )

        cleanup = rdata.get("cleanup_status", {})
        if not cleanup.get("scenario_restored", False):
            raise VerificationError(f"Trial '{trial_id}' result.json cleanup_status: scenario was not restored")
        if not cleanup.get("baseline_verified", False):
            raise VerificationError(f"Trial '{trial_id}' result.json cleanup_status: baseline was not verified")
        if cleanup.get("errors"):
            raise VerificationError(
                f"Trial '{trial_id}' result.json cleanup_status recorded errors: {cleanup.get('errors')}"
            )

        # 2. capture.pcap
        pcap_path = trial_dir / "capture.pcap"
        recorded_sha_result = rdata.get("capture_metadata", {}).get("pcap_sha256")
        recorded_sha_manifest = attempt.get("capture_metadata", {}).get("pcap_sha256")
        exp_sha = recorded_sha_result or recorded_sha_manifest

        calc_sha, pkt_count = _verify_pcap(pcap_path, expected_sha=exp_sha)

        if recorded_sha_result and recorded_sha_result.lower() != calc_sha.lower():
            raise VerificationError(
                f"PCAP SHA-256 mismatch in result.json for trial '{trial_id}': recorded {recorded_sha_result}, computed {calc_sha}"
            )
        if recorded_sha_manifest and recorded_sha_manifest.lower() != calc_sha.lower():
            raise VerificationError(
                f"PCAP SHA-256 mismatch in manifest for trial '{trial_id}': recorded {recorded_sha_manifest}, computed {calc_sha}"
            )

    else:
        # Preserved failed attempt
        failed_rec = trial_dir / "failed_attempt_record.json"
        if not failed_rec.is_file():
            raise VerificationError(
                f"Preserved failure evidence missing: 'failed_attempt_record.json' not found in '{trial_dir}' for failed attempt '{trial_id}' in slot '{slot_id}'"
            )
        if failed_rec.stat().st_size == 0:
            raise VerificationError(
                f"Empty failed_attempt_record.json in '{trial_dir}' for failed attempt '{trial_id}'"
            )

        try:
            fdata = json.loads(failed_rec.read_text(encoding="utf-8"))
        except Exception as exc:
            raise VerificationError(f"Malformed failed_attempt_record.json for trial '{trial_id}': {exc}") from exc

        f_status = fdata.get("status", "")
        f_validity = fdata.get("validity", "")
        if f_status == "COMPLETED" and f_validity == "VALID_LIVE":
            raise VerificationError(
                f"Failed attempt record in '{trial_dir}' contradicts failure status: records COMPLETED/VALID_LIVE"
            )

        # Require failure record to agree with manifest attempt
        f_trial_id = fdata.get("trial_id")
        if f_trial_id != trial_id:
            raise VerificationError(
                f"Trial ID mismatch in failed_attempt_record.json for '{trial_id}': expected '{trial_id}', got '{f_trial_id}'"
            )

        exp_status = attempt.get("status", "")
        if f_status != exp_status:
            raise VerificationError(
                f"Status mismatch in failed_attempt_record.json for trial '{trial_id}': manifest has '{exp_status}', record has '{f_status}'"
            )

        f_validity = fdata.get("validity", "")
        exp_validity = attempt.get("validity", "")
        if f_validity != exp_validity:
            raise VerificationError(
                f"Validity mismatch in failed_attempt_record.json for trial '{trial_id}': manifest has '{exp_validity}', record has '{f_validity}'"
            )

        f_exec = fdata.get("execution_mode", "")
        exp_exec = attempt.get("execution_mode", "")
        if exp_exec and f_exec != exp_exec:
            raise VerificationError(
                f"Execution mode mismatch in failed_attempt_record.json for trial '{trial_id}': manifest has '{exp_exec}', record has '{f_exec}'"
            )

        if f_status == "COMPLETED" and f_validity == "VALID_LIVE":
            raise VerificationError(
                f"Failed attempt record in '{trial_dir}' contradicts failure status: records COMPLETED/VALID_LIVE"
            )

        # Do not accept an unrelated or falsely successful result.json as proof of a failed attempt
        res_json = trial_dir / "result.json"
        if res_json.is_file():
            try:
                rdata = json.loads(res_json.read_text(encoding="utf-8"))
            except Exception as exc:
                raise VerificationError(f"Malformed result.json in failed attempt directory '{trial_dir}': {exc}") from exc

            r_tid = rdata.get("trial_id")
            if r_tid and r_tid != trial_id:
                raise VerificationError(
                    f"Unrelated result.json found in failed attempt directory '{trial_dir}': expected trial_id '{trial_id}', got '{r_tid}'"
                )

            r_cleanup = rdata.get("cleanup_status", {})
            r_pcap = rdata.get("capture_metadata", {})
            r_net = rdata.get("network_observations", {})
            r_classification = r_net.get("classification", "")
            r_validity = rdata.get("validity") or ("VALID_LIVE" if rdata.get("status") == "COMPLETED" else None)

            is_falsely_successful = (
                r_cleanup.get("scenario_restored") is True
                and r_cleanup.get("baseline_verified") is True
                and not r_cleanup.get("errors")
                and r_pcap.get("pcap_valid") is True
                and r_pcap.get("packet_count", 0) > 0
                and r_classification not in ("", "INCONCLUSIVE")
                and r_validity == "VALID_LIVE"
            )
            if is_falsely_successful:
                raise VerificationError(
                    f"Falsely successful result.json found in failed attempt directory '{trial_dir}' for attempt '{trial_id}'"
                )


def _verify_derived_directory(
    derived_dir: Path,
    campaign_id: str,
    all_campaign_trial_ids: Set[str],
    total_attempts_count: int,
    valid_trial_ids: Set[str],
    expected_attempts: Optional[Dict[str, Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Rigorously audits derived ledgers and provenance sidecars.
    Fails closed if the directory does not exist, any ledger is missing or empty,
    any provenance sidecar is missing/unverified/dirty, or campaign relationship mismatches.
    """
    dpath = Path(derived_dir).resolve()
    if not dpath.is_dir():
        raise VerificationError(f"Derived directory does not exist or is not a directory: '{dpath}'")

    ledger_counts: Dict[str, int] = {}

    for ledger in REQUIRED_DERIVED_LEDGERS:
        lf = dpath / ledger
        if not lf.is_file():
            raise VerificationError(f"Missing required derived ledger '{ledger}' in '{dpath}'")
        if lf.stat().st_size == 0:
            raise VerificationError(f"Empty derived ledger '{ledger}' in '{dpath}'")

        # 1. Verify cryptographic provenance sidecar
        prov_file = dpath / f"{ledger}.provenance.json"
        if not prov_file.is_file():
            raise VerificationError(f"Missing cryptographic provenance sidecar '{prov_file.name}' in '{dpath}'")
        if prov_file.stat().st_size == 0:
            raise VerificationError(f"Empty provenance sidecar '{prov_file.name}' in '{dpath}'")

        try:
            prov_data = json.loads(prov_file.read_text(encoding="utf-8"))
        except Exception as exc:
            raise VerificationError(f"Malformed provenance sidecar '{prov_file.name}': {exc}") from exc

        exp_hash = prov_data.get("sha256")
        if not exp_hash:
            raise VerificationError(f"Provenance sidecar '{prov_file.name}' missing 'sha256' field")
        actual_hash = sha256_file(lf)
        if actual_hash.lower() != exp_hash.lower():
            raise VerificationError(
                f"Provenance SHA-256 digest mismatch for '{ledger}': sidecar={exp_hash}, calculated={actual_hash}"
            )

        prov_status = prov_data.get("provenance_status")
        if prov_status != "VERIFIED":
            raise VerificationError(
                f"Provenance status for '{ledger}' is '{prov_status}', expected 'VERIFIED'"
            )

        if prov_data.get("git_dirty") is not False:
            raise VerificationError(
                f"Provenance sidecar for '{ledger}' indicates dirty git tree (git_dirty={prov_data.get('git_dirty')}). "
                "Partner replication evidence must be generated against a clean, committed git tree."
            )

        if prov_data.get("git_status") != "VERIFIED":
            raise VerificationError(
                f"Provenance git_status for '{ledger}' is '{prov_data.get('git_status')}', expected 'VERIFIED'"
            )

        # 2. Ingest CSV and verify campaign relationships
        with open(lf, "r", encoding="utf-8", newline="") as csvf:
            reader = csv.DictReader(csvf)
            rows = list(reader)

        row_count = len(rows)
        ledger_counts[ledger] = row_count

        if ledger == "attempts.csv":
            if row_count != total_attempts_count:
                raise VerificationError(
                    f"attempts.csv row count mismatch: expected {total_attempts_count} reconciled attempts, got {row_count}"
                )
            seen_csv_trials = set()
            seen_attempt_ids = set()
            for idx, r in enumerate(rows, start=1):
                r_cid = r.get("campaign_id")
                if r_cid != campaign_id:
                    raise VerificationError(
                        f"attempts.csv row {idx} campaign_id '{r_cid}' does not match campaign '{campaign_id}'"
                    )
                r_tid = r.get("trial_id")
                if not r_tid:
                    raise VerificationError(f"attempts.csv row {idx} missing trial_id")
                if r_tid in seen_csv_trials:
                    raise VerificationError(
                        f"Duplicate trial_id '{r_tid}' in attempts.csv at row {idx}"
                    )
                seen_csv_trials.add(r_tid)

                r_att_id = r.get("attempt_id")
                if not r_att_id:
                    raise VerificationError(f"attempts.csv row {idx} missing attempt_id")
                if r_att_id in seen_attempt_ids:
                    raise VerificationError(
                        f"Duplicate attempt_id '{r_att_id}' in attempts.csv at row {idx}"
                    )
                seen_attempt_ids.add(r_att_id)

                if r_tid not in all_campaign_trial_ids:
                    raise VerificationError(
                        f"attempts.csv row {idx} references unknown trial_id '{r_tid}'"
                    )

                # Strict numeric field parsing
                r_slot_idx = _parse_strict_int(
                    r.get("slot_index"), f"attempts.csv row {idx} slot_index", min_val=1, max_val=EXPECTED_TOTAL_SLOTS
                )
                r_rep = _parse_strict_int(
                    r.get("repetition"), f"attempts.csv row {idx} repetition", min_val=1, max_val=EXPECTED_REPETITIONS_PER_PAIR
                )
                r_att_num = _parse_strict_int(
                    r.get("attempt_number"), f"attempts.csv row {idx} attempt_number", min_val=1
                )

                if expected_attempts and r_tid in expected_attempts:
                    exp = expected_attempts[r_tid]
                    if exp.get("slot_id") and r.get("slot_id") != exp["slot_id"]:
                        raise VerificationError(
                            f"attempts.csv row {idx} slot_id mismatch for trial '{r_tid}': expected '{exp['slot_id']}', got '{r.get('slot_id')}'"
                        )
                    if exp.get("scenario_id") and r.get("scenario_id") != exp["scenario_id"]:
                        raise VerificationError(
                            f"attempts.csv row {idx} scenario_id mismatch for trial '{r_tid}': expected '{exp['scenario_id']}', got '{r.get('scenario_id')}'"
                        )
                    if exp.get("browser") and _normalize_browser_name(r.get("browser", "")) != exp["browser"]:
                        raise VerificationError(
                            f"attempts.csv row {idx} browser mismatch for trial '{r_tid}': expected '{exp['browser']}', got '{r.get('browser')}'"
                        )
                    if exp.get("status") and r.get("status") != exp["status"]:
                        raise VerificationError(
                            f"attempts.csv row {idx} status mismatch for trial '{r_tid}': expected '{exp['status']}', got '{r.get('status')}'"
                        )
                    if exp.get("validity") and r.get("validity_category") != exp["validity"]:
                        raise VerificationError(
                            f"attempts.csv row {idx} validity mismatch for trial '{r_tid}': expected '{exp['validity']}', got '{r.get('validity_category')}'"
                        )
                    if exp.get("repetition") is not None:
                        exp_rep = _parse_strict_int(exp["repetition"], f"expected repetition for trial {r_tid}")
                        if r_rep != exp_rep:
                            raise VerificationError(
                                f"attempts.csv row {idx} repetition mismatch for trial '{r_tid}': expected {exp_rep}, got {r_rep}"
                            )
                    if exp.get("attempt_number") is not None:
                        exp_att_num = _parse_strict_int(exp["attempt_number"], f"expected attempt_number for trial {r_tid}")
                        if r_att_num != exp_att_num:
                            raise VerificationError(
                                f"attempts.csv row {idx} attempt_number mismatch for trial '{r_tid}': expected {exp_att_num}, got {r_att_num}"
                            )

            if expected_attempts:
                missing_trials = set(expected_attempts.keys()) - seen_csv_trials
                if missing_trials:
                    raise VerificationError(
                        f"attempts.csv is missing {len(missing_trials)} campaign attempts: {sorted(list(missing_trials))[:3]}"
                    )
                extra_trials = seen_csv_trials - set(expected_attempts.keys())
                if extra_trials:
                    raise VerificationError(
                        f"attempts.csv contains {len(extra_trials)} unexpected extra attempts: {sorted(list(extra_trials))[:3]}"
                    )

        elif ledger == "connection_attempts.csv":
            if row_count == 0:
                raise VerificationError(f"Derived ledger '{ledger}' contains 0 data rows")
            seen_conn_trials = set()
            for idx, r in enumerate(rows, start=1):
                r_tid = r.get("trial_id")
                if not r_tid:
                    raise VerificationError(f"{ledger} row {idx} missing trial_id")
                if r_tid not in all_campaign_trial_ids:
                    raise VerificationError(
                        f"{ledger} row {idx} references unknown trial_id '{r_tid}'"
                    )
                seen_conn_trials.add(r_tid)

                _parse_strict_int(r.get("tcp_stream"), f"{ledger} row {idx} tcp_stream", min_val=0)
                if r.get("client_port") and str(r.get("client_port")).strip():
                    _parse_strict_int(r.get("client_port"), f"{ledger} row {idx} client_port", min_val=1, max_val=65535)
                if r.get("server_port") and str(r.get("server_port")).strip():
                    _parse_strict_int(r.get("server_port"), f"{ledger} row {idx} server_port", min_val=1, max_val=65535)
                if r.get("retransmitted_syn_count") and str(r.get("retransmitted_syn_count")).strip():
                    _parse_strict_int(r.get("retransmitted_syn_count"), f"{ledger} row {idx} retransmitted_syn_count", min_val=0)

            # Every valid live trial must have representation in connection_attempts.csv
            missing_valid = valid_trial_ids - seen_conn_trials
            if missing_valid:
                raise VerificationError(
                    f"connection_attempts.csv is missing connection data for {len(missing_valid)} valid live trials: {sorted(list(missing_valid))[:3]}"
                )

        elif ledger == "trial_timeline.csv":
            if row_count == 0:
                raise VerificationError(f"Derived ledger '{ledger}' contains 0 data rows")
            seen_timeline_trials = set()
            for idx, r in enumerate(rows, start=1):
                r_tid = r.get("trial_id")
                if not r_tid:
                    raise VerificationError(f"{ledger} row {idx} missing trial_id")
                if r_tid not in all_campaign_trial_ids:
                    raise VerificationError(
                        f"{ledger} row {idx} references unknown trial_id '{r_tid}'"
                    )
                seen_timeline_trials.add(r_tid)

                _parse_strict_int(r.get("event_index"), f"{ledger} row {idx} event_index", min_val=1)
                ts_raw = r.get("event_timestamp_epoch")
                if ts_raw is None or not str(ts_raw).strip():
                    raise VerificationError(f"{ledger} row {idx} missing event_timestamp_epoch")
                try:
                    float(str(ts_raw).strip())
                except ValueError:
                    raise VerificationError(f"{ledger} row {idx} invalid event_timestamp_epoch '{ts_raw}'")

                if r.get("tcp_stream") and str(r.get("tcp_stream")).strip():
                    _parse_strict_int(r.get("tcp_stream"), f"{ledger} row {idx} tcp_stream", min_val=0)
                if r.get("frame_number") and str(r.get("frame_number")).strip():
                    _parse_strict_int(r.get("frame_number"), f"{ledger} row {idx} frame_number", min_val=1)

            # Every trial (valid live trials and preserved failed attempts) must have timeline events
            missing_campaign_trials = all_campaign_trial_ids - seen_timeline_trials
            if missing_campaign_trials:
                raise VerificationError(
                    f"trial_timeline.csv is missing events for {len(missing_campaign_trials)} campaign trials: {sorted(list(missing_campaign_trials))[:3]}"
                )

    return {
        "path": str(dpath),
        "ledgers_verified": REQUIRED_DERIVED_LEDGERS,
        "row_counts": ledger_counts,
    }


def verify_partner_campaign_directory(
    campaign_dir: Path,
    derived_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Rigorously audits an extracted partner campaign directory and optional derived export directory.
    Consumes the actual CampaignRunner schema and physical evidence layout:
    - campaign_manifest.json with matrix_slots and ExecutionAttempt structures.
    - Physical layout: trials/<trial_id>/result.json and trials/<trial_id>/capture.pcap.
    - Preserved failure history under trials/<failed_trial_id>/.
    Returns audit details dict or raises VerificationError on violation.
    """
    campaign_dir = Path(campaign_dir).resolve()
    if not campaign_dir.is_dir():
        raise VerificationError(f"Campaign directory does not exist or is not a directory: {campaign_dir}")

    # Baseline preservation: Historical baseline campaign must never be substituted as partner evidence
    if campaign_dir.name == HISTORICAL_CAMPAIGN_ID:
        raise VerificationError(
            f"Campaign directory name matches protected historical campaign '{HISTORICAL_CAMPAIGN_ID}'. "
            "Partner replication requires an independently generated campaign on a second host."
        )

    cid_file = campaign_dir / "campaign_id.txt"
    if cid_file.is_file():
        try:
            cid = cid_file.read_text(encoding="utf-8").strip()
            if cid == HISTORICAL_CAMPAIGN_ID:
                raise VerificationError(
                    f"Partner evidence points to historical baseline campaign '{HISTORICAL_CAMPAIGN_ID}'. "
                    "Partner replication requires an independently generated campaign on a second host."
                )
        except OSError:
            pass

    manifest_file = campaign_dir / "campaign_manifest.json"
    if not manifest_file.is_file():
        raise VerificationError(f"Missing mandatory campaign_manifest.json in '{campaign_dir}'")

    try:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VerificationError(f"Failed to parse campaign_manifest.json: {exc}") from exc

    # Mandatory 1: Supported manifest schema version
    schema_ver = manifest_data.get("schema_version")
    if schema_ver not in SUPPORTED_SCHEMA_VERSIONS:
        raise VerificationError(
            f"Unsupported manifest schema_version '{schema_ver}'. "
            f"Supported versions: {sorted(list(SUPPORTED_SCHEMA_VERSIONS))}"
        )

    # Mandatory 2: Explicit is_simulation=false and execution_mode=LIVE
    is_simulation = manifest_data.get("is_simulation")
    if is_simulation is not False:
        raise VerificationError(
            f"Campaign manifest declares is_simulation={is_simulation}. "
            "Simulated or dry-run executions are strictly forbidden as authentic partner evidence."
        )

    exec_mode = manifest_data.get("execution_mode")
    if exec_mode != "LIVE":
        raise VerificationError(
            f"Campaign manifest declares execution_mode='{exec_mode}', expected 'LIVE'"
        )

    # Mandatory 3: Campaign status COMPLETED
    camp_status = manifest_data.get("status")
    if camp_status != "COMPLETED":
        raise VerificationError(
            f"Campaign status is '{camp_status}', expected 'COMPLETED'. "
            "Interrupted, in-progress, or failed campaigns cannot be verified."
        )

    campaign_id = manifest_data.get("campaign_id", "")
    if not campaign_id:
        raise VerificationError("Campaign manifest missing 'campaign_id'")
    if campaign_id == HISTORICAL_CAMPAIGN_ID:
        raise VerificationError(
            f"Campaign ID matches protected historical campaign '{HISTORICAL_CAMPAIGN_ID}'"
        )

    # Mandatory 4 & 5: Validate actual matrix_slots and their attempts
    matrix_slots = manifest_data.get("matrix_slots")
    if not isinstance(matrix_slots, list):
        raise VerificationError("Campaign manifest missing 'matrix_slots' list")

    if len(matrix_slots) != EXPECTED_TOTAL_SLOTS:
        raise VerificationError(
            f"Total matrix slot count mismatch: expected exactly {EXPECTED_TOTAL_SLOTS} slots, got {len(matrix_slots)}"
        )

    scenarios_present: Set[str] = set()
    browsers_present: Set[str] = set()
    slot_rep_tracker: Dict[Tuple[str, str], Set[int]] = {
        (sc, br): set() for sc in CANONICAL_SCENARIOS for br in CANONICAL_BROWSERS
    }

    seen_slot_ids: Set[str] = set()
    seen_all_trial_ids: Set[str] = set()
    valid_trial_ids: Set[str] = set()
    total_attempts_count = 0
    failed_attempts_count = 0

    trials_root = campaign_dir / "trials"
    if not trials_root.is_dir():
        raise VerificationError(f"Missing 'trials/' directory in campaign root: '{trials_root}'")

    expected_attempts: Dict[str, Dict[str, Any]] = {}

    for slot in matrix_slots:
        sid = slot.get("slot_id")
        if not sid:
            raise VerificationError("Found matrix slot missing 'slot_id'")
        if sid in seen_slot_ids:
            raise VerificationError(f"Duplicate slot_id observed in manifest: '{sid}'")
        seen_slot_ids.add(sid)

        sc = slot.get("scenario_id")
        br = slot.get("browser")
        rep = slot.get("repetition")
        slot_status = slot.get("status")

        if sc not in CANONICAL_SCENARIOS:
            raise VerificationError(f"Slot '{sid}' contains non-canonical scenario '{sc}'. Expected S0-S6.")

        br_norm = _normalize_browser_name(str(br))
        if br_norm not in CANONICAL_BROWSERS:
            raise VerificationError(
                f"Slot '{sid}' contains non-canonical browser '{br_norm}'. Expected google-chrome or firefox."
            )

        if not isinstance(rep, int) or rep < 1 or rep > EXPECTED_REPETITIONS_PER_PAIR:
            raise VerificationError(
                f"Slot '{sid}' invalid repetition {rep}. Expected integer 1..{EXPECTED_REPETITIONS_PER_PAIR}."
            )

        if rep in slot_rep_tracker[(sc, br_norm)]:
            raise VerificationError(f"Duplicate repetition {rep} observed for pair ({sc}, {br_norm}) in slot '{sid}'")
        slot_rep_tracker[(sc, br_norm)].add(rep)

        scenarios_present.add(sc)
        browsers_present.add(br_norm)

        # Mandatory 5 & 6: slot status must be COMPLETED
        if slot_status != "COMPLETED":
            raise VerificationError(f"Slot '{sid}' status is '{slot_status}', expected 'COMPLETED'")

        attempts = slot.get("attempts", [])
        if not isinstance(attempts, list) or len(attempts) == 0:
            raise VerificationError(f"Slot '{sid}' contains no execution attempts")

        current_tid = slot.get("current_trial_id")
        if not current_tid:
            raise VerificationError(f"Slot '{sid}' missing 'current_trial_id'")

        # Evaluate attempts in this slot
        valid_attempts_in_slot: List[Dict[str, Any]] = []

        for att in attempts:
            total_attempts_count += 1
            tid = att.get("trial_id")
            if not tid:
                raise VerificationError(f"Slot '{sid}' contains attempt missing 'trial_id'")

            # Mandatory 7: Reject duplicate trial IDs across all slots/attempts
            if tid in seen_all_trial_ids:
                raise VerificationError(f"Duplicate trial_id observed across attempts: '{tid}'")
            seen_all_trial_ids.add(tid)

            att_status = att.get("status")
            att_validity = att.get("validity")
            att_sim = att.get("is_simulation")
            att_mode = att.get("execution_mode")

            expected_attempts[tid] = {
                "slot_id": sid,
                "scenario_id": sc,
                "browser": br_norm,
                "repetition": rep,
                "attempt_number": att.get("attempt_number"),
                "status": att_status,
                "validity": att_validity,
                "execution_mode": att_mode,
            }

            # Mandatory 2: Reject simulation attempts
            if att_sim is not False:
                raise VerificationError(
                    f"Attempt '{tid}' in slot '{sid}' declares is_simulation={att_sim}. "
                    "Simulation attempts are strictly forbidden."
                )
            if att_mode != "LIVE":
                raise VerificationError(
                    f"Attempt '{tid}' in slot '{sid}' declares execution_mode='{att_mode}', expected 'LIVE'"
                )

            if att_status == "COMPLETED" and att_validity == "VALID_LIVE":
                valid_attempts_in_slot.append(att)
            else:
                # Mandatory 8: Preserved failed attempt
                failed_attempts_count += 1
                if att_validity not in ("CLEANUP_FAILURE", "MEASUREMENT_FAILURE", "INTERRUPTED"):
                    raise VerificationError(
                        f"Failed attempt '{tid}' in slot '{sid}' has unrecognized validity '{att_validity}'"
                    )
                # Verify physical preservation of failure
                _verify_trial_evidence(campaign_dir, sid, sc, br_norm, att, is_valid_live=False)

        # Mandatory 6 & 7: Exactly one completed VALID_LIVE attempt per slot
        if len(valid_attempts_in_slot) != 1:
            raise VerificationError(
                f"Slot '{sid}' has {len(valid_attempts_in_slot)} completed valid attempts, expected exactly 1"
            )

        valid_att = valid_attempts_in_slot[0]
        valid_tid = valid_att["trial_id"]
        if valid_tid != current_tid:
            raise VerificationError(
                f"Slot '{sid}' current_trial_id '{current_tid}' does not match valid attempt trial_id '{valid_tid}'"
            )
        valid_trial_ids.add(valid_tid)

        # Mandatory 9 & 10: Verify physical trial evidence (result.json & capture.pcap)
        _verify_trial_evidence(campaign_dir, sid, sc, br_norm, valid_att, is_valid_live=True)

    # Mandatory 4: Assert complete matrix coverage
    for (sc, br), reps in slot_rep_tracker.items():
        if len(reps) != EXPECTED_REPETITIONS_PER_PAIR:
            raise VerificationError(
                f"Incomplete matrix slot ({sc}, {br}): expected {EXPECTED_REPETITIONS_PER_PAIR} repetitions, got {len(reps)}"
            )

    # Mandatory 6: Valid trials count must be exactly 280
    if len(valid_trial_ids) != EXPECTED_VALID_TRIALS:
        raise VerificationError(
            f"Valid live trials count mismatch: expected exactly {EXPECTED_VALID_TRIALS}, got {len(valid_trial_ids)}"
        )

    # Validate manifest summary metrics if present
    summary = manifest_data.get("summary")
    if isinstance(summary, dict):
        if summary.get("completed_slots") != EXPECTED_TOTAL_SLOTS:
            raise VerificationError(
                f"Manifest summary completed_slots ({summary.get('completed_slots')}) != {EXPECTED_TOTAL_SLOTS}"
            )
        if summary.get("valid_live_attempts") != EXPECTED_VALID_TRIALS:
            raise VerificationError(
                f"Manifest summary valid_live_attempts ({summary.get('valid_live_attempts')}) != {EXPECTED_VALID_TRIALS}"
            )
        if summary.get("simulated_attempts", 0) != 0:
            raise VerificationError(
                f"Manifest summary records {summary.get('simulated_attempts')} simulated attempts, expected 0"
            )

    # Mandatory 11: Checksum manifest verification if partner_evidence.sha256 exists
    sha_manifest = campaign_dir / "partner_evidence.sha256"
    checked_files = 0
    if sha_manifest.is_file():
        for line_no, line in enumerate(sha_manifest.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            exp_hash, raw_rel_path = parts[0], parts[1].strip()
            # Clean leading ./ or .\ prefix portably
            rel_path = raw_rel_path
            if rel_path.startswith("./") or rel_path.startswith(".\\"):
                rel_path = rel_path[2:]

            # Mandatory 11 & 12: Enforce safe relative path without traversal
            if rel_path.startswith("/") or rel_path.startswith("\\") or ".." in Path(rel_path).parts:
                raise VerificationError(
                    f"Checksum manifest line {line_no} contains illegal or traversal path: '{raw_rel_path}'"
                )

            target_f = (campaign_dir / rel_path).resolve()
            try:
                target_f.relative_to(campaign_dir)
            except ValueError:
                raise VerificationError(
                    f"Checksum manifest line {line_no} path '{raw_rel_path}' escapes campaign directory"
                )

            if not target_f.is_file():
                raise VerificationError(f"Checksum manifest references missing file: '{rel_path}'")

            actual_hash = sha256_file(target_f)
            if actual_hash.lower() != exp_hash.lower():
                raise VerificationError(
                    f"Checksum mismatch for '{rel_path}': expected {exp_hash}, got {actual_hash}"
                )
            checked_files += 1

    # Mandatory 13, 14 & 15: Audit derived directory if supplied or explicitly requested
    derived_audit = None
    if derived_dir is not None:
        derived_audit = _verify_derived_directory(
            derived_dir=Path(derived_dir),
            campaign_id=campaign_id,
            all_campaign_trial_ids=seen_all_trial_ids,
            total_attempts_count=total_attempts_count,
            valid_trial_ids=valid_trial_ids,
            expected_attempts=expected_attempts,
        )

    return {
        "status": "PASS",
        "campaign_id": campaign_id,
        "valid_trials_count": len(valid_trial_ids),
        "total_slots": len(matrix_slots),
        "total_attempts": total_attempts_count,
        "failed_attempts_preserved": failed_attempts_count,
        "scenarios": sorted(list(scenarios_present)),
        "browsers": sorted(list(browsers_present)),
        "matrix_verified": True,
        "checksum_files_checked": checked_files,
        "derived_audit": derived_audit,
    }


def verify_partner_archive(archive_path: Path, derived_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Extracts a partner .tar.gz archive in a temporary root and audits its contents.
    Enforces path and type safety during extraction, verifies mandatory .sha256 sidecar,
    and executes portable campaign audit.
    """
    archive_path = Path(archive_path).resolve()
    if not archive_path.is_file():
        raise VerificationError(f"Archive file does not exist: {archive_path}")

    # Mandatory 15: Archive SHA-256 sidecar is mandatory; missing sidecar fails closed
    sha_sidecar = Path(f"{archive_path}.sha256")
    if not sha_sidecar.is_file():
        raise VerificationError(
            f"Missing mandatory archive SHA-256 sidecar '{sha_sidecar.name}'. "
            "Handover packages must include a verifiable .sha256 sidecar file."
        )

    content = sha_sidecar.read_text(encoding="utf-8").strip()
    if not content:
        raise VerificationError(f"Archive SHA-256 sidecar '{sha_sidecar.name}' is empty")

    exp_hash = content.split()[0]
    act_hash = sha256_file(archive_path)
    if exp_hash.lower() != act_hash.lower():
        raise VerificationError(
            f"Archive SHA-256 sidecar mismatch: expected {exp_hash}, calculated {act_hash}"
        )

    # Mandatory 15: If derived_dir is explicitly requested, fail closed if missing before extracting
    if derived_dir is not None and not Path(derived_dir).is_dir():
        raise VerificationError(f"Derived directory does not exist or is not a directory: '{derived_dir}'")

    with tempfile.TemporaryDirectory(prefix="ps028_partner_extract_") as extract_root:
        root_path = Path(extract_root).resolve()
        try:
            with tarfile.open(archive_path, "r:*") as tar:
                # Mandatory 12: Enforce archive extraction path and type safety
                for member in tar.getmembers():
                    mname = member.name
                    # Disallow absolute paths, Windows drive letters, or directory traversal
                    if mname.startswith("/") or mname.startswith("\\") or re.match(r"^[a-zA-Z]:", mname):
                        raise VerificationError(f"Refusing to extract archive with illegal path: '{mname}'")
                    if ".." in Path(mname).parts:
                        raise VerificationError(f"Refusing to extract archive with directory traversal: '{mname}'")

                    # Disallow device files and FIFOs
                    if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                        raise VerificationError(f"Refusing to extract archive containing special device node: '{mname}'")

                    # Disallow symlinks/hardlinks pointing outside the extraction root
                    if member.issym() or member.islnk():
                        link_target = member.linkname
                        if link_target.startswith("/") or link_target.startswith("\\") or ".." in Path(link_target).parts:
                            raise VerificationError(
                                f"Refusing to extract archive containing illegal link target: '{mname}' -> '{link_target}'"
                            )
                        # Verify combined path does not escape root_path
                        combined = (root_path / mname).parent / link_target
                        try:
                            combined.resolve().relative_to(root_path)
                        except ValueError:
                            raise VerificationError(
                                f"Refusing to extract archive containing link escaping root: '{mname}' -> '{link_target}'"
                            )

                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=root_path, filter="data")
                else:
                    tar.extractall(path=root_path)
        except Exception as exc:
            if isinstance(exc, VerificationError):
                raise
            raise VerificationError(f"Failed to extract tar archive: {exc}") from exc

        # Locate campaign root directory
        target_dir = root_path
        if not (target_dir / "campaign_manifest.json").is_file():
            candidates = [p.parent for p in root_path.rglob("campaign_manifest.json")]
            if candidates:
                target_dir = candidates[0]
            else:
                raise VerificationError("Extracted archive does not contain campaign_manifest.json")

        return verify_partner_campaign_directory(target_dir, derived_dir=derived_dir)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Independent Partner Handover Evidence Verifier"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--campaign-dir", type=Path, help="Path to partner campaign directory")
    group.add_argument("--archive", type=Path, help="Path to partner .tar.gz handover archive")
    parser.add_argument("--derived-dir", type=Path, default=None,
                        help="Optional path to derived CSV ledgers and provenance sidecars")
    parser.add_argument("--json", action="store_true", help="Output audit report as JSON")
    args = parser.parse_args()

    try:
        if args.archive:
            result = verify_partner_archive(args.archive, derived_dir=args.derived_dir)
        else:
            result = verify_partner_campaign_directory(args.campaign_dir, derived_dir=args.derived_dir)

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("=" * 78)
            print("PS-028 Independent Partner Handover Evidence Verification")
            print("=" * 78)
            print(f"Status        : {result['status']}")
            print(f"Campaign ID   : {result['campaign_id']}")
            print(f"Valid Trials  : {result['valid_trials_count']} / {EXPECTED_VALID_TRIALS}")
            print(f"Matrix Slots  : {result['total_slots']} / {EXPECTED_TOTAL_SLOTS} (100% Complete)")
            print(f"Total Attempts: {result['total_attempts']} ({result['failed_attempts_preserved']} failed attempts preserved)")
            print(f"Scenarios     : {', '.join(result['scenarios'])}")
            print(f"Browsers      : {', '.join(result['browsers'])}")
            print(f"Matrix Audit  : 100% Complete ({EXPECTED_REPETITIONS_PER_PAIR} repetitions per pair)")
            print(f"Checksum Files: {result['checksum_files_checked']} verified")
            if result.get("derived_audit"):
                d = result["derived_audit"]
                print(f"Derived Audit : Verified {len(d['ledgers_verified'])} ledgers + provenance sidecars")
            print("=" * 78)
            print("[SUCCESS] Partner evidence satisfies all PS-028 replication criteria.")
            print("=" * 78)
        return 0
    except VerificationError as err:
        err_dict = {"status": "FAIL", "error": str(err)}
        if args.json:
            print(json.dumps(err_dict, indent=2))
        else:
            print("=" * 78, file=sys.stderr)
            print(f"[VERIFICATION FAILED] {err}", file=sys.stderr)
            print("=" * 78, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
