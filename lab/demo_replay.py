#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Prototype Demonstration & Replay Utility
Milestone 7: Phase E (Demo-Readiness Remediation)

Features:
1. Replays 14 representative authentic preserved PCAPs across all seven canonical scenarios
   (S0, S1, S2, S3, S4, S5, S6) and both browser cohorts (Chrome 156 and Firefox 159).
   Note: These 14 cases are representative samples (repetition 1 of each cohort), not the
   complete 280-trial campaign.
2. Performs strict fail-closed validation: requires authentic readable PCAP, verified SHA-256
   checksum, matching trial metadata, explicit primary HTTP flow correlation, verified RFC 9293
   3-way handshake completion, correlated HTTP request/response frames, and an authentic HTTP status.
3. Eliminates all fabricated fallbacks: missing metrics remain null, zero measurements are preserved,
   and winning families are verified against recorded ground truth.
4. Preserves the canonical RFC 8305 connection racing pseudocode snippet (--pseudocode).
5. Runs 100% offline without root or network privileges.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lab.run_trial import dissect_pcap

CAMPAIGN_DIR = REPO_ROOT / "lab" / "campaigns" / "ps028-a10-live-20261030-01"
CHECKSUM_FILE = CAMPAIGN_DIR / "pcap_sha256_checksums.txt"
REDERIVED_DIR = REPO_ROOT / "lab" / "derived" / "phase-c" / "rederived_results"

# Representative authentic trial PCAPs from October 29 campaign (14 cases: S0-S6 x 2 browsers)
REPRESENTATIVE_TRIALS: List[Dict[str, Any]] = [
    {
        "scenario_id": "S0",
        "scenario_title": "S0 (Dual-Stack Baseline)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "Healthy dual-stack: both paths available; IPv6 preferred; 0 fallback.",
        "trial_id": "trial-20261029205425-6cb90a54",
        "pcap_relpath": "trials/trial-20261029205425-6cb90a54/capture.pcap",
        "expected_pcap_sha256": "69fd09eb63b53f2be42428e40d99ed61eeef4da47bead93fe129ecab1ba47f72",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S0",
        "scenario_title": "S0 (Dual-Stack Baseline)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "Healthy dual-stack: both paths available; IPv6 preferred; 0 fallback.",
        "trial_id": "trial-20261029205924-355df0f7",
        "pcap_relpath": "trials/trial-20261029205924-355df0f7/capture.pcap",
        "expected_pcap_sha256": "b053364fd2c1cd71fb5fc39f28ab0ced92b5a14f4f289323ae8cd30547025e59",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S1",
        "scenario_title": "S1 (IPv6 SYN Blackhole)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "IPv6 SYN dropped: client waits for CAD timer (~300ms) then connects over IPv4.",
        "trial_id": "trial-20261029205941-b5bd2503",
        "pcap_relpath": "trials/trial-20261029205941-b5bd2503/capture.pcap",
        "expected_pcap_sha256": "a58f7e24e002f870f9e457f8a321469a9d3809fa1534be1b0976111a4e4fafe9",
        "expected_family": "IPv4",
        "expected_classification": "IPV6_TO_IPV4_FALLBACK",
    },
    {
        "scenario_id": "S1",
        "scenario_title": "S1 (IPv6 SYN Blackhole)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "IPv6 SYN dropped: client waits for CAD timer (~400ms) then connects over IPv4.",
        "trial_id": "trial-20261029205956-a51aca94",
        "pcap_relpath": "trials/trial-20261029205956-a51aca94/capture.pcap",
        "expected_pcap_sha256": "32a28fdda2b7f40edb8996c911c0d95a324653ce58b8a6137b64e6ec49624a0b",
        "expected_family": "IPv4",
        "expected_classification": "IPV6_TO_IPV4_FALLBACK",
    },
    {
        "scenario_id": "S2",
        "scenario_title": "S2 (IPv6 TCP RST Active Failure)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "IPv6 rejected by RST: Chrome initiates immediate fallback to IPv4 (<10ms).",
        "trial_id": "trial-20261029210015-37425c7a",
        "pcap_relpath": "trials/trial-20261029210015-37425c7a/capture.pcap",
        "expected_pcap_sha256": "8abb73c01f12b43536b4415bb2b8b2ecce95fee05c27f4655472bef883acbb7c",
        "expected_family": "IPv4",
        "expected_classification": "IPV6_TO_IPV4_FALLBACK",
    },
    {
        "scenario_id": "S2",
        "scenario_title": "S2 (IPv6 TCP RST Active Failure)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "IPv6 rejected by RST: Firefox initiates sequential fallback to IPv4 (~160ms CAD).",
        "trial_id": "trial-20261029210032-6a901d45",
        "pcap_relpath": "trials/trial-20261029210032-6a901d45/capture.pcap",
        "expected_pcap_sha256": "44ed0a34f00045aae3c59d0fb0236e5897ebab4b7abebe4408a8f4028881b933",
        "expected_family": "IPv4",
        "expected_classification": "IPV6_TO_IPV4_FALLBACK",
    },
    {
        "scenario_id": "S3",
        "scenario_title": "S3 (Moderate IPv6 Latency: IPv6 150ms, IPv4 20ms)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "Moderate IPv6 delay: IPv6 SYN completes before CAD timer expires; IPv6 wins directly.",
        "trial_id": "trial-20261029210049-26b5b48b",
        "pcap_relpath": "trials/trial-20261029210049-26b5b48b/capture.pcap",
        "expected_pcap_sha256": "c43942d54af024d75bcce9e3142f2669812a23ac1ac4efc8306d2b13ee7375b9",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S3",
        "scenario_title": "S3 (Moderate IPv6 Latency: IPv6 150ms, IPv4 20ms)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "Moderate IPv6 delay: IPv6 completes handshake before CAD timer; IPv6 wins directly.",
        "trial_id": "trial-20261029210105-1144e256",
        "pcap_relpath": "trials/trial-20261029210105-1144e256/capture.pcap",
        "expected_pcap_sha256": "d88459129d76564d5a65839c13c45eabcf053fa543f5a563a5511fa3f4ef6279",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S4",
        "scenario_title": "S4 (Asymmetric Latency: IPv6 600ms, IPv4 20ms)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "Severe IPv6 delay: IPv4 attempt launched at CAD timer (~300ms) finishes handshake first.",
        "trial_id": "trial-20261029210122-cc8b2b9f",
        "pcap_relpath": "trials/trial-20261029210122-cc8b2b9f/capture.pcap",
        "expected_pcap_sha256": "6c1ccd5561f483fac74bdb98898aa6d956888513094e2e07950d019e8127f78b",
        "expected_family": "IPv4",
        "expected_classification": "IPV6_TO_IPV4_FALLBACK",
    },
    {
        "scenario_id": "S4",
        "scenario_title": "S4 (Asymmetric Latency: IPv6 600ms, IPv4 20ms)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "Severe IPv6 delay: IPv4 attempt launched at CAD timer (~400ms) finishes handshake first.",
        "trial_id": "trial-20261029210137-b906c7dd",
        "pcap_relpath": "trials/trial-20261029210137-b906c7dd/capture.pcap",
        "expected_pcap_sha256": "02e0fb098538a54da70cba451125f6daf9adf72b1dfcb07d4814bc57512bdd45",
        "expected_family": "IPv4",
        "expected_classification": "IPV6_TO_IPV4_FALLBACK",
    },
    {
        "scenario_id": "S5",
        "scenario_title": "S5 (50% Random IPv6 SYN Loss)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "Partial SYN loss: initial SYN survived; IPv6 established directly without fallback.",
        "trial_id": "trial-20261029210154-93e74c83",
        "pcap_relpath": "trials/trial-20261029210154-93e74c83/capture.pcap",
        "expected_pcap_sha256": "700225ed4926738ec20d1d283a20b209c9dc1c806178a1018b74b5e28f7eaedd",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S5",
        "scenario_title": "S5 (50% Random IPv6 SYN Loss)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "Partial SYN loss: initial SYN survived; IPv6 established directly without fallback.",
        "trial_id": "trial-20261029210210-3aef991a",
        "pcap_relpath": "trials/trial-20261029210210-3aef991a/capture.pcap",
        "expected_pcap_sha256": "28258e902cf0992363e6dd6954ed7eb9d3e70a1036230c397cdf6ea33a7a4e5f",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S6",
        "scenario_title": "S6 (Delayed AAAA DNS Resolution 500ms)",
        "browser": "google-chrome",
        "browser_display": "Google Chrome 156.0.8078.73",
        "description": "Delayed AAAA: browser Resolution Delay timer waits for late AAAA; IPv6 wins directly.",
        "trial_id": "trial-20261029215022-d5cc11cb",
        "pcap_relpath": "trials/trial-20261029215022-d5cc11cb/capture.pcap",
        "expected_pcap_sha256": "75eeda0399bfccc5c8d0c51840d12366a4b48d80e09298f0e62b5dcb40d889c3",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
    {
        "scenario_id": "S6",
        "scenario_title": "S6 (Delayed AAAA DNS Resolution 500ms)",
        "browser": "firefox",
        "browser_display": "Mozilla Firefox 159.0",
        "description": "Delayed AAAA: browser waits for AAAA answer (~500ms); IPv6 wins directly.",
        "trial_id": "trial-20261029215039-e54744f8",
        "pcap_relpath": "trials/trial-20261029215039-e54744f8/capture.pcap",
        "expected_pcap_sha256": "d40bd905344b8ed9db1f7f0ea1117e2b09f74ea48cf4267d1482f295808f47af",
        "expected_family": "IPv6",
        "expected_classification": "DIRECT_IPV6",
    },
]

PSEUDOCODE_SNIPPET = """
================================================================================
HAPPY EYEBALLS v2 / v3 CONNECTION RACING ALGORITHM (RFC 8305 / HEv3 Draft)
Canonical Dual-Stack Pacing Pseudocode Snippet (AIORI PS-028 Submission Kit)
================================================================================

function HappyEyeballsConnect(hostname, port):
    // 1. Asynchronous Hostname Resolution (RFC 8305 Section 3)
    dns_query_start = now()
    query_a = initiate_dns_query(hostname, "A")
    query_aaaa = initiate_dns_query(hostname, "AAAA")
    
    addresses = []
    first_family = wait_for_first_dns_response([query_a, query_aaaa])
    
    if first_family == IPv4 and query_aaaa not completed:
        // Wait for Resolution Delay (RECOMMENDED 50ms) for late AAAA response
        wait_with_timeout(query_aaaa, timeout=50ms)
    
    addresses = sort_and_interleave(query_a.answers, query_aaaa.answers)
    // RFC 6724 rule: prefer IPv6 first in sorted list

    // 2. Transport Connection Racing State Machine (RFC 8305 Section 5)
    active_attempts = []
    cad_timer = 250ms    // Recommended default (MUST NOT < 10ms, bounds 100-2000ms)
    
    for candidate_addr in addresses:
        attempt = initiate_nonblocking_tcp_syn(candidate_addr, port)
        active_attempts.append(attempt)
        last_syn_start = now()
        
        while attempt.is_pending():
            event = wait_for_event(active_attempts, timeout_remaining(last_syn_start + cad_timer))
            
            if event.type == TCP_SYNACK:
                winning_attempt = event.attempt
                send_tcp_ack(winning_attempt)   // Complete 3-way handshake (RFC 9293)
                cancel_and_rst_other_attempts(active_attempts, except=winning_attempt)
                return establish_http_session(winning_attempt)
                
            elif event.type == TCP_RST:
                // Active connection failure: trigger immediate fallback without waiting for CAD
                // Subject to mandatory inter-attempt spacing floor: MUST NOT start within 10ms
                enforce_mandatory_floor(since=last_syn_start, floor=10ms)
                break   // Break loop to launch subsequent candidate immediately
                
            elif event.type == CAD_TIMER_EXPIRED:
                // Unresponsive path: stagger next family attempt concurrently
                break   // Launch next candidate while keeping current attempt active
                
    raise ConnectionFailure("All address family candidates exhausted")
================================================================================
"""

TRIAL_ID_PATTERN = re.compile(r"trial-\d{14}-[0-9a-f]{8}")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 digest of a local file in 64KB blocks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def load_canonical_pcap_checksums(checksum_file: Path) -> Dict[str, str]:
    """
    Load authoritative PCAP SHA-256 checksums from the campaign checksum file.
    Resolves entries using trial ID or campaign-relative suffix.
    Does NOT require machine-specific host paths to exist.
    Fails closed on malformed digests or ambiguous duplicates.
    """
    if not checksum_file.is_file():
        raise FileNotFoundError(f"Canonical checksum file not found: {checksum_file}")

    checksum_map: Dict[str, str] = {}
    with open(checksum_file, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed checksum line {line_no} in {checksum_file}: {line}")
            digest, path_str = parts[0].strip().lower(), parts[1].strip()
            if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
                raise ValueError(f"Invalid SHA-256 digest on line {line_no}: '{digest}'")

            # Extract trial ID from path
            match = TRIAL_ID_PATTERN.search(path_str)
            if not match:
                raise ValueError(f"No trial ID found in checksum path on line {line_no}: '{path_str}'")
            trial_id = match.group(0)

            if trial_id in checksum_map and checksum_map[trial_id] != digest:
                raise ValueError(
                    f"Ambiguous conflicting checksums for trial {trial_id}: "
                    f"'{checksum_map[trial_id]}' vs '{digest}'"
                )
            checksum_map[trial_id] = digest

    return checksum_map


def print_pseudocode():
    """Print the canonical RFC 8305 pseudocode snippet."""
    print(PSEUDOCODE_SNIPPET)


def replay_single_trial(
    demo: Dict[str, Any],
    checksum_map: Dict[str, str],
    campaign_dir: Path,
    rederived_dir: Path,
    verbose_events: bool = False,
) -> Dict[str, Any]:
    """
    Replay a single representative trial capture with strict fail-closed validation.
    Returns a structured dictionary of observation metrics and verification results.
    """
    trial_id = demo["trial_id"]
    pcap_path = campaign_dir / demo["pcap_relpath"]
    expected_sha256 = demo["expected_pcap_sha256"].lower()
    expected_family = demo["expected_family"]
    expected_classification = demo["expected_classification"]

    record: Dict[str, Any] = {
        "trial_id": trial_id,
        "scenario_id": demo["scenario_id"],
        "scenario_title": demo["scenario_title"],
        "browser": demo["browser"],
        "browser_display": demo["browser_display"],
        "description": demo["description"],
        "pcap_path": str(pcap_path),
        "status": "FAIL",
        "errors": [],
        "warnings": [],
        "metrics": {},
        "primary_flow": {},
        "events": [],
    }

    # 1. PCAP Existence and Readability
    if not pcap_path.is_file():
        record["errors"].append(f"PCAP file missing or unreadable: {pcap_path}")
        return record

    # 2. PCAP SHA-256 Verification (against file, against checksum map, against registry)
    actual_sha256 = compute_sha256(pcap_path)
    record["pcap_sha256"] = actual_sha256
    if actual_sha256 != expected_sha256:
        record["errors"].append(
            f"PCAP digest mismatch with registry: actual {actual_sha256} != expected {expected_sha256}"
        )
        return record

    manifest_sha256 = checksum_map.get(trial_id)
    if not manifest_sha256:
        record["errors"].append(f"Trial ID {trial_id} absent from canonical checksum manifest")
        return record
    if actual_sha256 != manifest_sha256:
        record["errors"].append(
            f"PCAP digest mismatch with manifest: actual {actual_sha256} != manifest {manifest_sha256}"
        )
        return record

    # 3. Cross-Check Against Authentic Result Records & Require Rederived Record
    raw_result_file = campaign_dir / "trials" / trial_id / "result.json"
    if not raw_result_file.is_file():
        record["errors"].append(f"Raw result.json missing for trial: {raw_result_file}")
        return record

    try:
        with open(raw_result_file, "r", encoding="utf-8") as f:
            raw_res = json.load(f)
    except Exception as exc:
        record["errors"].append(f"Failed to parse raw result.json: {exc}")
        return record

    # Check raw execution invariants
    if raw_res.get("scenario_id") != demo["scenario_id"]:
        record["errors"].append(
            f"Scenario mismatch: raw {raw_res.get('scenario_id')} != spec {demo['scenario_id']}"
        )
    raw_browser = raw_res.get("browser", {})
    raw_browser_name = raw_browser.get("name") if isinstance(raw_browser, dict) else str(raw_browser)
    if raw_browser_name != demo["browser"]:
        record["errors"].append(
            f"Browser mismatch: raw {raw_browser_name} != spec {demo['browser']}"
        )
    if raw_res.get("execution_mode") != "LIVE":
        record["errors"].append(
            f"Execution mode not LIVE: raw {raw_res.get('execution_mode')}"
        )
    if raw_res.get("is_simulation") is not False:
        record["errors"].append("Trial incorrectly flagged as simulation")

    # Require rederived result record (fail-closed integrity)
    rederived_file = rederived_dir / f"{trial_id}.json"
    if not rederived_file.is_file():
        record["errors"].append(f"Rederived result JSON record missing: {rederived_file}")
        return record

    try:
        with open(rederived_file, "r", encoding="utf-8") as f:
            rederived_data = json.load(f)
    except Exception as exc:
        record["errors"].append(f"Rederived result JSON record malformed: {exc}")
        return record

    # Validate all trial identity and classification fields against rederived ground truth
    if rederived_data.get("trial_id") != trial_id:
        record["errors"].append(
            f"Rederived trial_id mismatch: {rederived_data.get('trial_id')} != {trial_id}"
        )
    if rederived_data.get("campaign_id") != "ps028-a10-live-20261030-01":
        record["errors"].append(
            f"Rederived campaign_id mismatch: {rederived_data.get('campaign_id')} != ps028-a10-live-20261030-01"
        )
    if rederived_data.get("scenario_id") != demo["scenario_id"]:
        record["errors"].append(
            f"Rederived scenario_id mismatch: {rederived_data.get('scenario_id')} != {demo['scenario_id']}"
        )
    if rederived_data.get("browser_name") != demo["browser"]:
        record["errors"].append(
            f"Rederived browser mismatch: {rederived_data.get('browser_name')} != {demo['browser']}"
        )
    expected_bver = demo["browser_display"]
    if rederived_data.get("browser_version") != expected_bver:
        record["errors"].append(
            f"Rederived browser_version mismatch: {rederived_data.get('browser_version')} != {expected_bver}"
        )
    if rederived_data.get("execution_mode") != "LIVE":
        record["errors"].append(
            f"Rederived execution_mode not LIVE: {rederived_data.get('execution_mode')}"
        )
    if rederived_data.get("is_simulation") is not False:
        record["errors"].append("Rederived record indicates simulation")
    if rederived_data.get("validity_category") != "VALID_LIVE":
        record["errors"].append(
            f"Rederived validity category not VALID_LIVE: {rederived_data.get('validity_category')}"
        )
    if rederived_data.get("classification") != expected_classification:
        record["errors"].append(
            f"Rederived classification mismatch: {rederived_data.get('classification')} != {expected_classification}"
        )

    reder_pf = rederived_data.get("primary_flow")
    if not reder_pf or not isinstance(reder_pf, dict):
        record["errors"].append("Rederived record missing or malformed primary_flow object")
    else:
        reder_pcap_digest = reder_pf.get("pcap_sha256")
        if not reder_pcap_digest or not isinstance(reder_pcap_digest, str):
            record["errors"].append("Rederived primary flow missing pcap_sha256 digest")
        elif not HEX64_RE.match(reder_pcap_digest):
            record["errors"].append(
                f"Rederived primary flow has malformed pcap_sha256 digest: {reder_pcap_digest!r}"
            )
        elif reder_pcap_digest.lower() != actual_sha256.lower():
            record["errors"].append(
                f"Rederived primary flow PCAP digest mismatch: {reder_pcap_digest.lower()} != {actual_sha256.lower()}"
            )

        if reder_pf.get("family") != expected_family:
            record["errors"].append(
                f"Rederived primary flow family mismatch: {reder_pf.get('family')} != {expected_family}"
            )
        if reder_pf.get("handshake_completed") is not True:
            record["errors"].append("Rederived primary flow handshake not completed")
        reder_status = reder_pf.get("http_status_code")
        if type(reder_status) is not int or reder_status != 200:
            record["errors"].append(
                f"Rederived primary flow HTTP status mismatch or non-integer: {reder_status} != 200"
            )
        for fr_key in ("syn_frame", "final_ack_frame", "http_request_frame", "http_response_frame"):
            fr_val = reder_pf.get(fr_key)
            if type(fr_val) is not int or fr_val <= 0:
                record["errors"].append(
                    f"Rederived primary flow {fr_key} missing or invalid positive integer: {fr_val}"
                )

    # 4. Offline TShark Dissection
    try:
        dissection = dissect_pcap(pcap_path)
    except Exception as exc:
        record["errors"].append(f"TShark dissection failed: {exc}")
        return record

    tcp_streams = dissection.get("tcp_streams", {})
    primary_flow = dissection.get("primary_flow")
    dissection_metrics = dissection.get("metrics", {})

    record["tcp_stream_count"] = len(tcp_streams)

    # 5. Strict Primary Flow Validation
    if not primary_flow or not isinstance(primary_flow, dict):
        record["errors"].append("Primary HTTP flow not correlated in capture")
        return record

    stream_id = primary_flow.get("stream_id")
    if stream_id is None or str(stream_id) == "":
        record["errors"].append("Primary flow missing stream identifier")
    elif reder_pf and str(stream_id) != str(reder_pf.get("stream_id")):
        record["errors"].append(
            f"Dissected stream ID mismatch: {stream_id} != {reder_pf.get('stream_id')}"
        )

    fam = primary_flow.get("family")
    if fam not in ("IPv4", "IPv6"):
        record["errors"].append(f"Primary flow family invalid or unknown: {fam}")
    elif fam != expected_family:
        record["errors"].append(
            f"Winning family discrepancy: observed {fam} != expected {expected_family}"
        )

    # Handshake verification (RFC 9293 §3.5)
    if primary_flow.get("handshake_completed") is not True:
        record["errors"].append("Primary flow RFC 9293 3-way handshake was not completed")

    for fr_key, fr_name in (
        ("syn_frame", "initial SYN frame"),
        ("final_ack_frame", "client final ACK frame"),
        ("http_request_frame", "HTTP request frame"),
        ("http_response_frame", "HTTP response frame"),
    ):
        fr_val = primary_flow.get(fr_key)
        if fr_val is None or type(fr_val) is not int or fr_val <= 0:
            record["errors"].append(f"Primary flow {fr_name} missing or invalid positive integer: {fr_val}")

    status_code = primary_flow.get("http_status_code")
    if status_code is None:
        record["errors"].append("Primary flow HTTP status code missing (fail-closed, no default)")
    elif type(status_code) is not int or status_code not in range(200, 300):
        record["errors"].append(f"Primary flow HTTP status not in 200-299 success range: {status_code}")

    # Latency metric extraction (preserve zeros, do not coerce missing to zero)
    t_connect = primary_flow.get("t_connect_ms")
    if t_connect is None:
        t_connect = dissection_metrics.get("t_connect_ms")
    if t_connect is not None and (t_connect < 0 or not (t_connect == t_connect)):
        record["errors"].append(f"t_connect_ms invalid: {t_connect}")

    t_setup_total = primary_flow.get("t_setup_total_ms")
    if t_setup_total is None:
        t_setup_total = dissection_metrics.get("t_setup_total_ms")

    syn_to_synack = primary_flow.get("syn_to_synack_ms")
    if syn_to_synack is None:
        syn_to_synack = dissection_metrics.get("syn_to_synack_ms")

    cad = dissection_metrics.get("connection_attempt_delay_ms")

    record["primary_flow"] = {
        "stream_id": stream_id,
        "family": fam,
        "client_endpoint": primary_flow.get("client_endpoint"),
        "server_endpoint": primary_flow.get("server_endpoint"),
        "syn_time": primary_flow.get("syn_time"),
        "final_ack_time": primary_flow.get("final_ack_time"),
        "http_status_code": status_code,
        "handshake_completed": primary_flow.get("handshake_completed"),
    }

    record["metrics"] = {
        "t_connect_ms": t_connect,
        "t_setup_total_ms": t_setup_total,
        "syn_to_synack_ms": syn_to_synack,
        "connection_attempt_delay_ms": cad,
    }

    # Extract timeline events if requested
    if verbose_events:
        events: List[Dict[str, Any]] = []
        # Add DNS events
        for dns in dissection.get("dns_transactions", []):
            if dns.get("query_time") is not None:
                events.append({
                    "time": dns.get("query_time"),
                    "type": "DNS_QUERY",
                    "details": f"Query {dns.get('qtype')} {dns.get('qname')} [id={dns.get('dns_id')}]",
                })
            if dns.get("response_time") is not None:
                events.append({
                    "time": dns.get("response_time"),
                    "type": "DNS_RESPONSE",
                    "details": f"Resp {dns.get('qtype')} answers={dns.get('answers')} ({dns.get('duration_ms')}ms)",
                })
        # Add TCP events
        for st_id, stream in tcp_streams.items():
            f_fam = stream.get("family", "UNKNOWN")
            if stream.get("syn_time") is not None:
                events.append({
                    "time": stream.get("syn_time"),
                    "type": "TCP_SYN",
                    "details": f"Stream #{st_id} ({f_fam}) initial SYN -> port {stream.get('server_port')}",
                })
            if stream.get("synack_time") is not None:
                events.append({
                    "time": stream.get("synack_time"),
                    "type": "TCP_SYNACK",
                    "details": f"Stream #{st_id} ({f_fam}) SYN/ACK received",
                })
            if stream.get("final_ack_time") is not None:
                events.append({
                    "time": stream.get("final_ack_time"),
                    "type": "TCP_FINAL_ACK",
                    "details": f"Stream #{st_id} ({f_fam}) client final ACK -> ESTABLISHED",
                })
            if stream.get("rst_time") is not None:
                events.append({
                    "time": stream.get("rst_time"),
                    "type": "TCP_RST",
                    "details": f"Stream #{st_id} ({f_fam}) TCP RST received",
                })

        events.sort(key=lambda ev: ev.get("time") or 0.0)
        record["events"] = events

    if not record["errors"]:
        record["status"] = "PASS"

    return record


def run_demonstration(
    scenario_filter: Optional[str] = None,
    browser_filter: Optional[str] = None,
    trial_filter: Optional[str] = None,
    summary_mode: bool = False,
    verbose_events: bool = False,
    as_json: bool = False,
) -> int:
    """
    Execute the prototype demonstration replay across all configured or filtered cases.
    Returns 0 on complete validation pass; returns non-zero (1) on any failure.
    """
    try:
        checksum_map = load_canonical_pcap_checksums(CHECKSUM_FILE)
    except Exception as exc:
        print(f"[ERROR] Failed to load canonical checksums: {exc}", file=sys.stderr)
        return 1

    # Filter trials
    selected = REPRESENTATIVE_TRIALS
    if scenario_filter:
        scen_norm = scenario_filter.upper().strip()
        selected = [t for t in selected if t["scenario_id"].upper() == scen_norm]
    if browser_filter:
        b_norm = browser_filter.lower().strip()
        selected = [t for t in selected if b_norm in t["browser"].lower()]
    if trial_filter:
        t_norm = trial_filter.strip()
        selected = [t for t in selected if t["trial_id"] == t_norm]

    if not selected:
        print(f"[ERROR] No trials matched the specified filters.", file=sys.stderr)
        return 1

    results: List[Dict[str, Any]] = []
    all_passed = True

    if not as_json and not summary_mode:
        print("================================================================================")
        print("AIORI-3 PS-028 Happy Eyeballs Measurement Lab: Prototype Demonstration")
        print("Preserved Authentic Packet Capture Replay Engine (October 29 Campaign)")
        print(f"Total Configured Replay Cases: {len(selected)} (Representative Subset)")
        print("================================================================================")
        print()

    for idx, demo in enumerate(selected, start=1):
        record = replay_single_trial(
            demo=demo,
            checksum_map=checksum_map,
            campaign_dir=CAMPAIGN_DIR,
            rederived_dir=REDERIVED_DIR,
            verbose_events=verbose_events,
        )
        results.append(record)

        if record["status"] != "PASS":
            all_passed = False

        if as_json:
            continue

        if summary_mode:
            status_tag = "[PASS]" if record["status"] == "PASS" else "[FAIL]"
            fam = record.get("primary_flow", {}).get("family", "NONE")
            code = record.get("primary_flow", {}).get("http_status_code", "NONE")
            t_conn = record.get("metrics", {}).get("t_connect_ms")
            t_conn_str = f"{t_conn:.2f}ms" if t_conn is not None else "N/A"
            cad = record.get("metrics", {}).get("connection_attempt_delay_ms")
            cad_str = f"{cad:.2f}ms" if cad is not None else "N/A"
            print(
                f"{status_tag} {record['scenario_id']:2} {record['browser']:13} "
                f"Winner={fam:4} HTTP={code} t_conn={t_conn_str:8} CAD={cad_str:8} "
                f"Trial={record['trial_id']}"
            )
            if record["errors"]:
                for err in record["errors"]:
                    print(f"       ERROR: {err}")
        else:
            print("--------------------------------------------------------------------------------")
            status_tag = "[PASS]" if record["status"] == "PASS" else "[FAIL]"
            print(f"DEMO TRIAL {idx}/{len(selected)} {status_tag}: {demo['scenario_title']}")
            print(f"Browser:     {demo['browser_display']}")
            print(f"Observation: {demo['description']}")
            print(f"Trial ID:    {record['trial_id']}")
            print(f"PCAP SHA256: {record.get('pcap_sha256', 'N/A')[:16]}... (checksum verified)")
            print("--------------------------------------------------------------------------------")

            if record["errors"]:
                for err in record["errors"]:
                    print(f"  [ERROR] {err}")
                print()
                continue

            pf = record["primary_flow"]
            metrics = record["metrics"]
            t_conn = metrics.get("t_connect_ms")
            t_setup = metrics.get("t_setup_total_ms")
            cad = metrics.get("connection_attempt_delay_ms")
            srv = pf.get("server_endpoint", ["", ""])
            srv_str = f"{srv[0]}:{srv[1]}" if isinstance(srv, list) and len(srv) == 2 else str(srv)

            print(f"  [PCAP Summary] TCP Streams Detected: {record.get('tcp_stream_count', 0)}")
            print(f"  [Winning Flow] Stream #{pf.get('stream_id')}: {pf.get('family')} -> {srv_str}")
            print(f"                 RFC 9293 t_connect_ms: {t_conn:.2f} ms (SYN -> Client Final ACK)")
            if t_setup is not None:
                print(f"                 Total Setup Time:     {t_setup:.2f} ms (First SYN any family -> Final ACK)")

            if cad is not None:
                print(f"  [Racing CAD]   Initial IPv6 SYN -> Initial IPv4 SYN: {cad:.2f} ms")
            elif record["scenario_id"] in ("S0", "S3", "S6"):
                print(f"  [Racing CAD]   Not applicable (Primary family completed without race fallback)")

            code = pf.get("http_status_code")
            print(f"  [Verdict]      Outcome: {pf.get('family')} won | HTTP {code} OK (Validated)")

            if verbose_events and record.get("events"):
                print("  [Event Sequence Timeline]:")
                t0 = record["events"][0]["time"]
                for ev in record["events"]:
                    rel_ms = (ev["time"] - t0) * 1000.0
                    print(f"    + {rel_ms:8.2f} ms | {ev['type']:14} | {ev['details']}")

            print()

    if as_json:
        report = {
            "title": "PS-028 Demonstration Replay Validation Report",
            "campaign_id": "ps028-a10-live-20261030-01",
            "scope": "14 Representative Authentic Cases (Repetition 1)",
            "total_selected": len(selected),
            "passed_count": sum(1 for r in results if r["status"] == "PASS"),
            "failed_count": sum(1 for r in results if r["status"] != "PASS"),
            "all_passed": all_passed,
            "results": results,
        }
        print(json.dumps(report, indent=2))
        return 0 if all_passed else 1

    print("================================================================================")
    if all_passed:
        print(f"[SUCCESS] Prototype demonstration completed. All {len(selected)} representative trials verified.")
    else:
        failed_count = sum(1 for r in results if r["status"] != "PASS")
        print(f"[FAILURE] Prototype demonstration FAILED: {failed_count}/{len(selected)} trials failed validation.")
    print("================================================================================")

    return 0 if all_passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PS-028 Prototype Demonstration & Authentic PCAP Replay Utility"
    )
    parser.add_argument(
        "--pseudocode",
        action="store_true",
        help="Print Happy Eyeballs connection racing pseudocode snippet (RFC 8305)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        default=True,
        help="Replay all 14 representative authentic PCAPs (default: True)",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Filter by scenario ID (e.g. S0, S1, S2, S3, S4, S5, S6)",
    )
    parser.add_argument(
        "--browser",
        type=str,
        default=None,
        help="Filter by browser name (google-chrome or firefox)",
    )
    parser.add_argument(
        "--trial",
        type=str,
        default=None,
        help="Replay a single specific trial ID",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Display compact tabular summary instead of full trial cards",
    )
    parser.add_argument(
        "--events",
        "--timeline",
        dest="events",
        action="store_true",
        help="Display detailed packet-derived event sequence timeline",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON validation report to stdout",
    )
    args = parser.parse_args()

    if args.pseudocode:
        print_pseudocode()
        return 0

    return run_demonstration(
        scenario_filter=args.scenario,
        browser_filter=args.browser,
        trial_filter=args.trial,
        summary_mode=args.summary,
        verbose_events=args.events,
        as_json=args.json,
    )


if __name__ == "__main__":
    sys.exit(main())
