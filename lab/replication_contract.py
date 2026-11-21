#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Centralized Replication Contract
Work Package A: Single Source of Truth for Independent Partner Replication

Defines the immutable, machine-readable scientific and operational contract:
1. Replication protocol and schema versions.
2. Canonical scenario IDs and complete parameters (S0-S6).
3. Pinned browser identities, exact versions, and executable requirements.
4. Python runtime and library versions.
5. System toolchain versions (exact pins and minimums).
6. DNS requirements and vantage point.
7. Metric definitions and schema requirements.
8. Matrix dimensions (14 cohorts x 20 repetitions = exactly 280 trials).
9. Campaign evidence structure and mandatory checksums.
10. S5 stochastic randomness policy and loss accounting.
11. Specification of record (draft-ietf-happy-happyeyeballs-v3-04).
12. Provenance and host restoration requirements.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PARTNER_MANIFEST_PATH = REPO_ROOT / "docs" / "phase-cd" / "partner_replication_manifest.json"

PROTOCOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0.0", "1.1.0"})

SPECIFICATION_OF_RECORD = "draft-ietf-happy-happyeyeballs-v3-04"
SPECIFICATION_STATUS_NOTE = (
    "draft-ietf-happy-happyeyeballs-v3-04 (published 1 July 2026; dated status check: 2026-11-13). "
    "HEv3 remains an Internet-Draft and must not be described as a published RFC."
)

HISTORICAL_BASELINE_CAMPAIGN_ID = "ps028-a10-live-20261030-01"
BASE_COMMIT_SHA = "0dc8c5801a73a55942dc905d4cf7cd5f6c55c896"

# PCAP Semantic Rederivation Timing Tolerance
# Derived from microsecond packet timestamp resolution, float conversion epsilon,
# decimal serialization rounding (2 decimal places = +/-0.01ms), and parser ACK
# segment identification (pure TCP ACK vs first payload ACK segment = up to 1.5ms).
PCAP_TIMING_RECONCILIATION_TOLERANCE_MS: float = 2.0

# Scientific Validity vs. Observable Results Separation
# Experimental validity audits physical network conditions, toolchain, and capture integrity.
# Scientific results evaluate address family choices and timing distributions.
EXPERIMENT_VALIDITY_CLASSES: Set[str] = {
    "VALID_LIVE",
    "VALID_LIVE_OBSERVATION",
    "VALID_LIVE_CONNECTION_FAILURE",
    "INVALID_EXPERIMENT",
}

SCIENTIFIC_COMPARISON_CLASSES: Set[str] = {
    "REPLICATED",
    "SYSTEMATIC_SHIFT",
    "BEHAVIORAL_DIVERGENCE",
    "INCONCLUSIVE",
    "INVALID",
}

# Predeclared Practical Equivalence Margins for Two One-Sided Tests (TOST)
PREDECLARED_EQUIVALENCE_MARGINS: Dict[str, Any] = {
    "baseline_latency_abs_margin_ms": 5.0,  # 20ms baseline link RTT: 25% of round-trip
    "baseline_latency_ratio_margin": (0.85, 1.15),  # +/-15% relative
    "s3_150ms_latency_abs_margin_ms": 25.0,  # 150ms netem RTT
    "s3_latency_ratio_margin": (0.85, 1.15),
    "s4_600ms_latency_abs_margin_ms_ipv4": 25.0,  # 20ms fallback path
    "s4_600ms_latency_abs_margin_ms_ipv6": 50.0,  # 600ms netem path
    "s4_latency_ratio_margin": (0.85, 1.15),
    "winning_family_proportion_margin": 0.15,  # +/-15 percentage points (<=3 trials in 20)
    "bootstrap_seed": 42,
    "bootstrap_iterations": 2000,
    "bootstrap_confidence": 0.90,  # 90% CI for two one-sided tests (TOST alpha=0.05)
}

# Exact Pinned Browser Builds
PINNED_BROWSERS: Dict[str, Dict[str, Any]] = {
    "google-chrome": {
        "canonical_name": "google-chrome",
        "pinned_version": "156.0.8078.73",
        "default_executable_path": "/usr/bin/google-chrome",
        "aliases": ["google-chrome", "google-chrome-stable", "chrome"],
    },
    "firefox": {
        "canonical_name": "firefox",
        "pinned_version": "159.0",
        "default_executable_path": "/usr/bin/firefox",
        "aliases": ["firefox"],
    },
}

# Canonical 7 Scenarios
CANONICAL_SCENARIO_IDS: List[str] = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]

SCENARIO_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "S0": {
        "scenario_id": "S0",
        "name": "healthy_baseline",
        "description": "Healthy dual-stack baseline, approximately 20ms RTT (10ms netem per link), immediate DNS",
        "type": "baseline",
        "target_family": "dual",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": 20},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 0},
        "nftables_rules": [],
    },
    "S1": {
        "scenario_id": "S1",
        "name": "ipv6_syn_blackhole",
        "description": "IPv6 TCP SYN blackhole (unresponsive primary path, triggers client SYN timeout)",
        "type": "nftables",
        "target_family": "ipv6",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": None},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 0},
        "nftables_rules": [
            'oifname "ps028-rt-sv6" ip6 daddr 2001:db8:2::10 tcp flags syn / syn,ack drop'
        ],
    },
    "S2": {
        "scenario_id": "S2",
        "name": "ipv6_tcp_rst",
        "description": "IPv6 TCP RST rejection (active failure, immediate reset without timeout)",
        "type": "nftables",
        "target_family": "ipv6",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": None},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 0},
        "nftables_rules": [
            'oifname "ps028-rt-sv6" ip6 daddr 2001:db8:2::10 tcp flags syn / syn,ack reject with tcp reset'
        ],
    },
    "S3": {
        "scenario_id": "S3",
        "name": "ipv6_rtt_150ms",
        "description": "IPv6 RTT approximately 150ms (75ms per link end), IPv4 approximately 20ms",
        "type": "netem",
        "target_family": "ipv6",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": 150},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 0},
        "nftables_rules": [],
    },
    "S4": {
        "scenario_id": "S4",
        "name": "ipv6_rtt_600ms",
        "description": "IPv6 RTT approximately 600ms (300ms per link end), IPv4 approximately 20ms",
        "type": "netem",
        "target_family": "ipv6",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": 600},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 0},
        "nftables_rules": [],
    },
    "S5": {
        "scenario_id": "S5",
        "name": "ipv6_syn_loss_50pct",
        "description": "Approximately 50% stochastic IPv6 SYN loss in client-to-server direction",
        "type": "nftables",
        "target_family": "ipv6",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": 20},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 0},
        "nftables_rules": [
            'oifname "ps028-rt-sv6" ip6 daddr 2001:db8:2::10 tcp flags syn / syn,ack numgen random mod 100 < 50 drop'
        ],
    },
    "S6": {
        "scenario_id": "S6",
        "name": "delay_aaaa_500ms",
        "description": "IPv6 AAAA DNS response delayed by 500ms, A response remains immediate (0ms)",
        "type": "dns",
        "target_family": "ipv6",
        "network": {"ipv4_rtt_ms": 20, "ipv6_rtt_ms": 20},
        "dns": {"A_delay_ms": 0, "AAAA_delay_ms": 500},
        "nftables_rules": [],
    },
}

# Replication Matrix Dimensions
REPETITIONS_PER_COHORT: int = 20
COHORTS_COUNT: int = 14  # 7 scenarios x 2 browsers
TOTAL_PLANNED_TRIALS: int = 280  # 14 cohorts x 20 repetitions

# Toolchain Requirements (Minimums and Specific Package Expectations)
REQUIRED_TOOLCHAIN: Dict[str, Dict[str, Any]] = {
    "python": {
        "min_version": "3.10.0",
        "check_command": ["--version"],
    },
    "iproute2": {
        "binary": "ip",
        "min_version": "6.1.0",
        "check_command": ["-V"],
    },
    "tc": {
        "binary": "tc",
        "min_version": "6.1.0",
        "check_command": ["-V"],
    },
    "nftables": {
        "binary": "nft",
        "min_version": "1.0.0",
        "check_command": ["-v"],
    },
    "tshark": {
        "binary": "tshark",
        "min_version": "4.0.0",
        "pinned_package_version": "4.2.2-1ubuntu1",  # Ubuntu 24.04 noble release
        "check_command": ["-v"],
    },
    "tcpdump": {
        "binary": "tcpdump",
        "min_version": "4.99.0",
        "check_command": ["--version"],
    },
    "nginx": {
        "binary": "nginx",
        "min_version": "1.24.0",
        "check_command": ["-v"],
    },
    "curl": {
        "binary": "curl",
        "min_version": "7.80.0",
        "check_command": ["--version"],
    },
}

# Pinned Python Dependencies
REQUIRED_PYTHON_DEPENDENCIES: Dict[str, Dict[str, Any]] = {
    "dnspython": {
        "expected": "2.6.1",
        "exact": True,
    },
    "pyyaml": {
        "expected": "6.0.1",
        "min_version": "6.0",
        "exact": False,
    },
}

# DNS and Vantage Point Requirements
DNS_REQUIREMENTS: Dict[str, Any] = {
    "domain_suffix": "he.test.",
    "wildcard_pattern": "*.he.test.",
    "server_ip": "10.0.1.1",
    "port": 53,
    "https_type65_nodata": True,
}

CAPTURE_VANTAGE_POINT: Dict[str, str] = {
    "namespace": "ps028-cl",
    "interface": "ps028-cl-rt",
    "filter": "tcp port 80 or udp port 53",
}

# S5 Randomness Policy
S5_RANDOMNESS_POLICY: Dict[str, Any] = {
    "policy_type": "PROBABILISTIC_KERNEL_NUMGEN",
    "mechanism": "nftables 'numgen random mod 100 < 50 drop'",
    "kernel_seedable": False,
    "scientific_rationale": (
        "Linux kernel nftables numgen random relies on kernel CSPRNG entropy (get_random_u32()) "
        "and is not seedable from userland. S5 is therefore formally documented and evaluated "
        "as a stochastic/probabilistic impairment with nominal drop probability p=0.50. "
        "Realized loss is measured from raw PCAP stream attempts and router nftables counters, "
        "and reported with binomial Wilson score confidence intervals rather than claiming "
        "false deterministic seed control across independent hosts."
    ),
    "nominal_drop_rate": 0.50,
    "evaluation_method": "raw_pcap_attempts_and_nftables_counters",
}

# Evidence Structure Requirements
REQUIRED_CAMPAIGN_FILES: List[str] = [
    "campaign_manifest.json",
]

REQUIRED_DERIVED_LEDGERS: List[str] = [
    "attempts.csv",
    "connection_attempts.csv",
    "trial_timeline.csv",
]

MANDATORY_INTERNAL_CHECKSUM_FILE: str = "partner_evidence.sha256"


def get_canonical_contract() -> Dict[str, Any]:
    """Returns the full canonical replication contract as a dictionary."""
    return {
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "supported_schema_versions": sorted(list(SUPPORTED_SCHEMA_VERSIONS)),
        "specification_of_record": SPECIFICATION_OF_RECORD,
        "specification_status_note": SPECIFICATION_STATUS_NOTE,
        "historical_baseline_campaign": HISTORICAL_BASELINE_CAMPAIGN_ID,
        "base_commit_sha": BASE_COMMIT_SHA,
        "pcap_timing_reconciliation_tolerance_ms": PCAP_TIMING_RECONCILIATION_TOLERANCE_MS,
        "experiment_validity_classes": sorted(list(EXPERIMENT_VALIDITY_CLASSES)),
        "scientific_comparison_classes": sorted(list(SCIENTIFIC_COMPARISON_CLASSES)),
        "predeclared_equivalence_margins": PREDECLARED_EQUIVALENCE_MARGINS,
        "browsers": PINNED_BROWSERS,
        "canonical_scenarios": SCENARIO_DEFINITIONS,
        "scenario_ids": CANONICAL_SCENARIO_IDS,
        "repetitions_per_cohort": REPETITIONS_PER_COHORT,
        "cohorts_count": COHORTS_COUNT,
        "planned_trial_count": TOTAL_PLANNED_TRIALS,
        "toolchain": REQUIRED_TOOLCHAIN,
        "python_dependencies": REQUIRED_PYTHON_DEPENDENCIES,
        "dns": DNS_REQUIREMENTS,
        "capture_vantage_point": CAPTURE_VANTAGE_POINT,
        "s5_randomness_policy": S5_RANDOMNESS_POLICY,
        "required_derived_ledgers": REQUIRED_DERIVED_LEDGERS,
        "mandatory_internal_checksum_file": MANDATORY_INTERNAL_CHECKSUM_FILE,
    }


def validate_partner_manifest_consistency(manifest_path: Path = PARTNER_MANIFEST_PATH) -> Tuple[bool, List[str]]:
    """
    Validates that docs/phase-cd/partner_replication_manifest.json agrees
    with this centralized replication contract.
    """
    errors: List[str] = []
    if not manifest_path.is_file():
        return False, [f"Partner replication manifest not found at {manifest_path}"]

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, [f"Failed to parse partner manifest JSON: {exc}"]

    # Check planned trials
    if data.get("planned_trial_count") != TOTAL_PLANNED_TRIALS:
        errors.append(
            f"planned_trial_count mismatch: manifest={data.get('planned_trial_count')}, contract={TOTAL_PLANNED_TRIALS}"
        )

    # Check target clients
    clients = data.get("target_clients", [])
    client_dict = {c.get("browser"): c for c in clients}
    for bname, binfo in PINNED_BROWSERS.items():
        if bname not in client_dict:
            errors.append(f"Missing required browser '{bname}' in target_clients")
        else:
            pver = client_dict[bname].get("pinned_version")
            if pver != binfo["pinned_version"]:
                errors.append(
                    f"Browser '{bname}' pinned_version mismatch: manifest={pver}, contract={binfo['pinned_version']}"
                )

    # Check scenarios
    scenarios = data.get("required_scenarios", [])
    sc_dict = {s.get("scenario_id"): s for s in scenarios}
    for sc_id in CANONICAL_SCENARIO_IDS:
        if sc_id not in sc_dict:
            errors.append(f"Missing canonical scenario '{sc_id}' in required_scenarios")
        else:
            reps = sc_dict[sc_id].get("repetitions")
            if reps != REPETITIONS_PER_COHORT:
                errors.append(
                    f"Scenario '{sc_id}' repetitions mismatch: manifest={reps}, contract={REPETITIONS_PER_COHORT}"
                )

    return (len(errors) == 0), errors
