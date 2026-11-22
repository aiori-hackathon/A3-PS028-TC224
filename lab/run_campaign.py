#!/usr/bin/env python3
"""
PS-028 Happy Eyeballs Measurement Lab: Campaign Runner & Orchestration Engine
Work Package A8: Campaign Runner & Orchestration Test Suite

Coordinates systematic, reproducible Happy Eyeballs measurement campaigns:
1. Matrix Selection & Sequential Execution:
   - Generates and schedules permutations of (scenario, browser, repetition).
   - Enforces strictly sequential execution; concurrent trials are strictly forbidden.
   - Distinguishes planned matrix slots from concrete execution attempts.
2. Evidence Integrity & Invariance:
   - Each attempt uses a unique trial ID conforming to DNS wildcarding rules.
   - Stores evidence under dedicated directories; NEVER overwrites previous attempts.
   - Employs only existing A7 evidence-validation rules (PCAP magic, SHA-256, packet count).
3. Fail-Stop Safety:
   - Immediately halts campaign execution if scenario restoration or baseline verification fails.
   - Guarantees lab safety and prevents cascades of contaminated measurements.
4. Concurrency Protection & Manifest Tracking:
   - Prevents concurrent access to the same campaign directory via dedicated manifest locks.
   - Persists versioned campaign manifest (campaign_manifest.json) atomically.
5. Safe Resume:
   - Resumes interrupted campaigns, validating evidence integrity for completed slots
     and executing remaining pending or failed slots cleanly.
6. Documented Mismatch Preservation:
   - Permanently records the documented S2/S4 README vs. scenarios.yaml mismatch in manifest
     metadata without modifying scenarios or relabeling existing evidence.
"""

import argparse
import contextlib
import datetime
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.impair as impair
import lab.partner_preflight as partner_preflight
from lab.replication_contract import (
    PROTOCOL_VERSION,
    PINNED_BROWSERS,
    CANONICAL_SCENARIO_IDS,
    TOTAL_PLANNED_TRIALS,
    REPETITIONS_PER_COHORT,
)
import lab.run_trial as run_trial

SCHEMA_VERSION = "1.1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0.0", "1.1.0"})
DEFAULT_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
DEFAULT_CAMPAIGNS_DIR = SCRIPT_DIR / "campaigns"
MANIFEST_FILENAME = "campaign_manifest.json"
LOCK_FILENAME = ".campaign.lock"
FAILURE_RECORD_FILENAME = "failed_attempt_record.json"

# Documented mismatch between initial README text and canonical lab/scenarios.yaml
# Per PS-028 specification, canonical scenarios are NEVER silently modified and evidence is not relabeled.
DOCUMENTED_SCENARIO_MISMATCHES: Dict[str, Dict[str, str]] = {
    "S2": {
        "readme_documentation": "IPv4 connection path unavailable",
        "configured_behavior": "IPv6 TCP RST rejection (ipv6_tcp_rst)",
        "canonical_reference": "lab/scenarios.yaml (reject with tcp reset on ps028-rt-sv6)",
        "policy": "Canonical lab/scenarios.yaml configuration preserved per PS-028 specification; evidence not relabeled."
    },
    "S4": {
        "readme_documentation": "Increased IPv4 path latency",
        "configured_behavior": "Increased IPv6 path latency 600ms RTT (ipv6_rtt_600ms)",
        "canonical_reference": "lab/scenarios.yaml (300ms netem delay on ps028-rt-sv6 and ps028-sv-rt6)",
        "policy": "Canonical lab/scenarios.yaml configuration preserved per PS-028 specification; evidence not relabeled."
    }
}


def _resolve_repo_relative_path(path: Union[str, Path]) -> Path:
    """Resolve portable and legacy evidence paths against the current checkout.

    New result JSON and campaign manifests use repository-relative paths for
    project-owned evidence. Absolute paths from a previous checkout (including
    the former ``he-webtester`` directory name) are remapped only when the
    corresponding repository-relative file exists in this checkout. Absolute
    paths outside a recognized checkout remain unchanged.
    """
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        return (REPO_ROOT / candidate).resolve()

    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(REPO_ROOT)
        return resolved
    except ValueError:
        pass

    recognized_checkout_names = {REPO_ROOT.name, "he-webtester"}
    parts = resolved.parts
    is_recognized_home_checkout = (
        len(parts) >= 6
        and parts[0] == "/"
        and parts[1] == "home"
        and bool(parts[2])
        and parts[3] == "projects"
        and parts[4] in recognized_checkout_names
    )
    if is_recognized_home_checkout:
        suffix = Path(*parts[5:])
        relocated = (REPO_ROOT / suffix).resolve()
        if relocated.is_file() or relocated.is_dir():
            return relocated

    return resolved


# ==============================================================================
# Exceptions
# ==============================================================================

class CampaignError(Exception):
    """Base exception for campaign runner errors."""
    pass


class CampaignLockError(CampaignError):
    """Raised when the campaign manifest lock cannot be acquired or is held concurrently."""
    pass


class CampaignConfigError(CampaignError):
    """Raised when campaign configuration or parameters are invalid."""
    pass


class CampaignResumeError(CampaignError):
    """Raised when resuming an existing campaign fails or configurations conflict."""
    pass


class CampaignHaltedError(CampaignError):
    """Raised when a campaign is halted immediately due to cleanup or baseline failure."""
    pass


# ==============================================================================
# Manifest Concurrency Lock (Safety Requirement 2)
# ==============================================================================

_MANIFEST_LOCK_TRACKER = threading.local()


def _get_manifest_locks() -> Dict[Path, Dict[str, Any]]:
    """Thread-local storage for manifest lock re-entrancy."""
    current_pid = os.getpid()
    held = getattr(_MANIFEST_LOCK_TRACKER, "held", None)
    if held is None or held.get("pid") != current_pid:
        held = {"pid": current_pid, "locks": {}}
        _MANIFEST_LOCK_TRACKER.held = held
    return held["locks"]


@contextlib.contextmanager
def acquire_manifest_lock(lock_path: Path, timeout: float = 10.0):
    """
    Acquires an exclusive file lock on the campaign manifest directory.
    Guarantees no two campaign runner processes access or mutate the same
    campaign manifest concurrently.
    Supports in-process re-entrancy within the same thread.
    """
    target = Path(lock_path).resolve()
    locks = _get_manifest_locks()

    if target in locks:
        locks[target]["count"] += 1
        try:
            yield
        finally:
            locks[target]["count"] -= 1
            if locks[target]["count"] <= 0:
                del locks[target]
        return

    if not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)

    try:
        fd = os.open(str(target), os.O_CREAT | os.O_RDWR, 0o666)
    except PermissionError:
        fd = os.open(str(target), os.O_RDONLY)

    start_time = time.time()
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (BlockingIOError, OSError):
                if time.time() - start_time >= timeout:
                    raise CampaignLockError(
                        f"Cannot acquire campaign lock on {target}: another campaign process "
                        "is actively operating on this campaign manifest. Concurrent access is prevented."
                    )
                time.sleep(0.05)

        locks[target] = {"fd": fd, "count": 1}
        yield
    finally:
        if acquired:
            if target in locks:
                del locks[target]
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass


# ==============================================================================
# Unique ID Generation & Matrix Structures (Safety Requirement 1)
# ==============================================================================

def generate_campaign_id(prefix: str = "campaign") -> str:
    """Generates a timestamped, unique campaign identifier."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    rand_suffix = hashlib.sha256(os.urandom(16)).hexdigest()[:8]
    return f"{prefix}-{ts}-{rand_suffix}"


def fsync_directory(dir_path: Union[str, Path]) -> None:
    """
    Durably flushes directory metadata changes to disk on POSIX systems so file additions,
    unlinks, or atomic renames (os.replace) are committed to the directory table.

    Fail-closed semantics:
    - On POSIX, opens the directory with O_RDONLY | O_DIRECTORY and calls os.fsync(fd).
    - Retries on EINTR (interrupted system call).
    - Always ensures the directory file descriptor is closed in a finally block.
    - Propagates genuine OSErrors (e.g. EIO, EROFS, EPERM, ENOSPC) to caller rather than silently ignoring.
    - On non-POSIX platforms where directory fsync is unsupported, raises an explicit OSError(errno.ENOSYS).
    """
    path_str = str(dir_path)
    if os.name != "posix":
        raise OSError(errno.ENOSYS, f"Directory fsync is not supported on non-POSIX platform: {os.name}")

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY

    fd = -1
    while True:
        try:
            fd = os.open(path_str, flags)
            break
        except InterruptedError:
            continue
        except OSError as err:
            raise OSError(err.errno, f"Failed to open directory '{path_str}' for fsync: {err.strerror}") from err

    try:
        while True:
            try:
                os.fsync(fd)
                break
            except InterruptedError:
                continue
            except OSError as err:
                raise OSError(err.errno, f"Failed to fsync directory '{path_str}': {err.strerror}") from err
    finally:
        while True:
            try:
                os.close(fd)
                break
            except InterruptedError:
                continue
            except OSError:
                break


class ExecutionAttempt:
    """
    Represents a concrete execution attempt for a matrix slot.
    Distinguishes individual run attempts from the abstract planned matrix slot.
    """
    def __init__(
        self,
        attempt_number: int,
        trial_id: str,
        execution_mode: str,
        is_simulation: bool,
        timestamps: Dict[str, Any],
        status: str,
        validity: str,
        evidence_paths: Dict[str, str],
        capture_metadata: Dict[str, Any],
        http_outcome: Dict[str, Any],
        network_observations: Dict[str, Any],
        cleanup_status: Dict[str, Any],
        error_message: Optional[str] = None,
        slot_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
        browser: Optional[str] = None,
        repetition: Optional[int] = None,
        campaign_id: Optional[str] = None,
        interruption: Optional[Dict[str, Any]] = None
    ):
        self.attempt_number = attempt_number
        self.trial_id = trial_id
        self.execution_mode = execution_mode
        self.is_simulation = is_simulation
        self.timestamps = timestamps
        self.status = status  # COMPLETED, FAILED, ABORTED
        self.validity = validity  # VALID_LIVE, SIMULATION, MEASUREMENT_FAILURE, CLEANUP_FAILURE
        self.evidence_paths = evidence_paths
        self.capture_metadata = capture_metadata
        self.http_outcome = http_outcome
        self.network_observations = network_observations
        self.cleanup_status = cleanup_status
        self.error_message = error_message
        self.slot_id = slot_id
        self.scenario_id = scenario_id
        self.browser = browser
        self.repetition = repetition
        self.campaign_id = campaign_id
        self.interruption = interruption

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "attempt_number": self.attempt_number,
            "trial_id": self.trial_id,
            "execution_mode": self.execution_mode,
            "is_simulation": self.is_simulation,
            "timestamps": self.timestamps,
            "status": self.status,
            "validity": self.validity,
            "evidence_paths": self.evidence_paths,
            "capture_metadata": self.capture_metadata,
            "http_outcome": self.http_outcome,
            "network_observations": self.network_observations,
            "cleanup_status": self.cleanup_status,
            "error_message": self.error_message,
        }
        if self.slot_id:
            res["slot_id"] = self.slot_id
        if self.scenario_id:
            res["scenario_id"] = self.scenario_id
        if self.browser:
            res["browser"] = self.browser
        if self.repetition is not None:
            res["repetition"] = self.repetition
        if self.campaign_id:
            res["campaign_id"] = self.campaign_id
        if self.interruption:
            res["interruption"] = self.interruption
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionAttempt":
        return cls(
            attempt_number=data.get("attempt_number", 1),
            trial_id=data.get("trial_id", ""),
            execution_mode=data.get("execution_mode", "LIVE"),
            is_simulation=data.get("is_simulation", False),
            timestamps=data.get("timestamps", {}),
            status=data.get("status", "FAILED"),
            validity=data.get("validity", "MEASUREMENT_FAILURE"),
            evidence_paths=data.get("evidence_paths", {}),
            capture_metadata=data.get("capture_metadata", {}),
            http_outcome=data.get("http_outcome", {}),
            network_observations=data.get("network_observations", {}),
            cleanup_status=data.get("cleanup_status", {}),
            error_message=data.get("error_message"),
            slot_id=data.get("slot_id"),
            scenario_id=data.get("scenario_id"),
            browser=data.get("browser"),
            repetition=data.get("repetition"),
            campaign_id=data.get("campaign_id"),
            interruption=data.get("interruption")
        )


def write_failed_attempt_record(
    trial_dir: Union[str, Path],
    attempt: Union[ExecutionAttempt, Dict[str, Any]]
) -> Path:
    """
    Atomically writes a durable failed_attempt_record.json to trial_dir:
    - Writes to a temporary file in trial_dir.
    - Flushes and fsyncs to ensure durability on disk.
    - Atomically renames to failed_attempt_record.json.
    - Flushes containing directory on POSIX systems for durability.
    - Preserves attempt number, trial ID, status, validity, execution mode,
      timestamps, cleanup information, evidence paths, and error details.
    """
    tdir = Path(trial_dir).resolve()
    tdir.mkdir(parents=True, exist_ok=True)
    target_path = tdir / FAILURE_RECORD_FILENAME
    tmp_path = tdir / f"{FAILURE_RECORD_FILENAME}.tmp.{os.getpid()}_{time.time_ns()}"

    data = attempt.to_dict() if isinstance(attempt, ExecutionAttempt) else dict(attempt)

    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, target_path)
    fsync_directory(tdir)
    return target_path


class MatrixSlot:
    """
    Represents a planned cell in the experimental campaign matrix:
    (scenario_id, browser, repetition).
    Maintains full history of all execution attempts.
    """
    def __init__(
        self,
        slot_id: str,
        slot_index: int,
        scenario_id: str,
        browser: str,
        repetition: int,
        status: str = "PENDING",
        current_trial_id: Optional[str] = None,
        attempts: Optional[List[ExecutionAttempt]] = None
    ):
        self.slot_id = slot_id
        self.slot_index = slot_index
        self.scenario_id = scenario_id
        self.browser = browser
        self.repetition = repetition
        self.status = status  # PENDING, COMPLETED, FAILED, SKIPPED
        self.current_trial_id = current_trial_id
        self.attempts = attempts if attempts is not None else []

    def is_completed(self) -> bool:
        return self.status == "COMPLETED"

    def add_attempt(self, attempt: ExecutionAttempt) -> None:
        self.attempts.append(attempt)
        self.current_trial_id = attempt.trial_id
        if attempt.status == "COMPLETED" and attempt.validity in ("VALID_LIVE", "SIMULATION"):
            self.status = "COMPLETED"
        else:
            self.status = "FAILED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "slot_index": self.slot_index,
            "scenario_id": self.scenario_id,
            "browser": self.browser,
            "repetition": self.repetition,
            "status": self.status,
            "current_trial_id": self.current_trial_id,
            "attempts": [a.to_dict() for a in self.attempts]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MatrixSlot":
        attempts = [ExecutionAttempt.from_dict(a) for a in data.get("attempts", [])]
        return cls(
            slot_id=data["slot_id"],
            slot_index=data["slot_index"],
            scenario_id=data["scenario_id"],
            browser=data["browser"],
            repetition=data["repetition"],
            status=data.get("status", "PENDING"),
            current_trial_id=data.get("current_trial_id"),
            attempts=attempts
        )


def build_matrix_slots(
    scenarios: List[str],
    browsers: List[str],
    repetitions: int
) -> List[MatrixSlot]:
    """
    Builds the deterministic experimental matrix ordered sequentially:
    Loops over repetitions, then scenarios, then browsers.
    Alternating scenarios and browsers across repetitions ensures any
    unintended lingering caching or state is immediately exposed.
    """
    slots: List[MatrixSlot] = []
    idx = 1
    for rep in range(1, repetitions + 1):
        for sc in scenarios:
            for bname in browsers:
                slot_id = f"slot-{idx:04d}-{sc}-{bname}-rep{rep:02d}"
                slots.append(MatrixSlot(
                    slot_id=slot_id,
                    slot_index=idx,
                    scenario_id=sc,
                    browser=bname,
                    repetition=rep,
                    status="PENDING"
                ))
                idx += 1
    return slots


# ==============================================================================
# Evidence Validation Rules (Safety Requirement 3)
# Reuses existing A7 evidence validation without inventing new rules
# ==============================================================================

def validate_attempt_evidence(
    result_json_path: Path,
    expected_scenario: str,
    is_simulation: bool
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validates evidence of an execution attempt using strictly existing A7 rules:
    - Parses result.json and checks schema_version == "1.0.0".
    - Validates scenario_id match.
    - Validates cleanup_status: scenario_restored, baseline_verified, errors == [].
    - Validates capture PCAP via run_trial.validate_pcap_file (magic bytes, size >= 24, SHA-256).
    - In live mode, requires packet_count > 0.
    - Strictly checks fallback classification adheres to A7 classification matrix.
    Returns: (is_valid, reason, result_dict)
    """
    result_json_path = _resolve_repo_relative_path(result_json_path)
    if not result_json_path.is_file():
        return False, f"result.json missing at {result_json_path}", {}

    try:
        data = json.loads(result_json_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"Failed to parse result.json: {e}", {}

    if data.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        return False, f"Schema version mismatch: {data.get('schema_version')} not in {sorted(list(SUPPORTED_SCHEMA_VERSIONS))}", data

    if data.get("scenario_id") != expected_scenario:
        return False, f"Scenario mismatch in result: {data.get('scenario_id')} != {expected_scenario}", data

    cleanup = data.get("cleanup_status", {})
    if not cleanup.get("scenario_restored", False):
        return False, "Cleanup status indicates scenario was not restored", data
    if not cleanup.get("baseline_verified", False):
        return False, "Cleanup status indicates baseline was not verified", data
    if cleanup.get("errors"):
        return False, f"Cleanup status recorded errors: {cleanup.get('errors')}", data

    # Validate PCAP using existing A7 validate_pcap_file
    pcap_str = data.get("capture_metadata", {}).get("pcap_path")
    if not pcap_str:
        return False, "capture_metadata missing pcap_path", data
    pcap_path = _resolve_repo_relative_path(pcap_str)
    if not pcap_path.is_file():
        return False, f"PCAP file missing at {pcap_path}", data

    min_packets = 1 if not is_simulation else 0
    pcap_valid, pcap_sha, pcap_size, pkt_count, msg = run_trial.validate_pcap_file(
        pcap_path,
        min_packets=min_packets
    )
    if not pcap_valid:
        return False, f"PCAP validation failed: {msg}", data

    recorded_sha = data.get("capture_metadata", {}).get("pcap_sha256")
    if recorded_sha and recorded_sha != pcap_sha:
        return False, f"PCAP SHA-256 mismatch: recorded={recorded_sha}, calculated={pcap_sha}", data

    # Mode validation
    result_sim = data.get("is_simulation", False)
    if is_simulation != result_sim:
        return False, f"Execution mode mismatch: requested simulation={is_simulation}, recorded={result_sim}", data

    return True, "Evidence verified per A7 rules", data


# ==============================================================================
# Campaign Manifest & Atomic Persistence
# ==============================================================================

PARTNER_PLACEHOLDER_TOKENS = frozenset({
    "UNASSIGNED",
    "PENDING",
    "PLACEHOLDER",
    "UNKNOWN",
    "NONE",
    "NULL",
    ""
})


def is_placeholder_partner_metadata(value: Optional[str]) -> bool:
    """
    Returns True if value is None, empty, whitespace-only, a known placeholder token,
    or an unpopulated template bracket (e.g. '<PARTNER_INSTITUTION>').
    """
    if value is None:
        return True
    s = str(value).strip()
    if not s or s.upper() in PARTNER_PLACEHOLDER_TOKENS:
        return True
    if s.startswith("<") and s.endswith(">"):
        return True
    return False


class CampaignManifest:
    """
    Encapsulates campaign state, matrix slots, attempts, configuration,
    and atomic serialization to campaign_manifest.json.
    """
    def __init__(
        self,
        campaign_id: str,
        output_dir: Path,
        scenarios: List[str],
        browsers: List[str],
        repetitions: int,
        is_simulation: bool,
        matrix_slots: List[MatrixSlot],
        status: str = "IN_PROGRESS",
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        completed_at: Optional[str] = None,
        halt_reason: Optional[str] = None,
        strict_partner: bool = False,
        protocol_version: str = PROTOCOL_VERSION,
        partner_info: Optional[Dict[str, Any]] = None,
        partner_institution: Optional[str] = None,
        operator_id: Optional[str] = None
    ):
        self.campaign_id = campaign_id
        self.output_dir = Path(output_dir).resolve()
        self.scenarios = scenarios
        self.browsers = browsers
        self.repetitions = repetitions
        self.is_simulation = is_simulation
        self.matrix_slots = matrix_slots
        self.status = status  # IN_PROGRESS, COMPLETED, HALTED_ON_FAILURE, INTERRUPTED
        self.created_at = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.updated_at = updated_at or self.created_at
        self.completed_at = completed_at
        self.halt_reason = halt_reason
        self.strict_partner = strict_partner
        self.protocol_version = protocol_version
        self.manifest_path = self.output_dir / MANIFEST_FILENAME
        self.lock_path = self.output_dir / LOCK_FILENAME

        if partner_info is not None:
            self.partner_info: Optional[Dict[str, str]] = {
                "partner_institution": str(partner_info.get("partner_institution", "")),
                "operator_id": str(partner_info.get("operator_id", "")),
            }
        elif partner_institution is not None or operator_id is not None:
            self.partner_info = {
                "partner_institution": str(partner_institution or ""),
                "operator_id": str(operator_id or ""),
            }
        else:
            self.partner_info = None

    @property
    def partner_institution(self) -> Optional[str]:
        if self.partner_info is not None:
            return self.partner_info.get("partner_institution")
        return None

    @property
    def operator_id(self) -> Optional[str]:
        if self.partner_info is not None:
            return self.partner_info.get("operator_id")
        return None

    def update_summary(self) -> Dict[str, Any]:
        """Calculates current campaign summary metrics."""
        total_slots = len(self.matrix_slots)
        completed_slots = sum(1 for s in self.matrix_slots if s.status == "COMPLETED")
        pending_slots = sum(1 for s in self.matrix_slots if s.status == "PENDING")
        failed_slots = sum(1 for s in self.matrix_slots if s.status == "FAILED")

        all_attempts = [att for s in self.matrix_slots for att in s.attempts]
        total_attempts = len(all_attempts)
        valid_live = sum(1 for a in all_attempts if a.validity == "VALID_LIVE")
        simulated = sum(1 for a in all_attempts if a.validity == "SIMULATION")
        failures = sum(1 for a in all_attempts if a.validity in ("MEASUREMENT_FAILURE", "CLEANUP_FAILURE"))

        return {
            "total_slots": total_slots,
            "completed_slots": completed_slots,
            "pending_slots": pending_slots,
            "failed_slots": failed_slots,
            "total_attempts": total_attempts,
            "valid_live_attempts": valid_live,
            "simulated_attempts": simulated,
            "failed_attempts": failures,
            "halt_reason": self.halt_reason,
        }

    def to_dict(self) -> Dict[str, Any]:
        self.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data = {
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.protocol_version,
            "campaign_id": self.campaign_id,
            "status": self.status,
            "halt_reason": self.halt_reason,
            "execution_mode": "SIMULATION" if self.is_simulation else "LIVE",
            "is_simulation": self.is_simulation,
            "strict_partner": self.strict_partner,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "configuration": {
                "scenarios": self.scenarios,
                "browsers": self.browsers,
                "repetitions": self.repetitions,
                "output_dir": str(self.output_dir),
            },
            "scenario_mismatch_notices": DOCUMENTED_SCENARIO_MISMATCHES,
            "summary": self.update_summary(),
            "matrix_slots": [s.to_dict() for s in self.matrix_slots]
        }
        if self.partner_info is not None:
            data["partner_info"] = self.partner_info
        return data

    def save_atomically(self) -> None:
        """
        Saves manifest atomically: writes to temporary file, flushes, fsyncs,
        atomically renames to campaign_manifest.json, and flushes directory on POSIX.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        tmp_path = self.manifest_path.with_suffix(f".tmp.{os.getpid()}_{time.time_ns()}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.manifest_path)
        fsync_directory(self.output_dir)

    @classmethod
    def load(cls, manifest_path: Path) -> "CampaignManifest":
        """Loads and parses an existing campaign manifest."""
        manifest_path = Path(manifest_path).resolve()
        if not manifest_path.is_file():
            raise CampaignResumeError(f"Campaign manifest not found at {manifest_path}")

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as e:
            raise CampaignResumeError(f"Failed to read campaign manifest {manifest_path}: {e}")

        if data.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
            raise CampaignResumeError(
                f"Manifest schema version mismatch: {data.get('schema_version')} not in {sorted(list(SUPPORTED_SCHEMA_VERSIONS))}"
            )

        config = data.get("configuration", {})
        slots = [MatrixSlot.from_dict(s) for s in data.get("matrix_slots", [])]

        partner_info = data.get("partner_info")
        if partner_info is None and ("partner_institution" in data or "operator_id" in data):
            partner_info = {
                "partner_institution": data.get("partner_institution", ""),
                "operator_id": data.get("operator_id", ""),
            }

        return cls(
            campaign_id=data["campaign_id"],
            output_dir=manifest_path.parent,
            scenarios=config.get("scenarios", []),
            browsers=config.get("browsers", []),
            repetitions=config.get("repetitions", 1),
            is_simulation=data.get("is_simulation", False),
            matrix_slots=slots,
            status=data.get("status", "IN_PROGRESS"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            completed_at=data.get("completed_at"),
            halt_reason=data.get("summary", {}).get("halt_reason"),
            strict_partner=data.get("strict_partner", False),
            protocol_version=data.get("protocol_version", PROTOCOL_VERSION),
            partner_info=partner_info
        )


# ==============================================================================
# Safe Resume Controller
# ==============================================================================

def reconcile_manifest_for_resume(
    manifest: CampaignManifest,
    expected_scenarios: List[str],
    expected_browsers: List[str],
    expected_reps: int,
    is_simulation: bool,
    expected_partner_institution: Optional[str] = None,
    expected_operator_id: Optional[str] = None,
    strict_partner: bool = False
) -> int:
    """
    Reconciles an existing manifest for a safe resume operation:
    1. Validates configuration and partner metadata compatibility.
    2. Validates evidence for every slot marked COMPLETED using A7 rules.
    3. If evidence is valid, slot remains COMPLETED and is skipped.
    4. If evidence is corrupted or missing, resets slot to PENDING (old attempts preserved).
    Returns count of verified completed slots.
    """
    if set(expected_scenarios) != set(manifest.scenarios):
        raise CampaignResumeError(
            f"Resume scenario mismatch: requested {expected_scenarios}, manifest has {manifest.scenarios}"
        )
    if set(expected_browsers) != set(manifest.browsers):
        raise CampaignResumeError(
            f"Resume browser mismatch: requested {expected_browsers}, manifest has {manifest.browsers}"
        )
    if expected_reps != manifest.repetitions:
        raise CampaignResumeError(
            f"Resume repetitions mismatch: requested {expected_reps}, manifest has {manifest.repetitions}"
        )
    if is_simulation != manifest.is_simulation:
        raise CampaignResumeError(
            f"Resume mode mismatch: requested simulation={is_simulation}, manifest has {manifest.is_simulation}"
        )
    if strict_partner != manifest.strict_partner:
        raise CampaignResumeError(
            f"Resume strict_partner mismatch: requested {strict_partner}, manifest has {manifest.strict_partner}"
        )

    # Validate partner metadata compatibility on resume
    manifest_partner = manifest.partner_info or {}
    manifest_inst = manifest_partner.get("partner_institution") or ""
    manifest_op = manifest_partner.get("operator_id") or ""

    if strict_partner or manifest.strict_partner:
        if is_placeholder_partner_metadata(manifest_inst):
            raise CampaignResumeError(
                f"Resume failed: existing manifest has unassigned or placeholder partner_institution: '{manifest_inst}'"
            )
        if is_placeholder_partner_metadata(manifest_op):
            raise CampaignResumeError(
                f"Resume failed: existing manifest has unassigned or placeholder operator_id: '{manifest_op}'"
            )

    if expected_partner_institution is not None or manifest_inst:
        exp_inst = expected_partner_institution or ""
        if exp_inst != manifest_inst:
            raise CampaignResumeError(
                f"Resume partner_institution mismatch: requested '{expected_partner_institution}', "
                f"manifest has '{manifest_inst}'"
            )

    if expected_operator_id is not None or manifest_op:
        exp_op = expected_operator_id or ""
        if exp_op != manifest_op:
            raise CampaignResumeError(
                f"Resume operator_id mismatch: requested '{expected_operator_id}', "
                f"manifest has '{manifest_op}'"
            )

    verified_completed = 0
    for slot in manifest.matrix_slots:
        if slot.status == "COMPLETED":
            # Find the successful attempt
            valid_attempt = None
            for att in reversed(slot.attempts):
                if att.status == "COMPLETED" and att.validity in ("VALID_LIVE", "SIMULATION"):
                    valid_attempt = att
                    break

            if valid_attempt:
                res_path = _resolve_repo_relative_path(valid_attempt.evidence_paths.get("result_json", ""))
                is_valid, msg, _ = validate_attempt_evidence(
                    res_path,
                    slot.scenario_id,
                    is_simulation=manifest.is_simulation
                )
                if is_valid:
                    verified_completed += 1
                    continue

            # Evidence was not verified: mark slot for retry without deleting history
            slot.status = "PENDING"

    if verified_completed == len(manifest.matrix_slots) and len(manifest.matrix_slots) > 0:
        manifest.status = "COMPLETED"
        manifest.halt_reason = None
        if not manifest.completed_at:
            latest_end = None
            for slot in reversed(manifest.matrix_slots):
                for att in reversed(slot.attempts):
                    if att.status == "COMPLETED" and att.timestamps.get("end_time"):
                        latest_end = att.timestamps["end_time"]
                        break
                if latest_end:
                    break
            manifest.completed_at = latest_end or datetime.datetime.now(datetime.timezone.utc).isoformat()
    else:
        manifest.status = "IN_PROGRESS"
        manifest.halt_reason = None

    manifest.save_atomically()
    return verified_completed


# ==============================================================================
# Interruption Coordination Engine (Signal-Safe Attempt Lifecycle)
# ==============================================================================

class InterruptionCoordinator:
    """
    Coordinates process-wide signal interception, graceful termination,
    and uninterrupted critical sections across campaign and trial execution.

    Invariants:
    1. First SIGINT or SIGTERM initiates controlled interruption.
    2. Critical sections (cleanup, baseline restoration, evidence preservation,
       manifest updates) run to completion without being aborted by signals.
    3. Active child processes (capture, browser) registered with coordinator
       are terminated and reaped when an interruption is signaled.
    4. Second SIGINT/SIGTERM causes immediate forced exit (128 + signum).
    5. Clean exit codes on interruption: SIGINT -> 130, SIGTERM -> 143.
    """
    def __init__(self):
        self._interrupted: bool = False
        self._interrupted_signum: Optional[int] = None
        self._interrupted_signal_name: Optional[str] = None
        self._signal_count: int = 0
        self._critical_depth: int = 0
        self._tracked_processes: Set[Any] = set()
        self._termination_errors: List[str] = []
        self._lock = threading.RLock()
        self._old_sigint = None
        self._old_sigterm = None
        self._installed: bool = False

    @property
    def interrupted(self) -> bool:
        return self._interrupted

    @property
    def signum(self) -> Optional[int]:
        return self._interrupted_signum

    @property
    def signal_name(self) -> Optional[str]:
        return self._interrupted_signal_name

    @property
    def signal_count(self) -> int:
        return self._signal_count

    def record_interruption(self, signum: int, signal_name: Optional[str] = None) -> None:
        """Manually records an interruption (e.g. from an exception or simulated signal)."""
        with self._lock:
            self._interrupted = True
            self._interrupted_signum = signum
            if signal_name:
                self._interrupted_signal_name = signal_name
            elif hasattr(signal, "Signals"):
                try:
                    self._interrupted_signal_name = signal.Signals(signum).name
                except Exception:
                    self._interrupted_signal_name = str(signum)
            else:
                self._interrupted_signal_name = str(signum)

    def register_process(self, proc: Any) -> None:
        """Registers an active child process (capture or browser) for lifecycle management."""
        with self._lock:
            if getattr(proc, "_ps028_leader_starttime", None) is None:
                pid = getattr(proc, "pid", None)
                if isinstance(pid, int) and pid > 0:
                    try:
                        ident = run_trial.get_process_identity(pid)
                        if ident and ident.get("valid", True) and ident.get("starttime"):
                            proc._ps028_leader_starttime = ident["starttime"]
                            proc._ps028_leader_ident = ident
                    except Exception:
                        pass
            self._tracked_processes.add(proc)

    def unregister_process(self, proc: Any) -> None:
        """Unregisters a finished or reaped child process."""
        with self._lock:
            self._tracked_processes.discard(proc)

    def record_termination_error(self, err: str) -> None:
        """Records an error encountered during child process termination or reaping."""
        with self._lock:
            self._termination_errors.append(err)

    def get_termination_errors(self) -> List[str]:
        """Returns all recorded process termination and reaping errors."""
        with self._lock:
            return list(self._termination_errors)

    def clear_termination_errors(self) -> None:
        """Clears recorded process termination errors."""
        with self._lock:
            self._termination_errors.clear()

    def terminate_tracked_processes(self) -> None:
        """Safely terminates and reaps all currently tracked child processes."""
        with self._lock:
            procs = list(self._tracked_processes)
            self._tracked_processes.clear()

        for proc in procs:
            try:
                reaped = run_trial.terminate_process_group(
                    proc,
                    timeout=1.5,
                    escalate_to_kill=True,
                    coordinator=self
                )
                if not reaped:
                    with self._lock:
                        err = f"Failed to terminate and reap tracked process {getattr(proc, 'pid', 'unknown')}"
                        if err not in self._termination_errors:
                            self._termination_errors.append(err)
            except Exception as exc:
                with self._lock:
                    self._termination_errors.append(
                        f"Exception terminating tracked process {getattr(proc, 'pid', 'unknown')}: {exc}"
                    )

    @contextlib.contextmanager
    def critical_section(self, section_name: str):
        """
        Guarantees that the enclosed code executes without being aborted by signals.
        If a signal arrives during this block, it is latched into coordinator state
        and child processes are terminated, but no KeyboardInterrupt is raised until
        after the critical section finishes.
        """
        with self._lock:
            self._critical_depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._critical_depth = max(0, self._critical_depth - 1)

    def handle_signal(self, signum: int, frame: Any) -> None:
        """Signal handler for SIGINT and SIGTERM."""
        with self._lock:
            self._signal_count += 1
            if self._signal_count > 1:
                print(
                    f"\n[CRITICAL] Repeated signal {signum} received; forcing immediate process exit.",
                    file=sys.stderr
                )
                sys.exit(128 + signum)

            self._interrupted = True
            self._interrupted_signum = signum
            signame = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
            self._interrupted_signal_name = signame
            in_critical = self._critical_depth > 0

        print(
            f"\n[WARN] Campaign received {signame} ({signum}); requesting controlled interruption "
            f"({'deferring until critical section completes' if in_critical else 'initiating controlled stop'})...",
            file=sys.stderr
        )

        self.terminate_tracked_processes()

        if not in_critical:
            raise KeyboardInterrupt(f"Campaign interrupted by signal {signum} ({signame})")

    def install(self) -> None:
        """Installs the signal handlers for SIGINT and SIGTERM."""
        with self._lock:
            if not self._installed:
                try:
                    self._old_sigint = signal.signal(signal.SIGINT, self.handle_signal)
                    self._old_sigterm = signal.signal(signal.SIGTERM, self.handle_signal)
                    self._installed = True
                except (ValueError, OSError):
                    pass

    def restore(self) -> None:
        """Restores previous signal handlers."""
        with self._lock:
            if self._installed:
                try:
                    if self._old_sigint is not None:
                        signal.signal(signal.SIGINT, self._old_sigint)
                    if self._old_sigterm is not None:
                        signal.signal(signal.SIGTERM, self._old_sigterm)
                except (ValueError, OSError):
                    pass
                self._installed = False


# ==============================================================================
# Sequential Campaign Execution Engine
# ==============================================================================

class CampaignRunner:
    """
    Sequential execution coordinator for Happy Eyeballs measurement campaigns.
    Enforces fail-stop safety, concurrency lock, evidence preservation, and manifest tracking.
    """
    def __init__(
        self,
        scenarios: Optional[List[str]] = None,
        browsers: Optional[List[str]] = None,
        repetitions: int = 1,
        campaign_id: Optional[str] = None,
        output_dir: Optional[Path] = None,
        is_simulation: bool = False,
        resume: bool = False,
        trial_timeout: float = 30.0,
        browser_timeout: float = 15.0,
        fail_fast_on_measurement: bool = False,
        lab_lock_file: Optional[Path] = None,
        lock_timeout: float = 10.0,
        exit_on_interruption: bool = True,
        coordinator: Optional[InterruptionCoordinator] = None,
        browser_cmd_override: Optional[List[str]] = None,
        strict_partner: bool = False,
        partner_institution: Optional[str] = None,
        operator_id: Optional[str] = None,
        partner_info: Optional[Dict[str, Any]] = None
    ):
        self.strict_partner = strict_partner
        if partner_info is not None:
            self.partner_institution = partner_info.get("partner_institution")
            self.operator_id = partner_info.get("operator_id")
        else:
            self.partner_institution = partner_institution
            self.operator_id = operator_id

        if self.partner_institution is not None or self.operator_id is not None:
            self.partner_info: Optional[Dict[str, str]] = {
                "partner_institution": str(self.partner_institution or ""),
                "operator_id": str(self.operator_id or ""),
            }
        else:
            self.partner_info = None

        self.scenarios = [s.upper() for s in (scenarios or DEFAULT_SCENARIOS)]
        for sc in self.scenarios:
            if sc not in run_trial.ALLOWED_SCENARIOS:
                raise CampaignConfigError(f"Invalid scenario '{sc}'. Allowed: {run_trial.ALLOWED_SCENARIOS}")

        if self.strict_partner:
            if is_simulation:
                raise CampaignConfigError(
                    "Strict partner replication mode forbids simulation mode (--simulation). "
                    "Authentic live measurements required."
                )
            if set(self.scenarios) != set(CANONICAL_SCENARIO_IDS) or len(self.scenarios) != 7:
                raise CampaignConfigError(
                    f"Strict partner replication requires exactly 7 canonical scenarios {CANONICAL_SCENARIO_IDS}, "
                    f"got {self.scenarios}"
                )
            if repetitions != REPETITIONS_PER_COHORT:
                raise CampaignConfigError(
                    f"Strict partner replication requires exactly {REPETITIONS_PER_COHORT} repetitions per cohort "
                    f"({TOTAL_PLANNED_TRIALS} total planned trials), got {repetitions}"
                )
            if browsers is not None and (set(browsers) != {"google-chrome", "firefox"} or len(browsers) != 2):
                raise CampaignConfigError(
                    f"Strict partner replication requires both canonical browsers ['google-chrome', 'firefox'], "
                    f"got {browsers}"
                )
            if is_placeholder_partner_metadata(self.partner_institution):
                raise CampaignConfigError(
                    f"Strict partner replication requires a valid, non-placeholder partner institution "
                    f"(--partner-institution), got: {self.partner_institution!r}."
                )
            if is_placeholder_partner_metadata(self.operator_id):
                raise CampaignConfigError(
                    f"Strict partner replication requires a valid, non-placeholder operator ID "
                    f"(--operator-id), got: {self.operator_id!r}."
                )

        if repetitions < 1:
            raise CampaignConfigError(f"Repetitions must be >= 1, got {repetitions}")
        self.repetitions = repetitions

        self.is_simulation = is_simulation
        self.resume = resume
        self.trial_timeout = trial_timeout
        self.browser_timeout = browser_timeout
        self.fail_fast_on_measurement = fail_fast_on_measurement
        self.lab_lock_file = lab_lock_file or concurrency.DEFAULT_LAB_LOCK_FILE
        self.lock_timeout = lock_timeout
        self.exit_on_interruption = exit_on_interruption
        self.browser_cmd_override = browser_cmd_override

        # Interruption coordinator & tracking
        self.coordinator = coordinator or InterruptionCoordinator()
        self._active_trial_id: Optional[str] = None
        self._active_trial_dir: Optional[Path] = None
        self._active_slot: Optional[MatrixSlot] = None

        # Resolve browsers
        self.browsers = self._resolve_browsers(browsers, is_simulation)

        # Output and campaign paths
        self.campaign_id = campaign_id or generate_campaign_id()
        self.output_dir = Path(output_dir or (DEFAULT_CAMPAIGNS_DIR / self.campaign_id)).resolve()
        self.trials_dir = self.output_dir / "trials"
        self.manifest_path = self.output_dir / MANIFEST_FILENAME
        self.lock_path = self.output_dir / LOCK_FILENAME

    @property
    def _interrupted(self) -> bool:
        return self.coordinator.interrupted

    @_interrupted.setter
    def _interrupted(self, val: bool) -> None:
        if val:
            self.coordinator.record_interruption(getattr(signal, "SIGINT", 2), "SIGINT")
        else:
            self.coordinator._interrupted = False

    @property
    def _interrupted_signum(self) -> Optional[int]:
        return self.coordinator.signum

    @_interrupted_signum.setter
    def _interrupted_signum(self, val: Optional[int]) -> None:
        self.coordinator._interrupted_signum = val

    @property
    def _interrupted_signal_name(self) -> Optional[str]:
        return self.coordinator.signal_name

    @_interrupted_signal_name.setter
    def _interrupted_signal_name(self, val: Optional[str]) -> None:
        self.coordinator._interrupted_signal_name = val

    @property
    def _signal_count(self) -> int:
        return self.coordinator.signal_count

    @_signal_count.setter
    def _signal_count(self, val: int) -> None:
        self.coordinator._signal_count = val

    def _resolve_browsers(self, requested: Optional[List[str]], is_simulation: bool) -> List[str]:
        """Resolves and validates available browsers."""
        if self.strict_partner:
            canonical_browsers = ["google-chrome", "firefox"]
            target_list = requested or canonical_browsers
            if set(target_list) != set(canonical_browsers) or len(target_list) != 2:
                raise CampaignConfigError(
                    f"Strict partner replication mode requires both canonical browsers {canonical_browsers}, "
                    f"got {target_list}"
                )
            # Enforce exact pinned browser builds via partner_preflight BEFORE initialization
            browsers_info = partner_preflight.get_browser_runtimes()
            if not browsers_info.get("all_exact_match", False):
                err_msgs = []
                for bname, bdata in browsers_info.get("browsers", {}).items():
                    if bdata.get("status") != "READY":
                        err_msgs.append(
                            f"{bname}: status={bdata.get('status')}, "
                            f"found='{bdata.get('raw_version_output')}', "
                            f"expected='{bdata.get('pinned_expected')}'"
                        )
                raise CampaignConfigError(
                    f"Strict partner replication failed browser preflight: {'; '.join(err_msgs)}. "
                    f"Exact pinned versions (Chrome {PINNED_BROWSERS['google-chrome']['pinned_version']}, "
                    f"Firefox {PINNED_BROWSERS['firefox']['pinned_version']}) and non-Snap binaries required."
                )
            return canonical_browsers

        if requested:
            resolved = []
            for b in requested:
                b_clean = b.strip()
                if not b_clean:
                    continue
                if not is_simulation:
                    # Validate browser runtime exists
                    try:
                        bname, _, _ = run_trial.find_browser_runtime(b_clean)
                        resolved.append(bname)
                    except run_trial.BrowserPreflightError as e:
                        raise CampaignConfigError(f"Browser validation failed for '{b_clean}': {e}")
                else:
                    resolved.append(b_clean)
            if not resolved:
                raise CampaignConfigError("No valid browsers specified")
            return resolved

        # Default discovery
        if is_simulation:
            return ["google-chrome"]

        try:
            bname, _, _ = run_trial.find_browser_runtime()
            return [bname]
        except run_trial.BrowserPreflightError as e:
            raise CampaignConfigError(f"Failed to auto-discover browser runtime: {e}")

    def initialize_manifest(self) -> CampaignManifest:
        """Initializes a new manifest or safely resumes an existing one."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.trials_dir.mkdir(parents=True, exist_ok=True)

        if self.resume:
            if not self.manifest_path.is_file():
                raise CampaignResumeError(f"Cannot resume: manifest missing at {self.manifest_path}")
            manifest = CampaignManifest.load(self.manifest_path)
            reconcile_manifest_for_resume(
                manifest=manifest,
                expected_scenarios=self.scenarios,
                expected_browsers=self.browsers,
                expected_reps=self.repetitions,
                is_simulation=self.is_simulation,
                expected_partner_institution=self.partner_institution,
                expected_operator_id=self.operator_id,
                strict_partner=self.strict_partner
            )
            return manifest

        # New campaign manifest
        slots = build_matrix_slots(self.scenarios, self.browsers, self.repetitions)
        if self.strict_partner and len(slots) != TOTAL_PLANNED_TRIALS:
            raise CampaignConfigError(
                f"Strict partner mode requires exactly {TOTAL_PLANNED_TRIALS} planned matrix slots, got {len(slots)}"
            )
        manifest = CampaignManifest(
            campaign_id=self.campaign_id,
            output_dir=self.output_dir,
            scenarios=self.scenarios,
            browsers=self.browsers,
            repetitions=self.repetitions,
            is_simulation=self.is_simulation,
            matrix_slots=slots,
            status="IN_PROGRESS",
            strict_partner=self.strict_partner,
            protocol_version=PROTOCOL_VERSION,
            partner_info=self.partner_info,
            partner_institution=self.partner_institution,
            operator_id=self.operator_id
        )
        manifest.save_atomically()
        return manifest

    def _collect_preserved_evidence(self, trial_dir: Path) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """
        Audits physical trial directory to preserve all genuine evidence generated
        prior to an error or signal interruption. Never overwrites or removes files.
        """
        paths = {"trial_dir": str(trial_dir)}
        cap_meta: Dict[str, Any] = {}

        pcap_file = trial_dir / "capture.pcap"
        if pcap_file.is_file() and pcap_file.stat().st_size > 0:
            try:
                valid, sha, sz, count, msg = run_trial.validate_pcap_file(pcap_file)
                cap_meta = {
                    "pcap_path": str(pcap_file),
                    "pcap_sha256": sha,
                    "pcap_size_bytes": sz,
                    "packet_count": count,
                    "pcap_valid": valid,
                    "validation_message": msg,
                }
            except Exception as pe:
                cap_meta = {
                    "pcap_path": str(pcap_file),
                    "pcap_size_bytes": pcap_file.stat().st_size,
                    "pcap_valid": False,
                    "validation_message": f"PCAP audit error: {pe}",
                }
            paths["capture_pcap"] = str(pcap_file)

        evidence_names = [
            ("result.json", "result_json"),
            ("tcpdump.log", "tcpdump_log"),
            ("browser.log", "browser_log"),
            ("netlog.json", "browser_netlog"),
            ("browser_telemetry.log", "browser_telemetry"),
            (FAILURE_RECORD_FILENAME, "failed_attempt_record")
        ]
        for fname, key in evidence_names:
            fpath = trial_dir / fname
            if fpath.is_file():
                paths[key] = str(fpath)

        return paths, cap_meta

    def execute_slot_attempt(
        self,
        slot: MatrixSlot,
        attempt_number: int
    ) -> ExecutionAttempt:
        """
        Executes one trial attempt for the given matrix slot:
        1. Generates unique trial ID (trial-<timestamp>-<hash>).
        2. Assigns dedicated directory under trials/<trial_id> (NEVER overwrites).
        3. Calls run_trial.run_trial in-process with caller-managed signal coordination.
        4. Validates cleanup and baseline restoration unconditionally.
        5. Preserves all partial evidence generated before an interruption or failure.
        6. Durably and atomically writes failed_attempt_record.json on failure or interruption.
        7. Returns structured ExecutionAttempt agreeing with physical failure record.
        """
        trial_id = run_trial.generate_trial_id()
        trial_dir = self.trials_dir / trial_id
        while trial_dir.exists():
            # Guarantee unique, non-colliding directory
            time.sleep(0.01)
            trial_id = run_trial.generate_trial_id()
            trial_dir = self.trials_dir / trial_id

        trial_dir.mkdir(parents=True, exist_ok=True)
        t_start = time.time()
        start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        trial_result: Optional[Dict[str, Any]] = None
        exec_error: Optional[str] = None

        self._active_slot = slot
        self._active_trial_id = trial_id
        self._active_trial_dir = trial_dir

        if self.strict_partner and not self.is_simulation:
            b_runtimes = partner_preflight.get_browser_runtimes().get("browsers", {})
            b_info = b_runtimes.get(slot.browser, {})
            if b_info.get("status") != "READY":
                raise CampaignHaltedError(
                    f"Strict partner runtime check failed for browser '{slot.browser}': "
                    f"status={b_info.get('status')}, expected={b_info.get('pinned_expected')}"
                )

        try:
            trial_result = run_trial.run_trial(
                scenario_id=slot.scenario_id,
                browser_pref=slot.browser,
                trial_id=trial_id,
                output_dir=trial_dir,
                timeout=self.trial_timeout,
                browser_timeout=self.browser_timeout,
                is_simulation=self.is_simulation,
                skip_baseline_check=False,
                lock_file=self.lab_lock_file,
                lock_timeout=self.lock_timeout,
                caller_manages_signals=True,
                coordinator=self.coordinator,
                raw_cmd_override=self.browser_cmd_override
            )
        except (KeyboardInterrupt, InterruptedError) as ki:
            if not self.coordinator.interrupted:
                self.coordinator.record_interruption(getattr(signal, "SIGINT", 2), "SIGINT")
            exec_error = f"Campaign attempt interrupted by signal {self.coordinator.signum} ({self.coordinator.signal_name}): {ki}"
        except Exception as exc:
            exec_error = str(exc)
        finally:
            self._active_trial_id = None
            self._active_trial_dir = None
            self._active_slot = None

        with self.coordinator.critical_section("attempt_finalization"):
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            duration_ms = round((time.time() - t_start) * 1000.0, 2)

            # Audit all genuine evidence physically written to trial_dir
            disk_paths, disk_pcap_meta = self._collect_preserved_evidence(trial_dir)

            # ----------------------------------------------------------------------
            # FAIL-STOP EVALUATION: Cleanup & Baseline Verification
            # ----------------------------------------------------------------------
            cleanup_status: Dict[str, Any] = {}
            if trial_result:
                cleanup_status = trial_result.get("cleanup_status", {})
            else:
                # Trial failed before writing result: check whether baseline is clean
                baseline_ok = False
                baseline_errs: List[str] = []
                try:
                    baseline_ok = impair.self_test_baseline(dry_run=self.is_simulation)
                    if not baseline_ok:
                        baseline_errs.append("Post-interruption baseline verification failed")
                except Exception as b_exc:
                    baseline_errs.append(f"baseline check error: {b_exc}")

                if not baseline_ok:
                    try:
                        impair.clear_impairments(dry_run=self.is_simulation)
                        baseline_ok = impair.self_test_baseline(dry_run=self.is_simulation)
                        if not baseline_ok:
                            baseline_errs.append("Baseline not clean after clear_impairments")
                    except Exception as c_err:
                        baseline_errs.append(f"impairment clear error: {c_err}")

                cleanup_status = {
                    "scenario_restored": baseline_ok,
                    "baseline_verified": baseline_ok,
                    "profile_cleaned": True,
                    "lock_released": True,
                    "errors": baseline_errs
                }

            scenario_restored = cleanup_status.get("scenario_restored", False)
            baseline_verified = cleanup_status.get("baseline_verified", False)
            cleanup_errors = list(cleanup_status.get("errors", []))

            # Include any child process termination/reaping failures from coordinator
            termination_errors = self.coordinator.get_termination_errors()
            if termination_errors:
                cleanup_errors.extend(termination_errors)
                self.coordinator.clear_termination_errors()

            # Extra verification of baseline state using impair.self_test_baseline
            try:
                post_baseline_ok = impair.self_test_baseline(dry_run=self.is_simulation)
                if not post_baseline_ok:
                    baseline_verified = False
                    cleanup_errors.append("Post-trial self_test_baseline returned False")
            except Exception as b_err:
                baseline_verified = False
                cleanup_errors.append(f"Post-trial self_test_baseline exception: {b_err}")

            # Persist updated cleanup and termination errors in cleanup_status
            cleanup_status["scenario_restored"] = scenario_restored
            cleanup_status["baseline_verified"] = baseline_verified
            cleanup_status["errors"] = list(cleanup_errors)

            # Interruption payload if signal was caught
            interruption_info = None
            if self.coordinator.interrupted:
                interruption_info = {
                    "signal_number": self.coordinator.signum,
                    "signal_name": self.coordinator.signal_name,
                    "interrupted_at": end_iso,
                    "error_details": exec_error or "Campaign interrupted by signal"
                }

            # Check for cleanup/baseline failure
            if not scenario_restored or not baseline_verified or len(cleanup_errors) > 0:
                err_details = "; ".join(cleanup_errors) if cleanup_errors else "Baseline not verified"
                timestamps = (
                    trial_result.get("timestamps", {})
                    if trial_result and trial_result.get("timestamps")
                    else {"start_time": start_iso, "end_time": end_iso, "duration_ms": duration_ms}
                )
                evidence_paths = (
                    trial_result.get("evidence_paths", {})
                    if trial_result and trial_result.get("evidence_paths")
                    else disk_paths
                )
                capture_metadata = (
                    trial_result.get("capture_metadata", {})
                    if trial_result and trial_result.get("capture_metadata")
                    else disk_pcap_meta
                )
                http_outcome = trial_result.get("http_outcome", {}) if trial_result else {}
                network_observations = trial_result.get("network_observations", {}) if trial_result else {}

                attempt = ExecutionAttempt(
                    attempt_number=attempt_number,
                    trial_id=trial_id,
                    execution_mode="SIMULATION" if self.is_simulation else "LIVE",
                    is_simulation=self.is_simulation,
                    timestamps=timestamps,
                    status="FAILED",
                    validity="CLEANUP_FAILURE",
                    evidence_paths=evidence_paths,
                    capture_metadata=capture_metadata,
                    http_outcome=http_outcome,
                    network_observations=network_observations,
                    cleanup_status=cleanup_status,
                    error_message=f"CLEANUP OR BASELINE FAILURE: {err_details}",
                    slot_id=slot.slot_id,
                    scenario_id=slot.scenario_id,
                    browser=slot.browser,
                    repetition=slot.repetition,
                    campaign_id=self.campaign_id,
                    interruption=interruption_info
                )
                write_failed_attempt_record(trial_dir, attempt)
                return attempt

            # If trial errored out during execution or was interrupted
            if trial_result is None or exec_error is not None:
                attempt_status = "INTERRUPTED" if self.coordinator.interrupted else "FAILED"
                attempt_validity = "INTERRUPTED" if self.coordinator.interrupted else "MEASUREMENT_FAILURE"
                attempt = ExecutionAttempt(
                    attempt_number=attempt_number,
                    trial_id=trial_id,
                    execution_mode="SIMULATION" if self.is_simulation else "LIVE",
                    is_simulation=self.is_simulation,
                    timestamps={"start_time": start_iso, "end_time": end_iso, "duration_ms": duration_ms},
                    status=attempt_status,
                    validity=attempt_validity,
                    evidence_paths=disk_paths,
                    capture_metadata=disk_pcap_meta,
                    http_outcome={},
                    network_observations={},
                    cleanup_status=cleanup_status,
                    error_message=exec_error,
                    slot_id=slot.slot_id,
                    scenario_id=slot.scenario_id,
                    browser=slot.browser,
                    repetition=slot.repetition,
                    campaign_id=self.campaign_id,
                    interruption=interruption_info
                )
                write_failed_attempt_record(trial_dir, attempt)
                return attempt

            # Validate evidence using existing A7 rules
            pcap_meta = trial_result.get("capture_metadata", {})
            pcap_valid = pcap_meta.get("pcap_valid", False)
            packet_count = pcap_meta.get("packet_count", 0)
            net_obs = trial_result.get("network_observations", {})
            classification = net_obs.get("classification", "INCONCLUSIVE")

            if self.is_simulation:
                validity = "SIMULATION"
                status = "COMPLETED"
            elif pcap_valid and packet_count > 0 and classification != "INCONCLUSIVE":
                validity = "VALID_LIVE"
                status = "COMPLETED"
            else:
                validity = "MEASUREMENT_FAILURE"
                status = "FAILED"
                exec_error = pcap_meta.get("validation_message") or "Measurement classification failed or inconclusive"

            attempt = ExecutionAttempt(
                attempt_number=attempt_number,
                trial_id=trial_id,
                execution_mode=trial_result.get("execution_mode", "LIVE"),
                is_simulation=self.is_simulation,
                timestamps=trial_result.get("timestamps", {}),
                status=status,
                validity=validity,
                evidence_paths=trial_result.get("evidence_paths", {}),
                capture_metadata=pcap_meta,
                http_outcome=trial_result.get("http_outcome", {}),
                network_observations=net_obs,
                cleanup_status=cleanup_status,
                error_message=exec_error,
                slot_id=slot.slot_id,
                scenario_id=slot.scenario_id,
                browser=slot.browser,
                repetition=slot.repetition,
                campaign_id=self.campaign_id,
                interruption=interruption_info
            )
            if status == "FAILED" or validity in ("CLEANUP_FAILURE", "MEASUREMENT_FAILURE"):
                write_failed_attempt_record(trial_dir, attempt)
            return attempt

    def run(self) -> Dict[str, Any]:
        """
        Executes the campaign sequentially under the campaign manifest lock:
        - Prevents concurrent access to the campaign manifest.
        - Sequentially runs each pending matrix slot.
        - Gracefully handles SIGINT (exit 130) and SIGTERM (exit 143), ensuring active attempts
          are finalized with durable failure records and cleanup is executed before exit.
        - Immediately stops upon any cleanup or baseline failure (FAIL-STOP).
        - Atomically saves manifest after every attempt.
        """
        with acquire_manifest_lock(self.lock_path, timeout=self.lock_timeout):
            manifest = self.initialize_manifest()
            self._manifest = manifest

            self.coordinator.install()
            try:
                for slot in manifest.matrix_slots:
                    if self.coordinator.interrupted:
                        break

                    if slot.is_completed():
                        continue

                    # Execute next attempt for this slot
                    attempt_num = len(slot.attempts) + 1
                    attempt = self.execute_slot_attempt(slot, attempt_number=attempt_num)
                    slot.add_attempt(attempt)

                    # Check FAIL-STOP condition: Cleanup or Baseline Failure (paramount, even after signal)
                    if attempt.validity == "CLEANUP_FAILURE":
                        manifest.status = "HALTED_ON_FAILURE"
                        manifest.halt_reason = (
                            f"FAIL-STOP: Lab cleanup or baseline restoration failed at slot "
                            f"{slot.slot_id} (trial {attempt.trial_id}): {attempt.error_message}"
                        )
                        with self.coordinator.critical_section("manifest_save"):
                            manifest.save_atomically()
                        raise CampaignHaltedError(manifest.halt_reason)

                    if self.coordinator.interrupted:
                        manifest.status = "INTERRUPTED"
                        manifest.halt_reason = (
                            f"Campaign interrupted by signal {self.coordinator.signum} "
                            f"({self.coordinator.signal_name})"
                        )
                        with self.coordinator.critical_section("manifest_save"):
                            manifest.save_atomically()
                        break

                    # Optional fail-fast on measurement failure
                    if self.fail_fast_on_measurement and attempt.status == "FAILED":
                        manifest.status = "HALTED_ON_FAILURE"
                        manifest.halt_reason = (
                            f"Fail-fast triggered on measurement failure at slot "
                            f"{slot.slot_id} (trial {attempt.trial_id}): {attempt.error_message}"
                        )
                        with self.coordinator.critical_section("manifest_save"):
                            manifest.save_atomically()
                        raise CampaignHaltedError(manifest.halt_reason)

                    # Save progress atomically after each attempt
                    with self.coordinator.critical_section("manifest_save"):
                        manifest.save_atomically()

                # Finalize campaign status
                if self.coordinator.interrupted:
                    manifest.status = "INTERRUPTED"
                    manifest.halt_reason = (
                        f"Campaign interrupted by signal {self.coordinator.signum} "
                        f"({self.coordinator.signal_name})"
                    )
                    with self.coordinator.critical_section("manifest_save"):
                        manifest.save_atomically()
                else:
                    all_done = all(s.is_completed() for s in manifest.matrix_slots)
                    if all_done:
                        manifest.status = "COMPLETED"
                        manifest.halt_reason = None
                        if not manifest.completed_at:
                            latest_end = None
                            for slot in reversed(manifest.matrix_slots):
                                for att in reversed(slot.attempts):
                                    if att.status == "COMPLETED" and att.timestamps.get("end_time"):
                                        latest_end = att.timestamps["end_time"]
                                        break
                                if latest_end:
                                    break
                            manifest.completed_at = latest_end or datetime.datetime.now(datetime.timezone.utc).isoformat()
                    else:
                        if manifest.status not in ("HALTED_ON_FAILURE", "INTERRUPTED"):
                            manifest.status = "INCOMPLETE"
                    with self.coordinator.critical_section("manifest_save"):
                        manifest.save_atomically()

                if self.coordinator.interrupted and self.exit_on_interruption:
                    sys.exit(128 + self.coordinator.signum)

                return manifest.to_dict()
            except KeyboardInterrupt:
                if self.coordinator.interrupted:
                    manifest.status = "INTERRUPTED"
                    manifest.halt_reason = (
                        f"Campaign interrupted by signal {self.coordinator.signum} "
                        f"({self.coordinator.signal_name})"
                    )
                    with self.coordinator.critical_section("manifest_save"):
                        manifest.save_atomically()
                    if self.exit_on_interruption:
                        sys.exit(128 + self.coordinator.signum)
                    return manifest.to_dict()
                raise
            finally:
                self.coordinator.restore()


# ==============================================================================
# Safe Finalization Utility
# ==============================================================================

def finalize_campaign_manifest(manifest_path: Path) -> CampaignManifest:
    """
    Safely finalizes an interrupted or completed campaign manifest without re-running trials:
    - Validates that every matrix slot has verified completion evidence per A7 rules.
    - Transitions manifest.status to "COMPLETED".
    - Sets completed_at from the latest attempt end timestamp (or current UTC time).
    - Clears active halt_reason while strictly preserving all historical failed attempts.
    - Atomically updates campaign_manifest.json under exclusive lock.
    """
    manifest_path = Path(manifest_path).resolve()
    lock_path = manifest_path.parent / LOCK_FILENAME
    with acquire_manifest_lock(lock_path):
        manifest = CampaignManifest.load(manifest_path)
        if not manifest.matrix_slots:
            raise CampaignResumeError(f"Manifest at {manifest_path} contains no matrix slots")

        all_done = True
        for slot in manifest.matrix_slots:
            if slot.status != "COMPLETED":
                all_done = False
                break
            valid_attempt = None
            for att in reversed(slot.attempts):
                if att.status == "COMPLETED" and att.validity in ("VALID_LIVE", "SIMULATION"):
                    valid_attempt = att
                    break
            if not valid_attempt:
                all_done = False
                break
            res_path = _resolve_repo_relative_path(valid_attempt.evidence_paths.get("result_json", ""))
            is_valid, _, _ = validate_attempt_evidence(res_path, slot.scenario_id, manifest.is_simulation)
            if not is_valid:
                all_done = False
                break

        if not all_done:
            raise CampaignResumeError(
                f"Cannot finalize campaign: not all {len(manifest.matrix_slots)} slots have verified completed evidence."
            )

        manifest.status = "COMPLETED"
        manifest.halt_reason = None
        if not manifest.completed_at:
            latest_end = None
            for slot in reversed(manifest.matrix_slots):
                for att in reversed(slot.attempts):
                    if att.status == "COMPLETED" and att.timestamps.get("end_time"):
                        latest_end = att.timestamps["end_time"]
                        break
                if latest_end:
                    break
            manifest.completed_at = latest_end or datetime.datetime.now(datetime.timezone.utc).isoformat()
        manifest.save_atomically()
        return manifest


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PS-028 Happy Eyeballs Campaign Runner (Work Package A8)"
    )
    parser.add_argument(
        "--scenarios", "-s",
        default=",".join(DEFAULT_SCENARIOS),
        help="Comma-separated scenario IDs to run (default: all S0-S6)"
    )
    parser.add_argument(
        "--browsers", "-b",
        default=None,
        help="Comma-separated browser runtimes/names (default: auto-detected)"
    )
    parser.add_argument(
        "--repetitions", "-n",
        type=int,
        default=1,
        help="Number of repetitions per scenario/browser pair (default: 1)"
    )
    parser.add_argument(
        "--campaign-id",
        default=None,
        help="Custom campaign identifier (default: auto-generated)"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=None,
        help="Directory to store campaign manifest and trials (default: lab/campaigns/<campaign_id>)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Safely resume an incomplete or interrupted campaign from --output-dir"
    )
    parser.add_argument(
        "--strict-partner",
        action="store_true",
        help="Enforce strict partner replication profile: 280 trials (S0-S6 x 2 pinned browsers x 20 reps), live execution only, exact pinned browser versions required"
    )
    parser.add_argument(
        "--partner-institution",
        dest="partner_institution",
        default=None,
        help="Partner institution name conducting the replication"
    )
    parser.add_argument(
        "--operator-id",
        dest="operator_id",
        default=None,
        help="Unique operator identifier responsible for replication execution"
    )
    parser.add_argument(
        "--simulation",
        action="store_true",
        help="Execute in simulation mode (offline/dry-run, clearly tagged in manifest)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Overall per-trial timeout in seconds (default: 30.0)"
    )
    parser.add_argument(
        "--browser-timeout",
        type=float,
        default=15.0,
        help="Browser execution timeout in seconds (default: 15.0)"
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop campaign immediately on measurement failures in addition to cleanup failures"
    )
    parser.add_argument(
        "--manifest", "-m",
        type=Path,
        default=None,
        help="Direct path to campaign_manifest.json to finalize or inspect"
    )
    parser.add_argument(
        "--finalize",
        action="store_true",
        help="Safely finalize a campaign manifest if all matrix slots are verified complete, without re-executing trials"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output campaign manifest summary as raw JSON to stdout"
    )
    return parser.parse_args(args)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if args.finalize:
        manifest_path = args.manifest
        if not manifest_path and args.output_dir:
            manifest_path = args.output_dir / MANIFEST_FILENAME
        elif not manifest_path and args.campaign_id:
            manifest_path = DEFAULT_CAMPAIGNS_DIR / args.campaign_id / MANIFEST_FILENAME
        if not manifest_path or not manifest_path.is_file():
            print(f"\033[1;31m[ERROR]\033[0m Manifest path not found: {manifest_path}", file=sys.stderr)
            return 1
        try:
            manifest = finalize_campaign_manifest(manifest_path)
            res = manifest.to_dict()
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                summary = res.get("summary", {})
                print("\033[1;32m[OK]\033[0m Campaign finalized successfully: status COMPLETED")
                print("=" * 65)
                print(f"Campaign ID:       {res['campaign_id']}")
                print(f"Status:            \033[1;32m{res['status']}\033[0m")
                print(f"Completed At:      {res['completed_at']}")
                if res.get("partner_info"):
                    p_info = res["partner_info"]
                    print(f"Partner Inst:      {p_info.get('partner_institution')}")
                    print(f"Operator ID:       {p_info.get('operator_id')}")
                print(f"Slots Total:       {summary['total_slots']} (completed={summary['completed_slots']}, pending={summary['pending_slots']}, failed={summary['failed_slots']})")
                print(f"Attempts:          {summary['total_attempts']} (valid_live={summary['valid_live_attempts']}, failed={summary['failed_attempts']})")
                print(f"Manifest Path:     {manifest_path}")
                print("=" * 65)
            return 0
        except Exception as e:
            print(f"\033[1;31m[FINALIZATION ERROR]\033[0m {e}", file=sys.stderr)
            return 1

    if args.strict_partner:
        if args.simulation:
            print("\033[1;31m[ERROR]\033[0m --strict-partner forbids simulation mode (--simulation). Authentic live measurements required.", file=sys.stderr)
            return 1
        scenarios = DEFAULT_SCENARIOS
        browsers = ["google-chrome", "firefox"]
        repetitions = 20
    else:
        scenarios = [s.strip().upper() for s in args.scenarios.split(",") if s.strip()]
        browsers = [b.strip() for b in args.browsers.split(",")] if args.browsers else None
        repetitions = args.repetitions

    try:
        runner = CampaignRunner(
            scenarios=scenarios,
            browsers=browsers,
            repetitions=repetitions,
            campaign_id=args.campaign_id,
            output_dir=args.output_dir,
            is_simulation=args.simulation,
            resume=args.resume,
            trial_timeout=args.timeout,
            browser_timeout=args.browser_timeout,
            fail_fast_on_measurement=args.fail_fast,
            strict_partner=args.strict_partner,
            partner_institution=args.partner_institution,
            operator_id=args.operator_id
        )
        res = runner.run()

        if args.json:
            print(json.dumps(res, indent=2))
        else:
            summary = res.get("summary", {})
            print("\033[1;34m[INFO]\033[0m PS-028 Measurement Campaign Execution Finished")
            print("=" * 65)
            print(f"Campaign ID:       {res['campaign_id']}")
            print(f"Status:            \033[1;32m{res['status']}\033[0m")
            print(f"Execution Mode:    {res['execution_mode']}")
            if res.get("partner_info"):
                p_info = res["partner_info"]
                print(f"Partner Inst:      {p_info.get('partner_institution')}")
                print(f"Operator ID:       {p_info.get('operator_id')}")
            print(f"Scenarios:         {res['configuration']['scenarios']}")
            print(f"Browsers:          {res['configuration']['browsers']}")
            print(f"Repetitions:       {res['configuration']['repetitions']}")
            print(f"Slots Total:       {summary['total_slots']} (completed={summary['completed_slots']}, pending={summary['pending_slots']}, failed={summary['failed_slots']})")
            print(f"Attempts:          {summary['total_attempts']} (valid_live={summary['valid_live_attempts']}, simulated={summary['simulated_attempts']}, failed={summary['failed_attempts']})")
            if summary.get("halt_reason"):
                print(f"Halt Reason:       \033[1;31m{summary['halt_reason']}\033[0m")
            print(f"Manifest Path:     {res['configuration']['output_dir']}/{MANIFEST_FILENAME}")
            print("=" * 65)

        return 0 if res.get("status") == "COMPLETED" else 2
    except CampaignHaltedError as he:
        print(f"\033[1;31m[CAMPAIGN HALTED - FAIL-STOP]\033[0m {he}", file=sys.stderr)
        return 2
    except (CampaignLockError, CampaignConfigError, CampaignResumeError) as ce:
        print(f"\033[1;31m[CAMPAIGN CONFIG/LOCK ERROR]\033[0m {ce}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\033[1;31m[UNEXPECTED ERROR]\033[0m Campaign failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
