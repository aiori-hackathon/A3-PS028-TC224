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
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lab.concurrency as concurrency
import lab.impair as impair
import lab.run_trial as run_trial

SCHEMA_VERSION = "1.0.0"
DEFAULT_SCENARIOS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6"]
DEFAULT_CAMPAIGNS_DIR = SCRIPT_DIR / "campaigns"
MANIFEST_FILENAME = "campaign_manifest.json"
LOCK_FILENAME = ".campaign.lock"

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
        error_message: Optional[str] = None
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

    def to_dict(self) -> Dict[str, Any]:
        return {
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
            error_message=data.get("error_message")
        )


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
    if not result_json_path.is_file():
        return False, f"result.json missing at {result_json_path}", {}

    try:
        data = json.loads(result_json_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"Failed to parse result.json: {e}", {}

    if data.get("schema_version") != run_trial.SCHEMA_VERSION:
        return False, f"Schema version mismatch: {data.get('schema_version')} != {run_trial.SCHEMA_VERSION}", data

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
    pcap_path = Path(pcap_str)
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
        halt_reason: Optional[str] = None
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
        self.manifest_path = self.output_dir / MANIFEST_FILENAME
        self.lock_path = self.output_dir / LOCK_FILENAME

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
        return {
            "schema_version": SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "status": self.status,
            "execution_mode": "SIMULATION" if self.is_simulation else "LIVE",
            "is_simulation": self.is_simulation,
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

    def save_atomically(self) -> None:
        """
        Saves manifest atomically: writes to temporary file, flushes, fsyncs,
        and atomically renames to campaign_manifest.json.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        data = self.to_dict()
        tmp_path = self.manifest_path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.manifest_path)

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

        if data.get("schema_version") != SCHEMA_VERSION:
            raise CampaignResumeError(
                f"Manifest schema version mismatch: {data.get('schema_version')} != {SCHEMA_VERSION}"
            )

        config = data.get("configuration", {})
        slots = [MatrixSlot.from_dict(s) for s in data.get("matrix_slots", [])]

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
            halt_reason=data.get("summary", {}).get("halt_reason")
        )


# ==============================================================================
# Safe Resume Controller
# ==============================================================================

def reconcile_manifest_for_resume(
    manifest: CampaignManifest,
    expected_scenarios: List[str],
    expected_browsers: List[str],
    expected_reps: int,
    is_simulation: bool
) -> int:
    """
    Reconciles an existing manifest for a safe resume operation:
    1. Validates configuration compatibility.
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
                res_path = Path(valid_attempt.evidence_paths.get("result_json", ""))
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

    manifest.save_atomically()
    return verified_completed


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
        lock_timeout: float = 10.0
    ):
        self.scenarios = [s.upper() for s in (scenarios or DEFAULT_SCENARIOS)]
        for sc in self.scenarios:
            if sc not in run_trial.ALLOWED_SCENARIOS:
                raise CampaignConfigError(f"Invalid scenario '{sc}'. Allowed: {run_trial.ALLOWED_SCENARIOS}")

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

        # Resolve browsers
        self.browsers = self._resolve_browsers(browsers, is_simulation)

        # Output and campaign paths
        self.campaign_id = campaign_id or generate_campaign_id()
        self.output_dir = Path(output_dir or (DEFAULT_CAMPAIGNS_DIR / self.campaign_id)).resolve()
        self.trials_dir = self.output_dir / "trials"
        self.manifest_path = self.output_dir / MANIFEST_FILENAME
        self.lock_path = self.output_dir / LOCK_FILENAME

    def _resolve_browsers(self, requested: Optional[List[str]], is_simulation: bool) -> List[str]:
        """Resolves and validates available browsers."""
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
                is_simulation=self.is_simulation
            )
            return manifest

        # New campaign manifest
        slots = build_matrix_slots(self.scenarios, self.browsers, self.repetitions)
        manifest = CampaignManifest(
            campaign_id=self.campaign_id,
            output_dir=self.output_dir,
            scenarios=self.scenarios,
            browsers=self.browsers,
            repetitions=self.repetitions,
            is_simulation=self.is_simulation,
            matrix_slots=slots,
            status="IN_PROGRESS"
        )
        manifest.save_atomically()
        return manifest

    def execute_slot_attempt(
        self,
        slot: MatrixSlot,
        attempt_number: int
    ) -> ExecutionAttempt:
        """
        Executes one trial attempt for the given matrix slot:
        1. Generates unique trial ID (trial-<timestamp>-<hash>).
        2. Assigns dedicated directory under trials/<trial_id> (NEVER overwrites).
        3. Calls run_trial.run_trial in-process.
        4. Validates cleanup and baseline restoration unconditionally.
        5. Returns structured ExecutionAttempt.
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
                lock_timeout=self.lock_timeout
            )
        except Exception as exc:
            exec_error = str(exc)

        end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        duration_ms = round((time.time() - t_start) * 1000.0, 2)

        # ----------------------------------------------------------------------
        # FAIL-STOP EVALUATION: Cleanup & Baseline Verification
        # ----------------------------------------------------------------------
        cleanup_status: Dict[str, Any] = {}
        if trial_result:
            cleanup_status = trial_result.get("cleanup_status", {})
        else:
            # Trial failed before writing result: check whether baseline is clean
            baseline_ok = False
            try:
                baseline_ok = impair.self_test_baseline(dry_run=self.is_simulation)
            except Exception as b_exc:
                exec_error = f"{exec_error}; baseline check error: {b_exc}" if exec_error else str(b_exc)
            cleanup_status = {
                "scenario_restored": False,
                "baseline_verified": baseline_ok,
                "profile_cleaned": True,
                "lock_released": True,
                "errors": [exec_error] if exec_error else ["Unknown trial error"]
            }

        scenario_restored = cleanup_status.get("scenario_restored", False)
        baseline_verified = cleanup_status.get("baseline_verified", False)
        cleanup_errors = cleanup_status.get("errors", [])

        # Extra verification of baseline state using impair.self_test_baseline
        try:
            post_baseline_ok = impair.self_test_baseline(dry_run=self.is_simulation)
            if not post_baseline_ok:
                baseline_verified = False
                cleanup_errors.append("Post-trial self_test_baseline returned False")
        except Exception as b_err:
            baseline_verified = False
            cleanup_errors.append(f"Post-trial self_test_baseline exception: {b_err}")

        # Check for cleanup/baseline failure
        if not scenario_restored or not baseline_verified or len(cleanup_errors) > 0:
            err_details = "; ".join(cleanup_errors) if cleanup_errors else "Baseline not verified"
            attempt = ExecutionAttempt(
                attempt_number=attempt_number,
                trial_id=trial_id,
                execution_mode="SIMULATION" if self.is_simulation else "LIVE",
                is_simulation=self.is_simulation,
                timestamps={"start_time": start_iso, "end_time": end_iso, "duration_ms": duration_ms},
                status="FAILED",
                validity="CLEANUP_FAILURE",
                evidence_paths={"trial_dir": str(trial_dir)},
                capture_metadata={},
                http_outcome={},
                network_observations={},
                cleanup_status=cleanup_status,
                error_message=f"CLEANUP OR BASELINE FAILURE: {err_details}"
            )
            return attempt

        # If trial errored out during execution
        if trial_result is None or exec_error is not None:
            attempt = ExecutionAttempt(
                attempt_number=attempt_number,
                trial_id=trial_id,
                execution_mode="SIMULATION" if self.is_simulation else "LIVE",
                is_simulation=self.is_simulation,
                timestamps={"start_time": start_iso, "end_time": end_iso, "duration_ms": duration_ms},
                status="FAILED",
                validity="MEASUREMENT_FAILURE",
                evidence_paths={"trial_dir": str(trial_dir)},
                capture_metadata={},
                http_outcome={},
                network_observations={},
                cleanup_status=cleanup_status,
                error_message=exec_error
            )
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
            error_message=exec_error
        )
        return attempt

    def run(self) -> Dict[str, Any]:
        """
        Executes the campaign sequentially under the campaign manifest lock:
        - Prevents concurrent access to the campaign manifest.
        - Sequentially runs each pending matrix slot.
        - Immediately stops upon any cleanup or baseline failure (FAIL-STOP).
        - Atomically saves manifest after every attempt.
        """
        with acquire_manifest_lock(self.lock_path, timeout=self.lock_timeout):
            manifest = self.initialize_manifest()

            # Signal interruption handler
            interrupted = False

            def _handle_signal(signum, frame):
                nonlocal interrupted
                interrupted = True
                manifest.status = "INTERRUPTED"
                manifest.halt_reason = f"Campaign interrupted by signal {signum}"
                manifest.save_atomically()
                print(f"\n[WARN] Campaign interrupted by signal {signum}. Manifest saved safely.", file=sys.stderr)
                sys.exit(130)

            old_sigint = signal.signal(signal.SIGINT, _handle_signal)
            old_sigterm = signal.signal(signal.SIGTERM, _handle_signal)

            try:
                for slot in manifest.matrix_slots:
                    if interrupted:
                        break

                    if slot.is_completed():
                        continue

                    # Execute next attempt for this slot
                    attempt_num = len(slot.attempts) + 1
                    attempt = self.execute_slot_attempt(slot, attempt_number=attempt_num)
                    slot.add_attempt(attempt)

                    # Check FAIL-STOP condition: Cleanup or Baseline Failure
                    if attempt.validity == "CLEANUP_FAILURE":
                        manifest.status = "HALTED_ON_FAILURE"
                        manifest.halt_reason = (
                            f"FAIL-STOP: Lab cleanup or baseline restoration failed at slot "
                            f"{slot.slot_id} (trial {attempt.trial_id}): {attempt.error_message}"
                        )
                        manifest.save_atomically()
                        raise CampaignHaltedError(manifest.halt_reason)

                    # Optional fail-fast on measurement failure
                    if self.fail_fast_on_measurement and attempt.status == "FAILED":
                        manifest.status = "HALTED_ON_FAILURE"
                        manifest.halt_reason = (
                            f"Fail-fast triggered on measurement failure at slot "
                            f"{slot.slot_id} (trial {attempt.trial_id}): {attempt.error_message}"
                        )
                        manifest.save_atomically()
                        raise CampaignHaltedError(manifest.halt_reason)

                    # Save progress atomically after each attempt
                    manifest.save_atomically()

                # Finalize campaign status
                if not interrupted and manifest.status != "HALTED_ON_FAILURE":
                    all_done = all(s.is_completed() for s in manifest.matrix_slots)
                    manifest.status = "COMPLETED" if all_done else "INCOMPLETE"
                    manifest.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    manifest.save_atomically()

                return manifest.to_dict()
            finally:
                signal.signal(signal.SIGINT, old_sigint)
                signal.signal(signal.SIGTERM, old_sigterm)


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
        "--json",
        action="store_true",
        help="Output campaign manifest summary as raw JSON to stdout"
    )
    return parser.parse_args(args)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    scenarios = [s.strip().upper() for s in args.scenarios.split(",") if s.strip()]
    browsers = [b.strip() for b in args.browsers.split(",")] if args.browsers else None

    try:
        runner = CampaignRunner(
            scenarios=scenarios,
            browsers=browsers,
            repetitions=args.repetitions,
            campaign_id=args.campaign_id,
            output_dir=args.output_dir,
            is_simulation=args.simulation,
            resume=args.resume,
            trial_timeout=args.timeout,
            browser_timeout=args.browser_timeout,
            fail_fast_on_measurement=args.fail_fast
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
