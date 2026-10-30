#!/usr/bin/env python3
"""
PS-028 Lab Concurrency & Shared Lock Controller
Work Package A6: PS-028 Lab Hardening

Provides a shared lab-wide lock (.lab.lock) preventing concurrent scenario changes,
measurement trials, and teardown operations.
Guarantees strict safety:
- Exclusive non-blocking flock with configurable timeout
- No bypass of active locks under any circumstance
- Clean, unconditional lock release on normal exit or exception
- Process-isolated re-entrancy within the same thread
- POSIX-compliant file permissions and flock semantics
"""

import contextlib
import fcntl
import os
from pathlib import Path
import threading
import time
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_LAB_LOCK_FILE = SCRIPT_DIR / ".lab.lock"


class LabLockError(Exception):
    """Raised when the lab-wide lock cannot be acquired within the specified timeout."""
    pass


# Thread-local storage to track re-entrancy safely per process and thread
_LOCAL_LOCK_TRACKER = threading.local()


def _get_thread_locks() -> dict:
    current_pid = os.getpid()
    held = getattr(_LOCAL_LOCK_TRACKER, "held", None)
    if held is None or held.get("pid") != current_pid:
        held = {"pid": current_pid, "locks": {}}
        _LOCAL_LOCK_TRACKER.held = held
    return held["locks"]


def is_lock_held_by_current_thread(lock_path: Optional[Path] = None) -> bool:
    """Returns True if the lock is held by the current thread in this process."""
    target = Path(lock_path or DEFAULT_LAB_LOCK_FILE).resolve()
    locks = _get_thread_locks()
    return target in locks and locks[target].get("count", 0) > 0


def is_lock_active(lock_path: Optional[Path] = None) -> bool:
    """
    Probes whether the lock is currently held by any process via non-blocking flock.
    Does not modify or keep the lock.
    """
    target = Path(lock_path or DEFAULT_LAB_LOCK_FILE).resolve()
    if not target.exists():
        return False
    try:
        fd = os.open(str(target), os.O_RDWR)
    except PermissionError:
        fd = os.open(str(target), os.O_RDONLY)
    except OSError:
        return False

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Lock was not held
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        return False
    except (BlockingIOError, OSError):
        os.close(fd)
        return True



@contextlib.contextmanager
def acquire_lab_lock(timeout: float = 5.0, lock_path: Optional[Path] = None):
    """
    Acquire an exclusive lab-wide lock preventing concurrent scenario changes,
    trials, and teardown.

    Parameters:
      timeout: Maximum duration (seconds) to wait before raising LabLockError.
      lock_path: Custom lock file path (defaults to lab/.lab.lock).
    """
    target = Path(lock_path or DEFAULT_LAB_LOCK_FILE).resolve()
    locks = _get_thread_locks()

    # Re-entrancy check for the same thread in the same process
    if target in locks:
        locks[target]["count"] += 1
        try:
            yield
        finally:
            locks[target]["count"] -= 1
            if locks[target]["count"] <= 0:
                del locks[target]
        return

    # First acquisition in this thread
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
                    raise LabLockError(
                        f"Cannot acquire shared lab lock on {target}: held by another scenario change, "
                        "trial, or teardown process. Refusing to bypass active lock."
                    )
                time.sleep(0.02)

        locks[target] = {"fd": fd, "count": 1}
        yield
    finally:
        if acquired:
            if target in locks:
                locks[target]["count"] -= 1
                if locks[target]["count"] <= 0:
                    del locks[target]
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass
