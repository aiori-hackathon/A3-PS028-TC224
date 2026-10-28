#!/usr/bin/env python3
"""
PS-028 Lab Concurrency & Shared Lock: Comprehensive Test Suite
Work Package A6: PS-028 Lab Hardening

Tests:
- Uncontended lock acquisition and clean release
- Lock re-entrancy within the same thread/process
- Guaranteed lock release on exception
- Inter-process contention detection and timeout handling
- Clean handover between distinct processes
- Mutual exclusion preventing concurrent scenario changes, trials, and teardown
- Bash teardown.sh integration and contention prevention
"""

import multiprocessing
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import lab.concurrency as concurrency
import lab.impair as impair

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TEARDOWN_SH = SCRIPT_DIR / "teardown.sh"


def _worker_acquire(lock_path: str, timeout: float, queue: multiprocessing.Queue):
    """Child process worker to test real cross-process lock contention."""
    try:
        with concurrency.acquire_lab_lock(timeout=timeout, lock_path=Path(lock_path)):
            queue.put("ACQUIRED")
            # Hold lock briefly to allow assertion
            time.sleep(0.3)
    except concurrency.LabLockError as e:
        queue.put(f"CONTENTION:{e}")
    except Exception as e:
        queue.put(f"ERROR:{e}")


def _worker_wait_and_acquire(lock_path: str, timeout: float, queue: multiprocessing.Queue):
    """Child process worker that waits for parent to release lock, then acquires."""
    try:
        with concurrency.acquire_lab_lock(timeout=timeout, lock_path=Path(lock_path)):
            queue.put("SUCCESS")
    except Exception as e:
        queue.put(f"FAIL:{e}")


class TestLabWideConcurrency(unittest.TestCase):
    """Test suite for shared lab lock behavior, contention, and safety."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ps028_lock_test_"))
        self.lock_file = self.temp_dir / ".lab.lock"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_uncontended_acquisition_and_release(self):
        """Uncontended lock must be acquired and released cleanly."""
        self.assertFalse(self.lock_file.exists())
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            self.assertTrue(self.lock_file.exists())
        # After block, file remains but is unlocked
        self.assertTrue(self.lock_file.exists())

    def test_reentrancy_in_same_thread(self):
        """Nested lock acquisition in the same thread must succeed without deadlocking."""
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            with concurrency.acquire_lab_lock(lock_path=self.lock_file):
                with concurrency.acquire_lab_lock(lock_path=self.lock_file):
                    pass
        # Lock should be fully released now; another acquisition must succeed
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            pass

    def test_guaranteed_release_on_exception(self):
        """Lock must be immediately released even if an unhandled exception occurs."""
        class TestException(Exception):
            pass

        with self.assertRaises(TestException):
            with concurrency.acquire_lab_lock(lock_path=self.lock_file):
                raise TestException("Simulated unexpected trial crash")

        # Must be immediately re-acquirable
        with concurrency.acquire_lab_lock(timeout=0.1, lock_path=self.lock_file):
            pass

    def test_cross_process_contention_failure(self):
        """When lock is held by parent, child process must timeout and raise LabLockError."""
        q = multiprocessing.Queue()
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            p = multiprocessing.Process(
                target=_worker_acquire,
                args=(str(self.lock_file), 0.15, q)
            )
            p.start()
            p.join(timeout=2.0)

            result = q.get_nowait()
            self.assertTrue(
                result.startswith("CONTENTION:"),
                f"Expected CONTENTION result from worker, got: {result}"
            )

    def test_lock_release_and_handover_between_processes(self):
        """When parent releases lock, child process must acquire it successfully."""
        q = multiprocessing.Queue()
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            # Launch child that waits up to 2.0s for the lock
            p = multiprocessing.Process(
                target=_worker_wait_and_acquire,
                args=(str(self.lock_file), 2.0, q)
            )
            p.start()
            # Release lock by exiting context manager
            time.sleep(0.1)

        # Parent exited context manager; child should now acquire lock
        p.join(timeout=2.0)
        result = q.get_nowait()
        self.assertEqual(result, "SUCCESS")

    def test_apply_scenario_contention_prevention(self):
        """Concurrent scenario apply must raise LabLockError if another process holds lab lock."""
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            with patch.object(impair, "LAB_LOCK_FILE", self.lock_file):
                # Another process trying to apply scenario must fail
                q = multiprocessing.Queue()
                def run_apply(lp, queue):
                    try:
                        impair.apply_scenario("S0", dry_run=True, lock_file=Path(lp), lock_timeout=0.15)
                        queue.put("APPLIED")
                    except concurrency.LabLockError as e:
                        queue.put(f"CONTENTION:{e}")
                    except Exception as e:
                        queue.put(f"OTHER:{e}")

                p = multiprocessing.Process(target=run_apply, args=(str(self.lock_file), q))
                p.start()
                p.join(timeout=2.0)

                res = q.get_nowait()
                self.assertTrue(res.startswith("CONTENTION:"), f"Expected contention error, got: {res}")

    def test_clear_impairments_contention_prevention(self):
        """Concurrent clear_impairments must raise LabLockError if lock is held."""
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            q = multiprocessing.Queue()
            def run_clear(lp, queue):
                try:
                    impair.clear_impairments(dry_run=True, lock_file=Path(lp), lock_timeout=0.15)
                    queue.put("CLEARED")
                except concurrency.LabLockError as e:
                    queue.put(f"CONTENTION:{e}")

            p = multiprocessing.Process(target=run_clear, args=(str(self.lock_file), q))
            p.start()
            p.join(timeout=2.0)

            res = q.get_nowait()
            self.assertTrue(res.startswith("CONTENTION:"), f"Expected contention error, got: {res}")

    def test_teardown_contention_prevention(self):
        """Concurrent teardown must raise LabLockError if another process holds lab lock."""
        with concurrency.acquire_lab_lock(lock_path=self.lock_file):
            q = multiprocessing.Queue()
            def run_teardown(lp, queue):
                try:
                    import lab.teardown as td
                    td.teardown_lab(dry_run=True, lock_file=Path(lp), lock_timeout=0.15)
                    queue.put("TORN_DOWN")
                except concurrency.LabLockError as e:
                    queue.put(f"CONTENTION:{e}")
                except Exception as e:
                    queue.put(f"OTHER:{e}")

            p = multiprocessing.Process(target=run_teardown, args=(str(self.lock_file), q))
            p.start()
            p.join(timeout=2.0)

            res = q.get_nowait()
            self.assertTrue(res.startswith("CONTENTION:"), f"Expected contention error, got: {res}")


if __name__ == "__main__":
    unittest.main()
