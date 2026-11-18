#!/usr/bin/env python3
"""
Adversarial Challenge & Stress-Test Suite for Milestone 4: Batch C5
Focus: Fail-Closed DNS Reload Protocol & Machine-Readable Evidence Bundle Lifecycle

Exports and executes the Tier 5 adversarial stress test suite from tests/test_tier5_adversarial_c5.py.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.test_tier5_adversarial_c5 import (
    TestAdversarialDNSReloadFaultInjections,
    TestAdversarialEvidenceBundleLifecycle,
)
from lab.test_c5_statistical_and_evidence_separation import (
    TestClopperPearsonMathematicalRigor,
    TestEvidenceSeparationRigor,
    TestParameterBoundsAndGovernance,
)

if __name__ == "__main__":
    import unittest
    unittest.main()
