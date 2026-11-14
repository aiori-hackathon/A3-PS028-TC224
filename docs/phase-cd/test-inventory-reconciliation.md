# PS-028 Test Inventory Reconciliation & Progression Record

- **Document Version**: 1.0.0
- **Snapshot Date**: 2026-11-14T17:30:00Z
- **Authoritative Validation Record**: `docs/phase-cd/p1-validation-record-2026-11-14.md`
- **Validated Source Commit SHA**: `ee59362ac3f53fad3bc01e65b5d90815697a93d4`
- **Protected P0 Baseline**: `176f688bacb5858fcc0daedb454200918e427f3f` on `fix/phase-e-bundle-timeline-mapping` (tag: `ps028-p0-accepted-2026-11-14`)
- **Working Remediation Branch**: `work/ps028-p1-remediation`
- **Historical Derivation Branch**: `regional/ps028-phase-cd`

---

## 1. Executive Summary

This document provides a comprehensive, chronological reconciliation of all test inventory figures appearing across the PS-028 codebase, reports, commit history, and presentation decks.

Throughout the development and remediation lifecycles of PS-028, test counts evolved as new test modules were authored, duplicates were eliminated via runner deduplication, frontend test suites were incorporated, and regression tests were added to protect scientific claims.

Earlier test counts (e.g., 400, 524, 818, 824, 918, 881, 928) represent authentic historical milestones. They must not be erased, overwritten, or conflated with the authoritative P1 validation snapshot.

---

## 2. Chronological Progression of Test Inventories

The table below details the full sequence of test suite milestones across the repository lifecycle:

| Tier | Milestone / Record | Date | Branch / Reference Commit | Lab Tests | Synthetic / E2E Tests | Frontend Tests | Total Unique Automated Tests | Status / Execution Context | Scope & Delta Explanation |
|:---|:---|:---:|:---|:---:|:---:|:---:|:---:|:---|:---|
| **0** | Preflight Baseline | 2026-10-29 | Historical initial commit | 431 | 93 | — | **524** | 100% PASS | Initial testbed baseline suite before Phase C/D hardening. |
| **1** | Batch C5 Gate | 2026-11-12 | `docs/phase-cd/gates/batch_c5.md` | 725 | 93 | — | **818** | 100% PASS | Sealed Phase C/D gate report snapshot prior to Batch D simulation tests. |
| **2** | Phase C/D Baseline | 2026-11-12 | `regional/ps028-phase-cd` HEAD | 731 | 93 | — | **824** | 100% PASS | Phase C/D baseline incorporating Batch D research sweep simulation tests (+6 in `lab/`). |
| **3** | Phase E Demo Readiness | 2026-11-13 | `regional/phase-e-demo-readiness` | 825 | 93 | — | **918** | 100% PASS | Phase E demo-readiness baseline including bundle export and timeline mapping tests (+94 in `lab/`). |
| **4** | Task 5C Deduplicated Discovery | 2026-11-14 | `fix/phase-e-bundle-timeline-mapping` | 788 | 93 | — | **881** | 866 PASS, 4 FAIL, 11 ERR (unprivileged sandbox) | Full repository discovery following Task 5C deduplication (renamed Batch C5 re-export runner eliminating 48 duplicate runs; 11 regression tests added). 199 focused offline tests passed 100%. |
| **5** | Historical P0 Sealed Baseline | 2026-11-14 | `5c84c93eff12903a1288770029a903aec48ac1a4` | 804 | 93 | 31 | **928** | 100% PASS | Sealed in `lab/derived/phase-c/test_run_record.json`. Incorporates 31 frontend unit tests (`setup/webtester/test/historical-evidence.test.mjs`) + 16 offline lab tests. Preserved as immutable P0 evidence. |
| **6** | **Authoritative P1 Validation Snapshot** | **2026-11-14** | `ee59362ac3f53fad3bc01e65b5d90815697a93d4` | **805** | **93** | **31** | **929** | **100% PASS (0 fail, 0 err, 0 skip)** | Documented in `docs/phase-cd/p1-validation-record-2026-11-14.md`. Adds +1 regression test (`test_scientific_presentation_claims_accuracy` in `lab/test_build_submission_report.py`). |

---

## 3. Authoritative P1 Test Suite Breakdown (929 Tests)

As validated on commit `ee59362ac3f53fad3bc01e65b5d90815697a93d4`:

### 3.1 Suite Inventory

1. **Lab Automated Suite (`lab/test_*.py`)**:
   - **805 tests** across 21 test modules.
   - Command: `python3 -m unittest discover -s lab -p "test_*.py"`
   - Result: 805 passed, 0 failures, 0 errors.

2. **Integration & Adversarial Suite (`tests/test_*.py`)**:
   - **93 tests** across 5 tiers (Unit, Integration, E2E, Synthetic, Adversarial).
   - Command: `python3 -m unittest discover -s tests -p "test_*.py"`
   - Result: 93 passed, 0 failures, 0 errors.

3. **Frontend Evidence Verification Suite (`setup/webtester/test/historical-evidence.test.mjs`)**:
   - **31 tests** covering bundle schema, cryptographic SHA-256 integrity, cohort grouping, median calculations, CAD formulas, and invariant checks.
   - Command: `npm test --prefix setup/webtester`
   - Result: 31 passed, 0 failures, 0 errors.

**Total Unique Automated Tests**: $805 + 93 + 31 = \mathbf{929}$ unique test definitions.

### 3.2 Separate Validations (Excluded from 929 Count)

The following acceptance checks validate distribution integrity and browser runtime behavior. In accordance with scientific measurement precision, they are reported separately and **must not** be summed into the unique automated test count:

- **Static Distribution Smoke Checks**: **16 checks** (`npm run test:smoke --prefix setup/webtester`).
- **Real-Browser Acceptance Suite**: **8 stages / 53 assertions** executed in genuine Chromium (`npm run test:browser --prefix setup/webtester`).
- **Production Static Site Build**: **8 static HTML pages** compiled (`npm run build --prefix setup/webtester`).
- **Cryptographic Evidence Seal**: **705 files** verified 100% matching against `lab/derived/phase-c/historical_integrity_before.sha256`.

---

## 4. Remote CI Disclosure

- **Remote CI Pipeline**: **NOT CONFIGURED / NOT RECORDED**.
- All reported passes reflect local, reproducible offline executions on Linux x86_64 within the project worktree. Local offline test pass rates must never be reported as remote CI passes.

---

## 5. Preservation Policy for Earlier Snapshots

- **`lab/derived/phase-c/test_run_record.json`**: Sealed P0 baseline recording 928 unit tests at commit `5c84c93eff12903a1288770029a903aec48ac1a4`. This artifact is strictly read-only and preserved without modification.
- **`docs/phase-cd/gates/batch_c5.md`**: Sealed historical gate record recording 818 tests at Phase C/D completion. Preserved without modification.
- **Presentation Deck (`presentation_deck.html` & PDF)**: Uses the authoritative 929-test P1 validation snapshot on Slide 2 and Slide 11, with the tested source commit (`ee59362ac3f5`) and snapshot date (`14 Nov 2026`) explicitly qualified. Outdated claims of 881 tests have been eliminated from presentation claims.
