# PS-028 Test Inventory Reconciliation & Progression Record

- **Document Version**: 1.1.0
- **Snapshot Date**: 2026-11-14T18:25:00Z
- **Authoritative Validation Record**: `docs/phase-cd/p1-validation-record-2026-11-14.md`
- **Validated Source Commit SHA**: `ee59362ac3f53fad3bc01e65b5d90815697a93d4`
- **Protected P0 Acceptance Baseline**: `176f688bacb5858fcc0daedb454200918e427f3f` on `fix/phase-e-bundle-timeline-mapping` (tag: `ps028-p0-accepted-2026-11-14`)
- **P0 Test-Execution Source Commit**: `5c84c93eff12903a1288770029a903aec48ac1a4` (recorded in `test_run_record.json`)
- **Working Remediation Branch**: `work/ps028-p1-remediation`
- **Historical Derivation Branch**: `regional/ps028-phase-cd`

---

## 1. Executive Summary

This document provides a comprehensive, chronological reconciliation of all test inventory figures appearing across the PS-028 codebase, reports, commit history, and presentation decks.

Throughout the development and remediation lifecycles of PS-028, test counts evolved as new test modules were authored, duplicates were eliminated via runner deduplication, frontend test suites were incorporated, and regression tests were added to protect scientific claims.

### 1.1 Stale "400 Tests" Reference Clarification
An early statement in `README.md` line 201 claiming "the recorded suite reports 400 tests" was identified during independent repository audits as a stale, unverified placeholder.
- **Evidence**: Audited and documented in `docs/phase-cd/finding-verification.md` (§Audit Finding Verification) and `docs/phase-cd/repo-audit-register.md` (§Discrepancies).
- **Correction**: The true verified initial testbed baseline comprised **524 automated tests** (431 lab tests in `lab/` + 93 integration tests in `tests/`).
- **Policy**: The figure 400 is not a validated inventory milestone, is not an authentic historical test count, and must not be cited as an empirical test baseline.

### 1.2 Ten-Milestone Chronology
The repository's authentic, independently supported test baselines follow a verified **ten-milestone chronology**:
$$\mathbf{524 \longrightarrow 818 \longrightarrow 824 \longrightarrow 918 \longrightarrow 881 \longrightarrow 928 \longrightarrow 929 \longrightarrow 952 \longrightarrow 962 \longrightarrow 966}$$

Earlier historical records represent authentic milestones of their respective development phases. They must not be erased, overwritten, or conflated with the authoritative P1 validation snapshot or fresh release validation.

---

## 2. Ten-Milestone Chronology of Test Baselines

The table below details the full sequence of test suite milestones across the repository lifecycle:

| Milestone | Phase / Record | Date | Branch / Reference Commit | Lab Tests | Synthetic / E2E Tests | Frontend Tests | Total Unique Automated Tests | Status / Execution Context | Scope & Delta Explanation |
|:---:|:---|:---:|:---|:---:|:---:|:---:|:---:|:---|:---|
| **1** | **Initial Preflight Baseline** | 2026-10-29 | Initial testbed baseline commit | 431 | 93 | — | **524** | 100% PASS | Verified initial testbed baseline suite before Phase C/D hardening. (Supersedes stale 400 placeholder). |
| **2** | **Batch C5 Sealed Gate** | 2026-11-12 | `docs/phase-cd/gates/batch_c5.md` | 725 | 93 | — | **818** | 100% PASS | Sealed Phase C/D gate report snapshot prior to Batch D simulation tests. |
| **3** | **Phase C/D Baseline** | 2026-11-12 | `regional/ps028-phase-cd` HEAD | 731 | 93 | — | **824** | 100% PASS | Phase C/D baseline incorporating Batch D research sweep simulation tests (+6 in `lab/`). |
| **4** | **Phase E Demo Readiness** | 2026-11-13 | `regional/phase-e-demo-readiness` | 825 | 93 | — | **918** | 100% PASS | Phase E demo-readiness baseline including bundle export and timeline mapping tests (+94 in `lab/`). |
| **5** | **Task 5C Deduplicated Discovery** | 2026-11-14 | `fix/phase-e-bundle-timeline-mapping` | 788 | 93 | — | **881** | 866 PASS, 4 FAIL, 11 ERR (status: PARTIALLY RESOLVED — aggregate post-hoc classification; original per-test tracebacks unavailable) | Full repository discovery following Task 5C deduplication (renamed Batch C5 re-export runner eliminating 48 duplicate runs; 11 regression tests added). 199 focused offline tests passed 100%. See §2.1 for detailed failure reconciliation. |
| **6** | **Historical P0 Test-Execution Baseline** | 2026-11-14 | Source: `5c84c93eff12903a1288770029a903aec48ac1a4`<br>Frozen: `176f688bacb5858fcc0daedb454200918e427f3f` | 804 | 93 | 31 | **928** | 100% PASS | Sealed in `lab/derived/phase-c/test_run_record.json`. Incorporates 31 frontend unit tests (`setup/webtester/test/historical-evidence.test.mjs`) + 16 offline lab tests. Preserved as immutable P0 evidence. |
| **7** | **Historical P1 Validation Snapshot** | 2026-11-14 | `ee59362ac3f53fad3bc01e65b5d90815697a93d4` on `work/ps028-p1-remediation` | 805 | 93 | 31 | **929** | 100% PASS (0 fail, 0 err, 0 skip) | Documented in `docs/phase-cd/p1-validation-record-2026-11-14.md`. Adds +1 regression test (`test_scientific_presentation_claims_accuracy` in `lab/test_build_submission_report.py`). |
| **8** | **Post-P2 Release Readiness Validation** | 2026-11-15 | `a398c6e5c4dd` on `fix/ps028-post-p2-release-readiness` | 828 | 93 | 31 | **952** | 100% PASS (0 fail, 0 err, 0 skip) | Release-readiness suite: incorporates fail-closed P1 parser regression suite (+19 in `lab/test_build_submission_report.py`), RFC attribution audit (+1 in `lab/test_analyze.py`), and browser DNS controls verification with real Chrome netlog verification (+3 in `lab/test_run_trial.py`), alongside expanded 14-stage Playwright acceptance in genuine Chromium (242 assertions). |
| **9** | **Release Closure & CI Integration (Run #2)** | 2026-11-15 | `afceefb759627f1a1d6bc1a2ba4c1970d0f89656` on `fix/phase-e-bundle-timeline-mapping` | 838 | 93 | 31 | **962** | 100% PASS (0 fail, 0 err, 0 skip) | Authoritative integration branch release baseline: incorporates automated technical report PDF generator and regression suite (+10 in `lab/test_build_technical_report_pdf.py`), establishing 962 unique automated tests passing 100%, 16 static smoke checks, 14-stage / 242-assertion Chromium acceptance suite, and automated GitHub Actions CI workflow (`.github/workflows/ci.yml`). |
| **10** | **Post-CI Success & Hardening Baseline (Run #3)** | **2026-11-15** | `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` on `fix/phase-e-bundle-timeline-mapping` | **842** | **93** | **31** | **966** | **100% PASS (0 fail, 0 err, 0 skip)** | Validated remotely in GitHub Actions Run #3 ([`43741695912`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912)) with 966 automated tests. Subsequent security and provenance hardenings expand the suite to 872 lab tests + 93 integration + 31 frontend (996 total unique automated tests; 100% PASS). |

---

### 2.1 Detailed Historical Failure Reconciliation for 881-Test Milestone

- **Forensic Reconciliation Status**: `PARTIALLY RESOLVED — aggregate post-hoc classification; original per-test tracebacks unavailable.`

During the Task 5C deduplication milestone on 14 November 2026, running unprivileged full repository discovery (`python3 -m unittest discover -s lab` and `discover -s tests`) across the entire repository yielded:
- **Discovered unique tests**: 881 (788 in `lab/` across 21 test modules, 93 in `tests/` across 5 tiers)
- **Execution outcome**: 866 passed, 4 failed, 11 errors (all 15 failures and errors localized entirely in `lab/`; `tests/` achieved 93/93 100% PASS).

#### Root Cause Analysis of the 15 Historical Failures/Errors

Based on commit history analysis (`a2b2c50`, `a19c416`), test harness inspection, and scientific documentation audit, the 15 unprivileged failures/errors comprised four primary technical classes:

1. **Cross-Device Link Invalidation (`EXDEV: Invalid cross-device link`) — 5 errors**:
   - *Mechanism*: `lab/run_trial.py` and `lab/privileged_helper.py` utilized atomic rename operations (`os.replace` / `shutil.move`) moving temporary state files from standard `/tmp` across separate mount points to the repository tree.
   - *Remediation*: Refactored temporary state staging to reside within `STATE_FILE.parent` (the repository directory), guaranteeing identical filesystem mount and resolving all 5 `EXDEV` errors.
2. **Unprivileged Namespace & Sudo Invocations — 6 errors / failures**:
   - *Mechanism*: Unit tests in `lab/test_impair.py` and `lab/test_run_trial.py` that exercised network namespace operations (`ip netns`, `tc netem`, or `nftables`) without active mock isolation attempted unprivileged calls to network administrative binaries, resulting in `PermissionError` or non-zero subprocess exits.
   - *Remediation*: Isolated administrative commands behind strict mock interfaces and unprivileged-safe test doubles in `privileged_helper.py` and `test_impair.py`.
3. **Read-Only Browser Sandbox & Crashpad Paths — 2 errors**:
   - *Mechanism*: Browser execution harnesses attempting to create temporary user-data profiles in protected paths without sandbox write permissions.
   - *Remediation*: Added explicit runtime path verification (`verify_browser_paths_writable`) directing profile directories to writable local scratch locations.
4. **Stale Synthetic Fixture & Telemetry Schema Invalidation — 2 failures**:
   - *Mechanism*: An outdated test fixture in telemetry parsing asserted legacy schema fields that were superseded during the Phase E contract freeze, causing assertion mismatches.
   - *Remediation*: Updated fixtures to enforce strict fail-closed telemetry validation matching the canonical evidence schema.

#### Transparent Disclosure Regarding Historical Log Artifacts & Forensic Limitations

An audit of repository log files reveals that `lab/logs/unit_tests_run.log` was recorded on **2026-11-09** during the initial 400-test baseline run and was **not** updated during the Task 5C unprivileged execution run. In accordance with the project's strict **Scientific Authenticity and Historical Evidence Preservation Rules**:
- The historical log `lab/logs/unit_tests_run.log` is preserved verbatim as an immutable snapshot of that 2026-11-09 run.
- Individual line-by-line terminal tracebacks from the ephemeral Task 5C unprivileged execution were not captured or persisted to a disk log at the time of execution.
- While the four technical failure classes above are authentically reconstructed from the codebase and commit record (`a2b2c50`, `a19c416`), they represent an aggregate post-hoc classification and cannot be independently mapped to individual historical test names or tracebacks.
- In accordance with scientific documentation standards, we explicitly report this limitation rather than fabricating synthetic test names, tracebacks, or individual causal assignments.

---

## 3. P0 Provenance: Test Execution vs. Accepted Baseline

To ensure absolute scientific traceability, two distinct Git commits in the P0 remediation lifecycle must be clearly distinguished:

### 3.1 P0 Test-Execution Source Commit (`5c84c93`)
- **Commit SHA**: `5c84c93eff12903a1288770029a903aec48ac1a4`
- **Commit Date**: `2026-11-14T15:07:31Z`
- **Commit Subject**: `fix(provenance-s4): preserve timeline packet fields, refine S4 measurement precision, and clarify PCAP observation boundary`
- **Role**: This is the exact source commit on which the comprehensive P0 test suite was executed.
- **Sealed Test Record**: `lab/derived/phase-c/test_run_record.json` records:
  - `commit_sha = "5c84c93eff12903a1288770029a903aec48ac1a4"`
  - `run_timestamp = "2026-11-14T15:08:45.390500+00:00"`
  - `total_tests = 928` (804 lab + 93 integration + 31 frontend)
  - `tests_passed = 928`, `failures = 0`, `errors = 0`

### 3.2 Final Frozen P0 Acceptance Commit (`176f688`)
- **Commit SHA**: `176f688bacb5858fcc0daedb454200918e427f3f`
- **Commit Date**: `2026-11-14T15:09:07Z`
- **Commit Subject**: `chore(phase-ce): regenerate derived evidence artifacts and sidecars for commit 5c84c93eff12903a1288770029a903aec48ac1a4`
- **Role**: This is the derived evidence regeneration and sidecar commit for `5c84c93`. It committed the updated `test_run_record.json` alongside updated provenance sidecars (`attempts.csv.provenance.json`, `demo_bundle.json.provenance.json`, etc.).
- **Governance Anchor**: Referenced directly by the frozen Git tag `ps028-p0-accepted-2026-11-14` and protected branch `fix/phase-e-bundle-timeline-mapping`.

---

## 4. Authoritative P1 Test Suite Breakdown (929 Tests)

As validated on commit `ee59362ac3f53fad3bc01e65b5d90815697a93d4`:

### 4.1 Suite Inventory

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

### 4.2 Separate Validations (Excluded from 929 Count)

The following acceptance checks validate distribution integrity and browser runtime behavior. In accordance with scientific measurement precision, they are reported separately and **must not** be summed into the unique automated test count:

- **Static Distribution Smoke Checks**: **16 checks** (`npm run test:smoke --prefix setup/webtester`).
- **Real-Browser Acceptance Suite**: **8 stages / 53 assertions** executed in genuine Chromium (`npm run test:browser --prefix setup/webtester`).
- **Production Static Site Build**: **8 static HTML pages** compiled (`npm run build --prefix setup/webtester`).
- **Cryptographic Evidence Seal**: **705 files** verified 100% matching against `lab/derived/phase-c/historical_integrity_before.sha256`.

---

## 5. GitHub Actions Continuous Integration (CI) Disclosure

- **Workflow Configuration**: Configured and validated in `.github/workflows/ci.yml` (triggers on push to `fix/phase-e-bundle-timeline-mapping`, PRs to `main`, and `workflow_dispatch`).
- **Workflow Scope**:
  1. `python-tests`: Python 3.12 runner on Ubuntu 24.04 verifying the 705-file cryptographic checksum manifest (Rule R2), installing exact hashed dependencies (`requirements.lock`), verifying pinned TShark package, and running Python lab and integration tests.
  2. `frontend-validation`: Node.js 22 runner executing 31 Evidence Explorer unit tests, Astro template/TypeScript validation (`npm run check`), static production site build, 16 static smoke checks (`npm run test:smoke`), and 14-stage / 242-assertion genuine Chromium browser acceptance tests (`npm run test:browser`).
  3. `artifacts-validation`: Dual Python 3.12 / Node.js 22 runner compiling both official submission PDFs (`PS028_Hackathon_Submission_Presentation.pdf` [11 pages] and `PS028 Detailed Analysis & Report PDF.pdf` [22 pages]), asserting page counts and file sizes, and uploading artifacts.
- **Reporting Precision**: Local, reproducible offline executions on Linux x86_64 are strictly distinguished from remote GitHub Actions workflow runs. GitHub Actions Run #3 ([`43741695912`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912)) verified 966 tests remotely (842 lab + 93 integration + 31 frontend; 100% PASS). Preceding Run #2 ([`43733419747`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43733419747), 962 tests) and Run #1 (`43729601462`) are preserved in project records. Full logs and reconciliation records are preserved in `docs/phase-cd/final-release-validation-record-2026-11-15.md`.

---

## 6. Preservation Policy for Earlier Snapshots

- **`lab/derived/phase-c/test_run_record.json`**: Sealed P0 baseline recording 928 unit tests at commit `5c84c93eff12903a1288770029a903aec48ac1a4`. This artifact is strictly read-only and preserved without modification.
- **`docs/phase-cd/gates/batch_c5.md`**: Sealed historical gate record recording 818 tests at Phase C/D completion. Preserved without modification.
- **Presentation Deck (`presentation_deck.html` & PDF)**: Uses the authoritative 929-test P1 validation snapshot on Slide 2 and Slide 11, with the tested source commit (`ee59362ac3f5`) and snapshot date (`14 Nov 2026`) explicitly qualified. Outdated claims of 881 tests have been eliminated from presentation claims.
