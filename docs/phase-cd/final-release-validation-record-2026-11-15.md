# PS-028 Final Release Validation Record

- **Document Version**: 1.3.0
- **Validation Date / UTC Timestamp**: 2026-11-15T15:00:00Z
- **Validated Source Commit SHA (Code Under Test)**: Exact HEAD on `fix/phase-e-bundle-timeline-mapping`
- **Integration Base Commit SHA**: `d7dc6714a03bac8f0058742eda664f6bdb7e77b5` (PR #10 merged HEAD)
- **Historical Remediation Branch**: `fix/ps028-post-p2-release-readiness`
- **Authoritative Integration Branch**: `fix/phase-e-bundle-timeline-mapping`
- **Historical P1 Source Branch**: `work/ps028-p1-remediation` (tested commit `ee59362ac3f53fad3bc01e65b5d90815697a93d4`)
- **Historical Derivation Branch**: `regional/ps028-phase-cd`
- **Protected P0 Acceptance Tag**: `ps028-p0-accepted-2026-11-14` (commit `176f688bacb5858fcc0daedb454200918e427f3f`)
- **Repository**: `https://github.com/aiori-hackathon/A3-PS028-TC224.git`
- **Problem Statement Compliance Status**: **17 MET, 2 PARTIAL, 1 PENDING** (17/20 Met; 15/15 Core Problem Statement Requirements Met; Remote CI Run #2 Verified)

---

## 1. Executive Summary

This document establishes the authoritative, independently reproducible final release validation evidence for the post-integration release-readiness remediation of the PS-028 repository.

All confirmed post-P2 source defects have been resolved:
1. **Silent Fallback Elimination (Issue #12)**: Strict fail-closed parsing implemented in `lab/build_submission_report.py` with 19 dedicated negative/malformed regression tests in `lab/test_build_submission_report.py`.
2. **RFC Attribution Correction (Issue #9)**: Docstring corrected in `lab/analyze.py` to cite RFC 8305 Section 2 and RFC 6724 Section 2.1, 6 Rule 6, 10.3 (instead of Section 3), with dedicated unit test in `lab/test_analyze.py`.
3. **Measurement Safeguards (Browser DoH & TRR Controls)**: Audited Google Chrome binary strings and confirmed that Chrome does not implement a `--dns-over-https-mode` CLI switch. Implemented effective profile-level disablement via `Local State` and `Default/Preferences` (`dns_over_https.mode = "off"`), `--user-data-dir` argument binding, and `DnsOverHttps` feature flag disablement in `lab/run_trial.py`. Wired `verify_browser_dns_controls()` into `run_browser()` prior to process spawn, aborting launch on any tampered/missing configuration. Empirically validated effective `secure_dns_mode = 0` (kOff) in Chrome's network stack via real Chrome netlog parsing in `lab/test_run_trial.py` across 10 observed internal resolver configuration (`DNS_CONFIG_CHANGED`) and host resolution job request (`HOST_RESOLVER_MANAGER_JOB`) events (confirming `can_use_secure_dns_transactions: false` and empty DoH servers `[]`). Preserved classification strictly as `BROWSER DNS CONFIGURATION VERIFIED — LIVE DNS PATH NOT YET EXPERIMENTALLY VERIFIED`.
4. **Expanded Real-Browser Playwright Suite (Issue #13)**: Interactive search (positive/negative/clear), pagination boundary controls, filter reset, timeline multi-source filtering, timeline text search, exclusions inspection, provenance display, and RFC 8305 content assertions exercised in genuine Chromium across 14 stages and 242 assertions.
5. **Documentation & Branch Metadata (Issues #15, #16, #17, Handover, Reconciliation)**: Reconciled 818-test and 881-test historical milestones (with 881 status qualified as `PARTIALLY RESOLVED — aggregate post-hoc classification; original per-test tracebacks unavailable`), updated compliance matrix and owner handover checklist, and updated README integration branch metadata.
6. **Fresh Complete Release Validation (Issues #19 & #20)**: Full test execution against validated commit `a398c6e5c4dd51103456ab4f5748cea50162126f`.

---

## 2. Test Execution Environment

| Parameter | Specification | Verification Command |
|---|---|---|
| **Operating System** | Ubuntu 24.04.5 LTS (Linux 6.18.58.1-microsoft-standard-WSL2 x86_64) | `uname -a` |
| **Python Runtime** | Python 3.12.3 | `python3 --version` |
| **Node.js Runtime** | Node.js v22.14.0 | `node --version` |
| **Package Manager** | npm 10.9.2 | `npm --version` |
| **Browser Runtime (E2E)** | Google Chrome / Chromium 157.0.8103.50 | `google-chrome --version` |
| **Playwright Engine** | Playwright v1.65.1 | `npx playwright --version` |
| **Frontend Framework** | Astro v5.16.3 + React 19.2.0 | `npx astro --version` |
| **Pinned Dependencies** | `PyYAML==6.0.1` (`requirements.txt`) | `pip freeze | grep PyYAML` |

---

## 3. Test Suite Inventory & Execution Results

### 3.1 Tier 1: Lab Unit & Regression Test Suite
- **Directory**: `lab/`
- **Scope**: Statistical analysis, metric extraction, trial runner, privileged helper, fail-closed report builder, impairment controls, and CSV/JSON evidence exporters across 21 modules.
- **Execution Command**:
  ```bash
  python3 -m unittest discover -s lab -p "test_*.py"
  ```
- **Results**:
  - **Total Discovered**: 828
  - **Passed**: 828
  - **Failed**: 0
  - **Errors**: 0
  - **Skipped**: 0
  - **Duration**: 51.814s
  - **Pass Rate**: **100.0%**

### 3.2 Tier 2: Synthetic, E2E & Adversarial Integration Suite
- **Directory**: `tests/`
- **Scope**: Tier 1 (Unit), Tier 2 (Integration), Tier 3 (E2E), Tier 4 (Synthetic Edge Cases), Tier 5 (Adversarial Privilege Challenges).
- **Execution Command**:
  ```bash
  python3 -m unittest discover -s tests -p "test_*.py"
  ```
- **Results**:
  - **Total Discovered**: 93
  - **Passed**: 93
  - **Failed**: 0
  - **Errors**: 0
  - **Skipped**: 0
  - **Duration**: 0.343s
  - **Pass Rate**: **100.0%**

### 3.3 Tier 3: Frontend Historical Evidence Unit Suite
- **Directory**: `setup/webtester/test/`
- **Scope**: Demo bundle JSON parsing, SubtleCrypto SHA-256 verification, valid vs. excluded cohort isolation, median timing calculation, canonical CAD formulas, S5 subflow invariant checks, and RFC 8305 assessment criteria.
- **Execution Command**:
  ```bash
  npm test --prefix setup/webtester
  ```
- **Results**:
  - **Total Discovered**: 31
  - **Passed**: 31
  - **Failed**: 0
  - **Errors**: 0
  - **Skipped**: 0
  - **Duration**: 0.655s
  - **Pass Rate**: **100.0%**

### 3.4 Summary: Total Unique Automated Tests
$$\mathbf{828 \text{ (Lab)} + 93 \text{ (Integration)} + 31 \text{ (Frontend)} = 952 \text{ Total Unique Automated Tests}}$$

- **Total Discovered & Executed**: **952**
- **Total Passed**: **952**
- **Total Failed**: **0**
- **Total Errors**: **0**
- **Total Skipped**: **0**
- **Overall Automated Suite Pass Rate**: **100.0%**

---

## 4. Separate Production, Smoke, and Browser Validations

In accordance with scientific measurement precision, the following validation checks evaluate production distribution artifacts, browser runtime execution, and static integrity. They are tracked and reported separately from the unique automated test definitions:

| Validation Category | Target & Scope | Command | Outcome | Details / Metrics |
|---|---|---|:---:|---|
| **Static Smoke Tests** | `dist/` preview HTTP server | `npm run test:smoke --prefix setup/webtester` | **PASS** | **16 checks executed** (MIME types, bundle JSON size 17.32MB, sidecar hash match, cohort counts, zero leakage). |
| **Browser Acceptance** | Genuine Chromium Playwright | `npm run test:browser --prefix setup/webtester` | **PASS** | **14 stages / 242 assertions** verified in Chromium 157.0.8103.50 (zero page errors, zero console errors, zero failed network requests). |
| **Astro Type Check** | Full frontend TypeScript check | `npm run check --prefix setup/webtester` | **PASS** | **55 files checked**: 0 errors, 0 warnings (4 deprecation hints). |
| **Production Build** | Static Astro site generation | `npm run build --prefix setup/webtester` | **PASS** | **8 static HTML pages** compiled in 2.96s (`dist/`). |
| **Data Preparation** | Bundle staging script | `npm run prepare:data --prefix setup/webtester` | **PASS** | Bundle verified: 17.32 MB, SHA-256: `42fad72c342c0e98...`, 280 valid trials, 2 exclusions. |
| **Evidence Integrity Seal** | Historical campaign files | `sha256sum -c historical_integrity_before.sha256` | **PASS** | **705 / 705 files** in `lab/campaigns/ps028-a10-live-20261030-01/` match bit-for-bit (0 mismatches, 0 missing). |
| **Presentation Deck** | 11-slide Beamer layout PDF | `python3 lab/build_submission_report.py` | **PASS** | `PS028_Hackathon_Submission_Presentation.pdf` compiled cleanly (207,985 bytes, exactly 11 pages, $160\text{ mm} \times 90\text{ mm}$). |
| **Remote CI Pipeline** | Remote automation | N/A | **NOT CONFIGURED** | Remote CI is **not configured / not recorded**. All reported results are local reproducible offline executions. |

---

## 5. Chronological Test Inventory Progression

To preserve scientific authenticity and avoid conflating distinct development milestones, the test inventory progression is reconciled across all eight repository milestones:

| # | Milestone Description | Date | Reference Commit / Document | Lab | Int | FE | Total Tests | Execution Status |
|:---:|---|:---:|---|:---:|:---:|:---:|:---:|---|
| **1** | Initial Preflight Baseline | 2026-10-29 | Initial testbed baseline | 431 | 93 | — | **524** | 100% PASS |
| **2** | Batch C5 Sealed Gate Snapshot | 2026-11-12 | `docs/phase-cd/gates/batch_c5.md` | 725 | 93 | — | **818** | 100% PASS |
| **3** | Phase C/D Baseline | 2026-11-12 | `regional/ps028-phase-cd` HEAD | 731 | 93 | — | **824** | 100% PASS |
| **4** | Phase E Demo Readiness | 2026-11-13 | `regional/phase-e-demo-readiness` | 825 | 93 | — | **918** | 100% PASS |
| **5** | Task 5C Deduplicated Discovery | 2026-11-14 | `fix/phase-e-bundle-timeline-mapping` | 788 | 93 | — | **881** | 866 PASS, 4 FAIL, 11 ERR (status: PARTIALLY RESOLVED — aggregate post-hoc classification; original per-test tracebacks unavailable) |
| **6** | Historical P0 Baseline | 2026-11-14 | `5c84c93` (frozen at `176f688`) | 804 | 93 | 31 | **928** | 100% PASS |
| **7** | Historical P1 Validation Snapshot | 2026-11-14 | `ee59362ac3f5` on `work/ps028-p1-remediation` | 805 | 93 | 31 | **929** | 100% PASS |
| **8** | **Post-P2 Release Readiness (Current)** | **2026-11-15** | `a398c6e5c4dd` on `fix/ps028-post-p2-release-readiness` | **828** | **93** | **31** | **952** | **100% PASS (0 fail, 0 err, 0 skip)** |

---

## 6. Detailed Reproducibility Runbook

To reproduce this validation from a clean checkout of branch `fix/ps028-post-p2-release-readiness`:

```bash
# 1. Verify commit SHA and worktree status
git rev-parse HEAD
# Expected: a398c6e5c4dd51103456ab4f5748cea50162126f (or docs commit HEAD)

# 2. Verify immutable historical campaign integrity
sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256 | grep -v "OK$" || echo "100% MATCH"

# 3. Execute Lab unit and regression tests (Tier 1)
python3 -m unittest discover -s lab -p "test_*.py"

# 4. Execute Integration, E2E, and Adversarial challenge tests (Tier 2)
python3 -m unittest discover -s tests -p "test_*.py"

# 5. Execute fail-closed report builder regression suite
python3 -m unittest lab.test_build_submission_report -v

# 6. Install frontend dependencies and verify frontend unit tests (Tier 3)
npm ci --prefix setup/webtester
npm test --prefix setup/webtester

# 7. Execute static distribution smoke tests
npm run test:smoke --prefix setup/webtester

# 8. Build production Astro frontend and execute Playwright genuine Chromium acceptance suite
npm run build --prefix setup/webtester
npm run test:browser --prefix setup/webtester

# 9. Verify TypeScript diagnostics
npm run check --prefix setup/webtester

# 10. Compile hackathon presentation slide deck and PDF
python3 lab/build_submission_report.py
```

---

## 7. Persisted Validation Log Reference

A complete log of test executions for this release validation has been persisted at:
`lab/logs/release_validation_20261115.log`

Historical logs are preserved immutable at:
- `lab/logs/unit_tests_run.log` (2026-11-09 baseline run)
- `lab/logs/ps028-a10-live-20261030-01.log` (2026-10-30 campaign execution log)

---

### Supplementary validation — Chrome DNS and lab regression

**Validated source commit:** `a398c6e5c4dd51103456ab4f5748cea50162126f`

**Execution checkout:** `6e95f4699b3e59f13a7cd0abd3859ddc4e63a30c`

The source revision under test was unchanged from the validated source commit.

Additional validation was executed successfully:

| Test | Result |
|---|---|
| Focused real Chrome NetLog configuration test | 1 passed |
| Full lab unit and regression suite | 828 passed |
| Failures | 0 |
| Errors | 0 |
| Exit codes | 0 for both commands |

---

## 7. Final Release Closure & GitHub Actions CI Integration (15 Nov 2026)

- **Authoritative Integration Branch**: `fix/phase-e-bundle-timeline-mapping`
- **Audit Timestamp**: `2026-11-15T15:00:00Z`
- **Scope**: Final two-day release closure, reproducible PDF generation, and GitHub Actions CI workflow integration.

### 7.1 Automated Technical Report PDF Generation Pipeline (Requirement #12)

- **Script**: `lab/build_technical_report_pdf.py`
- **Test Suite**: `lab/test_build_technical_report_pdf.py` (10 unit/regression tests, all passed in 1.3s)
- **Authoritative Source**: `docs/PS028_FINAL_EXPERIMENTAL_REPORT.md`
- **Generated Target Artifact**: `PS028 Detailed Analysis & Report PDF.pdf` (455,157 bytes, 22 pages, 104 streams)
- **Temporary Artifacts**: `lab/derived/phase-c/technical_report.html` (393,260 bytes), `lab/derived/phase-c/technical_report.pdf`
- **Styling & Engine**:
  - Publication-quality A4 academic layout ($22\text{ mm}$ top/bottom, $16\text{ mm}$ left/right margins).
  - Offline vendored KaTeX math rendering (`lab/resources/katex/`) for all equations ($\bar{x} \pm t_{0.975, n-1} \cdot \frac{s}{\sqrt{n}}$, $t_{\text{connect}}$, $t_{\text{setup\_total}}$) without network calls.
  - Executive cover page with campaign metadata table and AIORI hackathon banner.
  - Auto-generated Table of Contents linking directly to section anchors.
  - Shaded table headers, syntax-highlighted code blocks, blockquotes, and unorphaned headings (`break-after: avoid;`).
  - Running headers (`PS-028 Final Technical Validation Report`) and footers (`AIORI-3 PS-028 • Page X of Y`) via Playwright / Chromium with Chrome CLI fallback.
  - Strict fail-closed validation: asserts file existence, size $\ge 400\text{ KB}$, page count $\ge 18$, and stream counts before updating the root submission artifact.

### 7.2 Full Test Suite Inventory Across Entire Repository

| Tier | Test Suite Scope | Test Runner Command | Discovered | Passed | Failed | Errors | Skipped | Pass Rate |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Lab Unit & Regression** | `lab/test_*.py` (22 modules, +10 PDF tests) | `python3 -m unittest discover -s lab -p "test_*.py"` | 838 | 838 | 0 | 0 | 0 | **100.0%** |
| **Integration & Adversarial** | `tests/test_*.py` (5 tiers) | `python3 -m unittest discover -s tests -p "test_*.py"` | 93 | 93 | 0 | 0 | 0 | **100.0%** |
| **Frontend Unit Tests** | `setup/webtester/test/historical-evidence.test.mjs` | `npm test --prefix setup/webtester` | 31 | 31 | 0 | 0 | 0 | **100.0%** |
| **Total Automated Tests** | **Comprehensive Full Repository Discovery** | | **962** | **962** | **0** | **0** | **0** | **100.0%** |

### 7.3 Separate Validations & Distribution Checks

| Validation Item | Command / Procedure | Result | Status |
|---|---|---|:---:|
| **Historical Campaign Integrity** | `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256` | 705 / 705 files bit-for-bit matched | **PASS** |
| **Presentation PDF Compilation** | `python3 lab/build_submission_report.py` | 207,985 bytes, exactly 11 pages | **PASS** |
| **Technical Report PDF Compilation** | `python3 lab/build_technical_report_pdf.py` | 455,157 bytes, 22 pages, 104 streams | **PASS** |
| **Static Production Distribution** | `npm run build --prefix setup/webtester` | 8 static pages built | **PASS** |
| **Distribution Smoke Tests** | `npm run test:smoke --prefix setup/webtester` | 16 / 16 checks passed | **PASS** |
| **Genuine Browser Acceptance** | `npm run test:browser --prefix setup/webtester` | 14 / 14 stages passed (242 assertions) | **PASS** |

### 7.4 GitHub Actions Continuous Integration (`.github/workflows/ci.yml`)

- **Workflow Name**: `PS-028 Continuous Integration`
- **Triggers**: Push to `fix/phase-e-bundle-timeline-mapping`, PRs to `main`, `workflow_dispatch`.
- **Jobs**:
  1. `python-tests`: Python 3.12 runner verifying 705 campaign checksums, installing TShark, running 838 lab tests and 93 integration tests.
  2. `frontend-validation`: Node.js 22 runner running 31 frontend unit tests, Astro check, static build, 16 smoke checks, and 14-stage genuine-Chromium browser acceptance tests.
  3. `artifacts-validation`: Dual Python/Node runner building and validating both submission PDFs (11 pages presentation, $\ge 18$ pages report) and uploading artifacts via `actions/upload-artifact@v4`.
- **Reporting Boundary**: Local reproducible offline test passes (962 passed, exit code 0) are strictly distinguished from remote GitHub Actions workflow executions.

### 7.5 Remote GitHub Actions Run #1 Forensic Audit and Remediation Record

- **Historical Remote CI Run**: Run ID `43729601462`
- **Run URL**: `https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43729601462`
- **Triggering Commit**: `b296df488aac9fe77dcd6dec17ab611b2c6ef3a2` on `fix/phase-e-bundle-timeline-mapping`
- **Remote Results**:
  - `frontend-validation`: **PASS** (100% of unit, check, build, smoke, and Playwright browser acceptance tests passed).
  - `python-tests`: **FAIL** (630 discovered, failures=18, errors=18).
  - `artifacts-validation`: **SKIPPED** (due to `needs: [python-tests, frontend-validation]` fail-closed gate).

#### Forensic Classification of the 18 Errors and 18 Failures:
1. **Missing Python Dependency (`dnspython==2.6.1`)** (13 Errors):
   - `dnspython==2.6.1` was required by `lab/dns_server.py` but absent from `requirements.txt`.
   - Resulted in module import failures for `lab/test_dns_server.py` and `lab/test_run_trial.py` during unittest discovery, truncating discovered lab test count to 630 instead of 838 ($838 - 210 + 2 = 630$).
   - Caused 5 errors in `lab.test_impair` (DNS patch helper) and 5 errors in `lab.test_preflight`.
2. **Missing System Dependency (`tshark`)** (1 Error, 17 Failures):
   - Runner image lacked TShark CLI, required for authentic PCAP packet dissection.
   - Resulted in 1 error in `lab.test_c2_adversarial_challenge` (missing mandatory PCAP timeline events) and 17 failures (1 in `lab.test_campaign_pcap_regression`, 14 in `lab.test_demo_replay` representative trials, 2 in demo replay assertions).
3. **Shallow Git Checkout (`fetch-depth: 1`)** (1 Failure):
   - Default checkout did not fetch historical generator commit `f58028752b65a2ad37fa78c82cf7a9e683b41ed1`, causing `lab.test_demo_bundle::test_provenance_sidecar_generator_revision` to fail.
4. **Environment User Identity Lookup** (3 Errors):
   - Tests patching UID/GID to 1000 caused `identity.resolve_user_by_uid` to resolve user `packer` (`/home/packer`) on GitHub runner VM images, resulting in `PermissionError: [Errno 13]` when runner (UID 1001) attempted to create crashpad directories.
5. **Presentation Layer Null Formatting** (1 Error):
   - `lab/demo_replay.py` summary formatting raised `TypeError: unsupported format string passed to NoneType.__format__` when primary-flow metrics were `None` during a failed replay.

#### Root-Cause Remediation Implemented:
- `requirements.txt`: Added exact pinned dependency `dnspython==2.6.1`.
- `.github/workflows/ci.yml`: Added `fetch-depth: 0` to checkout steps and added dedicated non-interactive TShark system package installation (`sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark`) with `command -v tshark` and `tshark --version` verification.
- `lab/test_privileged_helper.py`: Isolated browser home directory in `TestBrowserIdentityAndPrivilegeDropping` and `TestSnapBrowserNamespaceMountsAndLaunch` to a test-owned temporary directory `self.user_home` via `_orig_resolve` patch.
- `lab/demo_replay.py`: Safe string formatting for `None` values (`NONE` / `N/A`) preserving underlying metrics and fail-closed non-zero exit codes without data fabrication.
- **Local Validation Evidence**: Captured in `lab/logs/release_validation_ci_remediation_20261115.log` (838 lab + 93 integration + 31 frontend = 962 automated tests passed, 0 failures, 0 errors, 16 smoke checks passed).

### 7.6 Remote GitHub Actions Run #2 Verification Record (Successful CI Execution)

- **Authoritative Remote CI Run**: Run ID [`43733419747`](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43733419747)
- **Run URL**: `https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43733419747`
- **Workflow**: `PS-028 Continuous Integration` (`.github/workflows/ci.yml`)
- **Triggering Commit**: `afceefb759627f1a1d6bc1a2ba4c1970d0f89656` on `fix/phase-e-bundle-timeline-mapping`
- **Run Outcome**: **SUCCESS** across all 3 jobs (Total duration: 3 minutes 7 seconds):
  - `python-tests`: **PASS** (1m 57s, ID `132870678897`)
  - `frontend-validation`: **PASS** (1m 23s, ID `132870679207`)
  - `artifacts-validation`: **PASS** (1m 3s, ID `132871277342`)

#### Verified Remote Test Counts & Integrity Assertions:
| Validation Item | Remote Verified Count | Result |
|---|:---:|:---:|
| Python lab unit & regression tests | 838 / 838 | **PASS** |
| Python integration tests | 93 / 93 | **PASS** |
| Frontend unit tests (`historical-evidence.test.mjs`) | 31 / 31 | **PASS** |
| **Total Unique Automated Tests** | **962 / 962** | **PASS (100%)** |
| Historical campaign checksums (`historical_integrity_before.sha256`) | 705 / 705 | **PASS** |
| Frontend distribution smoke checks | 16 / 16 | **PASS** |
| Genuine Chromium browser acceptance stages | 14 / 14 | **PASS** |
| Genuine Chromium browser assertions | 242 / 242 | **PASS** |
| Pinned TShark package verification (`tshark=4.2.2-1.1build3`) | Exact version match via `dpkg-query` | **PASS** |

#### Submission PDF Artifacts Generated & Uploaded:
- **GitHub Artifact Name**: `ps028-submission-artifacts`
- **Artifact ID**: `14169134466`
- **Archive Size**: 681,076 bytes
- **SHA-256 Digest**: `a15ac6456c6516245f7989aa0b4e9698eae07b9edb17727f52ab787f27e1d466`
- **Expiry Date**: `2027-02-13T16:04:45Z`
- **Artifact Contents**:
  - `PS028_Hackathon_Submission_Presentation.pdf`: 207,985 bytes, exactly 11 pages (100% byte-identical to local build).
  - `PS028 Detailed Analysis & Report PDF.pdf`: 463,831 bytes, exactly 22 pages.
  - `lab/derived/phase-c/technical_report.html`: 393,960 bytes.
  - `lab/derived/phase-c/presentation_deck.html`: 31,642 bytes.

#### Forensic Analysis of the 33-Byte PDF Size Difference:
- **Tracked Local PDF**: 463,864 bytes (`PS028 Detailed Analysis & Report PDF.pdf`, SHA-256: `d857fd7641c69bc7eb669bce2d53e4c89df89563c0ec6cff495c1bbf73b9aba7`).
- **CI-Generated PDF**: 463,831 bytes (SHA-256: `daa702caca886909bfc5eceb73e0e99f392cf730a8b97c346d781b99d70ce8c0`).
- **Exact Delta**: $463,864 - 463,831 = 33\text{ bytes}$.
- **Root-Cause Verification**: Detailed object inspection reveals that exactly 11 link annotation objects (Objects 85, 90, 91, 92, 106, 111, 112, 115, 116, 121, 122) contain `/URI (file://...)` annotations linking to absolute workspace file paths. The local runner path prefix `/home/promotheshchatterjee/projects/A3-PS028-TC224` (50 characters) is exactly 3 characters longer than the GitHub Actions runner path prefix `/home/runner/work/A3-PS028-TC224/A3-PS028-TC224` (47 characters). Over 11 link objects, $11 \times 3 = 33\text{ bytes}$.
- **Content Stream Verification**: Decompression with `zlib` confirms that all 52/52 decompressed content streams in the PDF are **100% byte-identical** between local and CI builds. Both documents have 22 pages, identical text, headings, tables, equations, styling, and visual layout.

#### Scientific Evidence Boundaries in CI Documentation:
- The Python CI log line `S5 PASSED: SYN packet count=50 ... dropped packets=24 ... observed loss=48.0%` originates from synthetic unit test fixture `test_verify_s5_syn_loss_variation_success` in `lab/test_self_test_scenarios.py`, where `measure_syn_loss()` is mocked with predetermined values.
- This test verifies software harness unit logic and tolerance checks, NOT a live network socket measurement.
- The CI run provides software reproducibility evidence, not new empirical S5 measurement data. Authentic S5 evidence remains the historical campaign `ps028-a10-live-20261030-01`.

### 7.7 Final Compliance Matrix Summary

- **Total Tracked Requirements**: 20
- **MET**: **17 (85.0%)** — All 15 Core Problem Statement Requirements Met (#1–#15), Ownership Transfer (#18), and Remote CI Verification (#19).
- **PARTIAL**: **2 (10.0%)** — #16 (Uniform netem live sweep; live research excluded by owner decision) and #17 (Live S5 binomial batch; live research excluded by owner decision; simulation verified).
- **PENDING**: **1 (5.0%)** — #20 (Independent partner replication package authored; scheduled as final separate milestone).
