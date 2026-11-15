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
- **Problem Statement Compliance Status**: **16 MET, 3 PARTIAL, 1 PENDING** (16/20 Met; 15/15 Core Problem Statement Requirements Met)

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
  1. `python-tests`: Python 3.12 runner verifying 705 campaign checksums, running 838 lab tests and 93 integration tests.
  2. `frontend-validation`: Node.js 22 runner running 31 frontend unit tests, Astro check, static build, 16 smoke checks, and 14-stage genuine-Chromium browser acceptance tests.
  3. `artifacts-validation`: Dual Python/Node runner building and validating both submission PDFs (11 pages presentation, $\ge 18$ pages report) and uploading artifacts via `actions/upload-artifact@v4`.
- **Reporting Boundary**: Local reproducible offline test passes (962 passed, exit code 0) are strictly distinguished from remote GitHub Actions workflow executions.

### 7.5 Final Compliance Matrix Summary

- **Total Tracked Requirements**: 20
- **MET**: **16 (80.0%)** — All 15 Core Problem Statement Requirements Met (#1–#15) + Ownership Transfer (#18).
- **PARTIAL**: **3 (15.0%)** — #16 (Uniform netem live sweep; live research excluded by owner decision), #17 (Live S5 binomial batch; simulation verified), and #19 (Offline test suite validated; remote CI execution pending on GitHub).
- **PENDING**: **1 (5.0%)** — #20 (Partner replication package authored; scheduled as final separate milestone).
