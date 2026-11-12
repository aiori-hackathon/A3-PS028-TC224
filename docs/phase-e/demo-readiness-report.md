# PS-028 Phase E Demo-Readiness Remediation & Verification Report

- **Document Version**: `1.0.0`
- **Report Date**: 2026-11-12
- **Lead Role**: Senior Internet Measurement Scientist, Network Protocol Engineer, Test Architect
- **Working Branch**: `regional/phase-e-demo-readiness`
- **Source Revision**: `regional/ps028-phase-cd` @ commit [`b920ebc93f2e6aaae8396b7095b6cd3c8598ade5`](https://github.com/aiori-hackathon/A3-PS028-TC224/commit/b920ebc93f2e6aaae8396b7095b6cd3c8598ade5)
- **Consolidation Target**: `regional/p0-remediation` @ commit [`7c6ab23c2a378bbc8556fcc15f5911f626502576`](https://github.com/aiori-hackathon/A3-PS028-TC224/commit/7c6ab23c2a378bbc8556fcc15f5911f626502576)
- **Historical Integrity Seal**: `lab/derived/phase-c/historical_integrity_before.sha256` (**705/705 Verified OK — 0 Failures**)
- **Automated Test Results**: **857 Passing Tests** (0 Failures, 0 Errors, 0 Skips — 100% Pass Rate)

---

## 1. Initial Repository & Branch Preflight State

At preflight discovery (Stage 0), the repository was situated on `regional/ps028-phase-cd` at commit `b920ebc93f2e6aaae8396b7095b6cd3c8598ade5`. The worktree was completely clean with zero uncommitted or untracked changes.

### Branch Verification
- Source HEAD `origin/regional/ps028-phase-cd` was verified at `b920ebc93f2e6aaae8396b7095b6cd3c8598ade5`.
- Consolidation target HEAD `origin/regional/p0-remediation` was verified at `7c6ab23c2a378bbc8556fcc15f5911f626502576`.
- Merge-base between source and target was confirmed as `7c6ab23c2a378bbc8556fcc15f5911f626502576`.
- The isolated working branch `regional/phase-e-demo-readiness` was created directly from `b920ebc93f2e6aaae8396b7095b6cd3c8598ade5`. Neither published branch was modified.

---

## 2. Catalog of Addressed Blockers

| Blocker ID | Severity | Description | Remediation Component |
|---|---|---|---|
| **Blocker P0-A** | Critical | CLI replay utility printed false success on failure; defaulted missing HTTP status to 200 and family to IPv6. | `lab/demo_replay.py` |
| **Blocker P0-B** | Critical | Demonstration lacked a deterministic pre-compiled data bundle, risking repeated slow PCAP parsing in UI. | `lab/build_demo_bundle.py` |
| **Blocker P0-C** | High | Evidence tracing between trial, attempt, PCAP, TCP streams, and timeline events was implicit. | `lab/build_demo_bundle.py` |
| **Blocker P0-D** | High | CLI replay omitted scenarios S3 and S5. | `lab/demo_replay.py` |
| **Blocker P1-A** | High | CLI replay only supported Chrome; omitted Firefox cohort. | `lab/demo_replay.py` |
| **Blocker P1-B** | Medium | Demonstration data lacked scenario, browser, outcome, and trial filtering structures. | `lab/demo_export.py`, bundle schema |
| **Blocker P1-C** | Medium | Metric definitions, units, formulas, and null reason codes were not machine-readable. | `lab/derived/phase-e/metric_registry.json` |
| **Blocker P1-D** | Medium | Evidence execution modes (`HISTORICAL_LIVE` vs `SIMULATION`) lacked explicit classification. | Bundle & Export schemas |
| **Blocker P2-A** | Medium | No security-hardened export utility; vulnerable to formula injection or path traversal. | `lab/demo_export.py` |
| **Blocker P2-B** | Medium | `README.md` metadata had stale baseline and mismatched demonstration video display text. | `README.md` |

---

## 3. Files Modified and Created

### Files Modified
1. `lab/demo_replay.py`: Full fail-closed rewrite supporting 14 authentic cases (S0–S6 × Chrome/Firefox).
2. `.gitignore`: Added `lab/derived/phase-e/exports/`.
3. `README.md`: Added Phase C revision metadata, PR destination, fixed video link text, and refreshed test counts.
4. `PHASE_CD_PROGRESS.md`: Updated Phase E milestones, documented test count reconciliation (857 tests).
5. `TEST_READY.md`: Added Phase E test count evolution and reconciliation addendum.

### Files Created
1. `lab/test_demo_replay.py`: 15 dedicated unit and acceptance tests for CLI replay engine.
2. `lab/build_demo_bundle.py`: Deterministic data bundle builder.
3. `lab/derived/phase-e/demo_bundle.json`: 9.7MB pre-compiled data bundle reconciling all 280 live trials.
4. `lab/derived/phase-e/demo_bundle.json.provenance.json`: Sibling provenance sidecar with source input hashes.
5. `lab/derived/phase-e/metric_registry.json`: Machine-readable metric specifications.
6. `lab/test_demo_bundle.py`: 9 validation tests covering determinism, counts, and simulation exclusion.
7. `lab/demo_export.py`: Security-hardened filtered CSV/JSON exporter.
8. `lab/test_demo_export.py`: 9 tests verifying formula sanitization and path containment.
9. `docs/phase-e/demo-readiness-report.md`: This comprehensive formal report.
10. `docs/phase-e/README.md`: Demonstration data developer runbook.

---

## 4. Technical Rationale & Before/After Behavioral Comparison

### 4.1 CLI Replay Engine (`lab/demo_replay.py`)
- **Before**: Only 5 Chrome scenarios (S0, S1, S2, S4, S6). Hardcoded fallback `status_code = primary.get("http_status_code", 200)` and `Outcome: {primary.get('family', 'IPv6')} won`. Silently skipped missing PCAPs and printed `[SUCCESS]` even on errors.
- **After**: Exactly 14 representative authentic cases covering all 7 scenarios (S0–S6) across both browser cohorts. Strict fail-closed validation requires authentic readable PCAP, verified SHA-256 against campaign checksums, verified trial metadata, explicit stream ID, RFC 9293 3-way handshake completion (`handshake_completed is True`), correlated HTTP request/response frames, and authentic HTTP status code from capture. Non-zero exit code on any failure; success banner emitted only when 100% of tested trials pass.

### 4.2 Data Bundle Builder (`lab/build_demo_bundle.py`)
- **Before**: No unified dataset; demo would need to invoke TShark across 280 PCAPs on user click.
- **After**: Compiles all authoritative Phase C artifacts into `demo_bundle.json`. Preserves canonical metric key `connection_attempt_delay_ms` (never renamed to `cad_ms`). Preserves native JSON numbers (int/float, rejects `NaN`/`Infinity`). Sibling `.provenance.json` records source hashes. Both files contain zero volatile timestamps, guaranteeing byte-identical multi-run reproducibility.

### 4.3 Demonstration Export Security (`lab/demo_export.py`)
- **Before**: No export script existed.
- **After**: Supports filtered CSV/JSON exports. Sanitizes spreadsheet formula injection on strings starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a leading `'` while strictly preserving valid numeric values (including negative numbers like `-10.5` and `0.0`). Rejects directory traversal (`../`) and symlink escapes via `realpath` containment checks.

### 4.4 Documentation & Metadata Alignment
- **Before**: `README.md` listed only `a/lab-foundation` @ `002c4453` and had a mismatched video hyperlink display text.
- **After**: `README.md` documents both the campaign execution baseline and the Phase C analysis revision (`regional/ps028-phase-cd` @ `b920ebc9`), identifies `regional/p0-remediation` as the PR base, fixes the demonstration video display text, and refreshes test counts to 857.

---

## 5. Authentic PCAP Replay Verification (14 Representative Cases)

All 14 representative trials were independently validated against their raw PCAP captures and rederived results:

| Scenario | Browser | Trial ID | PCAP SHA-256 (Prefix) | Winning Family | Outcome | $t_{\text{connect}}$ | Observed CAD | Status |
|:--:|:--|:--|:--|:--:|:--|:--:|:--:|:--:|
| **S0** | Google Chrome | `trial-20261029205425-6cb90a54` | `69fd09eb63b53f2b` | **IPv6** | `DIRECT_IPV6` | 22.80 ms | N/A | **PASS** |
| **S0** | Mozilla Firefox | `trial-20261029205924-355df0f7` | `b053364fd2c1cd71` | **IPv6** | `DIRECT_IPV6` | 24.25 ms | N/A | **PASS** |
| **S1** | Google Chrome | `trial-20261029205941-b5bd2503` | `a58f7e24e002f870` | **IPv4** | `IPV6_TO_IPV4_FALLBACK` | 20.87 ms | 300.49 ms | **PASS** |
| **S1** | Mozilla Firefox | `trial-20261029205956-a51aca94` | `32a28fdda2b7f40e` | **IPv4** | `IPV6_TO_IPV4_FALLBACK` | 30.23 ms | 656.97 ms | **PASS** |
| **S2** | Google Chrome | `trial-20261029210015-37425c7a` | `8abb73c01f12b435` | **IPv4** | `IPV6_TO_IPV4_FALLBACK` | 22.51 ms | 6.82 ms | **PASS** |
| **S2** | Mozilla Firefox | `trial-20261029210032-6a901d45` | `44ed0a34f00045aa` | **IPv4** | `IPV6_TO_IPV4_FALLBACK` | 21.64 ms | 262.88 ms | **PASS** |
| **S3** | Google Chrome | `trial-20261029210049-26b5b48b` | `c43942d54af024d7` | **IPv6** | `DIRECT_IPV6` | 151.36 ms | N/A | **PASS** |
| **S3** | Mozilla Firefox | `trial-20261029210105-1144e256` | `d88459129d76564d` | **IPv6** | `DIRECT_IPV6` | 150.99 ms | N/A | **PASS** |
| **S4** | Google Chrome | `trial-20261029210122-cc8b2b9f` | `6c1ccd5561f483fa` | **IPv4** | `IPV6_TO_IPV4_FALLBACK` | 21.60 ms | 299.96 ms | **PASS** |
| **S4** | Mozilla Firefox | `trial-20261029210137-b906c7dd` | `02e0fb098538a54d` | **IPv4** | `IPV6_TO_IPV4_FALLBACK` | 23.55 ms | 522.13 ms | **PASS** |
| **S5** | Google Chrome | `trial-20261029210154-93e74c83` | `700225ed4926738e` | **IPv6** | `DIRECT_IPV6` | 20.69 ms | N/A | **PASS** |
| **S5** | Mozilla Firefox | `trial-20261029210210-3aef991a` | `28258e902cf09923` | **IPv6** | `DIRECT_IPV6` | 24.95 ms | N/A | **PASS** |
| **S6** | Google Chrome | `trial-20261029215022-d5cc11cb` | `75eeda0399bfccc5` | **IPv6** | `DIRECT_IPV6` | 21.53 ms | N/A | **PASS** |
| **S6** | Mozilla Firefox | `trial-20261029215039-e54744f8` | `d40bd905344b8ed9` | **IPv6** | `DIRECT_IPV6` | 21.30 ms | N/A | **PASS** |

*Note: These 14 cases are representative samples (repetition 1 of each cohort). The full campaign contains 280 valid trials.*

---

## 6. Authoritative Campaign Reconciliation

The demonstration data bundle builder verified exact row count reconciliations across all sources:

- **Total Campaign Attempts**: Exactly **282 attempts**.
- **Valid Live Trials**: Exactly **280 trials** (`status == COMPLETED` and `validity_category == VALID_LIVE`).
- **Exclusion Records**: Exactly **2 cleanup failures** (`CLEANUP_FAILURE`). Held strictly in separate collection; zero contamination into empirical summary statistics.
- **Scenario Cohorts**: Exactly **7 scenarios** (S0–S6).
- **Browser Cohorts**: Exactly **2 pinned builds** (Google Chrome 156.0.8078.73, Mozilla Firefox 159.0).
- **Cohort Balance**: Exactly **20 valid trials** per scenario-browser cohort ($7 \times 2 = 14$ cohorts).
- **Connection Attempts Ledger**: Exactly **765 distinct TCP flows**.
- **S5 Flow Dissection**: Exactly **95 S5 flows** across 40 S5 trials.
- **Unified Timeline**: Exactly **28,330 events** across `HARNESS`, `PCAP`, and `BROWSER_TELEMETRY`.

---

## 7. Determinism & Serialization Verification

Multi-run determinism was verified by generating the bundle and sidecars across independent temporary directories:
```bash
python3 lab/build_demo_bundle.py --output-dir /tmp/run1 --commit-sha fixed_commit
python3 lab/build_demo_bundle.py --output-dir /tmp/run2 --commit-sha fixed_commit
cmp /tmp/run1/demo_bundle.json /tmp/run2/demo_bundle.json -> 0 (BYTE-IDENTICAL)
cmp /tmp/run1/demo_bundle.json.provenance.json /tmp/run2/demo_bundle.json.provenance.json -> 0 (BYTE-IDENTICAL)
cmp /tmp/run1/metric_registry.json /tmp/run2/metric_registry.json -> 0 (BYTE-IDENTICAL)
```
- Zero volatile timestamps inside scientific data payloads or sidecars.
- Native JSON numeric preservation verified: no floats coerced to string formatting.
- Rejection of `NaN` and `Infinity` enforced via `allow_nan=False`.

---

## 8. Historical Cryptographic Seal Verification

The historical integrity seal was executed from the repository root:
```bash
sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256 | grep -v ': OK' | wc -l
```
- **Result**: `0` mismatches.
- **Total Files Verified**: **705 files** under `lab/campaigns/ps028-a10-live-20261030-01/`.
- **Status**: **100% UNCHANGED**. Zero historical evidence files modified, moved, renamed, or deleted.

---

## 9. Comprehensive Fresh Test Counts & Reconciliation

### Fresh Test Execution Results
Executed on branch `regional/phase-e-demo-readiness` via Python 3.12:
- **`lab/` Unit Test Suite**: **764 executed, 764 passed, 0 failed, 0 errored, 0 skipped** (32.8s).
- **`tests/` E2E Test Suite**: **93 executed, 93 passed, 0 failed, 0 errored, 0 skipped** (0.35s).
- **Total Passing Automated Tests**: **857 tests (100% pass rate)**.

### Historical Snapshot Reconciliation
1. **67 Tests (`TEST_READY.md`)**: Initial E2E synthetic testing track baseline covering Tiers 1–4 prior to Batch C5.
2. **818 Tests (`docs/phase-cd/gates/batch_c5.md`)**: Sealed historical gate report snapshot (725 in `lab/` + 93 in `tests/`) prior to Batch D simulation tests. Historical gate reports are preserved without modification.
3. **824 Tests (`regional/ps028-phase-cd` HEAD)**: Phase C/D baseline (731 in `lab/` + 93 in `tests/`), incorporating Batch D research sweep tests (`lab/test_research_sweeps.py`, +6 tests).
4. **857 Tests (`regional/phase-e-demo-readiness`)**: Current Phase E demo-readiness test count incorporating new dedicated readiness test suites:
   - `lab/test_demo_replay.py` (+15 tests)
   - `lab/test_demo_bundle.py` (+9 tests)
   - `lab/test_demo_export.py` (+9 tests)
   - $731 + 33 = 764$ in `lab/` + $93$ in `tests/` = **857 total passing tests**.

---

## 10. Frontend (`setup/webtester/`) Assessment & Recommendations

### Inspection Findings
- `setup/webtester/` is an Astro 5.16 / React 19 / Tailwind 4 application derived from the upstream Happy Eyeballs WebTester project.
- Its existing source code contains client-side live measurement tools (testing remote endpoints for CAD, resolution delay, etc.), but is **not** currently wired to display the PS-028 historical campaign evidence.

### Host Environment Constraint
- Node.js and npm are not installed on this Linux container host (`which node` returned code 1).
- In strict adherence to Rule R6 (prohibiting host environment modifications, `sudo`, or package installs), commands `npm ci`, `npm run check`, and `npm run build` were **not executed**.
- This constraint is pre-existing and does not affect the offline Python measurement lab or evidence datasets.

### Architectural Recommendation for Subsequent Phase
For the upcoming interactive demonstration phase, we recommend:
1. **Dedicated Route within WebTester**: Leverage `setup/webtester/`'s existing Tailwind / Radix UI component library by adding an isolated route (e.g. `src/pages/demo/explorer.astro`).
2. **Static Bundle Ingestion**: Place or symlink `lab/derived/phase-e/demo_bundle.json` into `setup/webtester/src/data/` or `public/` so Astro can render the 280-trial dataset with zero runtime backend dependency.
3. **Strict Historical Separation**: Clearly label the historical evidence explorer with an `OFFLINE HISTORICAL REPLAY` banner, distinguishing it from WebTester's live browser testing mode.

---

## 11. Git Branch Comparison & Pull Request Readiness

- **Working Branch**: `regional/phase-e-demo-readiness`
- **Source Base**: `b920ebc93f2e6aaae8396b7095b6cd3c8598ade5` (`regional/ps028-phase-cd`)
- **Target Branch**: `regional/p0-remediation` (`7c6ab23c2a378bbc8556fcc15f5911f626502576`)
- **Total Commits on Working Branch**: 4 clean, logically grouped commits:
  1. `e6bf1ed`: `feat(phase-e): repair CLI replay engine, expand to 14 authentic cases, and add fail-closed tests`
  2. `c5715b2`: `feat(phase-e): implement deterministic demo bundle builder and metric registry`
  3. `3cfc49a`: `feat(phase-e): implement safe demonstration export utility with formula defense and path containment`
  4. `d4ed39f`: `docs(phase-e): update README baseline metadata, video link, and reconcile test count snapshots (857 tests)`
- **Pull Request Base**: Target branch is confirmed as `regional/p0-remediation`.
- **Merge Gate**: In accordance with instructions, the pull request will **not** be merged autonomously. Final integration is reserved for explicit owner approval.

---

## 12. Final Demonstration-Readiness Recommendation

The PS-028 repository has achieved full demonstration-readiness remediation:
1. All 14 representative authentic PCAPs dissect cleanly without false fallbacks or defaulted metrics.
2. The demonstration bundle (`demo_bundle.json`) provides a schema-versioned, deterministic data layer that frees frontend developers from runtime PCAP dissection.
3. Metric definitions, formulas, and null reasons are codified in machine-readable JSON.
4. Export utilities are protected against spreadsheet formula injection and symlink escapes.
5. All 705 historical evidence files remain strictly sealed and verified.

The repository is now fully prepared for subsequent interactive frontend demonstration development.
