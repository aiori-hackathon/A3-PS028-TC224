# PS-028 Happy Eyeballs Lab: Phase C + Phase D Progress Tracker

- **Branch**: `regional/phase-e-demo-readiness` (branched from `regional/ps028-phase-cd` @ `b920ebc93f2e6aaae8396b7095b6cd3c8598ade5`)
- **Base Branch**: `regional/p0-remediation` @ commit `7c6ab23c2a378bbc8556fcc15f5911f626502576`
- **Last Updated**: 2026-11-12T15:30:00Z
- **Current Status**: **PHASE C/D SEALED & VERIFIED; PHASE E DEMO-READINESS REMEDIATED (918 PASSING TESTS)**

---

## 1. Milestone & Batch Status Checklist

- [x] **Milestone 1: Step 0 Preflight & Baseline Establishment** — **PASSED**
  - [x] Branch resolution (`regional/p0-remediation` confirmed, work branch `regional/ps028-phase-cd` created)
  - [x] Baseline environment and 524 passing unit tests documented (`docs/phase-cd/baseline.md`)
  - [x] Pre-modification SHA-256 baseline computed for all 705 historical campaign files (`lab/derived/phase-c/historical_integrity_before.sha256`)
  - [x] Finding verification register complete for all 20 findings: 18 CONFIRMED, 2 PARTIAL, 0 NOT-REPRODUCED (`docs/phase-cd/finding-verification.md`)
  - [x] Repo-wide forensic audit register completed (14 findings cataloged in `docs/phase-cd/repo-audit-register.md`)
  - [x] Phase C Metric Contract v1.1.0 approved by user (`docs/phase-c-metric-contract.md`)
  - [x] Phase D Experiment Protocol v1.0.0 approved by user (`docs/phase-d-experiment-protocol.md`)
  - [x] Parallel E2E test harness created (67 synthetic tier tests in `tests/`)

- [x] **Milestone 2: Batch C1 (Parser & Metric Correctness)** — **PASSED**
  - [x] Implemented `t_connect_ms` (RFC 9293 §3.5 initial SYN to matching client final ACK on primary stream)
  - [x] Implemented `t_setup_total_ms` (first target-host SYN of any family to primary final ACK)
  - [x] Preserved diagnostic legacy `syn_to_synack_ms`
  - [x] Enforced initial-SYN timestamp locking against retransmissions
  - [x] Implemented exact normalized QNAME matching and DNS transaction ID pairing (`dns.id`, QTYPE, transport 5-tuple, RCODE)
  - [x] Implemented separate HTTPS/SVCB (Type 65) tracking
  - [x] Result schema bumped to 1.1.0 with compact `primary_flow` evidence object
  - [x] Updated `lab/analyze.py` to support dual schema parsing (1.0.0 and 1.1.0) with deep recursive type enforcement and fail-closed validation
  - [x] Re-derived all 280 October 29 PCAPs into `lab/derived/phase-c/reconciliation_report.csv`
  - [x] Confirmed exact 144/280 >1 ms discrepancy from README
  - [x] Remediated `DEFECT-C1-CHALLENGE-01` (scalar type validation shielding)
  - [x] Batch C1 Gate Report sealed (`docs/phase-cd/gates/batch_c1.md`) with unanimous gate clearance

- [x] **Milestone 3: Batches C2 (Evidence Exports) & C4 (Cohorts & S5 Flow Dissection)** — **PASSED**
  - [x] Implemented `lab/export_campaign_evidence.py` producing deterministic datasets in `lab/derived/phase-c/`
  - [x] `attempts.csv`: Exactly 282 rows reconciling 280 `VALID_LIVE` trials + 2 preserved `CLEANUP_FAILURE` attempts
  - [x] `connection_attempts.csv`: Exactly 765 per-TCP-flow connection attempts classified across all 280 historical trials
  - [x] `s5_flow_dissection.csv`: Exactly 95 flows across 40 S5 trials cleanly separating transport racing from application HTTP transactions
  - [x] `trial_timeline.csv`: 28,330 chronologically synchronized events across `HARNESS`, `PCAP`, and `BROWSER_TELEMETRY`
  - [x] Sibling provenance files (`*.provenance.json`) per Amendment A13 (zero nondeterministic timestamps in data files)
  - [x] Codified normative glossary (`docs/phase-cd/glossary.md`) defining four-tier measurement hierarchy
  - [x] Integrated `ResearchCohortKey` into `lab/analyze.py`
  - [x] Batch C2/C4 Gate Report sealed (`docs/phase-cd/gates/batch_c2_c4.md`) with unanimous approval

- [x] **Milestone 4: Batch C5 (Privilege Isolation & Fail-Closed DNS Robustness)** — **PASSED**
  - [x] Full privilege decoupling: removed ambient `require_root()` checks from `self_test_scenarios.py` and `impair.py`
  - [x] Added `setup-s5-counters`, `read-s5-counters`, and `measure-s5` (JSONL output) to `privileged_helper.py` using strict `argv` lists
  - [x] Dual-class S5 evidence separation: router nftables counters vs ephemeral-bound client probe socket telemetry
  - [x] Pure-Python Clopper-Pearson 99% exact binomial confidence intervals implemented (zero scipy dependency)
  - [x] 5-stage fail-closed DNS configuration reload protocol with PID check, log offset tracking, affirmative confirmation, and query timing validation
  - [x] Machine-readable self-test evidence bundle (`self_test_bundle.json`, `self_test_summary.csv`, and provenance sidecar)
  - [x] Documented non-interactive sudoers rules in `docs/phase-cd/sudoers_configuration.md` without modifying `/etc/sudoers*`
  - [x] Batch C5 Gate Report sealed (`docs/phase-cd/gates/batch_c5.md`) with unanimous approval

- [x] **Milestone 5: Batches C3 (Standards Audit) & C6 (Documentation Alignment & Report Generation)** — **PASSED**
  - [x] Resolved S2 median CAD mathematical contradiction: stratified Chrome (0.710 ms) vs Firefox (160.425 ms) in `rfc8305_assessment.csv`
  - [x] Enforced Rule R7 (No Conformance Claims) across all 7 RFC 8305 evaluation checks
  - [x] Corrected Resolution Delay citation to RFC 8305 Section 3 and Sorting to Section 4
  - [x] Generated `lab/derived/phase-c/rfc8305_assessment.csv` and `.provenance.json` sidecar
  - [x] Expanded boundary test fixtures in `lab/test_analyze.py` covering 4 intervals and 7 critical points
  - [x] Applied 17 documentation remediations across `README.md`, `PS028_REPRODUCIBILITY_RUNBOOK.md`, `PS028_FINAL_EXPERIMENTAL_REPORT.md`, `PROJECT.md`
  - [x] Implemented `lab/build_submission_report.py` compiling 11-slide presentation `PS028_Hackathon_Submission_Presentation.pdf` matching `Proposed-structure-hackathon.pdf` geometry (160mm x 90mm, PT Sans, `#0000DC`)
  - [x] Batch C3/C6 Gate Report sealed (`docs/phase-cd/gates/batch_c3_c6.md`)

- [x] **Milestone 6: Phase D (Empirical Research Sweeps D1–D5)** — **PAUSED - SIMULATION ONLY**
  - [x] Paused by owner directive per `docs/phase-cd/phase-d-paused.md` (priority: Phase C + demonstration)
  - [x] Zero live network commands or kernel impairments run; testbed state 100% clean
  - [x] Implemented `lab/run_research_sweep.py` adhering to `docs/phase-d-experiment-protocol.md`
  - [x] D1 Target IPv6 RTT sweep (symmetric netem model, uniform qdisc, tolerance max(5ms, 5%), n >= 20 per condition) -> `lab/derived/phase-d/d1_rtt_sweep.csv` (SIMULATION ONLY)
  - [x] D2 One-factor DNS delay sweeps (AAAA delay and A delay model, unique per-trial hostnames, Type 65 NODATA) -> `lab/derived/phase-d/d2_dns_sweep.csv` (SIMULATION ONLY)
  - [x] D3 Statistical modeling & reproducible plots (`lab/plot_research_sweeps.py` -> `d1_crossover_summary.csv`, `d2_resolution_summary.csv`, `d1_rtt_crossover_curve.svg`, all watermarked SIMULATION)
  - [x] D4 Qualitative literature comparison with published Firefox 132 (Sattler et al. IMC 2025) without conformance claims (`docs/phase-cd/firefox_comparative_analysis.md`)
  - [x] D5 Multi-host replication package (`docs/phase-cd/partner_replication_manifest.json`, `docs/phase-cd/partner_replication_runbook.md`, status: PENDING authentic evidence)
  - [x] Unit test suite in `lab/test_research_sweeps.py` (6 tests passing)
  - [x] Batch D Gate Report sealed (`docs/phase-cd/gates/batch_d.md`) with explicit Rule R1 simulation disclosure

- [x] **Milestone 7: Phase E (Demo-Readiness Remediation & Verification)** — **PASSED**
  - [x] Authored PS-028 compliance matrix (`docs/phase-cd/ps028-compliance-matrix.md`) mapping all 15 requirements to verifying evidence
  - [x] Remediated prototype demonstration replay script (`lab/demo_replay.py`) expanding to 14 representative authentic PCAPs across S0-S6 x Chrome/Firefox
  - [x] Eliminated fabricated fallbacks and truthiness zero bugs; enforced fail-closed validation on primary flow, 3-way handshake, and HTTP status
  - [x] Implemented canonical Happy Eyeballs connection racing pseudocode snippet (`lab/demo_replay.py --pseudocode`)
  - [x] Built deterministic demonstration data bundle (`lab/build_demo_bundle.py`) reconciling 280 valid live trials, 2 exclusions, 765 flows, 95 S5 flows, and 28,330 timeline events into `lab/derived/phase-e/demo_bundle.json`
  - [x] Generated machine-readable metric registry (`lab/derived/phase-e/metric_registry.json`) preserving canonical `connection_attempt_delay_ms` key
  - [x] Implemented safe demonstration export utility (`lab/demo_export.py`) with spreadsheet formula-injection defense and realpath containment checks
  - [x] Verified repository hygiene: updated `.gitignore`, corrected `README.md` metadata and video hyperlink text
  - [x] Reconciled test snapshots across project history (918 total fresh passing tests)
  - [x] Verified 100% offline clean test execution (918 passing tests total)

---

## 2. Test Suite Counts & Reconciliation

- **Class A (Deterministic Unit Tests in `lab/`)**: **825 passing** (0 errors, 0 failures, 0 skips) across 22 test modules
- **Class B (Synthetic & Fixture Tests in `tests/`)**: **93 passing** (0 errors, 0 failures, 0 skips) across 5 tiers
- **Total Passing Automated Tests**: **918 tests (100% pass rate)**

### Documented Test Count Reconciliation Across Project History
- **67 Tests (`TEST_READY.md`)**: Initial E2E synthetic testing track baseline covering Tiers 1–4 prior to Batch C5.
- **818 Tests (`docs/phase-cd/gates/batch_c5.md`)**: Sealed historical gate report snapshot (725 in `lab/` + 93 in `tests/`) prior to Batch D simulation tests. Historical gate reports are preserved without modification.
- **824 Tests (`regional/ps028-phase-cd` HEAD)**: Phase C/D baseline (731 in `lab/` + 93 in `tests/`), incorporating Batch D research sweep tests (`lab/test_research_sweeps.py`, +6 tests).
- **857 Tests (Initial Phase E PR #9 Submission)**: Pre-review Phase E baseline with `test_demo_replay` (15), `test_demo_bundle` (9), `test_demo_export` (9) (+33 tests in `lab/`).
- **871 Tests (`regional/phase-e-demo-readiness` Batch 1 Review Corrections)**: Intermediate demo-readiness test count incorporating expanded fail-closed, adversarial, and symlink security test suites (778 in `lab/` + 93 in `tests/`).
- **886 Tests (`regional/phase-e-demo-readiness` Batch 1B Final Evidence-Lineage Corrections)**: Intermediate demo-readiness test count incorporating rederived PCAP digests, 3-way checksum cross-checks, complete primary-flow validation, and provenance generator revision tests (793 in `lab/` + 93 in `tests/`).
- **900 Tests (`regional/phase-e-demo-readiness` Batch 1C Final Ledger Consistency and Strict Numeric Validation)**: Intermediate Phase E demo-readiness test count incorporating attempts-ledger consistency checks, strict integer frame/status validation, and provenance generator revision regression tests (807 in `lab/` + 93 in `tests/`).
- **913 Tests (`regional/phase-e-demo-readiness` Batch 1D Final Manifest Identity, Repetition, and Replay Status Consistency)**: Intermediate Phase E demo-readiness test count incorporating manifest campaign ID verification without fallback, strict repetition identity (1..20 integer validation, cohort repetition set completeness), and exact HTTP 200 replay verification (820 in `lab/` + 93 in `tests/`).
- **918 Tests (`regional/phase-e-demo-readiness` Batch 1E Canonical Scenario Identity and Cohort-Key Validation)**: Current Phase E demo-readiness test count incorporating canonical scenario ID validation against `CANONICAL_SCENARIOS` (rejecting missing, empty, or unknown scenario IDs) and exact canonical cohort-key validation (`actual_cohort_keys == expected_cohort_keys`):
  - `lab/test_demo_replay.py` (31 tests)
  - `lab/test_demo_bundle.py` (52 tests, +5 tests for unknown scenario S7 rejection, missing/empty scenario rejection, absent canonical cohort rejection, attempts ledger scenario mismatch rejection, and authentic 14 canonical cohorts validation)
  - `lab/test_demo_export.py` (11 tests)
  - 731 + 94 = 825 in `lab/` + 93 in `tests/` = **918 total passing tests**.

---

## 3. Data Integrity & Safety Status

- Pre-operation SHA-256 seal: `lab/derived/phase-c/historical_integrity_before.sha256`
- Total preserved files verified: **705 files** (280 PCAPs, 280 results, 2 cleanup failure records, 140 netlogs, manifests)
- Cryptographic match: **100.0% unchanged**
- Live network operations executed: **0**
- Sudo/root commands executed: **0**
- System sudoers modified: **0**
