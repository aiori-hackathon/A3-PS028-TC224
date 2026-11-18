# Quality Gate Report: Milestone 3 — Batch C2 & C4 (Evidence Exports & Cohorts)

- **Date / Timestamp**: 2026-11-12T05:35:00Z
- **Author**: `teamwork_worker_c2_1` (Implementer / QA / Specialist)
- **Governing Directives**:
  - AIORI-3 Problem Statement PS-028 & Submission Rules (`Proposed-structure-hackathon.pdf`)
  - Phase C Metric Contract v1.1.0 (`docs/phase-c-metric-contract.md` §2, §4, §5)
  - Pre-Implementation Audit Findings: C2-01 (Ledger Discrepancy), C2-02 (Enum Inconsistency), C2-03 (Export Engine), C4-01 (Research Cohort Keys), C4-02 (S5 Flow Dissection), C4-03 (Retransmission Invariance)
  - Core Amendments: A1 (TCP vs Attempt Disambiguation), A4 (Capture Vantage Point & Hierarchy), A9 (Provenance Hierarchy), A13 (Determinism & Sibling Provenance)
- **Work Branch**: `regional/ps028-phase-cd`
- **Status**: **PASS (Class A, Class B, Class C Verified; Class D Gate Respected)**

---

## 1. Executive Summary

Milestone 3 (Work Packages C2 & C4) establishes the forensic-grade evidence export engine and research cohort framework for the Happy Eyeballs measurement lab. All six audit findings across C2 and C4 have been fully resolved with genuine logic, strict fail-closed validation, and zero hardcoded or zero-coerced values:

1. **Attempts Ledger Reconciliation (Finding C2-01, Amendment A1)**:
   - Implemented `lab/export_campaign_evidence.py` to produce `lab/derived/phase-c/attempts.csv`, reconciling exactly **282 attempts** across the 280 planned matrix slots (280 `VALID_LIVE` trials + 2 preserved `CLEANUP_FAILURE` attempts).
   - Preserved verbatim error metadata from `lab/campaigns/ps028-a10-live-20261030-01/failed_attempt_record.json` and `exclusions.csv` for Slot 2 (`trial-20261029205442-aba6193c`) and Slot 13 (`trial-20261029210226-944fcfaa`).
   - Null latency metrics in failure records remain strictly empty (`""`) without zero-coercion (Rule R4).

2. **Per-TCP-Flow Connection Tracking (Finding C2-03, Amendment A1, Decision 1)**:
   - Generated `lab/derived/phase-c/connection_attempts.csv` capturing every distinct TCP flow initiated toward the testbed HTTP service across all 280 authentic October 29 PCAPs.
   - Reconciled exactly **765 TCP flows** across the campaign: 204 IPv4 flows, 561 IPv6 flows.
   - Evaluated connection outcomes across all 765 flows into canonical states with 0 unhandled or indeterminate streams:
     - `ESTABLISHED_PRIMARY`: 280 (exactly 1 per valid trial)
     - `ESTABLISHED_ANCILLARY`: 205 (secondary/favicon/preconnect)
     - `NO_SYNACK_TIMEOUT`: 196 (blackholed or netem-dropped SYNs)
     - `RESET`: 60 (active TCP RST rejections)
     - `ABANDONED`: 24 (client abort during handshake)
     - `INDETERMINATE`: 0

3. **S5 Stochastic Flow Dissection (Finding C4-02, C4-03)**:
   - Produced `lab/derived/phase-c/s5_flow_dissection.csv` across all 40 S5 trials (50% stochastic IPv6 SYN loss), extracting exactly **95 TCP flows**.
   - Decoupled transport streams from application transactions by classifying flows into four explicit categories:
     - `PRIMARY`: 40 (winning HTTP `GET /` document)
     - `ANCILLARY`: 12 (`GET /favicon.ico` or secondary subresources)
     - `SPECULATIVE`: 6 (idle preconnect connections established during racing)
     - `UNMATCHED`: 37 (unanswered SYNs dropped by netem loss)
   - Preserved retransmission invariance: retried SYNs on the same 5-tuple increment `retransmitted_syn_count` without advancing initial `syn_time`.

4. **Unified Multi-Source Chronological Timeline (Finding C2-03, Amendment A9)**:
   - Generated `lab/derived/phase-c/trial_timeline.csv` consolidating **28,330 events** across three provenance sources:
     - `HARNESS`: orchestration lifecycles (`TRIAL_START`, `SCENARIO_APPLIED`, `CAPTURE_START`, `BROWSER_LAUNCH`, `BROWSER_EXIT`, `CAPTURE_STOP`, `BASELINE_RESTORED`, `TRIAL_END`)
     - `PCAP`: ground-truth packet frame timestamps (`DNS_QUERY`, `DNS_RESPONSE`, `TCP_SYN`, `TCP_SYNACK`, `TCP_FINAL_ACK`, `TCP_RST`, `TCP_FIRST_PAYLOAD`, `HTTP_GET`, `HTTP_RESPONSE_HEADERS`)
     - `BROWSER_TELEMETRY`: Chrome NetLog events with exact epoch alignment `(timeTickOffset + event.time)/1000.0`, and Firefox UTC telemetry log parsing.

5. **Deterministic Invariance & Sibling Provenance Sidecars (Amendment A13)**:
   - Derived data CSVs contain pure experimental facts without exporter execution timestamps or nondeterministic environment variables.
   - Output uses `\n` line terminators, minimal quoting, and fixed float formatting (`.2f` for latency ms, `.6f` for epoch seconds).
   - Generated sibling `.provenance.json` sidecars for each export (`attempts.csv.provenance.json`, `connection_attempts.csv.provenance.json`, `s5_flow_dissection.csv.provenance.json`, `trial_timeline.csv.provenance.json`).
   - Byte-identical re-execution verified: consecutive runs yield 100% identical SHA-256 digests across all exported files.

6. **Unified Enums & Version-Aware Research Cohort Keys (Finding C2-02, C4-01)**:
   - Unified Python `(str, Enum)` enumerations across `lab/analyze.py`, `lab/run_trial.py`, and `lab/export_campaign_evidence.py`:
     `FallbackClassification`, `TrialValidity`, `ExecutionStatus`, `ConnectionOutcome`, `EventSource`.
   - Implemented `ResearchCohortKey` and `make_research_cohort_key` in `lab/analyze.py` to prevent statistical confounding in multi-version, multi-environment Phase D research sweeps.

7. **Authoritative Conceptual Glossary (Amendment A4)**:
   - Established `docs/phase-cd/glossary.md` defining the 4-tier measurement hierarchy (`Matrix Slot` $\to$ `Harness Attempt` $\to$ `Network Connection Attempt` $\to$ `TCP Stream`) and explicitly segregating out-of-band diagnostic probes.

---

## 2. File Modification & Ownership Index

| File Path | Nature of Modification | Rationale / Contract Reference |
|---|---|---|
| `lab/export_campaign_evidence.py` | New evidence export engine | Deterministic generator for `attempts.csv`, `connection_attempts.csv`, `s5_flow_dissection.csv`, `trial_timeline.csv`, and sibling `.provenance.json` sidecars |
| `lab/test_export_campaign_evidence.py` | New regression test suite | Comprehensive unit tests T01–T10 verifying determinism, row counts, null contracts, and fail-closed safety |
| `docs/phase-cd/glossary.md` | Authoritative normative glossary | Normative definition of 4-tier measurement hierarchy and taxonomy per Amendment A4 |
| `lab/analyze.py` | Core analyzer update | Added unified canonical enums and `ResearchCohortKey` composite dataclass (Finding C2-02, C4-01) |
| `lab/run_trial.py` | Core runner update | Exposed canonical enums and recorded `rst_time`/`rst_frame` on stream inspection |
| `lab/test_analyze.py` | Test suite enhancement | Added `TestResearchCohortKeysAndUnifiedEnums` validating enums and cohort key derivation |
| `lab/derived/phase-c/attempts.csv` | Derived evidence artifact | Deterministic 282-attempt ledger reconciling 280 valid live trials + 2 cleanup failures |
| `lab/derived/phase-c/attempts.csv.provenance.json` | Provenance sidecar | Amendment A13 metadata sidecar for `attempts.csv` |
| `lab/derived/phase-c/connection_attempts.csv` | Derived evidence artifact | Deterministic per-TCP-flow tracking across all 765 campaign flows |
| `lab/derived/phase-c/connection_attempts.csv.provenance.json` | Provenance sidecar | Amendment A13 metadata sidecar for `connection_attempts.csv` |
| `lab/derived/phase-c/s5_flow_dissection.csv` | Derived evidence artifact | Deep flow dissection for 95 flows across 40 S5 trials resolving Finding C4-02 |
| `lab/derived/phase-c/s5_flow_dissection.csv.provenance.json` | Provenance sidecar | Amendment A13 metadata sidecar for `s5_flow_dissection.csv` |
| `lab/derived/phase-c/trial_timeline.csv` | Derived evidence artifact | Unified chronological multi-source timeline (28,330 events) |
| `lab/derived/phase-c/trial_timeline.csv.provenance.json` | Provenance sidecar | Amendment A13 metadata sidecar for `trial_timeline.csv` |
| `docs/phase-cd/gates/batch_c2_c4.md` | Gate report artifact | Formal batch quality gate report |

---

## 3. Four Evidence Classes Verification Matrix (Rule R6)

### 3.1 Class A: Deterministic Unit Tests (`lab/test_*.py`)
- **Execution Command**:
  ```bash
  python3 -m unittest discover -s lab -p "test_*.py"
  ```
- **Outcome**: **PASS**
- **Test Count**: **582 tests run**, 0 failures, 0 errors in 18.739s.
- **Key Modules Verified**:
  - `lab/test_export_campaign_evidence.py` (10 tests):
    - T01: Attempts row count and reconciliation (282 rows)
    - T02: Attempts 20-column header schema
    - T03: Cleanup failure null metric contract (Rule R4)
    - T04: Connection attempts row count (765 rows)
    - T05: S5 flow dissection (95 flows, 40 primary)
    - T06: Connection attempts 5-tuple schema and outcome enums
    - T07: Trial timeline event source provenance (`HARNESS`, `PCAP`, `BROWSER_TELEMETRY`)
    - T08: Determinism and byte reproducibility (identical SHA-256 on repeat runs)
    - T09: Sibling provenance sidecar structure and checksum match
    - T10: Fail-closed on corrupt or unknown schema manifest
  - `lab/test_analyze.py` (including `TestResearchCohortKeysAndUnifiedEnums`):
    - Canonical enum string compatibility
    - ResearchCohortKey canonical string serialization and slug generation
    - TrialEvidence cohort key derivation
  - `lab/test_run_trial.py`, `lab/test_run_campaign.py`, `lab/test_impair.py`, `lab/test_dns_server.py`, `lab/test_preflight.py`, `lab/test_teardown.py`, `lab/test_self_test_scenarios.py`.

### 3.2 Class B: Synthetic & Fixture PCAP Tests (`tests/`)
- **Execution Command**:
  ```bash
  python3 -m unittest discover -s tests -p "test_*.py" -v
  ```
- **Outcome**: **PASS**
- **Test Count**: **67 tests run**, 0 failures, 0 errors in 0.005s.
- **Coverage Highlights**:
  - Tier 1 Features: DNS metrics, dual-stack racing CAD expiration, Type 65 query separation, attempts reconciliation 282 rows, scenario specifications S0–S6.
  - Tier 2 Boundaries: CAD recommended bounds (100ms, 250ms), extreme network delay (10,000ms), 0% and 100% loss, schema type coercion rejection.
  - Tier 3 Combinations: Asymmetric latency + SYN retransmission, concurrent HTTPS/SVCB + IPv6 timeout, DNS delay + SYN RST, CAD interleaving.
  - Tier 4 Scenarios: Fiber broadband, cellular handover, broken enterprise firewall, CDN anycast, satellite high-latency.

### 3.3 Class C: Historical Authentic-PCAP Validation
- **Execution Command**:
  ```bash
  python3 lab/export_campaign_evidence.py \
    --campaign-dir lab/campaigns/ps028-a10-live-20261030-01 \
    --output-dir lab/derived/phase-c
  ```
- **Outcome**: **PASS**
- **Artifacts Produced & Verified**:
  - `attempts.csv`: 282 rows (280 `VALID_LIVE` + 2 `CLEANUP_FAILURE`).
  - `connection_attempts.csv`: 765 rows across 280 trials.
  - `s5_flow_dissection.csv`: 95 rows across 40 S5 trials.
  - `trial_timeline.csv`: 28,330 events chronologically ordered.
- **Historical Campaign Integrity Verification**:
  - Command: `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256`
  - Result: **All 705 historical campaign files OK**. Zero historical artifact modifications.

### 3.4 Class D: New Live Acceptance
- **Status**: **NOT APPLICABLE / PENDING OPERATOR GATE**
- **Safety Control**: No network namespaces or live interface alterations were executed. Human gate remained strictly enforced.

---

## 4. Derived Artifact Metrics & Verification Checksums

All derived files are stored in `lab/derived/phase-c/` with bit-for-bit reproducible SHA-256 digests:

| File Name | Row Count (Data) | Byte Size | SHA-256 Digest |
|---|---|---|---|
| `attempts.csv` | 282 | 96,163 | `40001094e0b12dad4b75522416d0d483539d5252ecc2f854cd7b0f5e934c1faf` |
| `attempts.csv.provenance.json` | 18 | 711 | `1a5d24ecaa58a8a25c1f016d94c1f5139a3f2db91ecfae9ffb57dc6c2c7ae027` |
| `connection_attempts.csv` | 765 | 166,170 | `f28a3138b30ea872aeeb3709b47e5b22b10a2f146be2590fc53cb6ae058d4a36` |
| `connection_attempts.csv.provenance.json` | 18 | 687 | `6ea48d88fa7b789a7447d7c67531eeaa5fc987546059c36d27453d8e578c743d` |
| `s5_flow_dissection.csv` | 95 | 22,074 | `d5570d249d3290616b34954477161b40ee9cefd06259f422e176ebc1cf1bc557` |
| `s5_flow_dissection.csv.provenance.json` | 18 | 685 | `60670868f12c3217fc5981666cb669ef0cbf83cfa0181fe4bf4da68f44ff53c8` |
| `trial_timeline.csv` | 28,330 | 8,767,112 | `3c0db69c7fb5570c67926e95c1df7c40d04b38d33cfb86068e80ae40d2ba510b` |
| `trial_timeline.csv.provenance.json` | 18 | 684 | `59aa8b8d4bb9f21f00889ee839f9b5a2bf24f2b9623e1ca8ea4a569cb2292f39` |

---

## 5. Audit Finding Resolution Summary

| Finding ID | Title | Root Cause in Legacy Codebase | Batch C2/C4 Resolution |
|---|---|---|---|
| **C2-01** | Campaign Attempts Ledger Discrepancy | Manifest recorded 282 attempts, but export tools assumed 280 completed trials, omitting the 2 cleanup failures. | Reconciled all 282 attempts in `attempts.csv` with foreign key tracking, preserving failure records and null metrics. |
| **C2-02** | Classification & Validity Enum Inconsistency | String literals were fragmented and unvalidated across runner, analyzer, and campaign manager. | Implemented canonical shared `(str, Enum)` enums (`FallbackClassification`, `TrialValidity`, `ConnectionOutcome`, `EventSource`) across all modules. |
| **C2-03** | Lack of Deterministic Campaign Exporter | No dedicated CLI existed to export multi-flow records; existing scripts emitted volatile timestamps. | Built `lab/export_campaign_evidence.py` with pure CSV data, fixed float formatting, and sibling `.provenance.json` sidecars per A13. |
| **C4-01** | Statistical Confounding in Research Cohorts | Cohorts were indexed solely by `(browser, scenario_id)`, confounding sweep RTT, versions, and kernel differences. | Created `ResearchCohortKey` dataclass supporting multi-factor research stratification. |
| **C4-02** | Conflation of TCP Streams with Application Operations | S5 multi-socket racing treated TCP streams as HTTP operations. | Deep dissection in `s5_flow_dissection.csv` categorizing flows into `PRIMARY`, `ANCILLARY`, `SPECULATIVE`, and `UNMATCHED`. |
| **C4-03** | Retransmitted SYN CAD Contamination | Retransmitted SYNs in S5 loss could advance initial SYN timestamp. | Enforced retransmission invariance: initial SYN timestamp locked to very first SYN; retries increment `retransmitted_syn_count`. |

---

## 6. Gate Determination

**FINAL DETERMINATION: PASS**

Batch C2 (Evidence Exports & Validity Reconciliation) and Batch C4 (Cohorts & S5 Flow Dissection) have met all acceptance criteria, passed all offline test suites (582 `lab` tests + 67 `tests` tests = 649 tests passing), verified bit-for-bit deterministic reproducibility, and preserved all 705 historical campaign artifacts untouched.

The codebase is ready to proceed to Milestone 4: Batch C3 (Standards Audit & RFC Crosswalk) and Batch C5 (S5 Privilege Isolation & DNS Robustness).
