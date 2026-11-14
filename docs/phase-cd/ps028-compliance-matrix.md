# PS-028 Problem Statement Compliance & Verification Matrix

- **Date / Timestamp**: 2026-11-14T17:30:00Z (P2 Audit & Reconciliation; originally drafted 2026-11-12T07:54:00Z)
- **Repository**: `aiori-hackathon/A3-PS028-TC224`
- **Working Branch**: `work/ps028-p1-remediation`
- **Validated Source Commit**: `ee59362ac3f53fad3bc01e65b5d90815697a93d4`
- **Protected P0 Baseline**: `176f688bacb5858fcc0daedb454200918e427f3f` on `fix/phase-e-bundle-timeline-mapping` (tag: `ps028-p0-accepted-2026-11-14`)
- **Historical Derivation Branch**: `regional/ps028-phase-cd`
- **Category**: Internet Measurement (AIORI-3 PS-028)
- **Status**: **16/20 MET (80.0% Met, 3 Partial, 0 Owner-Only, 1 Pending; 14/15 Core Problem Statement Requirements Met)**

---

## 1. Compliance Matrix

| # | Problem Statement / Amendment Requirement | Implementation & Repository Location | Verifying Evidence & Artifacts | Compliance Status |
|:---|:---|:---|:---|:---:|
| **1** | **Two client implementations / pinned versions** | Pinned builds: Google Chrome 156.0.8078.73 & Mozilla Firefox 159.0 (`lab/run_trial.py`, `lab/scenarios.yaml`). | 280 valid live trials split evenly ($140$ Chrome, $140$ Firefox); zero unapproved browser additions (Rule R8). | **MET** |
| **2** | **Six controlled failure/delay scenarios + S0 baseline** | S0 (baseline 10ms RTT), S1 (IPv6 SYN drop), S2 (IPv6 TCP RST), S3 (symmetric 100ms), S4 (asymmetric IPv6 600ms, IPv4 10ms), S5 (50% SYN loss), S6 (500ms delayed AAAA) (`lab/scenarios.yaml`, `lab/impair.py`). | 40 trials per scenario across 7 scenarios ($7 \times 40 = 280$ trials) in campaign `ps028-a10-live-20261030-01`. | **MET** |
| **3** | **Controlled DNS & Pinned Specification Revision** | Controlled UDP DNS responder (`lab/dns_server.py`) with per-family delay injection; pinned specification of record `draft-ietf-happy-happyeyeballs-v3-04` (Amendment A10). | Dated status check: `2026-11-13`; wildcards `*.he.test.`; immediate NOERROR/NODATA for HTTPS Type 65. | **MET** |
| **4** | **Connection timelines for each test** | Multi-source chronological timeline collector (`lab/export_campaign_evidence.py`). | `lab/derived/phase-c/trial_timeline.csv` (28,330 events across HARNESS, PCAP, and TELEMETRY sources) + `.provenance.json`. | **MET** |
| **5** | **Winning family & failed attempts recorded** | Explicit classification and ledger generation (`lab/analyze.py`, `lab/run_trial.py`). | `lab/derived/phase-c/attempts.csv` (282 rows: 280 valid live + 2 cleanup failures; 154 direct IPv6, 126 IPv4 fallback). | **MET** |
| **6** | **$\ge 20$ repetitions per scenario** | Exactly 20 repetitions per browser $\times$ scenario ($2 \times 20 = 40$ trials/scenario) (`lab/run_campaign.py`). | Full 280 valid live trial dataset; exploratory sweeps with $n < 20$ barred from final claims (Amendment A2). | **MET** |
| **7** | **Connection setup time & fallback measurement** | Primary `GET /` stream RFC 9293 `t_connect_ms` (initial SYN to primary final ACK) and `t_setup_total_ms` (elapsed time from first target-host SYN observed across IPv4/IPv6 to primary final ACK; DNS timing evaluated separately via DNS transaction fields) (`lab/run_trial.py`, `docs/phase-c-metric-contract.md`). | `lab/derived/phase-c/connection_attempts.csv` (765 TCP flows classified with 0 indeterminate streams); `lab/derived/phase-c/attempts.csv` (280 valid live trials); `reconciliation_report.csv`. | **MET** |
| **8** | **Packet captures must validate connection attempts** | Dedicated packet capture per trial (`capture.pcap`); frame-level dissection linking `http.request_in`. | All 280 trial PCAPs verified with SHA-256 digests; 0 capture drops reported by kernel/interface. | **MET** |
| **9** | **Happy Eyeballs v3 treated as pinned draft** | Pinned reference `draft-ietf-happy-happyeyeballs-v3-04` published 1 July 2026; never labeled as settled RFC. | Documented across `README.md`, `PS028_REPRODUCIBILITY_RUNBOOK.md`, `docs/phase-c-metric-contract.md`. | **MET** |
| **10** | **No conformance claims on undocumented internals** | Strictly neutral 15-column observation schema; no assertions of browser violations or unobserved internal timers (Rule R7). | `lab/derived/phase-c/rfc8305_assessment.csv` (remediated S2 median contradiction; stratified Chrome vs Firefox reporting). | **MET** |
| **11** | **Submission PDF in Proposed-structure-hackathon.pdf format** | Automated build pipeline (`lab/build_submission_report.py`) compiling 11-slide Beamer layout ($160\text{ mm} \times 90\text{ mm}$, PT Sans, `#0000DC`). | `PS028_Hackathon_Submission_Presentation.pdf` generated (202,482 bytes, exactly 11 pages matching template geometry). | **MET** |
| **12** | **Technical Report PDF Regeneration (`PS028 Detailed Analysis & Report PDF.pdf`)** | Root submission technical report document. | Historical report preserved at root (`PS028 Detailed Analysis & Report PDF.pdf`); full LaTeX re-compilation not executed. | **PARTIAL** |
| **13** | **Prototype demonstration with pseudocode snippet** | Standalone replay utility (`lab/demo_replay.py`) replaying authentic PCAPs in $\le 10$ seconds, plus `--pseudocode` flag. | `lab/demo_replay.py` executes cleanly; prints canonical Happy Eyeballs connection racing pseudocode snippet. | **MET** |
| **14** | **Unprivileged safety & bounded helper isolation** | Dedicated unprivileged helper `lab/privileged_helper.py` mediating narrow network operations with integer bounds. | Zero ambient root assertions; 95 helper unit tests + 48 adversarial challenge tests passing. | **MET** |
| **15** | **Cryptographic preservation of historical evidence** | Cryptographic seal of October 29 campaign `ps028-a10-live-20261030-01` (Rule R2). | 705 files verified 100% matching against `lab/derived/phase-c/historical_integrity_before.sha256`. | **MET** |
| **16** | **Amendment A.6 (Uniform netem qdisc on live sweep)** | Pre-registered in `docs/phase-d-experiment-protocol.md` and modeled in `lab/run_research_sweep.py`. | Design and simulation code verified; live execution with `tc netem delay 0ms 0ms` pending live approval gate. | **PARTIAL** |
| **17** | **Live S5 Validation (Exact Binomial Acceptance on Live Host)** | `lab/self_test_scenarios.py` with pure-Python Clopper-Pearson 99% Exact Binomial CI ($n=200$). | Fully verified in unit tests and dry-run bundle export; live network socket batch execution pending live gate. | **PARTIAL** |
| **18** | **Repository Ownership Transfer & Collaborator Access** | Ownership transfer and collaborator configuration in GitHub repository settings. | Confirmed transferred to organisation `aiori-hackathon` on 14 November 2026; repository URL: `https://github.com/aiori-hackathon/A3-PS028-TC224.git`; verified via GitHub API repository metadata (`gh api repos/aiori-hackathon/A3-PS028-TC224` confirmed `owner: aiori-hackathon`). No agent execution of permissions or settings was performed. | **MET** |
| **19** | **Offline test suite reproducibility** | Reproducible offline unit, synthetic, and regression test suites. | Historical progression: Phase C/D gate: 725 lab + 93 synthetic = 818 tests; Phase C/D baseline: 731 lab + 93 synthetic = 824 tests; Phase E demo readiness: 825 lab + 93 synthetic = 918 tests; Task 5C deduplicated discovery: 788 lab + 93 synthetic = 881 tests; P0 sealed baseline: 804 lab + 93 synthetic + 31 frontend = 928 unit tests (`lab/derived/phase-c/test_run_record.json`); **Authoritative P1 validation snapshot (14 Nov 2026, commit `ee59362ac3f5`)**: **929 unique automated tests** (805 lab + 93 synthetic + 31 frontend; 100% PASS, 0 failures, 0 errors; separate 16 static smoke checks & 8-stage / 53-assertion browser suite; remote CI not configured/recorded). | **MET** |
| **20** | **Phase A.6 Partner Replication Package (Multi-Host Evidence)** | Second-host validation package (`docs/phase-cd/partner_replication_manifest.json`, `docs/phase-cd/partner_replication_runbook.md`). | Complete replication manifest and SOP authored; multi-host authentic evidence collection awaiting external partner execution. | **PENDING** |

### 1.1 Compliance Status Breakdown

| Status Category | Count | Percentage | Scope Details |
|:---|:---:|:---:|:---|
| **MET** | 16 | 80.0% | Fully fulfilled and verified with cryptographic evidence (#1–#11, #13–#15, #18, #19). |
| **PARTIAL** | 3 | 15.0% | #12 (Report PDF regeneration; historical PDF preserved), #16 (Uniform netem live sweep), #17 (Live S5 binomial batch). |
| **OWNER-ONLY** | 0 | 0.0% | None remaining; Requirement #18 verified transferred to `aiori-hackathon` organisation on 14 November 2026. |
| **PENDING** | 1 | 5.0% | #20 (Phase A.6 partner replication multi-host evidence; awaiting external partner host execution). |
| **Total Tracked** | **20** | **100.0%** | Comprehensive problem statement and amendment tracking. |

### 1.2 Specification Notes on Timing Metrics and Test Count Evolution

- **Canonical Timing Metric Definition (`t_setup_total_ms`)**: In accordance with `docs/phase-c-metric-contract.md` §1.2, `t_setup_total_ms` measures the trial-level transport connection setup interval from the first target-host SYN observed across IPv4 and IPv6 during a trial to the final ACK of the selected primary TCP connection (in fallback scenarios, including the elapsed interval before the selected primary connection completes):
  $$t_{\text{setup\_total}} = \left( t_{\text{final\_ack, primary}} - \min_{f \in \{\text{IPv4}, \text{IPv6}\}} \left( t_{\text{first\_syn, } f} \right) \right) \times 1000$$
  DNS timing is evaluated through separate DNS transaction fields (`dns_transactions`) and Resolution Delay metrics, and must not be conflated with this TCP setup metric. It does not measure user-visible navigation delay, application response time, or page-load performance.
- **Test Count Evolution & Seven-Milestone Chronology Reconciliation**:
  - *Stale Placeholder Note*: An early README reference to "400 tests" was identified during independent repository audit (`docs/phase-cd/finding-verification.md` and `docs/phase-cd/repo-audit-register.md`) as a stale unverified placeholder; the verified initial baseline comprised 524 automated tests (431 lab + 93 synthetic).
  - **Milestone 1 — 524 tests (Initial Preflight Baseline)**: Initial testbed baseline suite (431 in `lab/` + 93 in `tests/`).
  - **Milestone 2 — 818 tests (`docs/phase-cd/gates/batch_c5.md`)**: Sealed historical gate report snapshot (725 in `lab/` + 93 in `tests/`) at Phase C/D milestone.
  - **Milestone 3 — 824 tests (`regional/ps028-phase-cd` HEAD)**: Phase C/D baseline incorporating Batch D research sweep simulation tests (731 in `lab/` + 93 in `tests/`).
  - **Milestone 4 — 918 tests (`regional/phase-e-demo-readiness`)**: Phase E demo-readiness baseline (825 in `lab/` + 93 in `tests/`).
  - **Milestone 5 — 881 tests (Task 5C deduplicated checkout on `fix/phase-e-bundle-timeline-mapping`)**: Deduplicated repository test discovery (788 in `lab/` across 21 modules + 93 in `tests/` across 5 tiers: 881 unique test cases; 0 duplicate executions following Task 5C runner deduplication; 866 passed, 4 failed, 11 unprivileged sandbox errors; 199 focused offline regression tests passing 100%), incorporating 11 regression tests added during Tasks 1–3A and Task 5B (+2 in `test_demo_bundle.py`, +7 in `test_export_campaign_evidence.py`, +1 in `test_analyze.py`, +1 in `test_impair.py`).
  - **Milestone 6 — 928 tests (Historical P0 test-execution baseline)**: Executed on P0 source commit `5c84c93eff12903a1288770029a903aec48ac1a4` (timestamp `2026-11-14T15:07:31Z`) and recorded in `lab/derived/phase-c/test_run_record.json` (`2026-11-14T15:08:45Z`; 804 in `lab/` + 93 in `tests/` + 31 frontend tests in `setup/webtester/test/historical-evidence.test.mjs`), with derived evidence regenerated and frozen at acceptance commit `176f688bacb5858fcc0daedb454200918e427f3f` (tag `ps028-p0-accepted-2026-11-14`). Preserved as immutable historical P0 evidence.
  - **Milestone 7 — 929 tests (Authoritative P1 validation snapshot, 14 Nov 2026)**: Documented in `docs/phase-cd/p1-validation-record-2026-11-14.md` on tested source commit `ee59362ac3f53fad3bc01e65b5d90815697a93d4`. Adds +1 regression test (`test_scientific_presentation_claims_accuracy` in `lab/test_build_submission_report.py`) enforcing presentation and evidence integrity (805 in `lab/` + 93 in `tests/` + 31 in `setup/webtester`: 929 unique automated tests; 929 passed, 0 failures, 0 errors, 0 skips; 100% PASS). Separate validations: 16 static smoke checks, 8 browser stages with 53 assertions, 8 static pages built; remote CI not configured/recorded. See `docs/phase-cd/test-inventory-reconciliation.md`.

---

## 2. Conclusion

Of the twenty tracked requirements across the problem statement and amendments:
- **16 are MET (80.0%)**, including 14 of the 15 core binding problem statement requirements (#1–#11, #13–#15) plus repository ownership transfer (#18) and offline test suite reproducibility (#19).
- **3 are PARTIAL (15.0%)**: Requirement #12 (LaTeX technical report re-compilation; historical PDF preserved at root), Requirement #16 (uniform netem live sweep modeling verified; live sweep gated), and Requirement #17 (exact binomial live verification validated in simulation; live network socket batch gated).
- **0 are OWNER-ONLY (0.0%)**: Requirement #18 verified transferred to `aiori-hackathon` on 14 November 2026 via GitHub repository metadata.
- **1 is PENDING (5.0%)**: Requirement #20 (Phase A.6 partner replication package authored; multi-host execution awaiting external partner infrastructure).

Blanket 100% compliance is not claimed; all requirements are honestly and transparently accounted for with verifiable evidence.
