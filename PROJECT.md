# Project: PS-028 Happy Eyeballs Measurement Lab (Phase C & Phase D)

## Architecture
The Happy Eyeballs IPv4/IPv6 Fallback Measurement Lab evaluates browser connection racing behaviors under controlled network impairments across three Linux network namespaces:
- `ps028-cl` (Client): Executes browser binaries (Google Chrome, Mozilla Firefox) with isolated profiles, tracing tools (PCAP, NetLog), and DNS resolution.
- `ps028-rt` (Router): Implements network emulation via `tc netem` (symmetric link delays, jitter, packet loss) and stateful packet filtering via `nftables` (SYN blackholing, RST injection).
- `ps028-sv` (Server): Runs controlled dual-stack HTTP servers (Nginx) and a configurable DNS responder supporting independent delays for A and AAAA records, as well as HTTPS/SVCB (Type 65) handling.

```
+---------------------------------------------------------------------------------------+
|                                    PROJECT TOPOLOGY                                   |
|                                                                                       |
|  [ps028-cl (Client)]              [ps028-rt (Router)]             [ps028-sv (Server)]  |
|  198.51.100.2 / 2001:db8:1::2     ps028-rt-cl4 / ps028-rt-cl6     198.51.100.10       |
|  Browser (Chrome / Firefox)  <-->        tc netem / nft     <-->  2001:db8:2::10      |
|  DNS resolver config              ps028-rt-sv4 / ps028-rt-sv6     Nginx (HTTP/1.1)    |
|                                                                   DNS Responder       |
+---------------------------------------------------------------------------------------+
```

## Feature Inventory
Every requirement, finding, and deliverable identified in the Step 0 Survey is inventoried and mapped to a milestone below.

| # | Feature / Work Item | Description | Milestone | Source |
|---|---------------------|-------------|-----------|--------|
| 1 | Base Branch Resolution | Resolve `regional/p0-remediation` as base branch; create work branch `regional/ps028-phase-cd` | M1 | R1, Finding 0.1–0.2 |
| 2 | Baseline Environment & Test Log | Record Python, OS, kernel, tshark, git versions; execute 524 baseline tests into `docs/phase-cd/baseline.md` | M1 | R1, Finding 0.3 |
| 3 | Pre-Operation SHA-256 Baseline | Record SHA-256 hashes of all 280 PCAPs, manifests, result JSONs into `lab/derived/phase-c/historical_integrity_before.sha256` | M1 | R1, Finding 0.4, Rule R2 |
| 4 | Audit Finding Verification | Verify findings C1-01 through C6-01 against actual code in `docs/phase-cd/finding-verification.md` | M1 | R1, Finding 0.5 |
| 5 | Repo-Wide Audit Register | Comprehensive sweep of all files (DNS, server, setup, scripts) into `docs/phase-cd/repo-audit-register.md` | M1 | R1, Amendment A12 |
| 6 | Metric Contract Formulation | Define `t_connect_ms`, `t_setup_total_ms`, `syn_to_synack_ms`, DNS metrics, schema 1.1.0 in `docs/phase-c-metric-contract.md` | M1 | R1, Decisions 1–3, Amendments A1–A4 |
| 7 | Research Protocol Formulation | Define screening/refinement grids, identical qdiscs, Wilson CIs in `docs/phase-d-experiment-protocol.md` | M1 | R1, Decisions 4–6, Amendments A5–A8 |
| 8 | User Approval Gate (Contract) | Obtain user approval on metric contract and experiment protocol before proceeding | M1 | R1, Step 0.7 |
| 9 | TCP Connection Completion Metrics | Implement `t_connect_ms` (initial SYN to primary final ACK) and `t_setup_total_ms` (first SYN of any family to primary final ACK) | M2 | R2, C1-03, Decisions 1, A3 |
| 10 | Legacy Metric Preservation | Preserve `connection_setup_time_ms` definition (SYN to SYN/ACK) and export as diagnostic `syn_to_synack_ms` | M2 | R2, C1-03, Rule R3 |
| 11 | DNS Transaction Parsing | Extract dns.id, exact qname, qtype, rcode, transport (UDP/TCP), answer records, resolution duration per family | M2 | R2, C1-02, Decision 3, A7 |
| 12 | DNS-to-First-Byte Metrics | Extract `dns_query_to_first_payload_ms` and `dns_last_positive_response_to_first_payload_ms` | M2 | R2, Decision 2 |
| 13 | HTTPS/SVCB Tracking | Separate HTTPS/SVCB (Type 65) tracking from A/AAAA resolution statistics | M2 | R2, Amendment A8 |
| 14 | Schema 1.1.0 & Backward Compatibility | Bump schema to 1.1.0 with compact primary flow object; `analyze.py` supports 1.0.0 and 1.1.0, fails closed on unknown | M2 | R2, C1-04 |
| 15 | Historical PCAP Re-derivation | Re-derive all 280 October 29 PCAPs into `lab/derived/phase-c/` and reconcile against stored metrics | M2 | R2, C1-01 |
| 16 | Campaign Attempts Export | Export `attempts.csv` reconciling exactly 282 attempts (280 valid live + 2 cleanup failures) | M3 | R2, C2-01, C2-02 |
| 17 | Connection Attempts Export | Export `connection_attempts.csv` recording every TCP connection attempt with 5-tuple, stream, timestamps, outcome | M3 | R2, Amendment A1 |
| 18 | Trial Timeline Export | Export `trial_timeline.csv` merging harness and PCAP events with explicit `event_source` provenance | M3 | R2, C2-03, Amendment A9 |
| 19 | Shared Classification Enum & Matrix | Enforce single shared classification enum and validity matrix across runner and analyzer | M3 | R2, C2-02 |
| 20 | Cohort Key Expansion & S5 Stream Export | 14 browser × scenario cohorts (n=20); version-aware/environment-aware cohort keys; offline S5 TCP-flow export | M3 | R2, C4-01, C4-02, C4-03 |
| 21 | Terminology Glossary | Create `docs/phase-cd/glossary.md` defining attempt vs connection attempt vs probe vs tcp.stream | M3 | R2, Amendment A1 |
| 22 | Privilege Isolation (`privileged_helper.py`) | Add subcommands `setup-s5-counters`, `read-s5-counters`, `measure-s5` (JSONL output) with strict allowlists and integer bounds | M4 | R2, C5-01, C5-02, C5-04 |
| 23 | Unprivileged Harness Refactoring | Remove direct `require_root()` calls from `self_test_scenarios.py` and `impair.py` | M4 | R2, C5-01 |
| 24 | Fail-Closed DNS Configuration Reload | Enforce PID validation, `/proc/{pid}/cmdline` check, `dns.log` SIGHUP readback, and measured query timing check | M4 | R2, C5-03 |
| 25 | Sudoers Documentation | Document exact non-interactive sudoers rules in docs/runbook without editing system files | M4 | R2, C5-05, Rule R11 |
| 26 | RFC 8305 Citation Crosswalk | Audit RFC 8305 §3 (Resolution Delay), §4 (Sorting), §5 (Racing), §8 (Timers); fix runbook line 218 & CSV | M5 | R2, C3-01 |
| 27 | Boundary Fixtures & Re-issued RFC Assessment | Evaluate <10ms, 10–100ms, 100–2000ms, >2000ms boundary fixtures; re-issue RFC assessment CSV with R7 neutral wording | M5 | R2, C3-02, C3-03 |
| 28 | HEv3 Draft Pin Status Check | Pinned draft revision of record `draft-ietf-happy-happyeyeballs-v3-04`; informational status check for `-05` | M5 | R2, Amendment A10 |
| 29 | Documentation Correction & PDF Alignment | Correct stale test counts, broken links, paths; align technical report with `Proposed-structure-hackathon.pdf` | M5 | R2, C6-01, E2 |
| 30 | Constrained Research Runner | Build dedicated research sweep runner preserving canonical S0–S6 lifecycles and fail-stop handling | M6 | R3, D1–D5 |
| 31 | Target IPv6 Delay Sweep (D1) | Screening 0–800ms, refinement 25–50ms around transition, n ≥ 20 per condition, symmetric delay, identical netem qdiscs | M6 | R3, D1, Decisions 4–5, A2, A6 |
| 32 | DNS Delay Sweeps (D2) | One-factor AAAA delay and A delay sweeps (0–800ms) with unique per-trial hostnames and fresh profiles | M6 | R3, D2, Decision 6, A7, A8 |
| 33 | Analysis & Visualization (D3) | Stratified ECDFs, Wilson CIs for primary-family share, crossover transition intervals, deterministic seeded bootstrap | M6 | R3, D3, Amendment A5, A13 |
| 34 | Firefox Comparative Analysis (D4) | Qualitative comparison between Firefox 159 observations and published Firefox 132 literature (Sattler et al.) | M6 | R3, D4, Decision 8 |
| 35 | Multi-Host Readiness Framework (D5) | Partner subset manifest, environment capture script, and runbook; status pending authentic partner evidence | M6 | R3, D5, Decision 9 |
| 36 | PS-028 Compliance Matrix (E1) | Comprehensive requirement-to-evidence mapping in `docs/phase-cd/ps028-compliance-matrix.md` | M7 | R4, E1 |
| 37 | Demonstration Kit (E3) | Runnable offline demonstration script (≤ 10 min) replaying preserved PCAPs alongside Happy Eyeballs pseudocode | M7 | R4, E3 |
| 38 | Repository Hygiene & Clean Reproduction (E4/E5) | Clean git tree, pinned dependencies, tested one-command offline reproduction, owner handover checklist | M7 | R4, E4, E5 |
| 39 | E2E Testing Suite (Tiers 1–4) | Opaque-box test suite covering feature coverage, boundaries, pairwise combinations, and real-world workloads | M7 | Dual Track, TEST_READY.md |
| 40 | Adversarial Coverage Hardening (Tier 5) | White-box adversarial testing, edge case stress-testing, and regression hardening | M7 | Dual Track Final Phase |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Step 0 Preflight & Baseline Establishment | Base branch resolution, baseline recording, pre-op SHA-256, finding verification, repo audit register, metric contract & experiment protocol | none | DONE |
| M2 | Phase C1 Parser, Metrics & Schema Evolution | `t_connect_ms`, `t_setup_total_ms`, `syn_to_synack_ms`, DNS extraction, schema 1.1.0, 280 PCAP re-derivation | M1 | DONE |
| M3 | Phase C2 & C4 Evidence Exports & Cohorts | `attempts.csv` (282 attempts), `connection_attempts.csv`, `trial_timeline.csv`, classification matrix, cohorts, glossary | M2 | DONE |
| M4 | Phase C5 Privilege Isolation & DNS Robustness | `privileged_helper.py` subcommands, unprivileged harness refactoring, fail-closed DNS reload verification | M1 | IN_PROGRESS |
| M5 | Phase C3 Standards Audit & Technical Report | RFC 8305 crosswalk, boundary fixtures, draft pin check, documentation fixes, official hackathon PDF report | M2, M3 | PLANNED |
| M6 | Phase D Empirical Research Contributions | Constrained research runner, IPv6 delay sweep (D1), DNS delay sweeps (D2), stratified plots & Wilson CIs (D3), Firefox comparative analysis (D4), partner readiness (D5) | M2, M4 | PLANNED |
| M7 | E2E Test Suite, Hackathon Readiness & Demo Kit | 100% E2E test pass (Tiers 1–4), Tier 5 adversarial hardening, compliance matrix, demonstration kit, handover checklist | M3, M5, M6 | PLANNED |

## Interface Contracts
### Parser ↔ Analyzer / Exporters (`lab/run_trial.py` ↔ `lab/analyze.py` / `lab/export_campaign_evidence.py`)
- Schema Version: Minor bump to `"1.1.0"`. `analyze.py` MUST accept both `["1.0.0", "1.1.0"]` and reject any other version fail-closed.
- Metric Dictionary:
  - `t_connect_ms`: float | null (reason code if null). Primary stream initial SYN to matching client final ACK.
  - `t_setup_total_ms`: float | null. First target-host SYN of any family to primary final ACK.
  - `syn_to_synack_ms`: float | null. Diagnostic legacy metric (initial SYN to matching SYN/ACK).
  - `dns_query_to_first_payload_ms`: float | null. Target-host DNS query start to first data-bearing TCP payload.
  - `dns_last_positive_response_to_first_payload_ms`: float | null.
  - `dns_transactions`: list of objects containing `dns.id`, `qname`, `qtype`, `rcode`, `transport`, `answers`, `duration_ms`.
  - `https_svcb_queries`: list of objects tracking Type 65 queries separately from A/AAAA.

### Privilege Helper Interface (`lab/privileged_helper.py` ↔ Harness Scripts)
- Invocation: strictly via argv list `["python3", "lab/privileged_helper.py", "<subcommand>", ...args]` (no shell strings).
- Subcommands:
  - `setup-s5-counters`: configure router nftables counters.
  - `read-s5-counters`: output JSON dictionary of router aggregate counters.
  - `measure-s5`: perform constrained probe with integer count bound, emitting per-probe JSONL records.
- Error Handling: non-zero exit codes on any validation failure, structured error emission to stderr.

### DNS Reload Interface (`lab/impair.py` ↔ `lab/dns_server.py`)
- Reload Protocol: Deliver `SIGHUP` to verified PID of `dns_server.py`.
- Validation: Readback from `dns.log` confirming `"SIGHUP config reload applied successfully"`, plus active query timing check within pre-declared tolerance (±25ms). Fail-closed if confirmation is missing.

## Code Layout
- `lab/`: Core testbed execution, impairment, and analysis scripts
  - `run_trial.py`: Single trial orchestration, browser launch, packet capture parsing
  - `run_campaign.py`: Campaign slot execution, matrix iteration
  - `analyze.py`: PCAP and campaign results post-processing, RFC 8305 evaluation
  - `export_campaign_evidence.py`: Deterministic evidence export (`attempts.csv`, `trial_timeline.csv`, `connection_attempts.csv`)
  - `privileged_helper.py`: Narrow root-authorized helpers with strict argument validation
  - `impair.py`: Netem and nftables impairment controls
  - `dns_server.py`: Custom DNS responder with per-family delay injection
  - `scenarios.yaml`: Canonical definition of scenarios S0–S6
  - `test_*.py`: 21 unit and regression test modules in `lab/` (788 unique tests discovered, 773 passed; 881 unique tests discovered across repository, 0 duplicate executions, 866 passed; 199 focused regression tests passing 100%)
- `lab/derived/`: All newly generated derived artifacts
  - `lab/derived/phase-c/`: Phase C re-derived metrics, integrity checksums, exports, RFC assessments
  - `lab/derived/phase-d/`: Phase D sweep condition manifests, raw traces, long-form datasets, figures
- `docs/`: Technical reports and specifications
  - `phase-c-metric-contract.md`: Binding contract for all Phase C metrics and schemas
  - `phase-d-experiment-protocol.md`: Pre-registered experiment protocol for Phase D sweeps
  - `phase-cd/`: Audit register, finding verification, baseline records, compliance matrix, glossary
- `tests/`: End-to-end and integration test suites
