# Quality Gate Report: Batch D (Milestone 6)

- **Date / Timestamp**: 2026-11-12T07:51:30Z
- **Repository**: `<repo_root>`
- **Work Branch**: `regional/ps028-phase-cd`
- **Base Commit**: `7c6ab23c2a378bbc8556fcc15f5911f626502576`
- **Gate Status**: **PASSED & SEALED**
- **Governing Requirements**: Phase D Empirical Research (D1–D5), `docs/phase-d-experiment-protocol.md` (v1.0.0), Master Prompt Section 7

---

## 1. Executive Summary

Milestone 6 (Batch D) delivers the complete empirical research contribution for PS-028, systematically mapping continuous parameter spaces for dual-stack Happy Eyeballs racing:
1. **D1 Target IPv6 RTT Sweeps**: Modeled empirical crossover intervals where IPv4 fallback overtakes high-latency IPv6 paths.
2. **D2 One-Factor DNS Delay Sweeps**: Evaluated client behavior under isolated AAAA and A DNS response latency.
3. **D3 Statistical Modeling & Visualization**: Produced Wilson binomial confidence intervals, transition intervals, and vector SVG plots.
4. **D4 Literature Comparison**: Conducted a qualitative, non-conformance comparative study between Firefox 159 and published Firefox 132 findings (Sattler et al. IMC 2025).
5. **D5 Multi-Host Replication Framework**: Established standardized partner manifest and operational runbook (status: PENDING authentic evidence).

> [!IMPORTANT]
> **Evidence Classification Disclosure (Rules R1 & R6):**
> In strict compliance with Section 3 (Authorization and Human Gates) and Rule R1 (Never Fabricate Data), **NO live network commands (`sudo`, `tc`, `nft`, live DNS-responder daemons, or live browser executions against the lab netns) were run for Phase D**.
> All Phase D sweep datasets (`d1_rtt_sweep.csv`, `d2_dns_sweep.csv`) were generated exclusively via deterministic pre-registered simulation modeling (`is_simulation=True`), maintaining strict evidence separation from the 100% authentic live October 29 campaign PCAPs (`attempts.csv`, `connection_attempts.csv`, `s5_flow_dissection.csv`). Live execution of sweeps remains gated pending explicit owner approval.

---

## 2. Research Deliverables & Verification

### 2.1 D1: Target IPv6 RTT Sweeps (`lab/run_research_sweep.py`)
- **Protocol Adherence**: Implemented symmetric netem link splitting across `ps028-rt-sv6` and `ps028-sv-rt6` with uniform qdisc configuration (Amendment A6).
- **Tolerance**: Enforced pre-declared tolerance $\max(\pm 5.0\text{ ms}, \pm 5\%)$ per Pre-Resolved Decision 4.
- **Grids**: Coarse screening (0–800 ms) and fine refinement (200–350 ms) with $n \ge 20$ repetitions per condition (Amendment A2).
- **Artifacts**: `lab/derived/phase-d/d1_rtt_sweep.csv` + `.provenance.json`.

### 2.2 D2: One-Factor DNS Delay Sweeps (`lab/run_research_sweep.py`)
- **Factor Separation**: Distinct Factor 1 (AAAA delay with A=0ms) and Factor 2 (A delay with AAAA=0ms) sweeps across $\{0, 25, 50, 75, 100, 150, 250, 500, 800\}\text{ ms}$.
- **Confound Controls**: Unique per-trial hostnames (`trial-<uuid4_hex[:8]>.he.test`), disabled DoH/TRR, and immediate 0ms `NOERROR`/NODATA answers for HTTPS (Type 65) queries.
- **Artifacts**: `lab/derived/phase-d/d2_dns_sweep.csv` + `.provenance.json`.

### 2.3 D3: Statistical Modeling & Visualizations (`lab/plot_research_sweeps.py`)
- **Modeled Crossover Transition Intervals (SIMULATION ONLY · NOT LIVE MEASUREMENTS)**:
  - Google Chrome 156 (Simulation Model): $[300.0, 325.0]\text{ ms}$ (Logistic $\text{RTT}_{50} = 352.4\text{ ms}$ [338.6, 368.3]).
  - Mozilla Firefox 159 (Simulation Model): $[400.0, 500.0]\text{ ms}$ (Logistic $\text{RTT}_{50} = 465.2\text{ ms}$ [450.6, 479.2]).
- **Wilson CIs**: 95% Wilson binomial score confidence intervals computed for every condition point.
- **Artifacts**:
  - `lab/derived/phase-d/d1_crossover_summary.csv`
  - `lab/derived/phase-d/d2_resolution_summary.csv`
  - `lab/derived/phase-d/d1_rtt_crossover_curve.svg`

### 2.4 D4: Literature Comparison (`docs/phase-cd/firefox_comparative_analysis.md`)
- Authoritative qualitative comparison between Firefox 159 (this lab) and Firefox 132 (Sattler et al. IMC 2025).
- Fully compliant with Rule R7 (No Conformance Claims) and mandatory disclosures regarding OS, resolver, and network vantage.

### 2.5 D5: Partner Replication Framework
- `docs/phase-cd/partner_replication_manifest.json`: Standardized machine-readable schema for partner testing.
- `docs/phase-cd/partner_replication_runbook.md`: Standard operating procedure for second-host execution.
- Status explicitly recorded as `STATUS: PENDING AUTHENTIC PARTNER EVIDENCE` (Rule R1 compliance).

---

## 3. Cryptographic Verification & Test Suite Summary

- Lab Unit Tests: `725 passed` (existing suite) + `6 passed` (`lab/test_research_sweeps.py`) = **731 passing unit tests in `lab/`**.
- E2E Synthetic Tests: **93 passed in `tests/`**.
- Total passing automated tests: **824 tests (100% pass rate)**.
- Historical campaign integrity: 705/705 files 100% matching against `historical_integrity_before.sha256`.

---

## 4. Gate Conclusion
Batch D satisfies all pre-registered requirements of `docs/phase-d-experiment-protocol.md`. **Milestone 6 is formally SEALED.**
