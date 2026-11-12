# PS-028 Happy Eyeballs Measurement Lab: Test Infrastructure Specification

**Document Version**: 1.0.0  
**Status**: APPROVED / ACTIVE  
**Track**: Independent End-to-End Testing Track (Test Writer)  
**Target Environment**: Offline-Executable Standard Python `unittest`  
**Authoritative References**: RFC 8305, RFC 9293, RFC 6724, RFC 1035, PS-028, AIORI-3 Submission Requirements  

---

## 1. Executive Overview & Test Philosophy

### 1.1 Philosophy: Opaque-Box, Requirement-Driven Verification
The Happy Eyeballs Measurement Lab evaluates browser dual-stack connection racing under controlled network impairments. To ensure absolute scientific credibility, impartiality, and reproducibility, the end-to-end test harness operates under an **opaque-box, requirement-driven testing paradigm**:

1. **Specification as Oracle**: Test expectations are derived exclusively from authoritative protocol specifications (RFC 8305 Happy Eyeballs v2, RFC 9293 Transmission Control Protocol, RFC 6724 Default Address Selection) and the PS-028 Problem Statement. Tests do **not** depend on or inspect private implementation internals of the measurement harness or browser binaries.
2. **Offline Executability & Determinism**: Every unit and integration test in `tests/` executes offline without requiring live network interfaces, kernel namespace (`ip netns`) manipulations, root privileges (`sudo`), or real browser launches. Test fixtures simulate authentic wire packets, DNS payloads, and harness outputs deterministically.
3. **Fail-Closed Verification**: Interface boundaries (schema versions, metric ranges, state transitions) fail closed. Missing, unpairable, or ambiguous metrics must evaluate to `null` with explicit diagnostic reason codes—never implicitly coerced to zero.
4. **Historical Preservation & Safety**: No test modifies or mutates historical campaign datasets under `lab/campaigns/` or base code in `lab/` and `src/`. The testing track is strictly isolated to `tests/` and project-root test metadata (`TEST_INFRA.md`, `TEST_READY.md`).

---

## 2. 4-Tier Testing Methodology

The testing architecture is organized into four hierarchical verification tiers, providing complete validation from component-level invariant checks to full end-to-end application workloads.

```
+-----------------------------------------------------------------------------+
|                                4-TIER ARCHITECTURE                          |
+-----------------------------------------------------------------------------+
|  Tier 4: Real-World Scenarios   | Broadband, Mobile Handover, Enterprise     |
|                                 | Blackhole, CDN Anycast, Satellite Link     |
+---------------------------------+-------------------------------------------+
|  Tier 3: Cross-Feature Pairs    | DNS Delay + SYN RST, Delay + Loss,        |
|                                 | Blackhole + DNS Delay, HTTPS/SVCB + Timeout|
+---------------------------------+-------------------------------------------+
|  Tier 2: Boundary & Corners     | Zero Delay, Extreme Delay, Retransmits,   |
|                                 | Missing Final ACK, Malformed DNS, Schema  |
+---------------------------------+-------------------------------------------+
|  Tier 1: Feature Coverage       | S0–S6 Invariants, CAD Racing, DNS Parsing,|
|                                 | Schema 1.1.0/1.0.0, Evidence CSV Validity |
+-----------------------------------------------------------------------------+
```

### 2.1 Tier 1: Feature Coverage (Baseline & Core Functionality)
- **Objective**: Establish baseline behavioral correctness for each discrete functional module against its normative specification.
- **Scope**:
  - **Feature 1 (Scenarios S0–S6)**: Validates canonical impairment definitions, target address families, network delays (symmetric link RTTs), and DNS delays.
  - **Feature 2 (Dual-Stack Racing & Metrics)**: Verifies RFC 8305 racing state transitions, initial IPv6 preference, CAD timer expiration, IPv4 fallback initiation, and primary stream completion.
  - **Feature 3 (DNS Metrics & Transactions)**: Verifies extraction of `dns.id`, `qname`, `qtype`, `rcode`, transport, answer counts, resolution duration per family, and separate HTTPS/SVCB (Type 65) tracking.
  - **Feature 4 (Schema Parsing & Evolution)**: Validates dual-version parsing of Schema `1.1.0` (with compact primary flow object) and legacy `1.0.0`, with fail-closed rejection of unrecognized versions.
  - **Feature 5 (Export Validity & Reconciliation)**: Verifies deterministic generation of `attempts.csv` (282 reconciled attempts), `connection_attempts.csv` (5-tuple per-flow records), and `trial_timeline.csv` (with strict provenance enum `HARNESS | PCAP | BROWSER_TELEMETRY`).
- **Requirement**: Minimum $\ge 5$ distinct test cases per feature (total $\ge 25$ tests).

### 2.2 Tier 2: Boundary & Corner Cases (Stress & Extreme Conditions)
- **Objective**: Stress edge conditions, zero values, extreme bounds, protocol abnormalities, and corrupt payloads to guarantee robust failure containment.
- **Scope**:
  - **Boundary Delay & Loss**: Link delay at 0ms (explicit zero netem delay vs baseline), extreme delays (10,000ms / 30,000ms), 0% vs 100% packet loss, extreme jitter, and RFC 8305 CAD boundary thresholds (10ms floor, 100ms recommended min, 250ms default, 2000ms ceiling).
  - **Protocol Anomalies**: Missing final ACK (SYN + SYN/ACK exchanged without client final ACK $\to$ connection not established, $t_{\text{connect}}$ must be `null`), retransmitted SYNs (verifying initial SYN timestamp does not advance), immediate RST on SYN, and both families timing out simultaneously.
  - **DNS Parsing Corner Cases**: Malformed DNS wire buffers, zero-length question sections, 255-byte maximum domain labels, unpaired DNS queries, and multiple RR answer ordering.
  - **Schema Boundary Checks**: Schema version variations (`1.0.1`, `1.2.0`, `2.0.0`), null value preservation (ensuring `0.0` is not coerced to `null` and `null` is not coerced to `0.0`), empty payloads (`{}`), and type mismatch handling.
  - **Export Edge Cases**: Zero-row empty datasets, single-trial datasets ($n=1$ degrees of freedom), row count boundaries (282 vs 281/283), and colliding connection 5-tuples.
- **Requirement**: Minimum $\ge 5$ distinct test cases per feature (total $\ge 25$ tests).

### 2.3 Tier 3: Cross-Feature Combinations (Pairwise Protocol Interactions)
- **Objective**: Verify compound interactions where multiple impairment mechanisms (DNS delays, packet loss, TCP reset injection, latency differentials) operate simultaneously.
- **Scope**:
  1. *DNS Delay + SYN RST*: AAAA DNS response delayed by 500ms; when received, IPv6 SYN receives an immediate TCP RST $\to$ instant client fallback to IPv4.
  2. *IPv6 High Delay + High Loss*: 150ms link RTT combined with 50% SYN loss $\to$ multiple SYN retransmissions race against IPv4 CAD timer.
  3. *IPv6 SYN Blackhole + DNS A Delay*: IPv6 SYN silently blackholed, but DNS A query also delayed by 250ms $\to$ dual-stage fallback delay.
  4. *Concurrent HTTPS/SVCB Resolution + IPv6 Timeout*: Fast Type 65 response concurrent with unresponsive IPv6 endpoint.
  5. *Asymmetric Network Delay + SYN Retransmissions*: Uplink delay differs from downlink delay, testing timestamp integrity under retransmissions.
  6. *Impairment Rollback Failure + Export Reconciliation*: Verifying that aborted trials due to teardown issues are classified as `EXCLUDED_CLEANUP_FAILURE` without corrupting valid live metrics.
- **Requirement**: Minimum $\ge 6$ multi-factor combination tests.

### 2.4 Tier 4: Real-World Application Scenarios (End-to-End Workloads)
- **Objective**: Emulate realistic production network environments and application workloads exercising complete Happy Eyeballs fallback flows.
- **Scope**:
  1. *Dual-Stack Fast Broadband (FTTH)*: IPv6 15ms RTT, IPv4 20ms RTT, DNS 5ms $\to$ Clean IPv6 win, zero fallback, minimal connection setup time.
  2. *Mobile Cellular Handover*: Transient IPv6 packet drop during cell tower transition $\to$ CAD timer (250ms) expires, IPv4 connection establishes seamlessly over secondary path.
  3. *Enterprise IPv6 Firewall Blackhole*: Local dual-stack interface enabled with SLAAC, but WAN perimeter silently discards outgoing IPv6 SYN $\to$ RFC 8305 fallback to IPv4 with $t_{\text{setup\_total}}$ reflecting CAD + IPv4 RTT.
  4. *CDN Anycast DNS Degradation*: Authoritative AAAA nameserver degraded (400ms delay), IPv4 nameserver fast (20ms) $\to$ Happy Eyeballs starts IPv4 connection first upon resolution delay expiration.
  5. *High-Latency Satellite Link (GEO/LEO)*: 600ms IPv6 RTT with 30ms local IPv4 gateway fallback $\to$ racing dynamic under significant bufferbloat.
- **Requirement**: Minimum $\ge 5$ comprehensive scenario tests.

---

## 3. Feature Inventory & Traceability Matrix

| Feature ID | Feature Name | Normative Source | Test Tier | Verifying Module |
|---|---|---|---|---|
| **F-01** | Impairment Scenarios S0–S6 Invariants | PS-028 §4, `scenarios.yaml` | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-02** | Dual-Stack Racing & CAD Timers | RFC 8305 §5, RFC 9293 §3.5 | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-03** | Primary Stream & TCP Setup Metrics | RFC 8305 §5, PROJECT.md M2, Decision 1 | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-04** | DNS Transaction Extraction & Metrics | RFC 8305 §3, Decision 2, Amendment A7 | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-05** | HTTPS / SVCB Tracking Separation | RFC 9460, PROJECT.md M2, Amendment A8 | Tier 1, 3 | `tests/test_tier1_features.py`, `tests/test_tier3_combinations.py` |
| **F-06** | Schema Evolution & Backward Compatibility | PROJECT.md M2 § Interface Contracts | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-07** | Evidence Export Reconciliation (282 Rows) | PROJECT.md M3, Finding C2-01 | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-08** | Flow Connection Attempts & Timeline | PROJECT.md M3, Amendments A1, A9 | Tier 1, 2 | `tests/test_tier1_features.py`, `tests/test_tier2_boundaries.py` |
| **F-09** | Pairwise Impairment Interaction | PS-028 §5, RFC 8305 §5 | Tier 3 | `tests/test_tier3_combinations.py` |
| **F-10** | Real-World Application Workloads | PS-028 §6, RFC 8305 §1 | Tier 4 | `tests/test_tier4_scenarios.py` |

---

## 4. Test Architecture & Execution Semantics

### 4.1 Directory Layout
```
<repo_root>/
├── TEST_INFRA.md                   # This document
├── TEST_READY.md                   # Execution and readiness report
└── tests/
    ├── __init__.py                 # Test package initialization
    ├── common/
    │   ├── __init__.py             # Common utilities package
    │   ├── models.py               # Domain dataclasses (Packets, DNS, Schema, Exports)
    │   ├── simulators.py           # RFC 8305 racing simulator, DNS codec, validators
    │   └── fixtures.py             # Reusable packet traces and scenario templates
    ├── test_tier1_features.py      # Tier 1: Feature Coverage (>= 25 tests)
    ├── test_tier2_boundaries.py    # Tier 2: Boundary & Corner Cases (>= 25 tests)
    ├── test_tier3_combinations.py  # Tier 3: Cross-Feature Combinations (>= 6 tests)
    └── test_tier4_scenarios.py     # Tier 4: Real-World Scenarios (>= 5 tests)
```

### 4.2 Runner Location & Invocation Semantics
The entire test suite is fully discoverable and executable via standard Python `unittest`:

```bash
# Full test suite execution:
python3 -m unittest discover -s tests -p "test_*.py" -v

# Individual tier execution:
python3 -m unittest tests/test_tier1_features.py -v
python3 -m unittest tests/test_tier2_boundaries.py -v
python3 -m unittest tests/test_tier3_combinations.py -v
python3 -m unittest tests/test_tier4_scenarios.py -v
```

### 4.3 Deterministic Synthetic Engines
To maintain 100% offline isolation without mock brittleness, `tests/common/simulators.py` implements mathematical and protocol simulators:
1. **`HappyEyeballsSimulator`**: An exact state-machine implementation of RFC 8305 §5. Simulates socket connect calls, SYN transmission, netem delay addition, nftables drop/reject rules, Connection Attempt Delay (CAD) scheduling, and 3-way handshake completion.
2. **`DNSWireCodec`**: Encodes and decodes DNS wire frames (RFC 1035) with support for A (1), AAAA (28), and HTTPS/SVCB (65) records.
3. **`SchemaValidator`**: Validates JSON payloads against Schema 1.1.0 and 1.0.0 definitions, enforcing fail-closed rejection on unknown versions.
4. **`ExportReconciler`**: Ingests and verifies `attempts.csv`, `connection_attempts.csv`, and `trial_timeline.csv` schemas, foreign keys, and row constraints.

---

## 5. Coverage and Quality Thresholds

| Metric | Target Threshold | Enforcement Mechanism |
|---|---|---|
| **Test Suite Pass Rate** | 100% (0 failures, 0 errors) | Automated unittest execution |
| **Tier 1 Feature Tests** | $\ge 25$ tests ($\ge 5$ per feature) | Test count assertion in `test_tier1_features.py` |
| **Tier 2 Boundary Tests** | $\ge 25$ tests ($\ge 5$ per feature) | Test count assertion in `test_tier2_boundaries.py` |
| **Tier 3 Combination Tests** | $\ge 6$ tests | Test count assertion in `test_tier3_combinations.py` |
| **Tier 4 Scenario Tests** | $\ge 5$ tests | Test count assertion in `test_tier4_scenarios.py` |
| **Total Test Count** | $\ge 61$ tests | Aggregate count verified in `TEST_READY.md` |
| **Execution Time** | $\le 10$ seconds total | Pure in-memory synthetic execution |
| **Root/Sudo Requirements** | 0 commands (Strictly forbidden) | CI/Human Gate constraint enforcement |
| **External Dependencies** | Standard Library Only (`unittest`, `dataclasses`, `json`, `csv`, `struct`, `socket`, `math`) | Zero extra pip requirements |

---

## 6. Implementation and Verification Plan

1. **Phase 1**: Construct `tests/common/` domain models, protocol codecs, and simulation engines.
2. **Phase 2**: Implement `tests/test_tier1_features.py` covering features F-01 through F-08.
3. **Phase 3**: Implement `tests/test_tier2_boundaries.py` covering boundaries B-01 through B-05.
4. **Phase 4**: Implement `tests/test_tier3_combinations.py` covering pairwise interactions.
5. **Phase 5**: Implement `tests/test_tier4_scenarios.py` covering real-world workloads.
6. **Phase 6**: Execute test suite, verify 100% pass rate, and publish `TEST_READY.md`.
