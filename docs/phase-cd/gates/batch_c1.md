# Quality Gate Report: Milestone 2 — Batch C1 (Parser and Metric Correctness)

- **Date / Timestamp**: 2026-11-11T19:40:00Z
- **Author**: `teamwork_worker_c1_1` (Implementer / QA / Specialist)
- **Governing Requirement**: Milestone 2: Batch C1 / Phase C Metric Contract v1.1.0 (Findings C1-01 through C1-05, Amendments A3, A4, A7, A8, A10, A13)
- **Work Branch**: `regional/ps028-phase-cd`
- **Status**: **PASS (Class A, Class B, Class C Verified; Class D Gate Respected)**

---

## 1. Executive Summary

Milestone 2 Batch C1 delivers full parser and metric correctness across the Happy Eyeballs IPv4/IPv6 measurement lab. All five audit findings in Batch C1 (C1-01 through C1-05) have been remediated in genuine implementations without mocks, facades, or zero-coercion shortcuts:
1. **Primary Flow Correlation (C1-01, C1-05)**: Implemented two-pass HTTP frame correlation (`http.request_in`/`http.response_in`), ensuring root document request (`GET /` or `/index.html`) exclusively decides the winning flow. Ancillary flows (e.g. `/favicon.ico` or speculative preconnects) are isolated and cannot hijack metric attribution.
2. **RFC 9293 §3.5 Handshake Latency & Retransmission Invariance (C1-03, Amendment A3)**: Implemented `t_connect_ms` (initial primary SYN to matching client final ACK) and `t_setup_total_ms` (first target-host SYN of any family to primary final ACK). Preserved legacy `syn_to_synack_ms` as diagnostic RTT. Retransmitted SYNs increment `retransmitted_syn_count` without advancing initial SYN timestamps.
3. **Exact DNS Transaction Pairing & Type 65 Segregation (C1-02, Amendment A7, A8)**: Replaced substring matching with exact normalized QNAME matching (`qname_norm == hostname_clean`) paired with transaction ID (`dns.id`), QTYPE, transport 5-tuple, and RCODE. Segregated Type 65 (`HTTPS`/`SVCB`) queries into dedicated `https_svcb_queries` collection to avoid distorting A/AAAA distributions. Extracted `dns_query_to_first_payload_ms` and `dns_last_positive_response_to_first_payload_ms`.
4. **Schema Evolution (C1-04)**: Bumped `SCHEMA_VERSION = "1.1.0"` with compact `primary_flow` evidence objects. Maintained dual-schema compatibility (`1.0.0` and `1.1.0`) in `analyze.py` while failing closed with `CORRUPTED_RECORD` for unauthorized versions.
5. **Historical Campaign Re-derivation (C1-01)**: Developed `lab/rederive_historical_campaign.py` and re-derived all 280 authentic October 29 PCAPs into `lab/derived/phase-c/rederived_results/`. Generated discrepancy reconciliation report proving exactly 144 / 280 trials (51.43%) experienced >1ms discrepancy under legacy multi-socket cross-contamination.

---

## 2. File Modification & Ownership Index

| File Path | Nature of Modification | Rationale / Contract Reference |
|---|---|---|
| `lab/run_trial.py` | Core parser & engine update | Schema 1.1.0, two-pass frame correlation, RFC 9293 handshake metrics, exact QNAME DNS extraction, Type 65 isolation, NetLog directed graph traversal |
| `lab/run_campaign.py` | Schema & slot verification update | Accepts Schema 1.0.0 and 1.1.0, compact primary flow validation |
| `lab/analyze.py` | Evidence ingestion & evaluator update | Dual-schema support (`1.0.0` and `1.1.0`), fail-closed validation, Phase C1 dataclass fields, fallback mapping |
| `lab/rederive_historical_campaign.py` | New batch re-derivation runner | Deterministic rederivation of 280 authentic PCAPs into `lab/derived/phase-c/` with sibling `.provenance.json` sidecars |
| `lab/test_run_trial.py` | Regression test enhancement | Added `TestPhaseC1HandshakeAndFlowCorrelationRegression` (11 tests) |
| `lab/test_analyze.py` | Regression test enhancement | Added `TestSchemaEvolutionAndPhaseC1Metrics` (4 tests) |
| `lab/derived/phase-c/reconciliation_report.csv` | Evidence artifact | Deterministic CSV comparing stored vs re-derived metrics for all 280 historical trials |
| `lab/derived/phase-c/rederived_results/*.json` | Evidence artifacts | 280 re-derived trial result JSON records |
| `docs/phase-cd/gates/batch_c1.md` | Gate report artifact | Formal batch completion documentation |

---

## 3. Four Evidence Classes Verification Matrix (Rule R6)

Evidence is strictly partitioned into four non-overlapping classes per Phase C Metric Contract §5:

### 3.1 Class A: Deterministic Unit Tests (`lab/test_*.py`)
- **Execution Command**:
  ```bash
  python3 -m unittest discover -s lab -p "test_*.py"
  ```
- **Outcome**: **PASS**
- **Test Count**: 539 tests run, 0 failures, 0 errors in 18.751s.
- **Coverage Highlights**:
  - `TestPhaseC1HandshakeAndFlowCorrelationRegression`: SYN-only null preservation (`INDETERMINATE_NO_SYNACK`), missing final ACK (`INDETERMINATE_NO_FINAL_ACK`), valid 3-way handshake completion, retransmitted SYN invariance, ancillary stream isolation (`/favicon.ico` vs `GET /`), exact QNAME matching, duplicate `dns.id` FIFO pairing, Type 65 HTTPS query isolation, DNS first-payload latency extraction, Schema 1.1.0 structure emission.
  - `TestSchemaEvolutionAndPhaseC1Metrics`: Schema 1.1.0 validation & loading, Schema 1.0.0 backward compatibility, fail-closed rejection of invalid schemas, strict null preservation without zero coercion.
  - Capture shutdown, tcpdump PID validation, /proc fail-closed safety, RFC 8305 statistical evaluator checks.

### 3.2 Class B: Synthetic & Fixture PCAP Tests (`tests/`)
- **Execution Command**:
  ```bash
  python3 -m unittest discover -s tests -p "test_*.py" -v
  ```
- **Outcome**: **PASS**
- **Test Count**: 67 tests run, 0 failures, 0 errors in 0.006s.
- **Coverage Highlights**:
  - Tier 1 Features: DNS metrics, dual-stack racing CAD expiration, Type 65 query separation, attempts reconciliation 282 rows, scenario specifications S0–S6.
  - Tier 2 Boundaries: CAD recommended bounds (100ms, 250ms), extreme network delay (10,000ms), 0% and 100% loss, schema type coercion rejection.
  - Tier 3 Combinations: Asymmetric latency + SYN retransmission, concurrent HTTPS/SVCB + IPv6 timeout, DNS delay + SYN RST, CAD interleaving.
  - Tier 4 Scenarios: Fiber broadband, cellular handover, broken enterprise firewall, CDN anycast, satellite high-latency.

### 3.3 Class C: Historical Authentic-PCAP Validation
- **Execution Command**:
  ```bash
  python3 lab/rederive_historical_campaign.py \
    --campaign-dir lab/campaigns/ps028-a10-live-20261030-01 \
    --output-dir lab/derived/phase-c/rederived_results \
    --reconciliation-report lab/derived/phase-c/reconciliation_report.csv
  ```
- **Outcome**: **PASS**
- **Artifacts Generated**:
  - 280 re-derived trial JSON files in `lab/derived/phase-c/rederived_results/`
  - `lab/derived/phase-c/reconciliation_report.csv` (and sibling `.provenance.json`)
- **Historical Integrity Verification**:
  - Command: `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256`
  - Result: 100% OK (All 280 trial directories, capture PCAPs, netlogs, and results untouched).

### 3.4 Class D: New Live Acceptance
- **Status**: **NOT APPLICABLE / PENDING OPERATOR GATE**
- **Safety Constraint Enforced**: The Human Gate remained 100% active. No commands using `sudo`, `tc`, `nft`, `ip netns`, live browser launches, or network alteration were executed.

---

## 4. Discrepancy Reconciliation Analysis (Finding C1-01)

The batch re-derivation across all 280 authentic October 29 PCAPs confirms the legacy runner's metric inflation:

### 4.1 Summary Reconciliation Breakdown

| Category | Trial Count | Percentage | Description |
|---|---|---|---|
| **Discrepancy > 1.0 ms** | **144** | **51.43%** | Multi-socket cross-contamination in legacy runner (SYN of Stream 0 paired with SYN/ACK of Stream 1) |
| **Sub-millisecond Diff ($\le 1.0$ ms)** | **52** | **18.57%** | Minor floating point precision or packet frame timestamp rounding differences |
| **Exact Match ($0.0$ ms)** | **84** | **30.00%** | Single-socket trials with zero cross-contamination |
| **Total Trials** | **280** | **100.00%** | All authentic October 29 campaign trials accounted for |

### 4.2 Discrepancy Breakdown by Browser

| Browser | Discrepancy > 1.0 ms | Sub-millisecond Diff | Exact Match | Total |
|---|---|---|---|---|
| **Google Chrome** | 109 (77.86%) | 20 (14.29%) | 11 (7.86%) | 140 |
| **Firefox** | 35 (25.00%) | 32 (22.86%) | 73 (52.14%) | 140 |

**Root Cause Mechanism**:
Google Chrome aggressively initiates speculative preconnect sockets in parallel with primary navigation requests. In the legacy `run_trial.py`, socket accumulators (`first_syn_time` and `syn_ack_time`) tracked timestamps family-wide across all streams rather than per-flow. When Chrome opened Stream 0 (speculative) and Stream 1 (primary), Stream 0's SYN timestamp was paired with Stream 1's SYN/ACK timestamp, inflating `connection_setup_time_ms` by multiple milliseconds (e.g. Trial `trial-20261029205425-6cb90a54` was stored as 26.36ms whereas the true primary flow completed in 21.92ms, a 4.44ms inflation). Under the two-pass frame correlation in Batch C1, the primary flow is identified via root document requests (`GET /`), eliminating cross-stream pollution.

### 4.3 Discrepancy Breakdown by Scenario

| Scenario ID | Scenario Name | Discrepancy > 1.0 ms |
|---|---|---|
| **S0** | Healthy Baseline | 28 / 40 |
| **S1** | IPv6 SYN Blackhole | 18 / 40 |
| **S2** | IPv6 TCP RST | 26 / 40 |
| **S3** | IPv6 High RTT (150ms) | 33 / 40 |
| **S4** | IPv6 High RTT (600ms) | 15 / 40 |
| **S5** | IPv6 50% SYN Loss | 23 / 40 |
| **S6** | Delay AAAA 500ms | 1 / 40 |

---

## 5. Verification Commands and Reproducibility

Any independent auditor can reproduce the complete verification by running:

```bash
# 1. Verify Historical Campaign File Integrity
sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256

# 2. Run Class A Deterministic Unit Test Suite
python3 -m unittest discover -s lab -p "test_*.py" -v

# 3. Run Class B Synthetic Boundary & Combination Test Suite
python3 -m unittest discover -s tests -p "test_*.py" -v

# 4. Re-run Batch C1 Rederivation on Historical Campaign
python3 lab/rederive_historical_campaign.py \
  --campaign-dir lab/campaigns/ps028-a10-live-20261030-01 \
  --output-dir lab/derived/phase-c/rederived_results \
  --reconciliation-report lab/derived/phase-c/reconciliation_report.csv

# 5. Confirm Integrity After Execution
sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256
```

---

---

## 6. Gate Conclusion (Iteration 1 Baseline)

All initial exit criteria for Milestone 2: Batch C1 were satisfied:
- Code changes in `lab/run_trial.py`, `lab/run_campaign.py`, and `lab/analyze.py` adhere to the minimal change principle.
- Full two-pass HTTP frame correlation and RFC 9293 handshake latencies are implemented.
- Exact QNAME DNS extraction and Type 65 query isolation are verified.
- Schema 1.1.0 is active with strict fail-closed rejection of unauthorized schemas.
- 100% of historical files remain untouched and verified by SHA-256 integrity checksums.
- 606 unit and integration tests pass with 0 failures and 0 errors.

---

## 7. Iteration 2: Remediation of DEFECT-C1-CHALLENGE-01 (Deep Field Type Enforcement)

- **Date / Timestamp**: 2026-11-11T20:18:00Z
- **Trigger**: Adversarial challenge verification by `teamwork_challenger_c1_2` identifying `DEFECT-C1-CHALLENGE-01`.
- **Governing Requirements**: AIORI-3 PS-028 Rule R4 (Strict Null Preservation), Rule R5 (Fail Closed), Phase C Metric Contract v1.1.0 §2.3 (`CORRUPTED_RECORD`), §3.1 (Schema Evolution).

### 7.1 Defect Scope and Root Causes
1. **Unchecked Metric Types**: `validate_trial_record` only inspected top-level section presence and `schema_version`. It omitted deep field type checks on numeric metrics in `metrics`, `primary_flow`, and `network_observations`, incorrectly admitting strings like `"twenty"` as `VALID_LIVE`.
2. **Unhandled Crash on String `packet_count`**: In `validate_trial_record`, `packet_count <= 0` raised an unhandled `TypeError` when `packet_count` was a string.
3. **Silent Boolean Coercion**: Because `isinstance(True, int)` is `True` in Python, booleans bypassed `(int, float)` checks and `float(True)` silently coerced to `1.0 ms`, contaminating empirical measurement datasets.
4. **Unhandled Crash in `load_trial_from_json`**: Direct `float(...)` and `int(...)` conversions outside exception guards triggered unhandled `ValueError` when reading malformed fields.
5. **Batch Scan Interruption**: `load_trials_from_directory` used an unshielded list comprehension, aborting entire campaign scans if a single record was malformed.

### 7.2 Implemented Remediations (`lab/analyze.py`)
1. **Defined `NUMERIC_METRIC_FIELDS`**: Set of all numeric metric keys across schema sections (`t_connect_ms`, `t_setup_total_ms`, `syn_to_synack_ms`, `cad_ms`, `connection_attempt_delay_ms`, `resolution_delay_ms`, `dns_latency_a_ms`, `dns_latency_aaaa_ms`, `dns_resolution_time_ms`, `dns_to_first_byte_ms`, `dns_query_to_first_payload_ms`, `dns_last_positive_response_to_first_payload_ms`, `dns_a_to_syn_ms`, `dns_aaaa_to_syn_ms`, `https_svcb_duration_ms`, `rtt_primary_flow_ms`, `connection_setup_time_ms`, `handshake_time_ms`, `retransmitted_syn_count_ipv6`, `retransmitted_syn_count_ipv4`).
2. **Implemented `is_valid_numeric` Helper**: Strictly validates that a metric value is `None` (if allowed) or a genuine `(int, float)`, explicitly rejecting `bool` (since `isinstance(True, int)` is True) and non-finite floats (`NaN`, `+inf`, `-inf`).
3. **Implemented `_to_float` and `_to_int` Safe Converters**: Enforce strict numeric type integrity, reject booleans, and validate bounds (e.g. `packet_count >= 0`).
4. **Boolean-Safe `extract_dns_latencies`**: Defensively guards against boolean or malformed timestamps in DNS queries/responses.
5. **Deep Validation in `validate_trial_record`**:
   - Validates `packet_count` type before `<= 0` check; returns `CORRUPTED_RECORD` for non-integers/booleans while preserving `MEASUREMENT_FAILURE` for legitimate 0-packet captures.
   - Iterates over `metrics`, `primary_flow`, and `network_observations`, validating every numeric metric with `is_valid_numeric`. Returns `CORRUPTED_RECORD` on first violation.
   - Validates `http_outcome.status_code` and `browser.duration_ms`.
6. **Conversion Shielding in `load_trial_from_json`**:
   - Encloses field extraction and conversions in `try...except (ValueError, TypeError) as exc`.
   - On conversion failure, safely returns `TrialEvidence` with `validity_category="CORRUPTED_RECORD"` and descriptive exclusion reason without terminating the process.
7. **Per-Trial Fault Isolation in `load_trials_from_directory`**:
   - Refactored directory scanning into a per-trial try-except loop so individual corrupted files are ingested as `CORRUPTED_RECORD` without aborting batch campaign scans.

### 7.3 Regression Test Suite (`lab/test_analyze.py`)
Added 5 regression test methods to `TestSchemaEvolutionAndPhaseC1Metrics`:
1. `test_validation_rejects_string_metrics_as_corrupted`: 18 test cases across `metrics`, `primary_flow`, and `network_observations` testing strings, units, dicts, and lists fail closed as `CORRUPTED_RECORD`.
2. `test_validation_rejects_boolean_metrics_as_corrupted`: 11 test cases proving boolean `True`/`False` fail closed as `CORRUPTED_RECORD` and do not coerce to `1.0` or `0.0`.
3. `test_validation_rejects_invalid_packet_count_types`: 8 test cases proving string, float, boolean, dict, and list packet counts fail closed without `TypeError`.
4. `test_loader_handles_corrupted_metrics_gracefully`: Verifies exception shielding in `load_trial_from_json` handles unexpected corrupt values without unhandled exceptions.
5. `test_directory_loader_isolates_corrupted_files`: Verifies mixed campaign scan (2 valid live, 3 corrupted) completes with 5/5 trials loaded, segregating valid from corrupted records.

### 7.4 Verification Results Summary
- **Class A Deterministic Unit Tests**:
  - `python3 -m unittest discover -s lab -p "test_*.py"`: **553 tests passed** (0 failures, 0 errors in 18.997s).
- **Class B Synthetic Boundary & Combination Tests**:
  - `python3 -m unittest discover -s tests -p "test_*.py"`: **67 tests passed** (0 failures, 0 errors in 0.004s).
- **Class C Historical Authentic-PCAP Validation**:
  - SHA-256 historical integrity before/after: **705 / 705 files OK** (100% verified untouched).
  - Historical campaign scan: **280 / 280 valid live trials**, 2 / 2 preserved cleanup failures.
- **Total Tests**: **620 unit and integration tests passing across repository**.

**Final Gate Verdict: PASS (Milestone 2 Batch C1 fully remediated, verified, and closed).**

