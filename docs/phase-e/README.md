# PS-028 Phase E: Demonstration Data & Replay Guide

This directory documents the pre-compiled demonstration data layer and developer tooling prepared for subsequent interactive evidence-explorer development.

---

## 1. Quick Start

### 1.1 Run Authentic PCAP Replay
Replay the 14 representative authentic PCAPs (S0–S6 across Chrome and Firefox) completely offline:
```bash
# Compact tabular summary
python3 lab/demo_replay.py --summary

# Detailed trial cards with event timelines
python3 lab/demo_replay.py --events

# Filter by scenario or browser
python3 lab/demo_replay.py --scenario S2 --browser google-chrome

# Emit structured validation JSON
python3 lab/demo_replay.py --json

# Print canonical RFC 8305 pseudocode snippet
python3 lab/demo_replay.py --pseudocode
```

### 1.2 Regenerate Demonstration Data Bundle
Recompile the deterministic bundle from authoritative Phase C sources without live experiments:
```bash
python3 lab/build_demo_bundle.py
```
Outputs generated in `lab/derived/phase-e/`:
- `demo_bundle.json` (9.7 MB): Complete schema-versioned trial dataset.
- `demo_bundle.json.provenance.json`: Sibling provenance sidecar recording source digests.
- `metric_registry.json`: Machine-readable metric contract definitions.

### 1.3 Export Filtered Datasets Safely
Export filtered views into deterministic CSV and JSON:
```bash
# Export S2 Chrome trials with connection attempts and timeline events
python3 lab/demo_export.py --scenario S2 --browser google-chrome --include-flows --include-timeline

# Export all trials as CSV
python3 lab/demo_export.py --format csv
```

---

## 2. Source-of-Truth Hierarchy & Ingestion

The demo data bundle ingests the following authoritative Phase C sources:
1. `lab/campaigns/ps028-a10-live-20261030-01/campaign_manifest.json`: Campaign metadata.
2. `lab/derived/phase-c/attempts.csv`: 282 campaign attempts.
3. `lab/derived/phase-c/connection_attempts.csv`: 765 per-flow TCP attempts.
4. `lab/derived/phase-c/s5_flow_dissection.csv`: 95 S5 flows.
5. `lab/derived/phase-c/trial_timeline.csv`: 28,330 synchronized events.
6. `lab/derived/phase-c/rederived_results/*.json`: 280 corrected trial records.
7. `lab/derived/phase-c/reconciliation_report.csv`: 280 trial reconciliation report.
8. `lab/derived/phase-c/rfc8305_assessment.csv`: 7 standards assessment checks.

### Reconciliation Invariants
- Total Attempts: Exactly **282 attempts**.
- Valid Live Trials: Exactly **280 trials** (`VALID_LIVE`).
- Exclusions: Exactly **2 cleanup failures** (`CLEANUP_FAILURE`), preserved separately from empirical trial summaries.
- Cohorts: Exactly **14 cohorts** (7 scenarios × 2 browsers), with exactly **20 trials per cohort**.

---

## 3. Strict Evidence Separation (Rule R3)

- **`HISTORICAL_LIVE`**: Pertains exclusively to authentic live campaign trials conducted on October 29, 2026.
- **`SIMULATION`**: Strictly isolated to Phase D research sweeps (`lab/derived/phase-d/`). Phase D simulation data is **never** ingested into the empirical demonstration bundle.
- **`SYNTHETIC_FIXTURE` / `UNIT_TEST`**: Reserved for offline test suites in `tests/` and `lab/`.

---

## 4. Frontend Integration Guidelines

Subsequent frontend developers building an interactive dashboard or evidence explorer should:
1. **Consume `demo_bundle.json` Directly**: Do not invoke TShark or re-parse PCAP files on the frontend. The bundle contains pre-correlated primary flows, connection attempts, timeline events, and metric summaries.
2. **Preserve Canonical Metric Keys**: Always use `connection_attempt_delay_ms` as the data key (`CAD` is the display label).
3. **Preserve Null Reasons**: Missing metrics are `null` with an explicit reason code in `null_reasons` (e.g. `NOT_APPLICABLE_HEALTHY_PATH`). Never coerce missing values to 0.0.
4. **Offline Replay Banner**: Present the evidence explorer as an **Offline Historical Campaign Replay**, distinguishing it from live browser testing tools.
