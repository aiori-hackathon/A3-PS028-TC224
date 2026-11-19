# PS-028 Phase E: Demonstration Data, Replay & Evidence Explorer Guide

**Team AlgoRhythm** · **AIORI Hackathon 3** · **PS-028: Internet Measurement**

This directory documents the pre-compiled demonstration data layer, offline replay tooling, and frontend ingestion pipeline supporting the interactive Historical Evidence Explorer and Scenario Analytics Dashboard.

---

## 1. Quick Start

### 1.1 Run Authentic PCAP Replay
Replay the 14 representative authentic PCAPs (S0–S6 across Chrome and Firefox) completely offline:
```bash
# Compact tabular summary of 14 representative trials
python3 lab/demo_replay.py --summary

# Detailed trial cards with synchronized event timelines
python3 lab/demo_replay.py --events

# Filter by scenario or browser
python3 lab/demo_replay.py --scenario S2 --browser google-chrome

# Emit structured validation JSON
python3 lab/demo_replay.py --json

# Print canonical RFC 8305 pseudocode snippet
python3 lab/demo_replay.py --pseudocode
```

### 1.2 Regenerate Demonstration Data Bundle
Recompile the deterministic demonstration bundle from authoritative Phase C sources without live experiments:
```bash
python3 lab/build_demo_bundle.py
```
Generated artifacts in `lab/derived/phase-e/`:
- `demo_bundle.json`: Complete schema-versioned trial dataset (~17.32 MB / 18,157,449 bytes; verified SHA-256: `42fad72c342c0e986c12502b0f9f82dbfc2d22fed0ea7e2709ee4469588c4b86`).
- `demo_bundle.json.provenance.json`: Sibling provenance sidecar recording source input digests and generator commit.
- `metric_registry.json`: Machine-readable metric specifications, mathematical definitions, and null reason codes.

### 1.3 Export Filtered Datasets Safely
Export filtered views into deterministic, injection-safe CSV and JSON:
```bash
# Export S2 Chrome trials with connection attempts and timeline events
python3 lab/demo_export.py --scenario S2 --browser google-chrome --include-flows --include-timeline

# Export all trials as CSV
python3 lab/demo_export.py --format csv
```

---

## 2. Source-of-Truth Hierarchy & Ingestion

The demo data bundle compiles directly from authoritative Phase C sources:
1. `lab/campaigns/ps028-a10-live-20261030-01/campaign_manifest.json`: Campaign metadata and slot matrix.
2. `lab/derived/phase-c/attempts.csv`: 282 recorded campaign attempts.
3. `lab/derived/phase-c/connection_attempts.csv`: 765 per-flow TCP connection attempts.
4. `lab/derived/phase-c/s5_flow_dissection.csv`: 95 S5 flows cleanly separating transport racing from application HTTP transactions.
5. `lab/derived/phase-c/trial_timeline.csv`: 28,330 synchronized events across `HARNESS`, `PCAP`, and `BROWSER_TELEMETRY`.
6. `lab/derived/phase-c/rederived_results/*.json`: 280 corrected trial records.
7. `lab/derived/phase-c/reconciliation_report.csv`: 280 trial reconciliation report.
8. `lab/derived/phase-c/rfc8305_assessment.csv`: 7 standards assessment checks.

### Reconciliation Invariants
- **Total Recorded Attempts**: Exactly **282 attempts**.
- **Valid Live Trials**: Exactly **280 trials** (`VALID_LIVE`).
- **Excluded Attempts**: Exactly **2 cleanup failures** (`CLEANUP_FAILURE`), preserved separately from empirical trial summaries.
- **Cohorts**: Exactly **14 cohorts** (7 scenarios × 2 browsers), with exactly **20 trials per cohort**.
- **HTTP Success Rate**: **280 / 280 (100%)** HTTP 200 responses.
- **Zero Simulation Leakage**: Phase D simulation sweeps are strictly isolated and never enter empirical summaries.

---

## 3. Strict Evidence Separation (Rule R3)

- **`HISTORICAL_LIVE`**: Pertains exclusively to authentic live campaign trials conducted on October 29, 2026, in campaign `ps028-a10-live-20261030-01`.
- **`SIMULATION`**: Strictly isolated to Phase D research sweeps (`lab/derived/phase-d/`). Phase D simulation data is **never** ingested into the empirical demonstration bundle or cited as live evidence.
- **`SYNTHETIC_FIXTURE` / `UNIT_TEST`**: Reserved for offline test suites in `tests/` and `lab/`.

---

## 4. Implemented Frontend Ingestion Architecture

The data bundle is ingested directly by the Astro v5 / React 19 frontend application:

1. **Staging & Verification**:
   The frontend build pipeline executes `setup/webtester/scripts/prepare-historical-data.mjs`, which validates `lab/derived/phase-e/demo_bundle.json` against `demo_bundle.json.provenance.json` using SHA-256 before copying it to `setup/webtester/public/data/demo_bundle.json`.
2. **Client-Side Ingestion**:
   The Historical Evidence Explorer (`/evidence`) and Scenario Analytics Dashboard (`/analytics`) fetch `/data/demo_bundle.json` statically and verify integrity via WebCrypto SHA-256 before rendering.
3. **Canonical Metric Contract**:
   Domain logic in `setup/webtester/src/lib/historical-evidence.ts` and `setup/webtester/src/lib/analytics/` preserves canonical keys (`connection_attempt_delay_ms`, `t_connect_ms`, `t_setup_total_ms`) and never coerces missing values to 0.0 (null reasons preserved).
4. **Offline Historical Replay Notice**:
   Both views feature explicit notices informing users that the displayed data represents verified historical campaign replay, clearly distinguished from active local browser testing.
