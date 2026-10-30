# PS-028: Happy Eyeballs Reproducibility Runbook

## Purpose

This runbook describes how to preflight the PS-028 isolated lab, execute the integrated browser trial runner (A7), find the evidence it creates, and verify that the lab returns to its clean baseline. Use the repository's `lab/scenarios.yaml` as the canonical scenario configuration; do not treat narrative expectations as measured outcomes.

## Environment and safety

The current tested environment is WSL2 Ubuntu 24.04 with Chrome (`google-chrome`). The lab uses isolated client/router/server network namespaces, a DNS service for `he.test`, and an HTTP server. Live scenarios modify networking and DNS state. Run them only in the dedicated lab environment, one at a time, with the necessary privileges. Do not run trials concurrently.

Before beginning, make sure the repository is up to date and that you are in its root:

```bash
cd ~/projects/he-webtester
git status -sb
```

The main tools are:

- `lab/analyze.py`: statistical analysis CLI and RFC 8305 assessment engine (A9).
- `lab/run_campaign.py`: sequential campaign orchestrator and resume engine (A8).
- `lab/run_trial.py`: integrated browser-measurement runner (A7).
- `lab/impair.py`: scenario controller and S0–S6 self-test harness.
- `lab/scenarios.yaml`: canonical scenario definitions.
- `lab/trials/<trial_id>/result.json`: structured record for each trial.
- `lab/trials/<trial_id>/capture.pcap`: packet capture for each trial.

## 1. Preflight and baseline checks

Start with non-destructive checks:

```bash
sudo python3 lab/impair.py preflight
python3 lab/impair.py list
sudo python3 lab/impair.py self-test-baseline
```

Do not proceed with a live trial if preflight fails or the baseline self-test reports an active impairment or an unexpected state. Resolve the lab setup first, then re-run the checks.

The `run_trial.py` interface is:

```text
python3 lab/run_trial.py [--scenario {S0,S1,S2,S3,S4,S5,S6}]
                        [--browser BROWSER]
                        [--trial-id TRIAL_ID]
                        [--output-dir OUTPUT_DIR]
                        [--timeout TIMEOUT]
                        [--browser-timeout BROWSER_TIMEOUT]
                        [--simulation]
                        [--skip-baseline-check]
                        [--json]
```

Defaults are scenario `S0`, an auto-generated trial ID, output under `lab/trials/<trial_id>`, a 30-second overall timeout, and a 15-second browser timeout. Use the normal live mode for measurements; `--simulation` is a dry-run/simulation and must be labelled as such in any report. Do not use `--skip-baseline-check` for normal evidence collection.

## 2. Run one browser trial at a time

Run each scenario separately so that you can inspect its result and verify cleanup before starting the next one. For example:

```bash
sudo python3 lab/run_trial.py --scenario S0 --browser google-chrome
sudo python3 lab/impair.py self-test-baseline
```

Then repeat the first command with `S1`, `S2`, `S3`, `S4`, `S5`, and `S6`, checking the baseline after every trial. Keep the runner's generated trial ID. To request machine-readable JSON on standard output, add `--json`; the runner also stores a `result.json` in the trial evidence directory.

Do not manually apply a second impairment while the browser runner is active. The runner applies and clears its scenario as part of its lifecycle.

## 3. Confirm cleanup after each trial

After every trial, run:

```bash
sudo python3 lab/impair.py self-test-baseline
sudo python3 lab/impair.py status
```

A result is not cleanly completed merely because the browser received HTTP 200. Check `result.json` for the cleanup fields and require, at minimum:

- `cleanup_status.scenario_restored` is `true`.
- `cleanup_status.baseline_verified` is `true`.
- `cleanup_status.profile_cleaned` is `true`.
- `cleanup_status.lock_released` is `true`.
- `cleanup_status.errors` is an empty list.

Inspect the capture and result files without editing them:

```bash
find lab/trials -mindepth 2 -maxdepth 2 -type f \
  \( -name 'result.json' -o -name 'capture.pcap' -o -name 'capture.pcapng' \) \
  -printf '%TY-%Tm-%Td %TH:%TM:%TS %p %s bytes\n' | sort
```

For a particular trial, replace `<trial_id>` with the ID printed by the runner:

```bash
python3 -m json.tool lab/trials/<trial_id>/result.json | less
file lab/trials/<trial_id>/capture.pcap
```

If cleanup verification fails, stop running scenarios. Use the impairment controller's supported baseline-clear/verification commands and investigate the recorded error before continuing. Do not delete lock, state, DNS-backup, or PID files while a lab process may still be running.

## 4. Controlled S5 loss sampling

The controlled S5 probe test is separate from the browser trial and measures nftables rule counters. For example:

```bash
sudo python3 lab/impair.py test-scenarios --scenario S5 --probes 50 --json
sudo python3 lab/impair.py self-test-baseline
```

Use a larger sample when estimating drop rate:

```bash
sudo python3 lab/impair.py test-scenarios --scenario S5 --probes 200 --json
sudo python3 lab/impair.py self-test-baseline
```

Record the number of probes, dropped packets, undropped packets, and whether baseline restoration passed. Do not infer the exact drop percentage from a single small sample; random loss naturally varies between runs.

## 5. Existing live observations

These are observations from the recorded trials, not guaranteed results on every run:

| Scenario | Recorded trial | Observed result |
|---|---|---|
| S0 | `trial-20261028170148-49b91c58` | IPv6 served the page; HTTP 200; valid PCAP; baseline verified. DNS observations included HTTPS/SVCB type 65, AAAA, and A responses. |
| S1 | `trial-20261028170259-4334add3` | IPv6 SYN blackhole; browser fell back to IPv4; HTTP 200; measured connection-attempt delay about 301 ms; packet sequence showed unanswered IPv6 SYNs followed by IPv4 connection and HTTP response. |
| S2 | `trial-20261028170409-0556cb75` | IPv6 TCP reset; IPv4 fallback; HTTP 200; measured connection-attempt delay about 2.65 ms. |
| S3 | `trial-20261028170518-bd725705` | Increased IPv6 RTT; IPv6 won; HTTP 200; measured connection setup about 152 ms. |
| S4 | `trial-20261028170555-3b4a1829` | Increased IPv6 RTT; IPv4 won; HTTP 200; connection-attempt delay about 295 ms; setup about 29 ms. |
| S5 | `trial-20261028170712-3bf8b319` | This browser capture did **not** demonstrate SYN loss: the observed IPv6 SYNs received SYN-ACKs. A separate controlled nftables-counter test recorded 17/50 drops (34%), and a 200-probe run recorded 120/200 drops (60%). Combined: 137/250, or 54.8%. Report the sample sizes and variability. |
| S6 | `trial-20261028171417-b2d83f2f` | A arrived about 19 ms after its query; AAAA arrived about 515 ms after its query (roughly 496 ms later than A). Chrome connected over IPv6 shortly after the AAAA response. This run did **not** show IPv4 winning despite the delayed AAAA response. |

All seven recorded browser trials above had HTTP 200, a valid PCAP, and cleanup indicators reporting scenario restored, baseline verified, browser profile cleaned, lock released, and no cleanup errors.

### Important interpretation notes

- Treat these numbers as individual observations from the named trial IDs, not universal properties of Happy Eyeballs or Chrome.
- S5's single browser trial did not capture a loss event even though separate controlled probes confirmed packet drops. Keep those two evidence types distinct.
- The runner's inline scenario comment for S6 describes a target sequence ending with IPv4 winning, but the recorded Chrome trial connected over IPv6 after the delayed AAAA response. Preserve this discrepancy in reports and investigate it before claiming that S6 reliably causes IPv4 fallback.
- A `/favicon.ico` 404 seen after a successful main-page HTTP 200 is a secondary browser request and should not be confused with failure of the tested page request.

## 6. Evidence checklist for a handoff

For each trial that is included in a report, preserve:

1. Trial ID, scenario ID, browser name/version, date/time, and environment details.
2. `result.json` and its matching `capture.pcap`.
3. HTTP result and the relevant DNS/TCP sequence from the capture.
4. Cleanup fields and a successful baseline self-test immediately after the trial.
5. Any mismatch between the intended scenario and observed browser behavior.

Do not commit generated PCAPs, runtime logs, PID files, lock files, or trial evidence unless the team explicitly decides to publish a curated evidence subset. Keep source-code changes and potentially large local measurement artifacts separate.

## 7. Statistical analysis and RFC 8305 assessment (A9)

Use `lab/analyze.py` to aggregate and analyze existing measurement evidence strictly offline without executing trials, invoking browsers, or modifying network namespaces or routing.

### CLI interface

```bash
# Analyze auto-discovered local evidence (lab/trials/ and lab/campaigns/)
python3 lab/analyze.py

# Analyze a specific campaign directory or manifest
python3 lab/analyze.py --campaign-dir lab/campaigns/<campaign_id>
python3 lab/analyze.py --manifest lab/campaigns/<campaign_id>/campaign_manifest.json

# Analyze dedicated trials directory
python3 lab/analyze.py --trials-dir lab/trials

# Output reproducible CSV or JSON to stdout
python3 lab/analyze.py --csv
python3 lab/analyze.py --json

# Save structured summary artifacts
python3 lab/analyze.py -o lab/results/
```

When `--output-dir` (`-o`) is provided, `analyze.py` exports four reproducible artifact files:
- `summary.json`: Complete grouped metrics, dataset metadata, exclusions, and RFC 8305 checks.
- `summary.csv`: Tabular cohort metrics grouped by browser and scenario.
- `exclusions.csv`: Audit log of excluded attempts, corrupted files, and incomplete slots.
- `rfc8305_assessment.csv`: Standards conformance evaluation table with evidence justification.

### Statistical methodology and metric definitions

1. **Cohort Grouping**: All metrics are grouped deterministically by browser and scenario (`S0`–`S6`).
2. **Sample Counts**: Distinct counts are reported for `total_trials`, `valid_live_count`, `simulation_count`, `incomplete_count`, and `invalid_or_failed_count`.
3. **HTTP Success Rate**: Calculated as $\frac{\text{success\_count}}{\text{valid\_live\_count}}$ alongside a 95% Wilson score confidence interval:
   $$\text{Wilson CI} = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
   Guaranteed bounded in $[0.0, 1.0]$ across small samples.
4. **Winning Address Families**: Distribution of winning paths (`IPv6`, `IPv4`, or `None`) with Wilson score 95% confidence intervals.
5. **Connection Setup Times**: Setup latency of winning connection (SYN to SYN-ACK) reporting non-null count ($N$), median, 95th percentile (p95), interquartile range (IQR = $Q3 - Q1$), and 95% bootstrap confidence interval.
6. **Fallback Delays (Connection Attempt Delay)**: Elapsed time between initial IPv6 SYN and secondary IPv4 SYN. Reported with median, p95, IQR, and bootstrap confidence interval.
7. **DNS Latencies**: Per-record-type resolution latencies for A and AAAA records and total query-to-response resolution span.
8. **Handling of Missing Values**: Missing or unobserved metrics (e.g. fallback delay in direct IPv6 connections, or unreceived DNS responses) remain `null` in JSON and empty strings `""` in CSV. They are **never replaced with zero**.

### Evidence validation, segregation, and exclusions

The analyzer enforces strict A7/A8 validity rules:
- **Valid Live**: Genuine live trials with verified baseline restoration (`scenario_restored=true`, `baseline_verified=true`, no cleanup errors), valid PCAP, non-zero packet count (`packet_count > 0`), and conclusive classification.
- **Simulation**: Offline dry-run trials (`is_simulation=true`) are segregated from live statistics by default. Use `--include-simulations` only when explicitly studying simulated data.
- **Incomplete / Malformed**: Missing result files, corrupted JSON, or pending unexecuted campaign slots are recorded in `exclusions.csv` with their exact cause.
- **Measurement Failures**: Trials with zero-packet captures (such as `trial-20261028083344-ccc4810f`) or unresolved classifications are excluded from live calculations and preserved in the audit log.

### RFC 8305 standards conformance assessment

The analyzer evaluates Happy Eyeballs v2 requirements strictly from observable network evidence, distinguishing **`OBSERVED_CONFORMANCE`**, **`OBSERVED_DEVIATION`**, and **`INDETERMINATE`** results without inferring general browser conformance from individual trials. The assessment explicitly separates mandatory requirements (MUST/MUST NOT) from recommended parameters (SHOULD/SHOULD NOT) via `mandatory_status` and `recommended_status`:
- **RFC 8305 §3 (IPv6 Preference)**: Verifies whether initial connection attempts prefer IPv6 on dual-stack baseline (S0). In tested live trials, IPv6 was attempted first and won (`OBSERVED_CONFORMANCE`).
- **RFC 8305 §5 (Immediate Reset Fallback & 10 ms Inter-Attempt Floor)**: Evaluates TCP RST rejection (S2). RFC 8305 §5 distinguishes mandatory requirements (*"subsequent connection attempts MUST NOT start within 10 milliseconds of the previous attempt"*) from recommended parameters (minimum CAD timer of 100 ms, maximum CAD of 2 seconds). When an attempt actively fails (TCP RST), Section 5 recommends starting immediately without waiting for the CAD timer to expire, provided the 10 ms mandatory floor is respected. Because the recorded S2 Chrome trial launched its subsequent IPv4 attempt at 2.65 ms (< 10 ms interval between attempt starts), this is classified as an **`OBSERVED_DEVIATION`** specifically for **mandatory-floor violation** (`mandatory_status=OBSERVED_DEVIATION`) scoped to the recorded trial. Delays between 10 ms and 100 ms meet mandatory MUST requirements (`mandatory_status=OBSERVED_CONFORMANCE`) while falling outside recommended parameters (`recommended_status=OBSERVED_DEVIATION`), and are explained as recommended-range deviations without being labeled as MUST violations.
- **RFC 8305 §5 (CAD SYN Timeout)**: Verifies whether unacknowledged IPv6 SYNs (S1) schedule IPv4 fallback within the 100–2000 ms window (target: 250 ms). In the recorded S1 trial, CAD was 301.19 ms, satisfying both mandatory floor and recommended bounds (`OBSERVED_CONFORMANCE`).
- **RFC 8305 §5 (High Latency Fallback)**: Verifies whether 600 ms IPv6 latency (S4) allows IPv4 to complete handshake first. In the recorded S4 trial, IPv4 won with CAD 294.87 ms (`OBSERVED_CONFORMANCE`).
- **RFC 8305 §4 (Resolution Delay)**: Evaluates delayed AAAA behavior (S6). In the recorded Chrome trial (`trial-20261028171417-b2d83f2f`), Chrome waited ~515 ms for late AAAA and connected over IPv6 rather than initiating IPv4 fallback after the RFC 8305 §4 recommended 50 ms Resolution Delay. This is classified as an **`OBSERVED_DEVIATION`** strictly scoped to the recorded trial, without inferring general browser non-conformance.
- **Unsupported Checks**: Features not testable under isolated single-trial protocol (e.g., cross-session cache statefulness in §7) or out of testbed scope (e.g., QUIC/SCTP in §8) are strictly marked **`INDETERMINATE`**.

## 8. Useful commands

```bash
# Review available scenarios and their descriptions
python3 lab/impair.py list

# Inspect current scenario-controller status
sudo python3 lab/impair.py status

# Run statistical analysis and RFC 8305 assessment (A9)
python3 lab/analyze.py
python3 lab/analyze.py --csv
python3 lab/analyze.py -o lab/results/

# Check tool options
python3 lab/impair.py --help
python3 lab/run_trial.py --help
python3 lab/run_campaign.py --help
python3 lab/analyze.py --help

# Run automated tests (simulation/unit tests; not a replacement for live trials)
python3 lab/test_analyze.py
python3 lab/test_run_campaign.py
python3 lab/test_run_trial.py
python3 -m unittest discover lab
```

A successful automated test suite does not, by itself, prove a live network experiment worked. Use the matching trial JSON, PCAP, and baseline verification as evidence for live claims.
