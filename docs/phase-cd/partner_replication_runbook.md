# Independent Partner Core Campaign Replication Runbook

- **Document ID**: `PS028-RUNBOOK-CORE-REPLICATION`
- **Status**: **STANDARD OPERATING PROCEDURE (PENDING AUTHENTIC PARTNER EVIDENCE)**
- **Governing Requirements**: AIORI-3 PS-028 Core Campaign Replication Matrix (Requirements #1–#6, #20)
- **Rule Compliance**: Rule R1 (No Fabricated Data), Rule R6 (Evidence Classes Separated), Rule R7 (No Conformance Claims)

---

## 1. Overview and Purpose

To establish external reproducibility and cross-platform scientific validity, this runbook provides step-by-step instructions for an independent partner laboratory to replicate the canonical 280-trial PS-028 Happy Eyeballs measurement matrix:
- **Canonical Scenarios**: S0 through S6 (7 impairment/delay scenarios).
- **Target Client Implementations**: Pinned Google Chrome and Mozilla Firefox builds.
- **Trial Repetitions**: Exactly 20 valid live trials per browser per scenario ($7 \times 2 \times 20 = 280\text{ trials}$).
- **Milestone Scope**: Independent final verification milestone. Excludes Phase D exploratory sweeps (D1/D2), empirical netem parameter sweeps, and the Amendment A11 200-probe acceptance batch.

> [!CAUTION]
> **Rule R1 Non-Negotiable Mandate:**
> The repository explicitly records the replication status as `STATUS: PENDING AUTHENTIC PARTNER EVIDENCE`. No synthetic, mock, or simulated partner run may ever be relabeled or committed as authentic external replication evidence.

---

## 2. Amendment Scope Reconciliation (A2, A4, A6, A8, A10, A11, A13)

The partner replication manifest references historical project amendments. Their scope relative to the 280-trial core replication campaign is explicitly defined below:

### 2.1 Applicable Core-Campaign Protocol Requirements
* **Amendment A2 (Sample Size Rigor)**: Exactly $n=20$ valid live trials per browser per scenario ($7 \times 2 \times 20 = 280$ trials total). Exploratory or pilot runs with $n < 20$ are strictly barred from final claims.
* **Amendment A4 (Controlled DNS Responder Integrity)**: Controlled DNS responder with wildcard `*.he.test.`, immediate NOERROR/NODATA for HTTPS Type 65 queries, and fail-closed lock reload via SIGHUP.
* **Amendment A8 (Browser DNS Controls & Metric Isolation)**: Effective browser-level DoH/TRR disablement, isolated ephemeral user profiles, and separation of DNS transaction metrics from TCP connection setup timing (`t_setup_total_ms`).
* **Amendment A10 (Specification of Record Integrity)**: Pinned specification revision of record remains `draft-ietf-happy-happyeyeballs-v3-04` (published 1 July 2026; dated status check: 2026-11-13).
* **Amendment A13 (Deterministic Ordering & Provenance Sidecars)**: Pre-persisted random seeds, Schema 1.1.0 ledgers, and `.provenance.json` cryptographic sidecars for all derived outputs.

### 2.2 Explicit Amendment Exclusions
* **Amendment A6 (Uniform Netem Sweep Exclusion)**: Live uniform-netem parameter sweeps (`tc netem delay 0ms 0ms` parameter variations) are part of Phase D empirical research, which was **permanently removed from the delivery plan by owner decision**. The core campaign S0 scenario uses the canonical 10ms baseline link delay without parameter sweeps.
* **Amendment A11 (200-Probe Acceptance Batch Exclusion)**: The live 200-probe statistical acceptance batch with Clopper-Pearson 99% Exact Binomial confidence intervals is part of Phase D empirical research, which was **permanently removed from the delivery plan by owner decision**. For Scenario S5, the core campaign executes 20 valid live browser trials preceded by a 50-probe testbed readiness check.

---

## 3. Prerequisites and Environment Verification

The partner host MUST run a Linux-based operating system (bare-metal Ubuntu 24.04 LTS or WSL2 with systemd) with kernel `iproute2`, `tc-netem`, and `nftables` support.

### 3.1 Verify Host Capabilities
```bash
# Verify Python version >= 3.10
python3 --version

# Verify network namespace and routing tools
which ip tc nft tshark nginx

# Verify browser binaries match exact pinned versions
/usr/bin/google-chrome --version  # Expected: Google Chrome 156.0.8078.73
/usr/bin/firefox --version        # Expected: Mozilla Firefox 159.0
```

### 3.2 Configure Non-Interactive Sudoers
To execute network shaping and namespace operations without interactive password prompts, install the bounded helper rule per `docs/phase-cd/sudoers_configuration.md`:
```bash
sudo cp docs/phase-cd/sudoers.d/ps028_partner /etc/sudoers.d/ps028_partner
sudo chmod 0440 /etc/sudoers.d/ps028_partner
```

---

## 4. Replication Execution Workflow

### Step 1: Preflight Baseline Self-Test (Live Partner Readiness)

> [!WARNING]
> **PARTNER-ONLY LIVE NETWORK OPERATION — OWNER/PARTNER AUTHORIZATION REQUIRED**
>
> Executing `lab/self_test_scenarios.py` without `--dry-run` performs **live network configuration changes**, creates network namespaces, installs `tc netem` queuing disciplines, configures `nftables` packet drop rules, launches DNS responders, and executes live socket connection probes.
>
> **Execution Requirements & Protocol:**
> 1. **Explicit Authorization**: This command must only be executed by authorized partner laboratory personnel on a dedicated, non-production testbed host with explicit owner authorization.
> 2. **Environment Invariants**: Verify that host kernel versions match prerequisites, sudoers rules are installed, and no production network services share interface queues.
> 3. **Scenario Cleanup**: The test harness restores baseline impairments after each scenario check. If any check fails, immediately execute `sudo ./lab/teardown.sh` to purge residual namespaces and firewall tables.
> 4. **Post-Baseline Verification**: Run `./lab/setup_topology.sh check-host-invariance` to verify 100% restoration of host network state.
> 5. **Failure Handling**: On any `[FAIL]` or error output, halt execution immediately (`FAIL-STOP`). Do NOT proceed to campaign execution.
> 6. **Evidence Outputs**: Preflight self-test results are saved to `--output-dir` with full execution timestamps, kernel metadata, and per-probe latency records.
> 7. **Probe Count and Scope Distinctions**:
>    - **50-Probe Preflight Self-Test**: For Scenario S5 (stochastic 50% SYN loss), this readiness check runs **50 live TCP SYN probes by default** (`probe_count=50`, verifying that observed packet loss falls within $[20\%, 80\%]$) to verify that kernel packet dropping functions correctly.
>    - **280-Trial Core Campaign**: The core campaign consists of 20 live browser trials per scenario across 7 scenarios and 2 browsers ($7 \times 2 \times 20 = 280\text{ trials}$).
>    - **Excluded 200-Probe A11 Batch**: The 200-probe statistical acceptance batch is part of Phase D research and is **excluded** from this campaign.

```bash
# LIVE PREFLIGHT COMMAND (DO NOT RUN WITHOUT EXPLICIT AUTHORIZATION):
python3 lab/self_test_scenarios.py --bundle --output-dir lab/derived/partner-replication/self_tests
```
Verify that all preflight baseline checks report `[OK]`.

### Step 2: Initialize Partner Campaign
Create an independent campaign directory dedicated to the partner replication:
```bash
PARTNER_CAMPAIGN="ps028-partner-$(hostname)-$(date +%Y%m%d)"
python3 lab/run_campaign.py \
  --output-dir "lab/campaigns/${PARTNER_CAMPAIGN}" \
  --repetitions 20 \
  --browsers google-chrome firefox \
  --scenarios S0 S1 S2 S3 S4 S5 S6
```

### Step 3: Run Deterministic Post-Campaign Dissection & Evidence Export
Upon completion of all 280 planned trials, execute the deterministic analysis and evidence exporter:
```bash
# 1. Rederive metrics under Schema 1.1.0
python3 lab/rederive_historical_campaign.py \
  --campaign-dir "lab/campaigns/${PARTNER_CAMPAIGN}" \
  --output-dir "lab/derived/partner-replication/rederived"

# 2. Export standardized ledgers and Amendment A13 provenance sidecars
python3 lab/export_campaign_evidence.py \
  --campaign-dir "lab/campaigns/${PARTNER_CAMPAIGN}" \
  --output-dir "lab/derived/partner-replication" \
  --target all
```

### Step 4: Cryptographic Package & Handover
Compute the cryptographic integrity manifest and package the campaign evidence:
```bash
cd "lab/campaigns/${PARTNER_CAMPAIGN}"
find . -type f ! -name "*.sha256" -exec sha256sum {} + | sort -k2 > partner_evidence.sha256
tar -czvf "${PARTNER_CAMPAIGN}.tar.gz" .
```

Submit the archive and SHA-256 digest to the lead repository maintainer. The maintainer will inspect the authentic cryptographic evidence and update `docs/phase-cd/partner_replication_manifest.json` from `PENDING_AUTHENTIC_PARTNER_EVIDENCE` to `VERIFIED`.
