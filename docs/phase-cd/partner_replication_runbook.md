# Partner Multi-Host Replication Runbook (Phase D5)

- **Document ID**: `PS028-RUNBOOK-D5-REPLICATION`
- **Status**: **STANDARD OPERATING PROCEDURE (PENDING PARTNER EVIDENCE)**
- **Governing Requirements**: AIORI-3 PS-028 / Phase D Protocol Section 6.2
- **Rule Compliance**: Rule R1 (No Fabricated Data), Rule R6 (Evidence Classes Separated), Rule R7 (No Conformance Claims)

---

## 1. Overview and Purpose

To establish external reproducibility and cross-platform scientific validity, this runbook provides step-by-step instructions for an independent partner laboratory to replicate the complete 280-trial PS-028 Happy Eyeballs measurement matrix.

> [!CAUTION]
> **Rule R1 Non-Negotiable Mandate:**
> The repository explicitly records the replication status as `STATUS: PENDING AUTHENTIC PARTNER EVIDENCE`. No synthetic, mock, or simulated partner run may ever be relabeled or committed as authentic external replication evidence.

---

## 2. Prerequisites and Environment Verification

The partner host MUST run a Linux-based operating system (bare-metal Ubuntu 24.04 LTS or WSL2 with systemd) with kernel `iproute2`, `tc-netem`, and `nftables` support.

### 2.1 Verify Host Capabilities
```bash
# Verify Python version >= 3.10
python3 --version

# Verify network namespace and routing tools
which ip tc nft tshark nginx

# Verify browser binaries match pinned versions
/usr/bin/google-chrome --version  # Expected: Google Chrome 156+
/usr/bin/firefox --version        # Expected: Mozilla Firefox 159+
```

### 2.2 Configure Non-Interactive Sudoers
To execute network shaping and namespace operations without interactive password prompts, install the bounded helper rule per `docs/phase-cd/sudoers_configuration.md`:
```bash
sudo cp docs/phase-cd/sudoers.d/ps028_partner /etc/sudoers.d/ps028_partner
sudo chmod 0440 /etc/sudoers.d/ps028_partner
```

---

## 3. Replication Execution Workflow

### Step 1: Preflight Baseline Self-Test
Ensure the host is in a clean initial state with zero leftover interfaces, netns, or firewall tables:
```bash
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

Submit the archive and SHA-256 digest to the lead repository maintainer. The maintainer will inspect the authentic cryptographic evidence and update `docs/phase-cd/partner_replication_manifest.json` from `PENDING` to `VERIFIED`.
