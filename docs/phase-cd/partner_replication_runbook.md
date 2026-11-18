# Independent Partner Core Campaign Replication Runbook

- **Document ID**: `PS028-RUNBOOK-CORE-REPLICATION`
- **Status**: **STANDARD OPERATING PROCEDURE (PENDING AUTHENTIC PARTNER EVIDENCE)**
- **Governing Requirements**: AIORI-3 PS-028 Core Campaign Replication Matrix (Requirements #1–#6, #18)
- **Rule Compliance**: Rule R1 (No Fabricated Data), Rule R6 (Evidence Classes Separated), Rule R7 (No Conformance Claims)

---

## 1. Overview and Purpose

To establish external reproducibility and cross-platform scientific validity, this runbook provides step-by-step instructions for an independent partner laboratory to replicate the canonical 280-trial PS-028 Happy Eyeballs measurement matrix:
- **Canonical Scenarios**: S0 through S6 (7 impairment/delay scenarios).
- **Target Client Implementations**: Pinned Google Chrome and Mozilla Firefox builds.
- **Trial Repetitions**: Exactly 20 valid live trials per browser per scenario ($7 \times 2 \times 20 = 280\text{ trials}$).
- **Milestone Scope**: Canonical 280-trial core measurement experiment. Excludes exploratory sweeps and non-canonical parameter probes.

> [!CAUTION]
> **Rule R1 Non-Negotiable Mandate:**
> The repository explicitly records the replication status as `STATUS: PENDING AUTHENTIC PARTNER EVIDENCE`. No synthetic, mock, or simulated partner run may ever be relabeled or committed as authentic external replication evidence.

---

## 2. Applicable Protocol Requirements (A2, A4, A8, A10, A13)

The partner replication manifest adheres strictly to the applicable project protocol amendments:

* **Amendment A2 (Sample Size Rigor)**: Exactly $n=20$ valid live trials per browser per scenario ($7 \times 2 \times 20 = 280$ trials total). Exploratory or pilot runs with $n < 20$ are strictly barred from final claims.
* **Amendment A4 (Controlled DNS Responder Integrity)**: Controlled DNS responder with wildcard `*.he.test.`, immediate NOERROR/NODATA for HTTPS Type 65 queries, and fail-closed lock reload via SIGHUP.
* **Amendment A8 (Browser DNS Controls & Metric Isolation)**: Effective browser-level DoH/TRR disablement, isolated ephemeral user profiles, and separation of DNS transaction metrics from TCP connection setup timing (`t_setup_total_ms`).
* **Amendment A10 (Specification of Record Integrity)**: Pinned specification revision of record remains `draft-ietf-happy-happyeyeballs-v3-04` (published 1 July 2026; dated status check: 2026-11-13).
* **Amendment A13 (Deterministic Ordering & Provenance Sidecars)**: Pre-persisted random seeds, Schema 1.1.0 ledgers, and `.provenance.json` cryptographic sidecars for all derived outputs.

---

## 3. Prerequisites and Environment Verification

The partner host environment MUST run a supported Linux distribution (Ubuntu 24.04 LTS bare-metal or under WSL2 with systemd) with kernel `iproute2`, `tc-netem`, and `nftables` support.

### 3.1 Stage 1: Read-Only Host Preflight & Service Identity Verification
Execute the safe, non-mutating preflight script to audit host readiness without altering network state:
```bash
# Execute read-only partner preflight audit
python3 lab/partner_preflight.py

# Optional: output structured JSON report for partner record-keeping
python3 lab/partner_preflight.py --json -o partner_preflight_report.json
```

Verify service identity and capture partner host's baseline network snapshot before creating topology:
```bash
# Resolve operating user dynamically
OPERATOR_USER="${SUDO_USER:-$(id -un)}"
echo "Operating user: ${OPERATOR_USER}"

# Verify or provision dedicated Nginx service user 'ps028-sv'
# For privilege isolation, Nginx worker processes run strictly under ps028-sv (never the operator account)
id -u ps028-sv || sudo useradd --system --no-create-home -s /usr/sbin/nologin ps028-sv

# Establish machine-specific state directory
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/ps028"
mkdir -p "${STATE_DIR}"
BASELINE_FILE="${STATE_DIR}/host-network-baseline-$(hostname).txt"

# Capture partner host's own network baseline snapshot before topology creation
sudo ./lab/setup_topology.sh snapshot-host "${BASELINE_FILE}"
sha256sum "${BASELINE_FILE}" > "${BASELINE_FILE}.sha256"
echo "Partner host baseline snapshot saved to ${BASELINE_FILE}"
```

### 3.2 Stage 2: Deployment Specification Dry-Run
Before executing any privileged installation or upgrade, execute the deployment script in `--dry-run` mode. This audits Git provenance, source checkout cleanliness, absence of dirty working tree modifications, source permissions, service account properties, existing installation integrity, and sudoers syntax without modifying host files.
```bash
# Execute read-only dry-run audit with pinned release commit SHA
./lab/deploy_privileged_helper.sh --dry-run --user "${OPERATOR_USER}" --release-sha <APPROVED_RELEASE_SHA>
```
> [!NOTE]
> The dry-run command fails closed (returns a non-zero exit code) if any prerequisite fails (e.g., missing `ps028-sv`, dirty git tree, altered existing files, or invalid visudo syntax). It must report `[SUCCESS] Dry-run specification check complete.` before live deployment.

### 3.3 Stage 3: Transactional Installation / Upgrade
Deploy or upgrade the privileged helper under `/usr/local/libexec/ps028/` and install the non-interactive sudoers drop-in `/etc/sudoers.d/ps028-helper`:
```bash
# Transactionally install or upgrade the privileged helper using pinned release commit SHA
sudo ./lab/deploy_privileged_helper.sh --user "${OPERATOR_USER}" --release-sha <APPROVED_RELEASE_SHA>

# If upgrading an unmanifested legacy installation on the partner host:
# The legacy baseline commit SHA is pinned to 176f688bacb5858fcc0daedb454200918e427f3f (ps028-p0-accepted-2026-11-14^{commit}).
sudo ./lab/deploy_privileged_helper.sh --user "${OPERATOR_USER}" --release-sha <APPROVED_RELEASE_SHA> --migrate-unmanifested --legacy-baseline-commit 176f688bacb5858fcc0daedb454200918e427f3f
```

**Transactional Guarantees, State Machine & Safety Architecture:**
1. **Existing Installation Audit**: If an existing deployment is present, its manifest and all files are audited. Any altered files, unmanifested files, or symlinks cause an immediate abort before any files are modified.
2. **Legacy Migration Path & Strict Permission Invariants**:
   - Authoritative location: `/usr/local/libexec/ps028/privileged_helper.py`.
   - `--migrate-unmanifested` verifies that every installed file matches an authentic historical Git commit before synthesizing a baseline manifest. Hash verification is never bypassed.
   - **Permission Invariants**: Rejects any group-writable or world-writable files (`st_mode & 0o022 != 0`) or directories. Executables must have mode `0750` or `0755`; non-executable modules/configs must have mode `0640` or `0644`.
3. **Exclusive Concurrent Deployment Locking**: Exclusive non-blocking kernel lock (`flock -n`) on `${TARGET_PARENT}/.ps028_deploy.lock` held throughout operations.
4. **Discrete State Journaling & Crash Recovery**: Discrete state transitions committed to disk via `fsync` before file renames, supporting automatic recovery from process crashes or signals.

### 3.4 Stage 4: Post-Installation Integrity Verification
Verify that the deployed helper is functional and authorized via sudoers:
```bash
# Verify non-interactive helper authentication and subcommand registration
sudo /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py check-auth

# Verify installed manifest matches exact deployed source revision
cat /usr/local/libexec/ps028/deployment_manifest.json
```

---

## 4. Replication Execution Workflow

### Step 1: Live Topology Setup (Separate Authorization Gate)

> [!WARNING]
> **SEPARATE AUTHORIZATION GATE: LIVE TOPOLOGY PROVISIONING**
>
> Helper deployment ONLY installs the trusted execution boundary under `/usr/local/libexec/ps028/`.
> Network topology setup (`sudo ./lab/setup_topology.sh setup`) constitutes a strictly separate, explicit authorization gate.
> Do NOT provision network namespaces without explicit authorization on a dedicated testbed.

```bash
# Provision isolated network namespaces, veth interfaces, and baseline 10ms delays
sudo ./lab/setup_topology.sh setup

# Verify topology status and routing
sudo ./lab/setup_topology.sh status
```

### Step 2: Initialize Canonical 280-Trial Campaign
Create an independent campaign directory dedicated to the partner replication outside the source repository:
```bash
PARTNER_CAMPAIGN="ps028-partner-$(hostname)-$(date +%Y%m%d)"
PARTNER_EVIDENCE_DIR="${HOME}/ps028-partner-evidence/${PARTNER_CAMPAIGN}"
PARTNER_DERIVED_DIR="${HOME}/ps028-partner-derived/${PARTNER_CAMPAIGN}"

mkdir -p "${PARTNER_EVIDENCE_DIR}"
mkdir -p "${PARTNER_DERIVED_DIR}"

python3 lab/run_campaign.py \
  --output-dir "${PARTNER_EVIDENCE_DIR}" \
  --repetitions 20 \
  --browsers "google-chrome,firefox" \
  --scenarios "S0,S1,S2,S3,S4,S5,S6"
```
Verify that the campaign finishes with status `COMPLETED` and execution mode `LIVE`:
- The output manifest `${PARTNER_EVIDENCE_DIR}/campaign_manifest.json` tracks exactly 280 unique matrix slots (`matrix_slots`).
- Every planned matrix slot records status `COMPLETED` and contains a successful attempt with validity `VALID_LIVE`.
- If any retry occurred due to transient measurement or cleanup anomalies, failed-attempt history is preserved (`status: "FAILED"`, validity `MEASUREMENT_FAILURE` or `CLEANUP_FAILURE`) with its corresponding `failed_attempt_record.json` preserved under `trials/<trial_id>/`.
- Live trial outputs are structured under `trials/<trial_id>/result.json` and `trials/<trial_id>/capture.pcap`.
- Storing campaign outputs in `${PARTNER_EVIDENCE_DIR}` outside the source repository ensures that the Git working tree remains completely clean (`git_dirty: false`, `git_status: "VERIFIED"`), allowing downstream provenance sidecars to achieve `provenance_status: "VERIFIED"`.

### Step 3: Run Deterministic Post-Campaign Dissection & Evidence Export
Upon completion of all 280 planned trials, execute the deterministic analysis and evidence exporter. Storing derived ledgers outside the source checkout under `${PARTNER_DERIVED_DIR}` maintains clean repository provenance:
```bash
python3 lab/export_campaign_evidence.py \
  --campaign-dir "${PARTNER_EVIDENCE_DIR}" \
  --output-dir "${PARTNER_DERIVED_DIR}" \
  --target all
```

### Step 4: Topology Teardown & Host Invariance Verification
Clean up all network namespaces, interfaces, routing, and verify that the partner host network has been 100% restored to its original pre-experiment baseline snapshot:
```bash
# Teardown PS-028 network namespaces and interfaces
sudo ./lab/setup_topology.sh teardown

# Verify 100% restoration against the partner host's own baseline snapshot
sudo ./lab/setup_topology.sh check-host-invariance "${BASELINE_FILE}"
```

### Step 5: Cryptographic Package, Handover Archive & Local Verification
Compute the cryptographic integrity manifest and package the campaign evidence outside the campaign directory:
```bash
# 1. Compute checksums of campaign contents (excluding checksum manifests and archives)
cd "${PARTNER_EVIDENCE_DIR}"
find . -type f ! -name "*.sha256" ! -name "*.tar.gz" -exec sha256sum {} + | sort -k2 > partner_evidence.sha256

# 2. Package archive from parent directory to avoid recursive inclusion
cd "${HOME}/ps028-partner-evidence"
tar -czvf "${PARTNER_CAMPAIGN}.tar.gz" "${PARTNER_CAMPAIGN}"

# 3. Compute mandatory SHA-256 digest sidecar of the final handover archive
sha256sum "${PARTNER_CAMPAIGN}.tar.gz" > "${PARTNER_CAMPAIGN}.tar.gz.sha256"
cd - > /dev/null

# 4. Verify handover package against all PS-028 criteria before submission
python3 lab/verify_partner_handover.py \
  --archive "${HOME}/ps028-partner-evidence/${PARTNER_CAMPAIGN}.tar.gz" \
  --derived-dir "${PARTNER_DERIVED_DIR}"
```

**Portable Verification & Architecture Guarantees:**
1. **Manifest Schema Compliance**: Verifies `campaign_manifest.json` schema version `1.0.0` or `1.1.0`, `execution_mode: "LIVE"`, `is_simulation: false`, and campaign status `COMPLETED`.
2. **Matrix Rigor**: Strictly verifies all 280 canonical slots ($7 \times 2 \times 20$), requiring every slot to contain a valid live attempt.
3. **Physical Evidence Layout**: Resolves trial evidence portably under `trials/<trial_id>/result.json` and `trials/<trial_id>/capture.pcap`, never relying on original host absolute paths.
4. **Authenticity & Integrity**: Validates PCAP header magics, packet counts ($> 0$), SHA-256 digests, and cleanup restoration.
5. **Preserved History**: Ingests and verifies preserved failed attempts (`failed_attempt_record.json`) without silent relabeling.
6. **Provenance & Derived Ledgers**: Validates `.provenance.json` sidecars (`provenance_status: "VERIFIED"`, `git_dirty: false`, `git_status: "VERIFIED"`) across `attempts.csv`, `connection_attempts.csv`, and `trial_timeline.csv`.
7. **Fail-Closed Archive Extraction**: Prevents directory traversal attacks, rejecting path escaping, device nodes, or absolute paths during archive extraction. Requires companion `.sha256` checksum sidecar.

Submit the verified archive (`${HOME}/ps028-partner-evidence/${PARTNER_CAMPAIGN}.tar.gz`) and SHA-256 digest (`${HOME}/ps028-partner-evidence/${PARTNER_CAMPAIGN}.tar.gz.sha256`) to the lead repository maintainer. The maintainer will inspect the authentic cryptographic evidence and update `docs/phase-cd/partner_replication_manifest.json` from `PENDING_AUTHENTIC_PARTNER_EVIDENCE` to `VERIFIED`.
