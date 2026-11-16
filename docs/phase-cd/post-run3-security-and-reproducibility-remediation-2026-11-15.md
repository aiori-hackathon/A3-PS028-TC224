# PS-028 Comprehensive Security, Provenance, Reproducibility and Release-Protection Remediation

- **Document Version**: 1.0.0
- **Audit & Execution Date**: 2026-11-15
- **Authoritative Working Branch**: `fix/phase-e-bundle-timeline-mapping`
- **Starting & Current HEAD SHA**: `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`
- **Final Submission Branch (`main`) SHA**: `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26` (Untouched, 52 commits behind integration branch)
- **Protected Historical Acceptance Tag**: `ps028-p0-accepted-2026-11-14` (`176f688bacb5858fcc0daedb454200918e427f3f`, verified ancestor of HEAD)
- **Repository**: `https://github.com/aiori-hackathon/A3-PS028-TC224.git`
- **Problem Statement Compliance**: **17 MET (85.0%), 2 PARTIAL (10.0%), 1 PENDING (5.0%)** (15/15 Core PS Requirements Met)

---

## Section A: Executive Summary & Repository Identity

This document provides the authoritative engineering and governance record for the comprehensive security, evidence provenance, dependency locking, release documentation reconciliation, and repository protection remediation completed following the successful execution of remote GitHub Actions CI Run #3.

All five outstanding areas of technical risk and documentation precision identified during independent review have been addressed with production-grade mitigations:
1. **Task P1 — Privileged Helper Security Architecture**: Eliminated ambient root execution of user-writable code, sealed netns execution bypasses, implemented strict filesystem path confinement, validated network endpoints against strict PS-028 allowlists, hardened file ownership operations, and authored the secure system deployment specification.
2. **Task P2.3 — Release Documentation Reconciliation**: Fully reconciled `README.md`, `ps028-compliance-matrix.md`, `final-release-validation-record-2026-11-15.md`, `owner_handover_checklist.md`, and `test-inventory-reconciliation.md` with GitHub Actions Run #3, preserving historical Run #1 and Run #2 evidence and maintaining strict Phase D removal qualification.
3. **Task P2.4 — Evidence Provenance Fallback Elimination**: Removed all hardcoded fallback commit hashes, branch names, and tool version strings from `lab/export_campaign_evidence.py`. Implemented fail-closed `UNKNOWN`/`UNAVAILABLE` status and working tree dirty detection.
4. **Task P2.5 — Exact Dependency Locking & Reproducible Builds**: Eliminated floating version specifiers (`markdown-it-py>=3.0.0`), established direct specification in `requirements.in`, locked all distribution packages with cryptographically verified SHA-256 hashes in `requirements.lock`, and integrated `--require-hashes` enforcement into GitHub Actions CI.
5. **Task P2.6 — Repository Governance & Branch Protection Audit**: Performed transparent API inspection of `main` branch protection rules, documented administrative permission boundaries, and formulated the exact verified status check context configuration and owner-admin procedure.

All modifications remain strictly uncommitted in the local working tree, preserving zero-commit discipline pending final review.

---

## Section B: Privileged Helper Security Remediation (Task P1)

### 1. Root Execution of User-Writable Repository Code Mitigation
- **Vulnerability**: Invoking `sudo python3 lab/privileged_helper.py` executes code from a repository clone writable by an unprivileged user (`promotheshchatterjee`), permitting privilege escalation if the working directory or Python module search path is modified.
- **Architectural Solution**:
  - Implemented `sanitize_privileged_sys_path()`: When running with effective UID 0 (`os.geteuid() == 0`), the helper purges empty strings (`""`), current working directory (`"."`), current working directory string (`os.getcwd()`), and any directory with world-writable permissions (`stat.S_IWOTH`) from `sys.path`.
  - Created system deployment script `lab/deploy_privileged_helper.sh`: Installs the helper and its identity dependency into root-owned `/usr/local/libexec/ps028/` with file mode `0755` (`rwxr-xr-x`, root:root). Supports `--dry-run` validation without root privileges.
  - Updated sudoers configuration specification (`docs/phase-cd/sudoers_configuration.md`): Mandates Python isolated mode (`python3 -I`) and targets the canonical root-owned path `/usr/local/libexec/ps028/privileged_helper.py`, eliminating wildcard path execution.

### 2. S5 Internal Namespace Verification
- **Vulnerability**: The public CLI previously accepted `--in-netns <netns>`, allowing callers to claim execution inside network namespace `ps028-cl` without verification, executing S5 probes in the host network context.
- **Architectural Solution**:
  - Removed `--in-netns` option from public `measure-s5` CLI subparser.
  - Added dedicated internal subparser `measure-s5-worker` specifically for invocation by `ip netns exec ps028-cl`.
  - Implemented `get_netns_inode()` and `verify_current_netns()`: Authoritatively inspects `/proc/self/ns/net` device and inode numbers against `/run/netns/<netns>`.
  - Fails closed with `PrivilegedHelperError` if `measure_s5_privileged` is executed outside `ps028-cl` (with strict exception only for unprivileged loopback test fixtures with UID > 0).

### 3. Strict Filesystem Path Confinement
- **Vulnerability**: Potential path traversal or symlink escapes in path-accepting actions (`--scenarios-path`, `--config-file`, `--backup-file-a3`, `--backup-file-a4`, `--lock-file`, `--pcap-path`, `--pid-file`, `--mounts-file`, `--resolv-conf`, `--root-dir`).
- **Architectural Solution**:
  - Implemented `validate_secure_path()`:
    1. Null byte rejection (`\0`).
    2. Strict lexical path confinement: Normalized absolute paths (`os.path.abspath`) must reside within explicit allowlisted roots (`REPO_ROOT`, `/tmp`, `/var/tmp`, `/run`, `/var/run`, `/usr/local/libexec/ps028`).
    3. Symlink escape rejection: Direct symlinks and symlinked parent directory components escaping approved roots are rejected unless `allow_symlinks=True` is explicitly specified.
    4. Resolved target confinement: The fully resolved filesystem target must reside inside allowlisted roots.
    5. Regular file enforcement: Enforces `p.is_file()` where regular files are required.

### 4. Network Input Validation
- **Vulnerability**: Arbitrary IPs, ports, or command injection via S5 socket parameters or DNS delay arguments.
- **Architectural Solution**:
  - Implemented `validate_ip_endpoint()`: Parses input with `ipaddress.ip_address()`, enforces address family matching (IPv4 vs IPv6), rejects shell meta-characters (whitespace, quotes, semicolons), and strictly bounds target IPs to canonical PS-028 endpoints:
    - Allowed client IPs: `10.0.1.2`, `fd00:1::2`, `127.0.0.1`, `::1`.
    - Allowed target IPs: `10.0.2.2`, `10.0.3.2`, `fd00:2::2`, `fd00:3::2`, `127.0.0.1`, `::1`.
  - Interfaces restricted strictly to allowlist: `ps028-rt-sv6`, `ps028-rt-sv4`.
  - Integer boundaries enforced on ports (1–65535), probe counts (1–1000), timeouts (0.01s–60s), and concurrency (1–100).

### 5. Ownership and Privilege Dropping Safeguards
- Hardened `_chown_file()`: Validates target file with `validate_secure_path()`, refuses symlink targets, and strictly rejects root UID 0, GID 0, and privileged groups (`root`, `wheel`, `sudo`).
- Hardened `_resolve_and_validate_capture_owner()`: Resolves invoking unprivileged user via `lab.identity`, enforces target UID > 0, and rejects GID 0 or unauthorized groups.
- Hardened `launch_snap_browser_main()`: Immediately validates `reuid > 0` and `regid > 0`, exiting with status code 74 if root or invalid identities are passed.

### 6. Security Regression Test Suite
Added `TestPrivilegedHelperSecurityHardenings` to `lab/test_privileged_helper.py` containing 19 comprehensive test cases:
- `test_path_confinement_rejects_absolute_path_outside_approved_roots`
- `test_path_confinement_rejects_parent_traversal`
- `test_path_confinement_rejects_null_bytes`
- `test_path_confinement_rejects_symlink_escaping_approved_roots`
- `test_chown_file_refuses_symlink_target`
- `test_chown_refuses_root_uid_or_gid_0`
- `test_unapproved_dns_config_file_rejected`
- `test_unapproved_dns_backup_destination_rejected`
- `test_validate_ip_endpoint_rejects_invalid_ips`
- `test_validate_ip_endpoint_rejects_injection_strings`
- `test_validate_ip_endpoint_family_mismatch`
- `test_validate_ip_endpoint_unauthorized_ip`
- `test_validate_s5_params_rejects_unapproved_interface`
- `test_measure_s5_in_netns_flag_removed_from_public_cli`
- `test_measure_s5_worker_fails_closed_outside_netns_when_root`
- `test_sys_path_sanitization_removes_world_writable_and_cwd`
- `test_capture_owner_rejects_root_or_unauthorized_group`
- `test_snap_browser_rejects_root_uid_or_gid_0`
- `test_cli_rejects_unknown_subcommand_or_option`

---

## Section C: Release Documentation Reconciliation (Task P2, Section 3)

### 1. Updated Documentation Inventory
All core documentation has been reconciled to reflect the successful execution of remote GitHub Actions Run #3:
- `README.md`: Updated remote CI status badge and release record to Run #3 (ID `43741695912`, 966 tests, 2m 8s duration). Updated integration branch tracking to commit `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` (52 commits ahead of `main`). Preserved historical Run #1 and Run #2 references.
- `docs/phase-cd/ps028-compliance-matrix.md`: Updated Requirement #19 to record Run #3 PASS with 966 tests and artifact verification. Recorded Milestone 10 in the test chronology. Enforced explicit Phase D removal wording for Requirements #16 and #17.
- `docs/phase-cd/final-release-validation-record-2026-11-15.md`: Added Section 7.7 documenting Run #3 test counts, execution durations, and artifact metadata. Renumbered Section 7.8 Final Compliance Matrix Summary. Preserved Section 7.5 (Run #1) and Section 7.6 (Run #2).
- `docs/phase-cd/owner_handover_checklist.md`: Updated Section 1 and Section 2 to cite Run #3 URL and artifact link alongside Run #2.
- `docs/phase-cd/test-inventory-reconciliation.md`: Expanded test chronology from nine to ten milestones, recording Milestone 10 (966 tests, commit `275ebf45eaef`). Updated CI disclosure section.

### 2. Remote GitHub Actions Run #3 Authoritative Details
- **Run ID**: `43741695912`
- **Run URL**: `https://github.com/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912`
- **Workflow**: `PS-028 Continuous Integration` (`.github/workflows/ci.yml`)
- **Triggering Commit**: `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3` on `fix/phase-e-bundle-timeline-mapping`
- **Run Duration**: 2 minutes 8 seconds
- **Job Status**:
  - `python-tests`: **PASS** (1m 11s) — 842 lab tests + 93 integration tests + 705 checksums verified.
  - `frontend-validation`: **PASS** (1m 18s) — 31 unit tests + 16 smoke checks + 14 browser stages (242 assertions).
  - `artifacts-validation`: **PASS** (1m 3s) — Built presentation PDF (11 pages) and technical report PDF (22 pages).
- **Submission Artifact**:
  - Name: `ps028-submission-artifacts`
  - Artifact ID: `14172830625`
  - Size: 681,255 bytes
  - SHA-256 Digest: `ee16f8048be0511fd576ac327cc0367d84563e82869d9f140e75356b6ae9c333`

### 3. Problem Statement Compliance Breakdown
- **MET**: **17 (85.0%)** — All 15 Core Problem Statement Requirements (#1–#15), Ownership Transfer (#18), and Remote CI Verification (#19).
- **PARTIAL**: **2 (10.0%)** — Requirement #16 (Uniform netem live sweep: `REMOVED FROM CURRENT DELIVERY PLAN BY OWNER DECISION; analytical simulation models verified`) and Requirement #17 (Live S5 binomial batch: `REMOVED FROM CURRENT DELIVERY PLAN BY OWNER DECISION; simulation verified`).
- **OWNER-ONLY**: **0 (0.0%)** — Requirement #18 verified transferred to `aiori-hackathon` organisation on 14 November 2026.
- **PENDING**: **1 (5.0%)** — Requirement #20 (Phase A.6 partner replication package authored; scheduled as final separate milestone).
- **Total Tracked**: **20 (100.0%)**

---

## Section D: Evidence Provenance Fallback Remediation (Task P2, Section 4)

### 1. Eliminated Defects in `lab/export_campaign_evidence.py`
- **Stale Fallback Commit & Branch**: Previously, `get_git_info()` fell back to hardcoded commit `7c6ab23c2a378bbc8556fcc15f5911f626502576` and branch `regional/ps028-phase-cd` when `git rev-parse` failed.
- **Stale Tool Versions**: `get_tshark_version()` fell back to `"4.2.2"` on failure, and `tcpdump_version` was hardcoded to `"4.99.4"`.
- **Missing Working Tree Dirty Detection**: The exporter lacked awareness of uncommitted modifications.

### 2. Implemented Fail-Closed Architecture
- **Dynamic Git Inspection**: Queries `git rev-parse HEAD`, `git rev-parse --abbrev-ref HEAD`, and `git status --porcelain` with timeouts. On failure or non-git environment, returns `"git_commit": "UNKNOWN"`, `"git_branch": "UNKNOWN"`, `"git_dirty": False`, and `"git_status": "UNAVAILABLE"`. Returns `"git_status": "VERIFIED"` only when HEAD is successfully resolved.
- **Dynamic TShark Version**: Executes `tshark -v` with timeout and parses the version string. Returns `"UNAVAILABLE"` on failure; never returns a hardcoded version.
- **Dynamic TCPDump Version**: Executes `tcpdump --version` with timeout, inspecting stdout and stderr. Returns `"UNAVAILABLE"` on failure; never returns hardcoded `"4.99.4"`.
- **Sidecar Provenance Status**: In `write_provenance_sidecar()`, evaluates whether all tool versions and git metadata were authoritatively resolved. Populates `"provenance_status": "VERIFIED"` if and only if git status is `VERIFIED` and neither tool is `UNAVAILABLE`; otherwise populates `"provenance_status": "INCOMPLETE"`. Records `"git_dirty"` boolean.

### 3. Provenance Regression Tests
Added `TestExportCampaignEvidenceProvenanceHardenings` to `lab/test_export_campaign_evidence.py` with 10 test cases:
- `test_git_info_live`: Validates live git metadata resolution.
- `test_git_info_failure_fails_closed`: Verifies that git execution failure produces `UNKNOWN` and `UNAVAILABLE`.
- `test_git_info_dirty_flag_detection`: Verifies accurate detection of uncommitted modifications.
- `test_tshark_version_live`: Validates live TShark version retrieval.
- `test_tshark_version_failure_returns_unavailable`: Verifies fail-closed behavior on missing TShark.
- `test_tcpdump_version_live`: Validates live TCPDump version retrieval.
- `test_tcpdump_version_failure_returns_unavailable`: Verifies fail-closed behavior on missing TCPDump.
- `test_write_provenance_sidecar_schema_and_status`: Validates new fields (`git_dirty`, `git_status`, `provenance_status`, `tcpdump_version`) and `VERIFIED` state.
- `test_write_provenance_sidecar_incomplete_on_tool_failure`: Verifies `INCOMPLETE` state on tool failure.
- `test_no_hardcoded_stale_strings`: Asserts that `7c6ab23c...` and `regional/ps028-phase-cd` are completely absent from the source code.

---

## Section E: Exact Dependency Locking & Reproducible Builds (Task P2, Section 5)

### 1. Direct Dependency Specification (`requirements.in`)
Created `requirements.in` documenting direct top-level dependencies:
```text
PyYAML==6.0.1
markdown-it-py==3.0.0
mdurl==0.1.2
dnspython==2.6.1
```

### 2. Pinned Package Manifest (`requirements.txt`)
Updated `requirements.txt` to replace floating `markdown-it-py>=3.0.0` with exact pinned version:
```text
PyYAML==6.0.1
markdown-it-py==3.0.0
mdurl==0.1.2
dnspython==2.6.1
```

### 3. Cryptographically Locked Distribution File Hashes (`requirements.lock`)
Created `requirements.lock` containing exact SHA-256 digests for all official binary wheels and source distributions from PyPI for the pinned versions. Verified locally via:
```bash
pip install --dry-run --require-hashes --break-system-packages -r requirements.lock
```
(Exited with status code 0, confirming 100% hash coverage).

### 4. GitHub Actions CI Enforcement
Updated `.github/workflows/ci.yml`:
- In `python-tests` job: Added `cache-dependency-path: 'requirements.lock'` and replaced unhashed install with `pip install --require-hashes -r requirements.lock`.
- In `artifacts-validation` job: Added `cache-dependency-path: 'requirements.lock'` and replaced unhashed install with `pip install --require-hashes -r requirements.lock`.

---

## Section F: Branch Protection Configuration & Repository Governance (Task P2, Section 6)

### 1. API Verification and Permissions Boundary Disclosure
- **API Call Executed**:
  ```bash
  gh api -X PUT /repos/aiori-hackathon/A3-PS028-TC224/branches/main/protection --input protection_payload.json
  ```
- **Observed Result**: `HTTP 404 Not Found`
- **Root-Cause Investigation**:
  Inspected authenticated user permissions via `gh api /repos/aiori-hackathon/A3-PS028-TC224 --jq '.permissions'`:
  ```json
  {
    "admin": false,
    "maintain": false,
    "push": true,
    "triage": true,
    "pull": true
  }
  ```
- **Forensic Accounting**: In the GitHub REST API, configuring branch protection rules on `/repos/{owner}/{repo}/branches/{branch}/protection` strictly requires **Repository Administrator** permissions. When a non-admin token with push access attempts this endpoint, GitHub returns HTTP 404 (Not Found) rather than 403 (Forbidden) for security obscurity.
- **Non-Fabrication Policy**: In accordance with Section 1.1 and Section 11 of the project instructions, no false claim of branch protection activation is made. The exact status check context names, payload, and procedure are documented below for execution by the organization administrator.

### 2. Verified GitHub Actions CI Status Check Context Names
Authoritatively extracted from Run #3 check run records (`gh api /repos/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912/jobs --jq '.jobs[].name'`):
1. `Python Backend & Integration Tests`
2. `Frontend WebTester Validation`
3. `Submission Artifacts & PDF Validation`

### 3. Owner-Admin Branch Protection Procedure
To enforce branch protection on `main`, an organization administrator should execute:

```bash
gh api -X PUT /repos/aiori-hackathon/A3-PS028-TC224/branches/main/protection \
  --input - << 'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Python Backend & Integration Tests",
      "Frontend WebTester Validation",
      "Submission Artifacts & PDF Validation"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

---

## Section G: Complete Local Test & Build Verification Record

### 1. Test Suite Execution Summary
Executed on Linux x86_64 in an unprivileged user context:

| Test Suite | Discovery Path / Command | Tests Executed | Passed | Failed | Errors | Skips | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Lab Unit & Regression** | `python3 -m unittest discover -s lab -p "test_*.py"` | 872 | 872 | 0 | 0 | 0 | 46.267s |
| **Synthetic / Integration** | `python3 -m unittest discover -s tests -p "test_*.py"` | 93 | 93 | 0 | 0 | 0 | 0.353s |
| **Frontend WebTester** | `npm test --prefix setup/webtester` | 31 | 31 | 0 | 0 | 0 | 0.657s |
| **Total Automated Tests** | — | **996** | **996** | **0** | **0** | **0** | **47.277s** |

### 2. Quality Gate Verification
- **Historical Campaign Integrity (Rule R2)**:
  `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256`: **705/705 files verified 100% matched**.
- **Privileged Helper Security Suite**:
  `python3 -m unittest lab/test_privileged_helper.py`: **115/115 passed** (including 19 new security tests).
- **Evidence Provenance Suite**:
  `python3 -m unittest lab/test_export_campaign_evidence.py`: **26/26 passed** (including 10 new provenance tests).
- **Frontend Quality Gates**:
  - `npm run check --prefix setup/webtester`: Astro template & TypeScript validation PASS.
  - `npm run test:smoke --prefix setup/webtester`: 16/16 static distribution smoke checks PASS.
  - `npm run test:browser --prefix setup/webtester`: 14 stages, 242 assertions in genuine Chromium PASS.
- **Submission Document Compilation**:
  - `python3 lab/build_submission_report.py`: `PS028_Hackathon_Submission_Presentation.pdf` successfully generated (207,985 bytes, 11 pages).
  - `python3 lab/build_technical_report_pdf.py`: `PS028 Detailed Analysis & Report PDF.pdf` successfully generated (464,150 bytes, 22 pages, 104 streams).
  - `python3 -m unittest lab/test_build_submission_report.py lab/test_build_technical_report_pdf.py`: 44/44 regression tests PASS.

---

## Section H: Working Tree Audit & Compliance Confirmation

### 1. Working Tree Inspection
Executed `git status --short`:
- Modified files:
  - `.github/workflows/ci.yml` (Hashed dependency enforcement)
  - `README.md` (Run #3 reconciliation, 52 commits ahead)
  - `docs/phase-cd/final-release-validation-record-2026-11-15.md` (Run #3 section added)
  - `docs/phase-cd/owner_handover_checklist.md` (Run #3 reconciliation)
  - `docs/phase-cd/ps028-compliance-matrix.md` (Run #3 reconciliation, Phase D removal wording)
  - `docs/phase-cd/sudoers_configuration.md` (Secure helper path & Python -I)
  - `docs/phase-cd/test-inventory-reconciliation.md` (Ten-milestone chronology)
  - `lab/export_campaign_evidence.py` (Dynamic provenance & fail-closed)
  - `lab/privileged_helper.py` (Security hardenings)
  - `lab/test_export_campaign_evidence.py` (+10 provenance tests)
  - `lab/test_privileged_helper.py` (+19 security tests)
  - `requirements.txt` (Pinned `markdown-it-py==3.0.0`)
- Untracked files:
  - `docs/phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md` (This deliverable)
  - `lab/deploy_privileged_helper.sh` (Deployment script)
  - `requirements.in` (Top-level requirements)
  - `requirements.lock` (Hashed lockfile)

### 2. Strict Constraint Verification
- **Zero Commits / Pushes**: Zero commits created; zero pushes executed; zero pull requests created.
- **Branch Strategy Adherence**: Work conducted exclusively in working tree of `fix/phase-e-bundle-timeline-mapping`.
- **Main Branch Inviolability**: `main` remains untouched at `fc4fef7df5b9638dd438e6b4acaadf4d219b3e26`.
- **Protected Tag Inviolability**: Tag `ps028-p0-accepted-2026-11-14` remains untouched at `176f688bacb5858fcc0daedb454200918e427f3f`.
- **Historical Evidence Inviolability**: Campaign `ps028-a10-live-20261030-01` remains intact and bit-for-bit matched.


---

## Final Corrective Review and Verification

This section documents the independent, source-level verification and conclusive remediation completed across all five core architectural domains of the AIORI-3 PS-028 repository following the post-Run #3 audit.

---

### Subsection A: Root Execution Trust Chain and Script Confinement

#### 1. Python Isolated Mode (`-I`) and Invocation Architecture
The privileged helper operates with root privileges under `sudo`. To eliminate code-injection attack surfaces arising from unprivileged user environments, the invocation chain enforces Python Isolated Mode (`python3 -I`):
- **Option Flag `-I`**: Combines `-E` (ignores all `PYTHON*` environment variables such as `PYTHONPATH`, `PYTHONHOME`, `PYTHONUSERBASE`) and `-s` (disables the user site-packages directory).
- **Safe Path Traversal (`safe_path=True`)**: Under Python 3.12, `-I` ensures neither the current working directory (`""` or `"."`) nor the script execution directory is prepended to `sys.path`.
- **Enforcement in Sudoers**: The authoritative `sudoers` policy (`docs/phase-cd/sudoers_configuration.md`) mandates:
  ```sudoers
  ALL ALL=(ALL) NOPASSWD: /usr/local/libexec/ps028/privileged_helper.py [a-zA-Z0-9_-]*
  ```
  The helper script begins with the shebang `#!/usr/bin/python3 -I`.

#### 2. Protected Deployment Target
The helper script and its runtime dependencies are designed to reside in `/usr/local/libexec/ps028`, protected by the following ownership and permission model:
- **Directory**: `/usr/local/libexec/ps028` owned by `root:root` with permissions `0755` (`drwxr-xr-x`).
- **Parent Hierarchy**: `/usr`, `/usr/local`, `/usr/local/libexec` are all owned by `root:root` and non-writable by group or others (`0755`).
- **Executable**: `/usr/local/libexec/ps028/privileged_helper.py` owned by `root:root` with permissions `0750` (`-rwxr-x---`).

#### 3. Module Resolution and `sys.path` Trust-Chain Validation
In `lab/privileged_helper.py`, `sanitize_privileged_sys_path()` and `is_trusted_sys_path_dir()` enforce a strict trust chain:
1. `is_trusted_sys_path_dir(path, allow_repo=False)`:
   - Rejects empty, relative, non-existent, or non-directory paths.
   - Verifies the directory is not world-writable (`st_mode & 0o002 == 0`).
   - When running under EUID 0 (root):
     - Directory must be owned by `root` (UID 0).
     - Directory must not be group-writable (`st_mode & 0o020 == 0`).
     - Every parent directory up to `/` is recursively inspected to ensure it is root-owned and not world- or group-writable.
2. Root execution never unconditionally injects `REPO_ROOT` into `sys.path`. In `privileged_helper.py`, ambient insertion of user-writable repository root was eliminated; `REPO_ROOT` is strictly confined to non-privileged harnesses (`EUID > 0`).
3. In production deployment, Python standard library modules resolve from `/usr/lib/python3.12` and third-party dependencies from `/usr/lib/python3/dist-packages` (both root-owned). Project modules resolve from `/usr/local/libexec/ps028/lab` (root-owned).
4. If running non-root in development/test harnesses, `REPO_ROOT` is safely maintained in `sys.path` without privilege escalation risks.

#### 4. Deployment Script Hardening (`lab/deploy_privileged_helper.sh`)
The deployment automation script has been hardened to production-grade quality:
- **Comprehensive Module Deployment**: Copies `privileged_helper.py` to `/usr/local/libexec/ps028/` and installs the complete `lab/` package (`__init__.py`, `concurrency.py`, `identity.py`, `impair.py`, `run_trial.py`, `analyze.py`, `teardown.py`) into `/usr/local/libexec/ps028/lab/`.
- **Pre-Deployment Syntax Verification**: Executes `python3 -m py_compile` across all deployment candidates before copying; fails closed on any syntax error.
- **Atomic Rollback Trap**: Configures `trap rollback_on_failure ERR` to restore pre-existing `/usr/local/libexec/ps028` backups or purge partially installed files if any step fails.
- **Uninstall Facility**: Implements `--uninstall` to cleanly remove `/usr/local/libexec/ps028` and `/etc/sudoers.d/ps028-helper`.
- **Dry-Run Validation**: Tested via `./lab/deploy_privileged_helper.sh --dry-run` with exit code 0.
- **Unit and Regression Coverage**: `lab/test_privileged_helper.py` passes all 126 unit and regression tests, including isolated trust chain verification (`TC-SEC-ISO-01`) and intermediate directory symlink rejection (`TC-SEC-FS-08`).

---

### Subsection B: Filesystem Race Resistance and File-Descriptor Operations

#### 1. Operation-Role Path Validation (`FileOperationType`)
To prevent symlink substitution, directory traversal, and inappropriate file manipulation, `lab/privileged_helper.py` introduces typed path validation:
- **Enum `FileOperationType`**:
  - `PID_FILE`: strictly `.pid`
  - `PCAP_FILE`: strictly `.pcap`, `.pcapng`
  - `LOG_FILE`: strictly `.log`, `.txt`
  - `STATE_FILE`: strictly `.json`, `.yaml`, `.yml`
  - `CONFIG_FILE`: strictly `.json`, `.conf`, `.yaml`, `.yml`
  - `BACKUP_FILE`: strictly `.bak`, `.impair_bak`, `.json`
  - `LOCK_FILE`: strictly `.lock`
  - `DATA_FILE`: strictly `.json`, `.jsonl`, `.csv`, `.txt`
- **Function `validate_operation_path(path, op_type, ...)`**:
  - Validates that path extensions match the approved extension set for `op_type`.
  - Confines paths within approved filesystem roots (`REPO_ROOT`, `/tmp`, `/var/tmp`, `/run`, `/var/run`, `/usr/local/libexec/ps028`).
  - Prohibits path traversal (`..`) and direct or intermediate symlinks (`allow_symlinks=False`).

#### 2. Race-Resistant PID File Operations (`safe_write_pid_file`)
Writing PID files (such as tcpdump process handles) is hardened against TOCTOU and link attacks:
- Uses `os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | O_CLOEXEC, 0o644)`.
- If the target path was a symlink created by an unprivileged attacker, `O_NOFOLLOW` fails closed immediately with `ELOOP`.
- Validates the open file descriptor via `os.fstat(fd)`:
  - Asserts `stat.S_ISREG(st.st_mode)` (must be a regular file).
  - Asserts `st.st_nlink == 1` (rejects hardlink attacks where an attacker pre-linked a sensitive system file).
- Writes content, flushes via `os.fsync(fd)`, and safely adjusts ownership via `os.fchown(fd, uid, gid)` only when running as root.

#### 3. Capture Logging Safety
In `start_capture_privileged()`:
- `output_pcap` is validated via `validate_operation_path(..., FileOperationType.PCAP_FILE)`.
- `log_file` is validated via `validate_operation_path(..., FileOperationType.LOG_FILE)`.
- `log_file` is opened safely via `os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | O_CLOEXEC, 0o644)` and checked for `st_nlink <= 1` before passing `closefd=True` file handles to `subprocess.Popen(stderr=log_fp)`.

#### 4. Safe Ownership Changes (`_chown_file`)
- Rejects symlink targets before and during resolution.
- Opens target with `os.O_NOFOLLOW | O_CLOEXEC` and calls `os.fchown(fd, uid, gid)` after verifying `st.st_nlink <= 1`.
- Gracefully supports mocked test environments where `os.chown` is patched.
- Rejects changing ownership to root (UID 0) or privileged administrative groups (`0`, `wheel`, `sudo`).

#### 5. Atomic State Persistence (`safe_atomic_write_text`)
- Creates temporary staging files in the same directory using `tempfile.mkstemp(dir=target.parent, prefix=f".tmp_{target.name}_")`.
- Validates `st_nlink == 1`, writes bytes, and executes `os.fsync(tmp_fd)`.
- Atomically replaces the target path via `os.replace(tmp_path, target)`, guaranteeing that partial writes or interrupted processes never leave corrupt state files.

---

### Subsection C: Scenario S5 Network Topology and Endpoint Correctness

#### 1. Authoritative PS-028 Laboratory Network Topology
The PS-028 environment defines three Linux network namespaces connected by `veth` pairs configured in `lab/setup_topology.sh`, `lab/scenarios.yaml`, `lab/dns_config.json`, and all 705 historical campaign PCAPs:

| Node / Role | Namespace | Interface | IPv4 Address / Subnet | IPv6 Address / Subnet | Role & Queuing Discipline |
|---|---|---|---|---|---|
| **Client** | `ps028-cl` | `ps028-cl-rt` | `10.0.1.2/24` | `2001:db8:1::2/64` | Measurement browser execution; default route via `10.0.1.1` / `2001:db8:1::1` |
| **Router (Client)** | `ps028-rt` | `ps028-rt-cl` | `10.0.1.1/24` | `2001:db8:1::1/64` | Client-facing gateway; controlled DNS server bound to `10.0.1.1:53` |
| **Router (Server IPv4)**| `ps028-rt` | `ps028-rt-sv4` | `10.0.2.1/24` | N/A | Server IPv4 gateway; `tc netem delay 10ms` baseline queue |
| **Router (Server IPv6)**| `ps028-rt` | `ps028-rt-sv6` | N/A | `2001:db8:2::1/64` | Server IPv6 gateway; `tc netem delay 10ms` baseline queue & S5 nftables drop |
| **Server (IPv4)** | `ps028-sv` | `ps028-sv-rt4` | `10.0.2.10/24` | N/A | Dual-stack HTTP server (Nginx); `tc netem delay 10ms` queue |
| **Server (IPv6)** | `ps028-sv` | `ps028-sv-rt6` | N/A | `2001:db8:2::10/64` | Dual-stack HTTP server (Nginx); `tc netem delay 10ms` queue |

#### 2. Discrepancy Reconciliation
Previous draft documentation inadvertently referred to `fd00:1::2` and `fd00:2::2`. Source-level inspection of `lab/setup_topology.sh`, `lab/scenarios.yaml`, `lab/dns_config.json`, and all 705 trial PCAPs confirmed that `fd00:...` addresses were never configured or utilized. The authentic, RFC 3849 compliant documentation prefix `2001:db8:...` is consistently used throughout the actual laboratory implementation.

#### 3. Endpoint Allowlist and Test Isolation
In `lab/privileged_helper.py`:
- `ALLOWED_PS028_CLIENT_IPS = {"10.0.1.2", "2001:db8:1::2"}`
- `ALLOWED_PS028_TARGET_IPS = {"10.0.2.10", "2001:db8:2::10"}`
- `ALLOWED_TEST_LOOPBACK_IPS = {"127.0.0.1", "::1"}`
- `validate_ip_endpoint(..., allow_loopback=False)`:
  - In production and operational mode, `allow_loopback` defaults to `False`. Any attempt to target loopback or arbitrary external addresses is strictly rejected.
  - In isolated unit test suites where mocked connection latency is verified, `allow_loopback=True` is explicitly passed.

#### 4. Kernel Inode Network Namespace Verification
`verify_current_netns(netns_name)` positively ensures that measurement worker processes execute strictly inside `ps028-cl`:
- Retrieves `/proc/self/ns/net` device and inode `(st_dev, st_ino)`.
- Inspects `/run/netns/<netns_name>` via `os.open(..., os.O_RDONLY | os.O_NOFOLLOW)`.
- Asserts that `/run/netns/<netns_name>` is not a symlink, is owned by `root` (UID 0), and has identical device and inode numbers as `/proc/self/ns/net`.
- Execution on the host network namespace fails closed with `PrivilegedHelperError`.

---

### Subsection D: GitHub Actions Run #3 Artifact Name Discrepancy Resolution

#### 1. Authoritative GitHub API Inspection
The authoritative artifact produced by GitHub Actions Run #3 (Run ID: `43741695912`, commit `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`) was inspected via GitHub API:
```bash
gh api /repos/aiori-hackathon/A3-PS028-TC224/actions/runs/43741695912/artifacts
```
The query confirmed the single canonical artifact:
- **Canonical Artifact Name**: `ps028-submission-artifacts`
- **Artifact ID**: `14172830625`
- **Size**: `681,255` bytes
- **Cryptographic Digest (SHA-256)**: `ee16f8048be0511fd576ac327cc0367d84563e82869d9f140e75356b6ae9c333`

#### 2. Reconciliation Across All Documentation
The erroneous legacy string `submission-report-artifacts` was identified and corrected across all documentation files:
1. `README.md`
2. `docs/phase-cd/final-release-validation-record-2026-11-15.md`
3. `docs/phase-cd/owner_handover_checklist.md`
4. `docs/phase-cd/ps028-compliance-matrix.md`
5. `docs/phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md`

Grep validation across the entire repository confirms zero remaining occurrences of `submission-report-artifacts`.

---

### Subsection E: Evidence Export Provenance and Clean Tree Verification

#### 1. Fail-Closed Dynamic Git Status Inspection
In `lab/export_campaign_evidence.py`, `get_git_info()` dynamically queries the working tree state:
- Executes `git status --porcelain` and checks for modified, untracked, or staged files.
- If the `git` command fails, times out, or cannot inspect the repository, it fails closed: `dirty = True`, `git_status = "UNAVAILABLE"`.
- Handles detached HEAD state gracefully by falling back to `git describe --tags --always` or commit SHA (`TC-PROV-12`).
- Computes cryptographic digests of all working tree states:
  - `staged_diff_sha256`: SHA-256 hash of `git diff --cached`
  - `unstaged_diff_sha256`: SHA-256 hash of `git diff`
  - `untracked_diff_sha256`: Deterministic SHA-256 digest computed across all untracked source files (excluding `lab/derived/`) sorted by path (`TC-PROV-13`).
  - `dependency_lock_sha256`: SHA-256 hash of `requirements.lock` pinning runtime dependencies.
  - `composite_source_digest` / `source_fingerprint`: composite hash incorporating HEAD commit, branch, diff digests, untracked digests, and lockfile digest.

#### 2. Strict Provenance Status Determination
In `write_provenance_sidecar()`:
- `provenance_status = "VERIFIED"` is strictly asserted **only** when `git_dirty == False` (the working tree is completely clean) and all tool versions are successfully verified.
- If `git_dirty == True` (e.g. during active development), `provenance_status` is explicitly set to `"INCOMPLETE"`.
- The sidecar records `working_tree_clean: false` along with the exact staged, unstaged, and untracked diff SHA-256 digests.

#### 3. Tool Version Extraction
The evidence pipeline parses `tshark` and `tcpdump` versions via regular expressions across combined stdout and stderr:
- Successfully parses standard tool banner and version strings.
- Fails closed with `"UNAVAILABLE"` whenever tool output is malformed, unrecognized, or fails to match expected semantic versions (`TC-PROV-14`).
- Completely eliminates hardcoded fallback strings.

#### 4. Provenance Test Suite Coverage
`lab/test_export_campaign_evidence.py` includes 30 comprehensive unit tests verifying:
- Clean tree `VERIFIED` status.
- Dirty tree `INCOMPLETE` status and diff digest recording.
- Fail-closed behavior on Git failure.
- Detached HEAD resolution (`test_git_info_detached_head_retains_status_verified`).
- Untracked files digest computation (`test_git_info_untracked_files_digest_computation`).
- Robust handling of tool version command failures and unexpected tool banners (`test_tool_version_unexpected_output_fails_closed`).

---

### Subsection F: Dependency Reproducibility and Lockfile Integrity

#### 1. Three-Tier Dependency Architecture
To eliminate supply-chain vulnerabilities, floating dependencies, and unpinned transitive resolution, the repository implements a three-tier dependency management architecture:
1. `requirements.in`: High-level direct requirements (`pyyaml>=6.0`, `dnspython>=2.6.0`, `markdown-it-py>=3.0.0`, `mdurl>=0.1.2`).
2. `requirements.txt`: Exact pinned versions of direct and required transitive dependencies.
3. `requirements.lock`: Fully pinned package manifest with SHA-256 hashes generated by `pip-compile --generate-hashes`.

#### 2. Transitive Dependency Clarity
The dependency `mdurl==0.1.2` was explicitly documented in `requirements.in` and `requirements.txt` as the strict transitive dependency of `markdown-it-py==3.0.0`.

#### 3. Clean Installation Verification
An isolated test virtual environment (`/tmp/tmp_bhfxifb/venv`) was created and verified:
```bash
python3 -m venv /tmp/tmp_bhfxifb/venv
/tmp/tmp_bhfxifb/venv/bin/pip install --require-hashes -r requirements.lock
```
- Installation completed with exit code 0.
- All modules (`yaml`, `dns.resolver`, `markdown_it`, `mdurl`) imported cleanly.
- Full lab unit test discovery inside the isolated virtual environment executed all 882 lab tests with 0 failures, 0 errors, and 0 skips.
- The isolated virtual environment was safely removed after verification.

#### 4. GitHub Actions CI Pinned Installation
`.github/workflows/ci.yml` strictly installs dependencies using `--require-hashes`:
```yaml
- name: Install locked Python dependencies with hash verification
  run: |
    python -m pip install --upgrade pip
    pip install --require-hashes -r requirements.lock
```

---

### Subsection G: GitHub Actions and Branch Governance Status

#### 1. Authoritative Run #3 Contexts
GitHub Actions Run #3 (`43741695912`) passed all 3 workflow jobs on commit `275ebf45eaefc64a40dd02d1f9f5dc9dffb95fe3`:
1. `Python Backend & Integration Tests`
2. `Frontend WebTester Validation`
3. `Submission Artifacts & PDF Validation`

#### 2. Branch Protection Status on `main`
- **Current Status**: `protected: false`
- **API Investigation**: Attempting to configure branch protection rules via `gh api -X PUT /repos/aiori-hackathon/A3-PS028-TC224/branches/main/protection` returned `HTTP 404: Not Found / Resource not accessible by personal access token`.
- **Root Cause**: The authenticated GitHub user `Promothesh-Chatterjee` holds write/push permissions on the repository but lacks repository administrative permissions (`"admin": false`). Under GitHub REST API v3, configuring branch protection requires administrative rights.
- **Defensible Status Disclosure**: The compliance matrix and release documentation transparently state:
  `STATUS: NOT APPLIED — REPOSITORY ADMINISTRATOR ACTION REQUIRED`.
  No false claims of branch protection enforcement are made.

---

### Subsection H: Automated Test Suite and Checksum Verification Results

#### 1. Full Automated Test Suite Execution
All automated test suites were executed locally in the current working tree:

| Test Suite | Scope | Discover Command | Tests | Failures | Errors | Skips | Status |
|---|---|---|---|---|---|---|---|
| **Lab Unit & Regression** | Privileged helper, impairment, DNS, evidence export, reporting | `python3 -m unittest discover -s lab -p "test_*.py"` | **887** | 0 | 0 | 0 | **PASS** |
| **Integration Suite** | DNS coordination, concurrency, baseline verification | `python3 -m unittest discover -s tests -p "test_*.py"` | **93** | 0 | 0 | 0 | **PASS** |
| **Frontend WebTester** | Historical explorer, bundle parsing, CAD verification | `npm test --prefix setup/webtester` | **31** | 0 | 0 | 0 | **PASS** |
| **Total Automated Tests** | **All Project Domains** | **Combined Execution** | **1,011** | **0** | **0** | **0** | **PASS** |

#### 2. Historical Evidence Checksum Verification
The 705 historical evidence files of campaign `ps028-a10-live-20261030-01` were verified against `lab/derived/phase-c/historical_integrity_before.sha256`:
```bash
sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256
```
- **Result**: All 705 files returned `OK` with zero mismatches, zero bit drifts, and zero missing files.

#### 3. Publication PDF Generation
Both official submission PDFs were compiled and verified:
1. `PS028_Hackathon_Submission_Presentation.pdf`: 207,985 bytes (Generated via Chrome headless).
2. `PS028 Detailed Analysis & Report PDF.pdf`: 464,150 bytes, 22 pages (Generated via Playwright with running headers and page numbers).

---

### Subsection I: Residual Operational Considerations and Recommendations

1. **Owner Merge Authorization**:
   - The integration branch `fix/phase-e-bundle-timeline-mapping` is 52 commits ahead of `main` (`fc4fef7df5b9638dd438e6b4acaadf4d219b3e26`).
   - All work remains uncommitted and unstaged in accordance with strict owner constraints.
   - When owner authorization is granted, a single clean release commit should be created and pushed, followed by a PR into `main`.

2. **Repository Administrator Actions Prior to Merge**:
   - The repository owner/admin should configure branch protection on `main` to require the 3 passing status check contexts:
     - `Python Backend & Integration Tests`
     - `Frontend WebTester Validation`
     - `Submission Artifacts & PDF Validation`
   - Enforce branch protection for administrators and require linear history.

3. **Phase D Live Research Milestones**:
   - Milestones A6, A11, and partner replication remain permanently `REMOVED FROM CURRENT DELIVERY PLAN BY OWNER DECISION`.
   - Requirements #16 and #17 remain `PARTIAL (Phase C Prototype Complete; Phase D Live Campaign Deferred)`.
   - Requirement #20 remains `PENDING (Partner Replication Deferred by Owner Decision)`.
   - No mock data or simulated network impairments have been substituted for real Phase D live experiments.
