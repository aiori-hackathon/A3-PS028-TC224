# Repository-Wide Forensic Audit Register (Amendment A12)

- **Date / Timestamp**: 2026-11-11T18:23:00Z
- **Repository**: `<repo_root>`
- **Work Branch**: `regional/ps028-phase-cd`
- **Base Commit**: `7c6ab23c2a378bbc8556fcc15f5911f626502576`
- **Scope**: Exhaustive read-only forensic audit across all repository assets (DNS responder, web origin, setup/teardown, capture scripts, browser launchers, dependency pinning, `.gitignore`/LFS, licenses, repo hygiene) beyond the 12 core test files.
- **Governing Requirement**: Amendment A12 / Step 0.6

---

## Executive Summary

A repository-wide sweep of all 1,658 files outside `.git/` and `.agents/` was conducted. While the core test suite passes 524 tests and demonstrates strong low-level network namespace engineering, several critical privilege boundaries, configuration hygiene gaps, client DNS confounds, and dependency management omissions were discovered.

Findings are cataloged below ranked strictly by severity:
- **Critical (3 findings)**: Privilege leaks requiring ambient root, fail-open DNS reload handling, and unvalidated string execution.
- **High (4 findings)**: Browser DoH/TRR confounds, missing root dependency specifications, missing Git LFS tracking for multi-megabyte binaries, and absent evidence exporters.
- **Medium (4 findings)**: Incomplete `.gitignore` patterns, documentation drift and broken links, dual/conflicting licensing, and hardcoded topology IP addresses.
- **Low (3 findings)**: Untracked test harness artifacts, dead upstream Ansible playbooks, and placeholder directories.

---

## Forensic Findings Register

### 1. Critical Severity

#### Finding A12-CRIT-01: Direct `require_root()` Invocations in Unprivileged Test Harness
- **Location**: `lab/self_test_scenarios.py:323, 530`, `lab/impair.py:639, 691`
- **Description**:
  Unprivileged harness and self-test flows directly invoke `impair.require_root()`. If executed by an unprivileged user, execution halts with `SystemExit(1)`. This forces operators to execute the entire Python harness under `sudo` (e.g. `sudo python3 lab/run_trial.py`), which unnecessarily executes browser binaries and PCAP post-processors with root privileges.
- **Impact**: Violates non-interactive privilege separation and the principle of least privilege.
- **Remediation**: Remove direct `require_root()` checks from unprivileged orchestration scripts. Delegate all kernel-level impairment and counter actions to `lab/privileged_helper.py` via strictly bounded CLI commands.

#### Finding A12-CRIT-02: Fail-Open DNS Configuration Reload Protocol
- **Location**: `lab/impair.py:461–463, 478–479`
- **Description**:
  In `reload_dns_server()`, if `dns.pid` is missing or unreadable, the function logs a warning and returns `None` without raising an exception. If inspecting `/proc/{pid}/cmdline` encounters a `PermissionError`, it silently executes `pass`. There is no confirmation readback from `dns.log` verifying that `dns_server.py` received `SIGHUP` and successfully applied the new rules, nor is there an active query timing check before admitting trials.
- **Impact**: If the DNS server process has crashed, become unresponsive, or rejected malformed JSON, subsequent trials proceed under a corrupted or stale DNS state without failing closed.
- **Remediation**: Enforce fail-closed reload: verify process existence and cmdline, deliver `SIGHUP`, read back `dns.log` confirmation, and perform an active DNS query timing check within pre-declared tolerance (±25ms) before admitting trials.

#### Finding A12-CRIT-03: Unvalidated Multiline Python Script Injection into Namespace
- **Location**: `lab/self_test_scenarios.py:438–510` (`build_s5_probe_script`)
- **Description**:
  In `self_test_scenarios.py`, the S5 probe routine constructs an inline Python script as a raw multiline format string and passes it into the network namespace via `subprocess.run(["python3", "-c", py_script, ...])`.
- **Impact**: Violates the non-negotiable architectural constraint prohibiting shell string interpolation and arbitrary code execution across namespace boundaries.
- **Remediation**: Replace inline script execution with a dedicated, allowlisted subcommand in `privileged_helper.py` (`measure-s5`) that takes integer bounds and emits structured JSONL probe records.

---

### 2. High Severity

#### Finding A12-HIGH-01: Client DNS Confounds (Missing DoH / TRR Disabling)
- **Location**: `lab/run_trial.py:2965–2987, 3170–3179`
- **Description**:
  In `run_trial.py`, Firefox profiles configure several `user_pref` options in `user.js`, but fail to set `user_pref("network.trr.mode", 5)` (which strictly disables Trusted Recursive Resolver / DNS-over-HTTPS). Similarly, Google Chrome command-line arguments include `--disable-features=OptimizationHints,Translate`, but omit `--disable-features=DnsOverHttps` or `--dns-over-https-mode=off`.
- **Impact**: Modern browser builds may attempt opportunistic DoH or bootstrap secure DNS lookups, bypassing the controlled local DNS responder on `10.0.1.1:53` and corrupting Resolution Delay measurements (Scenario S6 and Phase D sweeps).
- **Remediation**: Explicitly set `network.trr.mode = 5` in Firefox `user.js` and pass `--disable-features=DnsOverHttps` to Google Chrome.

#### Finding A12-HIGH-02: Missing Root Dependency Specification and Version Pinning
- **Location**: Repository root (`<repo_root>/`)
- **Description**:
  There is no `requirements.txt`, `pyproject.toml`, `Pipfile`, or `setup.py` at the project root. While `setup/roles/dns-setup/files/dns/build/requirements.txt` specifies unpinned ranges (`dnslib >= 0.9.23`, `requests >= 2.32.0`), the root environment relies on ambient system Python packages (`python3-dnspython 2.6.1-1ubuntu1`, `python3-yaml`).
- **Impact**: Fails AIORI-3 one-command clean reproduction requirements; clean clones on external machines cannot deterministically establish identical toolchains.
- **Remediation**: Create a pinned root `requirements.txt` documenting exact package versions used during baseline validation.

#### Finding A12-HIGH-03: Direct Git Tracking of Multi-Megabyte Binaries Without Git LFS
- **Location**:
  - `lab/campaigns/ps028-a10-live-20261030-01/ps028_complete_evidence_bundle.tar.gz` (16 MB)
  - `lab/campaigns/ps028-a10-live-20261030-01/campaign_manifest.json` (1.2 MB)
  - `PS028 Detailed Analysis & Report PDF.pdf` (967 KB)
  - `lab/campaigns/ps028-a10-live-20261030-01/ps028_portable_data_bundle.zip` (611 KB)
- **Description**:
  Large archives and compiled PDFs are committed directly as regular Git objects without Git LFS. Git LFS is not configured in `.gitattributes` or installed on the system PATH.
- **Impact**: Bloats repository clone size; violates AIORI hygiene best practices and Rule R10.
- **Remediation**: Document binary management in reproduction runbook; configure `.gitattributes` for LFS tracking if required by submission infrastructure.

#### Finding A12-HIGH-04: Absence of Deterministic Evidence Exporters
- **Location**: `lab/export_campaign_evidence.py` (missing)
- **Description**:
  The authoritative October 29 campaign contains 280 valid live trials and 2 cleanup failures (282 total attempts), but the repository lacks `export_campaign_evidence.py` to produce deterministic, byte-identical exports: `attempts.csv` (282 rows), `connection_attempts.csv` (per-TCP-flow), and `trial_timeline.csv` (combined packet and harness timeline).
- **Impact**: PS-028 compliance requires packet-level evidence validation and timeline exports.
- **Remediation**: Implement `lab/export_campaign_evidence.py` in Milestone 3 adhering to deterministic formatting rules (Amendment A13).

---

### 3. Medium Severity

#### Finding A12-MED-01: Incomplete `.gitignore` Rules
- **Location**: `.gitignore:1–23`
- **Description**:
  `.gitignore` explicitly ignores `lab/__pycache__/`, but lacks global rules for `**/__pycache__/`, `*.pyc`, `*.pyo`, `.pytest_cache/`, and `.coverage`. Consequently, bytecode files generated under `tests/` (`tests/__pycache__/`) appear as untracked files in git.
- **Impact**: Dirty working tree and risk of accidental commits containing binary bytecode.
- **Remediation**: Add standard Python ignore patterns (`__pycache__/`, `*.py[cod]`, `*.so`, `.coverage`, `.cache/`).

#### Finding A12-MED-02: Stale Test Counts and Broken Documentation Links
- **Location**: `README.md:9, 11, 201, 205`, `docs/PS028_REPRODUCIBILITY_RUNBOOK.md:218`
- **Description**:
  - `README.md:9` has malformed nested markdown brackets: `[`PS028 Detailed Analysis & Report PDF.pdf`]([PS028 Detailed Analysis & Report PDF.pdf](https://...))`.
  - `README.md:201` states "the recorded suite reports 400 tests", while the baseline test suite has 524 tests.
  - `README.md:205` links to `docs/PS028_Final_Experimental_Report.pdf`, which does not exist in `docs/`.
  - `PS028_REPRODUCIBILITY_RUNBOOK.md:218` misattributes RFC 8305 §4 for Resolution Delay instead of Section 3.
- **Impact**: Misleads evaluators, fails automated link checkers, and violates Rule R9.
- **Remediation**: Correct all paths, link formatting, section citations, and replace static test counts with dynamic run logs.

#### Finding A12-MED-03: Dual and Inconsistent Repository Licensing
- **Location**: `LICENSE` (root), `LICENSES/MIT.txt`, `UPSTREAM_README.md:79–84`
- **Description**:
  The project root contains `LICENSE` with the Mozilla Public License 2.0 (MPL-2.0), while `LICENSES/MIT.txt` specifies the MIT License. `UPSTREAM_README.md` clarifies that the core webtester is MPL-2.0 while frontend UI elements are MIT. However, the top-level `README.md` does not explain the license boundaries.
- **Impact**: Legal ambiguity regarding license applicability to newly authored lab measurement modules.
- **Remediation**: Document license scoping clearly in `README.md` and submission metadata.

#### Finding A12-MED-04: Hardcoded Topology Network Addressing
- **Location**: `lab/run_trial.py`, `lab/impair.py`, `lab/dns_server.py`, `lab/self_test_scenarios.py`
- **Description**:
  IPv4 (`10.0.1.1`, `10.0.1.2`, `10.0.2.1`, `10.0.2.10`) and IPv6 (`2001:db8:1::2`, `2001:db8:2::1`, `2001:db8:2::10`) subnets and interfaces are hardcoded across multiple files rather than imported from a single central topology definition.
- **Impact**: Limits portability to alternative network environments or partner testbeds (Phase D5).
- **Remediation**: Centralize topology constants into a shared module (`lab/topology.py` or `lab/identity.py`).

---

### 4. Low Severity

#### Finding A12-LOW-01: Untracked Test Suite and Test Infrastructure Documentation
- **Location**: `tests/`, `TEST_INFRA.md`
- **Description**:
  The top-level `tests/` directory (containing 67 synthetic tier tests) and `TEST_INFRA.md` exist on disk but are not tracked in git on `regional/p0-remediation`.
- **Impact**: Divergence between local workspace and remote tracking branch.
- **Remediation**: Track and integrate `tests/` into continuous offline test execution.

#### Finding A12-LOW-02: Legacy Upstream Ansible Playbooks
- **Location**: `setup/` (139 files)
- **Description**:
  `setup/` contains extensive Ansible roles for Caddy, Docker, and Bind9 inherited from the upstream "Lazy Eye Inspection" server deployment. The PS-028 lab runs locally within Linux network namespaces (`ps028-cl`, `ps028-rt`, `ps028-sv`) using native Python servers, making most Ansible tasks inactive.
- **Impact**: Adds maintenance overhead and clutter to the repository.
- **Remediation**: Clearly document `setup/` as legacy upstream deployment assets in the repository layout.

#### Finding A12-LOW-03: Placeholder Directory at Project Root
- **Location**: `src/README.md`
- **Description**:
  `src/` contains only a 2-line placeholder `README.md`. All actual implementation code resides in `lab/`.
- **Impact**: Minor layout redundancy.
- **Remediation**: Document `lab/` as the canonical implementation directory in `PROJECT.md`.

---

## Action Plan and Milestone Mapping

| Severity | Finding ID | Summary | Target Milestone |
|---|---|---|:---:|
| **Critical** | A12-CRIT-01 | Unprivileged harness root calls | M4 (WP C5) |
| **Critical** | A12-CRIT-02 | Fail-open DNS reload handling | M4 (WP C5) |
| **Critical** | A12-CRIT-03 | Inline python string execution | M4 (WP C5) |
| **High** | A12-HIGH-01 | Browser DoH/TRR confounds | M4 (WP C5) & M6 (Phase D) |
| **High** | A12-HIGH-02 | Root dependency pinning | M7 (WP E4/E5) |
| **High** | A12-HIGH-03 | Git LFS & binary management | M7 (WP E4/E5) |
| **High** | A12-HIGH-04 | Missing evidence exporters | M3 (WP C2) |
| **Medium** | A12-MED-01 | `.gitignore` rule gaps | M7 (WP E4/E5) |
| **Medium** | A12-MED-02 | Documentation drift & broken links | M5 (WP C6) |
| **Medium** | A12-MED-03 | Licensing clarification | M5 (WP C6) |
| **Medium** | A12-MED-04 | Hardcoded topology addresses | M4 (WP C5) |
| **Low** | A12-LOW-01 | Untracked test harness files | M7 (WP E4/E5) |
| **Low** | A12-LOW-02 | Legacy Ansible documentation | M5 (WP C6) |
| **Low** | A12-LOW-03 | Directory structure documentation | M1 (PROJECT.md) |
