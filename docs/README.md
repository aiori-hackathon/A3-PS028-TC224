# PS-028 Happy Eyeballs Documentation Index

**Team AlgoRhythm** · **AIORI Hackathon 3** · **PS-028: Internet Measurement**

This directory contains the complete technical, scientific, operational, and historical documentation for the PS-028 Happy Eyeballs IPv4/IPv6 Fallback Measurement project.

---

## Documentation Categories

```
docs/
├── Operational & Scientific Documentation (Current Authoritative Guides)
├── Architecture & Verification Specifications
├── Historical Audit Snapshots & Evolution Records (Archival Milestones)
└── Upstream Documentation References
```

---

## 1. Current Operational & Scientific Documentation

These documents represent the active, authoritative technical specifications and procedures for reproducing, understanding, and evaluating the project.

| Document | Purpose & Description |
|---|---|
| [`../README.md`](../README.md) | **Authoritative Judge-Facing Repository Entry Point**: Complete project overview, executive summary, empirical results, architecture diagram, route inventory, reproducibility commands, CI status, and submission resources. |
| [`PS028_FINAL_EXPERIMENTAL_REPORT.md`](./PS028_FINAL_EXPERIMENTAL_REPORT.md) | **Official Technical Report (Source)**: Complete 22-page scientific publication manuscript detailing motivation, methodology, network-namespace testbed, raw-PCAP primary-flow timing, empirical results across S0–S6, RFC 8305 assessment, and threats to validity. Compiles to [`../PS028 Detailed Analysis & Report PDF.pdf`](../PS028%20Detailed%20Analysis%20%26%20Report%20PDF.pdf). |
| [`PS028_REPRODUCIBILITY_RUNBOOK.md`](./PS028_REPRODUCIBILITY_RUNBOOK.md) | **Laboratory Reproducibility Runbook**: Step-by-step instructions for preflight checks, baseline self-tests, safe trial orchestration, unprivileged helper execution, statistical analyzer CLI (`lab/analyze.py`), checksum verification, and test execution. |
| [`phase-cd/ps028-compliance-matrix.md`](./phase-cd/ps028-compliance-matrix.md) | **Problem Statement Compliance Matrix**: Granular audit mapping each PS-028 requirement and active amendment to implemented code, empirical artifacts, and verification evidence (17/18 MET, 1 PENDING external partner execution). |
| [`phase-e/README.md`](./phase-e/README.md) | **Demonstration Data & Evidence Explorer Guide**: Specifications for the pre-compiled historical demonstration bundle (`lab/derived/phase-e/demo_bundle.json`), SHA-256 provenance verification sidecar, CLI replay utility (`lab/demo_replay.py`), and frontend data ingestion pipeline. |
| [`../setup/webtester/README.md`](../setup/webtester/README.md) | **WebTester Frontend Application Guide**: Development, build, testing, and architecture manual for the Astro v5 / React 19 web application, including route map, smoke tests, and Playwright browser acceptance tests. |
| [`phase-c-metric-contract.md`](./phase-c-metric-contract.md) | **Phase C Metric & Schema Contract**: Binding definitions of primary handshake completion time ($t_{\text{connect\_ms}}$), total setup time ($t_{\text{setup\_total\_ms}}$), DNS transaction fields, and Result Schema 1.1.0. |
| [`phase-cd/glossary.md`](./phase-cd/glossary.md) | **Normative Terminology Glossary**: Definitions of attempt, connection attempt, probe, TCP stream, Connection Attempt Delay (CAD), Resolution Delay, and primary navigation flow. |

---

## 2. Historical Records, Progress Trackers & Audit Snapshots

> [!IMPORTANT]
> **Archival Notice**:
> The documents listed below are **historical records and dated verification snapshots**. They capture point-in-time milestones, branch positions, and forensic audit findings during earlier development phases (e.g., initial 524-test preflight, 818-test Batch C5, 918-test Phase E, 962-test release closure, 966-test remote CI).
>
> They are preserved immutable for complete scientific provenance and auditability. Their contents describe their original recording dates and should not be confused with current repository test totals or branch statuses.

| Document | Milestone Date | Historical Scope |
|---|---|---|
| [`phase-cd/test-inventory-reconciliation.md`](./phase-cd/test-inventory-reconciliation.md) | 2026-11-14 (Updated 2026-11-19) | Complete chronological evolution of test baselines ($524 \to 818 \to 824 \to 918 \to 881 \to 928 \to 929 \to 952 \to 962 \to 966 \to 1380$), plus forensic failure reconciliation of the Task 5C unprivileged execution run. |
| [`phase-cd/repo-audit-register.md`](./phase-cd/repo-audit-register.md) | 2026-11-11 | Comprehensive repository-wide forensic audit register recording 14 initial code, configuration, and documentation findings. |
| [`phase-cd/finding-verification.md`](./phase-cd/finding-verification.md) | 2026-11-11 | Verification of initial audit findings C1-01 through C6-01 against actual codebase implementations. |
| [`phase-cd/baseline.md`](./phase-cd/baseline.md) | 2026-10-29 | Initial environment baseline record and 524-test execution snapshot before Phase C/D refactoring. |
| [`phase-e/demo-readiness-report.md`](./phase-e/demo-readiness-report.md) | 2026-11-12 | Phase E demo-readiness remediation report resolving blockers P0-A through P2-B on 918-test baseline. |
| [`../PROJECT.md`](../PROJECT.md) | 2026-11-11 (Archived) | Historical project roadmap and feature inventory from Phase C/D initiation. |
| [`../PHASE_CD_PROGRESS.md`](../PHASE_CD_PROGRESS.md) | 2026-11-12 (Archived) | Progress tracker documenting completion of Milestones 1–5 and pausing of Phase D live sweeps. |
| [`../TEST_INFRA.md`](../TEST_INFRA.md) | 2026-11-11 | Test infrastructure specification establishing the opaque-box, 4-tier testing methodology for `tests/`. |
| [`../TEST_READY.md`](../TEST_READY.md) | 2026-11-11 / 2026-11-12 | Initial test readiness report validating 67 synthetic tier tests and subsequent expansion to 93 integration tests. |
| [`phase-cd/sudoers_configuration.md`](./phase-cd/sudoers_configuration.md) | 2026-11-12 | Non-interactive sudoers configuration guide for unprivileged helper operations. |
| [`phase-cd/owner_handover_checklist.md`](./phase-cd/owner_handover_checklist.md) | 2026-11-14 | Owner checklist for final repository transfer and artifact publication. |
| [`phase-cd/partner_replication_manifest.json`](./phase-cd/partner_replication_manifest.json) | 2026-11-14 | Machine-readable partner replication matrix manifest for secondary testbed verification. |
| [`phase-cd/partner_replication_runbook.md`](./phase-cd/partner_replication_runbook.md) | 2026-11-14 | Standard Operating Procedure (SOP) for external partner replication testbed execution. |
| [`phase-cd/phase-d-paused.md`](./phase-cd/phase-d-paused.md) | 2026-11-12 | Formal directive pausing live Phase D sweeps to prioritize Phase C empirical evidence and demonstration. |
| [`phase-cd/firefox_comparative_analysis.md`](./phase-cd/firefox_comparative_analysis.md) | 2026-11-12 | Scientific comparative analysis contrasting observed Firefox 159 behaviors with published Firefox 132 literature (Sattler et al.). |
| [`phase-cd/evidence-explorer-architecture-assessment.md`](./phase-cd/evidence-explorer-architecture-assessment.md) | 2026-11-14 | Architectural trade-off analysis evaluating frontend modularization vs regression risk. |
| [`phase-cd/p1-validation-record-2026-11-14.md`](./phase-cd/p1-validation-record-2026-11-14.md) | 2026-11-14 | Historical P1 validation record certifying 929 unique passing automated tests on commit `ee59362ac3f53fad3bc01e65b5d90815697a93d4`. |
| [`phase-cd/final-release-validation-record-2026-11-15.md`](./phase-cd/final-release-validation-record-2026-11-15.md) | 2026-11-15 | Historical release validation certifying 962 automated tests, 16 smoke checks, and 14-stage browser acceptance. |
| [`phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md`](./phase-cd/post-run3-security-and-reproducibility-remediation-2026-11-15.md) | 2026-11-15 | Post-CI Run #3 security hardening record (fail-closed launch identity, subreaper ownership protection). |
| [`phase-cd/final-p1-security-remediation-audit-2026-11-16.md`](./phase-cd/final-p1-security-remediation-audit-2026-11-16.md) | 2026-11-16 | Security audit certifying subprocess isolation, signal safety, and resource cleanups. |
| `phase-cd/gates/` | 2026-11-12 | Gate reports: [`batch_c1.md`](./phase-cd/gates/batch_c1.md), [`batch_c2_c4.md`](./phase-cd/gates/batch_c2_c4.md), [`batch_c5.md`](./phase-cd/gates/batch_c5.md), [`batch_c3_c6.md`](./phase-cd/gates/batch_c3_c6.md). |

---

## 3. Upstream Documentation

| Document | Upstream Project | Description |
|---|---|---|
| [`../UPSTREAM_README.md`](../UPSTREAM_README.md) | [Happy Eyeballs WebTester](https://github.com/happy-eyeballs/he-webtester) ([happy-eyeballs.net](https://www.happy-eyeballs.net)) | Preserved upstream documentation describing the online WebTester tool, multi-IP host setup, and Ansible deployment roles from the original IMC 2025 research project. Distinct from the PS-028 network-namespace measurement lab. |
