# Happy Eyeballs: IPv4/IPv6 Fallback Measurement

**Team AlgoRhythm** · **AIORI Hackathon 3** · **PS-028: Internet Measurement**

[![PS-028 CI](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/aiori-hackathon/A3-PS028-TC224/actions/workflows/ci.yml)
[![Live Demonstration](https://img.shields.io/badge/Demo-ps028--happy--eyeballs.vercel.app-097009?style=flat&logo=vercel)](https://ps028-happy-eyeballs.vercel.app/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-blue.svg)](LICENSE)
[![Frontend UI: MIT](https://img.shields.io/badge/UI_Components-MIT-green.svg)](LICENSES/MIT.txt)

---

## Submission Resources & Quick Links

| Resource | Deliverable | Details |
|---|---|---|
| **Live Interactive Web Application** | [ps028-happy-eyeballs.vercel.app](https://ps028-happy-eyeballs.vercel.app/) | Interactive Historical Evidence Explorer & Scenario Analytics Dashboard |
| **Official GitHub Repository** | [github.com/aiori-hackathon/A3-PS028-TC224](https://github.com/aiori-hackathon/A3-PS028-TC224) | Default branch `main` (commit `c6e561ed`) |
| **Official Technical Report (PDF)** | [`PS028 Detailed Analysis & Report PDF.pdf`](PS028%20Detailed%20Analysis%20%26%20Report%20PDF.pdf) | 22-page publication report with KaTeX math & RFC 8305 assessment |
| **Official Presentation Deck (PDF)** | [`PS028_Hackathon_Submission_Presentation.pdf`](PS028_Hackathon_Submission_Presentation.pdf) | 11-slide Beamer presentation deck matching organizer template |
| **Final Demonstration Video** | [YouTube: Final Project Demonstration](https://youtu.be/LYngp7dzoRI?si=1mPrapHizazV41zB) | Full video demonstration of replay tooling and web dashboard |
| **Team Introduction Video** | [YouTube: Team Introduction](https://youtu.be/5LLxlW9f6r4?si=EQjgtt3bIgkQ4Nix) | Video introduction to Team AlgoRhythm |
| **Campaign Evidence Directory** | [`lab/campaigns/ps028-a10-live-20261030-01/`](lab/campaigns/ps028-a10-live-20261030-01) | 280 valid live PCAPs, JSON logs, NetLog traces, and SHA-256 manifests |
| **Central Documentation Index** | [`docs/README.md`](docs/README.md) | Structured index to all operational, scientific, and historical documents |

---

## Contents

- [A. Project Identity](#a-project-identity)
- [B. Project Overview](#b-project-overview)
- [C. Live Demonstration](#c-live-demonstration)
- [D. Experimental Design](#d-experimental-design)
- [E. Results and Scientific Findings](#e-results-and-scientific-findings)
- [F. Architecture and Instrumentation](#f-architecture-and-instrumentation)
- [G. Frontend Architecture and Routes](#g-frontend-architecture-and-routes)
- [H. Repository Map](#h-repository-map)
- [I. Reproducibility](#i-reproducibility)
- [J. Testing and Continuous Integration](#j-testing-and-continuous-integration)
- [K. Limitations and Threats to Validity](#k-limitations-and-threats-to-validity)
- [L. Submission and Project Resources](#l-submission-and-project-resources)
- [M. Licensing and Upstream Attribution](#m-licensing-and-upstream-attribution)

---

## A. Project Identity

- **Project Title**: Happy Eyeballs — IPv4/IPv6 Fallback Measurement
- **Team**: AlgoRhythm
- **Hackathon**: AIORI Hackathon 3 (AI-Assisted Open Research Initiative)
- **Problem Statement**: PS-028 (Internet Measurement)
- **Repository**: [https://github.com/aiori-hackathon/A3-PS028-TC224](https://github.com/aiori-hackathon/A3-PS028-TC224)
- **Default Branch**: `main` (latest official release revision: commit `c6e561ed11a72682b72973dd829fdc910ee908bc`, merging PR #13 on 18 November 2026)
- **Campaign Identifier**: `ps028-a10-live-20261030-01`
- **Scope**: Empirical measurement, packet-capture correlation, and RFC 8305 standards evaluation of two pinned production browsers (**Google Chrome 156.0.8078.73** and **Mozilla Firefox 159.0**) under controlled dual-stack impairments.

---

## B. Project Overview

### The Dual-Stack Connection Racing Problem
Modern dual-stack hostnames routinely return both IPv4 (A) and IPv6 (AAAA) DNS resource records. While IPv6 is the preferred protocol across standard address selection policies ([RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.html)), real-world IPv6 paths frequently experience routing blackholes, high latency, firewall misconfigurations, or packet loss. A naive client that sequentially attempts an unresponsive IPv6 address before falling back to IPv4 imposes multi-second connection delays on end users.

### What Happy Eyeballs Solves
[Happy Eyeballs Version 2 (RFC 8305)](https://www.rfc-editor.org/rfc/rfc8305.html) specifies an algorithm that coordinates connection attempts across address families without waiting for full transport timeouts. A dual-stack client initiates an attempt to an IPv6 address, waits a bounded interval called the **Connection Attempt Delay (CAD)** (recommended default: 250 ms; recommended minimum: 100 ms; mandatory floor: 10 ms), and then initiates an IPv4 attempt if IPv6 has not yet completed. Whichever address family completes its transport handshake first is selected for application traffic, while redundant in-flight attempts are cleanly terminated.

### Experimental Objective
This project empirical measures how real, unmodified production web browsers implement dual-stack fallback under repeatable, controlled network conditions. We constructed an isolated, three-namespace Linux laboratory to evaluate:
1. Does the browser prefer IPv6 when paths are healthy?
2. Does the browser fall back to IPv4 when IPv6 is impaired?
3. How quickly does fallback occur across blackholes, resets, latency asymmetry, packet loss, and DNS delays?
4. How do observable packet timings align with the normative requirements and recommended parameters of RFC 8305?

> [!IMPORTANT]
> **Measurement Scope**:
> This project measures and analyzes the empirical network behavior of existing browser binaries. The team **did not** implement a new browser networking stack or fork browser source code. All observations reflect authentic client behavior measured from the wire.

### Why Packet-Level Evidence is Essential
Browser-reported JavaScript events (`PerformanceNavigationTiming`) and browser diagnostic logs (`NetLog`, Firefox socket logging) capture internal software states from heterogeneous internal vantage points. They cannot directly measure on-the-wire packet arrival, TCP sequence progression, or operating-system kernel socket behavior.

This project uses full packet captures (`capture.pcap`) recorded at the client-facing network interface (`ps028-cl-rt`) as the **primary ground-truth evidence**. Raw PCAPs are independently parsed, TCP streams are correlated with the primary HTTP `GET /` document request, and browser diagnostic telemetry is retained strictly as secondary supporting context.

---

## C. Live Demonstration

### Deployed Web Application
The project frontend is deployed and publicly accessible at:
👉 **[https://ps028-happy-eyeballs.vercel.app/](https://ps028-happy-eyeballs.vercel.app/)**

### Verified Functionality
The deployed application provides:
1. **Historical Evidence Explorer (`/evidence`)**:
   - Interactive data table inspecting all **280 valid live trials** and **2 excluded attempts** from campaign `ps028-a10-live-20261030-01`.
   - Multi-source chronological event timeline (28,330 synchronized events across `HARNESS`, `PCAP`, and `BROWSER_TELEMETRY`).
   - TCP connection attempt inspector displaying 5-tuple, sequence numbers, stream index, and attempt outcome.
   - Real-time client-side SHA-256 provenance verification using the WebCrypto API.
   - Filterable view isolating excluded cleanup attempts with zero empirical data leakage.
2. **Scenario Analytics Dashboard (`/analytics`)**:
   - Interactive comparative charts across scenarios S0 through S6 and browser implementations (Chrome vs Firefox).
   - Statistical Tukey box plots showing median, IQR, whiskers, and outlier distribution for connection setup times and fallback delays.
   - Address-family winner distributions (direct IPv6 vs IPv4 fallback).
   - Client-side customized PDF report generation (`jspdf`).
3. **Browser-Facing WebTester Tools (`/tests/*`)**:
   - Interactive diagnostic pages testing client browser behavior for Connection Attempt Delay, Resolution Delay, HTTP/3 QUIC capability, and HEv3 protocol racing.

### Critical Operational Boundary Notice
> [!CAUTION]
> **Static Evidence Replay vs. Live Measurement Lab**:
> The public Vercel deployment serves the statically compiled Astro application (`dist/`). The Historical Evidence Explorer and Scenario Analytics Dashboard inspect the authentic pre-compiled demonstration data bundle (`demo_bundle.json`, 17.32 MB) **offline within the user's browser**.
>
> A successful static deployment **does not** imply that the Linux measurement lab is executing in production on Vercel. Live network experiments require an isolated Linux kernel environment with network namespaces, `nftables` stateful filtering, `tc netem` link emulation, and root/sudo permissions, as documented in [`docs/PS028_REPRODUCIBILITY_RUNBOOK.md`](docs/PS028_REPRODUCIBILITY_RUNBOOK.md).

### Repository Parity, Vercel Integration & Deployment Boundaries
- **Historical Evidence Bundle Integrity**: The live Vercel deployment serves a `demo_bundle.json` whose byte length (18,157,449 bytes / ~17.32 MiB) and SHA-256 digest (`42fad72c342c0e986c12502b0f9f82dbfc2d22fed0ea7e2709ee4469588c4b86`) match the locally verified historical evidence bundle byte-for-byte.
- **Static Frontend Functionality**: The deployed web UI is operational, serving routes `/`, `/evidence`, `/analytics`, and `/tests/*`.
- **Vercel Git Integration**: As recorded in deployment logs, the current Vercel Git integration is connected to a personal repository (`Promothesh-Chatterjee/ps028-happy-eyeballs` @ commit `6d02743`) rather than directly to the official repository (`aiori-hackathon/A3-PS028-TC224`). Direct Git webhook integration to the official repository remains a manual owner decision.
- **Full Deployment Artifact Identity**: While payload parity of the primary evidence bundle and operational functionality of the frontend are verified, verifying the data bundle digest does not establish byte-for-byte identity of every compiled frontend HTML/JS/CSS asset across independent build environments.

---

## D. Experimental Design

The laboratory evaluates the six controlled impairment scenarios required by PS-028, plus **S0** as an unimpaired healthy baseline control. Canonical scenario specifications are maintained in [`lab/scenarios.yaml`](lab/scenarios.yaml).

| Scenario ID | Canonical Name | Controlled Network Condition | Measurement Purpose |
|:---:|:---|:---|:---|
| **S0** | `healthy_baseline` | Dual-stack baseline; IPv4 & IPv6 RTT ~20 ms; immediate A and AAAA DNS answers | Healthy reference control; observe baseline IPv6 preference per RFC 6724 |
| **S1** | `ipv6_syn_blackhole` | IPv6 TCP SYN packets silently dropped via `nftables`; IPv4 healthy (~20 ms RTT) | Observe recovery and fallback timing when preferred IPv6 path is completely unresponsive |
| **S2** | `ipv6_tcp_rst` | IPv6 TCP SYN actively rejected with TCP RST; IPv4 healthy (~20 ms RTT) | Observe browser behavior under immediate active path rejection |
| **S3** | `ipv6_rtt_150ms` | IPv6 RTT ~150 ms (75 ms link delay); IPv4 RTT ~20 ms | Test racing when IPv6 path is moderately slower than IPv4 |
| **S4** | `ipv6_rtt_600ms` | IPv6 RTT ~600 ms (300 ms link delay); IPv4 RTT ~20 ms | Test racing when IPv6 RTT substantially exceeds default CAD (250 ms) |
| **S5** | `ipv6_syn_loss_50pct` | 50% random probabilistic loss on client-to-server IPv6 TCP SYN only | Observe connection racing and retransmission behavior under lossy transport |
| **S6** | `delay_aaaa_500ms` | IPv4 A answer immediate (0 ms delay); IPv6 AAAA answer delayed by 500 ms | Observe address-family selection under asynchronous DNS resolution delay |

### Experimental Matrix & Population
- **Tested Browsers**:
  - Google Chrome `156.0.8078.73`
  - Mozilla Firefox `159.0`
- **Repetitions**: Exactly 20 valid trials per browser/scenario cohort.
- **Cohort Structure**: 7 scenarios × 2 browsers = **14 cohorts**.
- **Recorded Population**: **280 valid live trials** (14 cohorts × 20 repetitions).
- **Total Recorded Attempts**: **282 attempts** (280 valid live trials + 2 preserved cleanup failure attempts).
- **Trial Isolation**: Every trial executed inside an ephemeral browser profile, with unique trial identifiers and fail-closed baseline self-test verification.

---

## E. Results and Scientific Findings

### 1. Primary Navigation Winner Distribution
The winning address family is classified strictly from the IP version of the primary HTTP `GET /` document request and its successful HTTP 200 response on the same TCP stream. Secondary favicon requests or speculative preconnects are isolated and never misclassified as main-navigation fallbacks.

| Scenario | Chrome Direct IPv6 | Chrome IPv4 Fallback | Firefox Direct IPv6 | Firefox IPv4 Fallback | Total IPv6 | Total IPv4 | Primary Winner |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **S0** | 20 | 0 | 20 | 0 | 40 | 0 | **IPv6 (100%)** |
| **S1** | 0 | 20 | 0 | 20 | 0 | 40 | **IPv4 (100%)** |
| **S2** | 0 | 20 | 0 | 20 | 0 | 40 | **IPv4 (100%)** |
| **S3** | 20 | 0 | 20 | 0 | 40 | 0 | **IPv6 (100%)** |
| **S4** | 0 | 20 | 1 | 19 | 1 | 39 | **IPv4 (97.5%)** |
| **S5** | 18 | 2 | 15 | 5 | 33 | 7 | **IPv6 (82.5%)** |
| **S6** | 20 | 0 | 20 | 0 | 40 | 0 | **IPv6 (100%)** |
| **Total** | **98** | **42** | **56** | **84** | **154** | **126** | **154 / 126** |

**Summary Population Totals**:
- **Direct IPv6 Primary Navigation**: 154 / 280 trials (**55.00%**, 95% Wilson CI: [49.16%, 60.72%])
- **IPv4 Fallback Primary Navigation**: 126 / 280 trials (**45.00%**, 95% Wilson CI: [39.28%, 50.84%])
- **Valid HTTP 200 Responses**: 280 / 280 trials (**100.0%**)

---

### 2. Connection Timing Metrics: `t_connect_ms` vs `t_setup_total_ms`
To avoid conflating transport latency with application setup, the analysis explicitly distinguishes two complementary packet-derived timing metrics defined at the client capture interface (`ps028-cl-rt`):

1. **Primary Handshake Completion Time ($t_{\text{connect\_ms}}$)**: Measures the elapsed time from the initial client SYN of the *winning* TCP stream to its matching final ACK transitioning the socket to `ESTABLISHED` (RFC 9293 §3.5). On fallback trials, this reflects only the secondary IPv4 handshake (~20 ms).
2. **Total Connection Setup Time ($t_{\text{setup\_total\_ms}}$)**: Measures elapsed time from the client's first target-host SYN of **any** address family to the primary connection's final ACK:
   $$t_{\text{setup\_total}} = \left( t_{\text{final\_ack, primary}} - \min_{f \in \{\text{IPv4}, \text{IPv6}\}} \left( t_{\text{first\_syn, } f} \right) \right) \times 1000$$
   In fallback scenarios (S1, S2, S4, S5), $t_{\text{setup\_total\_ms}}$ incorporates the initial failed/delayed IPv6 attempt and Connection Attempt Delay (CAD).

| Scenario | Condition | Chrome Median $t_{\text{connect}}$ | Chrome Median $t_{\text{setup\_total}}$ | Firefox Median $t_{\text{connect}}$ | Firefox Median $t_{\text{setup\_total}}$ | Valid Trials ($N$) |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| **S0** | Baseline (20ms RTT, dual-stack) | 20.39 ms | 20.39 ms | 20.49 ms | 20.49 ms | 20 / 20 |
| **S1** | IPv6 SYN Blackhole (silent drop) | 21.08 ms | 322.00 ms | 20.55 ms | 429.74 ms | 20 / 20 |
| **S2** | IPv6 TCP RST (active rejection) | 20.37 ms | 21.12 ms | 20.50 ms | 181.87 ms | 20 / 20 |
| **S3** | IPv6 RTT 150ms (symmetric delay) | 150.76 ms | 150.76 ms | 150.45 ms | 150.45 ms | 20 / 20 |
| **S4** | IPv6 RTT 600ms, IPv4 20ms (racing) | 20.82 ms | 321.72 ms | 20.48 ms | 420.07 ms | 20 / 20 |
| **S5** | IPv6 50% SYN Loss (probabilistic) | 20.54 ms | 23.10 ms | 20.58 ms | 86.95 ms | 20 / 20 |
| **S6** | Delayed AAAA 500ms (Resolution Delay) | 20.71 ms | 20.71 ms | 20.47 ms | 20.58 ms | 20 / 20 |

---

### 3. Scenario-by-Scenario Scientific Findings

- **S0 (Healthy Baseline)**: Both Chrome and Firefox established primary connections over IPv6 in 100% of trials (40/40), confirming RFC 6724 default address selection favoring IPv6 in healthy conditions.
- **S1 (IPv6 SYN Blackhole)**: Both browsers successfully recovered and fell back to IPv4 in 100% of trials (40/40). First inter-family SYN spacing: Chrome median was 300.83 ms; Firefox median was 408.45 ms. Both fall comfortably within the RFC 8305 §5 recommended 100–2000 ms window.
- **S2 (IPv6 TCP RST)**: Both browsers completed over IPv4 in 100% of trials. Chrome initiated IPv4 SYNs almost immediately upon RST (median offset 0.71 ms), whereas Firefox exhibited a paced median offset of 160.43 ms. Because wire captures record family-first SYN timestamps across independent flows without logical attempt pairing or socket causality tracking, S2 cannot be evaluated against the RFC 8305 §5 10 ms mandatory floor and remains classified as **`NOT_ASSESSED`**. Neither RFC 8305 nor HEv3 mandates immediate retry upon receiving TCP RST.
- **S3 (IPv6 RTT 150 ms)**: IPv6 won 100% of trials (40/40) for both clients with primary handshake times ~150.7 ms, demonstrating that a moderately slower IPv6 path (150 ms vs 20 ms) still completes within typical browser CAD timers before IPv4 completes.
- **S4 (IPv6 RTT 600 ms)**: IPv4 completed first in 39/40 trials (100% Chrome, 95% Firefox). In 1 Firefox trial (`trial-20261029222109-5c74c26a`), IPv6 completed with a 600.95 ms handshake without an observed IPv4 SYN. Bounded wire captures cannot inspect browser timer scheduling; causality is preserved as `INSUFFICIENT_EVIDENCE`.
- **S5 (IPv6 50% SYN Loss)**: Primary navigation completed over IPv6 in 33 trials (18 Chrome, 15 Firefox) and fell back to IPv4 in 7 trials (2 Chrome, 5 Firefox). Independent router nftables counters confirmed 50.0% aggregate packet drops, proving the loss model operated as designed.
- **S6 (Delayed AAAA 500 ms)**: In all 40 trials, both browsers waited for the delayed AAAA response (~505 ms) and connected over IPv6 rather than initiating IPv4 fallback after the RFC 8305 §3 recommended 50 ms Resolution Delay. This is documented as an empirical **`OBSERVED_DEVIATION`** from recommendations under laboratory conditions.

---

## F. Architecture and Instrumentation

The experimental testbed uses three isolated Linux network namespaces interconnected by virtual ethernet (`veth`) pairs:

```
+---------------------------------------------------------------------------------------+
|                                    PROJECT TOPOLOGY                                   |
|                                                                                       |
|  [ps028-cl (Client Namespace)]       [ps028-rt (Router)]       [ps028-sv (Server)]     |
|  IPv4: 198.51.100.2 / IPv6: 2001:db8:1::2                       198.51.100.10 /       |
|  Google Chrome 156 / Firefox 159    <-->   tc netem / nft   <-->  2001:db8:2::10      |
|  tcpdump capture on ps028-cl-rt                                Nginx (HTTP/1.1)       |
|  Controlled DNS resolver                                       DNS Responder          |
+---------------------------------------------------------------------------------------+
```

### Namespace Roles & Core Modules
1. **Client Namespace (`ps028-cl`)**: Runs browser binaries with ephemeral profiles (`--user-data-dir` / `-profile`), client-side packet capture via `tcpdump` / `tshark`, and browser diagnostic telemetry collectors. Managed by [`lab/run_trial.py`](lab/run_trial.py).
2. **Router Namespace (`ps028-rt`)**: Acts as dual-stack gateway and traffic controller. Implements link latency and jitter via `tc netem` and stateful packet filtering/dropping via `nftables`. Controlled by [`lab/impair.py`](lab/impair.py) and [`lab/privileged_helper.py`](lab/privileged_helper.py).
3. **Server Namespace (`ps028-sv`)**: Hosts dual-stack Nginx HTTP/1.1 origin server and controlled UDP DNS responder ([`lab/dns_server.py`](lab/dns_server.py)) configured to inject independent delays for A and AAAA queries.

---

## G. Frontend Architecture and Routes

The frontend web application is located in [`setup/webtester/`](setup/webtester) and statically generated using Astro v5.

| Route | Source Component | Purpose & Description |
|---|---|---|
| `/` | `src/pages/index.astro` | **Laboratory Home Page**: Central navigational dashboard linking to evidence explorer, analytics, and browser tests. |
| `/evidence` | `src/pages/evidence.astro` | **Historical Evidence Explorer**: Interactive data grid of 280 trials, multi-source timeline (28,330 events), TCP attempt inspector, and SHA-256 integrity verification. |
| `/analytics` | `src/pages/analytics.astro` | **Scenario Analytics Dashboard**: Tukey box plots, latency distributions, address-family winner ratios, and custom PDF report export. |
| `/tests/connection-attempt-delay` | `src/pages/tests/connection-attempt-delay.astro` | **CAD Test**: Interactive browser test measuring Connection Attempt Delay. |
| `/tests/resolution-delay` | `src/pages/tests/resolution-delay.astro` | **Resolution Delay Test**: Evaluates client fallback when AAAA is delayed. |
| `/tests/http3-availability` | `src/pages/tests/http3-availability.astro` | **HTTP/3 Availability Test**: Checks client HTTP/3 (QUIC) capability. |
| `/tests/hev3-quic-tls` | `src/pages/tests/hev3-quic-tls.astro` | **HEv3 QUIC & TLS Test**: Evaluates Happy Eyeballs v3 protocol racing across QUIC and TLS. |
| `/tests/hev3-combined` | `src/pages/tests/hev3-combined.astro` | **HEv3 Combined Test**: Comprehensive Happy Eyeballs v3 feature evaluation suite. |

---

## H. Repository Map

```
A3-PS028-TC224/
├── README.md                                  # Authoritative judge-facing entry point
├── LICENSE                                    # Mozilla Public License Version 2.0 (MPL-2.0)
├── LICENSES/                                  # Upstream third-party licenses (MIT for shadcn UI)
├── UPSTREAM_README.md                         # Upstream WebTester project documentation
├── PROJECT.md                                 # Archived project specifications & roadmap
├── PHASE_CD_PROGRESS.md                       # Archived Phase C/D milestone progress tracker
├── TEST_INFRA.md                              # 5-tier test infrastructure specification
├── TEST_READY.md                              # Historical test readiness report
├── PS028 Detailed Analysis & Report PDF.pdf   # Official 22-page technical report (AIORI submission)
├── PS028_Hackathon_Submission_Presentation.pdf # Official 11-page Beamer presentation deck
├── AIORI_PS028_Happy_Eyeballs_Presentation.pdf# Preserved historical submission artifact
├── Proposed-structure-hackathon.pdf           # Organizer hackathon guidelines & structure
├── requirements.lock                          # Pinned Python dependencies with SHA-256 hashes
├── .github/workflows/
│   └── ci.yml                                 # 3-job GitHub Actions CI workflow (Python, Frontend, PDFs)
├── docs/                                      # Central scientific and technical documentation
│   ├── README.md                              # Central documentation directory index
│   ├── PS028_FINAL_EXPERIMENTAL_REPORT.md     # Authoritative technical report Markdown source
│   ├── PS028_REPRODUCIBILITY_RUNBOOK.md       # Laboratory reproducibility runbook
│   ├── phase-c-metric-contract.md             # Phase C metric contract and Schema 1.1.0
│   ├── phase-d-experiment-protocol.md         # Pre-registered research sweep protocol
│   ├── phase-e/                               # Demonstration data bundle documentation
│   └── phase-cd/                              # Compliance matrix, glossary, audits, gates
├── lab/                                       # Core measurement lab, impairment engine & analysis
│   ├── scenarios.yaml                         # Canonical S0–S6 scenario definitions
│   ├── run_campaign.py                        # Sequential campaign matrix orchestrator
│   ├── run_trial.py                           # Single-trial runner, browser launcher, PCAP classifier
│   ├── analyze.py                             # Statistical analysis CLI & RFC 8305 evaluator
│   ├── impair.py                              # Traffic control (netem) and packet filter (nft) manager
│   ├── dns_server.py                          # Controlled delay-injecting DNS responder
│   ├── privileged_helper.py                   # Root-authorized helper with argument validation
│   ├── build_submission_report.py             # Compiles presentation slide deck PDF
│   ├── build_technical_report_pdf.py          # Compiles publication technical report PDF
│   ├── demo_replay.py                         # Standalone offline PCAP replay utility
│   ├── build_demo_bundle.py                   # Rebuilds deterministic demo bundle JSON
│   ├── campaigns/                             # Historical raw campaign evidence
│   │   └── ps028-a10-live-20261030-01/        # 280 valid PCAPs, JSON logs, NetLog, checksums
│   ├── derived/                               # Deterministic derived evidence & reports
│   │   ├── phase-c/                           # Re-derived trial results, attempts.csv, timelines
│   │   └── phase-e/                           # demo_bundle.json, provenance, metric registry
│   └── test_*.py                              # 26 Python lab unit & regression test modules
├── setup/                                     # Setup tooling & frontend application
│   └── webtester/                             # Astro v5 / React 19 web application source
│       ├── README.md                          # Frontend development & operational guide
│       ├── package.json                       # Node dependencies & package scripts
│       ├── scripts/                           # Bundle preparation & distribution smoke tests
│       ├── src/                               # Frontend source: pages, components, lib
│       └── test/                              # Frontend unit tests & Playwright browser acceptance
├── src/                                       # Hackathon template placeholder
│   └── README.md                              # Architecture disclaimer pointing to lab/ & setup/
└── tests/                                     # 5-tier independent E2E & adversarial test suite
    ├── test_tier1_features.py                 # Tier 1: Canonical features S0–S6 & racing
    ├── test_tier2_boundaries.py               # Tier 2: Timing boundaries & schema invariants
    ├── test_tier3_combinations.py             # Tier 3: Cross-feature impairment combinations
    ├── test_tier4_scenarios.py                # Tier 4: Real-world network profiles
    └── test_tier5_adversarial_c5.py           # Tier 5: Adversarial privilege isolation & DNS
```

---

## I. Reproducibility

Reproducibility is organized into distinct, validated operational tiers:

### 1. Verify Historical Evidence Integrity (Rule R2)
Verify all 705 original PCAPs, JSON results, and campaign manifests against the cryptographic seal:
```bash
sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256
```
*Expected: 705/705 OK (100% pass).*

### 2. Run Offline Deterministic Test Suites
These tests run completely offline without root privileges, network namespaces, or browser processes:
```bash
# Python Lab Test Suite (1,243 tests)
python3 -m unittest discover -s lab -p "test_*.py"

# Python Integration Test Suite (93 tests)
python3 -m unittest discover -s tests -p "test_*.py"

# Frontend Unit Tests (44 tests)
cd setup/webtester && npm test
```

### 3. Rebuild Demonstration Data Bundle & Staged Assets
Recompile the deterministic demonstration bundle from Phase C sources:
```bash
python3 lab/build_demo_bundle.py
cd setup/webtester && npm run prepare:data
```

### 4. Build and Test the Frontend Application
```bash
cd setup/webtester

# Astro type checking and diagnostic checks
npm run check

# Static production build (compiles 8 pages into dist/)
npm run build

# Run distribution preview smoke tests (16 checks)
npm run test:smoke

# Run genuine Playwright browser acceptance tests (Chromium, 19 stages, 260 assertions)
npx playwright install --with-deps chromium
npm run test:browser
```

### 5. Replay Authentic Historical Trials Offline
```bash
# Tabular summary of 14 representative trials
python3 lab/demo_replay.py --summary

# Event-level synchronized timeline cards
python3 lab/demo_replay.py --events

# Display canonical RFC 8305 pseudocode snippet
python3 lab/demo_replay.py --pseudocode
```

### 6. Regenerate Official Submission PDFs
```bash
# Rebuild 11-slide Beamer presentation deck
python3 lab/build_submission_report.py

# Rebuild 22-page publication technical report
python3 lab/build_technical_report_pdf.py
```

### 7. Live Measurement Lab Requirements (Linux Only)
To execute genuinely new live experiments:
- **Operating System**: Linux (Ubuntu 24.04 LTS tested).
- **Prerequisites**: `iproute2` (`ip netns`, `tc netem`), `nftables`, `nginx`, `tshark`, `google-chrome`, `firefox`.
- **Privileges**: `sudo` permissions for namespace creation and impairment rules.
- Execution runbook: [`docs/PS028_REPRODUCIBILITY_RUNBOOK.md`](docs/PS028_REPRODUCIBILITY_RUNBOOK.md).

---

## J. Testing and Continuous Integration

Automated continuous integration is executed on GitHub Actions via [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

The CI pipeline runs across three dedicated jobs:
1. **`python-tests`**: Runs on Ubuntu 24.04; installs pinned TShark, sets up Python 3.12 with locked dependencies, validates 705 historical checksums, executes 1,243 Python lab unit tests, and executes 93 integration tests.
2. **`frontend-validation`**: Runs on Ubuntu 24.04; sets up Node.js 22, executes 44 frontend unit tests, runs Astro diagnostic check, compiles the 8-page production build, runs 16 distribution smoke checks, and executes the 19-stage / 260-assertion Playwright browser acceptance suite in genuine Chromium.
3. **`artifacts-validation`**: Builds both official submission PDFs (`PS028_Hackathon_Submission_Presentation.pdf` and `PS028 Detailed Analysis & Report PDF.pdf`), verifies page counts (11 and 22 pages) and byte-size thresholds, and uploads the artifacts to GitHub Actions.

### Fresh Current Test Execution Results (Local Working Tree based on `7cf178d` / `main` `c6e561e`)
- **Python Lab Test Suite (`lab/`)**: 1,243 discovered; 1,242 passed; 1 skipped.
- **Python Integration Test Suite (`tests/`)**: 93 passed.
- **Frontend Unit Test Suite (`setup/webtester/test/`)**: 44 passed.
- **Total Suite Outcome**: **1,380 unique automated tests discovered; 1,379 passed, 1 skipped due to an unprivileged host environment, zero failures and zero errors.**
- **Distribution Smoke Checks**: 16 checks passed.
- **Real-Browser Chromium Acceptance Suite**: 19 stages passed, 260 assertions verified.
- **Historical Checksums**: 705 / 705 files OK (`historical_integrity_before.sha256`).

> [!NOTE]
> **Provenance & CI Execution Notice**:
> These test results reflect local validation against the current working tree based on commit `7cf178dfb4df796c705ba9f439a10ad33322fd75` (whose tree is identical to official `main` commit `c6e561ed11a72682b72973dd829fdc910ee908bc`). The newly updated documentation and CI triggers are local working-tree modifications until published. The newly added push trigger for `main` in `.github/workflows/ci.yml` will be exercised by GitHub Actions once changes are committed and pushed to `main`.

---

## K. Limitations and Threats to Validity

1. **Single Laboratory Host**: All live measurements were conducted in one x86_64 Ubuntu 24.04 LTS / WSL2 environment. Results reflect this specific host kernel, network virtualization layer, and TCP implementation.
2. **Pinned Browser Builds**: Observations apply strictly to **Google Chrome 156.0.8078.73** and **Mozilla Firefox 159.0**. They should not be generalized across all versions, operating systems, or architectures.
3. **HTTP/1.1 over TCP Scope**: The historical campaign evaluates unencrypted HTTP/1.1 over TCP. It does not evaluate TLS handshake racing, HTTP/3 over QUIC, or SVCB/HTTPS endpoint resolution racing.
4. **Wire Observations vs. Internal Timers**: Packet captures record observable wire traffic at the network interface. They cannot directly observe browser-internal timer scheduling, socket state machines, or asynchronous task prioritization.
5. **No General Conformance Claims**: In accordance with Rule R7, empirical deviations under artificial impairments (e.g., S6 late AAAA delay) describe laboratory observations for the pinned builds; they do not assert general non-conformance of browser networking engines.
6. **RFC & Draft Specifications**: Conformance evaluations use [RFC 8305 (Happy Eyeballs v2)](https://www.rfc-editor.org/rfc/rfc8305.html). Happy Eyeballs v3 is evaluated strictly against the pinned historical reference [`draft-ietf-happy-happyeyeballs-v3-04`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-04) (1 July 2026), which was an active Internet-Draft, not an RFC, at the time of campaign execution.
7. **Ephemeral Profile Isolation**: Browser profiles were cleared before every trial to guarantee trial independence. This explicitly prevents evaluating multi-trial cache memory or persistent address-sorting history across sessions.

---

## L. Submission and Project Resources

| Deliverable | File / Location | Description |
|---|---|---|
| **Technical Validation Report** | [`PS028 Detailed Analysis & Report PDF.pdf`](PS028%20Detailed%20Analysis%20%26%20Report%20PDF.pdf) | Canonical 22-page technical report generated via `lab/build_technical_report_pdf.py` |
| **Presentation Slide Deck** | [`PS028_Hackathon_Submission_Presentation.pdf`](PS028_Hackathon_Submission_Presentation.pdf) | Canonical 11-slide Beamer presentation deck generated via `lab/build_submission_report.py` |
| **Historical Presentation Artifact** | [`AIORI_PS028_Happy_Eyeballs_Presentation.pdf`](AIORI_PS028_Happy_Eyeballs_Presentation.pdf) | Preserved historical presentation artifact from initial project upload |
| **Project Demonstration Video** | [YouTube: Final Project Demonstration](https://youtu.be/LYngp7dzoRI?si=1mPrapHizazV41zB) | Video demonstration of offline replay, WebTester, and analytics |
| **Team Introduction Video** | [YouTube: Team Introduction](https://youtu.be/5LLxlW9f6r4?si=EQjgtt3bIgkQ4Nix) | Team video introducing AlgoRhythm members |
| **Live Web Application** | [ps028-happy-eyeballs.vercel.app](https://ps028-happy-eyeballs.vercel.app/) | Deployed interactive Historical Evidence Explorer and Analytics Dashboard |
| **Problem Statement Compliance** | [`docs/phase-cd/ps028-compliance-matrix.md`](docs/phase-cd/ps028-compliance-matrix.md) | Requirement-to-evidence compliance mapping (17/18 MET, 1 PENDING partner execution) |

---

## M. Licensing and Upstream Attribution

### Repository License Boundaries
- **Project Root & Measurement Lab**: Licensed under the **Mozilla Public License Version 2.0** ([`LICENSE`](LICENSE)).
- **Frontend UI Components**: UI components under `setup/webtester/src/components/ui/` are adapted from [shadcn/ui](https://ui.shadcn.com/) and licensed under the **MIT License** ([`LICENSES/MIT.txt`](LICENSES/MIT.txt)).

### Upstream Project Attribution
The frontend WebTester framework is adapted from the original open-source [Happy Eyeballs WebTester](https://github.com/happy-eyeballs/he-webtester) developed by Patrick Sattler, Johannes Zirngibl, Matthias Kirstein, and Tim Betzer at the Technical University of Munich (TUM), accompanying the research paper:
> Patrick Sattler, Matthias Kirstein, Lars Wüstrich, Johannes Zirngibl, and Georg Carle. 2025. *Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations*. In Proceedings of the 2025 Internet Measurement Conference (IMC '25). ACM, New York, NY, USA. [https://doi.org/10.1145/3694834.3694850](https://doi.org/10.1145/3694834.3694850).

See [`UPSTREAM_README.md`](UPSTREAM_README.md) for original upstream documentation and deployment instructions.

---

**Team AlgoRhythm** · *Measure. Compare. Improve.*
