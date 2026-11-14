# Happy Eyeballs: IPv4/IPv6 Fallback Measurement

**Team AlgoRhythm** · **AIORI Hackathon 3** · **PS-028: Internet Measurement**

|Submission detail|Value|
|-|-|
|Campaign|`ps028-a10-live-20261030-01`|
|Evidence and code baseline|Branch `a/lab-foundation` · commit [`002c4453d35d6760760c6a14d2e98618b024f1f2`](https://github.com/aiori-hackathon/A3-PS028-TC224/commit/002c4453d35d6760760c6a14d2e98618b024f1f2)|
|Phase C/D analysis revision|Branch `regional/ps028-phase-cd` · commit [`b920ebc93f2e6aaae8396b7095b6cd3c8598ade5`](https://github.com/aiori-hackathon/A3-PS028-TC224/commit/b920ebc93f2e6aaae8396b7095b6cd3c8598ade5)|
|Consolidation target|Branch `regional/p0-remediation` (PR base)|
|Final technical report|[`PS028 Detailed Analysis & Report PDF.pdf`](PS028%20Detailed%20Analysis%20%26%20Report%20PDF.pdf)|
|Team introduction|https://youtu.be/5LLxlW9f6r4?si=EQjgtt3bIgkQ4Nix|
|Final Project Demonstration Video|[https://youtu.be/LYngp7dzoRI?si=1mPrapHizazV41zB](https://youtu.be/LYngp7dzoRI?si=1mPrapHizazV41zB)|
|Campaign evidence|[`lab/campaigns/ps028-a10-live-20261030-01/`](lab/campaigns/ps028-a10-live-20261030-01)|

\---

## Contents

* [Project summary](#project-summary)
* [Problem and objective](#problem-and-objective)
* [Experimental design](#experimental-design)
* [Testbed and instrumentation](#testbed-and-instrumentation)
* [Results](#results)
* [Evidence quality and exclusions](#evidence-quality-and-exclusions)
* [Statistical methods and metric definitions](#statistical-methods-and-metric-definitions)
* [RFC interpretation and scope](#rfc-interpretation-and-scope)
* [Repository guide](#repository-guide)
* [Reproduce offline analysis on Windows](#reproduce-offline-analysis-on-windows)
* [Limitations and threats to validity](#limitations-and-threats-to-validity)
* [References](#references)
* [Submission checklist](#submission-checklist)

\---

## Project summary

This project measures how two existing browser clients establish connections in a controlled dual-stack laboratory when IPv6 is impaired by a TCP SYN blackhole, active TCP reset, additional latency, packet loss or delayed DNS. The test harness runs six impairment scenarios required by PS-028 plus a healthy baseline control.

The completed campaign contains **280 valid live trials**: seven conditions × two browsers × 20 repetitions. The primary-navigation analysis classified **154 trials (55.00%) as direct IPv6** and **126 trials (45.00%) as IPv4 fallback**. All 280 valid trials returned HTTP 200.

> \*\*Scope:\*\* These are empirical observations from two pinned browser builds in one laboratory environment. This project does not implement a new browser stack and does not claim general RFC conformance.

## Problem and objective

A dual-stack hostname can return both A (IPv4) and AAAA (IPv6) records, while the corresponding network paths differ in reachability or latency. A client that waits too long on an impaired preferred path can increase connection-establishment time. Happy Eyeballs coordinates connection attempts across available address families so that a usable path can be selected without waiting for a long failure timeout.

The objective is to compare two existing browsers under repeatable, controlled conditions. Packet captures provide the primary network evidence; browser telemetry is retained as supporting diagnostic evidence.

## Experimental design

The PS-028 brief calls for six controlled impairment scenarios. **S0 is an additional healthy baseline**, so the campaign contains seven conditions in total. The canonical scenario definitions are maintained in [`lab/scenarios.yaml`](lab/scenarios.yaml).

|ID|Canonical scenario|Controlled condition|Measurement purpose|
|:-:|-|-|-|
|S0|`healthy\_baseline`|IPv4 and IPv6 RTT approximately 20 ms; A and AAAA answers immediate|Healthy dual-stack reference|
|S1|`ipv6\_syn\_blackhole`|IPv6 TCP SYN packets are silently dropped; IPv4 remains healthy|Observe recovery from an unresponsive IPv6 path|
|S2|`ipv6\_tcp\_rst`|IPv6 TCP SYN is actively rejected with TCP RST; IPv4 remains healthy|Observe response to active IPv6 rejection|
|S3|`ipv6\_rtt\_150ms`|IPv6 RTT approximately 150 ms; IPv4 approximately 20 ms|Compare a moderately slower IPv6 path|
|S4|`ipv6\_rtt\_600ms`|IPv6 RTT approximately 600 ms; IPv4 approximately 20 ms|Compare a severely slower IPv6 path|
|S5|`ipv6\_syn\_loss\_50pct`|Approximately 50% random loss on client-to-server IPv6 TCP SYN only|Observe behaviour under partial SYN loss|
|S6|`delay\_aaaa\_500ms`|A response is immediate; AAAA response is delayed by 500 ms|Observe address-family selection under delayed AAAA resolution|

### Clients and repetitions

|Client|Recorded build|Valid repetitions per condition|
|-|-:|-:|
|Google Chrome|`156.0.8078.73`|20|
|Mozilla Firefox|`159.0`|20|
|**Total**|**2 browser builds**|**280 valid trials**|

## Testbed and instrumentation

The experiment uses three isolated Linux network namespaces:

|Namespace|Role|Main components|
|-|-|-|
|`ps028-cl`|Dual-stack client|Chrome 156, Firefox 159, ephemeral browser profiles, client-link PCAP capture|
|`ps028-rt`|Router and DNS|IPv4/IPv6 forwarding, controlled DNS service, scenario-specific `nftables` rules, `tc netem` delay/loss|
|`ps028-sv`|Origin server|Nginx HTTP/1.1 endpoint, IPv4 `10.0.2.10`, IPv6 `2001:db8:2::10`|

`nftables` applies the IPv6 SYN blackhole, TCP reset and S5 packet-loss conditions. `tc netem` applies the configured link delays. Each trial records a `result.json`, packet capture, capture log and browser diagnostic telemetry (Chrome NetLog or Firefox network log). Browser diagnostics supplement, but do not replace, packet-level evidence.

**Recorded campaign environment**

|Component|Recorded version / configuration|
|-|-|
|Operating system|Ubuntu 24.04.5 LTS, x86\_64 WSL2 host|
|Kernel|`6.18.54.1-microsoft-standard-WSL2`|
|Python|`3.12.3`|
|Nginx|`1.24.0`|
|tcpdump|`4.99.4`|
|TShark|`4.2.2`|
|nftables|`1.0.9`|
|Traffic control|`iproute2` / `tc netem`|

These values describe the environment recorded for this campaign; they are not a compatibility guarantee for other hosts or software releases.

## Results

### Winning address family

The winner is classified from the address family of the primary HTTP `GET /` document request and its successful response on the same TCP stream. An IPv4 favicon request or speculative preconnect after an IPv6 document success is not counted as a main-navigation fallback.

|Scenario|Chrome direct IPv6|Chrome IPv4 fallback|Firefox direct IPv6|Firefox IPv4 fallback|
|:-:|-:|-:|-:|-:|
|S0|20|0|20|0|
|S1|0|20|0|20|
|S2|0|20|0|20|
|S3|20|0|20|0|
|S4|0|20|1|19|
|S5|18|2|15|5|
|S6|20|0|20|0|
|**Total**|**98**|**42**|**56**|**84**|

|Overall outcome|Trials|Share|
|-|-:|-:|
|Direct IPv6 primary navigation|154|55.00%|
|IPv4 primary navigation after IPv6 attempt|126|45.00%|
|**Total HTTP 200 responses**|**280 / 280**|**100%**|

### Primary-document TCP timing from raw PCAPs

All 280 packet captures were independently re-parsed. The primary `GET /` request was found in all 280 captures, and its TCP stream was correlated with the successful HTTP response. The primary-flow address family agreed with the browser-reported winner in all 280 trials.

The values below are the interval from the primary-document TCP SYN to the matching server SYN/ACK on the same stream. This is a packet-derived connection-response / RTT proxy; it is **not** page-load time and does not include the final ACK or application readiness.

|Scenario|Chrome median (IQR), ms|Firefox median (IQR), ms|
|:-:|-:|-:|
|S0|20.32 (0.07)|20.42 (0.16)|
|S1|20.96 (0.45)|20.41 (0.87)|
|S2|20.31 (0.10)|20.38 (0.24)|
|S3|150.65 (0.35)|150.39 (0.21)|
|S4|20.74 (0.72)|20.36 (0.15)|
|S5|20.46 (0.25)|20.50 (0.22)|
|S6|20.64 (0.50)|20.42 (0.30)|

S4 Firefox includes one direct-IPv6 main flow with a 600.95 ms SYN-to-SYN/ACK interval. Since the other 19 trials fell back to IPv4, the median remains near 20 ms; the empirical p95 is 52.24 ms and the maximum is 600.95 ms.

### Findings by scenario

|Scenario|Observed result|Interpretation|
|:-:|-|-|
|S0|Both browsers selected IPv6 in all 40 trials.|The healthy baseline behaved as expected in this testbed.|
|S1|All 40 trials completed over IPv4. Median first inter-family SYN interval: 300.83 ms (Chrome), 408.45 ms (Firefox).|Both clients recovered from the IPv6 SYN blackhole. The interval is attempt pacing, not the main-flow connection time.|
|S2|All 40 trials completed over IPv4. Chrome's 20 observed family-first-SYN offsets were 0.35–6.82 ms (median 0.71 ms); Firefox's were 130.78–336.23 ms (median 160.43 ms).|Because wire measurements capture family-first-SYN offsets across independent flows without logical attempt pairing or state tracking, S2 cannot be validly assessed against the RFC 8305 Section 5 10 ms floor and remains NOT_ASSESSED. Neither RFC 8305 nor draft HEv3 mandates immediate TCP RST fallback.|
|S3|All 40 trials completed over IPv6. Main-flow packet interval was approximately 150 ms for both clients.|The slower IPv6 path still won in this 150 ms condition.|
|S4|IPv4 won in 39/40 trials. In 1 Firefox trial (`trial-20261029222109-5c74c26a`), IPv6 recorded a 600.949 ms SYN-to-SYN/ACK interval (handshake completion at 601.045 ms; wire HTTP 200 at 1,298.191 ms).|No IPv4 TCP SYN packet was observed in the monitored PCAP (bounded by capture interface and observation window). Packet captures cannot establish browser-internal timer scheduling or suppression; causality remains INSUFFICIENT_EVIDENCE.|
|S5|33 main navigations completed over IPv6 (18 Chrome, 15 Firefox); seven completed over IPv4 (two Chrome, five Firefox).|Flow correlation prevents ancillary IPv4 favicon or speculative preconnect traffic from being misclassified as fallback.|
|S6|All 40 trials completed over IPv6. Median A latency: 4.83 ms (Chrome), 0.83 ms (Firefox). Median AAAA latency: 505.20 ms and 502.56 ms respectively.|In these builds, the primary navigation waited for the delayed AAAA response; no IPv4 primary navigation was observed after the recommended 50 ms Resolution Delay.|

## Evidence quality and exclusions

|Validation item|Recorded result|
|-|-|
|Planned / completed matrix slots|280 / 280|
|Total attempts / valid live trials|282 / 280|
|Preserved initial cleanup failures|2, both retried with new trial IDs and excluded from valid results|
|Simulated trials|0|
|Valid HTTP 200 responses|280 / 280|
|PCAP captures / PCAP checksum matches|280 / 280|
|PCAP packet count / reported capture drops|36,225 / 0|
|Primary `GET /` flows found|280 / 280|
|Primary-flow / browser winner disagreements|0|
|Recorded local test run|881 unique automated tests discovered across repository (788 in lab/ across 21 test modules, 93 in tests/ across 5 tiers; 0 duplicate executions): 866 passed, 4 failed, 11 errors in unprivileged environment; 199 focused offline tests passing 100%|

The two excluded attempts were a Firefox S0 preflight baseline self-test failure (`Broken pipe`) and a Chrome S6 cleanup failure caused by a helper operation requiring root privileges. Both records remain in the evidence trail and were retried using unique trial IDs. The historical 400-test record reflects the initial baseline. The test suite expanded through Phase C/D Batch C5 (725 unit + 93 synthetic = 818 tests), Phase C/D baseline (731 unit + 93 synthetic = 824 tests), and Phase E demo readiness (825 unit + 93 synthetic = 918 tests). Following test-suite deduplication in Task 5C (renaming the Batch C5 re-export runner to eliminate 48 duplicate executions), full repository discovery identifies exactly 881 unique test cases (788 in `lab/` across 21 modules, 93 in `tests/` across 5 tiers; 0 duplicate executions), incorporating 11 regression tests added during Tasks 1–3A and Task 5B (+2 in `test_demo_bundle.py`, +7 in `test_export_campaign_evidence.py`, +1 in `test_analyze.py`, +1 in `test_impair.py`): 866 passed, 4 failed, 11 errors in an unprivileged environment (all 15 failures/errors in `lab/` due to missing root/sudo privileges, unconfigured network namespaces, and read-only browser crashpad directories; 5 cross-device link errors were resolved by creating temporary state files within `STATE_FILE.parent`, and the stale synthetic fixture was repaired to enforce fail-closed telemetry validation; `tests/` passes 93/93). A focused offline regression suite of 199 tests (subset of `lab/`) executes with a 100% pass rate.

The complete evidence checksum index contains 1,411 checksum-indexed artifacts, reconciling the campaign execution log with the archived evidence. The complete archive and the portable analysis ZIP serve different purposes: the complete archive preserves captures and telemetry; the portable bundle provides the analysis inputs and code for offline regeneration.

## Statistical methods and metric definitions

|Item|Definition|
|-|-|
|Sample size|`n = 20` valid live trials per scenario and browser|
|Main-flow timing|Median, IQR and empirical p95 from primary-flow SYN-to-matching-SYN/ACK intervals|
|Median confidence interval|Deterministic percentile bootstrap, `B = 1,000`, seed `42`|
|Mean confidence interval in analyzer outputs|Student-t interval, `df = n - 1`|
|Proportion confidence interval in analyzer outputs|Ordinary Wilson score interval, without continuity correction|
|Inter-family first-SYN interval|Descriptive first IPv6/IPv4 SYN spacing; not necessarily a fallback delay if an observed connection is ancillary or speculative|

### Principal Connection Timing Metrics (`t_connect_ms` vs `t_setup_total_ms`)

The analysis distinguishes two complementary packet-derived timing metrics defined strictly at the client-side capture vantage point (`ps028-cl`, interface `ps028-cl-rt`):

- **Primary Handshake Completion Time (`t_connect_ms`)**: Measures the primary TCP stream duration from its initial client SYN to its matching final ACK transitioning the socket to `ESTABLISHED` (RFC 9293 §3.5). On winning fallback streams, this captures only the secondary IPv4 handshake (~20 ms) and excludes prior failed attempts.
- **Fallback Total Setup Time (`t_setup_total_ms`)**: Measures the trial-level elapsed time from the client's first target-host SYN of **any** address family (IPv4 or IPv6) to the primary connection's final ACK:
  $$t_{\text{setup\_total}} = \left( t_{\text{final\_ack, primary}} - \min_{f \in \{\text{IPv4}, \text{IPv6}\}} \left( t_{\text{first\_syn, } f} \right) \right) \times 1000$$
- **Why they differ**: In direct IPv6 connections (S0, S3, S6), $t_{\text{setup\_total\_ms}} \approx t_{\text{connect\_ms}}$ because the initial attempt establishes immediately. In fallback scenarios (S1, S2, S4, S5), $t_{\text{connect\_ms}}$ reflects only the secondary IPv4 handshake (~20 ms), whereas $t_{\text{setup\_total\_ms}}$ includes the initial failed/delayed IPv6 attempt and Connection Attempt Delay (CAD), representing the trial-level transport connection setup interval before the selected primary connection completes.
- **Population & Cohort Structure**: Evaluated across all **280 valid live trials** in campaign `ps028-a10-live-20261030-01` across 14 balanced cohorts (7 scenarios $\times$ 2 browsers $\times$ $n = 20$ repetitions per cohort). Neither metric measures DNS resolution duration, application response, or full browser page load.

| Scenario | Network Condition | Chrome Median `t_connect_ms` | Chrome Median `t_setup_total_ms` | Firefox Median `t_connect_ms` | Firefox Median `t_setup_total_ms` | Valid Trials ($N$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **S0** | Baseline (10ms RTT, dual-stack) | 20.39 ms | 20.39 ms | 20.49 ms | 20.49 ms | 20 / 20 |
| **S1** | IPv6 SYN Blackhole (silent drop) | 21.08 ms | 322.00 ms | 20.55 ms | 429.74 ms | 20 / 20 |
| **S2** | IPv6 TCP RST (active rejection) | 20.37 ms | 21.12 ms | 20.50 ms | 181.87 ms | 20 / 20 |
| **S3** | IPv6 RTT 150ms (symmetric delay) | 150.76 ms | 150.76 ms | 150.45 ms | 150.45 ms | 20 / 20 |
| **S4** | IPv6 RTT 600ms, IPv4 10ms (racing) | 20.82 ms | 321.72 ms | 20.48 ms | 420.07 ms | 20 / 20 |
| **S5** | IPv6 50% SYN Loss (probabilistic) | 20.54 ms | 23.10 ms | 20.58 ms | 86.95 ms | 20 / 20 |
| **S6** | Delayed AAAA 500ms (Resolution Delay) | 20.71 ms | 20.71 ms | 20.47 ms | 20.58 ms | 20 / 20 |

**Metric cautions**

* `response\_body\_bytes` is browser-process stdout length (308 bytes for Chrome and 72 bytes for Firefox), not the HTTP payload size.
* Browser-duration outputs arise from different capture mechanisms and are not a like-for-like application-readiness measure.
* The generic stored `connection\_setup\_time\_ms` differed by more than 1 ms from the raw-PCAP primary-flow interval in 144/280 trials. The timing comparison therefore uses the explicitly defined primary-flow packet metric.
* `rfc8305\_assessment.csv` reflects the authoritative assessment verified against underlying trial evidence (checks covering RFC 8305 Sections 2, 3, 4, and 5), reporting empirical S2 (family-first-SYN offsets on TCP RST, evaluated as NOT_ASSESSED for the 10 ms floor due to absence of attempt pairing) and S6 (late AAAA resolution delay) observations under laboratory conditions without inferring unobserved browser internals or general non-conformance.

## RFC interpretation and scope

[RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html) Section 2 ("Overview") assumes the host destination-address preference policy favors IPv6 over IPv4, referencing [RFC 6724](https://www.rfc-editor.org/rfc/rfc6724.html) Section 2.1 (policy table precedence: `::/0` precedence 40 vs `::ffff:0:0/96` precedence 35), Section 6 Rule 6 (Prefer higher precedence; Rule 2 is Prefer matching scope), and Section 10.3 (Configuring Preference for IPv6 or IPv4). RFC 8305 Section 3 ("Hostname Resolution Query Handling") covers asynchronous DNS resolution and recommends a 50 ms Resolution Delay when A arrives before AAAA. Section 4 ("Sorting Addresses") covers destination address sorting using RFC 6724, historical RTT information, and previously used addresses. Section 5 ("Connection Attempts") specifies that a subsequent connection attempt **MUST NOT** begin within 10 ms of the previous attempt (recommended minimum CAD 100 ms, recommended default 250 ms, recommended maximum 2 s). Immediate retry upon TCP RST is not mandated by RFC 8305 or HEv3. Section 7 ("Supporting IPv6-Only Networks with NAT64 and DNS64") addresses NAT64 and DNS64 operation on IPv6-only networks.

The Chrome S2 family-first-SYN offsets are reported as empirical observations, but without verified logical attempt pairing between IPv6 and IPv4 flows, the RFC 8305 Section 5 10 ms mandatory floor cannot be assessed (status remains NOT_ASSESSED). Furthermore, neither RFC 8305 nor HEv3 mandates immediate retry upon receiving TCP RST. The pinned HEv3 reference is [`draft-ietf-happy-happyeyeballs-v3-04`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-04), published on 1 July 2026; it was an active Internet-Draft, not an RFC, at the 31 October 2026 report snapshot. This campaign primarily evaluates HTTP/1.1 over TCP. It does not test HTTP/3/QUIC, SVCB/HTTPS processing, cross-session statefulness or all HEv3 features.

## Repository guide

|Path|Purpose|
|-|-|
|[`lab/scenarios.yaml`](lab/scenarios.yaml)|Canonical S0–S6 scenario configuration|
|[`lab/run\_campaign.py`](lab/run_campaign.py)|Campaign matrix orchestration and manifest management|
|[`lab/run\_trial.py`](lab/run_trial.py)|Browser trial execution, PCAP parsing and classification|
|[`lab/analyze.py`](lab/analyze.py)|Offline validation, statistics and analysis outputs|
|[`lab/test\_\*.py`](lab/)|Test modules; suite contains 788 unit and regression tests across 21 modules (0 duplicate discovery)|
|[`lab/campaigns/ps028-a10-live-20261030-01/`](lab/campaigns/ps028-a10-live-20261030-01/)|Campaign manifest, trial results, captures, checksums, archives and summaries|
|[`lab/logs/unit\_tests\_run.log`](lab/logs/unit_tests_run.log)|Recorded local test-run output|
|[`lab/logs/ps028-a10-live-20261030-01.log`](lab/logs/ps028-a10-live-20261030-01.log)|Live campaign console log|
|[`PS028 Detailed Analysis & Report PDF.pdf`](PS028%20Detailed%20Analysis%20%26%20Report%20PDF.pdf)|Final technical report (AIORI submission PDF)|

## Reproduce offline analysis on Windows

The analyzer uses the Python standard library. These commands regenerate analysis outputs from the committed campaign data; they do **not** rerun the live network experiment.

Run from the repository root in PowerShell:

```powershell
py -3 --version
py -3 .\\lab\\analyze.py `
  --campaign-dir .\\lab\\campaigns\\ps028-a10-live-20261030-01 `
  --output-dir .\\analysis\_out `
  --resamples 1000 --seed 42
```

For the standalone portable ZIP, extract the bundle first. Its root contains `campaign/` and `lab/`; run from that extracted root:

```powershell
py -3 .\\lab\\analyze.py `
  --campaign-dir .\\campaign `
  --output-dir .\\analysis\_out `
  --resamples 1000 --seed 42
```

Live experiment execution is a separate Linux workflow requiring network namespaces, `nftables`, `iproute2` / `tc netem`, tcpdump, TShark, Nginx and the recorded browser builds. The Windows instructions above are for offline analysis only.

## Limitations and threats to validity

1. Results reflect one x86\_64 Ubuntu 24.04.5 / WSL2 environment and the recorded Chrome 156 and Firefox 159 builds. They should not be generalized to all releases, operating systems or networks.
2. The campaign covers HTTP/1.1 over TCP, not HTTPS/TLS behaviour, HTTP/3/QUIC or SVCB/HTTPS endpoint selection.
3. Ephemeral profiles isolate individual trials but do not measure persistent cross-session failure memory.
4. Browser telemetry is diagnostic and version-dependent; PCAPs are the primary network evidence.
5. The generic setup-time field and browser-duration/body-byte fields are not all directly comparable with the primary-flow PCAP metric.
6. The auxiliary `rfc8305\_assessment.csv` has been regenerated and verified against the 280 empirical trial results; its S2 and S6 assessments reflect laboratory observations under controlled network impairments and do not imply protocol non-conformance across unobserved releases.
7. The organizer's `Proposed-structure-hackathon.pdf` template has been inspected and integrated. The report structure adheres strictly to the organizer's 11-section Beamer slide and technical report layout.

## References

1. [RFC 8305 - Happy Eyeballs Version 2](https://www.rfc-editor.org/rfc/rfc8305.html), especially Sections 3–5.
2. [RFC 6724 - Default Address Selection for IPv6](https://www.rfc-editor.org/rfc/rfc6724.html).
3. [RFC 6555 - Happy Eyeballs: Success with Dual-Stack Hosts](https://www.rfc-editor.org/rfc/rfc6555.html), obsoleted by RFC 8305.
4. [RFC 6556 - Testing Eyeball Happiness](https://www.rfc-editor.org/rfc/rfc6556.html), informational measurement methodology.
5. [Happy Eyeballs v3 - draft-ietf-happy-happyeyeballs-v3-04](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-04), 1 July 2026; pinned Internet-Draft of record.
6. Sattler et al., [Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations](https://happy-eyeballs.github.io/), ACM IMC 2025.
7. APNIC, [Analysing the state of Happy Eyeballs implementations](https://blog.apnic.net/2025/10/07/analysing-the-state-of-happy-eyeballs-implementations/), 7 October 2025.
8. [IETF 126 Happy Eyeballs WebTester hackathon materials](https://datatracker.ietf.org/meeting/126/materials/slides-126-hackathon-sessd-happy-eyeballs-webtester-00).
9. [Happy Eyeballs WebTester source repository](https://github.com/happy-eyeballs/he-webtester).
10. [Chromium NetLog documentation](https://chromium.googlesource.com/chromium/src/+/main/net/docs/net-log.md).
11. [Firefox networking and HTTP logging documentation](https://firefox-source-docs.mozilla.org/networking/http/logging.html).
12. [`tc-netem` manual](https://man7.org/linux/man-pages/man8/tc-netem.8.html).

> [!NOTE]
> **Happy Eyeballs v3 Draft Status and Historical Baseline Notice (as of 13 November 2026)**
>
> - **Historical Experimental Baseline**: The October 2026 PS-028 campaign used [`draft-ietf-happy-happyeyeballs-v3-04`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-04), published on 1 July 2026. The campaign's methodology and historical RFC/draft assessments retain that revision as their immutable experimental reference.
> - **Subsequent Revision**: On 2 November 2026, the IETF published [`draft-ietf-happy-happyeyeballs-v3-05`](https://datatracker.ietf.org/doc/html/draft-ietf-happy-happyeyeballs-v3-05). As of 13 November 2026, this revision is an active Internet-Draft in the HAPPY Working Group, with intended status Standards Track (IESG state: I-D Exists, expiring on 6 May 2027). It is not a published RFC or finalized standard.
> - **Scope Limitation**: The October 2026 campaign predates publication of revision -05. Its historical observations and assessment results have not been evaluated or reclassified against revision -05. Revision -05 does not retroactively alter or invalidate the empirical findings obtained under revision -04.

\---

**Team AlgoRhythm** · *Measure. Compare. Improve.*

