Happy Eyeballs: IPv4/IPv6 Fallback Measurement
Team: AlgoRhythm  
Hackathon: AIORI 3  
Problem Statement: PS-028 - Internet Measurement  
Campaign: `ps028-a10-live-20261030-01`  
Verified evidence/code baseline: `a/lab-foundation` at `002c4453d35d6760760c6a14d2e98618b024f1f2`

Final technical report: `docs/PS028_Final_Experimental_Report.pdf`  
Team introduction video: https://youtu.be/5LLxlW9f6r4?si=LnVE9HOa_QhDM8y4
---
Abstract
This project measures how two existing browser clients establish connections in a controlled dual-stack laboratory when IPv6 is impaired by packet blackholing, active TCP reset, latency, packet loss or delayed DNS. A reproducible test harness applied six impairment scenarios plus a healthy baseline. The campaign completed 280 valid live trials (7 conditions x 2 browsers x 20 repetitions), with packet captures, browser telemetry, per-trial result records and cryptographic evidence indexes. The final analysis classifies 154 primary navigations as direct IPv6 (55.00%) and 126 as IPv4 fallback (45.00%). All 280 valid trials returned HTTP 200.
Scope: this is an empirical comparison of two pinned browser builds in one laboratory environment. It is not a new browser implementation and does not claim general RFC conformance.
1. Problem and objective
Dual-stack hostnames can return both A (IPv4) and AAAA (IPv6) records, while the two network paths may have different reachability or performance. A client that waits too long on a broken or impaired preferred path can increase connection latency. Happy Eyeballs coordinates address-family connection attempts so that a usable connection can be established without waiting for a long failure timeout.
The project objective is to observe connection racing in two existing clients under repeatable, controlled conditions using packet captures as the primary network evidence and browser telemetry as supporting evidence.
2. Experimental design
The PS requires six impaired dual-stack scenarios. The campaign includes S0 as an additional healthy control. The resulting matrix is 7 conditions x 2 browsers x 20 repetitions = 280 valid live trials.
The canonical source of scenario truth is `lab/scenarios.yaml`. The earlier README contained stale S2 and S4 descriptions; the final report and this README follow the canonical configuration.
ID	Canonical condition	Impairment applied
S0	`healthy_baseline`	IPv4 and IPv6 RTT approximately 20 ms; A and AAAA answers immediate
S1	`ipv6_syn_blackhole`	Silently drop IPv6 TCP SYN packets; keep IPv4 healthy
S2	`ipv6_tcp_rst`	Actively reject IPv6 TCP SYN with TCP RST; keep IPv4 healthy
S3	`ipv6_rtt_150ms`	Raise IPv6 RTT to approximately 150 ms; keep IPv4 near 20 ms
S4	`ipv6_rtt_600ms`	Raise IPv6 RTT to approximately 600 ms; keep IPv4 near 20 ms
S5	`ipv6_syn_loss_50pct`	Apply approximately 50% random loss to client-to-server IPv6 TCP SYN only
S6	`delay_aaaa_500ms`	Return A immediately and delay AAAA by 500 ms
3. Testbed and instrumentation
The laboratory uses three Linux network namespaces:
`ps028-cl`: dual-stack client namespace running headless Google Chrome and Mozilla Firefox with ephemeral profiles.
`ps028-rt`: forwarding/router namespace hosting controlled DNS and scenario-specific `nftables` rules.
`ps028-sv`: dual-stack Nginx HTTP/1.1 server at IPv4 `10.0.2.10` and IPv6 `2001:db8:2::10`.
`tc netem` applies deterministic link delay and `nftables` implements SYN blackholing, RST rejection and the S5 loss rule. Packet captures are taken on the client link. Each trial records a `result.json`, PCAP, packet-capture log and browser-specific diagnostic telemetry (Chrome NetLog or Firefox network log). Browser diagnostics supplement but do not replace packet evidence.
Recorded environment: Ubuntu 24.04.5 LTS on x86_64 WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`; Python 3.12.3; Google Chrome 156.0.8078.73; Mozilla Firefox 159.0; Nginx 1.24.0; tcpdump 4.99.4; TShark 4.2.2; nftables 1.0.9; `iproute2` / `tc netem`. These are the campaign environment values recorded in the report/runbook and should not be generalized to other hosts or releases.
4. Results
Winning address family
Scenario	Chrome direct IPv6	Chrome IPv4 fallback	Firefox direct IPv6	Firefox IPv4 fallback
S0	20	0	20	0
S1	0	20	0	20
S2	0	20	0	20
S3	20	0	20	0
S4	0	20	1	19
S5	18	2	15	5
S6	20	0	20	0
Total	98	42	56	84
Across the 280 primary navigations, 154 (55.00%) were direct IPv6 and 126 (45.00%) completed over IPv4 after an IPv6 attempt. HTTP 200 was recorded in 280/280 valid trials.
Main-document TCP timing from raw PCAPs
All 280 PCAPs were independently re-parsed to correlate the primary `GET /` request with its successful HTTP response on the same TCP stream. The audit found 280/280 primary flows, zero missing primary requests and zero disagreements between the primary-flow address family and the browser-reported winning family.
The table reports the interval from the main-document TCP SYN to the matching SYN/ACK on that same flow. It is a packet-derived RTT/connection-response proxy; it is not page-load time and does not include the final ACK or application readiness.
Scenario	Chrome median (IQR), ms	Firefox median (IQR), ms
S0	20.32 (0.07)	20.42 (0.16)
S1	20.96 (0.45)	20.41 (0.87)
S2	20.31 (0.10)	20.38 (0.24)
S3	150.65 (0.35)	150.39 (0.21)
S4	20.74 (0.72)	20.36 (0.15)
S5	20.46 (0.25)	20.50 (0.22)
S6	20.64 (0.50)	20.42 (0.30)
S4 Firefox includes one direct-IPv6 main flow with a 600.95 ms SYN-to-SYN/ACK interval; because there are 19 fallbacks and one direct trial, the median remains near 20 ms. The empirical p95 for S4 Firefox is 52.24 ms, and the maximum is 600.95 ms.
Per-scenario findings
S0 - healthy baseline: both browsers selected IPv6 in all 40 trials. The packet-derived main-flow medians were 20.32 ms (Chrome) and 20.42 ms (Firefox).
S1 - IPv6 SYN blackhole: all 40 trials completed over IPv4. Median first inter-family SYN interval: 300.83 ms (Chrome) and 408.45 ms (Firefox).
S2 - IPv6 TCP RST: all 40 trials completed over IPv4. Chrome's 20 packet-observed intervals ranged from 0.35 to 6.82 ms (median 0.71 ms); all were below the RFC 8305 Section 5 mandatory 10 ms inter-attempt floor. Firefox's 20 observations ranged from 130.78 to 336.23 ms (median 160.43 ms). These are build- and testbed-specific observations, not global browser compliance verdicts.
S3 - IPv6 RTT 150 ms: all 40 trials completed over IPv6; the main-flow packet interval was approximately 150 ms for both clients.
S4 - IPv6 RTT 600 ms: IPv4 won in 39/40 trials. One Firefox trial completed directly over IPv6; its main-flow SYN-to-SYN/ACK interval was 600.95 ms.
S5 - IPv6 SYN loss 50%: 33 main navigations completed over IPv6 (18 Chrome, 15 Firefox), and 7 completed over IPv4 (2 Chrome, 5 Firefox). Five apparent mixed-family cases included post-navigation ancillary IPv4 traffic (favicon or speculative preconnect); main-flow correlation keeps these as direct IPv6 navigations.
S6 - AAAA delayed 500 ms: all 40 trials completed over IPv6. Median A response latency was 4.83 ms (Chrome) and 0.83 ms (Firefox); median AAAA response latency was 505.20 ms and 502.56 ms respectively. In these tested builds the clients waited for the delayed AAAA response instead of starting IPv4 after the RFC 8305 Section 3 recommended 50 ms Resolution Delay.
5. Evidence quality and exclusions
Campaign manifest: 280/280 matrix slots completed, 282 total attempts, 280 valid live attempts, two preserved initial cleanup failures, zero simulations.
PCAP audit: 280 captures; 36,225 packets; no kernel/interface packet drops reported; 280/280 PCAP SHA-256 values match the PCAP checksum index.
Main-flow audit: 280 primary GET / flows found; zero missing and zero winning-family mismatches.
Offline analyzer: the portable bundle's analyzer was rerun; the regenerated CSV is byte-identical to the supplied summary CSV. The JSON numeric sections also reproduce; only generation timestamp and local paths for excluded attempts differ.
Complete evidence manifest: 1,410 file entries inside the complete TAR archive plus the separately delivered campaign execution log (1,411 checksum-indexed artifacts overall); all listed checksums matched.
Exclusions: one Firefox S0 preflight baseline-check failure (`Broken pipe`) and one Chrome S6 cleanup/root-privilege failure. Both were retained and retried under new trial IDs; neither enters the 280 valid measurements.
Test suite: the recorded local run reports `Ran 400 tests in 20.927s` and `OK`. This is a partner-side Linux run, not a GitHub Actions result.
6. Statistical methods and metric definitions
Sample size per scenario/browser cell: n=20 valid live trials.
Main-flow timing: median, IQR and empirical p95 from packet-derived SYN-to-matching-SYN/ACK intervals. The reported 95% median interval uses percentile bootstrap resampling, B=1,000, seed=42.
The campaign analyzer's other continuous metrics report median CIs by deterministic percentile bootstrap (B=1,000, seed=42), mean CIs by Student-t (df=n-1), and proportions by the ordinary Wilson score interval (no continuity correction).
The inter-family first-SYN interval is not necessarily fallback delay when an IPv4 flow is ancillary or speculative; interpret it with the primary navigation winner.
Do not compare `response_body_bytes` across browsers as HTTP payload size. The stored value is derived from browser process stdout length (308 bytes for Chrome and 72 bytes for Firefox). Browser-duration fields also arise from different output capture mechanisms and are not a like-for-like application-readiness metric. The generic stored `connection_setup_time_ms` differed by more than 1 ms from the raw-PCAP main-flow interval in 144/280 trials; the final report uses the explicitly correlated primary-flow metric for the timing comparison.
7. RFC interpretation and scope
RFC 8305 Section 3 describes asynchronous hostname resolution and the recommended 50 ms Resolution Delay when A arrives before AAAA. Section 5 describes connection attempts: a subsequent attempt MUST NOT begin within 10 ms of the previous attempt; the recommended minimum is 100 ms, the recommended default is 250 ms, and the recommended maximum is 2 seconds. The S2 Chrome observations below 10 ms warrant explicit reporting, but the result is limited to the tested Chrome build, testbed, and measured attempt pairs. No general conformance verdict is made.
The pinned HEv3 reference is `draft-ietf-happy-happyeyeballs-v3-04` (2 July 2026), an active Internet-Draft as of the 31 October 2026 report snapshot, not an RFC. This campaign primarily evaluates HTTP/1.1 over TCP and does not test HTTP/3/QUIC, SVCB/HTTPS processing, cross-session statefulness or all HEv3 features.
8. Repository map
Path	Purpose
`lab/scenarios.yaml`	Canonical S0-S6 scenario definitions
`lab/run_campaign.py`	Matrix orchestration and manifest management
`lab/run_trial.py`	Browser trial, PCAP parsing and classification
`lab/analyze.py`	Offline evidence validation, statistics and RFC-oriented output
`lab/test_*.py`	Test modules (400 test methods in the recorded suite)
`lab/campaigns/ps028-a10-live-20261030-01/`	Manifest, 280 results, PCAP checksums, archives and analysis summaries
`lab/logs/unit_tests_run.log`	Recorded test console output
`lab/logs/ps028-a10-live-20261030-01.log`	Live campaign console log
`docs/PS028_Final_Experimental_Report.pdf`	Final report prepared for this submission
9. Reproduce offline analysis on Windows
Python standard library is sufficient for the analyzer. From the repository root in PowerShell:
```powershell
py -3 --version
py -3 .\lab\analyze.py `
  --campaign-dir .\lab\campaigns\ps028-a10-live-20261030-01 `
  --output-dir .\analysis_out `
  --resamples 1000 --seed 42
```
For the standalone portable ZIP, extract the bundle. It contains `campaign/` and `lab/` at its root; from that extracted root run:
```powershell
py -3 .\lab\analyze.py `
  --campaign-dir .\campaign `
  --output-dir .\analysis_out `
  --resamples 1000 --seed 42
```
Live laboratory execution is a separate Linux-only workflow requiring network namespaces, nftables, `iproute2`/`tc netem`, tcpdump, TShark, Nginx and the recorded browser builds. The Windows instructions above cover offline analysis only.
10. Limitations and threats to validity
Results reflect one x86_64 Ubuntu 24.04.5 / WSL2 environment and the recorded Chrome 156 / Firefox 159 builds; they should not be generalized to all releases or operating systems.
The campaign covers HTTP/1.1 over TCP, not HTTPS/TLS behaviour, HTTP/3/QUIC or SVCB/HTTPS endpoint selection.
Ephemeral profiles isolate trials but do not measure stateful cross-session failure memory.
Browser internal telemetry is diagnostic and version-dependent; PCAPs are the primary network evidence.
The generic stored setup-time field and browser-duration/body-byte fields are not all directly comparable with the primary-flow PCAP metric.
`rfc8305_assessment.csv` is an auxiliary generated artifact with stale S2/S6 assessment wording and should be regenerated before use as a standards assessment. The report interprets S2/S6 from the raw per-trial evidence and relevant RFC sections.
The official `Proposed-structure-hackathon.pdf` itself was not among the supplied attachments; the report follows the 11-section sequence documented in the project study guide's G12 mapping. Verify against the organizer's template if it is later supplied.
11. References
RFC 8305 - Happy Eyeballs Version 2, especially Sections 3-5.
RFC 6724 - Default Address Selection for IPv6.
RFC 6555 - Happy Eyeballs: Success with Dual-Stack Hosts, obsoleted by RFC 8305.
RFC 6556 - Testing Eyeball Happiness, informational measurement methodology.
Happy Eyeballs v3 - draft-ietf-happy-happyeyeballs-v3-04, 2 July 2026; active Internet-Draft at the report snapshot.
Sattler et al., Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations, ACM IMC 2025.
APNIC, Analysing the state of Happy Eyeballs implementations, 7 October 2025.
IETF 126 Happy Eyeballs WebTester hackathon materials.
Happy Eyeballs WebTester source repository.
Chromium NetLog documentation.
Firefox networking and HTTP logging documentation.
`tc-netem` manual.

Team AlgoRhythm - Measure. Compare. Improve. Compare. Improve.**
