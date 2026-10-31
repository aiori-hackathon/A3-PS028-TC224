Happy Eyeballs: IPv4/IPv6 Fallback Measurement
Team AlgoRhythm · AIORI Hackathon 3 · PS-028: Internet Measurement
![280 valid live trials](https://img.shields.io/badge/valid%20live%20trials-280-168F83?style=flat-square) ![400 tests passed](https://img.shields.io/badge/recorded%20tests-400%20passed-2866B2?style=flat-square) ![Campaign completed](https://img.shields.io/badge/campaign-completed-168F83?style=flat-square)
Submission detail	Value
Campaign	`ps028-a10-live-20261030-01`
Evidence and code baseline	Branch `a/lab-foundation` · commit `002c4453d35d6760760c6a14d2e98618b024f1f2`
Final technical report	`docs/PS028_Final_Experimental_Report.pdf`
Team introduction	Watch on YouTube
Campaign evidence	`lab/campaigns/ps028-a10-live-20261030-01/`
---
Contents
Project summary
Problem and objective
Experimental design
Testbed and instrumentation
Results
Evidence quality and exclusions
Statistical methods and metric definitions
RFC interpretation and scope
Repository guide
Reproduce offline analysis on Windows
Limitations and threats to validity
References
Submission checklist
---
Project summary
This project measures how two existing browser clients establish connections in a controlled dual-stack laboratory when IPv6 is impaired by a TCP SYN blackhole, active TCP reset, additional latency, packet loss or delayed DNS. The test harness runs six impairment scenarios required by PS-028 plus a healthy baseline control.
The completed campaign contains 280 valid live trials: seven conditions × two browsers × 20 repetitions. The primary-navigation analysis classified 154 trials (55.00%) as direct IPv6 and 126 trials (45.00%) as IPv4 fallback. All 280 valid trials returned HTTP 200.
> **Scope:** These are empirical observations from two pinned browser builds in one laboratory environment. This project does not implement a new browser stack and does not claim general RFC conformance.
Problem and objective
A dual-stack hostname can return both A (IPv4) and AAAA (IPv6) records, while the corresponding network paths differ in reachability or latency. A client that waits too long on an impaired preferred path can increase connection-establishment time. Happy Eyeballs coordinates connection attempts across available address families so that a usable path can be selected without waiting for a long failure timeout.
The objective is to compare two existing browsers under repeatable, controlled conditions. Packet captures provide the primary network evidence; browser telemetry is retained as supporting diagnostic evidence.
Experimental design
The PS-028 brief calls for six controlled impairment scenarios. S0 is an additional healthy baseline, so the campaign contains seven conditions in total. The canonical scenario definitions are maintained in `lab/scenarios.yaml`.
ID	Canonical scenario	Controlled condition	Measurement purpose
S0	`healthy_baseline`	IPv4 and IPv6 RTT approximately 20 ms; A and AAAA answers immediate	Healthy dual-stack reference
S1	`ipv6_syn_blackhole`	IPv6 TCP SYN packets are silently dropped; IPv4 remains healthy	Observe recovery from an unresponsive IPv6 path
S2	`ipv6_tcp_rst`	IPv6 TCP SYN is actively rejected with TCP RST; IPv4 remains healthy	Observe response to active IPv6 rejection
S3	`ipv6_rtt_150ms`	IPv6 RTT approximately 150 ms; IPv4 approximately 20 ms	Compare a moderately slower IPv6 path
S4	`ipv6_rtt_600ms`	IPv6 RTT approximately 600 ms; IPv4 approximately 20 ms	Compare a severely slower IPv6 path
S5	`ipv6_syn_loss_50pct`	Approximately 50% random loss on client-to-server IPv6 TCP SYN only	Observe behaviour under partial SYN loss
S6	`delay_aaaa_500ms`	A response is immediate; AAAA response is delayed by 500 ms	Observe address-family selection under delayed AAAA resolution
Clients and repetitions
Client	Recorded build	Valid repetitions per condition
Google Chrome	`156.0.8078.73`	20
Mozilla Firefox	`159.0`	20
Total	2 browser builds	280 valid trials
Testbed and instrumentation
The experiment uses three isolated Linux network namespaces:
Namespace	Role	Main components
`ps028-cl`	Dual-stack client	Chrome 156, Firefox 159, ephemeral browser profiles, client-link PCAP capture
`ps028-rt`	Router and DNS	IPv4/IPv6 forwarding, controlled DNS service, scenario-specific `nftables` rules, `tc netem` delay/loss
`ps028-sv`	Origin server	Nginx HTTP/1.1 endpoint, IPv4 `10.0.2.10`, IPv6 `2001:db8:2::10`
`nftables` applies the IPv6 SYN blackhole, TCP reset and S5 packet-loss conditions. `tc netem` applies the configured link delays. Each trial records a `result.json`, packet capture, capture log and browser diagnostic telemetry (Chrome NetLog or Firefox network log). Browser diagnostics supplement, but do not replace, packet-level evidence.
Recorded campaign environment
Component	Recorded version / configuration
Operating system	Ubuntu 24.04.5 LTS, x86_64 WSL2 host
Kernel	`6.18.54.1-microsoft-standard-WSL2`
Python	`3.12.3`
Nginx	`1.24.0`
tcpdump	`4.99.4`
TShark	`4.2.2`
nftables	`1.0.9`
Traffic control	`iproute2` / `tc netem`
These values describe the environment recorded for this campaign; they are not a compatibility guarantee for other hosts or software releases.
Results
Winning address family
The winner is classified from the address family of the primary HTTP `GET /` document request and its successful response on the same TCP stream. An IPv4 favicon request or speculative preconnect after an IPv6 document success is not counted as a main-navigation fallback.
Scenario	Chrome direct IPv6	Chrome IPv4 fallback	Firefox direct IPv6	Firefox IPv4 fallback
S0	20	0	20	0
S1	0	20	0	20
S2	0	20	0	20
S3	20	0	20	0
S4	0	20	1	19
S5	18	2	15	5
S6	20	0	20	0
Total	98	42	56	84

Overall outcome	Trials	Share
Direct IPv6 primary navigation	154	55.00%
IPv4 primary navigation after IPv6 attempt	126	45.00%
Total HTTP 200 responses	280 / 280	100%
Primary-document TCP timing from raw PCAPs
All 280 packet captures were independently re-parsed. The primary `GET /` request was found in all 280 captures, and its TCP stream was correlated with the successful HTTP response. The primary-flow address family agreed with the browser-reported winner in all 280 trials.
The values below are the interval from the primary-document TCP SYN to the matching server SYN/ACK on the same stream. This is a packet-derived connection-response / RTT proxy; it is not page-load time and does not include the final ACK or application readiness.
Scenario	Chrome median (IQR), ms	Firefox median (IQR), ms
S0	20.32 (0.07)	20.42 (0.16)
S1	20.96 (0.45)	20.41 (0.87)
S2	20.31 (0.10)	20.38 (0.24)
S3	150.65 (0.35)	150.39 (0.21)
S4	20.74 (0.72)	20.36 (0.15)
S5	20.46 (0.25)	20.50 (0.22)
S6	20.64 (0.50)	20.42 (0.30)
S4 Firefox includes one direct-IPv6 main flow with a 600.95 ms SYN-to-SYN/ACK interval. Since the other 19 trials fell back to IPv4, the median remains near 20 ms; the empirical p95 is 52.24 ms and the maximum is 600.95 ms.
Findings by scenario
Scenario	Observed result	Interpretation
S0	Both browsers selected IPv6 in all 40 trials.	The healthy baseline behaved as expected in this testbed.
S1	All 40 trials completed over IPv4. Median first inter-family SYN interval: 300.83 ms (Chrome), 408.45 ms (Firefox).	Both clients recovered from the IPv6 SYN blackhole. The interval is attempt pacing, not the main-flow connection time.
S2	All 40 trials completed over IPv4. Chrome's 20 observed intervals were 0.35–6.82 ms (median 0.71 ms); Firefox's were 130.78–336.23 ms (median 160.43 ms).	Every observed Chrome interval was below RFC 8305's 10 ms mandatory inter-attempt floor. This is limited to the measured Chrome build, testbed and attempt pairs; no general browser conformance verdict is made.
S3	All 40 trials completed over IPv6. Main-flow packet interval was approximately 150 ms for both clients.	The slower IPv6 path still won in this 150 ms condition.
S4	IPv4 won in 39/40 trials. One Firefox trial completed directly over IPv6 at 600.95 ms.	The 600 ms IPv6 condition produced fallback in nearly all trials, with one slow direct IPv6 success.
S5	33 main navigations completed over IPv6 (18 Chrome, 15 Firefox); seven completed over IPv4 (two Chrome, five Firefox).	Flow correlation prevents ancillary IPv4 favicon or speculative preconnect traffic from being misclassified as fallback.
S6	All 40 trials completed over IPv6. Median A latency: 4.83 ms (Chrome), 0.83 ms (Firefox). Median AAAA latency: 505.20 ms and 502.56 ms respectively.	In these builds, the primary navigation waited for the delayed AAAA response; no IPv4 primary navigation was observed after the recommended 50 ms Resolution Delay.
Evidence quality and exclusions
Validation item	Recorded result
Planned / completed matrix slots	280 / 280
Total attempts / valid live trials	282 / 280
Preserved initial cleanup failures	2, both retried with new trial IDs and excluded from valid results
Simulated trials	0
Valid HTTP 200 responses	280 / 280
PCAP captures / PCAP checksum matches	280 / 280
PCAP packet count / reported capture drops	36,225 / 0
Primary `GET /` flows found	280 / 280
Primary-flow / browser winner disagreements	0
Recorded local test run	400 tests; final test-runner status `OK`
The two excluded attempts were a Firefox S0 preflight baseline self-test failure (`Broken pipe`) and a Chrome S6 cleanup failure caused by a helper operation requiring root privileges. Both records remain in the evidence trail and were retried using unique trial IDs. The 400-test record is a partner-side local run, not a GitHub Actions result.
The complete evidence checksum index contains 1,411 checksum-indexed artifacts, reconciling the campaign execution log with the archived evidence. The complete archive and the portable analysis ZIP serve different purposes: the complete archive preserves captures and telemetry; the portable bundle provides the analysis inputs and code for offline regeneration.
Statistical methods and metric definitions
Item	Definition
Sample size	`n = 20` valid live trials per scenario and browser
Main-flow timing	Median, IQR and empirical p95 from primary-flow SYN-to-matching-SYN/ACK intervals
Median confidence interval	Deterministic percentile bootstrap, `B = 1,000`, seed `42`
Mean confidence interval in analyzer outputs	Student-t interval, `df = n - 1`
Proportion confidence interval in analyzer outputs	Ordinary Wilson score interval, without continuity correction
Inter-family first-SYN interval	Descriptive first IPv6/IPv4 SYN spacing; not necessarily a fallback delay if an observed connection is ancillary or speculative
Metric cautions
`response_body_bytes` is browser-process stdout length (308 bytes for Chrome and 72 bytes for Firefox), not the HTTP payload size.
Browser-duration outputs arise from different capture mechanisms and are not a like-for-like application-readiness measure.
The generic stored `connection_setup_time_ms` differed by more than 1 ms from the raw-PCAP primary-flow interval in 144/280 trials. The timing comparison therefore uses the explicitly defined primary-flow packet metric.
`rfc8305_assessment.csv` is an auxiliary generated artifact with stale S2/S6 assessment wording. Use the per-trial records and report interpretation for those cases; regenerate that CSV before relying on it as a standards assessment.
RFC interpretation and scope
RFC 8305 Section 3 covers asynchronous hostname resolution and recommends a 50 ms Resolution Delay when A arrives before AAAA. Section 5 specifies that a subsequent connection attempt MUST NOT begin within 10 ms of the previous attempt. The recommended minimum Connection Attempt Delay is 100 ms, the recommended default is 250 ms and the recommended maximum is 2 seconds.
The Chrome S2 observations below 10 ms are reported explicitly, but they do not support a general conformance verdict for Chrome or other browsers. The pinned HEv3 reference is `draft-ietf-happy-happyeyeballs-v3-04`, dated 2 July 2026; it was an active Internet-Draft, not an RFC, at the 31 October 2026 report snapshot. This campaign primarily evaluates HTTP/1.1 over TCP. It does not test HTTP/3/QUIC, SVCB/HTTPS processing, cross-session statefulness or all HEv3 features.
Repository guide
Path	Purpose
`lab/scenarios.yaml`	Canonical S0–S6 scenario configuration
`lab/run_campaign.py`	Campaign matrix orchestration and manifest management
`lab/run_trial.py`	Browser trial execution, PCAP parsing and classification
`lab/analyze.py`	Offline validation, statistics and analysis outputs
`lab/test_*.py`	Test modules; the recorded suite reports 400 tests
`lab/campaigns/ps028-a10-live-20261030-01/`	Campaign manifest, trial results, captures, checksums, archives and summaries
`lab/logs/unit_tests_run.log`	Recorded local test-run output
`lab/logs/ps028-a10-live-20261030-01.log`	Live campaign console log
`docs/PS028_Final_Experimental_Report.pdf`	Final technical report
Reproduce offline analysis on Windows
The analyzer uses the Python standard library. These commands regenerate analysis outputs from the committed campaign data; they do not rerun the live network experiment.
Run from the repository root in PowerShell:
```powershell
py -3 --version
py -3 .\lab\analyze.py `
  --campaign-dir .\lab\campaigns\ps028-a10-live-20261030-01 `
  --output-dir .\analysis_out `
  --resamples 1000 --seed 42
```
For the standalone portable ZIP, extract the bundle first. Its root contains `campaign/` and `lab/`; run from that extracted root:
```powershell
py -3 .\lab\analyze.py `
  --campaign-dir .\campaign `
  --output-dir .\analysis_out `
  --resamples 1000 --seed 42
```
Live experiment execution is a separate Linux workflow requiring network namespaces, `nftables`, `iproute2` / `tc netem`, tcpdump, TShark, Nginx and the recorded browser builds. The Windows instructions above are for offline analysis only.
Limitations and threats to validity
Results reflect one x86_64 Ubuntu 24.04.5 / WSL2 environment and the recorded Chrome 156 and Firefox 159 builds. They should not be generalized to all releases, operating systems or networks.
The campaign covers HTTP/1.1 over TCP, not HTTPS/TLS behaviour, HTTP/3/QUIC or SVCB/HTTPS endpoint selection.
Ephemeral profiles isolate individual trials but do not measure persistent cross-session failure memory.
Browser telemetry is diagnostic and version-dependent; PCAPs are the primary network evidence.
The generic setup-time field and browser-duration/body-byte fields are not all directly comparable with the primary-flow PCAP metric.
The auxiliary `rfc8305_assessment.csv` should be regenerated before it is used as a standards assessment because its S2/S6 narrative is stale.
The organizer's `Proposed-structure-hackathon.pdf` was not included in the supplied materials. The report follows the 11-section sequence documented in the project's study-guide mapping; verify against the organizer's template if it is later supplied.
References
RFC 8305 - Happy Eyeballs Version 2, especially Sections 3–5.
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
Submission checklist
[x] Controlled dual-stack lab and six impaired scenarios plus healthy baseline.
[x] Two pinned existing browser builds.
[x] 20 valid repetitions per scenario/browser cell.
[x] Trial records, PCAPs, logs, browser telemetry and checksum indexes preserved.
[x] Primary HTTP navigation flow audited from all 280 PCAPs.
[x] Offline analysis reproduced from portable evidence.
[x] Recorded test run: 400 tests; final test-runner status `OK`.
[ ] Add `docs/PS028_Final_Experimental_Report.pdf` to GitHub.
[ ] Demonstrate the prototype and pseudocode to the mentor.
[ ] Confirm the organizer's private-repository, collaborator and ownership requirements; the current repository is named `A3-PS028-TC224`, not `AlgoRhythm`.
[ ] Check against the organizer's `Proposed-structure-hackathon.pdf` if it becomes available.
---
Team AlgoRhythm · Measure. Compare. Improve.
