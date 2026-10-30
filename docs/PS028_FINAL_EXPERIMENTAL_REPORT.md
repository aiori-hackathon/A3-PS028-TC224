# PS-028 Final Experimental Results and Validation Report

**Campaign ID:** `ps028-a10-live-20261030-01`
**Manifest Status:** `COMPLETED`
**Completion Timestamp:** `2026-10-29T22:57:12.728189+00:00`
**Audited Date:** 2026-10-30
**Laboratory Testbed:** `~/projects/he-webtester`
**Document Classification:** Final Technical Validation Report (Work Package A10)

---

## 1. Executive Summary

This report documents the final experimental validation of the PS-028 Happy Eyeballs measurement campaign (`ps028-a10-live-20261030-01`), executed within the isolated dual-stack Linux network namespace testbed of `~/projects/he-webtester`. The campaign evaluated the connection establishment and fallback dynamics of modern production web browsers under systematic physical-layer, transport-layer, and DNS impairments conforming to RFC 8305 (Happy Eyeballs Version 2).

The measurement matrix comprised **280 planned cells** covering 7 scenarios (S0–S6), 2 browser runtimes (**Google Chrome 156.0.8078.73** and **Mozilla Firefox 159.0**), and 20 sequential repetitions per cell. A total of **282 execution attempts** were recorded:
- **280 attempts** achieved `VALID_LIVE` status with verified PCAP captures, valid cryptographic checksums, positive packet counts, zero packet drops, and HTTP 200 responses.
- **2 historical attempts** recorded `CLEANUP_FAILURE` during initial preflight checks; both were safely retried under new, unique trial identifiers during campaign resume, and their historical records are preserved in full.

Overall connection classification under the canonical PS-028 packet-based rule yielded **154 `DIRECT_IPV6`** connections (55.00%) and **126 `IPV6_TO_IPV4_FALLBACK`** connections (45.00%). Both browsers exhibited 100% IPv6 preference under healthy baseline conditions (S0) and successfully fell back to IPv4 under IPv6 SYN blackholing (S1) and IPv6 TCP RST rejection (S2). However, under delayed DNS AAAA resolution (S6), both Chrome and Firefox waited ~500ms for delayed AAAA responses rather than triggering an IPv4 fallback after the RFC 8305 recommended 50ms Resolution Delay, subsequently connecting directly over IPv6. In Scenario S5 (50% SYN loss), 33 trials connected over IPv6 (including 5 trials with post-navigation ancillary or speculative IPv4 traffic) and 7 trials fell back to IPv4.

All 280 valid trial PCAPs and result records were independently audited and verified against the finalized manifest. The testbed baseline state was validated clean, and the entire lab test suite of **396 tests** passes without errors.

---

## 2. Problem Statement and Research Objectives

As the Internet transitions toward IPv6-mostly and IPv6-first architectures, dual-stack end systems must navigate dual-stack network environments where IPv6 connectivity may be partially broken, blackholed, misconfigured, or subject to severe routing asymmetries. A naive dual-stack client implementation that attempts IPv6 connection establishment with a standard TCP connection timeout (often 21 to 75 seconds) infers dual-stack brokenness directly to the end user as unacceptable application latency or perceived network failure.

To address this challenge, the IETF standardized the Happy Eyeballs algorithm (originally RFC 6555, revised in RFC 8305). Happy Eyeballs specifies client connection algorithms designed to prefer IPv6 while initiating asynchronous or delayed connection attempts to IPv4 addresses.

The research objectives of the PS-028 campaign are:
1. **Empirical Verification:** Quantitatively observe and measure Happy Eyeballs connection attempt scheduling, connection attempt delay (CAD) timers, and address family selection in modern production browsers (Google Chrome and Mozilla Firefox) under rigorously controlled network conditions.
2. **Standard Conformance Assessment:** Assess empirical browser behavior against normative and informative requirements of RFC 8305, including IPv6 preference, CAD floor and default recommendations, immediate fallback upon TCP RST, and Resolution Delay when AAAA records are delayed relative to A records.
3. **Reproducible Experimental Architecture:** Construct a fully automated, reproducible, unprivileged-safe testbed that enforces strictly sequential trial execution, isolated browser profiles, comprehensive traffic capture, and automated post-trial baseline cleanup.

---

## 3. Happy Eyeballs IPv4/IPv6 Connection Behavior

RFC 8305 defines the operational state machine for initiating dual-stack transport connections:

```
+-------------------------------------------------------------+
| DNS Resolution: Initiate concurrent A and AAAA queries     |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| Address Sorting: Interleave families (prefer IPv6 first)    |
+-------------------------------------------------------------+
                               |
                               v
+-------------------------------------------------------------+
| Primary Attempt: Initiate TCP SYN to first address (IPv6)  |
+-------------------------------------------------------------+
                               |
             +-----------------+-----------------+
             |                                   |
             | SYN-ACK received                  | CAD timer expires
             v                                   | (or immediate TCP RST)
+-------------------------+                      v
| IPv6 Wins: Complete 3WHS|       +-----------------------------+
| Cancel secondary attempts|      | Fallback Attempt: Initiate  |
+-------------------------+       | TCP SYN to IPv4 address     |
                                  +-----------------------------+
                                                 |
                                                 v
                                  +-----------------------------+
                                  | First to Complete Wins      |
                                  | (IPv4 or IPv6)              |
                                  +-----------------------------+
```

Key timing parameters specified in RFC 8305 include:
- **Connection Attempt Delay (CAD) Timer (Section 5):** The delay between initiating a connection attempt to the preferred address family (IPv6) and initiating a fallback attempt to the secondary family (IPv4). RFC 8305 mandates that CAD **MUST NOT** be smaller than 10ms, **SHOULD NOT** be smaller than 100ms, defines a recommended default of **250ms**, and specifies a maximum of **2000ms**.
- **Immediate Fallback on Connection Failure (Section 5):** If the primary connection attempt fails immediately due to an active network rejection (such as an ICMP Port Unreachable or TCP RST), the client **SHOULD** immediately initiate a connection attempt to the next address family without awaiting the CAD timer expiration.
- **Resolution Delay (Section 4):** When asynchronous DNS responses arrive with the IPv4 (A) response arriving before the IPv6 (AAAA) response, the client **SHOULD** wait for a recommended delay of **50ms** before initiating an IPv4 connection, giving the preferred AAAA response an opportunity to arrive.

---

## 4. Experimental Architecture and Network Topology

The PS-028 testbed isolates client, network impairment, routing, DNS, and HTTP server functions into dedicated Linux network namespaces. The physical topology employs a three-tier architecture with separate veth pairs for IPv4 and IPv6 on the server leg:

```
+-------------------+                       +-------------------+                       +-------------------+
|   Client Netns    |                       |   Router Netns    |                       |   Server Netns    |
|    (ps028-cl)     |                       |    (ps028-rt)     |                       |    (ps028-sv)     |
|                   |                       |                   |                       |                   |
|                   |                       |  nftables / netem |                       | Nginx HTTP Server |
|                   |                       |  Impairment Engine|                       |  10.0.2.10:80     |
|  [ps028-cl-rt]    |<=====================>|   [ps028-rt-cl]   |                       | [2001:db8:2::10]:80|
|  10.0.1.2/24      |   Shared Dual-Stack   |   10.0.1.1/24     |                       |                   |
| 2001:db8:1::2/64  |       veth link       | 2001:db8:1::1/64  |                       |                   |
|                   |                       |                   |                       |                   |
|                   |                       |  [ps028-rt-sv4]   |<=====================>|   [ps028-sv-rt4]  |
|                   |                       |   10.0.2.1/24     |    IPv4 Dedicated     |   10.0.2.10/24    |
|                   |                       |                   |       veth link       |                   |
|                   |                       |  [ps028-rt-sv6]   |<=====================>|   [ps028-sv-rt6]  |
|                   |                       | 2001:db8:2::1/64  |    IPv6 Dedicated     | 2001:db8:2::10/64 |
+-------------------+                       +-------------------+       veth link       +-------------------+
          |                                           ^
          | DNS Queries (UDP/53)                      | Controlled DNS Server
          +-------------------------------------------+ (10.0.1.1:53)
```

By decoupling the router-to-server segment into independent IPv4 (`ps028-rt-sv4` $\leftrightarrow$ `ps028-sv-rt4`) and IPv6 (`ps028-rt-sv6` $\leftrightarrow$ `ps028-sv-rt6`) interfaces, transport-layer and traffic-control impairments (tc netem and nftables) can be applied to one address family with mathematical precision without cross-contaminating the other family.

### Baseline Path Latencies
In the healthy baseline state (Scenario S0), symmetric tc netem delays of **10ms** are installed on each server-facing interface (`ps028-rt-sv4`, `ps028-sv-rt4`, `ps028-rt-sv6`, `ps028-sv-rt6`). This establishes an identical **20ms round-trip time (RTT)** baseline for both IPv4 and IPv6 paths, eliminating RTT bias during address family selection.

---

## 5. Client, Router, DNS and Server Namespace Configuration

### Namespace Addressing Scheme

| Namespace | Interface Name | IPv4 Address | IPv6 Address | Function |
| :--- | :--- | :--- | :--- | :--- |
| **`ps028-cl`** | `ps028-cl-rt` | `10.0.1.2/24` | `2001:db8:1::2/64` | Client namespace executing browser runtimes |
| **`ps028-rt`** | `ps028-rt-cl` | `10.0.1.1/24` | `2001:db8:1::1/64` | Router interface facing client; DNS endpoint |
| **`ps028-rt`** | `ps028-rt-sv4`| `10.0.2.1/24` | — | Router interface facing server IPv4 |
| **`ps028-rt`** | `ps028-rt-sv6`| — | `2001:db8:2::1/64` | Router interface facing server IPv6 |
| **`ps028-sv`** | `ps028-sv-rt4`| `10.0.2.10/24`| — | Server interface receiving IPv4 traffic |
| **`ps028-sv`** | `ps028-sv-rt6`| — | `2001:db8:2::10/64`| Server interface receiving IPv6 traffic |

### DNS Namespace Architecture
DNS resolution inside `ps028-cl` is strictly isolated using Linux network namespace configuration:
- The host directory `/etc/netns/ps028-cl/resolv.conf` is mounted to override DNS inside `ps028-cl`, configured with `nameserver 10.0.1.1`.
- A controlled Python DNS server (`lab/dns_server.py`) listens on `10.0.1.1:53`.
- The DNS server dynamically parses `lab/dns_config.json` and supports wildcard resolution for `*.he.test`, resolving:
  - `A` queries to `10.0.2.10`
  - `AAAA` queries to `2001:db8:2::10`
- The DNS server incorporates a programmable delay engine that delays query responses on a per-record-type basis (`A_delay_ms` and `AAAA_delay_ms`).

### Measurement Endpoint Configuration
An Nginx HTTP measurement server runs in namespace `ps028-sv`, listening on both `10.0.2.10:80` and `[2001:db8:2::10]:80`. The server delivers an identical static HTML document containing metadata regarding supported address families.

---

## 6. Browser Versions, Execution Isolation and Measurement Instrumentation

### Browser Runtimes

| Runtime | Binary Executable Path | Version String | Execution Architecture |
| :--- | :--- | :--- | :--- |
| **Google Chrome** | `/usr/bin/google-chrome` | `Google Chrome 156.0.8078.73` | Headless (`--headless=new`) with `--dump-dom` |
| **Mozilla Firefox** | `/home/indrani/opt/firefox-measurement/firefox` | `Mozilla Firefox 159.0` | Headless (`--headless`) standalone binary |

### Execution Isolation
To ensure experimental independence and prevent cross-trial state contamination:
1. **Unprivileged Process Context:** Browsers are executed inside the `ps028-cl` namespace under target non-root user UID/GID (`indrani`, UID 1000) using `setpriv --reuid=1000 --regid=1000 --init-groups`.
2. **Ephemeral Profiles:** Every trial allocates a freshly generated, isolated temporary profile directory (`--user-data-dir` for Chrome; `--profile` for Firefox). Profile paths are completely unlinked and removed immediately following trial execution.
3. **Cache Elimination:** Hardened command-line flags disable background networking, component updates, domain reliability, crash reporting, session restore, predictive prefetching, and disk caching.

### Measurement Instrumentation
Each trial collects evidence across three independent observation planes:
1. **Packet Capture (`capture.pcap`):** `tcpdump` runs directly inside `ps028-cl` on interface `ps028-cl-rt`, capturing all inbound and outbound Ethernet frames without packet truncations (`-s 0`).
2. **Chromium NetLog (`netlog.json`):** Chrome writes socket pool, connect job, and HTTP transaction events via `--log-net-log`.
3. **Firefox Internal Telemetry (`browser_telemetry.log`):** Firefox internal socket transport and HTTP transactions are captured using environment flags:
   ```bash
   MOZ_LOG="sync,timestamp,nsHttp:5,nsSocketTransport:5"
   ```

---

## 7. Detailed Scenario Definitions S0–S6 and Intended Impairments

The canonical scenario configuration is maintained in [`lab/scenarios.yaml`](file:///home/indrani/projects/he-webtester/lab/scenarios.yaml).

| ID | Canonical Name | Target Family | Mechanism | Configured Impairment |
| :--- | :--- | :--- | :--- | :--- |
| **S0** | `healthy_baseline` | None | Baseline | IPv4 RTT: 20ms, IPv6 RTT: 20ms. Baseline 0ms DNS delay. |
| **S1** | `ipv6_syn_blackhole` | IPv6 | `nftables` | Client-to-server IPv6 TCP SYN packets silently discarded (`drop`). |
| **S2** | `ipv6_tcp_rst` | IPv6 | `nftables` | Client-to-server IPv6 TCP SYN rejected with `reject with tcp reset`. |
| **S3** | `ipv6_rtt_150ms` | IPv6 | `tc netem` | Router netem delay increased to 75ms on IPv6 links $\rightarrow$ 150ms RTT. |
| **S4** | `ipv6_rtt_600ms` | IPv6 | `tc netem` | Router netem delay increased to 300ms on IPv6 links $\rightarrow$ 600ms RTT. |
| **S5** | `ipv6_syn_loss_50pct`| IPv6 | `nftables` | Client IPv6 TCP SYN packets dropped with 50% probability (`drop`). |
| **S6** | `delay_aaaa_500ms` | DNS (AAAA)| `dns_server` | AAAA DNS responses delayed by 500ms; A responses remain immediate. |

---

## 8. Experimental Methodology

The campaign runner ([`lab/run_campaign.py`](file:///home/indrani/projects/he-webtester/lab/run_campaign.py)) coordinates strictly sequential trial scheduling:

1. **Sequential Matrix Traversal:** The matrix loops across 20 repetitions, iterating through scenarios (S0–S6) and alternating between Google Chrome and Mozilla Firefox. Concurrent trials are strictly prevented by a system-wide lock file (`/tmp/.ps028_lab.lock`).
2. **Unique Trial Identifiers:** Each attempt generates a unique trial ID (`trial-<timestamp>-<hash>`) mapping to a dedicated directory under `trials/<trial_id>/`. Evidence is never overwritten.
3. **Fail-Stop Verification:** Prior to applying any scenario impairment, the preflight baseline check verifies that the testbed is healthy. Immediately after trial execution, impairments are restored to baseline and [`impair.self_test_baseline()`](file:///home/indrani/projects/he-webtester/lab/impair.py) executes. If any cleanup step fails or baseline verification deviates, the campaign immediately halts (`FAIL-STOP`) to prevent contaminated measurements.
4. **Atomic Manifest Persistence:** Progress is written to `campaign_manifest.json` atomically via temporary file rename under directory lock (`.campaign.lock`).

---

## 9. Campaign Configuration and Trial Matrix

The finalized live campaign `ps028-a10-live-20261030-01` executed the complete $7 \times 2 \times 20$ matrix:

- **Total Planned Matrix Slots:** 280
- **Total Completed Matrix Slots:** 280 (100.0%)
- **Repetitions per Cell:** 20
- **Browsers Evaluated:** Google Chrome 156 (`google-chrome`), Mozilla Firefox 159 (`firefox`)
- **Execution Mode:** `LIVE` (real browser processes, network namespaces, and traffic capture)

### Slot and Attempt Accounting

```
Planned Matrix Slots: 280
├── Executed with 1 Attempt:  278 slots (278 VALID_LIVE)
└── Executed with 2 Attempts:   2 slots (2 CLEANUP_FAILURE + 2 VALID_LIVE retries)
                              ─────────────────────────────────────────────────
                              Total Attempts Recorded: 282
                              Valid Live Attempts Ingested: 280
```

---

## 10. Results by Scenario and Browser

Statistical metrics were computed across all 280 valid live trials using the PS-028 statistical analysis engine ([`lab/analyze.py`](file:///home/indrani/projects/he-webtester/lab/analyze.py)). All confidence intervals (CI) represent 95% intervals computed via deterministic bootstrap resampling ($N = 10{,}000$, seed = 42) for continuous metrics and Wilson score intervals for binomial proportions.

### Comprehensive Summary Table

| Browser | Scen | $N$ | HTTP 200 | Direct IPv6 | Fallback IPv4 | Setup Time (ms) Median [IQR] | CAD (ms) Median [IQR] | DNS A (ms) Median | DNS AAAA (ms) Median |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Firefox** | S0 | 20 | 100% | 20 | 0 | 20.64 [392.28] | — | 0.82 | 1.27 |
| **Firefox** | S1 | 20 | 100% | 0 | 20 | 20.41 [0.38] | 408.45 [149.33] | 0.84 | 1.36 |
| **Firefox** | S2 | 20 | 100% | 0 | 20 | 21.32 [278.43] | 160.43 [86.91] | 0.77 | 1.33 |
| **Firefox** | S3 | 20 | 100% | 20 | 0 | 281.25 [379.88] | — | 0.81 | 1.32 |
| **Firefox** | S4 | 20 | 100% | 1 | 19 | 20.36 [0.55] | 397.94 [46.85] | 0.86 | 1.41 |
| **Firefox** | S5 | 20 | 100% | 15 | 5 | 20.50 [3.37] | 392.86 [24.49] | 0.80 | 1.40 |
| **Firefox** | S6 | 20 | 100% | 20 | 0 | 20.60 [0.68] | — | 0.83 | 502.56 |
| **Chrome** | S0 | 20 | 100% | 20 | 0 | 24.02 [4.58] | — | 2.98 | 2.18 |
| **Chrome** | S1 | 20 | 100% | 0 | 20 | 23.53 [4.51] | 300.83 [0.73] | 2.54 | 1.80 |
| **Chrome** | S2 | 20 | 100% | 0 | 20 | 24.52 [5.33] | 0.71 [0.32] | 2.60 | 1.95 |
| **Chrome** | S3 | 20 | 100% | 20 | 0 | 154.67 [5.08] | — | 2.58 | 2.04 |
| **Chrome** | S4 | 20 | 100% | 0 | 20 | 25.68 [3.82] | 300.81 [1.02] | 2.98 | 2.04 |
| **Chrome** | S5 | 20 | 100% | 18 | 2 | 23.88 [4.49] | 300.96 [1.08] | 3.39 | 2.13 |
| **Chrome** | S6 | 20 | 100% | 20 | 0 | 21.09 [0.46] | — | 4.83 | 505.20 |

---

## 11. Direct IPv6 versus IPv6-to-IPv4 Fallback Analysis

Across the 280 valid live trials, connection behavior partitioned into:
- **`DIRECT_IPV6`:** 154 trials (55.00%)
- **`IPV6_TO_IPV4_FALLBACK`:** 126 trials (45.00%)

```
Distribution of Classifications Across 280 Valid Trials:
S0 (Healthy Baseline):        [==================== 40 DIRECT_IPV6 ] (0 Fallback)
S1 (IPv6 SYN Blackhole):      [==================== 40 FALLBACK    ] (0 Direct IPv6)
S2 (IPv6 TCP RST):            [==================== 40 FALLBACK    ] (0 Direct IPv6)
S3 (IPv6 RTT 150ms):          [==================== 40 DIRECT_IPV6 ] (0 Fallback)
S4 (IPv6 RTT 600ms):          [=================== 39 FALLBACK     ] (1 Direct IPv6)
S5 (IPv6 SYN Loss 50%):       [================ 33 DIRECT_IPV6 ][=== 7 FALLBACK]
S6 (Delayed AAAA 500ms):      [==================== 40 DIRECT_IPV6 ] (0 Fallback)
```

### Observations by Scenario

1. **S0 (Healthy Baseline):** 40/40 trials (100.0%) established `DIRECT_IPV6` connections without initiating IPv4 connection attempts. Median connection setup time was 24.02ms for Chrome and 20.64ms for Firefox, reflecting the 20ms baseline path RTT.
2. **S1 (IPv6 SYN Blackhole):** 40/40 trials (100.0%) successfully fell back to IPv4 after the primary IPv6 SYN was silently discarded.
   - Chrome exhibited an exceptionally tight CAD timer distribution: median **300.83ms** (IQR: 0.73ms, mean: 300.95ms, std: 0.63ms).
   - Firefox exhibited a longer, more variable CAD timer: median **408.45ms** (IQR: 149.33ms, mean: 441.60ms, std: 88.09ms).
3. **S2 (IPv6 TCP RST):** 40/40 trials (100.0%) fell back to IPv4 upon receiving a TCP RST on the IPv6 path.
   - Chrome exhibited **immediate fallback**: median CAD was **0.71ms** (mean: 1.11ms, std: 1.39ms), conforming to the RFC 8305 recommendation to initiate fallback immediately upon hard connection rejection.
   - Firefox introduced an observable delay before initiating IPv4: median CAD was **160.43ms** (mean: 176.97ms, std: 51.38ms), indicating that Firefox does not immediately schedule the secondary address family upon TCP RST.
4. **S3 (IPv6 RTT 150ms):** 40/40 trials (100.0%) established `DIRECT_IPV6` connections. Because the 150ms IPv6 RTT is shorter than the browsers' CAD timers (~300ms in Chrome, ~400ms in Firefox), the primary IPv6 3-way handshake finished before the CAD timer expired, successfully preventing unnecessary IPv4 fallback attempts.
5. **S4 (IPv6 RTT 600ms):** When IPv6 path RTT (600ms) substantially exceeded the CAD timer:
   - Chrome fell back to IPv4 in 20/20 trials (100.0%), with median CAD of **300.81ms**. The IPv4 connection finished in ~25ms, winning the race while IPv6 was still awaiting SYN-ACK.
   - Firefox fell back to IPv4 in 19/20 trials (95.0%, median CAD: **397.94ms**). In 1 trial (`slot-0136-S4-firefox-rep10`), Firefox did not attempt IPv4, completing direct IPv6 setup in 600.95ms.
6. **S5 (IPv6 SYN Loss 50%):** Under 50% SYN loss, connection outcomes varied based on whether the primary IPv6 SYN was dropped and how retransmissions raced against CAD. In 33 trials (18 Chrome, 15 Firefox), IPv6 completed navigation successfully (including 5 trials where an ancillary favicon request or speculative socket preconnect over IPv4 was observed post-navigation). In 7 trials (2 Chrome, 5 Firefox), IPv6 SYN drops allowed IPv4 to complete connection setup first and win the HTTP navigation.
7. **S6 (Delayed AAAA 500ms):** In all 40/40 trials (100.0%), both Chrome and Firefox established `DIRECT_IPV6` connections, awaiting the late AAAA response rather than connecting immediately over IPv4.

---

## 12. DNS Observations and S6's Delayed AAAA Behavior

### Standard DNS Latency Profile
In scenarios S0–S5, DNS responses for both `A` and `AAAA` records were delivered without artificial delay.
- Firefox observed median A latency of **0.82ms** and AAAA latency of **1.32ms**.
- Chrome observed median A latency of **2.60ms** and AAAA latency of **2.04ms**.

### S6 DNS Asynchrony Analysis
Scenario S6 evaluated RFC 8305 Section 4 ("Resolution Delay"). The DNS server delivered `A` responses immediately (0ms delay) while delaying `AAAA` responses by 500ms.

```
DNS Query / Connection Timeline in Scenario S6 (Chrome & Firefox):
t = 0.000s: Browser sends concurrent A and AAAA queries
t = 0.002s: Immediate A response arrives (10.0.2.10)
            [RFC 8305 §4 Recommended 50ms Resolution Delay Window Expires at t = 0.052s]
            (Browser does NOT initiate IPv4 connection)
t = 0.505s: Delayed AAAA response arrives (2001:db8:2::10)
t = 0.507s: Browser sends IPv6 TCP SYN
t = 0.528s: IPv6 SYN-ACK arrives -> 3WHS complete -> DIRECT_IPV6 connection established
```

- **Observed Metrics:** PCAP packet timestamps confirmed that A queries were answered in $0.83\text{ms}$ (Firefox) and $4.83\text{ms}$ (Chrome), while AAAA queries were answered in $502.56\text{ms}$ (Firefox) and $505.20\text{ms}$ (Chrome).
- **Behavioral Finding:** Neither Chrome nor Firefox adhered to the RFC 8305 recommended 50ms Resolution Delay. Rather than initiating an IPv4 connection attempt when the 50ms window elapsed, both browsers waited the full ~500ms for the AAAA response to arrive, subsequently initiating an IPv6 connection.

---

## 13. PCAP Validation, SHA-256 Verification and Packet-Drop Accounting

Evidence integrity was verified across all 280 valid captures using strict cryptographic and structural rules:

1. **PCAP Structure & Header Integrity:** All 280 captures have valid global PCAP magic bytes (`0xa1b2c3d4` or `0xd4c3b2a1`), standard 24-byte headers, and link type 1 (Ethernet).
2. **Cryptographic Invariance:** Recalculated SHA-256 digests for all 280 `capture.pcap` files matched the `pcap_sha256` recorded in `capture_metadata` in `result.json` with zero discrepancies.
3. **Packet Drop Accounting:** Kernel capture statistics from `tcpdump` stderr were audited. Zero packet drops (`packets_dropped == 0`) were reported across all 280 valid captures.

---

## 14. Browser HTTP Response Measurements

All 280 valid live trials achieved **100.0% HTTP 200 OK success**:
- **Chrome HTTP Outcome:** Extracted from internal NetLog URL request events. In all 140 Chrome trials, NetLog recorded `HTTP/1.1 200 OK` for the target URL.
- **Firefox HTTP Outcome:** Extracted from Firefox `nsHttp` telemetry (`MOZ_LOG`). In all 140 Firefox trials, telemetry recorded `HTTP/1.1 200 OK` for the target URL.
- **Process Exit Codes:** Every browser process terminated cleanly with exit code 0.

---

## 15. Cleanup, Baseline Restoration and Process/Lock Safety

The measurement harness enforces complete laboratory isolation:

1. **Impairment Teardown:** After each trial attempt, the scenario-specific impairment was purged:
   - `ps028_impair` nftables tables in `ps028-rt` were deleted.
   - tc netem qdiscs on all four server-facing links were restored to the baseline 10ms delay.
   - `dns_config.json` was restored to 0ms delays.
2. **Post-Trial Self-Test:** [`impair.self_test_baseline()`](file:///home/indrani/projects/he-webtester/lab/impair.py) executed after every attempt, verifying that no active scenarios remained in `.impair_state.json`, DNS configuration was clean, no backup files existed, and the DNS daemon was healthy.
3. **Process and Concurrency Safety:** Ephemeral browser profiles and stale background processes were terminated using target-PID signaling. Campaign execution remained protected by manifest-level (`.campaign.lock`) and lab-level (`/tmp/.ps028_lab.lock`) concurrency locks.

---

## 16. Historical Failures and Their Resolution

Two attempts failed during the initial campaign run:

1. **`slot-0002-S0-firefox-rep01` (Attempt 1):** `trial-20261029205442-aba6193c`
   - *Failure Type:* `CLEANUP_FAILURE`
   - *Error:* `Lab preflight failed: Baseline self-test failed: [Errno 32] Broken pipe`
   - *Resolution:* The pipe error was transient during preflight. Upon campaign resume, Attempt 2 (`trial-20261029205924-355df0f7`) executed cleanly and achieved `VALID_LIVE`.
2. **`slot-0013-S6-google-chrome-rep01` (Attempt 1):** `trial-20261029210226-944fcfaa`
   - *Failure Type:* `CLEANUP_FAILURE`
   - *Error:* `This operation requires root privileges. Please run with sudo or pass --dry-run.`
   - *Resolution:* Root authorization had expired before slot 13. Sudo credentials were refreshed, and upon resume, Attempt 2 (`trial-20261029215022-d5cc11cb`) executed cleanly and achieved `VALID_LIVE`.

Both failed attempts were safely preserved in the manifest audit trail.

---

## 17. Five S5 Classification Inconsistencies and Verified Correction

### The Discrepancy
In Scenario S5 (`ipv6_syn_loss_50pct`), five trials originally recorded a heuristic network classification of `IPV6_TO_IPV4_FALLBACK`, while browser application telemetry confirmed `winning_address_family: "IPv6"`.

| Slot ID | Trial ID | Browser | Initial Classification | Corrected Classification | Browser Winning AF |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `slot-0039-S5-google-chrome-rep03` | `trial-20261029215655-0740c6b1` | Chrome | `IPV6_TO_IPV4_FALLBACK` | `DIRECT_IPV6` | `IPv6` |
| `slot-0067-S5-google-chrome-rep05` | `trial-20261029220355-c31e2d8a` | Chrome | `IPV6_TO_IPV4_FALLBACK` | `DIRECT_IPV6` | `IPv6` |
| `slot-0068-S5-firefox-rep05` | `trial-20261029220410-ba849ee9` | Firefox | `IPV6_TO_IPV4_FALLBACK` | `DIRECT_IPV6` | `IPv6` |
| `slot-0124-S5-firefox-rep09` | `trial-20261029221812-497a84ab` | Firefox | `IPV6_TO_IPV4_FALLBACK` | `DIRECT_IPV6` | `IPv6` |
| `slot-0277-S5-google-chrome-rep20` | `trial-20261029225616-f02fbd7b` | Chrome | `IPV6_TO_IPV4_FALLBACK` | `DIRECT_IPV6` | `IPv6` |

### Packet-Level Verification
Detailed frame-by-frame analysis of original PCAP captures and browser telemetry logs established the exact mechanism:

```
Timeline of S5 Inconsistent Trials (e.g., slot-0039):
t = 0.460s: Client retransmits IPv6 SYN (Frame 129)
t = 0.481s: Server responds with IPv6 SYN-ACK (Frame 130) -> IPv6 connection established
t = 0.482s: Client sends "GET / HTTP/1.1" over IPv6 (Frame 132)
t = 0.503s: Server responds with "HTTP/1.1 200 OK" over IPv6 (Frame 136)
            [MAIN DOCUMENT NAVIGATION COMPLETES OVER IPv6]
t = 0.504s: Client issues TCP FIN on IPv6 connection (Frame 137)
--- Post-Navigation Ancillary Traffic ---
t = 0.518s: Chrome initiates IPv4 TCP SYN to 10.0.2.10:80 (Frame 141)
t = 0.541s: IPv4 TCP 3-way handshake completes (Frame 152)
t = 0.559s: Chrome sends "GET /favicon.ico HTTP/1.1" over IPv4 (Frame 165)
t = 0.579s: Server returns "HTTP/1.1 404 Not Found" over IPv4 (Frame 168)
```

- **Chrome Analysis:** The main document navigation (`GET /`) was initiated and completed entirely over IPv6. After the main page rendered, Chrome issued an ancillary request for `/favicon.ico`. For this ancillary request, Chrome's internal socket pool initiated a connection over IPv4. The 3-way handshake succeeded, which previously triggered the packet-based fallback heuristic because both families had connected.
- **Firefox Analysis:** The main document navigation completed entirely over IPv6. Approximately 210ms after receiving the HTTP 200 response on IPv6, Firefox initiated a speculative background preconnect socket over IPv4. The IPv4 TCP handshake succeeded, but **zero HTTP requests** were transmitted over it.
- **Root Cause & Technical Correction:** In [`lab/run_trial.py`](file:///home/indrani/projects/he-webtester/lab/run_trial.py#L1856), `classify_fallback` previously checked if both IPv6 and IPv4 connections were established without verifying whether IPv6 won the primary navigation (`winning_family == "IPv6"`). The classifier was updated to ensure that when IPv6 establishes and wins the HTTP navigation, the trial is classified as `DIRECT_IPV6` with `fallback_occurred: False`.
- **Audit & Evidence Preservation:** The original PCAP captures, SHA-256 hashes, CAD measurements (300.96ms to 407.22ms), and browser logs were preserved without modification. The derived classification fields in `result.json` and `campaign_manifest.json` were corrected to `DIRECT_IPV6`, restoring complete analytical consistency between browser telemetry and network observation across all 280 trials.

---

## 18. Cross-Browser Response-Body-Byte Metric Limitation

In the campaign results, `response_body_bytes` is invariant by browser:
- **Google Chrome:** Exactly **308 bytes** in 140/140 trials.
- **Mozilla Firefox:** Exactly **72 bytes** in 140/140 trials.

### Metric Limitation Analysis
In [`lab/run_trial.py`](file:///home/indrani/projects/he-webtester/lab/run_trial.py#L2837), `response_body_bytes` is computed as:
```python
"response_body_bytes": len(browser_result.get("stdout", ""))
```
This measures the string length of the browser process's standard output stream rather than HTTP wire transfer size:
- **Chrome:** Executed with `--dump-dom`, Chrome prints the serialized HTML DOM tree to stdout (308 bytes).
- **Firefox:** Firefox headless mode does not support `--dump-dom`. Firefox stdout captured an internal graphics fallback notice:
  ```
  [GFX1-]: RenderCompositorSWGL failed mapping default framebuffer, no dt\n
  ```
  The length of this string is exactly 72 bytes.

> [!WARNING]
> **Metric Semantics:** The `response_body_bytes` metric is **not comparable across browsers**. It reflects stdout logging differences rather than HTTP payload differences. HTTP 200 delivery was independently verified via browser telemetry in both browsers.

---

## 19. Two Preserved CLEANUP_FAILURE Attempts

The two failed attempts are classified as exclusions in statistical analysis:
1. `trial-20261029205442-aba6193c` (`slot-0002`)
2. `trial-20261029210226-944fcfaa` (`slot-0013`)

### Justification for Exclusion
- Both attempts failed during initial environment setup and preflight verification before `tcpdump` or browser processes were launched.
- Neither attempt generated valid packet capture data or HTTP responses.
- Both attempts violated the fail-stop baseline verification invariant.
- Per PS-028 analysis rules ([`lab/analyze.py`](file:///home/indrani/projects/he-webtester/lab/analyze.py)), failed attempts cannot be treated as valid measurement samples. They are preserved in `campaign_manifest.json` as an immutable audit trail.

---

## 20. Scenario Mismatch Notices from the Campaign Manifest

The campaign manifest permanently records two documented mismatches between early narrative documentation and the canonical implementation in [`lab/scenarios.yaml`](file:///home/indrani/projects/he-webtester/lab/scenarios.yaml):

### Exact Manifest Notices

```json
{
  "S2": {
    "readme_documentation": "IPv4 connection path unavailable",
    "configured_behavior": "IPv6 TCP RST rejection (ipv6_tcp_rst)",
    "canonical_reference": "lab/scenarios.yaml (reject with tcp reset on ps028-rt-sv6)",
    "policy": "Canonical lab/scenarios.yaml configuration preserved per PS-028 specification; evidence not relabeled."
  },
  "S4": {
    "readme_documentation": "Increased IPv4 path latency",
    "configured_behavior": "Increased IPv6 path latency 600ms RTT (ipv6_rtt_600ms)",
    "canonical_reference": "lab/scenarios.yaml (300ms netem delay on ps028-rt-sv6 and ps028-sv-rt6)",
    "policy": "Canonical lab/scenarios.yaml configuration preserved per PS-028 specification; evidence not relabeled."
  }
}
```

### Analytical Impact
- **Scenario S2:** Canonical `scenarios.yaml` injects an IPv6 TCP RST (`reject with tcp reset`), testing client fallback upon explicit connection refusal. Early narrative README text had informally labeled this as an unavailable IPv4 path. The canonical implementation was preserved and verified.
- **Scenario S4:** Canonical `scenarios.yaml` adds 300ms netem delay to each direction of the IPv6 path (600ms RTT total), testing Happy Eyeballs fallback when IPv6 path latency substantially exceeds the CAD timer. Early documentation had informally referenced IPv4 path latency. The canonical implementation was preserved.

---

## 21. Limitations, Threats to Validity and Future Improvements

### Limitations and Threats to Validity
1. **Single-Site Topology:** Experiments were conducted within a local synthetic network namespace testbed. While tc netem and nftables reproduce packet-level delays and loss with fidelity, real-world WAN phenomena (BGP route flapping, Path MTU Discovery issues, intermediate middleboxes) were not evaluated.
2. **Profile Isolation vs. Caching:** To guarantee measurement independence, ephemeral browser profiles were used for every trial. This intentionally precluded evaluating RFC 8305 Section 7 ("Statefulness"), which permits clients to cache historical connection failures across sessions.
3. **Transport Scope:** In accordance with PS-028 specifications, measurements evaluated HTTP/1.1 over TCP. Alternate transport protocols such as HTTP/3 over QUIC were out of scope.

### Future Improvements
1. Extend telemetry collection to extract raw HTTP payload byte counters directly from socket buffers rather than process stdout.
2. Incorporate Multi-Prefix IPv6 environments and NAT64/DNS64 synthesis topologies.
3. Develop stateful multi-trial sequences to explicitly evaluate RFC 8305 Section 7 adaptive past-failure caching.

---

## 22. Reproducibility Instructions

### Environment Prerequisites
- Linux kernel 5.15+ with network namespaces, veth pairs, `nftables`, and `iproute2` (tc netem).
- Python 3.10+ standard library.
- Google Chrome and Mozilla Firefox installed.
- Wireshark / `tshark` and `tcpdump`.

### Verification Steps

1. **Verify Baseline State:**
   ```bash
   sudo python3 lab/impair.py preflight
   sudo python3 lab/impair.py self-test-baseline
   ```

2. **Execute Full Test Suite:**
   ```bash
   python3 -m unittest discover -s lab
   ```

3. **Re-Run Statistical Analysis on Campaign Evidence:**
   ```bash
   python3 lab/analyze.py --campaign-dir lab/campaigns/ps028-a10-live-20261030-01
   ```

4. **Export Structured Analysis Summary:**
   ```bash
   python3 lab/analyze.py --campaign-dir lab/campaigns/ps028-a10-live-20261030-01 \
     --output-json lab/campaigns/ps028-a10-live-20261030-01/analysis_summary.json \
     --output-csv lab/campaigns/ps028-a10-live-20261030-01/analysis_summary.csv
   ```

---

## 23. Conclusion

The PS-028 live measurement campaign (`ps028-a10-live-20261030-01`) successfully completed all 280 planned matrix slots across Google Chrome 156 and Mozilla Firefox 159 under seven systematically impaired network scenarios. The empirical findings provide concrete evidence regarding the operation of Happy Eyeballs in modern web browsers:

1. **IPv6 Preference:** Both browsers exhibit 100% IPv6 preference under normal dual-stack conditions, incurring zero dual-stack connection penalty when IPv6 paths are healthy.
2. **CAD Timer Implementation:** Google Chrome implements an exceptionally consistent CAD timer centered at **~300ms**, whereas Mozilla Firefox implements a slightly more relaxed CAD timer averaging **~408–441ms**.
3. **Active Rejection (TCP RST):** Chrome demonstrates immediate fallback (< 1ms CAD) upon receiving a TCP RST, fully satisfying RFC 8305 recommendations. Firefox introduces an observable delay (~160ms) before initiating fallback.
4. **Delayed DNS Resolution:** Neither browser initiated an IPv4 fallback after the recommended 50ms Resolution Delay when AAAA records were delayed by 500ms; both waited for the late AAAA response and connected directly over IPv6.
5. **Measurement Integrity:** The testbed architecture demonstrated robust isolation, zero packet capture loss, atomic manifest tracking, and complete preservation of historical evidence.
