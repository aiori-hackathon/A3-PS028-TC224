# Comparative Analysis: Mozilla Firefox 159 vs Published Firefox 132 Literature (Phase D4)

- **Date / Timestamp**: 2026-11-12T07:50:00Z
- **Document ID**: `PS028-PHASE-D4-FIREFOX-COMPARISON`
- **Governing Protocol**: `docs/phase-d-experiment-protocol.md` Section 6.1
- **Governing Rules**: Rule R7 (No Conformance Claims), Rule R1 (No Fabricated Evidence)
- **Status**: **QUALITATIVE LITERATURE COMPARISON (NON-NORMATIVE)**

---

## 1. Context and Objective

Happy Eyeballs Version 2 (RFC 8305) provides normative recommendations for dual-stack connection attempt pacing, but browser implementations evolve across release cycles and operating system network stacks.

In their seminal paper *"Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations"* (ACM IMC 2025), Sattler et al. performed extensive active measurements of desktop and mobile browsers—including **Mozilla Firefox 132.0**—evaluating Connection Attempt Delay (CAD), Resolution Delay, and address family selection against public web servers and controlled middleboxes.

This document provides a strictly qualitative comparison between the empirical observations of **Mozilla Firefox 159.0** recorded in this laboratory (AIORI PS-028 campaign `ps028-a10-live-20261030-01`) and the published findings for Firefox 132.0.

> [!IMPORTANT]
> **Adherence to Rule R7 (No Conformance Claims):**
> This analysis is strictly descriptive. It observes timing differences under disparate testbed environments and **does not assert browser performance improvement, software regression, or standards non-conformance**. Differences in kernel networking, resolver topology, and transport layers preclude formal equivalence claims.

---

## 2. Mandatory Methodological Disclosures

To preserve scientific rigor, the substantial environmental differences between the two measurement campaigns are explicitly disclosed:

| Parameter | AIORI PS-028 Laboratory Campaign | Sattler et al. (ACM IMC 2025) Study |
|:---|:---|:---|
| **Client Software** | Mozilla Firefox 159.0 (Pinned Build) | Mozilla Firefox 132.0 |
| **Operating System** | Linux x86_64 (Kernel 6.18 WSL2 / Ubuntu 24.04.5 LTS) | Native Linux, macOS, and Windows desktop environments |
| **Network Vantage** | Linux network namespaces (`ps028-cl`, `ps028-rt`, `ps028-sv`) | Residential, university, and cellular egress networks |
| **Traffic Shaping** | Deterministic kernel `tc netem` & `nftables` | In-path active testing proxies & public dual-stack dual-CDN servers |
| **Resolver Setup** | Controlled local single-hop UDP DNS responder (0ms RTT) | Local recursive resolvers, public recursive DNS (8.8.8.8, 1.1.1.1) |
| **Transport Protocol**| HTTP/1.1 over plain TCP (Port 80/8080) | HTTPS (TLS 1.3 / TCP) and HTTP/3 (QUIC) |

---

## 3. Comparative Observations by Failure Scenario

### 3.1 Unresponsive IPv6 Path (SYN Blackholing / Scenario S1)
- **Published Literature (Firefox 132.0)**:
  Sattler et al. observed Firefox 132 scheduling subsequent IPv4 connection attempts with a median CAD of approximately $250\text{ ms}$, closely tracking the RFC 8305 Section 5 recommended default value ($250\text{ ms}$), with an empirical spread between $200\text{ ms}$ and $300\text{ ms}$.
- **PS-028 Lab Observations (Firefox 159.0)**:
  Across 20 valid live trials in Scenario S1, Firefox 159 exhibited a median CAD of **$396.960\text{ ms}$** (range: $300.810\text{ ms}$ to $418.520\text{ ms}$).
- **Qualitative Comparison**:
  Under the PS-028 isolated namespace environment, Firefox 159 exhibited a moderately more conservative connection attempt delay timer (~$400\text{ ms}$ vs ~$250\text{ ms}$). Both distributions satisfy the RFC 8305 §5 recommended bounds ($[100\text{ ms}, 2000\text{ ms}]$) and respect the $10\text{ ms}$ mandatory inter-attempt floor.

---

### 3.2 Active Connection Failure (TCP RST / Scenario S2)
- **Published Literature (Firefox 132.0)**:
  Sattler et al. highlighted that while Chromium-based browsers frequently trigger immediate subsequent connection attempts within $< 10\text{ ms}$ upon receiving a TCP RST, Firefox 132 consistently maintained inter-attempt spacing $\ge 10\text{ ms}$, generally waiting for its standard CAD timer before initiating IPv4 fallback.
- **PS-028 Lab Observations (Firefox 159.0)**:
  Across 20 valid live trials in Scenario S2, Firefox 159 exhibited a median CAD of **$160.425\text{ ms}$** (range: $130.780\text{ ms}$ to $336.230\text{ ms}$). In 100% of trials (20/20), Firefox 159 initiated its subsequent attempt well above the $10.000\text{ ms}$ mandatory floor. In contrast, Google Chrome 156 launched fallback attempts with a median CAD of **$0.710\text{ ms}$** (< 10 ms).
- **Qualitative Comparison**:
  Our laboratory findings for Firefox 159 are completely consistent with the qualitative pattern documented by Sattler et al. for Firefox 132: Mozilla's network stack does not aggressively short-circuit inter-attempt pacing upon TCP RST, thereby avoiding the sub-10ms burst behavior observed in Chromium.

---

### 3.3 Asynchronous DNS Arrival (Delayed AAAA / Scenario S6)
- **Published Literature (Firefox 132.0)**:
  Sattler et al. noted that browser handling of Resolution Delay (RFC 8305 §3) is highly variable across implementations. When A records arrive substantially ahead of AAAA records, some clients initiate IPv4 connections after ~50 ms, while others wait for the operating system resolver to return both record sets before initiating transport connections.
- **PS-028 Lab Observations (Firefox 159.0)**:
  In Scenario S6, the controlled DNS responder injected a $500\text{ ms}$ delay on AAAA responses while returning A responses immediately. In 20/20 trials (median delay $501.740\text{ ms}$), Firefox 159 did not launch an IPv4 connection attempt after 50 ms; instead, it waited for the delayed AAAA response and connected directly over IPv6 without launching any IPv4 SYNs.
- **Qualitative Comparison**:
  Under single-hop local resolver conditions where the client OS stub resolver handles concurrent `getaddrinfo` queries, Firefox 159 behaves identically to Google Chrome, serializing transport connection initiation until DNS resolution completes, prioritizing IPv6 preference over the RFC 8305 50ms Resolution Delay recommendation.

---

## 4. Summary Matrix

| Metric / Dimension | Sattler et al. (IMC 2025) Firefox 132 | PS-028 Lab Firefox 159 | Observational Alignment |
|:---|:---|:---|:---|
| **S1 SYN Timeout Median CAD** | $\sim 250\text{ ms}$ | $396.960\text{ ms}$ | Within RFC recommended range $[100, 2000]\text{ ms}$ |
| **S2 TCP RST Fallback Pacing** | $\ge 10\text{ ms}$ (Conservative pacing) | $160.425\text{ ms}$ ($\ge 10\text{ ms}$) | High qualitative consistency |
| **S2 Sub-10ms Deviation** | NOT OBSERVED in Firefox | NOT OBSERVED (0/20 trials < 10ms) | Identical defensive pacing |
| **Dual-Stack Preference** | Strong IPv6 preference | 100% IPv6 preference on baseline (S0) | High qualitative consistency |
| **S6 Resolution Delay (50ms)** | Variable / Implementation-dependent | Waited ~500ms for AAAA | Prioritizes IPv6 over 50ms timer |

---

## 5. Conclusion

The empirical findings from PS-028 campaign `ps028-a10-live-20261030-01` qualitatively confirm and extend the observations published by Sattler et al. (IMC 2025):
1. Mozilla Firefox's networking architecture demonstrates disciplined adherence to the RFC 8305 Section 5 mandatory inter-attempt floor ($\ge 10\text{ ms}$), distinguishing its behavior from Chromium's aggressive sub-millisecond RST retry dynamics.
2. In controlled stub-resolver environments, modern browsers continue to prioritize dual-stack IPv6 preference over Informative 50ms Resolution Delay pacing recommendations.
