# AIORI-3-HACKATHON-PROJECTS
This repository will contain the code and resources for the AIORI-3 hackathon that will be developed during the AIORI-3

# Happy Eyeballs: IPv4/IPv6 Fallback Measurement

**Team:** AlgoRhythm · **Hackathon:** AIORI 3 · **Problem Statement:** PS-028  
**Domain:** Internet Measurement

Team Introduction Video on YouTube: https://youtu.be/5LLxlW9f6r4?si=hoTZUTnZqHj3ni9-

## Overview

This project evaluates how existing web clients establish connections when IPv4 and IPv6 paths experience controlled delays or failures. It uses a reproducible dual-stack laboratory to measure connection setup time, winning address family, failed connection attempts, and fallback behavior.

**Objective:** Quantitatively compare two existing client implementations and explain their observed behavior using connection timelines and packet-level evidence.

## Problem Statement

In dual-stack networks, IPv4 and IPv6 may have different connectivity and performance characteristics. A broken or slow path can delay connection establishment if a client waits too long before attempting an alternative.

The **Happy Eyeballs algorithm**, specified in [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html), mitigates this problem by coordinating connection attempts across available address families.

This project investigates how effectively existing clients handle controlled network impairments, without developing a new browser stack or making unsupported conformance claims.

## Proposed Methodology

1. **Environment:** Establish an isolated dual-stack client–DNS–server testbed with deterministic DNS responses.
2. **Client selection:** Pin two existing web client implementations or versions and document their configurations.
3. **Fault injection:** Apply reproducible network delays, packet loss, link failures, and DNS response delays.
4. **Instrumentation:** Collect client connection timelines, structured event logs, and packet captures.
5. **Analysis:** Compare connection performance, address-family selection, and fallback behavior across repeated trials.

## Experimental Design

Use a healthy baseline plus six controlled failure/delay scenarios:

| Scenario | Controlled condition |
|---|---|
| S1 | IPv6 connection path unavailable |
| S2 | IPv4 connection path unavailable |
| S3 | Increased IPv6 path latency |
| S4 | Increased IPv4 path latency |
| S5 | Packet loss on one address-family path |
| S6 | Delayed DNS response for one address family |

Run **at least 20 repetitions per client per scenario**. This gives a minimum of 280 trials across two clients, six impaired scenarios, and the healthy baseline.

Keep server configuration, application protocol, client settings, and measurement procedures consistent. Prevent connection reuse and DNS caching from unintentionally contaminating trials.

## Measurement and Analysis

**Primary metrics**
- Connection setup time and service-readiness time, reported separately.
- Winning address family: IPv4 or IPv6.
- Failed, successful, and cancelled connection attempts.
- Fallback delay and overall connection success rate.
- DNS resolution latency and per-attempt event timelines.

Report median, 95th-percentile latency, interquartile range, and confidence intervals where appropriate. Use packet captures to validate observed connection attempts and distinguish network failures from client-side behavior.

## Expected Deliverables

- Reproducible dual-stack scenario runner.
- Two documented and tested client configurations.
- Six controlled failure/delay scenarios and repeated-trial dataset.
- Timestamped connection timelines and packet captures.
- Per-scenario comparative analysis and technical report.
- Demonstration and pseudocode for the experimental workflow.

## Scientific Principles

- Use an isolated lab; do not inject faults into public or production networks.
- Record exact client versions, configuration, DNS behavior, and specification revision.
- Preserve raw measurements and document exclusions, failures, and limitations.
- Base conclusions on observable evidence rather than undocumented implementation assumptions.
- Treat Happy Eyeballs v3 as a pinned Internet-Draft unless its publication status is verified at experiment launch.

## Standards and Related Work

- [RFC 8305 — Happy Eyeballs Version 2](https://www.rfc-editor.org/rfc/rfc8305.html)
- [RFC 6724 — Default Address Selection](https://www.rfc-editor.org/rfc/rfc6724.html)
- [Happy Eyeballs Version 3 — IETF Datatracker](https://datatracker.ietf.org/doc/draft-ietf-happy-happyeyeballs-v3/)
- [IETF Happy Eyeballs WebTester](https://github.com/happy-eyeballs/he-webtester)

Our contribution is a controlled, evidence-driven comparison of existing clients, designed to make IPv4/IPv6 connection behavior measurable, explainable, and reproducible.

## Project Status

**Status:** Experimental framework and methodology proposed; implementation and measurements to be documented as completed.

**Team AlgoRhythm — Measure. Compare. Improve.**
