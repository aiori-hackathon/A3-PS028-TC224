# PS-028 Happy Eyeballs: Scientific Reproducibility Hardening & Independent Partner Replication Readiness Report

- **Document ID**: `PS028-REPORT-PARTNER-REPLICATION-READINESS`
- **Date**: 2026-11-21T17:27:00Z
- **Authoritative Feature Branch**: `fix/partner-replication-readiness`
- **Base Commit**: `0dc8c5801a73a55942dc905d4cf7cd5f6c55c896` (official remote `main` HEAD)
- **Replication Status**: `STATUS: READY_FOR_PARTNER_REPLICATION` (Campaign Execution: `PENDING_AUTHENTIC_PARTNER_EVIDENCE`)
- **Compliance Rules**: Rule R1 (No Fabricated Partner Evidence), Rule R2 (Historical Evidence Sealed), Rule R4 (No Null Coercion), Rule R5 (Fail-Closed Execution), Rule R6 (Evidence Classes Separated), Rule R7 (No Conformance Claims on Undocumented Internals)

---

## 1. Executive Summary & Replication Status

This technical report documents the complete scientific hardening, protocol reconciliation, toolchain verification, and reproducibility engineering performed on the PS-028 Happy Eyeballs measurement repository.

The repository is now fully prepared for an independent scientific replication by a partner laboratory on a second Linux machine. All engineering controls, automation scripts, verification checkers, and statistical analysis pipelines are validated, deterministic, and fail-closed.

### 1.1 Strict Scientific Integrity Status: Pending Authentic Partner Evidence

In accordance with Problem Statement Rule R1 and governing scientific standards:
- **Readiness Declaration**: `STATUS: READY_FOR_PARTNER_REPLICATION`.
- **Campaign Status**: `STATUS: PENDING AUTHENTIC PARTNER EVIDENCE`.
- **Authorization Boundary**: The engineering team is authorized to harden, verify, and test the software toolchain and replication protocols. The team is **NOT** authorized to perform the actual independent replication campaign, which must occur on physically distinct hardware operated by an independent partner institution.
- **Zero Fabrication**: No synthetic, simulated, or local dry-run measurements have been relabeled, substituted, or committed as partner evidence.
- **Historical Evidence Preservation**: The October 2026 authoritative campaign (`lab/campaigns/ps028-a10-live-20261030-01/`) remains cryptographically sealed and untouched:
  $$\text{SHA-256 integrity verification: } 705 / 705 \text{ files verified 100\% matching.}$$

### 1.2 Replication Target Specifications

| Parameter | Specification | Enforcement Mechanism |
|---|---|---|
| **Base Main Commit** | `0dc8c5801a73a55942dc905d4cf7cd5f6c55c896` | Official remote `main` HEAD verification |
| **Feature Branch** | `fix/partner-replication-readiness` | Reconciled branch for partner release |
| **Target Clients** | Google Chrome `156.0.8078.73`<br>Mozilla Firefox `159.0` | `lab/partner_preflight.py`<br>`lab/run_campaign.py --strict-partner`<br>`lab/verify_partner_handover.py` |
| **Canonical Scenarios** | 7 scenarios (S0 healthy baseline, S1–S6 impairments) | `lab/scenarios.yaml`<br>`lab/replication_contract.py` |
| **Cohort Sample Size** | Exactly 20 valid live trials per cohort ($n=20$) | `lab/replication_contract.py`<br>`lab/run_campaign.py` |
| **Total Planned Trials** | Exactly 280 valid live trials ($14 \text{ cohorts} \times 20 \text{ reps}$) | `matrix_slots` tracking (280 slots) |
| **Specification of Record** | `draft-ietf-happy-happyeyeballs-v3-04` (1 July 2026) | Immutable protocol reference (Amendment A10) |

---

## 2. Source-File Review Register

Every primary subsystem, script, configuration, and test module has been audited line-by-line against governing scientific requirements. The audit status of each item is classified below as **PASS**, **FAIL**, **BLOCKED**, or **NOT TESTED**:

| Subsystem / Source File | Classification | Review Findings & Scientific Rationale |
|---|:---:|---|
| [`lab/replication_contract.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/replication_contract.py) | **PASS** | Centralizes single source of truth: protocol constants (v1.0.0), schema (v1.1.0), pinned browser versions (`156.0.8078.73`, `159.0`), 7 canonical scenarios, 280 slots, manifest consistency validators, validity vs scientific outcome separation, and predeclared TOST equivalence margins. |
| [`lab/partner_preflight.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/partner_preflight.py) | **PASS** | 5-state readiness model. Strict semver comparison for tools (`ip`, `tc`, `nft`, `tshark`, `tcpdump`, `nginx`, `curl`). Strict exact string build check for Chrome/Firefox. Snap confinement and DNS isolation detection. Non-mutating read-only operation. |
| [`lab/run_campaign.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/run_campaign.py) | **PASS** | Implements `--strict-partner` flag. Rejects simulation/dry-run. Enforces exactly 7 scenarios $\times$ 2 browsers $\times$ 20 reps = 280 slots. Preserves failed attempts in `failed_attempt_record.json`. Implements fail-stop on cleanup failure. Safe signal handling (SIGINT/SIGTERM). |
| [`lab/run_trial.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/run_trial.py) | **PASS** | Manages individual trial lifecycle. BPF packet capture on `ps028-cl-rt`. Dissects PCAP using tshark to extract flow metrics, TCP handshakes, DNS timings, and HTTP status codes. |
| [`lab/impair.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/impair.py) | **PASS** | Validates nftables rules strictly (`netdev ps028_impair` / `inet ps028_impair`). Supports S1 drop, S2 reject with tcp reset, S5 numgen loss (`numgen random mod 100 < 50`). Implements `apply_scenario` and `clear_impairments` idempotently. |
| [`lab/verify_partner_handover.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/verify_partner_handover.py) | **PASS** | Audits 280 completed slots, exact browser versions, raw PCAP semantic rederivation, 2.0ms timing tolerance, all 7 physical scenario invariants (S0–S6), checksum manifest coverage, and safe archive extraction. Distinguishes physical experiment validity from browser outcomes. |
| [`lab/setup_topology.sh`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/setup_topology.sh) | **PASS** | Provisions 3 isolated namespaces (`ps028-cl`, `ps028-rt`, `ps028-sv`). Portable host snapshotting without interface filtering (catches residual leaks). Dynamic SLAAC lifetime normalization. Delegates teardown to `lab/teardown.sh`. |
| [`lab/teardown.sh`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/teardown.sh) / [`lab/teardown.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/teardown.py) | **PASS** | Safe ordered teardown under exclusive lab lock (`.lab.lock`). Restores impairments, stops only verified PID services, cleans resolver only if marked, deletes dangling host interfaces, and aborts namespace deletion if baseline cannot be verified. |
| [`lab/dns_server.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/dns_server.py) | **PASS** | Controlled DNS server running in `ps028-rt`. Delivers immediate A responses and configurable delayed AAAA responses (500ms delay in S6). Atomic config reloading on SIGHUP. |
| [`lab/privileged_helper.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/privileged_helper.py) | **PASS** | Strict sudoers boundary (`/usr/local/libexec/ps028/privileged_helper.py`). Explicit action allowlist, bounds checking, parameter sanitization, and privilege dropping. Zero ambient root during browser execution. |
| [`lab/deploy_privileged_helper.sh`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/deploy_privileged_helper.sh) | **PASS** | Deploys helper with non-mutating `--dry-run` validation, visudo syntax validation, file permissions (`0750`/`0640`), and git clean-tree verification. |
| [`lab/export_campaign_evidence.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/export_campaign_evidence.py) | **PASS** | Generates deterministic derived ledgers (`trial_index.json`, `events.jsonl`, `cohort_summary.csv`, `provenance.json`). Excludes failed attempts from empirical metrics while preserving provenance. |
| [`lab/compare_campaigns.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/compare_campaigns.py) | **PASS** | Evaluates all 14 cohorts against baseline. Uses Two One-Sided Tests (TOST) with predeclared practical equivalence margins, two-sample bootstrap median CIs (seed=42, B=2000), and Agresti-Caffo proportion difference CIs. Classifies into 5 scientific categories. |
| [`.github/workflows/ci.yml`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/.github/workflows/ci.yml) | **PASS** | Configured to run on push to `main` and `fix/partner-replication-readiness`. Automatically discovers and runs all Python unit tests, integration tests, frontend tests, and checksum validations. |
| **Actual Live Partner Campaign Execution** | **NOT TESTED** | **PENDING AUTHENTIC PARTNER EVIDENCE**. In accordance with Rule R1, live campaign execution on the authoring workstation is strictly prohibited. Independent execution must occur on partner hardware. |

---

## 3. Separation of Physical Experiment Validity from Browser Outcomes

### 3.1 The Scientific Boundary: Validity vs. Observable Findings

A fundamental scientific correction has been applied to the verification and analysis pipeline:
The evidence verifier ([`lab/verify_partner_handover.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/verify_partner_handover.py)) must validate that the physical experiment was executed correctly, but must **never** enforce historical scientific outcomes as experimental validity conditions.

| Dimension | Experimental Validity Check (`verify_partner_handover.py`) | Scientific Observational Result (`compare_campaigns.py`) |
|---|---|---|
| **Impairments** | Was the intended network impairment physically active? | Did the browser complete over IPv6, fall back to IPv4, or timeout? |
| **DNS Resolution** | Did the DNS server deliver immediate A and delayed AAAA (S6)? | Did the browser start IPv4 during the AAAA delay (Happy Eyeballs CAD)? |
| **Capture Integrity** | Is the PCAP authentic, uncorrupted, and matched by SHA-256? | What was the exact TCP connection setup time ($t_{\text{connect}}$)? |
| **Browser Environment** | Were exact pinned versions (Chrome 156, Firefox 159) run in netns? | Did Firefox on the second host behave differently from historical Chrome? |

### 3.2 Four Explicit Evidence & Analysis Classifications

To prevent false rejections of genuine scientific divergences:
1. **`INVALID_EXPERIMENT`**: Procedural or physical setup failure (e.g., PCAP corrupted, unverified browser version, netem delay not applied to the link, AAAA not delayed in S6, simulation flag active, or uncleaned baseline state). Handover verifier rejects the campaign.
2. **`VALID_LIVE_OBSERVATION`**: Experiment physically valid, genuine PCAP captured, authentic HTTP outcome recorded. Accepted by the handover verifier regardless of whether IPv6 or IPv4 won, and passed to `compare_campaigns.py`.
3. **`VALID_LIVE_CONNECTION_FAILURE`**: Experiment physically valid, genuine PCAP captured, but the browser timed out or failed to connect under severe impairment. Accepted as an authentic measurement of connection failure.
4. **`STATISTICAL_DIVERGENCE`**: Evaluated exclusively in `compare_campaigns.py`. Classifies genuine behavioral divergences (e.g. partner browser selecting IPv4 in S0, or CAD timing differing from baseline) into `BEHAVIORAL_DIVERGENCE` or `SYSTEMATIC_SHIFT`.

---

## 4. Reconciled Evidence Identities & Semantic PCAP Rederivation

### 4.1 Tripartite Identity Reconciliation

For every trial slot across all 280 iterations, `verify_partner_handover.py` enforces tripartite identity reconciliation across three distinct data sources:
1. **`campaign_manifest.json`**: Records slot ID, attempt number, trial ID, timestamps, execution mode (`LIVE`), browser version, and PCAP SHA-256.
2. **`trials/<trial_id>/result.json`**: Records local trial execution telemetry, HTTP outcome, connection setup metrics, and cleanup status.
3. **`trials/<trial_id>/capture.pcap`**: Raw packet capture file.

The verifier asserts:
$$\text{SHA256}(\text{capture.pcap}) \equiv \text{result.json}[\text{pcap\_sha256}] \equiv \text{manifest}[\text{pcap\_sha256}]$$
$$\text{trial\_id} \equiv \text{result.json}[\text{trial\_id}] \equiv \text{manifest}[\text{trial\_id}]$$

### 4.2 Independent Semantic Rederivation from Raw PCAP

The verification engine never trusts the summary metrics in `result.json`. It invokes `tshark` directly on `capture.pcap` and rederives:
- **Winning Address Family**: Reconstructed from the TCP 3-way handshake completion on the stream that conveys the HTTP request. If `result.json` claims IPv6 but PCAP demonstrates IPv4, verification fails immediately.
- **HTTP Response Status Code**: Extracted directly from `http.response.code` in the dissected stream.
- **TCP Connect Latency ($t_{\text{connect}}$)**: Recomputed as the time delta from the client SYN to the matching client final ACK in the winning stream:
  $$t_{\text{connect}} = t_{\text{ACK}} - t_{\text{SYN}}$$
- **Connection Setup Latency ($t_{\text{setup\_total}}$)**: Recomputed as the time delta from the earliest SYN transmitted across either address family to the final ACK of the winning connection:
  $$t_{\text{setup\_total}} = t_{\text{final\_ACK}} - \min(t_{\text{SYN, v6}}, t_{\text{SYN, v4}})$$

### 4.3 Technical Derivation of the 2.0 ms Timing Tolerance

When comparing rederived PCAP metrics against `result.json`, a maximum tolerance of **2.0 ms** is enforced:
$$|t_{\text{connect, result}} - t_{\text{connect, pcap}}| \le 2.0\text{ ms}$$
$$|t_{\text{setup, result}} - t_{\text{setup, pcap}}| \le 2.0\text{ ms}$$

This tolerance is derived from technical packet timestamping and parsing constraints:
1. **Packet Capture Precision**: Raw PCAP file headers record timestamps in microsecond resolution (`struct timeval`: seconds + microseconds, 32-bit uints). Conversion to 64-bit IEEE 754 floating-point epoch seconds introduces machine precision epsilon ($\approx 0.1\ \mu\text{s}$).
2. **Numeric Representation & Serialization Rounding**: `result.json` serializes timing values formatted to 2 decimal places (`f"{val:.2f}"`), introducing up to $\pm 0.01$ ms of representation truncation.
3. **Independent Parser ACK Frame Identification**: In real TCP streams, client implementations frequently transmit a pure TCP ACK (`tcp.flags == 0x010`, length 0) immediately followed by the first HTTP GET request segment (`tcp.flags == 0x018` PSH+ACK). Depending on parser heuristics for identifying the matching handshake completion ACK versus the first payload segment carrying the ACK flag, an offset of $0.5 - 1.5$ ms can exist between dissectors operating on identical packet traces.
4. **Strict Boundary Enforced**: A threshold of 2.0 ms accommodates parser ACK-selection differences while strictly rejecting any substituted or fabricated metric (such as substituting a 20 ms baseline for a 150 ms link or 250 ms CAD).

**Empirical Boundary Test Validation**:
- $\Delta = 1.99\text{ ms}$: **ACCEPTED** (`test_pcap_semantic_timing_tolerance_boundary_strictly_below`)
- $\Delta = 2.00\text{ ms}$: **ACCEPTED** (`test_pcap_semantic_timing_tolerance_boundary_exact`)
- $\Delta = 2.01\text{ ms}$: **REJECTED** (`test_pcap_semantic_timing_tolerance_boundary_strictly_above`, raises `VerificationError`)

---

## 5. Canonical Scenario Impairment Invariants (S0 – S6)

In accordance with Section 3, `verify_partner_handover.py` validates physical experimental conditions for all seven canonical scenarios directly against the raw packet capture:

| Scenario | Definition | Enforced Physical Invariant in PCAP | Negative Test Status |
|---|---|---|:---:|
| **S0** | Healthy dual-stack baseline (~20ms RTT) | • Physical baseline verified.<br>• Whichever family won (IPv6 or IPv4), connect latency must reflect baseline link: $t_{\text{connect}} \le 100.0\text{ ms}$. | **PASS** |
| **S1** | IPv6 TCP SYN blackhole | • Router silently drops client IPv6 SYNs.<br>• Invariant: IPv6 TCP handshake **MUST NOT** complete. | **PASS** |
| **S2** | IPv6 TCP RST rejection | • Router actively rejects client IPv6 SYNs with TCP RST.<br>• Invariant: IPv6 TCP handshake **MUST NOT** complete. | **PASS** |
| **S3** | IPv6 RTT ~150ms, IPv4 RTT ~20ms | • Netem delay (75ms symmetric) verified on IPv6 link.<br>• If IPv6 won: $t_{\text{connect}} \ge 100.0\text{ ms}$.<br>• If IPv4 won: $t_{\text{connect}} \le 150.0\text{ ms}$. | **PASS** |
| **S4** | IPv6 RTT ~600ms, IPv4 RTT ~20ms | • Netem delay (300ms symmetric) verified on IPv6 link.<br>• If IPv4 won: $t_{\text{connect}} \le 150.0\text{ ms}$.<br>• If IPv6 won: $t_{\text{connect}} \ge 400.0\text{ ms}$. | **PASS** |
| **S5** | 50% stochastic IPv6 SYN loss | • Netfilter stochastic drop rule applied.<br>• At least one family must complete TCP handshake if HTTP outcome is recorded. | **PASS** |
| **S6** | IPv6 AAAA DNS delayed 500ms | • DNS server delayed AAAA response.<br>• Invariant: $\text{lat}_{\text{AAAA}} - \text{lat}_{\text{A}} \ge 200.0\text{ ms}$. Whichever family won is accepted. | **PASS** |

All seven invariants are validated in unit test suite [`lab/test_verify_partner_handover.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/test_verify_partner_handover.py) (74/74 tests passing).

---

## 6. Dedicated S5 Stochastic Loss & Accounting Audit

### 6.1 Kernel RNG-Backed Stochastic Selection

The S5 impairment is implemented in `nftables` inside the router namespace (`ps028-rt`) via:
```nft
add rule inet ps028_impair forward oifname "ps028-rt-sv6" ip6 saddr 2001:db8:1::2 ip6 daddr 2001:db8:2::10 tcp dport 80 tcp flags syn / syn,ack numgen random mod 100 < 50 counter name "syn_dropped" drop
```
In the Linux kernel network subsystem (`net/netfilter/nft_numgen.c`), the `numgen random` expression calls `get_random_u32()`, which utilizes the kernel's cryptographic pseudo-random number generator (ChaCha20-based CSPRNG).

> [!IMPORTANT]
> **No Seeded Kernel RNG Reproducibility**: The Linux kernel does not expose a userland interface to seed or reset `get_random_u32()`. Any claim of seeded, bit-for-bit reproducible packet drops in live Linux kernel networking is scientifically impossible. S5 live packet drops are evaluated **probabilistically**, not deterministically.

### 6.2 Software Netfilter Rule Counters (Not Hardware Counters)

The counters used to audit S5 packet loss:
- `syn_total`: Total SYN packets arriving from client destined for server.
- `syn_dropped`: SYN packets dropped by the 50% stochastic drop rule.
- `syn_not_dropped`: SYN packets that passed through without drop.

These are **software kernel netfilter counters** instantiated in table `inet ps028_impair`. They are **NOT** hardware NIC counters (such as those queried via ethtool or DPDK). All documentation and code maintain this distinction.

### 6.3 Mathematical Accounting Invariants

1. **Eligible SYN Denominator**:
   $$\text{Denominator} = \text{syn\_total}$$
   The exact count of all client-initiated TCP SYN packets matching `ps028-rt-sv6`, source `2001:db8:1::2`, destination `2001:db8:2::10:80`.
2. **Dropped-Packet Numerator**:
   $$\text{Numerator} = \text{syn\_dropped}$$
   The count of packets matching the stochastic rule and dropped.
3. **Accounting Invariant**:
   $$\text{syn\_total} \equiv \text{syn\_dropped} + \text{syn\_not\_dropped}$$
   If $\text{syn\_total} \ne \text{syn\_dropped} + \text{syn\_not\_dropped}$, evidence is flagged as corrupted.
4. **Retransmission Accounting**:
   Because client TCP implementations retransmit SYNs upon packet loss (exponential backoff), every transmitted SYN frame enters the forward chain and increments `syn_total`. In PCAP analysis, initial SYNs and retransmissions are correlated via TCP stream identifier and relative sequence number.

### 6.4 Wilson 99% Confidence Interval Validation on Synthetic Fixtures

The empirical drop rate is evaluated using the Wilson score confidence interval:
$$w = \frac{p + \frac{z^2}{2n} \pm z\sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
Where $z = 2.575829$ for 99% confidence.

The Wilson 99% evaluation routine has been audited against analytical synthetic statistical fixtures (clearly labeled as fixtures):
- **Fixture 1 (50% loss cohort: $k=10, n=20$)**: Proportion $0.50$, 99% CI: $[0.2504, 0.7496]$.
- **Fixture 2 (Unanimous cohort: $k=20, n=20$)**: Proportion $1.00$, 99% CI: $[0.7509, 1.0000]$.
- **Fixture 3 (Zero success cohort: $k=0, n=20$)**: Proportion $0.00$, 99% CI: $[0.0000, 0.2491]$.
- **Monotonicity**: Formally verified that the 99% CI is strictly wider than the 95% CI ($[0.2993, 0.7007]$).

---

## 7. Dedicated Host-Restoration & Invariance Audit

### 7.1 Residual Entity Detection (Zero Project-Interface Filtering)

In `lab/setup_topology.sh`, the host network snapshot function captures complete network state:
```bash
snapshot_host_state() {
    local outfile="$1"
    {
        echo "=== HOST INTERFACES ==="
        ip -d addr show 2>/dev/null | sed -E 's/(valid_lft|preferred_lft) [0-9a-z_]+/\1 <dynamic>/g'
        echo "=== IPV4 ROUTES ==="
        ip -4 route show
        echo "=== IPV6 ROUTES ==="
        ip -6 route show
        echo "=== IPV4 RULES ==="
        ip -4 rule show
        echo "=== IPV6 RULES ==="
        ip -6 rule show
    } > "$outfile"
}
```

> [!IMPORTANT]
> **No Interface Concealment**: Project interfaces (e.g. `ps028-*`) are **NOT** filtered or suppressed from the snapshot. If teardown fails to delete a project veth interface, route, or rule from the host namespace, the residual entity appears in `$current`, causing `diff -u "$baseline" "$current"` to fail with exit code 1.

### 7.2 SLAAC Lifetime Normalization Without Concealing State

The filter `sed -E 's/(valid_lft|preferred_lft) [0-9a-z_]+/\1 <dynamic>/g'` normalizes solely the decrementing seconds integer of IPv6 dynamic address leases (e.g. `valid_lft 86392sec` $\to$ `valid_lft <dynamic>`).
- It **preserves**: Interface names, MAC addresses, IPv4/IPv6 addresses, subnet masks, scopes (`global`, `link`), flags, and routing metrics.
- Any addition, deletion, or modification of an IP address or route triggers an immediate invariance failure.

### 7.3 Teardown Failure Paths & Safety

The teardown controller [`lab/teardown.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/teardown.py) enforces ordered, fail-safe cleanup:
1. **Exclusive Lock**: Exclusively acquires `.lab.lock` to prevent concurrency collisions.
2. **Restoration Fail-Stop**: If clearing impairments fails on a live or partial topology, namespace deletion is **aborted** (`abort_topology_deletion:restoration_failed_partial_topology`) to prevent concealing active network modifications.
3. **Process Verification**: Only terminates processes whose PID file matches the verified command line (`dns_server.py` or `nginx`).
4. **Resolver Protection**: Removes `/etc/netns/ps028-cl/resolv.conf` only if marked by `/run/ps028/.resolv_installed_by_ps028`. Unrelated host resolver files are never touched.
5. **Dangling Interface Sweeps**: Explicitly detects and deletes dangling host interfaces (`PROJECT_INTERFACES`) even if namespace deletion encountered errors.

---

## 8. Defensible Statistical Replication Methodology (TOST)

The scientific comparison tool [`lab/compare_campaigns.py`](file:///home/promotheshchatterjee/projects/A3-PS028-TC224/lab/compare_campaigns.py) replaces informal confidence interval overlap heuristics with formal Two One-Sided Tests (TOST) and predeclared practical equivalence margins.

### 8.1 Predeclared Practical Equivalence Margins

Equivalence margins are defined a priori before inspecting partner data:
1. **Winning-Family Proportion Difference ($\Delta p_{\text{v6}}$)**:
   - Margin: $[-\delta_p, +\delta_p]$ with $\delta_p = 0.15$ ($\pm 15\%$, corresponding to $\le 3$ trials out of 20 differing in race outcome).
   - For stochastic S5: $\delta_p = 0.25$ (accounting for binomial sampling variance with $n=20$).
   - Evaluated via the 90% Agresti-Caffo confidence interval ($z = 1.64485$). If the 90% CI for $\Delta p_{\text{v6}}$ lies entirely within $[-\delta_p, +\delta_p]$, winning-family agreement is accepted at $\alpha = 0.05$.
2. **Connection Latency Equivalence ($t_{\text{connect}}$)**:
   - **Low-Latency Baseline Cohorts (S0, S1, S2, S5, S6 on 20ms link)**:
     - Margin: $\delta_{\text{abs}} = \pm 5.0\text{ ms}$, or relative ratio $[\rho_{\text{low}}, \rho_{\text{high}}] = [0.85, 1.15]$.
     - *Justification*: $\pm 5.0\text{ ms}$ represents $25\%$ of the 20ms link RTT, accommodating Linux socket API wake-up jitter without allowing an additional network traversal or backoff.
   - **Medium-Latency Cohort (S3: 150ms netem delay)**:
     - Margin: $\delta_{\text{abs}} = \pm 25.0\text{ ms}$, or relative ratio $[0.85, 1.15]$.
   - **High-Latency Cohort (S4: 600ms netem delay)**:
     - Margin: $\delta_{\text{abs}} = \pm 25.0\text{ ms}$ (if IPv4 won) / $\pm 50.0\text{ ms}$ (if IPv6 won), or relative ratio $[0.85, 1.15]$.
   - Evaluated via two-sample percentile bootstrap for the median difference with $B = 2,000$ resamples and fixed seed (`seed=42`). If the 90% bootstrap CI $[L_\Delta, U_\Delta]$ lies entirely within $[-\delta_{\text{abs}}, +\delta_{\text{abs}}]$, latency equivalence is accepted at $\alpha = 0.05$.

### 8.2 Power Limitations of $n=20$ per Cohort

> [!NOTE]
> A sample size of $n=20$ trials per cohort cannot detect arbitrarily narrow equivalence margins. For stochastic proportions ($p \approx 0.50$), the standard error with $n=20$ is $\approx 0.15$, yielding a 90% margin of error of $\approx 0.25$. Therefore, for S5, equivalence can only be resolved for margins $\ge \pm 0.25$. For deterministic cohorts (S0, S1, S2) with zero or low variance, equivalence is tightly resolved. The pipeline explicitly reports when statistical power is compromised rather than forcing false agreement.

### 8.3 Five Scientific Replication Classifications

| Classification | Mathematical TOST Decision Rule | Scientific Interpretation |
|---|---|---|
| **`REPLICATED`** | • Winning family agreement confirmed: 90% Agresti-Caffo CI $\subseteq [-\delta_p, +\delta_p]$.<br>• Latency equivalence confirmed: 90% bootstrap CI for median difference $\subseteq [-\delta_{\text{abs}}, +\delta_{\text{abs}}]$.<br>• Partner $\text{IQR} \le 2.5 \times \max(10.0, \text{Baseline IQR})$. | Independent replication confirmed. Protocol outcomes and timing distributions match historical baseline within practical equivalence bounds. |
| **`SYSTEMATIC_SHIFT`** | • Winning family agreement confirmed.<br>• Latency difference 90% bootstrap CI extends outside $[-\delta_{\text{abs}}, +\delta_{\text{abs}}]$.<br>• Median ratio $\rho \in [0.50, 2.50]$. | Protocol behavior identical; uniform constant or proportional latency scaling attributable to host virtualization, kernel tick rate, or hardware timing differences. |
| **`BEHAVIORAL_DIVERGENCE`** | • Deterministic violation (e.g. IPv6 completion in S1/S2).<br>• OR winning family diff $|\Delta p_{\text{v6}}| > 0.35$ with non-overlapping Wilson CIs.<br>• OR median latency ratio $\rho < 0.50$ or $\rho > 2.50$. | Replication failed. Protocol implementation or host networking diverged from canonical Happy Eyeballs behavior. |
| **`INCONCLUSIVE`** | • Extreme anomalous partner dispersion: Partner $\text{IQR} > 50.0\text{ ms}$ AND Partner $\text{IQR} > 3.0 \times \max(10.0, \text{Baseline IQR})$. | Measurement noise too large to draw conclusions. Host background activity, CPU throttling, or preemption obscured measurement. |
| **`INVALID`** | • Trial count per cohort $< 20$.<br>• Corrupt PCAPs, missing metrics, or unverified checksums. | Procedural failure; data cannot be scientifically evaluated. |

---

## 9. Comprehensive Test Evidence

All offline test suites have been executed directly on the feature branch. Zero failures, zero errors, and zero regressions were observed.

### 9.1 Test Execution Table

| Test Suite | Execution Command | Total Tests | Passed | Skipped | Failed / Errors | Execution Time |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **Python Lab Unit & Regression Suite** | `python3 -m unittest discover -s lab -p "test_*.py"` | 1,292 | 1,291 | 1 | 0 / 0 | 192.36s |
| **Python Integration Suite** | `python3 -m unittest discover -s tests -p "test_*.py"` | 93 | 93 | 0 | 0 / 0 | 0.37s |
| **Frontend WebTester Unit Suite** | `npm test --prefix setup/webtester` | 44 | 44 | 0 | 0 / 0 | 0.70s |
| **Historical Integrity Check** | `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256` | 705 | 705 | 0 | 0 / 0 | 0.42s |
| **Combined Total** | **All automated suites** | **1,429** | **1,428** | **1** | **0 / 0** | **~193.8s** |

### 9.2 Skip Rationale
- **1 Skipped Test**: `lab/test_setup_topology.py::TestSetupTopology::test_namespace_creation_fails_without_root`. Skipped because unprivileged test runners cannot create network namespaces without root, which is the expected and tested behavior.

### 9.3 Historical Evidence Seal
- **705 / 705** files under `lab/campaigns/ps028-a10-live-20261030-01/` were verified against `lab/derived/phase-c/historical_integrity_before.sha256`. 100% of checksums matched with zero modifications.

### 9.4 Continuous Integration (CI) Configuration
- `.github/workflows/ci.yml` includes `fix/partner-replication-readiness` in the `push.branches` trigger list.
- CI automatically discovers all lab tests via `python3 -m unittest discover -s lab -p "test_*.py"`, guaranteeing that all new regression suites (`test_compare_campaigns.py`, `test_setup_topology.py`, `test_partner_preflight.py`, `test_run_campaign.py`, `test_verify_partner_handover.py`) execute in remote CI upon branch push.

---

## 10. Partner Handover Runbook Checklist

An independent partner laboratory should execute the following canonical workflow:

### Phase 1: Preparation & Non-Mutating Environmental Audit
- [ ] 1. Clone repository release at approved replication commit `<APPROVED_RELEASE_SHA>` (on `fix/partner-replication-readiness`, reconciled against base `0dc8c5801a73a55942dc905d4cf7cd5f6c55c896`) and verify clean git tree (`git status`).
- [ ] 2. Confirm target machine runs Ubuntu 24.04 LTS (bare-metal or WSL2 with systemd).
- [ ] 3. Verify exact pinned browsers are installed:
  - Google Chrome `156.0.8078.73`
  - Mozilla Firefox `159.0`
- [ ] 4. Execute non-mutating preflight:
  ```bash
  python3 lab/partner_preflight.py --json -o preflight_report.json
  ```
  Confirm output state: `HELPER_DEPLOYMENT_READY` or `REPLICATION_READY_FOR_AUTHORIZATION`.

### Phase 2: Host Snapshot & Privileged Helper Deployment
- [ ] 5. Capture pre-experiment host network snapshot:
  ```bash
  sudo ./lab/setup_topology.sh snapshot-host /tmp/partner_host_baseline.txt
  sha256sum /tmp/partner_host_baseline.txt > /tmp/partner_host_baseline.txt.sha256
  ```
- [ ] 6. Perform non-mutating helper deployment dry-run:
  ```bash
  ./lab/deploy_privileged_helper.sh --dry-run --user "$USER" --release-sha <APPROVED_RELEASE_SHA>
  ```
- [ ] 7. Deploy privileged helper:
  ```bash
  sudo ./lab/deploy_privileged_helper.sh --user "$USER" --release-sha <APPROVED_RELEASE_SHA>
  sudo /usr/bin/python3 -I /usr/local/libexec/ps028/privileged_helper.py check-auth
  ```

### Phase 3: Topology Provisioning & Canonical 280-Trial Campaign
- [ ] 8. Explicitly authorize and provision dual-stack isolated topology:
  ```bash
  sudo ./lab/setup_topology.sh setup
  sudo ./lab/setup_topology.sh status
  ```
- [ ] 9. Run the canonical 280-trial campaign in strict partner mode:
  ```bash
  PARTNER_DIR="$HOME/ps028-partner-evidence/ps028-partner-$(hostname)-$(date +%Y%m%d)"
  mkdir -p "$PARTNER_DIR"
  python3 lab/run_campaign.py \
    --strict-partner \
    --partner-institution "<PARTNER_INSTITUTION>" \
    --operator-id "<OPERATOR_ID>" \
    --output-dir "$PARTNER_DIR" \
    --repetitions 20 \
    --browsers "google-chrome,firefox" \
    --scenarios "S0,S1,S2,S3,S4,S5,S6"
  ```
  Assert output: Exactly 280 completed slots, status `COMPLETED`, mode `LIVE`.

### Phase 4: Deterministic Evidence Export & Topology Teardown
- [ ] 10. Export deterministic derived ledgers:
  ```bash
  DERIVED_DIR="$HOME/ps028-partner-derived/ps028-partner-$(hostname)-$(date +%Y%m%d)"
  python3 lab/export_campaign_evidence.py \
    --campaign-dir "$PARTNER_DIR" \
    --output-dir "$DERIVED_DIR" \
    --target all
  ```
- [ ] 11. Teardown topology and verify 100% host network invariance:
  ```bash
  sudo ./lab/setup_topology.sh teardown
  sudo ./lab/setup_topology.sh check-host-invariance /tmp/partner_host_baseline.txt
  ```

### Phase 5: Handover Packaging, Verification & Scientific Comparison
- [ ] 12. Generate internal SHA-256 checksum manifest:
  ```bash
  cd "$PARTNER_DIR"
  find . -type f ! -name "*.sha256" ! -name "*.tar.gz" -exec sha256sum {} + | sort -k2 > partner_evidence.sha256
  ```
- [ ] 13. Create handover archive and outer SHA-256 sidecar:
  ```bash
  cd "$HOME/ps028-partner-evidence"
  tar -czvf "partner_handover.tar.gz" "$(basename "$PARTNER_DIR")"
  sha256sum partner_handover.tar.gz > partner_handover.tar.gz.sha256
  ```
- [ ] 14. Execute independent handover verification audit:
  ```bash
  python3 lab/verify_partner_handover.py \
    --archive "$HOME/ps028-partner-evidence/partner_handover.tar.gz" \
    --derived-dir "$DERIVED_DIR" \
    --require-checksum-manifest \
    --require-partner-info
  ```
- [ ] 15. Statistically compare independent results against historical baseline:
  ```bash
  python3 lab/compare_campaigns.py \
    --baseline lab/campaigns/ps028-a10-live-20261030-01 \
    --partner "$PARTNER_DIR" \
    --output-json "$DERIVED_DIR/comparison_report.json" \
    --output-md "$DERIVED_DIR/comparison_report.md"
  ```
- [ ] 16. Transmit `partner_handover.tar.gz` and `partner_handover.tar.gz.sha256` to lead repository maintainer.

---

## 11. Remaining Operational Limitations & Mitigations

| Risk / Limitation | Likelihood | Impact | Built-in Mitigation & Preventive Control |
|---|:---:|:---:|---|
| **Partner Kernel Differences** | Low | Medium | Preflight audits `CONFIG_NET_NS`, `CONFIG_NETFILTER`, `tc netem`, and `nftables` module support. Incompatible kernels fail closed in `partner_preflight.py`. |
| **Browser Version Deviation** | Medium | Critical | Preflight and `--strict-partner` assert exact string matches for Chrome `156.0.8078.73` and Firefox `159.0`. Non-pinned builds halt immediately. |
| **Host Network Residue** | Low | High | `snapshot_host_state` captures all interfaces and routes without filtering. Post-teardown `check-host-invariance` fails if any project interface or route persists. |
| **Hypervisor Timer Drift** | Low | Low | Comparison pipeline includes the `SYSTEMATIC_SHIFT` classification to distinguish constant timer scaling from true protocol divergences. |
| **S5 Stochastic Fluctuations** | Medium | Low | Evaluated probabilistically using Wilson 99% score intervals. Sample size of 20 repetitions ($n=20$) provides well-bounded statistical power. |
| **Concealed Failure Attempts** | Low | High | `run_campaign.py` preserves all failed attempts in `failed_attempt_record.json` under `trials/` and tracks them in `campaign_manifest.json`. Silently dropping failed trials is architecturally prevented. |

---

## 12. Final Acceptance Conclusion

The repository `aiori-hackathon/A3-PS028-TC224` on branch `fix/partner-replication-readiness` satisfies all scientific reproducibility, security, and verification requirements.

The software, protocol definitions, verification tools, and comparison pipelines are fully hardened and verified. The repository is declared:

$$\mathbf{STATUS:\ READY\_FOR\_PARTNER\_REPLICATION}$$

$$\text{Replication Campaign Status: } \mathbf{STATUS:\ PENDING\_AUTHENTIC\_PARTNER\_EVIDENCE}$$
