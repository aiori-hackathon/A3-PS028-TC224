# PS-028 Phase D Experiment Protocol: Empirical Research Sweeps

- **Document Version**: `1.0.0` (Pre-Registered Research Protocol)
- **Status**: **PRE-IMPLEMENTATION PROTOCOL (DESIGN GATE)**
- **Governing Requirement**: AIORI-3 PS-028 / Master Prompt Section 4, 5, 7 (Step 0.7)
- **Applicability**: Phase D research runner (`lab/run_research_sweep.py`), sweep analyzers, and visualization tools.

---

## 1. Experimental Overview & Pre-Registration Mandate

Phase D extends the Happy Eyeballs measurement lab beyond canonical fixed-point scenarios (S0–S6) to systematically map browser connection racing dynamics across continuous parameter spaces:
1. **D1: Target IPv6 RTT Delay Sweeps**: Evaluating racing crossover points where IPv4 fallback overtakes delayed IPv6.
2. **D2: One-Factor DNS Delay Sweeps**: Evaluating client Resolution Delay and asynchronous query arrival dynamics for A and AAAA records.
3. **D3: Statistical Modeling & Visualizations**: Stratified Empirical CDFs, Wilson binomial confidence intervals, and crossover transition intervals.
4. **D4: Firefox Comparative Analysis**: Qualitative comparison between Firefox 159 observations and published Firefox 132 literature (Sattler et al. IMC 2025).
5. **D5: Multi-Host Readiness Framework**: Standardized partner manifest and capture runbook for second-host verification (status: PENDING authentic evidence).

### 1.1 Non-Negotiable Research Constraints
- **Rule R7 (No Conformance Claims)**: Sweeps observe client behavior under controlled stimuli. Deliberate delays at the DNS responder or network router are external stimuli, **not direct measurements of undocumented browser internals** (e.g. internal browser timers).
- **Amendment A2 (Sample Size Rigor & Pilot Labelling)**: Any condition point supporting a published claim, figure, or crossover interval MUST satisfy **$n \ge 20$ valid live trials per browser**. Exploratory runs with $n < 20$ are designated `PILOT/EXPLORATORY` and excluded from final claims. Top-up runs to reach $n \ge 20$ must be recorded as separate runs.
- **Amendment A6 (Netem Confound Elimination)**: All sweep points, including the nominal 0 ms condition, MUST apply an identical `tc netem` qdisc structure with explicit delay parameters (`delay 0ms` vs `delay Xms`), ensuring kernel queuing overhead is uniform across all conditions.
- **Amendment A10 (Specification Pin Integrity & Status Tracking)**: The campaign's pinned specification revision of record is `draft-ietf-v6ops-happy-eyeballs-v3-04`. It remains the immutable baseline of record. A dated status check (`Draft status check: 2026-11-11`) tracks Datatracker status without silently altering the pin. No draft is ever described as an RFC or settled standard.
- **Amendment A13 (Deterministic Ordering & Sibling Provenance)**: All sweep iterations MUST use a pre-persisted pseudorandom seed (`seed = 42`) and execute in blocked/interleaved order across browsers and conditions. Derived CSV/JSON outputs omit generation timestamps and store run provenance in `<filename>.provenance.json` sibling files.

---

## 2. Research Sweep D1: Target IPv6 RTT Sweeps

### 2.1 Independent Variable & Network Configuration (Decision 4)
- **Independent Variable**: Target IPv6 Round-Trip Time ($\text{RTT}_{\text{IPv6}}$).
- **Symmetric Link Splitting**: Netem delay is split symmetrically across both router-to-server and server-to-router IPv6 virtual ethernet links:
  $$\text{LinkDelay}_{\text{IPv6}} = \frac{\text{Target RTT}_{\text{IPv6}} - \text{Baseline Floor}}{2}$$
  *(Where Baseline Floor is the zero-delay loopback/veth overhead, typically $< 0.2\text{ ms}$)*.
- **Fixed Baseline IPv4 Path**: IPv4 remains clamped to canonical S0 baseline: $10\text{ ms}$ per link ($\sim 20\text{ ms}$ nominal IPv4 RTT).
- **0 ms Condition Definition**: "0 ms" signifies zero imposed netem delay (`netem delay 0ms 0ms`), not physical instantaneous transmission.
- **Pre-Declared RTT Tolerances (Amendment A6)**:
  Measured ping RTT between `ps028-cl` and `2001:db8:2::10` MUST fall within:
  $$\text{Tolerance} = \max\left( \pm 5.0\text{ ms}, \pm 5\% \text{ of target RTT} \right)$$
  Trials with measured RTT outside tolerance trigger automatic fail-stop.

---

### 2.2 Two-Stage Sweep Grid (Decision 5, Amendment A2)

```
Target IPv6 RTT (ms)
0      100     200   225 250 275 300   400     500     600     700     800
|-------|-------|-----|-|-|-|-|-----|-------|-------|-------|-------|
[-------- Screening Grid --------]   [-------- Screening Grid --------]
                [ Refinement Grid ]
```

#### Stage 1: Coarse Screening Grid
- **Condition Values**: $\{0, 100, 200, 300, 400, 500, 600, 700, 800\}\text{ ms}$ (9 points).
- **Sample Size**: $n = 20$ valid trials per browser condition ($9 \times 2 \times 20 = 360$ trials).
- **Objective**: Identify the broad interval where primary-family selection shifts from IPv6 to IPv4 fallback.

#### Stage 2: Fine Refinement Grid
- **Condition Values**: Centered around the observed transition (nominal $250\text{ ms}$ CAD window):
  $$\{200, 225, 250, 275, 300, 325, 350\}\text{ ms} \quad (\Delta = 25\text{–}50\text{ ms})$$
- **Sample Size**: $n = 20$ valid trials per browser condition ($7 \times 2 \times 20 = 280$ trials).
- **Objective**: Measure the crossover transition interval and transition slope with high statistical resolution.

---

## 3. Research Sweep D2: One-Factor DNS Delay Sweeps

### 3.1 Experimental Design (Decision 6, Amendment A8)
To evaluate how asynchronous DNS arrival impacts Happy Eyeballs racing independently of TCP link latency, two orthogonal one-factor sweeps are executed:

1. **Factor 1: AAAA Delay Sweep (A = 0 ms)**:
   - Immediate A record response ($A = 0\text{ ms}$ imposed delay).
   - Delayed AAAA record response:
     $$\text{Grid}_{\text{AAAA}} = \{0, 25, 50, 75, 100, 150, 250, 500, 800\}\text{ ms}$$
   - Evaluates client adherence to RFC 8305 §3 recommended $50\text{ ms}$ Resolution Delay.
2. **Factor 2: A Delay Sweep (AAAA = 0 ms)**:
   - Immediate AAAA record response ($\text{AAAA} = 0\text{ ms}$ imposed delay).
   - Delayed A record response:
     $$\text{Grid}_{\text{A}} = \{0, 25, 50, 75, 100, 150, 250, 500, 800\}\text{ ms}$$
   - Evaluates whether delayed A records impact immediate IPv6 connection establishment.

### 3.2 Distinct Observation Separation (Rule R7)
Three separate observations are tracked for every DNS trial:
1. **Imposed Server Delay ($\Delta_{\text{server}}$)**: Configured sleep parameter in DNS responder rules.
2. **Observed DNS Arrival Gap ($\Delta_{\text{pcap}}$)**: PCAP-dissected interval between client A response frame and AAAA response frame.
3. **Browser Connection Decision**: Observed address family of initial TCP SYN and winning HTTP transaction.

Under no circumstances will a browser's failure to wait for AAAA be asserted as a protocol violation; it is reported strictly as observed behavior relative to RFC 8305 §3 recommendations.

---

## 4. Confound Controls & Hygiene Protocol

### 4.1 Client DNS Confounds (Amendment A8)
- **DoH / TRR Disabling**:
  - Google Chrome: `--disable-features=DnsOverHttps --dns-over-https-mode=off`
  - Mozilla Firefox: `user_pref("network.trr.mode", 5)`
- **Cache Elimination**:
  - Fresh ephemeral profile created for every trial and unlinked immediately after PCAP capture.
  - Target hostname is unique per trial: `trial-<uuid4_hex[:8]>.he.test` (Amendment A7).
  - DNS responder configured with wildcard zone `*.he.test.`.
- **HTTPS/SVCB Handling**:
  - DNS responder configured to return deterministic `NOERROR` with empty answer (NODATA) for QTYPE 65 (`HTTPS`) within $0\text{ ms}$.

### 4.2 S5 Stochastic Loss & Binomial Stopping Rule (Decision 7, Amendment A11)
- **Separate Evidence Classes**: Router aggregate counters, per-TCP-flow PCAP statistics, and controlled per-probe records MUST remain distinct. Router aggregate counters MUST NEVER be cited as per-socket drop proof.
- **Pre-Registered Acceptance Window**:
  - Batch size: $n = 200$ synthetic connection probes inside `ps028-cl`.
  - Nominal drop rate: $p = 0.50$ (50%).
  - Confidence Level: $99\%$ ($\alpha = 0.01$).
  - Exact Binomial Confidence Interval: Clopper-Pearson interval $[p_L, p_U]$ calculated as:
    $$p_L = B\left(\frac{\alpha}{2};\, k,\, n - k + 1\right), \quad p_U = B\left(1 - \frac{\alpha}{2};\, k + 1,\, n - k\right)$$
  - Acceptance Rule: Batch passes iff $[p_L, p_U]$ encloses $0.50$.
  - Re-run Rule: No silent re-running. If a batch fails, the run is rejected, state is preserved, and the incident is recorded in the self-test bundle.

---

## 5. Statistical Analysis & Visualizations (D3)

### 5.1 Stratified Empirical Cumulative Distribution Functions (Amendment A5)
- All latency distributions ($t_{\text{connect\_ms}}$, $t_{\text{setup\_total\_ms}}$, $\text{CAD}$) MUST be plotted as ECDFs **stratified by winning address family and condition**.
- Failed, timed-out, or unpairable connections MUST NEVER be pooled into successful latency distributions.
- Every ECDF curve MUST display its effective sample size $n$ and failed count $n_{\text{failed}}$ directly in the plot legend.

### 5.2 Wilson Score Confidence Intervals for Primary-Family Share
For each condition point, the proportion of trials where IPv4 won navigation ($p_{\text{v4}} = k / n$) is reported with a 95% Wilson score confidence interval:
$$\hat{p} \pm \frac{z}{1 + \frac{z^2}{n}} \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}} \quad \text{where } z = 1.95996$$

### 5.3 Crossover Transition Interval Estimation
- **Definition**: The parameter interval $[\text{RTT}_{\text{lower}}, \text{RTT}_{\text{upper}}]$ over which the winning share crosses $50\%$.
- **Primary Estimant**: The observed laboratory crossover interval:
  $$\text{Crossover} = \left[ \max \left\{ \text{RTT} \mid p_{\text{v4}} < 0.50 \right\}, \; \min \left\{ \text{RTT} \mid p_{\text{v4}} \ge 0.50 \right\} \right]$$
- **Secondary Estimant**: Seeded parametric logistic regression fit:
  $$P(\text{IPv4 wins}) = \frac{1}{1 + e^{-(\beta_0 + \beta_1 \cdot \text{RTT})}}$$
  Solving for $\text{RTT}_{50\%} = -\frac{\beta_0}{\beta_1}$ with 95% bootstrap confidence interval ($B=2,000, \text{seed}=42$).
- **Reporting Rule**: Plainly state that the crossover point is a laboratory selection transition under specific testbed queuing constraints, not a universal path threshold.

---

## 6. Literature & Multi-Host Protocols (D4, D5)

### 6.1 Firefox Comparative Analysis Protocol (Decision 8)
- **External Literature Reference**: Sattler et al. "Lazy Eye Inspection: Capturing the State of Happy Eyeballs Implementations" (ACM IMC 2025).
- **Comparison Scope**: Qualitative comparison between Firefox 159 (tested in this laboratory) and published Firefox 132 findings.
- **Prohibited Claims**: No assertions of browser improvement, performance regression, or standards compliance.
- **Mandatory Disclosures**:
  1. *Browser Build*: Firefox 159.0 (this lab) vs Firefox 132.0 (IMC 2025).
  2. *OS Environment*: WSL2 Linux kernel 6.18 on Ubuntu 24.04 vs native Linux/macOS/Windows public web testing.
  3. *Resolver Infrastructure*: Controlled local single-hop DNS responder vs open internet resolvers.
  4. *Impairment Mechanics*: Kernel netem delay and nftables stateful dropping vs live wide-area transit paths.

### 6.2 Multi-Host Readiness Protocol (Decision 9)
- **Status of Deliverable A.6**: Kept marked **PENDING** until authentic partner evidence is supplied.
- **Host Segregation**: Second-host evidence (bare-metal Ubuntu vs VM vs WSL2) MUST remain in an independent dataset. Data from different host classes MUST NEVER be pooled into unified statistical distributions.
- **Readiness Artifacts**:
  1. Predeclared subset condition manifest: $\{S0, S1, S2, S4, S5, S6\}$ plus sweep endpoints ($0\text{ ms}, 300\text{ ms}, 800\text{ ms}$).
  2. Environment capture script: recording kernel version, CPU topology, NIC driver, and virtualized container flags.
  3. Operator runbook for partner replication.
