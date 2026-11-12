# Phase D: Paused Status & Simulation-Only Disclosure

**Status**: PAUSED BY OWNER DECISION  
**Effective Date**: 2026-11-12  
**Primary Project Focus**: Completion & Verification of Phase C (Scientific Credibility) and Demonstration Preparation.

---

## 1. Executive Notice

Phase D empirical research live sweeps have been **PAUSED** by explicit owner directive.

### Mandatory Data Disclosures
* **Zero Live Measurements**: No live network sweeps, browser trials, kernel impairments, or privileged commands were executed for Phase D.
* **Simulation-Only Modeling**: All data, figures, transition intervals, and regression curves residing under `lab/derived/phase-d/` are **purely synthetic simulation models** (`is_simulation=true`, `data_source="SIMULATION"`).
* **No Empirical Research Claims**: No crossover threshold, transition interval (e.g. $[300, 325]\text{ ms}$ for Chrome or $[400, 500]\text{ ms}$ for Firefox), or one-factor DNS sensitivity number represents an empirical or live network measurement. All such numbers represent offline statistical simulations and mathematical proofs based on historical CAD offsets.

---

## 2. Phase D Resume Checklist

When the project owner decides to resume Phase D for live data collection, the following strict protocol must be adhered to:

1. **Human Gate Authorization**:
   - Obtain formal user approval in-chat prior to executing any privileged commands (`sudo`, `tc`, `nft`, `ip netns`, daemon lifecycles).
2. **Privilege Boundary**:
   - Run browser automation and measurement drivers as the normal unprivileged user (`promotheshchatterjee`).
   - Route network-impairing and capture actions strictly through the allowlisted `ps028-helper` binary or `lab/privileged_helper.py`.
3. **Execution Grid**:
   - Execute the exact pre-registered grid:
     * D1 Target IPv6 RTT Sweep: $n=20$ trials per condition across target $\text{RTT} \in [10, 20, 30, 40, 50, 75, 100, 150, 200, 250, 300, 350, 400, 500]\text{ ms}$.
     * D2 One-Factor DNS Delay Sweep: $n=20$ trials per condition across $T_{\text{AAAA\_delay}} \in [0, 50, 100, 150, 200, 250, 300, 350, 400, 500]\text{ ms}$.
4. **Isolated Data Path**:
   - Stage all new live trials in `lab/derived/phase-d/live/` or a freshly initialized campaign directory outside the October 29 campaign tree.
   - Tag all live outputs with `"data_type": "LIVE"`, `"simulation": false`.
5. **Teardown & Verification**:
   - Run `sudo ./lab/teardown.sh` upon completion.
   - Run `./lab/setup_topology.sh check-host-invariance` to verify 100% restoration of host network state.
