# Phase D: Paused Status & Simulation-Only Disclosure

**Status**: REMOVED FROM CURRENT PLAN BY OWNER DECISION
**Effective Date**: 2026-11-12 (Confirmed 2026-11-15 for Final Release)
**Primary Project Focus**: Completion, Verification, and Submission of Core Phase C/E Deliverables on Authoritative Branch `fix/phase-e-bundle-timeline-mapping`.

---

## 1. Executive Notice

Phase D empirical research live sweeps (D1 target IPv6 RTT sweeps, D2 one-factor DNS-delay sweeps, D3 empirical crossover sweeps, and D4 live Firefox comparisons) have been **EXPLICITLY REMOVED** from the current project plan by owner decision.

There is **no planned Phase D resume task** in the hackathon submission and handover schedule.

### Mandatory Data Disclosures
* **Zero Live Measurements**: No live network sweeps, browser trials, kernel impairments, or privileged commands were executed for Phase D.
* **Simulation-Only Modeling**: All data, figures, transition intervals, and regression curves residing under `lab/derived/phase-d/` are **purely synthetic simulation models** (`is_simulation=true`, `data_source="SIMULATION"`).
* **No Empirical Research Claims**: No crossover threshold, transition interval (e.g. $[300, 325]\text{ ms}$ for Chrome or $[400, 500]\text{ ms}$ for Firefox), or one-factor DNS sensitivity number represents an empirical or live network measurement. All such numbers represent offline statistical simulations and mathematical proofs based on historical CAD offsets.
* **Preservation as Historical Records**: Simulation datasets, analytical models, and figures are preserved as historical artifacts and must never be altered or conflated with authentic Phase C campaign evidence.

---

## 2. Long-Term Future Work Reference (Non-Hackathon Scope)

If independent research is conducted in post-hackathon cycles, any live data collection must adhere to the following protocol:

1. **Human Gate Authorization**:
   - Obtain formal user approval prior to executing any privileged commands (`sudo`, `tc`, `nft`, `ip netns`, daemon lifecycles).
2. **Privilege Boundary**:
   - Run browser automation and measurement drivers as the normal unprivileged user (`promotheshchatterjee`).
   - Route network-impairing and capture actions strictly through the allowlisted `ps028-helper` binary or `lab/privileged_helper.py`.
3. **Execution Grid**:
   - Execute the exact pre-registered grid:
     * D1 Target IPv6 RTT Sweep: $n=20$ trials per condition across target $\text{RTT} \in [10, 20, 30, 40, 50, 75, 100, 150, 200, 250, 300, 350, 400, 500]\text{ ms}$.
     * D2 One-Factor DNS Delay Sweep: $n=20$ trials per condition across $T_{\text{AAAA\_delay}} \in [0, 50, 100, 150, 200, 250, 300, 350, 400, 500]\text{ ms}$.
4. **Isolated Data Path**:
   - Stage all new live trials in a separate repository or freshly initialized campaign directory outside the October 29 campaign tree.
   - Tag all live outputs with `"data_type": "LIVE"`, `"simulation": false`.
5. **Teardown & Verification**:
   - Run `sudo ./lab/teardown.sh` upon completion.
   - Run `./lab/setup_topology.sh check-host-invariance` to verify 100% restoration of host network state.
