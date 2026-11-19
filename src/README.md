# PS-028 Source Code Architecture Notice

> [!NOTE]
> This root `src/` directory is an organizational placeholder retained from the hackathon repository template.
> Active application source code and experimental infrastructure are modularized across dedicated directories:

| Component | Directory | Description |
|---|---|---|
| **Measurement Lab & Analysis Engine** | [`lab/`](../lab/) | Python network namespace orchestrator, scenario impairment engine (`nftables`/`tc netem`), DNS responder, PCAP analysis, and automated PDF report compilation. |
| **Frontend WebTester Application** | [`setup/webtester/src/`](../setup/webtester/src/) | Astro v5 / React 19 interactive Historical Evidence Explorer, Scenario Analytics Dashboard, and browser-facing WebTester client. |
| **E2E & Adversarial Test Suites** | [`tests/`](../tests/) | 5-tier independent verification suite covering specification compliance, boundaries, pairwise combinations, and adversarial stress tests. |
| **Research Documentation & Runbooks** | [`docs/`](../docs/) | Scientific reports, reproducibility runbooks, metric contracts, compliance matrices, and historical audit logs. |
