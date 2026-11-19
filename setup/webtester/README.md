# PS-028 WebTester & Evidence Explorer Frontend

**Team AlgoRhythm** · **AIORI Hackathon 3** · **PS-028: Internet Measurement**

This directory contains the source code for the PS-028 interactive web application, built with **Astro v5**, **React 19**, and **Tailwind CSS v4**.

It provides two primary capabilities:
1. **Historical Evidence Explorer & Analytics Dashboard**: Offline, client-side exploration of the October 2026 Happy Eyeballs experimental campaign (`ps028-a10-live-20261030-01`), including 280 valid live trials, 2 excluded cleanup failures, 765 TCP connection attempts, and 28,330 synchronized timeline events with full SHA-256 cryptographic provenance verification.
2. **Browser-Facing WebTester**: Interactive browser tests for measuring client-side Happy Eyeballs behaviors (Connection Attempt Delay, Resolution Delay, HTTP/3 availability, HEv3 QUIC/TLS).

---

## 1. Architecture & Framework Stack

- **Framework**: [Astro v5](https://astro.build/) in pure static mode (`output: "static"`).
- **UI Components**: [React 19](https://react.dev/), [Radix UI](https://www.radix-ui.com/), and [shadcn/ui](https://ui.shadcn.com/) components styled with [Tailwind CSS v4](https://tailwindcss.com/).
- **Icons**: [Lucide React](https://lucide.dev/).
- **Client-Side PDF Generation**: [jsPDF](https://github.com/parallax/jsPDF) for dynamic analytics report exports.
- **Testing**: Node.js native test runner (`node --test`), Playwright for real-browser Chromium acceptance.
- **Target Runtime**: Node.js 22 LTS (CI uses Node.js 22.14.0).
- **Output Directory**: `dist/` (static HTML, CSS, JavaScript, and staged data assets).

---

## 2. Route Inventory

The application statically builds 8 distinct pages:

| Route | Source File | Description | Operational Scope |
|---|---|---|---|
| `/` | `src/pages/index.astro` | **Laboratory Home Page**: Executive overview, navigation cards for evidence exploration, analytics, and browser tests. | Static presentation |
| `/evidence` | `src/pages/evidence.astro` | **Historical Evidence Explorer**: Interactive data grid, multi-source event timeline (Harness, PCAP, Browser Telemetry), TCP connection attempt inspector, excluded attempts isolation, RFC 8305 assessment cards, and WebCrypto SHA-256 integrity checks. | Client-side hydrated (`<EvidenceExplorer client:load />`) using pre-compiled `demo_bundle.json` |
| `/analytics` | `src/pages/analytics.astro` | **Scenario Analytics Dashboard**: Interactive Tukey box plots, latency distributions, winner ratios (IPv6 vs IPv4), cross-cohort comparative filters (S0–S6, Chrome vs Firefox), and dynamic PDF report export. | Client-side hydrated (`<AnalyticsDashboard client:load />`) |
| `/tests/connection-attempt-delay` | `src/pages/tests/connection-attempt-delay.astro` | **Connection Attempt Delay (CAD) Test**: Tests visitor client IPv6-to-IPv4 fallback racing when IPv6 delay is injected. | Browser-facing client test |
| `/tests/resolution-delay` | `src/pages/tests/resolution-delay.astro` | **Resolution Delay Test**: Evaluates client fallback behavior under delayed AAAA DNS responses. | Browser-facing client test |
| `/tests/http3-availability` | `src/pages/tests/http3-availability.astro` | **HTTP/3 Availability Test**: Checks client HTTP/3 (QUIC) capability. | Browser-facing client test |
| `/tests/hev3-quic-tls` | `src/pages/tests/hev3-quic-tls.astro` | **HEv3 QUIC & TLS Test**: Evaluates Happy Eyeballs v3 protocol racing across QUIC and TLS endpoints. | Browser-facing client test |
| `/tests/hev3-combined` | `src/pages/tests/hev3-combined.astro` | **HEv3 Combined Test**: Comprehensive Happy Eyeballs v3 feature evaluation suite. | Browser-facing client test |

---

## 3. Data Ingestion & Cryptographic Provenance

The Evidence Explorer and Analytics Dashboard consume a deterministic, schema-versioned demonstration data bundle:
- **Source**: `lab/derived/phase-e/demo_bundle.json` (17.32 MB / 18,157,449 bytes).
- **Staging Script**: `scripts/prepare-historical-data.mjs`.
- **Target**: `public/data/demo_bundle.json`.
- **Provenance Sidecar**: `public/data/demo_bundle.json.provenance.json`.
- **Verified SHA-256**: `42fad72c342c0e986c12502b0f9f82dbfc2d22fed0ea7e2709ee4469588c4b86`.

Before every build or development server start, `scripts/prepare-historical-data.mjs`:
1. Locates the authoritative source bundle in `lab/derived/phase-e/`.
2. Computes the SHA-256 digest of the file.
3. Compares the hash against `demo_bundle.json.provenance.json`.
4. Copies the verified bundle into `public/data/demo_bundle.json` for static asset distribution.
5. If the digest mismatches or the provenance sidecar is absent, the build fails closed.

---

## 4. Local Installation & Development Workflow

### Prerequisites
- Node.js 22.x LTS (`node --version`)
- npm 10.x or higher (`npm --version`)

### Quick Start
From the `setup/webtester` directory:

```bash
# 1. Install locked dependencies
npm ci

# 2. Run unit tests
npm test

# 3. Astro TypeScript diagnostics and type check
npm run check

# 4. Start local development server (http://localhost:4321)
npm run dev
```

---

## 5. Production Build & Quality Gates

The frontend enforces a strict 4-stage quality gate matching the CI workflow:

```bash
# Stage 1: Unit Tests
# Executes 44 unit tests covering schema validation, cohort math, provenance, Tukey fences, and PDF export
npm test

# Stage 2: Astro Type Check
# Validates TypeScript types and template diagnostics across all 73 source files
npm run check

# Stage 3: Static Production Build
# Stages verified demo bundle and compiles static site to dist/ (8 pages)
npm run build

# Stage 4: Distribution Smoke Tests
# Serves dist/ locally and executes 16 automated HTTP and data-integrity verification checks
npm run test:smoke

# Stage 5: Genuine Browser Acceptance Suite (Chromium via Playwright)
# Launches a genuine headless browser, walks through all 19 stages, verifies 260 assertions
npx playwright install --with-deps chromium
npm run test:browser
```

---

## 6. Deployment & Operational Scope

- **Live Deployment**: [https://ps028-happy-eyeballs.vercel.app/](https://ps028-happy-eyeballs.vercel.app/)
- **Vercel Git Integration**: Current Vercel Git integration is connected to personal repository `Promothesh-Chatterjee/ps028-happy-eyeballs` rather than directly to `aiori-hackathon/A3-PS028-TC224`. Live data payload parity (`demo_bundle.json` byte length and SHA-256) is verified; direct Git webhook reconnection to the official AIORI repository remains a manual owner decision.
- **Environment Variables**: None required. Inspection of source code confirms that all routes and build steps operate with zero runtime or build-time environment variable dependencies.
- **Static Deployment Boundaries & Parity**:
  - The deployed application runs strictly as static HTML, CSS, and client-side JavaScript.
  - Verification of the demonstration bundle digest confirms evidence payload parity, but does not establish byte-for-byte identity of every compiled frontend HTML/JS/CSS asset across independent build environments.
  - The Historical Evidence Explorer and Analytics Dashboard inspect the committed historical campaign data offline in the user's browser.
  - The deployment **does not** execute the Linux network-namespace laboratory testbed (`ps028-cl`, `ps028-rt`, `ps028-sv`). Kernel network namespaces, `nftables` packet filtering, and `tc netem` link impairments require a Linux host with root/sudo permissions, as documented in [`docs/PS028_REPRODUCIBILITY_RUNBOOK.md`](../../docs/PS028_REPRODUCIBILITY_RUNBOOK.md).
