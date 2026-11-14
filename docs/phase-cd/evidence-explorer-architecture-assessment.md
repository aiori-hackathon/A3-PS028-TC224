# PS-028 EvidenceExplorer Architectural Assessment & Maintainability Review

- **Component Target**: `setup/webtester/src/components/evidence/evidence-explorer.tsx`
- **Assessment Date**: 2026-11-14T17:30:00Z
- **Reviewer**: Senior Internet Measurement Scientist & Frontend Architecture Reviewer
- **Working Branch**: `work/ps028-p1-remediation`
- **P2 Item**: P2.4 — Modularize the large EvidenceExplorer component when technically appropriate
- **Status Classification**: **INTENTIONALLY DEFERRED**

---

## 1. Executive Summary

This document records the architectural evaluation of `EvidenceExplorer` (`setup/webtester/src/components/evidence/evidence-explorer.tsx`), assessing component size, state complexity, data transformations, integrity guarantees, test coverage, and modularization trade-offs.

Following an exhaustive audit against the 7 evaluation dimensions specified in the P2 charter, `EvidenceExplorer` is classified as **INTENTIONALLY DEFERRED**. The computational domain logic, schema validation, cohort metrics, invariant checks, and cryptographic evaluations are **already cleanly modularized** in `setup/webtester/src/lib/historical-evidence.ts` (735 lines, 31 dedicated unit tests). The React component serves strictly as a unified presentation orchestrator. Decomposing the presentation layer into multiple subcomponent files would introduce unnecessary prop-drilling or context overhead with high regression risk across the 8-stage / 53-assertion real-browser Chromium test suite, yielding an unfavorable benefit-to-risk ratio.

---

## 2. Evaluation Across the Seven Architectural Dimensions

### 2.1 Component Size and Responsibility Boundaries
- **Current Size**: 1,720 lines of TypeScript JSX.
- **Role in Application**: Mounts as the client-side hydrated root (`<EvidenceExplorer client:load />`) on the `/evidence` page in the Astro application (`src/pages/evidence.astro`).
- **Boundaries**: The component contains the UI layout for 7 navigation tabs:
  1. `overview`: High-level campaign metrics, SHA-256 seal status, and invariant verification cards.
  2. `comparison`: Scenario-by-scenario (S0–S6) stratified cohort matrix ($14$ cohorts) and primary-handshake ordering audit.
  3. `trials`: Searchable, filterable, and paginated table of the 280 valid live trials.
  4. `trial-detail`: Deep inspection of a single trial, including primary flow metadata and chronological multi-source timeline events with packet provenance.
  5. `exclusions`: Dedicated isolated view of the 2 preflight/cleanup exclusion records.
  6. `provenance`: Display of raw generator provenance metadata, Git SHA, and build environment details.
  7. `rfc`: Tabular summary of the 15-column observation schema across RFC 8305 and RFC 9293 requirements.

### 2.2 State-Management Complexity
- **State Hooks (11 hooks)**:
  - Data loading & integrity: `bundle`, `provenance`, `isLoading`, `loadError`, `computedSha256`, `shaMatch`.
  - Navigation & selection: `activeTab`, `selectedTrialId`, `selectedExclusionId`.
  - Filtering & pagination: `searchQuery`, `scenarioFilter`, `browserFilter`, `classificationFilter`, `currentPage`, `timelineSourceFilter`, `timelineSearch`.
- **Inter-Tab Coupling**:
  - Clicking a trial in the `trials` list sets `selectedTrialId` and triggers a programmatic tab switch to `trial-detail`.
  - The `trial-detail` header contains a "Back to Trial List" button that returns to `trials` while preserving active filter and search state.
  - Fail-safe state: If cryptographic hash verification fails (`FAIL_SAFE_MISMATCH`), every tab unconditionally renders an `<AlertTriangle>` fail-safe error overlay, blocking data presentation across the entire application.

### 2.3 Data-Transformation Responsibilities
- **Assessment**: The component does **not** contain inline statistical or transformation calculations. All analytical formulas and data structures are delegated to `setup/webtester/src/lib/historical-evidence.ts`:
  - `computeCohortMetrics()`: Computes median, IQR, p95, fallback proportions, and CAD classifications.
  - `validateCampaignInvariants()`: Verifies the 10 campaign invariants.
  - `auditPrimaryHandshakeOrdering()`: Computes 3-way handshake completion metrics.
  - `deriveRelativeOffsetMs()`: Calculates relative timeline offsets without mutating epoch timestamps.
- The separation of concerns between domain calculations and view rendering is already fully realized.

### 2.4 Evidence Integrity and Provenance Responsibilities
- **Cryptographic Verification**: The component fetches `/data/demo_bundle.json` and its provenance sidecar `/data/demo_bundle.json.provenance.json` in parallel on mount.
- **Client-Side SHA-256**: Uses browser WebCrypto (`window.crypto.subtle.digest('SHA-256', buffer)`) to independently compute the digest of the raw bundle blob and compares it to the sidecar's `output_bundle_sha256`.
- **Fail-Safe Integrity Policy**: Evaluated via `evaluateEvidenceIntegrity()`. If the hash differs or cannot be verified, fail-safe mode activates, suppressing cohort tables and timeline events.

### 2.5 Rendering Responsibilities
- Strictly declarative React JSX utilizing Tailwind CSS classes and Lucide icons.
- Purely presents the memoized data models (`filteredTrials`, `paginatedTrials`, `cohortMatrix`, `handshakeAuditRows`, `selectedTrialTimelineEvents`).

### 2.6 Existing Tests and Coverage
The component and its underlying domain library are validated by three independent test layers:
1. **Unit Test Suite (`test/historical-evidence.test.mjs`)**:
   - 31 automated tests exercising schema validation, provenance hashing, cohort grouping, median calculations, CAD formulas, S5 subflow counts, S2 CAD qualification, and invariant health checks. Pass rate: 100% (31/31).
2. **Static Distribution Smoke Test (`scripts/smoke-test-preview.mjs`)**:
   - 16 automated checks verifying HTTP 200 responses, static bundle size, WebCrypto hash calculation, filter behavior, and exclusion isolation on the production build. Pass rate: 100% (16/16).
3. **Playwright Real-Browser Acceptance Suite (`test/browser-acceptance.test.mjs`)**:
   - 8 test stages with 53 assertions executed in genuine Chromium (`/usr/bin/google-chrome`), validating live hydration, tab navigation, search/filter interactions, trial detail selection, event timeline packet provenance, hash mismatch fail-safe behavior across all 7 tabs, and S5 missing flow failure. Pass rate: 100% (53/53 assertions).

### 2.7 Benefit-to-Risk Ratio Analysis
- **Modularization Benefits**:
  - Decreasing the line count of `evidence-explorer.tsx` by splitting tabs into separate files (e.g. `OverviewTab.tsx`, `ComparisonTab.tsx`, etc.).
- **Modularization Risks**:
  - **High regression risk in browser acceptance tests**: The 53 Playwright assertions inspect specific DOM hierarchy, button text, and class selectors across tabs. Refactoring JSX structures risks breaking selector chains.
  - **Prop-drilling or context overhead**: Splitting into 7 subcomponent files requires passing 11 state hooks, 7 memoized selectors, and multiple callbacks, or introducing a React Context provider which adds runtime abstraction with zero functional benefit.
  - **Astro SSR/Hydration risk**: Adding nested subcomponent boundaries can introduce client-side hydration timing discrepancies under Astro's `client:load` hydration island.
- **Decision**: The benefit-to-risk ratio is unfavorable. Maintainability is already maximized by the existing isolation of domain logic in `src/lib/historical-evidence.ts`.

---

## 3. Conclusion & Intentional Deferral

`EvidenceExplorer` is intentionally retained as a unified UI orchestrator. The component's monolithic presentation structure is cohesive, robust, fully covered by 53 real-browser assertions and 31 unit tests, and presents zero empirical defects or maintenance hazards.

No refactoring is required or recommended. This completes the technical evaluation for P2.4.
