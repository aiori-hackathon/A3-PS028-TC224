# PS-028 Happy Eyeballs — P1 Validation Record (14 November 2026)

## 1. Validation Metadata and Environment

- **Repository:** `https://github.com/aiori-hackathon/A3-PS028-TC224.git`
- **Validation Branch:** `work/ps028-p1-remediation`
- **Accepted P0 Baseline Tag:** `ps028-p0-accepted-2026-11-14`
- **Accepted P0 Commit SHA:** `176f688bacb5858fcc0daedb454200918e427f3f`
- **Tested P1 Source Commit SHA:** `ee59362ac3f53fad3bc01e65b5d90815697a93d4`
- **Validation Timestamp:** `2026-11-14T16:19:30Z`
- **Operating System:** Linux 6.18.58.1-microsoft-standard-WSL2 x86_64
- **Python Version:** 3.12.3
- **Node.js Version:** v22.14.0
- **npm Version:** 10.9.2
- **Browser Engine:** Google Chrome 157.0.8103.50
- **GitHub CI Status:** Local validation completed; remote GitHub CI is not configured or recorded.

---

## 2. Test Execution Inventory and Disaggregated Taxonomy

All tests executed against source commit `ee59362ac3f53fad3bc01e65b5d90815697a93d4`.

### 2.1 Unique Automated Unit & Regression Tests (929 Tests)

| Tier | Test Command | Module / File Scope | Discovered | Passed | Failed | Errors | Skipped | Duration |
|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Python Lab Unit & Regression** | `python3 -m unittest discover -s lab -p "test_*.py"` | 21 modules in `lab/` | **805** | **805** | 0 | 0 | 0 | 43.79s |
| **Python Integration Tier** | `python3 -m unittest discover -s tests -p "test_*.py"` | 2 modules in `tests/` | **93** | **93** | 0 | 0 | 0 | 0.35s |
| **Frontend Unit Tests** | `node --experimental-strip-types --test test/historical-evidence.test.mjs` | `setup/webtester/test/historical-evidence.test.mjs` | **31** | **31** | 0 | 0 | 0 | 0.67s |
| **Total Automated Unit Definitions** | Disaggregated Unique Definitions | Unit & Regression Tier | **929** | **929** | **0** | **0** | **0** | **44.81s** |

*Note on Test Inclusion:* The 4 authentic PCAP regression tests in `lab/test_campaign_pcap_regression.py` are discovered and included within the 805 Python lab unit tests. Their separate execution below is a dedicated preservation check, not additional unique test definitions.

### 2.2 Static Distribution and Smoke Verification (16 Checks)

- **Command:** `npm run test:smoke` (in `setup/webtester`)
- **Script:** `setup/webtester/scripts/smoke-test-preview.mjs`
- **Checks Executed:** 16 checks (HTTP routes, headers, HTML mount, WebCrypto SHA-256 digest calculation against sidecar, trial cohorts, and isolation)
- **Status:** **PASSED** (16/16 checks verified; 0 failures)

### 2.3 Genuine Browser Acceptance Suite (8 Stages, 53 Assertions)

- **Command:** `npm run test:browser` (in `setup/webtester`)
- **Script:** `setup/webtester/test/browser-acceptance.test.mjs`
- **Execution Engine:** Playwright with Chromium (Google Chrome 157.0.8103.50)
- **Coverage:**
  - Stage 1: Page mount and hydration verified
  - Stage 2: Overview statistics and integrity badge verified ("Digest Consistent (Same-Origin)")
  - Stage 3: Tab switching verified across all 7 views
  - Stage 4: S2 cohort filter and search interaction verified
  - Stage 5: Timeline event packet provenance verified in live DOM (`#`, `Frame`, `Details & Provenance`, `source:`)
  - Stage 6: Cryptographic hash mismatch fail-safe behavior verified across all 7 analytical tabs
  - Stage 7: S5 invariant strict failure verified on missing underlying flow data
  - Stage 8: Health check confirmed 0 page errors, 0 console errors, 0 failed network requests
- **Status:** **PASSED** (8/8 stages passed; 53 assertions verified; 0 errors)

### 2.4 Production Build Verification

- **Command:** `npm run build` (in `setup/webtester`)
- **Output Directory:** `setup/webtester/dist/`
- **Pages Built:** 8 static pages built in 3.09s
- **Status:** **PASSED** (0 errors)

### 2.5 Dedicated Post-Validation Preservation Checks

- **Command:** `python3 -m unittest lab/test_campaign_pcap_regression.py`
- **Checks Executed:** 4 tests (S0–S5 live PCAP re-dissection against authentic captures)
- **Status:** **PASSED** (4/4 passed in 1.95s)

---

## 3. Cryptographic Campaign Evidence Preservation

All authentic campaign measurement evidence remains 100% bit-for-bit preserved from the audited root:

| Verification Target | Command / Manifest | Total Entries | Verified | Mismatches | Status |
|:---|:---|:---:|:---:|:---:|:---:|
| **Historical Evidence Seal** | `sha256sum -c lab/derived/phase-c/historical_integrity_before.sha256` | 705 | 705 | 0 | **VERIFIED** |
| **Complete Evidence Archive** | `lab/campaigns/ps028-a10-live-20261030-01/complete_evidence_sha256_manifest.txt` | 1,411 | 1,411 | 0 | **VERIFIED** |
| **Campaign PCAP Digest Index** | `sha256sum -c lab/recovery/pcap_sha256_checksums.relative.txt` | 280 | 280 | 0 | **VERIFIED** |

---

## 4. Historical P0 Validation Record Integrity

The historical P0 validation record at `lab/derived/phase-c/test_run_record.json` (recording 928 unit tests, commit `5c84c93eff12903a1288770029a903aec48ac1a4`) remains completely untouched and preserved as immutable historical P0 evidence.
