/**
 * Playwright Browser Acceptance Test Suite for PS-028 Historical Evidence Explorer
 *
 * Launches a real Chromium/Google Chrome browser instance via Playwright to exercise
 * the production-built Evidence Explorer web application in an actual browser engine.
 *
 * Fulfills Audit Findings #5, #13, #19, and #20:
 * 1. Launches genuine browser engine (Chromium / Google Chrome).
 * 2. Navigates to `/evidence` and verifies hydration and bundle loading.
 * 3. Verifies overview metrics, campaign statistics, and integrity badges.
 * 4. Verifies tab switching across all 7 analytical views.
 * 5. Exercises interactive trial search (positive match, negative match with empty state, clearing).
 * 6. Exercises trial pagination controls, boundary disabled states, and filter-reset behavior.
 * 7. Exercises trial detail inspection and connection attempt metrics.
 * 8. Exercises timeline multi-source filtering (HARNESS, PCAP, TELEMETRY, ALL).
 * 9. Exercises timeline text search and event-level packet provenance display.
 * 10. Exercises Excluded Attempts tab inspection, lifecycle events, and zero empirical leakage.
 * 11. Exercises Provenance & Integrity tab (sidecar SHA-256, generator metadata, input file hashes).
 * 12. Exercises RFC 8305 Assessment tab (all 7 normative check cards, section attributions, sample sizes).
 * 13. Exercises cryptographic hash-mismatch fail-safe state across all 7 tabs via request routing.
 * 14. Exercises S5 missing-data invariant failure state via deterministic bundle routing.
 * 15. Verifies zero uncaught page errors, console errors, or network request failures.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '../dist');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

async function runBrowserAcceptanceTests() {
  console.log('================================================================================');
  console.log('PS-028 Genuine Browser-Level Acceptance Test Suite');
  console.log('Engine: Playwright with Chromium (Real Browser)');
  console.log('================================================================================');

  if (!fs.existsSync(distDir)) {
    throw new Error(`Production dist directory does not exist at ${distDir}. Run 'npm run build' first.`);
  }

  // 1. Create static HTTP server for production build
  const server = http.createServer((req, res) => {
    let reqPath;

    // Decode URL-encoded paths before filesystem lookup.
    // Browser requests encode spaces as %20.
    try {
      reqPath = decodeURIComponent(
        new URL(req.url || '/', 'http://127.0.0.1').pathname
      );
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Bad Request');
      return;
    }

    // Convert URL path into a relative filesystem path.
    const relativePath = reqPath.replace(/^[/\\]+/, '');
    let filePath = path.resolve(distDir, relativePath);

    // Prevent paths from escaping the production dist directory.
    const isInsideDist = (candidate) => {
      const relative = path.relative(distDir, candidate);

      return (
        relative === '' ||
        (relative !== '..' &&
          !relative.startsWith(`..${path.sep}`) &&
          !path.isAbsolute(relative))
      );
    };

    if (!isInsideDist(filePath)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    // Resolve directory routes to index.html.
    if (reqPath.endsWith('/')) {
      filePath = path.join(filePath, 'index.html');
    } else if (!path.extname(relativePath)) {
      const indexPath = path.join(filePath, 'index.html');

      if (fs.existsSync(indexPath)) {
        filePath = indexPath;
      }
    }

    if (!isInsideDist(filePath)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('Forbidden');
      return;
    }

    // Return 404 only when the actual decoded file is missing.
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': contentType,
    });
    fs.createReadStream(filePath).pipe(res);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[OK] Preview HTTP server listening on ${baseUrl}`);

  // 2. Launch real browser
  const chromePath = '/usr/bin/google-chrome';
  const launchOptions = {
    headless: true,
    args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
  };
  if (fs.existsSync(chromePath)) {
    launchOptions.executablePath = chromePath;
  }

  console.log(`[INFO] Launching browser (executable: ${launchOptions.executablePath || 'bundled chromium'})...`);
  const browser = await chromium.launch(launchOptions);
  const browserVersion = browser.version();
  console.log(`[OK] Browser launched successfully: Chromium/Chrome ${browserVersion}`);

  const pageErrors = [];
  const consoleErrors = [];
  const failedRequests = [];
  const httpErrors = [];
  let testsPassed = 0;
  let testsFailed = 0;

  function assert(condition, message) {
    if (!condition) {
      testsFailed++;
      throw new Error(`ASSERTION FAILED: ${message}`);
    }
    testsPassed++;
  }

  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    // Listen to console and page errors
    page.on('pageerror', (err) => {
      pageErrors.push(err.message || String(err));
    });
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const location = msg.location();

        consoleErrors.push(
          `${msg.text()} | Source: ${location.url}:${location.lineNumber}`
        );
      }
    });
    // Record HTTP errors with their actual URLs.
    page.on('response', (response) => {
      if (response.status() >= 400) {
        const request = response.request();

        httpErrors.push(
          `${response.status()} ${request.method()} ${request.resourceType()} ${response.url()}`
        );
      }
    });
    page.on('requestfailed', (req) => {
      failedRequests.push(`${req.method()} ${req.url()}: ${req.failure()?.errorText}`);
    });

    // -------------------------------------------------------------------------
    // TEST STAGE 1: Real Navigation and Hydration Verification
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 1] Navigating to /evidence and verifying hydration...');
    await page.goto(`${baseUrl}/evidence`, { waitUntil: 'networkidle', timeout: 30000 });

    // Wait for Evidence Explorer to mount
    await page.waitForSelector('[data-testid="evidence-explorer-mounted"]', { timeout: 15000 });
    const titleText = await page.textContent('h1');
    assert(titleText.includes('Historical Evidence'), 'Page title must include Historical Evidence');
    console.log('  [PASS] Page mounted and hydrated successfully');

    // -------------------------------------------------------------------------
    // TEST STAGE 2: Campaign Metadata and Overview Statistics
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 2] Verifying overview metrics and integrity badge...');
    const bodyText = await page.textContent('body');
    assert(bodyText.includes('ps028-a10-live-20261030-01'), 'Campaign ID must be present in DOM');
    assert(bodyText.includes('HISTORICAL_LIVE'), 'Evidence type must be HISTORICAL_LIVE');
    assert(bodyText.includes('280'), 'Must display 280 valid live trials');
    assert(bodyText.includes('28,330') || bodyText.includes('28330'), 'Must display 28,330 timeline events');

    // Check integrity badge
    const badgeElement = await page.waitForSelector('[data-testid="integrity-status-badge"]', { timeout: 5000 });
    const badgeText = await badgeElement.textContent();
    assert(badgeText.includes('Digest Consistent'), 'Integrity badge must indicate Digest Consistent (Same-Origin)');
    assert(!badgeText.includes('Provenance Verified'), 'Must NOT claim Provenance Verified for same-origin hashes');
    console.log(`  [PASS] Overview statistics and integrity badge verified ("${badgeText.trim()}")`);

    // -------------------------------------------------------------------------
    // TEST STAGE 3: Tab Navigation
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 3] Exercising tab switching...');
    // Click "Scenario & Cohort Comparison" tab
    await page.click('button:has-text("Scenario & Cohort Comparison")');
    await page.waitForTimeout(300);
    const comparisonText = await page.textContent('body');
    assert(comparisonText.includes('Historical Campaign Cohort Matrix') || comparisonText.includes('S0'), 'Matrix comparison tab must render');

    // Click "Trial Explorer" tab
    await page.click('button:has-text("Trial Explorer")');
    await page.waitForTimeout(300);
    assert(await page.isVisible('input[placeholder*="Search by trial ID"]'), 'Search input must be visible on Trials tab');
    console.log('  [PASS] Tab switching verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 4: Interactive Trial Search (Positive, Negative, and Clear)
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 4] Exercising interactive trial search (positive, negative, and clear)...');
    const searchInputSelector = 'input[placeholder*="Search by trial ID"]';

    // 4.1 Positive search: Search for an authoritative trial ID
    const targetTrialId = 'trial-20261029205425-6cb90a54';
    await page.fill(searchInputSelector, targetTrialId);
    await page.waitForTimeout(300);

    let rows = await page.$$('tbody tr');
    assert(rows.length === 1, `Expected exactly 1 matching row for query '${targetTrialId}', got ${rows.length}`);
    const matchedTrialText = await page.textContent('tbody tr:first-child');
    assert(matchedTrialText.includes(targetTrialId), `Matched row must contain ${targetTrialId}`);
    assert(matchedTrialText.includes('S0'), 'Matched row for target trial must be scenario S0');
    console.log('  [PASS] Positive trial search returned exact matching record');

    // 4.2 Negative search: Search for a nonexistent trial ID
    const nonexistentQuery = 'trial-nonexistent-99999999-deadbeef';
    await page.fill(searchInputSelector, nonexistentQuery);
    await page.waitForTimeout(300);

    const emptyTableText = await page.textContent('tbody');
    assert(
      emptyTableText.includes('No valid trials match the selected filter criteria.'),
      'Empty state message must be displayed when query matches zero trials'
    );
    rows = await page.$$('tbody tr');
    assert(rows.length === 1, 'Empty state must render single informational row');
    console.log('  [PASS] Negative trial search displayed empty state message');

    // 4.3 Clear search query: Restores full default page
    await page.fill(searchInputSelector, '');
    await page.waitForTimeout(300);

    rows = await page.$$('tbody tr');
    assert(rows.length === 15, `Clearing search query must restore 15 paginated rows, got ${rows.length}`);
    console.log('  [PASS] Clearing search query restored default paginated view');

    // -------------------------------------------------------------------------
    // TEST STAGE 5: Trial Pagination Controls & Filter Reset Behavior
    // -------------------------------------------------------------------------
    // Verify all trials were restored after clearing the search.
    const trialCountSummary = await page
    .getByTestId('trial-count-summary')
  .textContent();

assert(
  trialCountSummary.includes('Showing 280 of 280'),
  `Expected all 280 trials to be restored, got '${trialCountSummary}'`
);

// Use a stable test identifier instead of Tailwind CSS classes.
const paginationTextLocator = page
  .getByTestId('trial-pagination')
  .locator('span')
  .first();

let paginationText = await paginationTextLocator.textContent();

assert(
  paginationText.includes('Page 1 of 19'),
  `Expected initial pagination 'Page 1 of 19', got '${paginationText}'`
);

    // Verify Previous button is disabled on page 1
    const prevBtnDisabled = await page.getAttribute('button[aria-label="Previous Page"]', 'disabled');
    assert(prevBtnDisabled !== null, 'Previous Page button must be disabled on page 1');

    // Click Next Page button
    const firstTrialPage1 = (await page.textContent('tbody tr:first-child td:first-child')).trim();
    await page.click('button[aria-label="Next Page"]');
    await page.waitForTimeout(300);

    paginationText = await paginationTextLocator.textContent();
    assert(paginationText.includes('Page 2 of 19'), `Expected 'Page 2 of 19' after clicking Next, got '${paginationText}'`);
    const firstTrialPage2 = (await page.textContent('tbody tr:first-child td:first-child')).trim();
    assert(firstTrialPage1 !== firstTrialPage2, `Page 2 first trial (${firstTrialPage2}) must differ from Page 1 (${firstTrialPage1})`);

    // Click Previous Page button to return to page 1
    await page.click('button[aria-label="Previous Page"]');
    await page.waitForTimeout(300);
    paginationText = await paginationTextLocator.textContent();
    assert(paginationText.includes('Page 1 of 19'), `Expected 'Page 1 of 19' after clicking Previous, got '${paginationText}'`);

    // Filter by Scenario S2 (40 trials -> 3 pages of 15, 15, 10)
    await page.selectOption('select[aria-label="Filter trials by scenario"]', 'S2');
    await page.waitForTimeout(300);
    paginationText = await paginationTextLocator.textContent();
    assert(paginationText.includes('Page 1 of 3'), `Expected 'Page 1 of 3' for Scenario S2, got '${paginationText}'`);

    // Navigate to page 2 of S2
    await page.click('button[aria-label="Next Page"]');
    await page.waitForTimeout(300);
    paginationText = await paginationTextLocator.textContent();
    assert(paginationText.includes('Page 2 of 3'), `Expected 'Page 2 of 3', got '${paginationText}'`);

    // Now change browser filter to google-chrome (20 trials -> 2 pages of 15, 5)
    // Filter change MUST reset currentPage back to 1
    await page.selectOption('select[aria-label="Filter trials by browser"]', 'google-chrome');
    await page.waitForTimeout(300);
    paginationText = await paginationTextLocator.textContent();
    assert(paginationText.includes('Page 1 of 2'), `Filter change must reset pagination to 'Page 1 of 2', got '${paginationText}'`);

    // Click "Reset Filters" button
    await page.click('button:has-text("Reset Filters")');
    await page.waitForTimeout(300);
    paginationText = await paginationTextLocator.textContent();
    assert(paginationText.includes('Page 1 of 19'), `Reset filters must restore 'Page 1 of 19', got '${paginationText}'`);
    console.log('  [PASS] Pagination controls, page boundaries, and filter-reset behavior verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 6: Trial Selection, Connection Attempts & Detail View
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 6] Selecting a representative trial and verifying detail view...');
    // Search for targetTrialId to inspect it deterministically
    await page.fill(searchInputSelector, targetTrialId);
    await page.waitForTimeout(300);

    // Click "Inspect" button
    await page.click('tbody tr:first-child button:has-text("Inspect")');
    await page.waitForTimeout(400);

    const detailContent = await page.textContent('body');
    assert(detailContent.includes(targetTrialId), 'Trial detail view must show selected trial ID');
    assert(detailContent.includes('Recorded TCP Connection Attempts'), 'Trial detail connection attempts must render');
    assert(detailContent.includes('Classification:'), 'Classification section must render');
    assert(detailContent.includes('Chronological Multi-Source Event Timeline'), 'Timeline section must render');
    console.log('  [PASS] Trial detail view and connection attempts verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 7: Timeline Multi-Source Filtering
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 7] Exercising timeline multi-source filtering (HARNESS, PCAP, TELEMETRY, ALL)...');
    const sourceSelect = 'select[aria-label="Filter events by source"]';
    const timelineRowsSelector = 'div.max-h-\\[500px\\] table tbody tr';

    // Verify baseline trial has multi-source events
    let initialTimelineRows = await page.$$(timelineRowsSelector);
    assert(initialTimelineRows.length > 10, `Initial timeline must contain multiple events, got ${initialTimelineRows.length}`);

    // 7.1 Filter by HARNESS
    await page.selectOption(sourceSelect, 'HARNESS');
    await page.waitForTimeout(200);
    let harnessRows = await page.$$(timelineRowsSelector);
    assert(harnessRows.length > 0, 'HARNESS filter must return events');
    for (const row of harnessRows) {
      const badge = await row.$eval('td:nth-child(4)', (el) => el.textContent.trim());
      assert(badge === 'HARNESS', `Expected HARNESS badge in source column, got '${badge}'`);
    }
    console.log(`  [PASS] Filtered by HARNESS: ${harnessRows.length} events, all verified`);

    // 7.2 Filter by PCAP
    await page.selectOption(sourceSelect, 'PCAP');
    await page.waitForTimeout(200);
    let pcapRows = await page.$$(timelineRowsSelector);
    assert(pcapRows.length > 0, 'PCAP filter must return events');
    for (const row of pcapRows) {
      const badge = await row.$eval('td:nth-child(4)', (el) => el.textContent.trim());
      assert(badge === 'PCAP', `Expected PCAP badge in source column, got '${badge}'`);
    }
    console.log(`  [PASS] Filtered by PCAP: ${pcapRows.length} events, all verified`);

    // 7.3 Filter by BROWSER_TELEMETRY
    await page.selectOption(sourceSelect, 'BROWSER_TELEMETRY');
    await page.waitForTimeout(200);
    let telemRows = await page.$$(timelineRowsSelector);
    assert(telemRows.length > 0, 'BROWSER_TELEMETRY filter must return events');
    for (const row of telemRows) {
      const badge = await row.$eval('td:nth-child(4)', (el) => el.textContent.trim());
      assert(badge === 'TELEMETRY', `Expected TELEMETRY badge in source column, got '${badge}'`);
    }
    console.log(`  [PASS] Filtered by BROWSER_TELEMETRY: ${telemRows.length} events, all verified`);

    // 7.4 Reset source filter to ALL
    await page.selectOption(sourceSelect, 'ALL');
    await page.waitForTimeout(200);
    let restoredTimelineRows = await page.$$(timelineRowsSelector);
    assert(
      restoredTimelineRows.length === initialTimelineRows.length,
      `Resetting to ALL sources must restore initial ${initialTimelineRows.length} rows, got ${restoredTimelineRows.length}`
    );
    console.log('  [PASS] Reset source filter to ALL: all events restored');

    // -------------------------------------------------------------------------
    // TEST STAGE 8: Timeline Text Search & Packet Provenance Verification
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 8] Exercising timeline text search and packet provenance details...');
    const timelineSearchInput = 'input[placeholder="Filter events..."]';

    // 8.1 Search for 'SYN'
    await page.fill(timelineSearchInput, 'SYN');
    await page.waitForTimeout(200);
    let synRows = await page.$$(timelineRowsSelector);
    assert(synRows.length > 0, "Searching for 'SYN' must return TCP SYN events");
    for (const row of synRows) {
      const rowText = await row.textContent();
      assert(rowText.toUpperCase().includes('SYN'), "Each matched event must contain 'SYN'");
    }
    console.log(`  [PASS] Timeline search for 'SYN' returned ${synRows.length} matching events`);

    // 8.2 Negative search in timeline
    await page.fill(timelineSearchInput, 'NONEXISTENT_EVENT_STRING_XYZ_9999');
    await page.waitForTimeout(200);
    let nonExistentRows = await page.$$(timelineRowsSelector);
    assert(nonExistentRows.length === 0, `Nonexistent search query must yield 0 timeline rows, got ${nonExistentRows.length}`);
    console.log('  [PASS] Timeline negative search returned 0 rows');

    // 8.3 Clear timeline search
    await page.fill(timelineSearchInput, '');
    await page.waitForTimeout(200);

    // Verify packet provenance display: Frame column and source paths
    const timelineTableHtml = await page.innerHTML('div.max-h-\\[500px\\] table');
    assert(timelineTableHtml.includes('Frame'), 'Timeline header must contain Frame column');
    assert(timelineTableHtml.includes('source:'), 'Timeline details must contain source provenance path');
    console.log('  [PASS] Event-level packet provenance display verified in timeline');

    // -------------------------------------------------------------------------
    // TEST STAGE 9: Excluded Attempts Tab Inspection & Zero Leakage Audit
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 9] Exercising Excluded Attempts tab and verifying zero empirical leakage...');
    await page.click('button:has-text("Excluded Attempts")');
    await page.waitForTimeout(300);

    const exclusionsText = await page.textContent('body');
    assert(exclusionsText.includes('Isolated Cleanup Failure Exclusions'), 'Excluded attempts header must render');
    assert(exclusionsText.includes('trial-20261029205442-aba6193c'), 'Firefox S0 cleanup failure trial must be listed');
    assert(exclusionsText.includes('trial-20261029210226-944fcfaa'), 'Chrome S6 helper permission error trial must be listed');
    assert(exclusionsText.includes('CLEANUP_FAILURE'), 'Validity category CLEANUP_FAILURE must be displayed');

    // Assert exactly 2 exclusion cards rendered
    const exclusionCards = await page.$$('div.grid.md\\:grid-cols-2 > div');
    assert(exclusionCards.length === 2, `Expected exactly 2 exclusion cards, got ${exclusionCards.length}`);

    // Click card 1 and verify selection border ring
    await exclusionCards[0].click();
    await page.waitForTimeout(200);
    let card1Class = await exclusionCards[0].getAttribute('class');
    assert(card1Class.includes('ring-amber-500'), 'Card 1 must have active ring styling on selection');

    // Click card 2 and verify selection updates
    await exclusionCards[1].click();
    await page.waitForTimeout(200);
    let card2Class = await exclusionCards[1].getAttribute('class');
    assert(card2Class.includes('ring-amber-500'), 'Card 2 must have active ring styling on selection');

    // Verify lifecycle events rendered within exclusion cards
    assert(exclusionsText.includes('Preserved Boundary Lifecycle Events'), 'Exclusion card must display preserved boundary events');
    assert(exclusionsText.includes('TRIAL_START'), 'Lifecycle must include TRIAL_START');
    assert(exclusionsText.includes('TRIAL_END'), 'Lifecycle must include TRIAL_END');

    // Return to Campaign Overview tab and verify valid trials count remains strictly 280
    await page.click('button:has-text("Campaign Overview")');
    await page.waitForTimeout(300);
    const overviewText = await page.textContent('body');
    assert(overviewText.includes('280'), 'Valid trials count must remain strictly 280 (zero leakage of exclusions)');
    console.log('  [PASS] Excluded attempts inspection and zero empirical leakage verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 10: Provenance & Integrity Tab Verification
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 10] Exercising Provenance & Integrity tab and verifying sidecar metadata...');
    await page.click('button:has-text("Provenance & Integrity")');
    await page.waitForTimeout(300);

    const provContent = await page.textContent('body');
    assert(provContent.includes('Cryptographic Provenance Verification'), 'Provenance header must render');
    assert(provContent.includes('42fad72c342c0e986c12502b0f9f82dbfc2d22fed0ea7e2709ee4469588c4b86'), 'Must display authoritative output bundle SHA-256');
    assert(provContent.includes('lab/build_demo_bundle.py'), 'Must display generator script name');
    assert(provContent.includes('ps028-a10-live-20261030-01'), 'Must display campaign identifier');

    // Verify input artifacts checksum table
    assert(provContent.includes('Input Artifacts Cryptographic Hashes'), 'Input artifacts table must render');
    assert(provContent.includes('attempts.csv'), 'Input artifacts must include attempts.csv');
    assert(provContent.includes('campaign_manifest.json'), 'Input artifacts must include campaign_manifest.json');
    assert(provContent.includes('rfc8305_assessment.csv'), 'Input artifacts must include rfc8305_assessment.csv');
    assert(provContent.includes('reconciliation_report.csv'), 'Input artifacts must include reconciliation_report.csv');

    // Status badge on provenance tab
    const provBadge = await page.textContent('[data-testid="provenance-integrity-status-badge"]');
    assert(provBadge.includes('Bit-for-bit SHA-256 Match'), 'Provenance badge must confirm Bit-for-bit SHA-256 Match');
    console.log('  [PASS] Cryptographic provenance metadata and input file hashes verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 11: RFC 8305 Assessment Tab Verification
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 11] Exercising RFC 8305 Assessment tab and verifying all 7 normative checks...');
    await page.click('button:has-text("RFC 8305 Assessment")');
    await page.waitForTimeout(300);

    const rfcContent = await page.textContent('body');
    assert(rfcContent.includes('RFC 8305 & Happy Eyeballs v3 (draft -04) Compliance Evaluation'), 'RFC assessment title must render');
    assert(rfcContent.includes('7 normative checks extracted'), 'Must state 7 normative checks');

    // Check 1: RFC8305-SEC2-IPV6-PREFERENCE (Section 2 attribution & RFC 6724)
    assert(rfcContent.includes('RFC8305-SEC2-IPV6-PREFERENCE'), 'Must render RFC8305-SEC2-IPV6-PREFERENCE card');
    assert(rfcContent.includes('RFC 8305 Section 2'), 'Must cite RFC 8305 Section 2');
    assert(rfcContent.includes('RFC 6724 Section 2.1, Section 6 Rule 6, Section 10.3') || rfcContent.includes('RFC 6724'), 'Must cite RFC 6724 address selection rules');
    assert(rfcContent.includes('ALIGNED'), 'RFC8305-SEC2-IPV6-PREFERENCE must be ALIGNED');

    // Check 2: RFC8305-SEC3-RESOLUTION-DELAY
    assert(rfcContent.includes('RFC8305-SEC3-RESOLUTION-DELAY'), 'Must render RFC8305-SEC3-RESOLUTION-DELAY card');
    assert(rfcContent.includes('OUTSIDE_RECOMMENDED_RANGE'), 'RFC8305-SEC3-RESOLUTION-DELAY must be OUTSIDE_RECOMMENDED_RANGE');
    assert(rfcContent.includes('501.190 ms') || rfcContent.includes('501.19'), 'Must show observed median resolution delay');

    // Check 3: RFC8305-SEC5-CAD-10MS-FLOOR
    assert(rfcContent.includes('RFC8305-SEC5-CAD-10MS-FLOOR'), 'Must render RFC8305-SEC5-CAD-10MS-FLOOR card');
    assert(rfcContent.includes('NOT_ASSESSED'), 'RFC8305-SEC5-CAD-10MS-FLOOR must be NOT_ASSESSED');

    // Check 4: RFC8305-SEC5-CAD-HIGH-LATENCY
    assert(rfcContent.includes('RFC8305-SEC5-CAD-HIGH-LATENCY'), 'Must render RFC8305-SEC5-CAD-HIGH-LATENCY card');

    // Check 5: RFC8305-SEC5-CAD-SYN-TIMEOUT
    assert(rfcContent.includes('RFC8305-SEC5-CAD-SYN-TIMEOUT'), 'Must render RFC8305-SEC5-CAD-SYN-TIMEOUT card');

    // Check 6: HEV3-DRAFT04-SEC6.1-QUIC
    assert(rfcContent.includes('HEV3-DRAFT04-SEC6.1-QUIC'), 'Must render HEV3-DRAFT04-SEC6.1-QUIC card');
    assert(rfcContent.includes('OUT_OF_SCOPE'), 'HEV3-DRAFT04-SEC6.1-QUIC must be OUT_OF_SCOPE');

    // Check 7: RFC8305-SEC4-HISTORICAL-STATE
    assert(rfcContent.includes('RFC8305-SEC4-HISTORICAL-STATE'), 'Must render RFC8305-SEC4-HISTORICAL-STATE card');

    // Count rendered cards
    const rfcCards = await page.$$('div.space-y-3 > div.rounded-lg.border.bg-card');
    assert(rfcCards.length === 7, `Expected exactly 7 RFC check cards, got ${rfcCards.length}`);
    console.log(`  [PASS] All 7 RFC 8305 assessment cards verified with correct section attribution`);

    // -------------------------------------------------------------------------
    // TEST STAGE 12: Negative Case — Cryptographic Hash Mismatch Fail-Safe State
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 12] Testing cryptographic hash mismatch fail-safe state across all 7 analytical tabs...');
    const mismatchContext = await browser.newContext();
    const mismatchPage = await mismatchContext.newPage();

    // Deterministically intercept provenance sidecar to simulate hash mismatch
    await mismatchPage.route('**/demo_bundle.json.provenance.json', async (route) => {
      const response = await route.fetch();
      const provJson = await response.json();
      provJson.output_bundle_sha256 = 'f'.repeat(64); // Tampered hash
      await route.fulfill({
        response,
        body: JSON.stringify(provJson),
        headers: { 'Content-Type': 'application/json' },
      });
    });

    await mismatchPage.goto(`${baseUrl}/evidence`, { waitUntil: 'networkidle', timeout: 30000 });
    await mismatchPage.waitForSelector('[data-testid="evidence-explorer-mounted"]', { timeout: 15000 });

    // Verify prominent persistent warning banner appears
    await mismatchPage.waitForSelector('[data-testid="integrity-mismatch-banner"]', { timeout: 5000 });
    const bannerText = await mismatchPage.textContent('[data-testid="integrity-mismatch-banner"]');
    assert(bannerText.includes('Hash Mismatch'), 'Mismatch banner must warn of Hash Mismatch');
    assert(bannerText.includes('Unverified Inspection Mode'), 'Banner must declare Unverified Inspection Mode');

    const mismatchBadge = await mismatchPage.textContent('[data-testid="integrity-status-badge"]');
    assert(mismatchBadge.includes('Hash Mismatch (Unverified)'), 'Badge must reflect unverified state');

    // Overview Invariant badge must report unverified
    const invariantBadge = await mismatchPage.textContent('[data-testid="invariants-status-badge"]');
    assert(invariantBadge.includes('Unverified (Hash Mismatch)'), 'Invariant badge must show Unverified (Hash Mismatch)');

    // Exercise all 7 tabs in hash-mismatch state and assert persistent unverified state
    const tabsToTest = [
      { name: 'Campaign Overview', button: 'button:has-text("Campaign Overview")' },
      { name: 'Scenario Comparison', button: 'button:has-text("Scenario & Cohort Comparison")' },
      { name: 'Trial Explorer', button: 'button:has-text("Trial Explorer")' },
      { name: 'Selected Trial Detail', button: 'button:has-text("Selected Trial Detail")' },
      { name: 'Excluded Attempts', button: 'button:has-text("Excluded Attempts")' },
      { name: 'Provenance & Integrity', button: 'button:has-text("Provenance & Integrity")' },
      { name: 'RFC 8305 Assessment', button: 'button:has-text("RFC 8305 Assessment")' },
    ];

    for (const tab of tabsToTest) {
      await mismatchPage.click(tab.button);
      await mismatchPage.waitForTimeout(100);

      // Warning banner must remain visible on all tabs
      const isBannerVisible = await mismatchPage.isVisible('[data-testid="integrity-mismatch-banner"]');
      assert(isBannerVisible, `Warning banner must remain visible on tab: ${tab.name}`);

      // Top badge must consistently report unverified
      const badgeTextVal = await mismatchPage.textContent('[data-testid="integrity-status-badge"]');
      assert(badgeTextVal.includes('Hash Mismatch (Unverified)'), `Integrity badge on ${tab.name} must show Hash Mismatch (Unverified)`);

      // Never display authentic / verified confirmation on any tab
      const pageTextVal = await mismatchPage.textContent('body');
      assert(!pageTextVal.includes('Digest Consistent (Same-Origin)'), `Tab ${tab.name} must never show Digest Consistent`);
      assert(!pageTextVal.includes('Bit-for-bit SHA-256 Match'), `Tab ${tab.name} must never show Bit-for-bit Match in unverified state`);

      // Special check on Provenance tab
      if (tab.name === 'Provenance & Integrity') {
        const provMismatchBadge = await mismatchPage.textContent('[data-testid="provenance-integrity-status-badge"]');
        assert(provMismatchBadge.includes('Cryptographic Mismatch (Unverified)'), 'Provenance badge must show Cryptographic Mismatch (Unverified)');
      }
    }

    await mismatchContext.close();
    console.log('  [PASS] Cryptographic hash mismatch fail-safe behavior verified across all 7 tabs');

    // -------------------------------------------------------------------------
    // TEST STAGE 13: Negative Case — S5 Invariant Missing Data Failure State
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 13] Testing S5 invariant failure when underlying flow data is missing...');
    const s5Context = await browser.newContext();
    const s5Page = await s5Context.newPage();

    // Deterministically intercept bundle to simulate empty S5 flow records
    let modifiedHash = '';
    await s5Page.route('**/demo_bundle.json', async (route) => {
      const response = await route.fetch();
      const bundleJson = await response.json();
      // Empty S5 flow dissections across all trials
      for (const t of bundleJson.trials) {
        if (t.scenario_id === 'S5') {
          t.s5_flow_dissection = [];
        }
      }
      // Note: reconciliation_summary.s5_flows_count is intentionally left as 95 to verify summary fallback cannot save it
      const bodyStr = JSON.stringify(bundleJson);
      modifiedHash = crypto.createHash('sha256').update(bodyStr).digest('hex');
      await route.fulfill({
        response,
        body: bodyStr,
        headers: { 'Content-Type': 'application/json' },
      });
    });

    // Also update provenance sidecar with the matching hash so integrity is satisfied and invariant failure is isolated
    await s5Page.route('**/demo_bundle.json.provenance.json', async (route) => {
      const response = await route.fetch();
      const provJson = await response.json();
      provJson.output_bundle_sha256 = modifiedHash;
      await route.fulfill({
        response,
        body: JSON.stringify(provJson),
        headers: { 'Content-Type': 'application/json' },
      });
    });

    await s5Page.goto(`${baseUrl}/evidence`, { waitUntil: 'networkidle', timeout: 30000 });
    await s5Page.waitForSelector('[data-testid="evidence-explorer-mounted"]', { timeout: 15000 });

    // Invariant card should show failure
    const invariantsBadge = await s5Page.waitForSelector('[data-testid="invariants-status-badge"]', { timeout: 5000 });
    const invBadgeText = await invariantsBadge.textContent();
    assert(invBadgeText.includes('Failed') || invBadgeText.includes('Invariant Failed'), 'Must indicate invariant failure when S5 flows are empty');
    await s5Context.close();
    console.log('  [PASS] S5 invariant strict failure verified (summary cannot manufacture pass)');

    // -------------------------------------------------------------------------
    // TEST STAGE 14: Verify Error Free Baseline Execution
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 14] Verifying page errors and network request health in baseline session...');
    console.log('\n[DIAGNOSTIC] HTTP responses with status >= 400:');
    console.log(
      httpErrors.length > 0
        ? httpErrors.join('\n')
        : 'No HTTP errors detected'
    );
    console.log('\n[DIAGNOSTIC] Browser console errors:');
    console.log(
      consoleErrors.length > 0
        ? consoleErrors.join('\n')
        : 'No console errors detected'
    );
    assert(pageErrors.length === 0, `Expected 0 uncaught page errors, got: ${pageErrors.join('; ')}`);
    assert(consoleErrors.length === 0, `Expected 0 browser console errors, got: ${consoleErrors.join('; ')}`);
    assert(failedRequests.length === 0, `Expected 0 failed network requests, got: ${failedRequests.join('; ')}`);
    console.log('  [PASS] Zero page errors, zero console errors, zero failed requests in baseline run');

    console.log('\n================================================================================');
    console.log(`✓ ALL 14 BROWSER ACCEPTANCE TEST STAGES PASSED (${testsPassed} assertions verified)`);
    console.log(`Browser: Chromium/Chrome ${browserVersion}`);
    console.log('================================================================================\n');

    return {
      passed: true,
      testsPassed,
      testsFailed,
      browserVersion,
      pageErrors,
      consoleErrors,
      failedRequests,
    };
  } finally {
    await browser.close();
    server.close();
  }
}

runBrowserAcceptanceTests().catch((err) => {
  console.error('\n[FATAL] Browser acceptance test suite failed:', err);
  process.exit(1);
});
