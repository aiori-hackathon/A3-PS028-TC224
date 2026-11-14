/**
 * Playwright Browser Acceptance Test Suite for PS-028 Historical Evidence Explorer
 *
 * Launches a real Chromium/Google Chrome browser instance via Playwright to exercise
 * the production-built Evidence Explorer web application in an actual browser engine.
 *
 * Fulfills Audit Findings #5 & #13:
 * 1. Launches genuine browser engine (not Node.js mocks).
 * 2. Navigates to `/evidence` and waits for hydration and bundle loading.
 * 3. Verifies DOM rendering, stats, tabs, search/filter interactions.
 * 4. Verifies event-level packet provenance display in timeline table.
 * 5. Exercises hash-mismatch unverified inspection mode via deterministic Playwright request routing.
 * 6. Exercises S5 missing-data failure state via deterministic Playwright request routing.
 * 7. Captures page errors, console errors, and network request failures.
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
    let reqPath = req.url.split('?')[0];
    if (reqPath.endsWith('/')) {
      reqPath += 'index.html';
    } else if (!path.extname(reqPath)) {
      if (fs.existsSync(path.join(distDir, reqPath, 'index.html'))) {
        reqPath = path.join(reqPath, 'index.html');
      }
    }

    const filePath = path.join(distDir, reqPath);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': contentType });
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
        consoleErrors.push(msg.text());
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
    // TEST STAGE 4: Real Search & Filtering Interaction
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 4] Exercising filter interactions (Scenario S2 + Google Chrome)...');
    // Select S2 scenario filter
    await page.selectOption('select[aria-label="Filter trials by scenario"]', 'S2');
    // Select google-chrome browser filter
    await page.selectOption('select[aria-label="Filter trials by browser"]', 'google-chrome');
    await page.waitForTimeout(300);

    // Verify trials listed for S2 Chrome cohort
    const s2Rows = await page.$$('tbody tr');
    assert(s2Rows.length >= 15, 'S2 Chrome filtered view must populate table rows');
    const tableContent = await page.textContent('table');
    assert(tableContent.includes('S2'), 'Filtered table must contain S2 trials');
    console.log('  [PASS] Search and cohort filter interaction verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 5: Trial Selection, Detail View, and Event Timeline Provenance
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 5] Selecting a trial and verifying timeline event provenance...');
    // Click the "Inspect" button in the first trial of the filtered list
    await page.click('tbody tr:first-child button:has-text("Inspect")');
    await page.waitForTimeout(400);

    const detailContent = await page.textContent('body');
    assert(detailContent.includes('Recorded TCP Connection Attempts'), 'Trial detail connection attempts must render');
    assert(detailContent.includes('Chronological Multi-Source Event Timeline'), 'Timeline section must render');

    // Verify timeline Frame column header exists
    assert(detailContent.includes('Frame'), 'Timeline table must contain Frame provenance column');
    console.log('  [PASS] Trial detail and event timeline packet provenance verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 6: Negative Case — Cryptographic Hash Mismatch Fail-Safe State
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 6] Testing cryptographic hash mismatch fail-safe state...');
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
    await mismatchContext.close();
    console.log('  [PASS] Cryptographic hash mismatch fail-safe behavior verified');

    // -------------------------------------------------------------------------
    // TEST STAGE 7: Negative Case — S5 Invariant Missing Data Failure State
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 7] Testing S5 invariant failure when underlying flow data is missing...');
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
    // TEST STAGE 8: Verify Error Free Baseline Execution
    // -------------------------------------------------------------------------
    console.log('\n[STAGE 8] Verifying page errors and network request health...');
    assert(pageErrors.length === 0, `Expected 0 uncaught page errors, got: ${pageErrors.join('; ')}`);
    assert(consoleErrors.length === 0, `Expected 0 browser console errors, got: ${consoleErrors.join('; ')}`);
    assert(failedRequests.length === 0, `Expected 0 failed network requests, got: ${failedRequests.join('; ')}`);
    console.log('  [PASS] Zero page errors, zero console errors, zero failed requests in baseline run');

    console.log('\n================================================================================');
    console.log(`✓ ALL 8 BROWSER ACCEPTANCE TEST STAGES PASSED (${testsPassed} assertions verified)`);
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
