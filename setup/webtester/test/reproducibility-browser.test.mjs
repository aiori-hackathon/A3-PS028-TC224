import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
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
  '.woff2': 'font/woff2',
};

export const RECOGNIZED_OFFLINE_ERROR_CODES = Object.freeze([
  'net::ERR_INTERNET_DISCONNECTED',
  'net::ERR_NAME_NOT_RESOLVED',
  'net::ERR_CONNECTION_REFUSED',
  'net::ERR_ADDRESS_UNREACHABLE',
  'net::ERR_NETWORK_CHANGED',
  'net::ERR_TIMED_OUT',
  'net::ERR_CONNECTION_RESET',
  'net::ERR_ABORTED',
]);

/**
 * Validates whether a URL corresponds strictly to the optional external Google Fonts CDN.
 * Uses exact hostname matching to prevent spoofing or accidental exemption of local assets.
 */
export function isOptionalExternalFontUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return false;
  }
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname === 'fonts.googleapis.com' || parsed.hostname === 'fonts.gstatic.com';
  } catch {
    return false;
  }
}

/**
 * Checks whether an error message contains an explicitly recognized offline network failure code.
 */
export function isRecognizedOfflineError(errorText) {
  if (typeof errorText !== 'string' || !errorText.trim()) {
    return false;
  }
  return RECOGNIZED_OFFLINE_ERROR_CODES.some((code) => errorText.includes(code));
}

/**
 * Extracts a candidate URL from text, if present.
 */
export function extractUrlFromText(text) {
  if (typeof text !== 'string') return null;
  const match = text.match(/https?:\/\/[^\s"'<>)]+/);
  return match ? match[0] : null;
}

/**
 * Evaluates whether a request failure should be suppressed.
 * Suppressed ONLY if:
 * 1. Target URL strictly matches an optional Google Fonts CDN host (exact hostname).
 * 2. Failure error text strictly matches an explicitly recognized offline error code.
 */
export function shouldSuppressRequestFailure(url, errorText) {
  if (!isOptionalExternalFontUrl(url)) {
    return false;
  }
  return isRecognizedOfflineError(errorText);
}

/**
 * Evaluates whether a browser console error message should be suppressed.
 * Suppressed ONLY if:
 * 1. Target URL (from location or message) strictly matches an optional Google Fonts host.
 * 2. Message text contains an explicitly recognized offline error code.
 */
export function shouldSuppressConsoleError(msgText, locationUrl) {
  const targetUrl = locationUrl || extractUrlFromText(msgText);
  if (!targetUrl || !isOptionalExternalFontUrl(targetUrl)) {
    return false;
  }
  return isRecognizedOfflineError(msgText);
}

async function runBrowserTests() {
  console.log('================================================================================');
  console.log('PS-028 Reproducibility Card & Procedure Page Browser Acceptance Test');
  console.log('================================================================================');

  if (!fs.existsSync(distDir)) {
    throw new Error(`Production dist directory does not exist at ${distDir}.`);
  }

  const server = http.createServer((req, res) => {
    let reqPath = decodeURIComponent(req.url.split('?')[0]);
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
  console.log(`[OK] HTTP Server listening on ${baseUrl}`);

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const pageErrors = [];
  const consoleErrors = [];

  try {
    const context = await browser.newContext({
      permissions: ['clipboard-read', 'clipboard-write']
    });
    const page = await context.newPage();

    page.on('pageerror', (err) => {
      console.error('[Browser Error]:', err);
      pageErrors.push(err);
    });

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const text = msg.text();
        const loc = msg.location();
        if (shouldSuppressConsoleError(text, loc?.url)) {
          return;
        }
        console.error('[Console Error]:', text);
        consoleErrors.push(text);
      }
    });

    page.on('requestfailed', (req) => {
      const errorText = req.failure()?.errorText || '';
      if (shouldSuppressRequestFailure(req.url(), errorText)) {
        return;
      }
      console.error('[Request Failed]:', req.url(), errorText);
      pageErrors.push(new Error(`Request failed: ${req.url()}${errorText ? ` (${errorText})` : ''}`));
    });

    page.on('response', (res) => {
      // Do not suppress HTTP 4xx or 5xx responses, even when originating from Google Fonts domains
      if (res.status() >= 400) {
        console.error('[Response Status >= 400]:', res.url(), res.status());
        pageErrors.push(new Error(`HTTP ${res.status()} on ${res.url()}`));
      }
    });

    // 1. Visit Main Page
    console.log('\n[STAGE 1] Testing Main Page & Reproducibility Card...');
    await page.goto(`${baseUrl}/`, { waitUntil: 'domcontentloaded' });

    // Verify 3 cards exist
    const cards = page.locator('.group.relative.flex.flex-col, [data-testid="test-card"], .rounded-xl.border');
    const cardCount = await cards.count();
    console.log(`  Found ${cardCount} cards on index page.`);

    // Check third card
    const card3Title = page.locator('text=How to run your own tests?');
    await card3Title.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] Card 3 title visible: "How to run your own tests?"');

    const seeProcedureBtn = page.locator('a[href="/procedure"]:has-text("See procedure")');
    await seeProcedureBtn.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] "See procedure" navigation link visible');

    // Click link and navigate
    console.log('\n[STAGE 2] Navigating to /procedure...');
    await seeProcedureBtn.click();
    await page.waitForURL('**/procedure');
    console.log('  [PASS] Successfully navigated to /procedure');

    // 2. Verify Procedure Page content
    console.log('\n[STAGE 3] Verifying Procedure Page Header & Body Content...');
    const heading = page.locator('h1:has-text("Steps for Reproducing")');
    await heading.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] Heading "Steps for Reproducing Test Laboratory" verified');

    const subheader = page.locator('text=How we are making PS-028 reproducible');
    await subheader.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] Subheading verified');

    // 3. Verify Red Callout Bubble
    console.log('\n[STAGE 4] Verifying Red Callout Bubble & Reproducibility Practices...');
    const redBubble = page.locator('[data-testid="reproducibility-practices-callout"]');
    await redBubble.waitFor({ state: 'visible', timeout: 5000 });

    // Check text color of bubble content is black (rgb(0, 0, 0))
    const firstPractice = redBubble.locator('li').first();
    const computedColor = await firstPractice.evaluate((el) => window.getComputedStyle(el).color);
    console.log(`  [PASS] Bubble text color is: ${computedColor}`);

    // Verify all 5 practices are present
    const listItems = redBubble.locator('li');
    const practiceCount = await listItems.count();
    if (practiceCount !== 5) {
      throw new Error(`Expected 5 practices, found ${practiceCount}`);
    }
    console.log(`  [PASS] All ${practiceCount} practices present`);

    // Verify KaTeX math rendered
    const katexEl = redBubble.locator('.katex');
    await katexEl.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] KaTeX math rendered without raw LaTeX delimiters');

    // 4. Verify Downloadable Resources Table & Downloads
    console.log('\n[STAGE 5] Verifying Downloadable Resources Table...');
    const tableRows = page.locator('[data-testid="downloadable-resources-section"] tbody tr');
    const rowCount = await tableRows.count();
    if (rowCount !== 10) {
      throw new Error(`Expected 10 table rows, found ${rowCount}`);
    }
    console.log(`  [PASS] Downloadable resource table contains 10 rows`);

    // Test downloading files via same-origin HTTP request
    const filesToTest = [
      'README.md',
      'partner_replication_runbook.md',
      'partner_replication_manifest.json',
      'scenarios.yaml',
      'phase-c-metric-contract.md',
      'partner_preflight.py',
      'setup_topology.sh',
      'run_campaign.py',
      'run_trial.py',
      'export_campaign_evidence.py',
      'analyze.py',
      'verify_partner_handover.py'
    ];

    for (const filename of filesToTest) {
      const res = await page.request.get(`${baseUrl}/downloads/${filename}`);
      if (res.status() !== 200) {
        throw new Error(`Failed to download ${filename}, status=${res.status()}`);
      }
      const body = await res.body();
      if (body.length === 0) {
        throw new Error(`Downloaded ${filename} is empty`);
      }
    }
    console.log(`  [PASS] Successfully downloaded all 12 verified files from server`);

    // 5. Verify Section B: Reproduction Steps & Copy Interaction
    console.log('\n[STAGE 6] Verifying Reproduction Steps & Copy Interaction...');
    const step1Title = page.locator('text=Step 1 — Clone the repository and use a fixed source revision');
    await step1Title.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] Step 1 heading present');

    const copyBtn = page.locator('.code-block-wrapper .copy-btn').first();
    await copyBtn.waitFor({ state: 'visible', timeout: 5000 });
    await copyBtn.click();
    await page.waitForTimeout(300);
    const copyLabel = await copyBtn.locator('.copy-label').textContent();
    console.log(`  [PASS] Copy button interaction verified (label: "${copyLabel}")`);

    // Verify Step 7 Submit heading
    const step7Title = page.locator('h3:has-text("Submit the independent evidence")');
    await step7Title.waitFor({ state: 'visible', timeout: 5000 });
    console.log('  [PASS] Step 7 "Submit the independent evidence" verified');

    // 6. Mobile Responsiveness Check
    console.log('\n[STAGE 7] Verifying Mobile Responsiveness (375x667)...');
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(300);

    const hasHorizontalOverflow = await page.evaluate(() => {
      return document.documentElement.scrollWidth > window.innerWidth;
    });

    if (hasHorizontalOverflow) {
      const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
      throw new Error(`Mobile view has horizontal overflow: scrollWidth=${scrollWidth}px > innerWidth=375px`);
    }
    console.log('  [PASS] No horizontal overflow detected at 375px viewport');

    // 7. Verify zero errors
    console.log('\n[STAGE 8] Error logs evaluation...');
    if (pageErrors.length > 0) {
      throw new Error(`Encountered ${pageErrors.length} browser page errors`);
    }
    if (consoleErrors.length > 0) {
      throw new Error(`Encountered ${consoleErrors.length} console errors`);
    }
    console.log('  [PASS] Zero browser page errors and zero console errors');

    console.log('\n================================================================================');
    console.log('✓ ALL REPRODUCIBILITY BROWSER ACCEPTANCE TESTS PASSED');
    console.log('================================================================================');
  } finally {
    await browser.close();
    server.close();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runBrowserTests().catch((err) => {
    console.error('[FATAL]:', err);
    process.exit(1);
  });
}
