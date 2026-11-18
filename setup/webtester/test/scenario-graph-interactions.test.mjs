/**
 * Verification Test Suite for Scenario Graph Interactions, Text Contrast, and Main Page Card Cleanup
 *
 * Verifies:
 * 1. Main page card count and order (exactly first three cards, subsequent cards removed).
 * 2. Click interaction on every graph (Graph 1 to Graph 7).
 * 3. Persistence of displayed info when cursor moves away.
 * 4. Updating info on selecting another entry.
 * 5. Deselection on clicking active entry again.
 * 6. Explicit dismissal via Dismiss button.
 * 7. Active selected-state visual indicators on graph elements.
 * 8. Stale selection reconciliation/clearing on filter changes.
 * 9. Keyboard navigation (Enter / Space key selection).
 * 10. Complete absence of text-muted-foreground in graph containers (all replaced with text-black).
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
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
  '.ico': 'image/x-icon',
};

async function runVerification() {
  console.log('================================================================================');
  console.log('PS-028 Verification: Scenario Graph Interactions & Card Cleanup');
  console.log('================================================================================');

  const server = http.createServer((req, res) => {
    let reqPath = decodeURIComponent(new URL(req.url || '/', 'http://127.0.0.1').pathname);
    let filePath = path.resolve(distDir, reqPath.replace(/^[/\\]+/, ''));
    if (reqPath.endsWith('/') || !path.extname(filePath)) {
      filePath = path.join(filePath, 'index.html');
    }
    if (!fs.existsSync(filePath)) {
      res.writeHead(404);
      res.end('Not Found');
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[OK] Server listening at ${baseUrl}`);

  const browser = await chromium.launch();
  const page = await browser.newPage();

  try {
    // -------------------------------------------------------------------------
    // TEST 1: First main page cards
    // -------------------------------------------------------------------------
    console.log('\n[TEST 1] Verifying First Main Page Card Collection...');
    await page.goto(`${baseUrl}/`);
    await page.waitForLoadState('networkidle');

    // Cards on main page are in the grid container
    const cardHeadings = await page.$$eval('.grid a h2, .grid a div.font-bold, .grid h2, .grid div.font-bold', (els) =>
      els.map((el) => el.textContent?.trim()).filter(Boolean)
    );
    // Find all article / card elements
    const cardTitles = await page.$$eval('a[href]', (links) =>
      links
        .map((a) => {
          const titleEl = a.querySelector('h2, div[class*="font-semibold"], div[class*="font-bold"]');
          return titleEl ? titleEl.textContent?.trim() : null;
        })
        .filter(Boolean)
    );

    console.log('  Cards detected on main page:', cardTitles);
    assert.equal(cardTitles.length, 3, `Expected exactly 3 cards, found ${cardTitles.length}`);
    assert.equal(cardTitles[0], 'Historical Evidence Explorer');
    assert.equal(cardTitles[1], 'Scenario Analytics Dashboard');
    assert.equal(cardTitles[2], 'Connection Attempt Delay Test');
    console.log('  [PASS] Exactly first three cards retained in original order');

    // -------------------------------------------------------------------------
    // TEST 2: Navigate to Scenario Analytics Page
    // -------------------------------------------------------------------------
    console.log('\n[TEST 2] Navigating to Scenario Analytics page...');
    await page.goto(`${baseUrl}/analytics`);
    await page.waitForSelector('[data-testid="analytics-dashboard-mounted"]', { timeout: 10000 });
    console.log('  [PASS] /analytics mounted and hydrated');

    // -------------------------------------------------------------------------
    // TEST 3: Graph 1 (Connection Time Chart) Click Interaction & Text Contrast
    // -------------------------------------------------------------------------
    console.log('\n[TEST 3] Testing Graph 1 — Connection Establishment Time...');
    const g1Card = page.locator('[data-testid="graph-1-card"]');
    await g1Card.scrollIntoViewIfNeeded();

    // Verify no text-muted-foreground in Graph 1
    const g1Muted = await g1Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g1Muted, 0, 'Graph 1 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 1 has zero muted-foreground text');

    // Click a Chrome bar
    const g1ChromeBar = g1Card.locator('rect[aria-label*="Google Chrome"]').first();
    await g1ChromeBar.click();

    // Verify pinned panel appears
    const g1Panel = page.locator('[data-testid="graph-1-selected-panel"]');
    await g1Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g1PanelText = await g1Panel.textContent();
    assert.ok(g1PanelText.includes('Google Chrome'), 'Panel must identify Google Chrome');
    assert.ok(g1PanelText.includes('t_connect'), 'Panel must show metric');
    assert.ok(g1PanelText.includes('Active Selection'), 'Panel must show Active Selection badge');
    console.log('  [PASS] Graph 1 displays selected information panel');

    // Move cursor away to 0,0 and verify info remains visible
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g1Panel.isVisible(), 'Graph 1 selection panel must remain visible after cursor moves away');
    console.log('  [PASS] Graph 1 info remains visible after cursor moves away');

    // Click Firefox bar in same scenario to update
    const g1FirefoxBar = g1Card.locator('rect[aria-label*="Mozilla Firefox"]').first();
    await g1FirefoxBar.click();
    await page.waitForTimeout(200);
    const g1PanelTextUpdated = await g1Panel.textContent();
    assert.ok(g1PanelTextUpdated.includes('Mozilla Firefox'), 'Panel must update to Mozilla Firefox');
    console.log('  [PASS] Graph 1 clicking another entry updates selection info');

    // Click Firefox bar again to deselect
    await g1FirefoxBar.click();
    await page.waitForTimeout(200);
    assert.ok(!(await g1Panel.isVisible()), 'Clicking active entry again deselects');
    console.log('  [PASS] Graph 1 clicking active entry again deselects');

    // Test Dismiss button
    await g1ChromeBar.click();
    await g1Panel.waitFor({ state: 'visible' });
    const g1Dismiss = g1Panel.locator('button[aria-label="Dismiss selection"]');
    await g1Dismiss.click();
    await page.waitForTimeout(200);
    assert.ok(!(await g1Panel.isVisible()), 'Dismiss button clears selection');
    console.log('  [PASS] Graph 1 Dismiss button clears selection');

    // -------------------------------------------------------------------------
    // TEST 4: Graph 2 (Winner Distribution Chart)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 4] Testing Graph 2 — IPv4 vs IPv6 Winner Distribution...');
    const g2Card = page.locator('[data-testid="graph-2-card"]');
    await g2Card.scrollIntoViewIfNeeded();

    const g2Muted = await g2Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g2Muted, 0, 'Graph 2 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 2 has zero muted-foreground text');

    // Click IPv6 segment
    const g2V6Bar = g2Card.locator('rect[aria-label*="IPv6 Winner"]').first();
    await g2V6Bar.click();

    const g2Panel = page.locator('[data-testid="graph-2-selected-panel"]');
    await g2Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g2PanelText = await g2Panel.textContent();
    assert.ok(g2PanelText.includes('IPv6'), 'Panel must identify IPv6');
    assert.ok(g2PanelText.includes('Preferred Winner'), 'Panel must describe role');

    // Move mouse away
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g2Panel.isVisible(), 'Graph 2 panel remains visible');
    console.log('  [PASS] Graph 2 panel persistent after cursor leaves');

    // Click IPv4 segment
    const g2V4Bar = g2Card.locator('rect[aria-label*="IPv4 Winner"]').first();
    if (await g2V4Bar.count() > 0) {
      await g2V4Bar.click();
      await page.waitForTimeout(200);
      const g2Updated = await g2Panel.textContent();
      assert.ok(g2Updated.includes('IPv4'), 'Panel must update to IPv4');
      console.log('  [PASS] Graph 2 updates on selecting another segment');
    }

    // Dismiss
    await g2Panel.locator('button[aria-label="Dismiss selection"]').click();
    await page.waitForTimeout(200);
    assert.ok(!(await g2Panel.isVisible()));
    console.log('  [PASS] Graph 2 dismissal verified');

    // -------------------------------------------------------------------------
    // TEST 5: Graph 3 (Latency Distribution Box Plot)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 5] Testing Graph 3 — Connection Latency Distribution...');
    const g3Card = page.locator('[data-testid="graph-3-card"]');
    await g3Card.scrollIntoViewIfNeeded();

    const g3Muted = await g3Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g3Muted, 0, 'Graph 3 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 3 has zero muted-foreground text');

    // Click BoxPlotItem
    const g3Box = g3Card.locator('g[role="button"][aria-label*="box plot"]').first();
    await g3Box.click();

    const g3Panel = page.locator('[data-testid="graph-3-selected-panel"]');
    await g3Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g3Text = await g3Panel.textContent();
    assert.ok(g3Text.includes('Median:'), 'Panel must display median');
    assert.ok(g3Text.includes('IQR:'), 'Panel must display IQR');

    // Move mouse away
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g3Panel.isVisible(), 'Graph 3 panel remains visible');
    console.log('  [PASS] Graph 3 panel persistent after cursor leaves');

    // Deselect on click again
    await g3Box.click();
    await page.waitForTimeout(200);
    assert.ok(!(await g3Panel.isVisible()), 'Deselects on click again');
    console.log('  [PASS] Graph 3 deselects on clicking same element');

    // -------------------------------------------------------------------------
    // TEST 6: Graph 4 (DNS Performance Chart)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 6] Testing Graph 4 — DNS Resolution Performance...');
    const g4Card = page.locator('[data-testid="graph-4-card"]');
    await g4Card.scrollIntoViewIfNeeded();

    const g4Muted = await g4Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g4Muted, 0, 'Graph 4 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 4 has zero muted-foreground text');

    // Click A Record bar
    const g4Bar = g4Card.locator('rect[aria-label*="A Record"]').first();
    await g4Bar.click();

    const g4Panel = page.locator('[data-testid="graph-4-selected-panel"]');
    await g4Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g4Text = await g4Panel.textContent();
    assert.ok(g4Text.includes('A Record'), 'Panel identifies A Record');

    // Move mouse away
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g4Panel.isVisible(), 'Graph 4 panel remains visible');
    console.log('  [PASS] Graph 4 panel persistent after cursor leaves');

    // Click AAAA Record bar to update
    const g4AaaaBar = g4Card.locator('rect[aria-label*="AAAA Record"]').first();
    await g4AaaaBar.click();
    await page.waitForTimeout(200);
    const g4AaaaText = await g4Panel.textContent();
    assert.ok(g4AaaaText.includes('AAAA Record'), 'Panel updates to AAAA Record');
    console.log('  [PASS] Graph 4 updates on selecting another entry');

    // Dismiss
    await g4Panel.locator('button[aria-label="Dismiss selection"]').click();
    await page.waitForTimeout(200);
    assert.ok(!(await g4Panel.isVisible()));
    console.log('  [PASS] Graph 4 dismissal verified');

    // -------------------------------------------------------------------------
    // TEST 7: Graph 5 (SYN Retransmission Chart)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 7] Testing Graph 5 — SYN Retransmission Analysis...');
    const g5Card = page.locator('[data-testid="graph-5-card"]');
    await g5Card.scrollIntoViewIfNeeded();

    const g5Muted = await g5Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g5Muted, 0, 'Graph 5 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 5 has zero muted-foreground text');

    // Click Retransmission bar
    const g5Bar = g5Card.locator('rect[aria-label*="Retransmissions"]').first();
    await g5Bar.click();

    const g5Panel = page.locator('[data-testid="graph-5-selected-panel"]');
    await g5Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g5Text = await g5Panel.textContent();
    assert.ok(g5Text.includes('Retransmissions'), 'Panel identifies Retransmissions');

    // Move mouse away
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g5Panel.isVisible(), 'Graph 5 panel remains visible');
    console.log('  [PASS] Graph 5 panel persistent after cursor leaves');

    // Dismiss
    await g5Panel.locator('button[aria-label="Dismiss selection"]').click();
    await page.waitForTimeout(200);
    assert.ok(!(await g5Panel.isVisible()));
    console.log('  [PASS] Graph 5 dismissal verified');

    // -------------------------------------------------------------------------
    // TEST 8: Graph 6 (Scenario Performance Heatmap)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 8] Testing Graph 6 — Scenario Performance Heatmap...');
    const g6Card = page.locator('[data-testid="graph-6-card"]');
    await g6Card.scrollIntoViewIfNeeded();

    const g6Muted = await g6Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g6Muted, 0, 'Graph 6 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 6 has zero muted-foreground text');

    // Click a heatmap cell
    const g6Cell = g6Card.locator('td[role="button"]').first();
    await g6Cell.click();

    const g6Panel = page.locator('[data-testid="graph-6-selected-panel"]');
    await g6Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g6Text = await g6Panel.textContent();
    assert.ok(g6Text.includes('Active Selection'), 'Panel has Active Selection');
    assert.ok(g6Text.includes('Cohort Breakdown'), 'Panel displays Cohort Breakdown comparison');

    // Move mouse away
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g6Panel.isVisible(), 'Graph 6 panel remains visible');
    console.log('  [PASS] Graph 6 panel persistent after cursor leaves');

    // Click cell again to deselect
    await g6Cell.click();
    await page.waitForTimeout(200);
    assert.ok(!(await g6Panel.isVisible()));
    console.log('  [PASS] Graph 6 deselects on clicking active cell again');

    // -------------------------------------------------------------------------
    // TEST 9: Graph 7 (Connection Event Timeline)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 9] Testing Graph 7 — TCP Connection Event Timeline...');
    const g7Card = page.locator('[data-testid="graph-7-card"]');
    await g7Card.scrollIntoViewIfNeeded();

    const g7Muted = await g7Card.evaluate((el) => {
      return el.querySelectorAll('.text-muted-foreground, .fill-muted-foreground').length;
    });
    assert.equal(g7Muted, 0, 'Graph 7 must have 0 text-muted-foreground elements');
    console.log('  [PASS] Graph 7 has zero muted-foreground text');

    // Click an event dot
    const g7Event = g7Card.locator('circle[role="button"][aria-label*="Select event"]').first();
    await g7Event.click({ force: true });

    const g7Panel = page.locator('[data-testid="graph-7-selected-panel"]');
    await g7Panel.waitFor({ state: 'visible', timeout: 3000 });
    const g7Text = await g7Panel.textContent();
    assert.ok(g7Text.includes('Relative Offset:'), 'Panel displays relative offset');
    assert.ok(g7Text.includes('Absolute Timestamp:'), 'Panel displays absolute timestamp');

    // Move mouse away
    await page.mouse.move(0, 0);
    await page.waitForTimeout(200);
    assert.ok(await g7Panel.isVisible(), 'Graph 7 panel remains visible');
    console.log('  [PASS] Graph 7 panel persistent after cursor leaves');

    // Dismiss
    await g7Panel.locator('button[aria-label="Dismiss selection"]').click();
    await page.waitForTimeout(200);
    assert.ok(!(await g7Panel.isVisible()));
    console.log('  [PASS] Graph 7 dismissal verified');

    // -------------------------------------------------------------------------
    // TEST 10: Keyboard navigation test
    // -------------------------------------------------------------------------
    console.log('\n[TEST 10] Testing Keyboard Navigation (Space/Enter key selection)...');
    await g1ChromeBar.focus();
    await page.keyboard.press('Enter');
    await g1Panel.waitFor({ state: 'visible' });
    assert.ok(await g1Panel.isVisible(), 'Pressing Enter selects element');
    await page.keyboard.press('Space');
    await page.waitForTimeout(200);
    assert.ok(!(await g1Panel.isVisible()), 'Pressing Space deselects element');
    console.log('  [PASS] Keyboard selection via Enter/Space working');

    // -------------------------------------------------------------------------
    // TEST 11: Filter reconciliation test (unselecting scenario clears stale selection)
    // -------------------------------------------------------------------------
    console.log('\n[TEST 11] Testing Filter Reconciliation (Stale Selection Cleared)...');
    // Select S0 in Graph 1
    await g1ChromeBar.click();
    await g1Panel.waitFor({ state: 'visible' });

    // Toggle S0 off in scenario selector
    const s0Btn = page.locator('button[data-testid="scenario-badge-S0"]');
    if (await s0Btn.count() > 0) {
      await s0Btn.click();
      await page.waitForTimeout(300);
      assert.ok(!(await g1Panel.isVisible()), 'Deselecting scenario removes stale selection');
      console.log('  [PASS] Stale selection reconciled and cleared when scenario filtered out');
      // Re-enable S0
      await s0Btn.click();
      await page.waitForTimeout(300);
    }

    console.log('\n================================================================================');
    console.log('✓ ALL VERIFICATION TESTS PASSED SUCCESSFULLY');
    console.log('================================================================================');
  } finally {
    await browser.close();
    server.close();
  }
}

runVerification().catch((err) => {
  console.error('\n[FAIL] Test encountered error:', err);
  process.exit(1);
});
