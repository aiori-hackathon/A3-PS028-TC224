import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  isOptionalExternalFontUrl,
  isRecognizedOfflineError,
  isPermittedFontCancellation,
  isFatalHttpResponse,
  shouldSuppressRequestFailure,
  shouldSuppressConsoleError,
  RECOGNIZED_OFFLINE_ERROR_CODES
} from './reproducibility-browser.test.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '../dist');

describe('PS-028 Reproducibility Card & Test Laboratory Procedure Page Verification', () => {
  const indexHtmlPath = path.join(distDir, 'index.html');
  const procedureHtmlPath = path.join(distDir, 'procedure/index.html');

  it('1. Verifies production build artifacts exist', () => {
    assert.strictEqual(fs.existsSync(indexHtmlPath), true, 'dist/index.html must exist');
    assert.strictEqual(fs.existsSync(procedureHtmlPath), true, 'dist/procedure/index.html must exist');
  });

  it('2. Main Page: replaces only the third card and preserves cards 1 and 2', () => {
    const html = fs.readFileSync(indexHtmlPath, 'utf8');

    // Check first card
    assert.match(html, /Historical Evidence Explorer/, 'Card 1 title must be preserved');
    assert.match(html, /href="\/evidence"/, 'Card 1 href must be preserved');
    assert.match(html, /Explore campaign evidence/, 'Card 1 action text must be preserved');

    // Check second card
    assert.match(html, /Scenario Analytics Dashboard/, 'Card 2 title must be preserved');
    assert.match(html, /href="\/analytics"/, 'Card 2 href must be preserved');
    assert.match(html, /View interactive analytics &amp; PDF reports|View interactive analytics & PDF reports/, 'Card 2 action text must be preserved');

    // Check third card
    assert.match(html, /How to run your own tests\?/, 'Card 3 title must be "How to run your own tests?"');
    assert.match(html, /href="\/procedure"/, 'Card 3 href must be "/procedure"');
    assert.match(html, /See procedure/, 'Card 3 action text must be "See procedure"');

    // Check third card description text
    const expectedDesc = 'Reproducibility in our project means making it possible for another researcher to repeat our IPv4/IPv6 fallback experiments under the same documented conditions and independently verify our findings. We have prepared an independent replication runbook so another researcher can set up the laboratory, execute the same 280-trial experiment, process the evidence, and compare their results with ours. In essence, we want our results to be independently verifiable—not just something others have to trust.';
    assert.strictEqual(html.includes(expectedDesc), true, 'Card 3 description must match exactly');
  });

  it('3. Procedure Page: verifies headings and intro text', () => {
    const html = fs.readFileSync(procedureHtmlPath, 'utf8');

    assert.match(html, /Steps for Reproducing/i, 'Title line 1 must match');
    assert.match(html, /Test Laboratory/i, 'Title line 2 must match');
    assert.match(html, /How we are making PS-028 reproducible/, 'Subheading must match');

    const expectedIntro = 'Our project is designed so that another researcher or networking enthusiast can repeat the same experiment, collect independent evidence, and compare their findings with ours.';
    assert.strictEqual(html.includes(expectedIntro), true, 'Intro body text must match exactly');
  });

  it('4. Procedure Page: verifies red information bubble styling, black text, and 5 practices', () => {
    const html = fs.readFileSync(procedureHtmlPath, 'utf8');

    // Red bubble styling
    assert.match(html, /data-testid="reproducibility-practices-callout"/, 'Callout testid must be present');
    assert.match(html, /bg-destructive\/10/, 'Red callout must use bg-destructive/10');
    assert.match(html, /border-destructive\/40/, 'Red callout must use border-destructive/40');
    assert.match(html, /text-black/, 'Red callout must use text-black');

    // Check practice intro
    assert.match(html, /We achieve this through five main practices:/, 'Bubble intro sentence must be present');

    // Check all 5 practices
    assert.match(html, /Fixed experimental conditions:/, 'Practice 1 title must be present');
    assert.match(html, /Pinned software and specifications:/, 'Practice 2 title must be present');
    assert.match(html, /Repeatable execution:/, 'Practice 3 title must be present');
    assert.match(html, /Evidence-based measurement:/, 'Practice 4 title must be present');
    assert.match(html, /Deterministic analysis and integrity checks:/, 'Practice 5 title must be present');

    // Check mathematical expression rendering: no raw \( or \) delimiters
    assert.strictEqual(html.includes('\\('), false, 'Must not contain raw \\( delimiter');
    assert.strictEqual(html.includes('\\)'), false, 'Must not contain raw \\) delimiter');
    assert.match(html, /<math/, 'Math must be rendered via MathML / KaTeX');
    assert.match(html, /katex/, 'KaTeX styling must be present');

    // Check closing sentence
    assert.match(html, /This makes it possible to distinguish genuine live experiments from simulations, synthetic tests, and historical evidence\./, 'Closing sentence must match');
  });

  it('5. Procedure Page: Section A downloadable resources table and verified files', () => {
    const html = fs.readFileSync(procedureHtmlPath, 'utf8');

    assert.match(html, /Downloadable project resources/, 'Section A heading must be present');
    assert.match(html, /The following files are the most useful starting points\. They are available in our integration branch\./, 'Intro text must match');

    const expectedFiles = [
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

    for (const filename of expectedFiles) {
      assert.match(html, new RegExp(`href="/downloads/${filename}"`), `Link for ${filename} must point to /downloads/${filename}`);
      assert.match(html, new RegExp(`download="${filename}"`), `Download attribute for ${filename} must be set`);

      // Verify physical file in dist/downloads/
      const distFilePath = path.join(distDir, 'downloads', filename);
      assert.strictEqual(fs.existsSync(distFilePath), true, `File ${filename} must exist in dist/downloads/`);
      const stat = fs.statSync(distFilePath);
      assert.ok(stat.size > 0, `File ${filename} must not be empty`);
    }
  });

  it('6. Procedure Page: Section B reproduction steps and commands', () => {
    const html = fs.readFileSync(procedureHtmlPath, 'utf8');

    assert.match(html, /How another researcher can reproduce the experiment/, 'Section B heading must be present');
    assert.match(html, /Step 1 — Clone the repository and use a fixed source revision/, 'Step 1 heading');
    assert.match(html, /61c46aa2184245a06e878f6aca85102e08d726fa/, 'Step 1 commit hash');

    assert.match(html, /Step 2 — Prepare a compatible Linux environment/, 'Step 2 heading');
    assert.match(html, /Ubuntu 24\.04 LTS/, 'Step 2 Ubuntu reference');

    assert.match(html, /Step 3 — Run the read-only preflight checks/, 'Step 3 heading');
    assert.match(html, /python3 lab\/partner_preflight\.py/, 'Step 3 command');

    assert.match(html, /Step 4 — Provision the isolated experimental network/, 'Step 4 heading');
    assert.match(html, /Explicit Authorization Gate/, 'Step 4 authorization notice');

    assert.match(html, /Step 5 — Run the canonical 280-trial campaign/, 'Step 5 heading');
    assert.match(html, /run_campaign\.py/, 'Step 5 command');

    assert.match(html, /Step 6 — Generate and validate the experimental evidence/, 'Step 6 heading');
    assert.match(html, /export_campaign_evidence\.py/, 'Step 6 command');

    assert.match(html, /Submit the independent evidence/, 'Step 7 exact heading');
    assert.match(html, /Submit the evidence archive and its SHA-256 checksum to the project maintainers\./, 'Step 7 text');
  });

  it('7. Verifies exact-hostname exemption for optional external Google Fonts CDNs', () => {
    // Fonts CSS host and Font binary CDN host must match exactly
    assert.strictEqual(isOptionalExternalFontUrl('https://fonts.googleapis.com/css2?family=Redaction+10'), true);
    assert.strictEqual(isOptionalExternalFontUrl('https://fonts.gstatic.com/s/redaction10/v1/nKKP-GMjH5FfZdL7VGuARJRZiF9jHc_7.woff2'), true);

    // Negative tests: local assets, IP addresses, subdomains, attacker spoofing must NOT be exempted
    assert.strictEqual(isOptionalExternalFontUrl('http://127.0.0.1:41525/procedure'), false);
    assert.strictEqual(isOptionalExternalFontUrl('http://127.0.0.1:41525/_astro/main.css'), false);
    assert.strictEqual(isOptionalExternalFontUrl('http://localhost:3000/script.js'), false);
    assert.strictEqual(isOptionalExternalFontUrl('https://fonts.googleapis.com.evil.com/fake.css'), false);
    assert.strictEqual(isOptionalExternalFontUrl('https://attacker.org/fonts.gstatic.com/font.woff2'), false);
    assert.strictEqual(isOptionalExternalFontUrl('https://fake-fonts.googleapis.com/test'), false);
    assert.strictEqual(isOptionalExternalFontUrl('https://evil.com/fonts.googleapis.com'), false);
    assert.strictEqual(isOptionalExternalFontUrl('https://evil.com/fonts.gstatic.com'), false);
    assert.strictEqual(isOptionalExternalFontUrl(''), false);
    assert.strictEqual(isOptionalExternalFontUrl(null), false);
    assert.strictEqual(isOptionalExternalFontUrl(undefined), false);
    assert.strictEqual(isOptionalExternalFontUrl('javascript:alert(1)'), false);
    assert.strictEqual(isOptionalExternalFontUrl('not-a-valid-url'), false);
  });

  it('8. Verifies explicitly recognized offline network error codes (excludes net::ERR_ABORTED)', () => {
    // All genuine offline connectivity failure codes must be recognized
    for (const code of RECOGNIZED_OFFLINE_ERROR_CODES) {
      assert.strictEqual(isRecognizedOfflineError(code), true, `${code} must be recognized`);
      assert.strictEqual(isRecognizedOfflineError(`Prefix ${code} suffix`), true, `Embedded ${code} must be recognized`);
    }

    // Negative requirement: net::ERR_ABORTED is strictly excluded because request cancellation
    // is not exclusively evidence of offline connectivity
    assert.strictEqual(
      isRecognizedOfflineError('net::ERR_ABORTED'),
      false,
      'net::ERR_ABORTED must NOT be classified as an offline network failure'
    );
    assert.strictEqual(
      RECOGNIZED_OFFLINE_ERROR_CODES.includes('net::ERR_ABORTED'),
      false,
      'RECOGNIZED_OFFLINE_ERROR_CODES must not include net::ERR_ABORTED'
    );

    // Unrecognized or security-related error codes must NOT be recognized as offline network errors
    assert.strictEqual(isRecognizedOfflineError('net::ERR_CERT_COMMON_NAME_INVALID'), false);
    assert.strictEqual(isRecognizedOfflineError('net::ERR_SSL_PROTOCOL_ERROR'), false);
    assert.strictEqual(isRecognizedOfflineError('net::ERR_BLOCKED_BY_CLIENT'), false);
    assert.strictEqual(isRecognizedOfflineError('HTTP 404 Not Found'), false);
    assert.strictEqual(isRecognizedOfflineError('HTTP 500 Internal Server Error'), false);
    assert.strictEqual(isRecognizedOfflineError('Uncaught ReferenceError'), false);
    assert.strictEqual(isRecognizedOfflineError(''), false);
    assert.strictEqual(isRecognizedOfflineError(null), false);
    assert.strictEqual(isRecognizedOfflineError(undefined), false);
  });

  it('9. Verifies request failure suppression logic and negative test for unpermitted cancellation', () => {
    // Genuine offline network failures on genuine Google Fonts CDN hosts must be suppressed
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.googleapis.com/css2', 'net::ERR_NAME_NOT_RESOLVED'), true);
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.gstatic.com/font.woff2', 'net::ERR_INTERNET_DISCONNECTED'), true);
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.gstatic.com/font.woff2', 'net::ERR_CONNECTION_REFUSED'), true);

    // Negative requirement: an aborted request is NOT automatically classified as an offline failure
    assert.strictEqual(
      shouldSuppressRequestFailure('https://fonts.gstatic.com/font.woff2', 'net::ERR_ABORTED', { allowFontCancellation: false }),
      false,
      'Aborted Google Fonts request must not be automatically suppressed when allowFontCancellation is false'
    );

    // Explicitly authorized font preloader cancellation in test environment is tolerated when enabled
    assert.strictEqual(
      shouldSuppressRequestFailure('https://fonts.gstatic.com/font.woff2', 'net::ERR_ABORTED', { allowFontCancellation: true }),
      true,
      'Explicitly controlled font cancellation on genuine font host must be permitted'
    );

    // Genuine offline network errors on LOCAL assets must NOT be suppressed (must remain fatal)
    assert.strictEqual(shouldSuppressRequestFailure('http://127.0.0.1:41525/_astro/main.css', 'net::ERR_ABORTED'), false);
    assert.strictEqual(shouldSuppressRequestFailure('http://localhost:3000/app.js', 'net::ERR_CONNECTION_REFUSED'), false);

    // Genuine offline network errors on ATTACKER spoofed URLs must NOT be suppressed
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.googleapis.com.evil.com/font.woff2', 'net::ERR_ABORTED'), false);
    assert.strictEqual(shouldSuppressRequestFailure('https://evil.com/fonts.gstatic.com', 'net::ERR_NAME_NOT_RESOLVED'), false);

    // NON-OFFLINE errors on genuine Google Fonts CDN hosts must NOT be suppressed (must remain fatal)
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.gstatic.com/font.woff2', 'net::ERR_CERT_AUTHORITY_INVALID'), false);
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.googleapis.com/css2', 'net::ERR_BLOCKED_BY_ADMINISTRATOR'), false);
    assert.strictEqual(shouldSuppressRequestFailure('https://fonts.googleapis.com/css2', ''), false);
  });

  it('10. Verifies explicitly controlled font cancellation policy (isPermittedFontCancellation)', () => {
    // Valid font host with net::ERR_ABORTED and allowFontCancellation=true
    assert.strictEqual(
      isPermittedFontCancellation('https://fonts.gstatic.com/s/redaction10/v1/font.woff2', 'net::ERR_ABORTED', { allowFontCancellation: true }),
      true
    );
    assert.strictEqual(
      isPermittedFontCancellation('https://fonts.googleapis.com/css2', 'net::ERR_ABORTED', { allowFontCancellation: true }),
      true
    );

    // Negative: disabled control option
    assert.strictEqual(
      isPermittedFontCancellation('https://fonts.gstatic.com/font.woff2', 'net::ERR_ABORTED', { allowFontCancellation: false }),
      false
    );

    // Negative: non-cancellation error codes
    assert.strictEqual(
      isPermittedFontCancellation('https://fonts.gstatic.com/font.woff2', 'net::ERR_TIMED_OUT', { allowFontCancellation: true }),
      false
    );

    // Negative: local assets or attacker domains with cancellation
    assert.strictEqual(
      isPermittedFontCancellation('http://127.0.0.1:41525/_astro/main.css', 'net::ERR_ABORTED', { allowFontCancellation: true }),
      false
    );
    assert.strictEqual(
      isPermittedFontCancellation('https://evil.com/font.woff2', 'net::ERR_ABORTED', { allowFontCancellation: true }),
      false
    );
    assert.strictEqual(
      isPermittedFontCancellation('https://fonts.googleapis.com.attacker.org/font.woff2', 'net::ERR_ABORTED', { allowFontCancellation: true }),
      false
    );
  });

  it('11. Verifies console error suppression logic (exact URL extraction and validation)', () => {
    // Console error with location URL matching font host and recognized offline error
    assert.strictEqual(shouldSuppressConsoleError('Failed to load resource: net::ERR_INTERNET_DISCONNECTED', 'https://fonts.gstatic.com/font.woff2'), true);
    assert.strictEqual(shouldSuppressConsoleError('Failed to load resource: net::ERR_NAME_NOT_RESOLVED', 'https://fonts.googleapis.com/css2'), true);

    // Console error with font URL embedded in message text and recognized offline error
    assert.strictEqual(shouldSuppressConsoleError('GET https://fonts.googleapis.com/css2 net::ERR_NAME_NOT_RESOLVED', null), true);

    // Console error with net::ERR_ABORTED tolerated under explicit font cancellation policy
    assert.strictEqual(
      shouldSuppressConsoleError('Failed to load resource: net::ERR_ABORTED', 'https://fonts.gstatic.com/font.woff2', { allowFontCancellation: true }),
      true
    );
    assert.strictEqual(
      shouldSuppressConsoleError('Failed to load resource: net::ERR_ABORTED', 'https://fonts.gstatic.com/font.woff2', { allowFontCancellation: false }),
      false
    );

    // Console error on local asset must NOT be suppressed
    assert.strictEqual(shouldSuppressConsoleError('Failed to load resource: net::ERR_ABORTED', 'http://127.0.0.1:41525/script.js'), false);

    // Console error on attacker URL must NOT be suppressed
    assert.strictEqual(shouldSuppressConsoleError('Failed to load resource: net::ERR_ABORTED', 'https://fonts.googleapis.com.evil.com/x'), false);

    // Non-offline console error on genuine font host must NOT be suppressed (e.g. JS error)
    assert.strictEqual(shouldSuppressConsoleError('Uncaught TypeError: Cannot read property of undefined', 'https://fonts.gstatic.com/font.woff2'), false);
  });

  it('12. Verifies shared HTTP response fatality helper (isFatalHttpResponse) across boundary status codes', () => {
    // Requirement 4: Test actual helper for HTTP 399, 400, 404, 500, and 599

    // HTTP 399: Non-fatal boundary (highest 3xx redirect / non-error code)
    assert.strictEqual(isFatalHttpResponse(399), false, 'HTTP 399 must be non-fatal');
    assert.strictEqual(isFatalHttpResponse(399, 'https://fonts.googleapis.com/css2'), false, 'HTTP 399 on font host must be non-fatal');

    // HTTP 400: Fatal boundary (lowest 4xx client error code)
    assert.strictEqual(isFatalHttpResponse(400), true, 'HTTP 400 must be fatal');
    assert.strictEqual(isFatalHttpResponse(400, 'https://fonts.googleapis.com/css2'), true, 'HTTP 400 on font host must be fatal');

    // HTTP 404: Fatal (Not Found)
    assert.strictEqual(isFatalHttpResponse(404), true, 'HTTP 404 must be fatal');
    assert.strictEqual(isFatalHttpResponse(404, 'https://fonts.gstatic.com/s/redaction10/v1/missing.woff2'), true, 'HTTP 404 on font host must be fatal');

    // HTTP 500: Fatal (Internal Server Error)
    assert.strictEqual(isFatalHttpResponse(500), true, 'HTTP 500 must be fatal');
    assert.strictEqual(isFatalHttpResponse(500, 'https://fonts.googleapis.com/css2'), true, 'HTTP 500 on font host must be fatal');

    // HTTP 599: Fatal boundary (highest standard 5xx server error code)
    assert.strictEqual(isFatalHttpResponse(599), true, 'HTTP 599 must be fatal');
    assert.strictEqual(isFatalHttpResponse(599, 'https://fonts.gstatic.com/font.woff2'), true, 'HTTP 599 on font host must be fatal');

    // Additional standard status codes
    assert.strictEqual(isFatalHttpResponse(200, 'http://127.0.0.1:41525/'), false, 'HTTP 200 must be non-fatal');
    assert.strictEqual(isFatalHttpResponse(204), false, 'HTTP 204 must be non-fatal');
    assert.strictEqual(isFatalHttpResponse(301), false, 'HTTP 301 must be non-fatal');
    assert.strictEqual(isFatalHttpResponse(302), false, 'HTTP 302 must be non-fatal');
    assert.strictEqual(isFatalHttpResponse(403), true, 'HTTP 403 must be fatal');
    assert.strictEqual(isFatalHttpResponse(502), true, 'HTTP 502 must be fatal');
    assert.strictEqual(isFatalHttpResponse(503), true, 'HTTP 503 must be fatal');

    // Invalid / non-integer inputs fail closed (treated as fatal)
    assert.strictEqual(isFatalHttpResponse('invalid'), true, 'Non-numeric status code must fail closed as fatal');
    assert.strictEqual(isFatalHttpResponse(NaN), true, 'NaN status code must fail closed as fatal');
    assert.strictEqual(isFatalHttpResponse(null), true, 'null status code must fail closed as fatal');
  });
});
