/**
 * Unit Test Suite for PS-028 Scenario Analytics Dashboard & PDF Generation
 *
 * Exercises:
 * 1. Scenario selection (single, multiple, all, clear)
 * 2. Browser filtering (Chrome, Firefox, Both)
 * 3. Box plot quartile mathematics & outlier detection
 * 4. Empirical cohort metrics & baseline comparisons
 * 5. DNS metrics & S6 delayed AAAA verification
 * 6. Winner distribution & SYN retransmission counting
 * 7. Zero empirical leakage of excluded attempts
 * 8. Scientific RFC 8305 CAD qualification preservation
 * 9. PDF Report generation (valid blob, multi-scenario, single-scenario, error on empty)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const bundlePath = path.resolve(__dirname, '../public/data/demo_bundle.json');
const provenancePath = path.resolve(__dirname, '../public/data/demo_bundle.json.provenance.json');

// Import analytics calculation utilities directly
import {
  computeBoxPlotStats,
  getTrialMetricValue,
  computeScenarioCohortAggregates,
  computeOverallSummary,
} from '../src/lib/analytics/analytics-calculations.ts';

import {
  ALL_SCENARIOS,
  SCENARIO_METADATA,
} from '../src/lib/analytics/analytics-filters.ts';

import {
  generateScenarioAnalysisPdf,
} from '../src/components/analytics/reports/pdf-report-generator.ts';

import {
  evaluateEvidenceIntegrity,
} from '../src/lib/historical-evidence.ts';

describe('PS-028 Scenario Analytics Dashboard & Visualizations Test Suite', () => {
  const bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
  const provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
  const allTrials = bundle.trials;
  const validTrials = allTrials.filter((t) => t.validity_category === 'VALID_LIVE');

  it('1. Bundle loading and valid trial inventory (280 valid live trials, 2 exclusions)', () => {
    assert.equal(validTrials.length, 280, 'Expected exactly 280 valid live trials');
    assert.equal(bundle.exclusions.length, 2, 'Expected exactly 2 excluded attempts');
  });

  it('2. Scenario metadata integrity across S0 through S6', () => {
    assert.equal(ALL_SCENARIOS.length, 7, 'Expected 7 controlled scenarios');
    for (const scId of ALL_SCENARIOS) {
      const meta = SCENARIO_METADATA[scId];
      assert.ok(meta, `Scenario ${scId} must have metadata`);
      assert.equal(meta.id, scId);
      assert.ok(meta.name.length > 0);
      assert.ok(meta.condition.length > 0);
      assert.ok(meta.description.length > 0);
    }
  });

  it('3. Scenario filtering and trial counts (single scenario vs multiple scenarios)', () => {
    // S0 only
    const s0Summary = computeOverallSummary(allTrials, ['S0'], 'ALL');
    assert.equal(s0Summary.selectedScenariosCount, 1);
    assert.equal(s0Summary.validTrialsCount, 40); // 20 Chrome + 20 Firefox
    assert.equal(s0Summary.chromeTrialsCount, 20);
    assert.equal(s0Summary.firefoxTrialsCount, 20);

    // Multi-scenario: S1, S3, S5
    const multiSummary = computeOverallSummary(allTrials, ['S1', 'S3', 'S5'], 'ALL');
    assert.equal(multiSummary.selectedScenariosCount, 3);
    assert.equal(multiSummary.validTrialsCount, 120); // 40 * 3
    assert.equal(multiSummary.chromeTrialsCount, 60);
    assert.equal(multiSummary.firefoxTrialsCount, 60);

    // All scenarios
    const allSummary = computeOverallSummary(allTrials, ALL_SCENARIOS, 'ALL');
    assert.equal(allSummary.selectedScenariosCount, 7);
    assert.equal(allSummary.validTrialsCount, 280);

    // Empty scenarios
    const emptySummary = computeOverallSummary(allTrials, [], 'ALL');
    assert.equal(emptySummary.selectedScenariosCount, 0);
    assert.equal(emptySummary.validTrialsCount, 0);
  });

  it('4. Browser cohort filtering (Chrome only, Firefox only, Both browsers)', () => {
    const chromeSummary = computeOverallSummary(allTrials, ALL_SCENARIOS, 'google-chrome');
    assert.equal(chromeSummary.validTrialsCount, 140);
    assert.equal(chromeSummary.chromeTrialsCount, 140);
    assert.equal(chromeSummary.firefoxTrialsCount, 0);

    const firefoxSummary = computeOverallSummary(allTrials, ALL_SCENARIOS, 'firefox');
    assert.equal(firefoxSummary.validTrialsCount, 140);
    assert.equal(firefoxSummary.chromeTrialsCount, 0);
    assert.equal(firefoxSummary.firefoxTrialsCount, 140);

    const bothSummary = computeOverallSummary(allTrials, ALL_SCENARIOS, 'ALL');
    assert.equal(bothSummary.validTrialsCount, 280);
    assert.equal(bothSummary.chromeTrialsCount, 140);
    assert.equal(bothSummary.firefoxTrialsCount, 140);
  });

  it('5. Box-and-whisker calculation mathematics (median, quartiles, Tukey fences, outliers)', () => {
    // Test known synthetic distribution
    const sample = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 300]; // 300 is an outlier
    const stats = computeBoxPlotStats(sample);
    assert.ok(stats);
    assert.equal(stats.sampleSize, 11);
    assert.equal(stats.min, 10);
    assert.equal(stats.median, 60);
    assert.equal(stats.outliers.length, 1);
    assert.equal(stats.outliers[0], 300);
    assert.equal(stats.max, 100); // Whisker max is highest non-outlier

    // Null and empty handling
    assert.equal(computeBoxPlotStats([]), null);
    assert.equal(computeBoxPlotStats([null, undefined, NaN]), null);
  });

  it('6. Empirically calculated cohort medians reconcile with authoritative values', () => {
    // S0 Chrome: t_connect ~ 20.39ms
    const s0Chrome = computeScenarioCohortAggregates(allTrials, 'S0', 'google-chrome');
    assert.ok(s0Chrome.tConnectMedian !== null);
    assert.ok(Math.abs(s0Chrome.tConnectMedian - 20.39) < 0.1, `Got ${s0Chrome.tConnectMedian}`);

    // S3 Chrome (150ms RTT link): t_connect ~ 150.76ms
    const s3Chrome = computeScenarioCohortAggregates(allTrials, 'S3', 'google-chrome');
    assert.ok(s3Chrome.tConnectMedian !== null);
    assert.ok(Math.abs(s3Chrome.tConnectMedian - 150.76) < 0.5, `Got ${s3Chrome.tConnectMedian}`);

    // S1 Chrome (fallback): t_connect ~ 21.08ms, t_setup_total ~ 322.00ms
    const s1Chrome = computeScenarioCohortAggregates(allTrials, 'S1', 'google-chrome');
    assert.ok(s1Chrome.tConnectMedian !== null);
    assert.ok(s1Chrome.tSetupTotalMedian !== null);
    assert.ok(Math.abs(s1Chrome.tConnectMedian - 21.08) < 0.5, `Got ${s1Chrome.tConnectMedian}`);
    assert.ok(Math.abs(s1Chrome.tSetupTotalMedian - 322.00) < 0.5, `Got ${s1Chrome.tSetupTotalMedian}`);
  });

  it('7. Scenario S6 DNS resolution and AAAA delay verification (~500ms)', () => {
    const s6Aggregates = computeScenarioCohortAggregates(allTrials, 'S6', 'ALL');
    assert.ok(s6Aggregates.dnsAAAAMedian !== null);
    assert.ok(s6Aggregates.dnsAMedian !== null);
    assert.ok(s6Aggregates.dnsResolutionMedian !== null);

    // AAAA is delayed by 500ms; A is immediate (~2ms)
    assert.ok(s6Aggregates.dnsAAAAMedian >= 500, `Expected AAAA >= 500ms, got ${s6Aggregates.dnsAAAAMedian}`);
    assert.ok(s6Aggregates.dnsAMedian < 10, `Expected A < 10ms, got ${s6Aggregates.dnsAMedian}`);
    assert.ok(s6Aggregates.dnsResolutionMedian >= 500, `Expected Resolution >= 500ms, got ${s6Aggregates.dnsResolutionMedian}`);
  });

  it('8. Primary flow winner distribution across scenarios (IPv6 vs IPv4)', () => {
    // S0: 100% IPv6 wins
    const s0Stats = computeScenarioCohortAggregates(allTrials, 'S0', 'ALL');
    assert.equal(s0Stats.ipv6Wins, 40);
    assert.equal(s0Stats.ipv4Wins, 0);

    // S1: 100% IPv4 fallback wins
    const s1Stats = computeScenarioCohortAggregates(allTrials, 'S1', 'ALL');
    assert.equal(s1Stats.ipv6Wins, 0);
    assert.equal(s1Stats.ipv4Wins, 40);

    // S5: 50% loss rule: IPv6 wins in majority (33 of 40)
    const s5Stats = computeScenarioCohortAggregates(allTrials, 'S5', 'ALL');
    assert.equal(s5Stats.ipv6Wins, 33);
    assert.equal(s5Stats.ipv4Wins, 7);
  });

  it('9. SYN retransmission counts observed from packet telemetry', () => {
    const s1Firefox = computeScenarioCohortAggregates(allTrials, 'S1', 'firefox');
    assert.equal(s1Firefox.retransIpv6Total, 2, 'Expected 2 observed IPv6 SYN retransmissions in S1 Firefox');

    const s5Stats = computeScenarioCohortAggregates(allTrials, 'S5', 'ALL');
    assert.equal(s5Stats.retransIpv6Total, 0, 'Expected 0 SYN retransmissions in S5');
    assert.equal(s5Stats.retransIpv4Total, 0, 'Expected 0 IPv4 SYN retransmissions in S5');
  });

  it('10. Excluded attempts strictly quarantined from all analytics calculations', () => {
    assert.equal(bundle.exclusions.length, 2);
    const excludedIds = bundle.exclusions.map((e) => e.trial_id);

    // Verify none of the excluded IDs exist in valid live trials
    for (const exId of excludedIds) {
      const match = validTrials.find((t) => t.trial_id === exId);
      assert.equal(match, undefined, `Excluded trial ${exId} must not be in valid trials`);
    }

    // Verify overall summary ignores exclusions
    const allSummary = computeOverallSummary(bundle.trials, ALL_SCENARIOS, 'ALL');
    assert.equal(allSummary.validTrialsCount, 280);
  });

  it('11. Dynamic PDF Report generation for multiple selected scenarios', async () => {
    const integrity = evaluateEvidenceIntegrity(provenance.output_bundle_sha256, provenance);

    const pdfBlob = await generateScenarioAnalysisPdf({
      bundle,
      provenance,
      integrity,
      selectedScenarios: ['S1', 'S3', 'S5'],
      selectedBrowser: 'ALL',
      selectedMetric: 't_connect_ms',
      allTrials: validTrials,
    });

    assert.ok(pdfBlob instanceof Blob);
    assert.ok(pdfBlob.size > 10000, `Expected PDF blob > 10KB, got ${pdfBlob.size} bytes`);
    assert.equal(pdfBlob.type, 'application/pdf');
  });

  it('12. Dynamic PDF Report generation for single scenario and Chrome only', async () => {
    const integrity = evaluateEvidenceIntegrity(provenance.output_bundle_sha256, provenance);

    const pdfBlob = await generateScenarioAnalysisPdf({
      bundle,
      provenance,
      integrity,
      selectedScenarios: ['S6'],
      selectedBrowser: 'google-chrome',
      selectedMetric: 'dns_latency_aaaa_ms',
      allTrials: validTrials,
    });

    assert.ok(pdfBlob instanceof Blob);
    assert.ok(pdfBlob.size > 8000, `Expected PDF blob > 8KB, got ${pdfBlob.size} bytes`);
    assert.equal(pdfBlob.type, 'application/pdf');
  });

  it('13. PDF Report generation throws error when no scenarios are selected', async () => {
    const integrity = evaluateEvidenceIntegrity(provenance.output_bundle_sha256, provenance);

    await assert.rejects(
      async () => {
        await generateScenarioAnalysisPdf({
          bundle,
          provenance,
          integrity,
          selectedScenarios: [],
          selectedBrowser: 'ALL',
          selectedMetric: 't_connect_ms',
          allTrials: validTrials,
        });
      },
      {
        message: 'Cannot generate report: No scenarios selected.',
      }
    );
  });
});
