/**
 * Frontend Test Suite: PS-028 Historical Evidence Explorer Data Contract & Logic
 *
 * Executed via Node's built-in test runner: `node --test test/historical-evidence.test.mjs`
 * Validates data reconciliation, scenario mapping, CAD qualification, timestamp integrity,
 * and strict isolation for the Phase F Historical Evidence Explorer.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import {
  computeMedian,
  deriveRelativeOffsetMs,
  computeCohortMetrics,
  auditPrimaryHandshakeOrdering,
  validateCampaignInvariants,
  evaluateEvidenceIntegrity,
  AUTHORITATIVE_SCENARIOS,
} from '../src/lib/historical-evidence.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../../..');

const bundlePath = path.join(repoRoot, 'lab', 'derived', 'phase-e', 'demo_bundle.json');
const provPath = path.join(repoRoot, 'lab', 'derived', 'phase-e', 'demo_bundle.json.provenance.json');

describe('PS-028 Historical Evidence Explorer Test Suite (TASK 6A Reconciled)', () => {
  // Load real authoritative bundle and provenance
  const rawBundleBytes = fs.readFileSync(bundlePath);
  const bundle = JSON.parse(rawBundleBytes.toString('utf8'));
  const provenance = JSON.parse(fs.readFileSync(provPath, 'utf8'));

  test('1. Bundle parsing and schema validation', () => {
    assert.equal(bundle.bundle_schema_version, '1.0.0');
    assert.equal(bundle.campaign_id, 'ps028-a10-live-20261030-01');
    assert.equal(bundle.evidence_type, 'HISTORICAL_LIVE');
    assert.ok(Array.isArray(bundle.trials), 'trials must be an array');
    assert.ok(Array.isArray(bundle.exclusions), 'exclusions must be an array');
    assert.ok(bundle.reconciliation_summary, 'reconciliation_summary must exist');
    assert.ok(bundle.scenario_definitions, 'scenario_definitions must exist');
    assert.ok(bundle.browser_cohorts, 'browser_cohorts must exist');
    assert.ok(bundle.statistical_summaries, 'statistical_summaries must exist');
    assert.ok(Array.isArray(bundle.rfc8305_assessment), 'rfc8305_assessment must be an array');
  });

  test('2. Provenance SHA-256 validation', () => {
    const computedHash = crypto.createHash('sha256').update(rawBundleBytes).digest('hex');
    assert.equal(computedHash, provenance.output_bundle_sha256, 'Computed SHA-256 must match provenance sidecar');
    assert.equal(provenance.generator_script, 'lab/build_demo_bundle.py');
    assert.match(provenance.generator_commit, /^[0-9a-f]{40}$/, 'generator_commit must be a 40-character hex commit SHA');
  });

  test('3. Valid-trial versus excluded-trial separation', () => {
    const validTrialIds = new Set(bundle.trials.map((t) => t.trial_id));
    const excludedTrialIds = new Set(bundle.exclusions.map((e) => e.trial_id));

    // Must be completely disjoint
    for (const exId of excludedTrialIds) {
      assert.ok(!validTrialIds.has(exId), `Excluded trial ${exId} must NOT exist in valid trials population`);
    }

    // Check validity categories
    for (const t of bundle.trials) {
      assert.equal(t.validity_category, 'VALID_LIVE', `Valid trial ${t.trial_id} must have VALID_LIVE category`);
    }
    for (const e of bundle.exclusions) {
      assert.equal(e.validity_category, 'CLEANUP_FAILURE', `Exclusion ${e.trial_id} must have CLEANUP_FAILURE category`);
    }
  });

  test('4. Correct 280 valid-trial count and presence of all trial IDs', () => {
    assert.equal(bundle.trials.length, 280, 'Must contain exactly 280 valid live trials');
    assert.equal(bundle.reconciliation_summary.valid_live_trials, 280);

    const trialIdSet = new Set(bundle.trials.map((t) => t.trial_id));
    assert.equal(trialIdSet.size, 280, 'All 280 trial IDs must be unique');
  });

  test('5. Correct 2 excluded-attempt count', () => {
    assert.equal(bundle.exclusions.length, 2, 'Must contain exactly 2 excluded cleanup-failure attempts');
    assert.equal(bundle.reconciliation_summary.cleanup_failure_exclusions, 2);
    const exIds = bundle.exclusions.map((e) => e.trial_id).sort();
    assert.deepEqual(exIds, ['trial-20261029205442-aba6193c', 'trial-20261029210226-944fcfaa'].sort());
  });

  test('6. Exclusion records never enter empirical cohort calculations', () => {
    for (const scId of ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6']) {
      for (const brId of ['google-chrome', 'firefox']) {
        const stats = computeCohortMetrics(bundle.trials, scId, brId, bundle.browser_cohorts);
        assert.equal(stats.sampleSize, 20, `Cohort ${scId}:${brId} sample size must be strictly 20`);
      }
    }
  });

  test('7. Correct valid-trial and exclusion event counts', () => {
    let validEvents = 0;
    for (const t of bundle.trials) {
      validEvents += t.timeline_events.length;
    }
    let exclusionEvents = 0;
    for (const e of bundle.exclusions) {
      exclusionEvents += e.timeline_events.length;
    }

    assert.equal(validEvents, 28326, 'Must contain exactly 28,326 valid-trial timeline events');
    assert.equal(exclusionEvents, 4, 'Must contain exactly 4 exclusion timeline events (2 per excluded attempt)');
    assert.equal(validEvents + exclusionEvents, 28330, 'Total timeline events must equal 28,330');
    assert.equal(bundle.reconciliation_summary.timeline_events_count, 28330);
  });

  test('8. Cohort grouping by scenario and browser (14 cohorts x 20 reps)', () => {
    const cohorts = {};
    for (const t of bundle.trials) {
      const key = `${t.scenario_id}:${t.browser}`;
      cohorts[key] = (cohorts[key] || 0) + 1;
    }

    assert.equal(Object.keys(cohorts).length, 14, 'Must have exactly 14 cohorts (7 scenarios x 2 browsers)');
    for (const [key, count] of Object.entries(cohorts)) {
      assert.equal(count, 20, `Cohort ${key} must have exactly 20 repetitions`);
    }
  });

  test('9. All 14 cohort median values reconcile with authoritative historical metrics', () => {
    const EXPECTED = {
      'S0:google-chrome': { tConn: 20.39, tSetup: 20.39, cad: null, rawOffset: null },
      'S0:firefox':       { tConn: 20.49, tSetup: 20.49, cad: null, rawOffset: null },
      'S1:google-chrome': { tConn: 21.08, tSetup: 322.00, cad: 300.83, rawOffset: 300.83 },
      'S1:firefox':       { tConn: 20.55, tSetup: 429.74, cad: 408.46, rawOffset: 408.46 },
      'S2:google-chrome': { tConn: 20.37, tSetup: 21.12, cad: null, rawOffset: 0.71 },
      'S2:firefox':       { tConn: 20.50, tSetup: 181.87, cad: null, rawOffset: 160.43 },
      'S3:google-chrome': { tConn: 150.76, tSetup: 150.76, cad: null, rawOffset: null },
      'S3:firefox':       { tConn: 150.45, tSetup: 150.45, cad: null, rawOffset: null },
      'S4:google-chrome': { tConn: 20.82, tSetup: 321.72, cad: 300.80, rawOffset: 300.80 },
      'S4:firefox':       { tConn: 20.48, tSetup: 420.07, cad: 397.94, rawOffset: 397.94 },
      'S5:google-chrome': { tConn: 20.54, tSetup: 23.10, cad: null, rawOffset: 300.96 },
      'S5:firefox':       { tConn: 20.58, tSetup: 86.95, cad: null, rawOffset: 392.86 },
      'S6:google-chrome': { tConn: 20.71, tSetup: 20.71, cad: null, rawOffset: null },
      'S6:firefox':       { tConn: 20.47, tSetup: 20.58, cad: null, rawOffset: null },
    };

    for (const [key, exp] of Object.entries(EXPECTED)) {
      const [scId, brId] = key.split(':');
      const stats = computeCohortMetrics(bundle.trials, scId, brId, bundle.browser_cohorts);

      assert.equal(stats.sampleSize, 20, `${key} must have n=20`);
      assert.ok(
        Math.abs(stats.tConnectMedian - exp.tConn) < 0.05,
        `${key} t_connect median ~${exp.tConn} (got ${stats.tConnectMedian})`
      );
      assert.ok(
        Math.abs(stats.tSetupTotalMedian - exp.tSetup) < 0.5,
        `${key} t_setup_total median ~${exp.tSetup} (got ${stats.tSetupTotalMedian})`
      );

      if (exp.cad === null) {
        assert.equal(stats.cadMedian, null, `${key} CAD median must be null (not assessed or N/A)`);
      } else {
        assert.ok(
          Math.abs(stats.cadMedian - exp.cad) < 0.5,
          `${key} CAD median ~${exp.cad} (got ${stats.cadMedian})`
        );
      }

      if (exp.rawOffset !== null) {
        assert.ok(
          Math.abs(stats.rawFamilySynOffsetMedian - exp.rawOffset) < 0.5,
          `${key} rawFamilySynOffsetMedian ~${exp.rawOffset} (got ${stats.rawFamilySynOffsetMedian})`
        );
      }
    }
  });

  test('10. Scenario labels: S2 is TCP RST and S5 is IPv6 50% SYN loss', () => {
    assert.equal(AUTHORITATIVE_SCENARIOS.S0.name, 'Baseline dual-stack');
    assert.equal(AUTHORITATIVE_SCENARIOS.S1.name, 'IPv6 SYN blackhole');
    assert.equal(AUTHORITATIVE_SCENARIOS.S2.name, 'IPv6 TCP RST');
    assert.ok(
      !AUTHORITATIVE_SCENARIOS.S2.name.toLowerCase().includes('immediate'),
      'S2 name must not contain Immediate'
    );
    assert.ok(
      !AUTHORITATIVE_SCENARIOS.S2.name.toLowerCase().includes('fallback'),
      'S2 name must not contain Fallback'
    );

    assert.equal(AUTHORITATIVE_SCENARIOS.S3.name, 'IPv6 RTT 150 ms');
    assert.equal(AUTHORITATIVE_SCENARIOS.S4.name, 'IPv6 RTT 600 ms with IPv4 10 ms');
    assert.equal(AUTHORITATIVE_SCENARIOS.S5.name, 'IPv6 50% SYN loss');
    assert.ok(
      !AUTHORITATIVE_SCENARIOS.S5.name.toLowerCase().includes('subflows'),
      'S5 scenario name must NOT be named after subflows'
    );
    assert.equal(AUTHORITATIVE_SCENARIOS.S6.name, 'Delayed AAAA response');
  });

  test('11. S5 HTTP/1.1 subflows count is preserved as a separate telemetry measurement', () => {
    assert.equal(bundle.reconciliation_summary.s5_flows_count, 95);
    const subflowsInTrials = bundle.trials.reduce(
      (sum, t) => sum + (t.s5_flow_dissection?.length ?? 0),
      0
    );
    assert.equal(subflowsInTrials, 95, 'Must contain 95 total HTTP/1.1 subflows across S5 trials');
  });

  test('12. S2 CAD presentation is qualified as NOT_ASSESSED with raw SYN offset preserved', () => {
    const s2Chrome = computeCohortMetrics(bundle.trials, 'S2', 'google-chrome');
    assert.equal(s2Chrome.isCadAssessed, false);
    assert.equal(s2Chrome.cadStatusLabel, 'NOT_ASSESSED');
    assert.equal(s2Chrome.cadMedian, null);
    assert.ok(Math.abs(s2Chrome.rawFamilySynOffsetMedian - 0.71) < 0.05);

    const s2Firefox = computeCohortMetrics(bundle.trials, 'S2', 'firefox');
    assert.equal(s2Firefox.isCadAssessed, false);
    assert.equal(s2Firefox.cadStatusLabel, 'NOT_ASSESSED');
    assert.equal(s2Firefox.cadMedian, null);
    assert.ok(Math.abs(s2Firefox.rawFamilySynOffsetMedian - 160.43) < 0.05);
  });

  test('13. RFC 8305 S2 assessment check identifier and status', () => {
    const check2 = bundle.rfc8305_assessment.find((c) => c.scenario_id === 'S2');
    assert.ok(check2, 'S2 assessment check must exist');
    assert.equal(check2.check_id, 'RFC8305-SEC5-CAD-10MS-FLOOR');
    assert.equal(check2.overall_observation_status, 'NOT_ASSESSED');

    const check1 = bundle.rfc8305_assessment.find((c) => c.check_id === 'RFC8305-SEC2-IPV6-PREFERENCE');
    assert.ok(check1, 'Check 1 (RFC8305-SEC2-IPV6-PREFERENCE) must exist');
    assert.equal(check1.rfc_section, 'RFC 8305 Section 2');

    const check5 = bundle.rfc8305_assessment.find((c) => c.check_id === 'RFC8305-SEC3-RESOLUTION-DELAY');
    assert.ok(check5, 'Check 5 (RFC8305-SEC3-RESOLUTION-DELAY) must exist');
    assert.equal(check5.rfc_section, 'RFC 8305 Section 3');

    const check6 = bundle.rfc8305_assessment.find((c) => c.check_id === 'RFC8305-SEC4-HISTORICAL-STATE');
    assert.ok(check6, 'Check 6 (RFC8305-SEC4-HISTORICAL-STATE) must exist');
    assert.equal(check6.rfc_section, 'RFC 8305 Section 4');
  });

  test('14. Absolute epoch timestamps integrity and actual campaign time range', () => {
    let minEpoch = Infinity;
    let maxEpoch = -Infinity;

    for (const t of bundle.trials) {
      for (const ev of t.timeline_events) {
        assert.equal(typeof ev.timestamp, 'number');
        assert.ok(isFinite(ev.timestamp));
        if (ev.timestamp < minEpoch) minEpoch = ev.timestamp;
        if (ev.timestamp > maxEpoch) maxEpoch = ev.timestamp;
      }
    }

    // Earliest event: 1793307265.657889 (2026-10-29T20:54:25 UTC)
    // Latest event:   1793314632.728189 (2026-10-29T22:57:12 UTC)
    assert.ok(minEpoch >= 1793307265, `Min epoch (${minEpoch}) must be >= 1793307265 (October 2026)`);
    assert.ok(maxEpoch <= 1793314633, `Max epoch (${maxEpoch}) must be <= 1793314633 (October 2026)`);

    const startDate = new Date(minEpoch * 1000).toISOString();
    const endDate = new Date(maxEpoch * 1000).toISOString();
    assert.ok(startDate.startsWith('2026-10-29'), `Start date ${startDate} must be 2026-10-29`);
    assert.ok(endDate.startsWith('2026-10-29'), `End date ${endDate} must be 2026-10-29`);
  });

  test('15. Event timestamps fall within recorded trial lifecycles and preserve chronological order', () => {
    for (const trial of bundle.trials) {
      const events = trial.timeline_events;
      assert.ok(events.length > 0, `Trial ${trial.trial_id} must have timeline events`);
      const tFirst = events[0].timestamp;
      const tLast = events[events.length - 1].timestamp;

      assert.ok(tLast >= tFirst, `tLast (${tLast}) must be >= tFirst (${tFirst}) in ${trial.trial_id}`);

      for (let i = 1; i < events.length; i++) {
        assert.ok(
          events[i].timestamp >= events[i - 1].timestamp,
          `Monotonic ordering violated at event ${i} in ${trial.trial_id}`
        );
      }
    }
  });

  test('16. UI-derived relative offsets do not alter source timestamps', () => {
    const trial = bundle.trials[0];
    const events = trial.timeline_events;
    const originalFirstTs = events[0].timestamp;
    const originalLastTs = events[events.length - 1].timestamp;

    const relFirst = deriveRelativeOffsetMs(events, originalFirstTs);
    const relLast = deriveRelativeOffsetMs(events, originalLastTs);

    assert.equal(relFirst, 0.0);
    assert.ok(relLast > 0);

    // Source timestamps preserved bit-for-bit
    assert.equal(events[0].timestamp, originalFirstTs);
    assert.equal(events[events.length - 1].timestamp, originalLastTs);
  });

  test('17. Null-safe timing aggregation utility functions', () => {
    assert.equal(computeMedian([]), null);
    assert.equal(computeMedian([null, undefined, NaN]), null);
    assert.equal(computeMedian([10, null, 20, undefined, 30]), 20);
    assert.equal(computeMedian([10, 20, 30, 40]), 25);
    assert.equal(computeMedian([50, 10, 30]), 30);
  });

  test('18. Search and filter functionality matches trial cohorts', () => {
    const s2Trials = bundle.trials.filter((t) => t.scenario_id === 'S2');
    assert.equal(s2Trials.length, 40, 'Scenario S2 must have 40 trials across both browsers');

    const s2Chrome = bundle.trials.filter((t) => t.scenario_id === 'S2' && t.browser === 'google-chrome');
    assert.equal(s2Chrome.length, 20, 'S2 Chrome must have 20 trials');

    const targetTrial = bundle.trials.find((t) => t.trial_id === 'trial-20261029205425-6cb90a54');
    assert.ok(targetTrial, 'Representative trial-20261029205425-6cb90a54 must exist');
    assert.equal(targetTrial.scenario_id, 'S0');
    assert.equal(targetTrial.browser, 'google-chrome');
  });

  test('19. Strict isolation (no live API dependencies or simulation flags)', () => {
    for (const trial of bundle.trials) {
      assert.equal(trial.execution_mode, 'LIVE', `Trial ${trial.trial_id} must have execution_mode LIVE`);
      assert.equal(trial.is_simulation, false, `Trial ${trial.trial_id} must have is_simulation false`);
      assert.equal(trial.evidence_type, 'HISTORICAL_LIVE');
    }
  });

  test('20. Invariant health check validator function passes all 10 invariants', () => {
    const checks = validateCampaignInvariants(bundle);
    assert.equal(checks.length, 10, 'Must produce 10 invariant checks');
    for (const c of checks) {
      assert.equal(c.passed, true, `Invariant check ${c.name} must PASS (got actual=${c.actual})`);
    }
  });

  test('21. Canonical CAD formula derivation across dual-family trials', () => {
    // Formula per lab/run_trial.py:1890 and docs/phase-c-metric-contract.md:
    // connection_attempt_delay_ms = (t_first_syn_ipv4 - t_first_syn_ipv6) * 1000.0 ms
    let verifiedCount = 0;
    for (const trial of bundle.trials) {
      const attempts = trial.connection_attempts || [];
      const v6Syns = attempts
        .filter((a) => a.family === 'IPv6' && typeof a.syn_time === 'number')
        .map((a) => a.syn_time);
      const v4Syns = attempts
        .filter((a) => a.family === 'IPv4' && typeof a.syn_time === 'number')
        .map((a) => a.syn_time);

      if (v6Syns.length > 0 && v4Syns.length > 0) {
        const minV6 = Math.min(...v6Syns);
        const minV4 = Math.min(...v4Syns);
        if (minV4 >= minV6) {
          const expectedCadMs = (minV4 - minV6) * 1000.0;
          const reportedCadMs = trial.metrics?.connection_attempt_delay_ms;
          assert.ok(
            reportedCadMs !== undefined && reportedCadMs !== null,
            `Trial ${trial.trial_id} missing reported CAD metric`
          );
          assert.ok(
            Math.abs(reportedCadMs - expectedCadMs) < 0.05,
            `Trial ${trial.trial_id} reported CAD ${reportedCadMs} != expected ${expectedCadMs}`
          );
          verifiedCount++;
        }
      }
    }
    // S1 (40) + S2 (40) + S4 (39) + S5 (12) = 131 trials with minV4 >= minV6
    assert.equal(verifiedCount, 131, 'Must strictly verify canonical CAD formula across all 131 dual-family trials');
  });

  test('22. Handshake ordering audit across all 14 cohorts', () => {
    const rows = auditPrimaryHandshakeOrdering(bundle.trials, bundle.browser_cohorts);
    assert.equal(rows.length, 14, 'Must produce 14 audit rows (7 scenarios x 2 browsers)');

    for (const row of rows) {
      assert.equal(row.validTrialCount, 20, `Cohort ${row.scenarioId}:${row.browserId} must have 20 valid trials`);

      if (['S0', 'S3', 'S6'].includes(row.scenarioId)) {
        assert.equal(row.bothFamiliesObservedCount, 0, `${row.scenarioId} has 0 trials with both families`);
        assert.equal(row.cadClassification, 'NOT_APPLICABLE');
        assert.equal(row.cadMedian, null);
        assert.equal(row.rawFamilySynOffsetMedian, null);
        assert.equal(row.insufficientPairingCount, 0);
        assert.deepEqual(row.classificationCounts, { NOT_APPLICABLE: 20 });
      } else if (row.scenarioId === 'S1') {
        assert.equal(row.bothFamiliesObservedCount, 20);
        assert.equal(row.oppSynBeforeAckCount, 20);
        assert.equal(row.oppSynAfterAckCount, 0);
        assert.equal(row.cadClassification, 'PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET');
        assert.equal(row.insufficientPairingCount, 20);
        assert.deepEqual(row.classificationCounts, { PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET: 20 });
        assert.ok(row.cadMedian !== null);
      } else if (row.scenarioId === 'S2') {
        assert.equal(row.bothFamiliesObservedCount, 20);
        assert.equal(row.oppSynBeforeAckCount, 20);
        assert.equal(row.oppSynAfterAckCount, 0);
        assert.equal(row.cadClassification, 'NOT_ASSESSED');
        assert.equal(row.insufficientPairingCount, 20);
        assert.deepEqual(row.classificationCounts, { NOT_ASSESSED: 20 });
        assert.equal(row.cadMedian, null);
        assert.ok(row.rawFamilySynOffsetMedian !== null);
      } else if (row.scenarioId === 'S4') {
        const expectedBoth = row.browserId === 'google-chrome' ? 20 : 19;
        assert.equal(row.bothFamiliesObservedCount, expectedBoth);
        assert.equal(row.oppSynBeforeAckCount, expectedBoth);
        assert.equal(row.oppSynAfterAckCount, 0);
        assert.equal(row.cadClassification, 'PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET');
        assert.equal(row.insufficientPairingCount, expectedBoth);
        if (row.browserId === 'google-chrome') {
          assert.deepEqual(row.classificationCounts, { PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET: 20 });
        } else {
          assert.deepEqual(row.classificationCounts, { PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET: 19, NOT_APPLICABLE: 1 });
        }
        assert.ok(row.cadMedian !== null);
      } else if (row.scenarioId === 'S5') {
        const expectedBoth = row.browserId === 'google-chrome' ? 5 : 7;
        const expectedBefore = row.browserId === 'google-chrome' ? 2 : 5;
        const expectedAfter = row.browserId === 'google-chrome' ? 3 : 2;

        assert.equal(row.bothFamiliesObservedCount, expectedBoth);
        assert.equal(row.oppSynBeforeAckCount, expectedBefore);
        assert.equal(row.oppSynAfterAckCount, expectedAfter);
        assert.equal(row.cadClassification, 'RAW_FAMILY_SYN_OFFSET');
        assert.equal(row.insufficientPairingCount, expectedBoth);
        if (row.browserId === 'google-chrome') {
          assert.deepEqual(row.classificationCounts, {
            NOT_APPLICABLE: 15,
            RAW_FAMILY_SYN_OFFSET: 3,
            PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET: 2,
          });
        } else {
          assert.deepEqual(row.classificationCounts, {
            NOT_APPLICABLE: 13,
            RAW_FAMILY_SYN_OFFSET: 2,
            PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET: 5,
          });
        }
        assert.equal(row.cadMedian, null);
        assert.ok(row.rawFamilySynOffsetMedian !== null);
      }
    }
  });

  test('23. S5 Anomaly Verification: Subflow timing and winner counts', () => {
    const chromeS5 = bundle.trials.filter((t) => t.scenario_id === 'S5' && t.browser === 'google-chrome');
    const firefoxS5 = bundle.trials.filter((t) => t.scenario_id === 'S5' && t.browser === 'firefox');

    assert.equal(chromeS5.length, 20);
    assert.equal(firefoxS5.length, 20);

    const chromeWinners = { ipv6: 0, ipv4: 0 };
    for (const t of chromeS5) {
      const w = (t.primary_flow?.winning_family || '').toLowerCase();
      chromeWinners[w] = (chromeWinners[w] || 0) + 1;
    }
    assert.equal(chromeWinners.ipv6, 18, 'Chrome S5 must have 18 IPv6 winners');
    assert.equal(chromeWinners.ipv4, 2, 'Chrome S5 must have 2 IPv4 winners');

    const firefoxWinners = { ipv6: 0, ipv4: 0 };
    for (const t of firefoxS5) {
      const w = (t.primary_flow?.winning_family || '').toLowerCase();
      firefoxWinners[w] = (firefoxWinners[w] || 0) + 1;
    }
    assert.equal(firefoxWinners.ipv6, 15, 'Firefox S5 must have 15 IPv6 winners');
    assert.equal(firefoxWinners.ipv4, 5, 'Firefox S5 must have 5 IPv4 winners');

    // Total S5 trials with both families observed: exactly 12 (5 Chrome, 7 Firefox)
    const s5DualChrome = chromeS5.filter((t) => {
      const a = t.connection_attempts || [];
      return a.some((x) => x.family === 'IPv6') && a.some((x) => x.family === 'IPv4');
    });
    const s5DualFirefox = firefoxS5.filter((t) => {
      const a = t.connection_attempts || [];
      return a.some((x) => x.family === 'IPv6') && a.some((x) => x.family === 'IPv4');
    });
    assert.equal(s5DualChrome.length, 5, 'Chrome S5 must have 5 trials with both families');
    assert.equal(s5DualFirefox.length, 7, 'Firefox S5 must have 7 trials with both families');

    // Opposite-family SYN initiated after primary final ACK: exactly 5 trials (3 Chrome, 2 Firefox)
    const postAckChrome = s5DualChrome.filter((t) => {
      const v4Syns = (t.connection_attempts || []).filter((a) => a.family === 'IPv4').map((a) => a.syn_time);
      const minV4 = Math.min(...v4Syns);
      return minV4 > t.primary_flow?.final_ack_time;
    });
    const postAckFirefox = s5DualFirefox.filter((t) => {
      const v4Syns = (t.connection_attempts || []).filter((a) => a.family === 'IPv4').map((a) => a.syn_time);
      const minV4 = Math.min(...v4Syns);
      return minV4 > t.primary_flow?.final_ack_time;
    });

    assert.equal(postAckChrome.length, 3, 'Chrome S5 must have 3 trials with IPv4 SYN after primary final ACK');
    assert.equal(postAckFirefox.length, 2, 'Firefox S5 must have 2 trials with IPv4 SYN after primary final ACK');

    const postAckChromeReps = postAckChrome.map((t) => t.repetition).sort((a, b) => a - b);
    const postAckFirefoxReps = postAckFirefox.map((t) => t.repetition).sort((a, b) => a - b);
    assert.deepEqual(postAckChromeReps, [3, 5, 20], 'Post-ACK Chrome S5 reps must be 3, 5, 20');
    assert.deepEqual(postAckFirefoxReps, [5, 9], 'Post-ACK Firefox S5 reps must be 5, 9');

    // Verify post-ACK offsets: between +34ms and +245ms
    for (const t of [...postAckChrome, ...postAckFirefox]) {
      const v4Syn = Math.min(...(t.connection_attempts || []).filter((a) => a.family === 'IPv4').map((a) => a.syn_time));
      const deltaMs = (v4Syn - t.primary_flow.final_ack_time) * 1000.0;
      assert.ok(deltaMs > 30.0 && deltaMs < 250.0, `Post-ACK delta ${deltaMs}ms must be within expected range`);
    }
  });

  test('24. S5 raw family offsets are NOT promoted to logical CAD', () => {
    const s5Chrome = computeCohortMetrics(bundle.trials, 'S5', 'google-chrome');
    assert.equal(s5Chrome.cadClassification, 'RAW_FAMILY_SYN_OFFSET');
    assert.equal(s5Chrome.isCadAssessed, false);
    assert.equal(s5Chrome.cadMedian, null);
    assert.ok(Math.abs(s5Chrome.rawFamilySynOffsetMedian - 300.96) < 0.05);

    const s5Firefox = computeCohortMetrics(bundle.trials, 'S5', 'firefox');
    assert.equal(s5Firefox.cadClassification, 'RAW_FAMILY_SYN_OFFSET');
    assert.equal(s5Firefox.isCadAssessed, false);
    assert.equal(s5Firefox.cadMedian, null);
    assert.ok(Math.abs(s5Firefox.rawFamilySynOffsetMedian - 392.86) < 0.05);
  });

  test('25. S2 CAD remains qualified as NOT_ASSESSED per RFC 8305 Section 5', () => {
    const s2Chrome = computeCohortMetrics(bundle.trials, 'S2', 'google-chrome');
    assert.equal(s2Chrome.cadClassification, 'NOT_ASSESSED');
    assert.equal(s2Chrome.isCadAssessed, false);
    assert.equal(s2Chrome.cadMedian, null);
    assert.ok(Math.abs(s2Chrome.rawFamilySynOffsetMedian - 0.71) < 0.05);

    const s2Firefox = computeCohortMetrics(bundle.trials, 'S2', 'firefox');
    assert.equal(s2Firefox.cadClassification, 'NOT_ASSESSED');
    assert.equal(s2Firefox.isCadAssessed, false);
    assert.equal(s2Firefox.cadMedian, null);
    assert.ok(Math.abs(s2Firefox.rawFamilySynOffsetMedian - 160.43) < 0.05);
  });

  test('26. S1 CAD summary reconciliation with authoritative historical records', () => {
    const s1Chrome = computeCohortMetrics(bundle.trials, 'S1', 'google-chrome');
    const s1Firefox = computeCohortMetrics(bundle.trials, 'S1', 'firefox');

    // Chrome cohort sample median: 300.83 ms
    assert.ok(
      Math.abs(s1Chrome.cadMedian - 300.83) < 0.05,
      `Chrome S1 median must be 300.83 ms (got ${s1Chrome.cadMedian})`
    );

    // Firefox cohort sample median: 408.46 ms
    assert.ok(
      Math.abs(s1Firefox.cadMedian - 408.46) < 0.05,
      `Firefox S1 median must be 408.46 ms (got ${s1Firefox.cadMedian})`
    );

    // Pooled median across all 40 trials: 342.155 ms
    const s1Trials = bundle.trials.filter((t) => t.scenario_id === 'S1');
    const pooledCadVals = s1Trials.map((t) => t.metrics?.connection_attempt_delay_ms);
    const pooledMedian = computeMedian(pooledCadVals);
    assert.ok(
      Math.abs(pooledMedian - 342.155) < 0.01,
      `S1 pooled median must be 342.155 ms (got ${pooledMedian})`
    );
  });

  test('27. S5 PCAP stream analysis and zero SYN retransmissions', () => {
    const s5Trials = bundle.trials.filter((t) => t.scenario_id === 'S5');
    assert.equal(s5Trials.length, 40, 'Scenario S5 must contain exactly 40 trials');

    let v6Wins = 0;
    let v4Wins = 0;

    for (const trial of s5Trials) {
      assert.equal(
        trial.metrics?.retransmitted_syn_count_ipv6,
        0,
        `Trial ${trial.trial_id} had IPv6 SYN retransmissions`
      );
      assert.equal(
        trial.metrics?.retransmitted_syn_count_ipv4,
        0,
        `Trial ${trial.trial_id} had IPv4 SYN retransmissions`
      );

      const winner = (trial.primary_flow?.winning_family || '').toLowerCase();
      if (winner === 'ipv6') v6Wins++;
      else if (winner === 'ipv4') v4Wins++;
    }

    // Neutral observation: IPv6 was primary winning family in 33 of 40 trials
    assert.equal(v6Wins, 33, 'IPv6 must be the winning family in 33 of 40 S5 trials');
    assert.equal(v4Wins, 7, 'IPv4 must be the winning family in 7 of 40 S5 trials');
  });

  test('28. Stream-level attempt audit for S1 and S4 confirms PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET', () => {
    const s1Chrome = bundle.trials.filter((t) => t.scenario_id === 'S1' && t.browser === 'google-chrome');
    const s1Firefox = bundle.trials.filter((t) => t.scenario_id === 'S1' && t.browser === 'firefox');
    const s4Chrome = bundle.trials.filter((t) => t.scenario_id === 'S4' && t.browser === 'google-chrome');
    const s4Firefox = bundle.trials.filter((t) => t.scenario_id === 'S4' && t.browser === 'firefox');

    // S1 Chrome: 20 trials, each with 5 streams (3 IPv6, 2 IPv4)
    for (const t of s1Chrome) {
      assert.equal(t.connection_attempts?.length, 5);
      const v6 = t.connection_attempts.filter((a) => a.family === 'IPv6');
      const v4 = t.connection_attempts.filter((a) => a.family === 'IPv4');
      assert.equal(v6.length, 3);
      assert.equal(v4.length, 2);
    }

    // S1 Firefox: 20 trials, each with 3 streams (2 IPv6, 1 IPv4)
    for (const t of s1Firefox) {
      assert.equal(t.connection_attempts?.length, 3);
      const v6 = t.connection_attempts.filter((a) => a.family === 'IPv6');
      const v4 = t.connection_attempts.filter((a) => a.family === 'IPv4');
      assert.equal(v6.length, 2);
      assert.equal(v4.length, 1);
    }

    // S4 Chrome: 20 trials, each with 5 streams (3 IPv6, 2 IPv4)
    for (const t of s4Chrome) {
      assert.equal(t.connection_attempts?.length, 5);
      const v6 = t.connection_attempts.filter((a) => a.family === 'IPv6');
      const v4 = t.connection_attempts.filter((a) => a.family === 'IPv4');
      assert.equal(v6.length, 3);
      assert.equal(v4.length, 2);
    }

    // S4 Firefox: 19 trials with 3 streams (2 IPv6, 1 IPv4) and 1 trial with 2 streams (2 IPv6, 0 IPv4)
    const s4FfDual = s4Firefox.filter((t) => t.repetition !== 10);
    const s4FfRep10 = s4Firefox.find((t) => t.repetition === 10);

    assert.equal(s4FfDual.length, 19);
    for (const t of s4FfDual) {
      assert.equal(t.connection_attempts?.length, 3);
      const v6 = t.connection_attempts.filter((a) => a.family === 'IPv6');
      const v4 = t.connection_attempts.filter((a) => a.family === 'IPv4');
      assert.equal(v6.length, 2);
      assert.equal(v4.length, 1);
      // Stream 0 completed as ESTABLISHED_ANCILLARY, Stream 2 as ESTABLISHED_PRIMARY
      assert.equal(t.primary_flow?.winning_family?.toLowerCase(), 'ipv4');
    }

    assert.ok(s4FfRep10);
    assert.equal(s4FfRep10.connection_attempts?.length, 2);
    assert.equal(s4FfRep10.connection_attempts.filter((a) => a.family === 'IPv4').length, 0);
    assert.equal(s4FfRep10.primary_flow?.winning_family?.toLowerCase(), 'ipv6');
    assert.equal(s4FfRep10.metrics?.connection_attempt_delay_ms, null);
  });

  test('29. S5 invariant strict flow counting (no summary fallback false pass)', () => {
    // 1. Valid bundle with 95 underlying flows
    const normalChecks = validateCampaignInvariants(bundle);
    const s5Normal = normalChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.ok(s5Normal, 'S5 invariant check must exist');
    assert.equal(s5Normal.actual, 95);
    assert.equal(s5Normal.passed, true);

    // 2. Mock bundle with fewer than 95 flows (e.g. 94)
    const mockFewer = JSON.parse(JSON.stringify(bundle));
    const s5TrialFewer = mockFewer.trials.find((t) => t.scenario_id === 'S5' && t.s5_flow_dissection?.length > 0);
    s5TrialFewer.s5_flow_dissection.pop();
    const fewerChecks = validateCampaignInvariants(mockFewer);
    const s5Fewer = fewerChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.equal(s5Fewer.actual, 94);
    assert.equal(s5Fewer.passed, false, 'Fewer than 95 flows must FAIL');

    // 3. Mock bundle with more than 95 flows (e.g. 96)
    const mockMore = JSON.parse(JSON.stringify(bundle));
    const s5TrialMore = mockMore.trials.find((t) => t.scenario_id === 'S5' && t.s5_flow_dissection?.length > 0);
    s5TrialMore.s5_flow_dissection.push({ ...s5TrialMore.s5_flow_dissection[0] });
    const moreChecks = validateCampaignInvariants(mockMore);
    const s5More = moreChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.equal(s5More.actual, 96);
    assert.equal(s5More.passed, false, 'More than 95 flows must FAIL');

    // 4. Mock bundle with empty S5 flow data
    const mockEmpty = JSON.parse(JSON.stringify(bundle));
    for (const t of mockEmpty.trials) {
      if (t.scenario_id === 'S5') t.s5_flow_dissection = [];
    }
    const emptyChecks = validateCampaignInvariants(mockEmpty);
    const s5Empty = emptyChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.equal(s5Empty.actual, 0);
    assert.equal(s5Empty.passed, false, 'Empty S5 flows must FAIL');

    // 5. Mock bundle with missing S5 flow data property
    const mockMissing = JSON.parse(JSON.stringify(bundle));
    for (const t of mockMissing.trials) {
      if (t.scenario_id === 'S5') delete t.s5_flow_dissection;
    }
    const missingChecks = validateCampaignInvariants(mockMissing);
    const s5Missing = missingChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.equal(s5Missing.actual, 0);
    assert.equal(s5Missing.passed, false, 'Missing S5 flow property must FAIL');

    // 6. Mock bundle missing reconciliation summary but with 95 underlying flows
    const mockNoSummary = JSON.parse(JSON.stringify(bundle));
    delete mockNoSummary.reconciliation_summary;
    const noSummaryChecks = validateCampaignInvariants(mockNoSummary);
    const s5NoSummary = noSummaryChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.equal(s5NoSummary.actual, 95);
    assert.equal(s5NoSummary.passed, true, 'Underlying 95 flows must pass even without reconciliation summary');

    // 7. CRITICAL AUDIT CASE: Reconciliation summary claims 95 while underlying dataset is empty
    const mockDeceptive = JSON.parse(JSON.stringify(bundle));
    mockDeceptive.reconciliation_summary = { s5_flows_count: 95 };
    for (const t of mockDeceptive.trials) {
      if (t.scenario_id === 'S5') t.s5_flow_dissection = [];
    }
    const deceptiveChecks = validateCampaignInvariants(mockDeceptive);
    const s5Deceptive = deceptiveChecks.find((c) => c.name === 'S5 HTTP/1.1 Subflows');
    assert.equal(s5Deceptive.actual, 0);
    assert.equal(s5Deceptive.passed, false, 'Summary fallback must NEVER manufacture a pass when underlying flows are empty');
  });

  test('30. Cryptographic evidence integrity evaluation states and fail-safe policy', () => {
    const validHash = provenance.output_bundle_sha256;
    const invalidHash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    // 1. Matching bundle and sidecar
    const resMatched = evaluateEvidenceIntegrity(validHash, provenance);
    assert.equal(resMatched.status, 'HASH_MATCHED');
    assert.equal(resMatched.isHashMatched, true);
    assert.equal(resMatched.isAuthenticityEstablished, false, 'Same-origin hash match must NOT claim independent authenticity');
    assert.equal(resMatched.statusLabel, 'Digest Consistent (Same-Origin)');

    // 2. Mismatching digest
    const resMismatch = evaluateEvidenceIntegrity(invalidHash, provenance);
    assert.equal(resMismatch.status, 'HASH_MISMATCHED');
    assert.equal(resMismatch.isHashMatched, false);
    assert.equal(resMismatch.isAuthenticityEstablished, false);
    assert.equal(resMismatch.statusLabel, 'Hash Mismatch (Unverified)');

    // 3. Missing sidecar
    const resNoSidecar = evaluateEvidenceIntegrity(validHash, null);
    assert.equal(resNoSidecar.status, 'HASH_UNAVAILABLE');
    assert.equal(resNoSidecar.isHashMatched, false);

    // 4. Missing computed hash
    const resNoComputed = evaluateEvidenceIntegrity(null, provenance);
    assert.equal(resNoComputed.status, 'HASH_UNAVAILABLE');
    assert.equal(resNoComputed.isHashMatched, false);

    // 5. Missing expected hash in sidecar
    const emptySidecar = { ...provenance, output_bundle_sha256: '' };
    const resEmptySidecar = evaluateEvidenceIntegrity(validHash, emptySidecar);
    assert.equal(resEmptySidecar.status, 'HASH_UNAVAILABLE');
    assert.equal(resEmptySidecar.isHashMatched, false);
  });

  test('31. Event-level packet provenance preservation in bundle timeline events', () => {
    // 1. Inspect trials in bundle to confirm event_index, frame_number, pcap_sha256, source_path exist on PCAP events
    let pcapEventsChecked = 0;
    let nonPcapEventsChecked = 0;
    for (const trial of bundle.trials) {
      for (const ev of trial.timeline_events || []) {
        if (ev.source === 'PCAP') {
          pcapEventsChecked++;
          assert.ok(typeof ev.event_index === 'number', `Event index must be number for ${trial.trial_id}`);
          assert.ok(typeof ev.frame_number === 'number', `Frame number must be number for ${trial.trial_id}`);
          assert.match(ev.pcap_sha256, /^[0-9a-f]{64}$/, `PCAP hash must be 64-char hex for ${trial.trial_id}`);
          assert.ok(typeof ev.source_path === 'string' && ev.source_path.length > 0, `Source path must exist for ${trial.trial_id}`);
        } else {
          nonPcapEventsChecked++;
          assert.ok(typeof ev.event_index === 'number', `Non-PCAP event index must be number for ${trial.trial_id}`);
          assert.strictEqual(ev.frame_number, null, `Non-PCAP frame_number must legitimately remain null for ${trial.trial_id}`);
        }
      }
    }
    assert.ok(pcapEventsChecked > 0, 'Must have verified PCAP events with packet-level provenance');
    assert.ok(nonPcapEventsChecked > 0, 'Must have verified non-PCAP events with legitimate null frame_number');

    // 2. Direct CSV-to-bundle value comparison for sample trial
    const sampleTrial = bundle.trials.find((t) => t.trial_id === 'trial-20261029205425-6cb90a54');
    assert.ok(sampleTrial, 'Sample trial must exist in bundle');
    const pcapEv = sampleTrial.timeline_events.find((e) => e.source === 'PCAP' && e.frame_number === 102);
    assert.ok(pcapEv, 'PCAP frame 102 must exist in sample trial');
    assert.strictEqual(pcapEv.event_index, 86);
    assert.strictEqual(pcapEv.frame_number, 102);
    assert.strictEqual(pcapEv.pcap_sha256, '69fd09eb63b53f2be42428e40d99ed61eeef4da47bead93fe129ecab1ba47f72');
    assert.strictEqual(pcapEv.source_path, 'lab/campaigns/ps028-a10-live-20261030-01/trials/trial-20261029205425-6cb90a54/capture.pcap');

    const harnessEv = sampleTrial.timeline_events.find((e) => e.source === 'HARNESS' && e.event_index === 1);
    assert.ok(harnessEv, 'HARNESS event 1 must exist in sample trial');
    assert.strictEqual(harnessEv.event_index, 1);
    assert.strictEqual(harnessEv.frame_number, null);
    assert.strictEqual(harnessEv.source_path, 'lab/campaigns/ps028-a10-live-20261030-01/trials/trial-20261029205425-6cb90a54/result.json');
  });
});
