/**
 * Statistical Calculations and Aggregations for PS-028 Scenario Analytics
 *
 * Strictly adheres to empirical integrity rules:
 * - Never fabricates measurements
 * - Excluded attempts are never included in calculations
 * - Missing measurements are treated as null, NEVER as zero
 * - Correct mathematical quartiles and medians
 */

import type { HistoricalTrial } from '../historical-evidence.ts';
import { computeMedian } from '../historical-evidence.ts';
import type {
  SupportedMetricKey,
  BoxPlotStats,
  ScenarioCohortAggregates,
  BrowserFilterId,
  OverallSummaryStats,
} from './analytics-types';

/**
 * Computes quartile statistics and box-and-whisker metrics from numeric samples.
 * Uses standard Tukey box plot method with 1.5 * IQR outlier fences.
 */
export function computeBoxPlotStats(values: (number | null | undefined)[]): BoxPlotStats | null {
  const clean = values.filter(
    (v): v is number => typeof v === 'number' && !isNaN(v) && isFinite(v)
  );

  if (clean.length === 0) return null;

  clean.sort((a, b) => a - b);
  const n = clean.length;

  const getPercentile = (p: number): number => {
    if (n === 1) return clean[0]!;
    const index = p * (n - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    const weight = index - lower;
    return clean[lower]! * (1 - weight) + clean[upper]! * weight;
  };

  const minVal = clean[0]!;
  const maxVal = clean[n - 1]!;
  const q1 = getPercentile(0.25);
  const median = getPercentile(0.5);
  const q3 = getPercentile(0.75);
  const iqr = q3 - q1;

  const lowerFence = q1 - 1.5 * iqr;
  const upperFence = q3 + 1.5 * iqr;

  const outliers: number[] = [];
  const nonOutliers: number[] = [];

  for (const v of clean) {
    if (v < lowerFence || v > upperFence) {
      outliers.push(v);
    } else {
      nonOutliers.push(v);
    }
  }

  // Whisker bounds to highest/lowest non-outlier data points
  const whiskerMin = nonOutliers.length > 0 ? nonOutliers[0]! : minVal;
  const whiskerMax = nonOutliers.length > 0 ? nonOutliers[nonOutliers.length - 1]! : maxVal;

  const sum = clean.reduce((acc, v) => acc + v, 0);
  const mean = sum / n;

  return {
    min: whiskerMin,
    q1,
    median,
    q3,
    max: whiskerMax,
    mean,
    iqr,
    outliers,
    sampleSize: n,
  };
}

/**
 * Extracts a specific metric value from a trial record, returning null if missing or excluded.
 */
export function getTrialMetricValue(
  trial: HistoricalTrial,
  metric: SupportedMetricKey
): number | null {
  if (trial.validity_category !== 'VALID_LIVE') return null;
  const m = trial.metrics;
  if (!m) return null;

  switch (metric) {
    case 't_connect_ms':
      return typeof m.t_connect_ms === 'number' ? m.t_connect_ms : null;
    case 't_setup_total_ms':
      return typeof m.t_setup_total_ms === 'number' ? m.t_setup_total_ms : null;
    case 'dns_resolution_time_ms':
      return typeof m.dns_resolution_time_ms === 'number' ? m.dns_resolution_time_ms : null;
    case 'dns_latency_a_ms':
      return typeof m.dns_latency_a_ms === 'number' ? m.dns_latency_a_ms : null;
    case 'dns_latency_aaaa_ms':
      return typeof m.dns_latency_aaaa_ms === 'number' ? m.dns_latency_aaaa_ms : null;
    case 'dns_query_to_first_payload_ms':
      return typeof m.dns_query_to_first_payload_ms === 'number' ? m.dns_query_to_first_payload_ms : null;
    case 'retransmitted_syn_count_ipv4':
      return typeof m.retransmitted_syn_count_ipv4 === 'number' ? m.retransmitted_syn_count_ipv4 : null;
    case 'retransmitted_syn_count_ipv6':
      return typeof m.retransmitted_syn_count_ipv6 === 'number' ? m.retransmitted_syn_count_ipv6 : null;
    default:
      return null;
  }
}

/**
 * Computes scenario cohort statistics for a specific scenario and browser cohort.
 */
export function computeScenarioCohortAggregates(
  trials: HistoricalTrial[],
  scenarioId: string,
  browserId: string
): ScenarioCohortAggregates {
  const cohortTrials = trials.filter(
    (t) =>
      t.scenario_id === scenarioId &&
      (browserId === 'ALL' || t.browser === browserId) &&
      t.validity_category === 'VALID_LIVE'
  );

  let ipv6Wins = 0;
  let ipv4Wins = 0;
  let retransIpv4Total = 0;
  let retransIpv6Total = 0;

  for (const t of cohortTrials) {
    const winner = (t.primary_flow?.winning_family || t.primary_flow?.family || '').toLowerCase();
    if (winner === 'ipv6') ipv6Wins++;
    else if (winner === 'ipv4') ipv4Wins++;

    if (typeof t.metrics?.retransmitted_syn_count_ipv4 === 'number') {
      retransIpv4Total += t.metrics.retransmitted_syn_count_ipv4;
    }
    if (typeof t.metrics?.retransmitted_syn_count_ipv6 === 'number') {
      retransIpv6Total += t.metrics.retransmitted_syn_count_ipv6;
    }
  }

  const metricKeys: SupportedMetricKey[] = [
    't_connect_ms',
    't_setup_total_ms',
    'dns_resolution_time_ms',
    'dns_latency_a_ms',
    'dns_latency_aaaa_ms',
    'dns_query_to_first_payload_ms',
    'retransmitted_syn_count_ipv4',
    'retransmitted_syn_count_ipv6',
  ];

  const metricStats = {} as Record<SupportedMetricKey, BoxPlotStats | null>;
  for (const k of metricKeys) {
    const vals = cohortTrials.map((t) => getTrialMetricValue(t, k));
    metricStats[k] = computeBoxPlotStats(vals);
  }

  const n = cohortTrials.length;

  return {
    scenarioId,
    browserId,
    sampleSize: n,
    tConnectMedian: metricStats.t_connect_ms?.median ?? null,
    tSetupTotalMedian: metricStats.t_setup_total_ms?.median ?? null,
    dnsResolutionMedian: metricStats.dns_resolution_time_ms?.median ?? null,
    dnsAMedian: metricStats.dns_latency_a_ms?.median ?? null,
    dnsAAAAMedian: metricStats.dns_latency_aaaa_ms?.median ?? null,
    dnsPayloadMedian: metricStats.dns_query_to_first_payload_ms?.median ?? null,
    ipv6Wins,
    ipv4Wins,
    retransIpv4Total,
    retransIpv6Total,
    retransIpv4Mean: n > 0 ? retransIpv4Total / n : 0,
    retransIpv6Mean: n > 0 ? retransIpv6Total / n : 0,
    metricStats,
  };
}

/**
 * Computes high-level aggregated summary across selected scenarios and browser filter.
 */
export function computeOverallSummary(
  allTrials: HistoricalTrial[],
  selectedScenarios: string[],
  browserFilter: BrowserFilterId
): OverallSummaryStats {
  const activeTrials = allTrials.filter(
    (t) =>
      selectedScenarios.includes(t.scenario_id) &&
      (browserFilter === 'ALL' || t.browser === browserFilter) &&
      t.validity_category === 'VALID_LIVE'
  );

  const chromeCount = activeTrials.filter((t) => t.browser === 'google-chrome').length;
  const firefoxCount = activeTrials.filter((t) => t.browser === 'firefox').length;

  const tConnectVals = activeTrials.map((t) => getTrialMetricValue(t, 't_connect_ms'));
  const tSetupVals = activeTrials.map((t) => getTrialMetricValue(t, 't_setup_total_ms'));
  const dnsResVals = activeTrials.map((t) => getTrialMetricValue(t, 'dns_resolution_time_ms'));
  const dnsAVals = activeTrials.map((t) => getTrialMetricValue(t, 'dns_latency_a_ms'));
  const dnsAAAAVals = activeTrials.map((t) => getTrialMetricValue(t, 'dns_latency_aaaa_ms'));

  let ipv4Wins = 0;
  let ipv6Wins = 0;
  let retransIpv4Total = 0;
  let retransIpv6Total = 0;

  for (const t of activeTrials) {
    const winner = (t.primary_flow?.winning_family || t.primary_flow?.family || '').toLowerCase();
    if (winner === 'ipv4') ipv4Wins++;
    else if (winner === 'ipv6') ipv6Wins++;

    if (typeof t.metrics?.retransmitted_syn_count_ipv4 === 'number') {
      retransIpv4Total += t.metrics.retransmitted_syn_count_ipv4;
    }
    if (typeof t.metrics?.retransmitted_syn_count_ipv6 === 'number') {
      retransIpv6Total += t.metrics.retransmitted_syn_count_ipv6;
    }
  }

  const totalWins = ipv4Wins + ipv6Wins;
  const ipv4WinPercentage = totalWins > 0 ? (ipv4Wins / totalWins) * 100 : null;
  const ipv6WinPercentage = totalWins > 0 ? (ipv6Wins / totalWins) * 100 : null;

  // Baseline S0 comparisons
  const s0Trials = allTrials.filter(
    (t) =>
      t.scenario_id === 'S0' &&
      (browserFilter === 'ALL' || t.browser === browserFilter) &&
      t.validity_category === 'VALID_LIVE'
  );

  let baselineComparison: OverallSummaryStats['baselineComparison'];

  if (s0Trials.length > 0) {
    const s0TConnect = computeMedian(s0Trials.map((t) => getTrialMetricValue(t, 't_connect_ms')));
    const s0TSetup = computeMedian(s0Trials.map((t) => getTrialMetricValue(t, 't_setup_total_ms')));
    const curTConnect = computeMedian(tConnectVals);
    const curTSetup = computeMedian(tSetupVals);

    baselineComparison = {
      s0TConnectMedian: s0TConnect,
      s0TSetupMedian: s0TSetup,
      tConnectDeltaMs:
        typeof curTConnect === 'number' && typeof s0TConnect === 'number'
          ? curTConnect - s0TConnect
          : null,
      tSetupDeltaMs:
        typeof curTSetup === 'number' && typeof s0TSetup === 'number'
          ? curTSetup - s0TSetup
          : null,
    };
  }

  return {
    selectedScenariosCount: selectedScenarios.length,
    validTrialsCount: activeTrials.length,
    chromeTrialsCount: chromeCount,
    firefoxTrialsCount: firefoxCount,
    tConnectMedian: computeMedian(tConnectVals),
    tSetupTotalMedian: computeMedian(tSetupVals),
    ipv4WinCount: ipv4Wins,
    ipv6WinCount: ipv6Wins,
    ipv4WinPercentage,
    ipv6WinPercentage,
    dnsResolutionMedian: computeMedian(dnsResVals),
    dnsAMedian: computeMedian(dnsAVals),
    dnsAAAAMedian: computeMedian(dnsAAAAVals),
    retransIpv4Total,
    retransIpv6Total,
    baselineComparison,
  };
}
