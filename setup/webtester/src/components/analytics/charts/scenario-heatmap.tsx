import React, { useState } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { SupportedMetricKey } from '@/lib/analytics/analytics-types';
import { SUPPORTED_METRICS } from '@/lib/analytics/analytics-types';
import { computeMedian } from '@/lib/historical-evidence';
import { getTrialMetricValue } from '@/lib/analytics/analytics-calculations';
import { SCENARIO_METADATA } from '@/lib/analytics/analytics-filters';

interface ScenarioHeatmapProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalMetric: SupportedMetricKey;
}

export const ScenarioHeatmap: React.FC<ScenarioHeatmapProps> = ({
  trials,
  globalScenarios,
  globalMetric,
}) => {
  const [localMetric, setLocalMetric] = useState<SupportedMetricKey | 'INHERIT'>('INHERIT');
  const [hoveredCell, setHoveredCell] = useState<{
    scenario: string;
    scenarioName: string;
    column: string;
    val: number | null;
    sampleSize: number;
  } | null>(null);

  const effectiveMetric = localMetric === 'INHERIT' ? globalMetric : localMetric;
  const metricDef = SUPPORTED_METRICS[effectiveMetric] || SUPPORTED_METRICS.t_connect_ms;
  const scenarios = globalScenarios;

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold">Graph 6 — Scenario Performance Heatmap</CardTitle>
          <CardDescription>Select at least one scenario to display heatmap matrix.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-muted-foreground border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  // Calculate cell values for each row (scenario) and columns (Chrome, Firefox, Overall)
  const rows = scenarios.map((scId) => {
    const meta = SCENARIO_METADATA[scId];
    const chromeTrials = trials.filter(
      (t) => t.scenario_id === scId && t.browser === 'google-chrome' && t.validity_category === 'VALID_LIVE'
    );
    const firefoxTrials = trials.filter(
      (t) => t.scenario_id === scId && t.browser === 'firefox' && t.validity_category === 'VALID_LIVE'
    );
    const allTrials = trials.filter(
      (t) => t.scenario_id === scId && t.validity_category === 'VALID_LIVE'
    );

    const chromeVals = chromeTrials.map((t) => getTrialMetricValue(t, effectiveMetric));
    const firefoxVals = firefoxTrials.map((t) => getTrialMetricValue(t, effectiveMetric));
    const allVals = allTrials.map((t) => getTrialMetricValue(t, effectiveMetric));

    return {
      scenarioId: scId,
      scenarioName: meta?.name || scId,
      chrome: {
        val: computeMedian(chromeVals),
        sampleSize: chromeTrials.length,
      },
      firefox: {
        val: computeMedian(firefoxVals),
        sampleSize: firefoxTrials.length,
      },
      overall: {
        val: computeMedian(allVals),
        sampleSize: allTrials.length,
      },
    };
  });

  // Calculate global min and max for color intensity
  const allNumericVals = rows
    .flatMap((r) => [r.chrome.val, r.firefox.val, r.overall.val])
    .filter((v): v is number => typeof v === 'number');

  const minVal = allNumericVals.length > 0 ? Math.min(...allNumericVals) : 0;
  const maxVal = allNumericVals.length > 0 ? Math.max(...allNumericVals) : 100;

  const getCellBgColor = (val: number | null) => {
    if (val === null) return 'bg-muted/30 text-muted-foreground';
    if (maxVal === minVal) return 'bg-primary/20 text-foreground';

    const ratio = Math.max(0, Math.min(1, (val - minVal) / (maxVal - minVal)));

    // Progressive teal/emerald color scale from light to deep
    if (ratio < 0.2) return 'bg-emerald-50 dark:bg-emerald-950/30 text-emerald-900 dark:text-emerald-200';
    if (ratio < 0.4) return 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-950 dark:text-emerald-100 font-medium';
    if (ratio < 0.6) return 'bg-emerald-200 dark:bg-emerald-800/50 text-emerald-950 dark:text-emerald-50 font-semibold';
    if (ratio < 0.8) return 'bg-emerald-300 dark:bg-emerald-700/60 text-emerald-950 dark:text-white font-bold';
    return 'bg-emerald-400 dark:bg-emerald-600/70 text-emerald-950 dark:text-white font-black';
  };

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-foreground">
              Graph 6 — Scenario Performance Heatmap
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground mt-0.5">
              Cross-cohort performance matrix by scenario and browser cohort for {metricDef.label}.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex items-center gap-2 text-xs">
            <select
              value={localMetric}
              onChange={(e) => setLocalMetric(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-foreground"
              aria-label="Filter metric for Heatmap"
            >
              <option value="INHERIT">Metric: Auto</option>
              <option value="t_connect_ms">t_connect (ms)</option>
              <option value="t_setup_total_ms">t_setup_total (ms)</option>
              <option value="dns_resolution_time_ms">DNS Resolution (ms)</option>
              <option value="dns_latency_aaaa_ms">AAAA Latency (ms)</option>
              <option value="dns_latency_a_ms">A Latency (ms)</option>
              <option value="dns_query_to_first_payload_ms">DNS to Payload (ms)</option>
            </select>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-4">
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left border-collapse">
            <thead>
              <tr className="border-b bg-muted/30 text-muted-foreground">
                <th className="p-2.5 font-semibold">Scenario</th>
                <th className="p-2.5 font-semibold text-center w-36">Google Chrome</th>
                <th className="p-2.5 font-semibold text-center w-36">Mozilla Firefox</th>
                <th className="p-2.5 font-semibold text-center w-36">Combined Cohort</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {rows.map((r) => (
                <tr key={r.scenarioId} className="hover:bg-muted/20 transition-colors">
                  <td className="p-2.5">
                    <div className="font-bold text-foreground flex items-center gap-1.5">
                      <span className="size-2 rounded-full bg-primary" />
                      {r.scenarioId}
                    </div>
                    <div className="text-[11px] text-muted-foreground line-clamp-1">{r.scenarioName}</div>
                  </td>

                  {/* Chrome Cell */}
                  <td
                    className={`p-2.5 text-center font-mono cursor-pointer transition-all ${getCellBgColor(
                      r.chrome.val
                    )}`}
                    onMouseEnter={() =>
                      setHoveredCell({
                        scenario: r.scenarioId,
                        scenarioName: r.scenarioName,
                        column: 'Google Chrome',
                        val: r.chrome.val,
                        sampleSize: r.chrome.sampleSize,
                      })
                    }
                    onMouseLeave={() => setHoveredCell(null)}
                  >
                    {r.chrome.val !== null ? `${r.chrome.val.toFixed(2)} ${metricDef.unit}` : '—'}
                  </td>

                  {/* Firefox Cell */}
                  <td
                    className={`p-2.5 text-center font-mono cursor-pointer transition-all ${getCellBgColor(
                      r.firefox.val
                    )}`}
                    onMouseEnter={() =>
                      setHoveredCell({
                        scenario: r.scenarioId,
                        scenarioName: r.scenarioName,
                        column: 'Mozilla Firefox',
                        val: r.firefox.val,
                        sampleSize: r.firefox.sampleSize,
                      })
                    }
                    onMouseLeave={() => setHoveredCell(null)}
                  >
                    {r.firefox.val !== null ? `${r.firefox.val.toFixed(2)} ${metricDef.unit}` : '—'}
                  </td>

                  {/* Overall Cell */}
                  <td
                    className={`p-2.5 text-center font-mono cursor-pointer transition-all ${getCellBgColor(
                      r.overall.val
                    )}`}
                    onMouseEnter={() =>
                      setHoveredCell({
                        scenario: r.scenarioId,
                        scenarioName: r.scenarioName,
                        column: 'Combined Cohort',
                        val: r.overall.val,
                        sampleSize: r.overall.sampleSize,
                      })
                    }
                    onMouseLeave={() => setHoveredCell(null)}
                  >
                    {r.overall.val !== null ? `${r.overall.val.toFixed(2)} ${metricDef.unit}` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Heatmap Legend */}
        <div className="flex flex-wrap items-center justify-between gap-2 mt-3 pt-2 border-t text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px]">Intensity Scale:</span>
            <div className="flex items-center gap-0.5">
              <span className="w-5 h-3.5 rounded-xs bg-emerald-50 dark:bg-emerald-950/30 border" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-100 dark:bg-emerald-900/40" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-200 dark:bg-emerald-800/50" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-300 dark:bg-emerald-700/60" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-400 dark:bg-emerald-600/70" />
            </div>
            <span className="font-mono text-[10px] ml-1">
              {minVal.toFixed(1)} &rarr; {maxVal.toFixed(1)} {metricDef.unit}
            </span>
          </div>

          <div className="text-[11px]">
            Values represent median measurements &bull; Missing data marked with &lsquo;—&rsquo;
          </div>
        </div>

        {/* Floating Tooltip */}
        {hoveredCell && (
          <div className="p-2 rounded bg-popover text-popover-foreground border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold">
              {hoveredCell.scenario} ({hoveredCell.scenarioName}) &bull; {hoveredCell.column}:
            </span>
            <span className="font-mono ml-2 font-bold text-primary">
              {hoveredCell.val !== null ? `${hoveredCell.val.toFixed(2)} ${metricDef.unit}` : 'Unavailable'}{' '}
              <span className="text-muted-foreground font-sans font-normal">(n={hoveredCell.sampleSize})</span>
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
