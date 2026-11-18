import React, { useState, useEffect } from 'react';
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

interface SelectedHeatmapEntry {
  scenarioId: string;
  scenarioName: string;
  column: 'Google Chrome' | 'Mozilla Firefox' | 'Combined Cohort';
  val: number | null;
  sampleSize: number;
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

  const [selectedEntry, setSelectedEntry] = useState<SelectedHeatmapEntry | null>(null);

  const effectiveMetric = localMetric === 'INHERIT' ? globalMetric : localMetric;
  const metricDef = SUPPORTED_METRICS[effectiveMetric] || SUPPORTED_METRICS.t_connect_ms;
  const scenarios = globalScenarios;

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

  // Reconcile or clear selection when filters change
  useEffect(() => {
    if (!selectedEntry) return;
    if (!scenarios.includes(selectedEntry.scenarioId)) {
      setSelectedEntry(null);
      return;
    }
    const currentRow = rows.find((r) => r.scenarioId === selectedEntry.scenarioId);
    if (!currentRow) {
      setSelectedEntry(null);
      return;
    }
    const val =
      selectedEntry.column === 'Google Chrome'
        ? currentRow.chrome.val
        : selectedEntry.column === 'Mozilla Firefox'
        ? currentRow.firefox.val
        : currentRow.overall.val;
    const sampleSize =
      selectedEntry.column === 'Google Chrome'
        ? currentRow.chrome.sampleSize
        : selectedEntry.column === 'Mozilla Firefox'
        ? currentRow.firefox.sampleSize
        : currentRow.overall.sampleSize;

    setSelectedEntry((prev) =>
      prev
        ? {
            ...prev,
            scenarioName: currentRow.scenarioName,
            val,
            sampleSize,
          }
        : null
    );
  }, [scenarios, effectiveMetric, trials]);

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold text-black">Graph 6 — Scenario Performance Heatmap</CardTitle>
          <CardDescription className="text-xs text-black">Select at least one scenario to display heatmap matrix.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-black border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  const handleCellSelect = (item: SelectedHeatmapEntry) => {
    if (
      selectedEntry &&
      selectedEntry.scenarioId === item.scenarioId &&
      selectedEntry.column === item.column
    ) {
      setSelectedEntry(null);
    } else {
      setSelectedEntry(item);
    }
  };

  // Find comparison row for active selection
  const comparisonRow = selectedEntry
    ? rows.find((r) => r.scenarioId === selectedEntry.scenarioId) || null
    : null;

  // Calculate global min and max for color intensity
  const allNumericVals = rows
    .flatMap((r) => [r.chrome.val, r.firefox.val, r.overall.val])
    .filter((v): v is number => typeof v === 'number');

  const minVal = allNumericVals.length > 0 ? Math.min(...allNumericVals) : 0;
  const maxVal = allNumericVals.length > 0 ? Math.max(...allNumericVals) : 100;

  const getCellBgColor = (val: number | null) => {
    if (val === null) return 'bg-muted/30 text-black';
    if (maxVal === minVal) return 'bg-primary/20 text-black';

    const ratio = Math.max(0, Math.min(1, (val - minVal) / (maxVal - minVal)));

    // Progressive teal/emerald color scale from light to deep
    if (ratio < 0.2) return 'bg-emerald-50 dark:bg-emerald-950/30 text-black';
    if (ratio < 0.4) return 'bg-emerald-100 dark:bg-emerald-900/40 text-black font-medium';
    if (ratio < 0.6) return 'bg-emerald-200 dark:bg-emerald-800/50 text-black font-semibold';
    if (ratio < 0.8) return 'bg-emerald-300 dark:bg-emerald-700/60 text-black font-bold';
    return 'bg-emerald-400 dark:bg-emerald-600/70 text-black font-black';
  };

  const hasSelection = selectedEntry !== null;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-black">
              Graph 6 — Scenario Performance Heatmap
            </CardTitle>
            <CardDescription className="text-xs text-black mt-0.5">
              Cross-cohort performance matrix by scenario and browser cohort for {metricDef.label}.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex items-center gap-2 text-xs">
            <select
              value={localMetric}
              onChange={(e) => setLocalMetric(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
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
              <tr className="border-b bg-muted/30 text-black">
                <th className="p-2.5 font-semibold text-black">Scenario</th>
                <th className="p-2.5 font-semibold text-center w-36 text-black">Google Chrome</th>
                <th className="p-2.5 font-semibold text-center w-36 text-black">Mozilla Firefox</th>
                <th className="p-2.5 font-semibold text-center w-36 text-black">Combined Cohort</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {rows.map((r) => {
                const isChromeSelected =
                  selectedEntry?.scenarioId === r.scenarioId &&
                  selectedEntry?.column === 'Google Chrome';
                const isFirefoxSelected =
                  selectedEntry?.scenarioId === r.scenarioId &&
                  selectedEntry?.column === 'Mozilla Firefox';
                const isOverallSelected =
                  selectedEntry?.scenarioId === r.scenarioId &&
                  selectedEntry?.column === 'Combined Cohort';

                return (
                  <tr key={r.scenarioId} className="hover:bg-muted/20 transition-colors">
                    <td className="p-2.5">
                      <div className="font-bold text-black flex items-center gap-1.5">
                        <span className="size-2 rounded-full bg-primary" />
                        {r.scenarioId}
                      </div>
                      <div className="text-[11px] text-black line-clamp-1">{r.scenarioName}</div>
                    </td>

                    {/* Chrome Cell */}
                    <td
                      role="button"
                      tabIndex={0}
                      aria-pressed={isChromeSelected}
                      aria-label={`Select ${r.scenarioId} Google Chrome: ${r.chrome.val !== null ? `${r.chrome.val.toFixed(2)} ${metricDef.unit}` : 'Unavailable'}`}
                      className={`p-2.5 text-center font-mono cursor-pointer transition-all outline-none ${getCellBgColor(
                        r.chrome.val
                      )} ${
                        isChromeSelected
                          ? 'ring-2 ring-black ring-inset font-black shadow-inner scale-[0.98]'
                          : hasSelection
                          ? 'opacity-60 hover:opacity-100'
                          : ''
                      }`}
                      onClick={() =>
                        handleCellSelect({
                          scenarioId: r.scenarioId,
                          scenarioName: r.scenarioName,
                          column: 'Google Chrome',
                          val: r.chrome.val,
                          sampleSize: r.chrome.sampleSize,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleCellSelect({
                            scenarioId: r.scenarioId,
                            scenarioName: r.scenarioName,
                            column: 'Google Chrome',
                            val: r.chrome.val,
                            sampleSize: r.chrome.sampleSize,
                          });
                        }
                      }}
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
                      role="button"
                      tabIndex={0}
                      aria-pressed={isFirefoxSelected}
                      aria-label={`Select ${r.scenarioId} Mozilla Firefox: ${r.firefox.val !== null ? `${r.firefox.val.toFixed(2)} ${metricDef.unit}` : 'Unavailable'}`}
                      className={`p-2.5 text-center font-mono cursor-pointer transition-all outline-none ${getCellBgColor(
                        r.firefox.val
                      )} ${
                        isFirefoxSelected
                          ? 'ring-2 ring-black ring-inset font-black shadow-inner scale-[0.98]'
                          : hasSelection
                          ? 'opacity-60 hover:opacity-100'
                          : ''
                      }`}
                      onClick={() =>
                        handleCellSelect({
                          scenarioId: r.scenarioId,
                          scenarioName: r.scenarioName,
                          column: 'Mozilla Firefox',
                          val: r.firefox.val,
                          sampleSize: r.firefox.sampleSize,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleCellSelect({
                            scenarioId: r.scenarioId,
                            scenarioName: r.scenarioName,
                            column: 'Mozilla Firefox',
                            val: r.firefox.val,
                            sampleSize: r.firefox.sampleSize,
                          });
                        }
                      }}
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
                      role="button"
                      tabIndex={0}
                      aria-pressed={isOverallSelected}
                      aria-label={`Select ${r.scenarioId} Combined Cohort: ${r.overall.val !== null ? `${r.overall.val.toFixed(2)} ${metricDef.unit}` : 'Unavailable'}`}
                      className={`p-2.5 text-center font-mono cursor-pointer transition-all outline-none ${getCellBgColor(
                        r.overall.val
                      )} ${
                        isOverallSelected
                          ? 'ring-2 ring-black ring-inset font-black shadow-inner scale-[0.98]'
                          : hasSelection
                          ? 'opacity-60 hover:opacity-100'
                          : ''
                      }`}
                      onClick={() =>
                        handleCellSelect({
                          scenarioId: r.scenarioId,
                          scenarioName: r.scenarioName,
                          column: 'Combined Cohort',
                          val: r.overall.val,
                          sampleSize: r.overall.sampleSize,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleCellSelect({
                            scenarioId: r.scenarioId,
                            scenarioName: r.scenarioName,
                            column: 'Combined Cohort',
                            val: r.overall.val,
                            sampleSize: r.overall.sampleSize,
                          });
                        }
                      }}
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
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Selected Entry Detail Panel */}
        {selectedEntry && (
          <div
            data-testid="graph-6-selected-panel"
            className="mt-3 p-3 rounded-lg border-2 border-black/30 bg-muted/30 text-black text-xs space-y-2 animate-fade-in"
          >
            <div className="flex items-center justify-between border-b border-black/15 pb-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-black text-white">
                  Active Selection
                </span>
                <span className="font-bold text-black text-sm">
                  {selectedEntry.scenarioId} ({selectedEntry.scenarioName}) &bull; {selectedEntry.column}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEntry(null)}
                className="text-black hover:text-black/70 p-1 rounded hover:bg-black/10 cursor-pointer flex items-center gap-1 text-[11px] font-medium"
                aria-label="Dismiss selection"
                title="Dismiss selection"
              >
                <span>Dismiss</span>
                <span className="text-base font-bold leading-none">&times;</span>
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-black pt-1">
              <div>
                <span className="font-semibold block text-[11px] text-black">Cohort:</span>
                <span className="font-mono text-black font-bold">{selectedEntry.column}</span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Measured Median:</span>
                <span className="font-mono font-bold text-black text-sm">
                  {selectedEntry.val !== null ? `${selectedEntry.val.toFixed(2)} ${metricDef.unit}` : 'Unavailable'}
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Cohort Sample:</span>
                <span className="font-mono text-black">n = {selectedEntry.sampleSize} live trials</span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Metric Evaluated:</span>
                <span className="font-mono text-black">{metricDef.label}</span>
              </div>
            </div>

            {comparisonRow && (
              <div className="pt-1.5 border-t border-black/10 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-black">
                <span className="font-semibold text-black">Cohort Breakdown:</span>
                <span>
                  Chrome:{' '}
                  <strong className="font-mono text-black">
                    {comparisonRow.chrome.val !== null ? `${comparisonRow.chrome.val.toFixed(2)} ${metricDef.unit}` : '—'}
                  </strong>{' '}
                  (n={comparisonRow.chrome.sampleSize})
                </span>
                <span>
                  Firefox:{' '}
                  <strong className="font-mono text-black">
                    {comparisonRow.firefox.val !== null ? `${comparisonRow.firefox.val.toFixed(2)} ${metricDef.unit}` : '—'}
                  </strong>{' '}
                  (n={comparisonRow.firefox.sampleSize})
                </span>
                <span>
                  Combined:{' '}
                  <strong className="font-mono text-black">
                    {comparisonRow.overall.val !== null ? `${comparisonRow.overall.val.toFixed(2)} ${metricDef.unit}` : '—'}
                  </strong>{' '}
                  (n={comparisonRow.overall.sampleSize})
                </span>
              </div>
            )}
          </div>
        )}

        {/* Heatmap Legend */}
        <div className="flex flex-wrap items-center justify-between gap-2 mt-3 pt-2 border-t text-xs text-black">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] text-black font-medium">Intensity Scale:</span>
            <div className="flex items-center gap-0.5">
              <span className="w-5 h-3.5 rounded-xs bg-emerald-50 dark:bg-emerald-950/30 border" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-100 dark:bg-emerald-900/40" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-200 dark:bg-emerald-800/50" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-300 dark:bg-emerald-700/60" />
              <span className="w-5 h-3.5 rounded-xs bg-emerald-400 dark:bg-emerald-600/70" />
            </div>
            <span className="font-mono text-[10px] ml-1 text-black">
              {minVal.toFixed(1)} &rarr; {maxVal.toFixed(1)} {metricDef.unit}
            </span>
          </div>

          <div className="text-[11px] text-black">
            Values represent median measurements &bull; Missing data marked with &lsquo;—&rsquo;
          </div>
        </div>

        {/* Floating Tooltip */}
        {hoveredCell && (
          <div className="p-2 rounded bg-popover text-black border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold text-black">
              {hoveredCell.scenario} ({hoveredCell.scenarioName}) &bull; {hoveredCell.column}:
            </span>
            <span className="font-mono ml-2 font-bold text-black">
              {hoveredCell.val !== null ? `${hoveredCell.val.toFixed(2)} ${metricDef.unit}` : 'Unavailable'}{' '}
              <span className="text-black font-sans font-normal">(n={hoveredCell.sampleSize})</span>
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
