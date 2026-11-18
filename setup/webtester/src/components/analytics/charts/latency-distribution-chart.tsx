import React, { useState, useEffect } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { SupportedMetricKey, BrowserFilterId, BoxPlotStats } from '@/lib/analytics/analytics-types';
import { computeBoxPlotStats, getTrialMetricValue } from '@/lib/analytics/analytics-calculations';
import { SUPPORTED_METRICS } from '@/lib/analytics/analytics-types';

interface LatencyDistributionChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
  globalMetric: SupportedMetricKey;
}

interface SelectedBoxPlotEntry {
  scenario: string;
  browser: string;
  browserKey: 'google-chrome' | 'firefox';
  stats: BoxPlotStats;
}

export const LatencyDistributionChart: React.FC<LatencyDistributionChartProps> = ({
  trials,
  globalScenarios,
  globalBrowser,
  globalMetric,
}) => {
  const [localMetric, setLocalMetric] = useState<SupportedMetricKey | 'INHERIT'>('INHERIT');
  const [localBrowser, setLocalBrowser] = useState<BrowserFilterId | 'INHERIT'>('INHERIT');
  const [hoveredBox, setHoveredBox] = useState<{
    scenario: string;
    browser: string;
    stats: BoxPlotStats;
  } | null>(null);

  const [selectedEntry, setSelectedEntry] = useState<SelectedBoxPlotEntry | null>(null);

  const effectiveMetric = localMetric === 'INHERIT' ? globalMetric : localMetric;
  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  const metricDef = SUPPORTED_METRICS[effectiveMetric] || SUPPORTED_METRICS.t_connect_ms;

  // Calculate box plot stats for each scenario
  const data = scenarios.map((scId) => {
    const chromeTrials = trials.filter(
      (t) => t.scenario_id === scId && t.browser === 'google-chrome' && t.validity_category === 'VALID_LIVE'
    );
    const firefoxTrials = trials.filter(
      (t) => t.scenario_id === scId && t.browser === 'firefox' && t.validity_category === 'VALID_LIVE'
    );

    const chromeVals = chromeTrials.map((t) => getTrialMetricValue(t, effectiveMetric));
    const firefoxVals = firefoxTrials.map((t) => getTrialMetricValue(t, effectiveMetric));

    return {
      scenario: scId,
      chromeStats: computeBoxPlotStats(chromeVals),
      firefoxStats: computeBoxPlotStats(firefoxVals),
    };
  });

  // Reconcile or clear selection when filters change
  useEffect(() => {
    if (!selectedEntry) return;
    if (!scenarios.includes(selectedEntry.scenario)) {
      setSelectedEntry(null);
      return;
    }
    if (effectiveBrowser !== 'ALL' && effectiveBrowser !== selectedEntry.browserKey) {
      setSelectedEntry(null);
      return;
    }
    const currentData = data.find((d) => d.scenario === selectedEntry.scenario);
    if (!currentData) {
      setSelectedEntry(null);
      return;
    }
    const updatedStats =
      selectedEntry.browserKey === 'google-chrome'
        ? currentData.chromeStats
        : currentData.firefoxStats;
    if (!updatedStats) {
      setSelectedEntry(null);
      return;
    }
    setSelectedEntry((prev) => (prev ? { ...prev, stats: updatedStats } : null));
  }, [scenarios, effectiveBrowser, effectiveMetric, trials]);

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold text-black">Graph 3 — Connection Latency Distribution</CardTitle>
          <CardDescription className="text-xs text-black">Select at least one scenario to display latency distributions.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-black border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  const handleBoxSelect = (item: SelectedBoxPlotEntry) => {
    if (
      selectedEntry &&
      selectedEntry.scenario === item.scenario &&
      selectedEntry.browserKey === item.browserKey
    ) {
      setSelectedEntry(null);
    } else {
      setSelectedEntry(item);
    }
  };

  // Find comparison stats for active selection
  const comparisonInfo = selectedEntry
    ? (() => {
        const scData = data.find((d) => d.scenario === selectedEntry.scenario);
        if (!scData) return null;
        const isChrome = selectedEntry.browserKey === 'google-chrome';
        const compBrowser = isChrome ? 'Mozilla Firefox' : 'Google Chrome';
        const compStats = isChrome ? scData.firefoxStats : scData.chromeStats;
        const diff =
          compStats !== null
            ? selectedEntry.stats.median - compStats.median
            : null;
        return { compBrowser, compStats, diff };
      })()
    : null;

  // Calculate overall bounds for SVG scale
  const allValues: number[] = [];
  data.forEach((d) => {
    if (d.chromeStats && (effectiveBrowser === 'ALL' || effectiveBrowser === 'google-chrome')) {
      allValues.push(d.chromeStats.min, d.chromeStats.max, ...d.chromeStats.outliers);
    }
    if (d.firefoxStats && (effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox')) {
      allValues.push(d.firefoxStats.min, d.firefoxStats.max, ...d.firefoxStats.outliers);
    }
  });

  const rawMax = allValues.length > 0 ? Math.max(...allValues) : 100;
  const rawMin = allValues.length > 0 ? Math.min(0, Math.min(...allValues)) : 0;
  const maxVal = rawMax * 1.15;
  const minVal = Math.min(0, rawMin);

  const width = 640;
  const height = 300;
  const margin = { top: 25, right: 30, bottom: 45, left: 60 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const groupWidth = innerWidth / scenarios.length;
  const boxWidth = Math.min(22, (groupWidth * 0.7) / (effectiveBrowser === 'ALL' ? 2 : 1));

  const yScale = (val: number) => {
    if (maxVal === minVal) return height - margin.bottom;
    const ratio = (val - minVal) / (maxVal - minVal);
    return height - margin.bottom - ratio * innerHeight;
  };

  const hasSelection = selectedEntry !== null;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-black">
              Graph 3 — Connection Latency Distribution
            </CardTitle>
            <CardDescription className="text-xs text-black mt-0.5">
              Empirical Box-and-Whisker plot showing Median, Q1, Q3, Min, Max, and Outliers for {metricDef.label}.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Metric Selector */}
            <select
              value={localMetric}
              onChange={(e) => setLocalMetric(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
              aria-label="Filter metric for Graph 3"
            >
              <option value="INHERIT">Metric: Auto</option>
              <option value="t_connect_ms">t_connect (ms)</option>
              <option value="t_setup_total_ms">t_setup_total (ms)</option>
              <option value="dns_resolution_time_ms">DNS Resolution (ms)</option>
              <option value="dns_latency_aaaa_ms">AAAA Latency (ms)</option>
              <option value="dns_latency_a_ms">A Latency (ms)</option>
            </select>

            {/* Browser Selector */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
              aria-label="Filter browser for Graph 3"
            >
              <option value="INHERIT">Browser: Auto</option>
              <option value="ALL">Both Browsers</option>
              <option value="google-chrome">Chrome Only</option>
              <option value="firefox">Firefox Only</option>
            </select>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-4 relative">
        <div className="w-full overflow-x-auto">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-auto min-w-[500px] select-none"
            aria-label="Latency Distribution Box and Whisker Plot"
          >
            {/* Y Axis Gridlines and Labels */}
            {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
              const val = minVal + (maxVal - minVal) * ratio;
              const y = margin.top + innerHeight * (1 - ratio);
              return (
                <g key={ratio}>
                  <line
                    x1={margin.left}
                    y1={y}
                    x2={width - margin.right}
                    y2={y}
                    stroke="currentColor"
                    strokeDasharray="3 3"
                    className="text-border/40"
                  />
                  <text
                    x={margin.left - 8}
                    y={y + 3}
                    textAnchor="end"
                    className="text-[10px] fill-black text-black font-mono"
                  >
                    {val.toFixed(0)} {metricDef.unit}
                  </text>
                </g>
              );
            })}

            {/* Axis Lines */}
            <line
              x1={margin.left}
              y1={margin.top}
              x2={margin.left}
              y2={height - margin.bottom}
              stroke="currentColor"
              className="text-border"
            />
            <line
              x1={margin.left}
              y1={height - margin.bottom}
              x2={width - margin.right}
              y2={height - margin.bottom}
              stroke="currentColor"
              className="text-border"
            />

            {/* Scenario Box Plots */}
            {data.map((d, i) => {
              const groupX = margin.left + i * groupWidth;
              const centerX = groupX + groupWidth / 2;

              const showChrome = effectiveBrowser === 'ALL' || effectiveBrowser === 'google-chrome';
              const showFirefox = effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox';

              const chromeCenterX = effectiveBrowser === 'ALL' ? centerX - boxWidth / 2 - 2 : centerX;
              const firefoxCenterX = effectiveBrowser === 'ALL' ? centerX + boxWidth / 2 + 2 : centerX;

              const isChromeSelected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.browserKey === 'google-chrome';
              const isFirefoxSelected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.browserKey === 'firefox';

              return (
                <g key={d.scenario}>
                  {/* Scenario X Label */}
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-black text-black"
                  >
                    {d.scenario}
                  </text>

                  {/* Chrome Box */}
                  {showChrome && d.chromeStats && (
                    <BoxPlotItem
                      cx={chromeCenterX}
                      width={boxWidth}
                      stats={d.chromeStats}
                      yScale={yScale}
                      color="blue"
                      isSelected={isChromeSelected}
                      hasSelection={hasSelection}
                      onSelect={() =>
                        handleBoxSelect({
                          scenario: d.scenario,
                          browser: 'Google Chrome',
                          browserKey: 'google-chrome',
                          stats: d.chromeStats!,
                        })
                      }
                      onHover={() =>
                        setHoveredBox({
                          scenario: d.scenario,
                          browser: 'Google Chrome',
                          stats: d.chromeStats!,
                        })
                      }
                      onLeave={() => setHoveredBox(null)}
                      ariaLabel={`Select ${d.scenario} Google Chrome box plot: Median ${d.chromeStats.median.toFixed(2)} ${metricDef.unit}`}
                    />
                  )}

                  {/* Firefox Box */}
                  {showFirefox && d.firefoxStats && (
                    <BoxPlotItem
                      cx={firefoxCenterX}
                      width={boxWidth}
                      stats={d.firefoxStats}
                      yScale={yScale}
                      color="amber"
                      isSelected={isFirefoxSelected}
                      hasSelection={hasSelection}
                      onSelect={() =>
                        handleBoxSelect({
                          scenario: d.scenario,
                          browser: 'Mozilla Firefox',
                          browserKey: 'firefox',
                          stats: d.firefoxStats!,
                        })
                      }
                      onHover={() =>
                        setHoveredBox({
                          scenario: d.scenario,
                          browser: 'Mozilla Firefox',
                          stats: d.firefoxStats!,
                        })
                      }
                      onLeave={() => setHoveredBox(null)}
                      ariaLabel={`Select ${d.scenario} Mozilla Firefox box plot: Median ${d.firefoxStats.median.toFixed(2)} ${metricDef.unit}`}
                    />
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Entry Detail Panel */}
        {selectedEntry && (
          <div
            data-testid="graph-3-selected-panel"
            className="mt-3 p-3 rounded-lg border-2 border-black/30 bg-muted/30 text-black text-xs space-y-2 animate-fade-in"
          >
            <div className="flex items-center justify-between border-b border-black/15 pb-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-black text-white">
                  Active Selection
                </span>
                <span className="font-bold text-black text-sm">
                  {selectedEntry.scenario} &bull; {selectedEntry.browser} ({metricDef.shortLabel})
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

            <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 font-mono text-[11px] text-black pt-1">
              <div>
                <span className="font-sans font-semibold block text-[11px] text-black">Min:</span>
                <strong className="text-black">{selectedEntry.stats.min.toFixed(2)}</strong>
              </div>
              <div>
                <span className="font-sans font-semibold block text-[11px] text-black">Q1:</span>
                <strong className="text-black">{selectedEntry.stats.q1.toFixed(2)}</strong>
              </div>
              <div>
                <span className="font-sans font-semibold block text-[11px] text-black">Median:</span>
                <strong className="text-black font-bold text-sm">{selectedEntry.stats.median.toFixed(2)} {metricDef.unit}</strong>
              </div>
              <div>
                <span className="font-sans font-semibold block text-[11px] text-black">Q3:</span>
                <strong className="text-black">{selectedEntry.stats.q3.toFixed(2)}</strong>
              </div>
              <div>
                <span className="font-sans font-semibold block text-[11px] text-black">Max:</span>
                <strong className="text-black">{selectedEntry.stats.max.toFixed(2)}</strong>
              </div>
              <div>
                <span className="font-sans font-semibold block text-[11px] text-black">Sample:</span>
                <strong className="text-black">n = {selectedEntry.stats.sampleSize}</strong>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-black/10 text-[11px] text-black">
              <div>
                <span className="font-semibold text-black">IQR:</span>{' '}
                <span className="font-mono text-black">{(selectedEntry.stats.q3 - selectedEntry.stats.q1).toFixed(2)} {metricDef.unit}</span>
                {selectedEntry.stats.outliers.length > 0 && (
                  <span className="ml-3 text-black">
                    Outliers: [{selectedEntry.stats.outliers.map((o) => o.toFixed(1)).join(', ')}]
                  </span>
                )}
              </div>
              {comparisonInfo && comparisonInfo.compStats && (
                <div className="font-mono text-black">
                  Vs. {comparisonInfo.compBrowser}: Median {comparisonInfo.compStats.median.toFixed(2)} {metricDef.unit}
                  {comparisonInfo.diff !== null && (
                    <span className="ml-1 text-black font-semibold">
                      ({comparisonInfo.diff > 0 ? `+${comparisonInfo.diff.toFixed(2)}` : comparisonInfo.diff.toFixed(2)} {metricDef.unit})
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t text-xs text-black">
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'google-chrome') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs border-2 border-blue-600 bg-blue-500/20" />
              <span className="text-black font-medium">Google Chrome (IQR Box, Whiskers, Median)</span>
            </div>
          )}
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs border-2 border-amber-600 bg-amber-500/20" />
              <span className="text-black font-medium">Mozilla Firefox (IQR Box, Whiskers, Median)</span>
            </div>
          )}
        </div>

        {/* Floating Tooltip */}
        {hoveredBox && (
          <div className="p-2.5 rounded bg-popover text-black border text-xs shadow-md mt-2 space-y-1">
            <div className="font-semibold flex items-center justify-between border-b pb-1 text-black">
              <span>
                {hoveredBox.scenario} &bull; {hoveredBox.browser} ({metricDef.shortLabel})
              </span>
              <span className="text-black font-mono">n={hoveredBox.stats.sampleSize}</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-[11px] pt-0.5 text-black">
              <div>
                Min: <strong>{hoveredBox.stats.min.toFixed(2)}</strong>
              </div>
              <div>
                Q1: <strong>{hoveredBox.stats.q1.toFixed(2)}</strong>
              </div>
              <div>
                Median: <strong className="text-black">{hoveredBox.stats.median.toFixed(2)}</strong>
              </div>
              <div>
                Q3: <strong>{hoveredBox.stats.q3.toFixed(2)}</strong>
              </div>
              <div>
                Max: <strong>{hoveredBox.stats.max.toFixed(2)}</strong>
              </div>
            </div>
            {hoveredBox.stats.outliers.length > 0 && (
              <div className="text-[10px] text-black">
                Outliers: [{hoveredBox.stats.outliers.map((o) => o.toFixed(1)).join(', ')}]
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};

interface BoxPlotItemProps {
  cx: number;
  width: number;
  stats: BoxPlotStats;
  yScale: (val: number) => number;
  color: 'blue' | 'amber';
  isSelected?: boolean;
  hasSelection?: boolean;
  onSelect?: () => void;
  onHover: () => void;
  onLeave: () => void;
  ariaLabel?: string;
}

const BoxPlotItem: React.FC<BoxPlotItemProps> = ({
  cx,
  width,
  stats,
  yScale,
  color,
  isSelected = false,
  hasSelection = false,
  onSelect,
  onHover,
  onLeave,
  ariaLabel,
}) => {
  const yMin = yScale(stats.min);
  const yQ1 = yScale(stats.q1);
  const yMed = yScale(stats.median);
  const yQ3 = yScale(stats.q3);
  const yMax = yScale(stats.max);

  const boxY = Math.min(yQ1, yQ3);
  const boxHeight = Math.max(2, Math.abs(yQ1 - yQ3));

  const strokeColor = isSelected
    ? 'stroke-black'
    : color === 'blue'
    ? 'stroke-blue-600 dark:stroke-blue-400'
    : 'stroke-amber-600 dark:stroke-amber-400';

  const fillColor = isSelected
    ? color === 'blue'
      ? 'fill-blue-500/40'
      : 'fill-amber-500/40'
    : color === 'blue'
    ? 'fill-blue-500/20 hover:fill-blue-500/30'
    : 'fill-amber-500/20 hover:fill-amber-500/30';

  const medianColor = isSelected
    ? 'stroke-black'
    : color === 'blue'
    ? 'stroke-blue-800 dark:stroke-blue-200'
    : 'stroke-amber-800 dark:stroke-amber-200';

  return (
    <g
      role="button"
      tabIndex={0}
      aria-pressed={isSelected}
      aria-label={ariaLabel}
      className="cursor-pointer transition-all outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px]"
      opacity={isSelected ? 1 : hasSelection ? 0.45 : 1}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onSelect?.();
        }
      }}
      onMouseEnter={onHover}
      onMouseLeave={onLeave}
    >
      {/* Lower whisker line */}
      <line
        x1={cx}
        y1={yMin}
        x2={cx}
        y2={yQ1}
        className={strokeColor}
        strokeWidth={isSelected ? 2.5 : 1.5}
      />
      {/* Lower whisker cap */}
      <line
        x1={cx - width / 3}
        y1={yMin}
        x2={cx + width / 3}
        y2={yMin}
        className={strokeColor}
        strokeWidth={isSelected ? 2.5 : 1.5}
      />

      {/* Upper whisker line */}
      <line
        x1={cx}
        y1={yMax}
        x2={cx}
        y2={yQ3}
        className={strokeColor}
        strokeWidth={isSelected ? 2.5 : 1.5}
      />
      {/* Upper whisker cap */}
      <line
        x1={cx - width / 3}
        y1={yMax}
        x2={cx + width / 3}
        y2={yMax}
        className={strokeColor}
        strokeWidth={isSelected ? 2.5 : 1.5}
      />

      {/* IQR Box (Q1 to Q3) */}
      <rect
        x={cx - width / 2}
        y={boxY}
        width={width}
        height={boxHeight}
        rx={2}
        className={`${fillColor} ${strokeColor}`}
        strokeWidth={isSelected ? 3 : 1.5}
      />

      {/* Median Line */}
      <line
        x1={cx - width / 2}
        y1={yMed}
        x2={cx + width / 2}
        y2={yMed}
        className={medianColor}
        strokeWidth={isSelected ? 3.5 : 2.5}
      />

      {/* Outlier Points */}
      {stats.outliers.map((o, idx) => {
        const oy = yScale(o);
        return (
          <circle
            key={idx}
            cx={cx}
            cy={oy}
            r={isSelected ? 3.5 : 2.5}
            className={`${strokeColor} fill-background`}
            strokeWidth={isSelected ? 2 : 1.5}
          />
        );
      })}
    </g>
  );
};
