import React, { useState } from 'react';
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

  const effectiveMetric = localMetric === 'INHERIT' ? globalMetric : localMetric;
  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  const metricDef = SUPPORTED_METRICS[effectiveMetric] || SUPPORTED_METRICS.t_connect_ms;

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold">Graph 3 — Connection Latency Distribution</CardTitle>
          <CardDescription>Select at least one scenario to display latency distributions.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-muted-foreground border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

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

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-foreground">
              Graph 3 — Connection Latency Distribution
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground mt-0.5">
              Empirical Box-and-Whisker plot showing Median, Q1, Q3, Min, Max, and Outliers for {metricDef.label}.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Metric Selector */}
            <select
              value={localMetric}
              onChange={(e) => setLocalMetric(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-foreground"
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
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-foreground"
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
                    className="text-[10px] fill-muted-foreground font-mono"
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

              return (
                <g key={d.scenario}>
                  {/* Scenario X Label */}
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-foreground"
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
                      onHover={() =>
                        setHoveredBox({
                          scenario: d.scenario,
                          browser: 'Google Chrome',
                          stats: d.chromeStats!,
                        })
                      }
                      onLeave={() => setHoveredBox(null)}
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
                      onHover={() =>
                        setHoveredBox({
                          scenario: d.scenario,
                          browser: 'Mozilla Firefox',
                          stats: d.firefoxStats!,
                        })
                      }
                      onLeave={() => setHoveredBox(null)}
                    />
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t text-xs text-muted-foreground">
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'google-chrome') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs border-2 border-blue-600 bg-blue-500/20" />
              <span>Google Chrome (IQR Box, Whiskers, Median)</span>
            </div>
          )}
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs border-2 border-amber-600 bg-amber-500/20" />
              <span>Mozilla Firefox (IQR Box, Whiskers, Median)</span>
            </div>
          )}
        </div>

        {/* Floating Tooltip */}
        {hoveredBox && (
          <div className="p-2.5 rounded bg-popover text-popover-foreground border text-xs shadow-md mt-2 space-y-1">
            <div className="font-semibold flex items-center justify-between border-b pb-1">
              <span>
                {hoveredBox.scenario} &bull; {hoveredBox.browser} ({metricDef.shortLabel})
              </span>
              <span className="text-muted-foreground font-mono">n={hoveredBox.stats.sampleSize}</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-[11px] pt-0.5">
              <div>
                Min: <strong>{hoveredBox.stats.min.toFixed(2)}</strong>
              </div>
              <div>
                Q1: <strong>{hoveredBox.stats.q1.toFixed(2)}</strong>
              </div>
              <div>
                Median: <strong className="text-primary">{hoveredBox.stats.median.toFixed(2)}</strong>
              </div>
              <div>
                Q3: <strong>{hoveredBox.stats.q3.toFixed(2)}</strong>
              </div>
              <div>
                Max: <strong>{hoveredBox.stats.max.toFixed(2)}</strong>
              </div>
            </div>
            {hoveredBox.stats.outliers.length > 0 && (
              <div className="text-[10px] text-muted-foreground">
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
  onHover: () => void;
  onLeave: () => void;
}

const BoxPlotItem: React.FC<BoxPlotItemProps> = ({
  cx,
  width,
  stats,
  yScale,
  color,
  onHover,
  onLeave,
}) => {
  const yMin = yScale(stats.min);
  const yQ1 = yScale(stats.q1);
  const yMed = yScale(stats.median);
  const yQ3 = yScale(stats.q3);
  const yMax = yScale(stats.max);

  const boxY = Math.min(yQ1, yQ3);
  const boxHeight = Math.max(2, Math.abs(yQ1 - yQ3));

  const strokeColor =
    color === 'blue'
      ? 'stroke-blue-600 dark:stroke-blue-400'
      : 'stroke-amber-600 dark:stroke-amber-400';
  const fillColor =
    color === 'blue'
      ? 'fill-blue-500/20 hover:fill-blue-500/30'
      : 'fill-amber-500/20 hover:fill-amber-500/30';
  const medianColor =
    color === 'blue'
      ? 'stroke-blue-800 dark:stroke-blue-200'
      : 'stroke-amber-800 dark:stroke-amber-200';

  return (
    <g className="cursor-pointer transition-opacity" onMouseEnter={onHover} onMouseLeave={onLeave}>
      {/* Lower whisker line */}
      <line
        x1={cx}
        y1={yMin}
        x2={cx}
        y2={yQ1}
        className={strokeColor}
        strokeWidth={1.5}
      />
      {/* Lower whisker cap */}
      <line
        x1={cx - width / 3}
        y1={yMin}
        x2={cx + width / 3}
        y2={yMin}
        className={strokeColor}
        strokeWidth={1.5}
      />

      {/* Upper whisker line */}
      <line
        x1={cx}
        y1={yMax}
        x2={cx}
        y2={yQ3}
        className={strokeColor}
        strokeWidth={1.5}
      />
      {/* Upper whisker cap */}
      <line
        x1={cx - width / 3}
        y1={yMax}
        x2={cx + width / 3}
        y2={yMax}
        className={strokeColor}
        strokeWidth={1.5}
      />

      {/* IQR Box (Q1 to Q3) */}
      <rect
        x={cx - width / 2}
        y={boxY}
        width={width}
        height={boxHeight}
        rx={2}
        className={`${fillColor} ${strokeColor}`}
        strokeWidth={1.5}
      />

      {/* Median Line */}
      <line
        x1={cx - width / 2}
        y1={yMed}
        x2={cx + width / 2}
        y2={yMed}
        className={medianColor}
        strokeWidth={2.5}
      />

      {/* Outlier Points */}
      {stats.outliers.map((o, idx) => {
        const oy = yScale(o);
        return (
          <circle
            key={idx}
            cx={cx}
            cy={oy}
            r={2.5}
            className={`${strokeColor} fill-background`}
            strokeWidth={1.5}
          />
        );
      })}
    </g>
  );
};
