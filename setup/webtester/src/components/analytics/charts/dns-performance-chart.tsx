import React, { useState } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';
import { computeMedian } from '@/lib/historical-evidence';

interface DnsPerformanceChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

export const DnsPerformanceChart: React.FC<DnsPerformanceChartProps> = ({
  trials,
  globalScenarios,
  globalBrowser,
}) => {
  const [localBrowser, setLocalBrowser] = useState<BrowserFilterId | 'INHERIT'>('INHERIT');
  const [metricView, setMetricView] = useState<'a_vs_aaaa' | 'resolution' | 'payload'>('a_vs_aaaa');
  const [hoveredItem, setHoveredItem] = useState<{
    scenario: string;
    label: string;
    value: number | null;
  } | null>(null);

  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold">Graph 4 — DNS Resolution Performance</CardTitle>
          <CardDescription>Select at least one scenario to inspect DNS performance.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-muted-foreground border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  // Calculate medians for A, AAAA, Resolution, and First Payload for each scenario
  const data = scenarios.map((scId) => {
    const scTrials = trials.filter(
      (t) =>
        t.scenario_id === scId &&
        (effectiveBrowser === 'ALL' || t.browser === effectiveBrowser) &&
        t.validity_category === 'VALID_LIVE'
    );

    const aVals = scTrials.map((t) => t.metrics?.dns_latency_a_ms);
    const aaaaVals = scTrials.map((t) => t.metrics?.dns_latency_aaaa_ms);
    const resVals = scTrials.map((t) => t.metrics?.dns_resolution_time_ms);
    const payloadVals = scTrials.map((t) => t.metrics?.dns_query_to_first_payload_ms);

    return {
      scenario: scId,
      aMedian: computeMedian(aVals),
      aaaaMedian: computeMedian(aaaaVals),
      resMedian: computeMedian(resVals),
      payloadMedian: computeMedian(payloadVals),
      sampleSize: scTrials.length,
    };
  });

  const width = 640;
  const height = 280;
  const margin = { top: 25, right: 30, bottom: 45, left: 55 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  // Determine max value for Y-axis scaling
  let allVals: (number | null)[] = [];
  if (metricView === 'a_vs_aaaa') {
    allVals = data.flatMap((d) => [d.aMedian, d.aaaaMedian]);
  } else if (metricView === 'resolution') {
    allVals = data.map((d) => d.resMedian);
  } else {
    allVals = data.map((d) => d.payloadMedian);
  }
  const cleanVals = allVals.filter((v): v is number => typeof v === 'number');
  const maxVal = cleanVals.length > 0 ? Math.max(...cleanVals, 50) * 1.15 : 100;

  const groupWidth = innerWidth / scenarios.length;
  const barWidth = metricView === 'a_vs_aaaa' ? Math.min(26, groupWidth * 0.35) : Math.min(40, groupWidth * 0.6);

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-foreground">
              Graph 4 — DNS Resolution Performance
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground mt-0.5">
              Authoritative DNS response latency and resolution intervals (inspect S6 for 500ms AAAA delay).
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* View Selector */}
            <div className="flex items-center rounded-md border bg-background p-0.5">
              <button
                type="button"
                onClick={() => setMetricView('a_vs_aaaa')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  metricView === 'a_vs_aaaa'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                A vs AAAA
              </button>
              <button
                type="button"
                onClick={() => setMetricView('resolution')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  metricView === 'resolution'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Resolution
              </button>
              <button
                type="button"
                onClick={() => setMetricView('payload')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  metricView === 'payload'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                DNS to Payload
              </button>
            </div>

            {/* Local Browser Filter */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-foreground"
              aria-label="Filter browser for Graph 4"
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
            aria-label="DNS Resolution Performance Bar Chart"
          >
            {/* Y Axis Gridlines and Labels */}
            {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
              const val = maxVal * ratio;
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
                    {val.toFixed(0)} ms
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

            {/* Group Bars */}
            {data.map((d, i) => {
              const centerX = margin.left + i * groupWidth + groupWidth / 2;

              if (metricView === 'a_vs_aaaa') {
                const aHeight = typeof d.aMedian === 'number' ? (d.aMedian / maxVal) * innerHeight : 0;
                const aaaaHeight =
                  typeof d.aaaaMedian === 'number' ? (d.aaaaMedian / maxVal) * innerHeight : 0;

                const aX = centerX - barWidth - 2;
                const aaaaX = centerX + 2;

                return (
                  <g key={d.scenario}>
                    <text
                      x={centerX}
                      y={height - margin.bottom + 18}
                      textAnchor="middle"
                      className="text-xs font-semibold fill-foreground"
                    >
                      {d.scenario}
                    </text>

                    {/* A Record Bar */}
                    <rect
                      x={aX}
                      y={height - margin.bottom - aHeight}
                      width={barWidth}
                      height={Math.max(2, aHeight)}
                      rx={3}
                      className="fill-sky-600 dark:fill-sky-500 hover:opacity-85 cursor-pointer"
                      onMouseEnter={() =>
                        setHoveredItem({
                          scenario: d.scenario,
                          label: 'A Record (IPv4) Latency',
                          value: d.aMedian,
                        })
                      }
                      onMouseLeave={() => setHoveredItem(null)}
                    />

                    {/* AAAA Record Bar */}
                    <rect
                      x={aaaaX}
                      y={height - margin.bottom - aaaaHeight}
                      width={barWidth}
                      height={Math.max(2, aaaaHeight)}
                      rx={3}
                      className="fill-purple-600 dark:fill-purple-500 hover:opacity-85 cursor-pointer"
                      onMouseEnter={() =>
                        setHoveredItem({
                          scenario: d.scenario,
                          label: 'AAAA Record (IPv6) Latency',
                          value: d.aaaaMedian,
                        })
                      }
                      onMouseLeave={() => setHoveredItem(null)}
                    />
                  </g>
                );
              }

              // Single bar for resolution or payload
              const val = metricView === 'resolution' ? d.resMedian : d.payloadMedian;
              const barHeight = typeof val === 'number' ? (val / maxVal) * innerHeight : 0;
              const barX = centerX - barWidth / 2;
              const colorClass =
                metricView === 'resolution'
                  ? 'fill-teal-600 dark:fill-teal-500'
                  : 'fill-indigo-600 dark:fill-indigo-500';

              return (
                <g key={d.scenario}>
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-foreground"
                  >
                    {d.scenario}
                  </text>
                  <rect
                    x={barX}
                    y={height - margin.bottom - barHeight}
                    width={barWidth}
                    height={Math.max(2, barHeight)}
                    rx={3}
                    className={`${colorClass} hover:opacity-85 cursor-pointer`}
                    onMouseEnter={() =>
                      setHoveredItem({
                        scenario: d.scenario,
                        label: metricView === 'resolution' ? 'DNS Resolution Time' : 'DNS to Payload',
                        value: val,
                      })
                    }
                    onMouseLeave={() => setHoveredItem(null)}
                  />
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t text-xs text-muted-foreground">
          {metricView === 'a_vs_aaaa' && (
            <>
              <div className="flex items-center gap-1.5">
                <span className="size-3 rounded-xs bg-sky-600 dark:bg-sky-500" />
                <span>A Record Latency (IPv4)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="size-3 rounded-xs bg-purple-600 dark:bg-purple-500" />
                <span>AAAA Record Latency (IPv6, 500ms in S6)</span>
              </div>
            </>
          )}
          {metricView === 'resolution' && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-teal-600 dark:bg-teal-500" />
              <span>Full DNS Resolution Time (ms)</span>
            </div>
          )}
          {metricView === 'payload' && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-indigo-600 dark:bg-indigo-500" />
              <span>DNS Query to First HTTP Payload Time (ms)</span>
            </div>
          )}
        </div>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div className="p-2 rounded bg-popover text-popover-foreground border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold">
              {hoveredItem.scenario} &bull; {hoveredItem.label}:
            </span>
            <span className="font-mono ml-2 font-bold text-primary">
              {hoveredItem.value !== null ? `${hoveredItem.value.toFixed(2)} ms` : 'N/A'}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
