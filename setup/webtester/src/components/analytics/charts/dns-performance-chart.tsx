import React, { useState, useEffect } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';
import { computeMedian } from '@/lib/historical-evidence';

interface DnsPerformanceChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

interface SelectedDnsEntry {
  scenario: string;
  metricKey: 'a' | 'aaaa' | 'resolution' | 'payload';
  metricLabel: string;
  value: number | null;
  sampleSize: number;
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

  const [selectedEntry, setSelectedEntry] = useState<SelectedDnsEntry | null>(null);

  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

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

  // Reconcile or clear selection when filters change
  useEffect(() => {
    if (!selectedEntry) return;
    if (!scenarios.includes(selectedEntry.scenario)) {
      setSelectedEntry(null);
      return;
    }
    const currentData = data.find((d) => d.scenario === selectedEntry.scenario);
    if (!currentData) {
      setSelectedEntry(null);
      return;
    }

    let val: number | null = null;
    if (selectedEntry.metricKey === 'a') val = currentData.aMedian;
    else if (selectedEntry.metricKey === 'aaaa') val = currentData.aaaaMedian;
    else if (selectedEntry.metricKey === 'resolution') val = currentData.resMedian;
    else if (selectedEntry.metricKey === 'payload') val = currentData.payloadMedian;

    setSelectedEntry((prev) =>
      prev ? { ...prev, value: val, sampleSize: currentData.sampleSize } : null
    );
  }, [scenarios, effectiveBrowser, metricView, trials]);

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold text-black">Graph 4 — DNS Resolution Performance</CardTitle>
          <CardDescription className="text-xs text-black">Select at least one scenario to inspect DNS performance.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-black border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  const handleBarSelect = (item: SelectedDnsEntry) => {
    if (
      selectedEntry &&
      selectedEntry.scenario === item.scenario &&
      selectedEntry.metricKey === item.metricKey
    ) {
      setSelectedEntry(null);
    } else {
      setSelectedEntry(item);
    }
  };

  // Find comparison info for active selection
  const comparisonInfo = selectedEntry
    ? (() => {
        const scData = data.find((d) => d.scenario === selectedEntry.scenario);
        if (!scData) return null;
        if (selectedEntry.metricKey === 'a') {
          const compLabel = 'AAAA Record (IPv6)';
          const compVal = scData.aaaaMedian;
          const diff =
            selectedEntry.value !== null && compVal !== null
              ? selectedEntry.value - compVal
              : null;
          return { compLabel, compVal, diff };
        } else if (selectedEntry.metricKey === 'aaaa') {
          const compLabel = 'A Record (IPv4)';
          const compVal = scData.aMedian;
          const diff =
            selectedEntry.value !== null && compVal !== null
              ? selectedEntry.value - compVal
              : null;
          return { compLabel, compVal, diff };
        } else {
          // Compare against baseline S0 if present
          const s0Data = data.find((d) => d.scenario === 'S0');
          const baselineVal =
            selectedEntry.metricKey === 'resolution'
              ? s0Data?.resMedian ?? null
              : s0Data?.payloadMedian ?? null;
          const diff =
            selectedEntry.value !== null && baselineVal !== null
              ? selectedEntry.value - baselineVal
              : null;
          return { compLabel: 'Baseline S0', compVal: baselineVal, diff };
        }
      })()
    : null;

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

  const hasSelection = selectedEntry !== null;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-black">
              Graph 4 — DNS Resolution Performance
            </CardTitle>
            <CardDescription className="text-xs text-black mt-0.5">
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
                    : 'text-black hover:opacity-80'
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
                    : 'text-black hover:opacity-80'
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
                    : 'text-black hover:opacity-80'
                }`}
              >
                DNS to Payload
              </button>
            </div>

            {/* Local Browser Filter */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
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
                    className="text-[10px] fill-black text-black font-mono"
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

                const isASelected =
                  selectedEntry?.scenario === d.scenario && selectedEntry?.metricKey === 'a';
                const isAaaaSelected =
                  selectedEntry?.scenario === d.scenario && selectedEntry?.metricKey === 'aaaa';

                return (
                  <g key={d.scenario}>
                    <text
                      x={centerX}
                      y={height - margin.bottom + 18}
                      textAnchor="middle"
                      className="text-xs font-semibold fill-black text-black"
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
                      role="button"
                      tabIndex={0}
                      aria-pressed={isASelected}
                      aria-label={`Select ${d.scenario} A Record: ${d.aMedian !== null ? `${d.aMedian.toFixed(2)} ms` : 'N/A'}`}
                      stroke={isASelected ? '#000000' : 'none'}
                      strokeWidth={isASelected ? 3 : 0}
                      opacity={isASelected ? 1 : hasSelection ? 0.45 : 1}
                      className="fill-sky-600 dark:fill-sky-500 hover:opacity-85 cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px] transition-all"
                      onClick={() =>
                        handleBarSelect({
                          scenario: d.scenario,
                          metricKey: 'a',
                          metricLabel: 'A Record (IPv4) Latency',
                          value: d.aMedian,
                          sampleSize: d.sampleSize,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleBarSelect({
                            scenario: d.scenario,
                            metricKey: 'a',
                            metricLabel: 'A Record (IPv4) Latency',
                            value: d.aMedian,
                            sampleSize: d.sampleSize,
                          });
                        }
                      }}
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
                      role="button"
                      tabIndex={0}
                      aria-pressed={isAaaaSelected}
                      aria-label={`Select ${d.scenario} AAAA Record: ${d.aaaaMedian !== null ? `${d.aaaaMedian.toFixed(2)} ms` : 'N/A'}`}
                      stroke={isAaaaSelected ? '#000000' : 'none'}
                      strokeWidth={isAaaaSelected ? 3 : 0}
                      opacity={isAaaaSelected ? 1 : hasSelection ? 0.45 : 1}
                      className="fill-purple-600 dark:fill-purple-500 hover:opacity-85 cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px] transition-all"
                      onClick={() =>
                        handleBarSelect({
                          scenario: d.scenario,
                          metricKey: 'aaaa',
                          metricLabel: 'AAAA Record (IPv6) Latency',
                          value: d.aaaaMedian,
                          sampleSize: d.sampleSize,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleBarSelect({
                            scenario: d.scenario,
                            metricKey: 'aaaa',
                            metricLabel: 'AAAA Record (IPv6) Latency',
                            value: d.aaaaMedian,
                            sampleSize: d.sampleSize,
                          });
                        }
                      }}
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

              const isBarSelected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.metricKey === metricView;

              return (
                <g key={d.scenario}>
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-black text-black"
                  >
                    {d.scenario}
                  </text>
                  <rect
                    x={barX}
                    y={height - margin.bottom - barHeight}
                    width={barWidth}
                    height={Math.max(2, barHeight)}
                    rx={3}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isBarSelected}
                    aria-label={`Select ${d.scenario} ${metricView === 'resolution' ? 'DNS Resolution Time' : 'DNS to Payload'}: ${val !== null ? `${val.toFixed(2)} ms` : 'N/A'}`}
                    stroke={isBarSelected ? '#000000' : 'none'}
                    strokeWidth={isBarSelected ? 3 : 0}
                    opacity={isBarSelected ? 1 : hasSelection ? 0.45 : 1}
                    className={`${colorClass} hover:opacity-85 cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px] transition-all`}
                    onClick={() =>
                      handleBarSelect({
                        scenario: d.scenario,
                        metricKey: metricView,
                        metricLabel:
                          metricView === 'resolution' ? 'DNS Resolution Time' : 'DNS to Payload',
                        value: val,
                        sampleSize: d.sampleSize,
                      })
                    }
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleBarSelect({
                          scenario: d.scenario,
                          metricKey: metricView,
                          metricLabel:
                            metricView === 'resolution' ? 'DNS Resolution Time' : 'DNS to Payload',
                          value: val,
                          sampleSize: d.sampleSize,
                        });
                      }
                    }}
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

        {/* Selected Entry Detail Panel */}
        {selectedEntry && (
          <div
            data-testid="graph-4-selected-panel"
            className="mt-3 p-3 rounded-lg border-2 border-black/30 bg-muted/30 text-black text-xs space-y-2 animate-fade-in"
          >
            <div className="flex items-center justify-between border-b border-black/15 pb-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-black text-white">
                  Active Selection
                </span>
                <span className="font-bold text-black text-sm">
                  {selectedEntry.scenario} &bull; {selectedEntry.metricLabel}
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
                <span className="font-semibold block text-[11px] text-black">Metric:</span>
                <span className="font-mono text-black">{selectedEntry.metricLabel}</span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Measured Median:</span>
                <span className="font-mono font-bold text-black text-sm">
                  {selectedEntry.value !== null ? `${selectedEntry.value.toFixed(2)} ms` : 'N/A'}
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Cohort Sample:</span>
                <span className="font-mono text-black">
                  n = {selectedEntry.sampleSize} trials ({effectiveBrowser === 'ALL' ? 'Chrome & Firefox' : effectiveBrowser})
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">
                  {comparisonInfo ? `Vs. ${comparisonInfo.compLabel}:` : 'Comparison:'}
                </span>
                <span className="font-mono text-black">
                  {comparisonInfo && comparisonInfo.compVal !== null
                    ? `${comparisonInfo.compVal.toFixed(2)} ms ${
                        comparisonInfo.diff !== null
                          ? `(${comparisonInfo.diff > 0 ? `+${comparisonInfo.diff.toFixed(2)}` : comparisonInfo.diff.toFixed(2)} ms)`
                          : ''
                      }`
                    : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t text-xs text-black">
          {metricView === 'a_vs_aaaa' && (
            <>
              <div className="flex items-center gap-1.5">
                <span className="size-3 rounded-xs bg-sky-600 dark:bg-sky-500" />
                <span className="text-black font-medium">A Record Latency (IPv4)</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="size-3 rounded-xs bg-purple-600 dark:bg-purple-500" />
                <span className="text-black font-medium">AAAA Record Latency (IPv6, 500ms in S6)</span>
              </div>
            </>
          )}
          {metricView === 'resolution' && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-teal-600 dark:bg-teal-500" />
              <span className="text-black font-medium">Full DNS Resolution Time (ms)</span>
            </div>
          )}
          {metricView === 'payload' && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-indigo-600 dark:bg-indigo-500" />
              <span className="text-black font-medium">DNS Query to First HTTP Payload Time (ms)</span>
            </div>
          )}
        </div>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div className="p-2 rounded bg-popover text-black border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold text-black">
              {hoveredItem.scenario} &bull; {hoveredItem.label}:
            </span>
            <span className="font-mono ml-2 font-bold text-black">
              {hoveredItem.value !== null ? `${hoveredItem.value.toFixed(2)} ms` : 'N/A'}
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
