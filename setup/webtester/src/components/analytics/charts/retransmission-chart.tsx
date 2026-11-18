import React, { useState, useEffect } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';

interface RetransmissionChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

interface SelectedRetransmissionEntry {
  scenario: string;
  family: 'IPv6' | 'IPv4';
  familyLabel: string;
  count: number;
  observedValue: number;
  sampleSize: number;
  compFamilyLabel: string;
  compCount: number;
  compObservedValue: number;
}

export const RetransmissionChart: React.FC<RetransmissionChartProps> = ({
  trials,
  globalScenarios,
  globalBrowser,
}) => {
  const [localBrowser, setLocalBrowser] = useState<BrowserFilterId | 'INHERIT'>('INHERIT');
  const [displayMode, setDisplayMode] = useState<'total' | 'mean'>('total');
  const [hoveredItem, setHoveredItem] = useState<{
    scenario: string;
    ipv4Count: number;
    ipv6Count: number;
    sampleSize: number;
  } | null>(null);

  const [selectedEntry, setSelectedEntry] = useState<SelectedRetransmissionEntry | null>(null);

  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  // Aggregate retransmissions per scenario
  const data = scenarios.map((scId) => {
    const scTrials = trials.filter(
      (t) =>
        t.scenario_id === scId &&
        (effectiveBrowser === 'ALL' || t.browser === effectiveBrowser) &&
        t.validity_category === 'VALID_LIVE'
    );

    let v4Total = 0;
    let v6Total = 0;

    for (const t of scTrials) {
      if (typeof t.metrics?.retransmitted_syn_count_ipv4 === 'number') {
        v4Total += t.metrics.retransmitted_syn_count_ipv4;
      }
      if (typeof t.metrics?.retransmitted_syn_count_ipv6 === 'number') {
        v6Total += t.metrics.retransmitted_syn_count_ipv6;
      }
    }

    const n = scTrials.length;
    const v4Val = displayMode === 'total' ? v4Total : n > 0 ? v4Total / n : 0;
    const v6Val = displayMode === 'total' ? v6Total : n > 0 ? v6Total / n : 0;

    return {
      scenario: scId,
      ipv4Total: v4Total,
      ipv6Total: v6Total,
      ipv4Val: v4Val,
      ipv6Val: v6Val,
      sampleSize: n,
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
    const isV6 = selectedEntry.family === 'IPv6';
    setSelectedEntry((prev) =>
      prev
        ? {
            ...prev,
            count: isV6 ? currentData.ipv6Total : currentData.ipv4Total,
            observedValue: isV6 ? currentData.ipv6Val : currentData.ipv4Val,
            sampleSize: currentData.sampleSize,
            compCount: isV6 ? currentData.ipv4Total : currentData.ipv6Total,
            compObservedValue: isV6 ? currentData.ipv4Val : currentData.ipv6Val,
          }
        : null
    );
  }, [scenarios, effectiveBrowser, displayMode, trials]);

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold text-black">Graph 5 — SYN Retransmission Analysis</CardTitle>
          <CardDescription className="text-xs text-black">Select at least one scenario to inspect retransmission observations.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-black border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  const handleBarSelect = (scenario: string, family: 'IPv6' | 'IPv4') => {
    if (
      selectedEntry &&
      selectedEntry.scenario === scenario &&
      selectedEntry.family === family
    ) {
      setSelectedEntry(null);
    } else {
      const scData = data.find((d) => d.scenario === scenario);
      if (scData) {
        const isV6 = family === 'IPv6';
        setSelectedEntry({
          scenario,
          family,
          familyLabel: isV6 ? 'IPv6 SYN Retransmissions' : 'IPv4 SYN Retransmissions',
          count: isV6 ? scData.ipv6Total : scData.ipv4Total,
          observedValue: isV6 ? scData.ipv6Val : scData.ipv4Val,
          sampleSize: scData.sampleSize,
          compFamilyLabel: isV6 ? 'IPv4 SYN Retransmissions' : 'IPv6 SYN Retransmissions',
          compCount: isV6 ? scData.ipv4Total : scData.ipv6Total,
          compObservedValue: isV6 ? scData.ipv4Val : scData.ipv6Val,
        });
      }
    }
  };

  const width = 640;
  const height = 280;
  const margin = { top: 25, right: 30, bottom: 45, left: 55 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const allVals = data.flatMap((d) => [d.ipv4Val, d.ipv6Val]);
  const rawMax = Math.max(...allVals, 2);
  const maxVal = rawMax < 5 ? 5 : rawMax * 1.2;

  const groupWidth = innerWidth / scenarios.length;
  const barWidth = Math.min(26, groupWidth * 0.35);

  const hasSelection = selectedEntry !== null;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-black">
              Graph 5 — SYN Retransmission Analysis
            </CardTitle>
            <CardDescription className="text-xs text-black mt-0.5">
              Empirically observed TCP SYN retransmission counts across address families.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Display Mode */}
            <div className="flex items-center rounded-md border bg-background p-0.5">
              <button
                type="button"
                onClick={() => setDisplayMode('total')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  displayMode === 'total'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-black hover:opacity-80'
                }`}
              >
                Total Observed
              </button>
              <button
                type="button"
                onClick={() => setDisplayMode('mean')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  displayMode === 'mean'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-black hover:opacity-80'
                }`}
              >
                Mean / Trial
              </button>
            </div>

            {/* Local Browser Filter */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
              aria-label="Filter browser for Graph 5"
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
            aria-label="SYN Retransmission Analysis Bar Chart"
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
                    {displayMode === 'total' ? val.toFixed(0) : val.toFixed(2)}
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

            {/* Bar Groups */}
            {data.map((d, i) => {
              const centerX = margin.left + i * groupWidth + groupWidth / 2;

              const v6Height = (d.ipv6Val / maxVal) * innerHeight;
              const v4Height = (d.ipv4Val / maxVal) * innerHeight;

              const v6X = centerX - barWidth - 2;
              const v4X = centerX + 2;

              const isV6Selected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.family === 'IPv6';
              const isV4Selected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.family === 'IPv4';

              return (
                <g
                  key={d.scenario}
                  onMouseEnter={() =>
                    setHoveredItem({
                      scenario: d.scenario,
                      ipv4Count: d.ipv4Total,
                      ipv6Count: d.ipv6Total,
                      sampleSize: d.sampleSize,
                    })
                  }
                  onMouseLeave={() => setHoveredItem(null)}
                >
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-black text-black"
                  >
                    {d.scenario}
                  </text>

                  {/* IPv6 SYN Retransmissions Bar */}
                  <rect
                    x={v6X}
                    y={height - margin.bottom - v6Height}
                    width={barWidth}
                    height={Math.max(2, v6Height)}
                    rx={3}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isV6Selected}
                    aria-label={`Select ${d.scenario} IPv6 Retransmissions: ${d.ipv6Total} (${d.ipv6Val.toFixed(2)}/trial)`}
                    stroke={isV6Selected ? '#000000' : 'none'}
                    strokeWidth={isV6Selected ? 3 : 0}
                    opacity={isV6Selected ? 1 : hasSelection ? 0.45 : 1}
                    className="fill-rose-600 dark:fill-rose-500 hover:opacity-85 cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px] transition-all"
                    onClick={() => handleBarSelect(d.scenario, 'IPv6')}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleBarSelect(d.scenario, 'IPv6');
                      }
                    }}
                  />

                  {/* IPv4 SYN Retransmissions Bar */}
                  <rect
                    x={v4X}
                    y={height - margin.bottom - v4Height}
                    width={barWidth}
                    height={Math.max(2, v4Height)}
                    rx={3}
                    role="button"
                    tabIndex={0}
                    aria-pressed={isV4Selected}
                    aria-label={`Select ${d.scenario} IPv4 Retransmissions: ${d.ipv4Total} (${d.ipv4Val.toFixed(2)}/trial)`}
                    stroke={isV4Selected ? '#000000' : 'none'}
                    strokeWidth={isV4Selected ? 3 : 0}
                    opacity={isV4Selected ? 1 : hasSelection ? 0.45 : 1}
                    className="fill-amber-600 dark:fill-amber-500 hover:opacity-85 cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px] transition-all"
                    onClick={() => handleBarSelect(d.scenario, 'IPv4')}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleBarSelect(d.scenario, 'IPv4');
                      }
                    }}
                  />
                </g>
              );
            })}
          </svg>
        </div>

        {/* Selected Entry Detail Panel */}
        {selectedEntry && (
          <div
            data-testid="graph-5-selected-panel"
            className="mt-3 p-3 rounded-lg border-2 border-black/30 bg-muted/30 text-black text-xs space-y-2 animate-fade-in"
          >
            <div className="flex items-center justify-between border-b border-black/15 pb-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-black text-white">
                  Active Selection
                </span>
                <span className="font-bold text-black text-sm">
                  {selectedEntry.scenario} &bull; {selectedEntry.familyLabel}
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
                <span className="font-semibold block text-[11px] text-black">Target Family:</span>
                <span className="font-mono text-black font-bold">{selectedEntry.family}</span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">
                  {displayMode === 'total' ? 'Total Retransmissions:' : 'Mean Retransmissions / Trial:'}
                </span>
                <span className="font-mono font-bold text-black text-sm">
                  {displayMode === 'total'
                    ? `${selectedEntry.count} retransmissions`
                    : `${selectedEntry.observedValue.toFixed(2)} / trial (${selectedEntry.count} total)`}
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
                  Comparison ({selectedEntry.compFamilyLabel}):
                </span>
                <span className="font-mono text-black">
                  {displayMode === 'total'
                    ? `${selectedEntry.compCount} retransmissions`
                    : `${selectedEntry.compObservedValue.toFixed(2)} / trial (${selectedEntry.compCount} total)`}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t text-xs text-black">
          <div className="flex items-center gap-1.5">
            <span className="size-3 rounded-xs bg-rose-600 dark:bg-rose-500" />
            <span className="text-black font-medium">IPv6 SYN Retransmissions</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-3 rounded-xs bg-amber-600 dark:bg-amber-500" />
            <span className="text-black font-medium">IPv4 SYN Retransmissions</span>
          </div>
        </div>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div className="p-2 rounded bg-popover text-black border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold text-black">{hoveredItem.scenario} Retransmissions:</span>
            <span className="font-mono ml-2 text-xs text-black">
              <span className="text-rose-700 dark:text-rose-400 font-bold">
                IPv6: {hoveredItem.ipv6Count}
              </span>
              {' &bull; '}
              <span className="text-amber-700 dark:text-amber-400 font-bold">
                IPv4: {hoveredItem.ipv4Count}
              </span>
              <span className="text-black ml-1">(trials n={hoveredItem.sampleSize})</span>
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
