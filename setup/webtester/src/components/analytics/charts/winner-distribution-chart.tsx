import React, { useState } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';

interface WinnerDistributionChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

export const WinnerDistributionChart: React.FC<WinnerDistributionChartProps> = ({
  trials,
  globalScenarios,
  globalBrowser,
}) => {
  const [displayMode, setDisplayMode] = useState<'percent' | 'count'>('percent');
  const [localBrowser, setLocalBrowser] = useState<BrowserFilterId | 'INHERIT'>('INHERIT');
  const [hoveredItem, setHoveredItem] = useState<{
    scenario: string;
    ipv6Wins: number;
    ipv4Wins: number;
    total: number;
    v6Pct: number;
    v4Pct: number;
  } | null>(null);

  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold">Graph 2 — IPv4 vs IPv6 Winner Distribution</CardTitle>
          <CardDescription>Select at least one scenario to inspect winner distribution.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-muted-foreground border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  // Aggregate winner counts per scenario
  const data = scenarios.map((scId) => {
    const scTrials = trials.filter(
      (t) =>
        t.scenario_id === scId &&
        (effectiveBrowser === 'ALL' || t.browser === effectiveBrowser) &&
        t.validity_category === 'VALID_LIVE'
    );

    let v6Wins = 0;
    let v4Wins = 0;

    for (const t of scTrials) {
      const winner = (t.primary_flow?.winning_family || t.primary_flow?.family || '').toLowerCase();
      if (winner === 'ipv6') v6Wins++;
      else if (winner === 'ipv4') v4Wins++;
    }

    const total = v6Wins + v4Wins;
    const v6Pct = total > 0 ? (v6Wins / total) * 100 : 0;
    const v4Pct = total > 0 ? (v4Wins / total) * 100 : 0;

    return {
      scenario: scId,
      ipv6Wins: v6Wins,
      ipv4Wins: v4Wins,
      total,
      v6Pct,
      v4Pct,
    };
  });

  const width = 640;
  const height = 280;
  const margin = { top: 25, right: 30, bottom: 45, left: 55 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const maxCount = Math.max(...data.map((d) => d.total), 20);
  const barWidth = Math.min(42, (innerWidth / scenarios.length) * 0.65);
  const groupWidth = innerWidth / scenarios.length;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-foreground">
              Graph 2 — IPv4 vs IPv6 Winner Distribution
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground mt-0.5">
              Stacked proportion of primary connection path winners across selected scenarios.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Toggle count / percentage */}
            <div className="flex items-center rounded-md border bg-background p-0.5">
              <button
                type="button"
                onClick={() => setDisplayMode('percent')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  displayMode === 'percent'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Percentage (%)
              </button>
              <button
                type="button"
                onClick={() => setDisplayMode('count')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  displayMode === 'count'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Count (n)
              </button>
            </div>

            {/* Local Browser Filter */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-foreground"
              aria-label="Filter browser for Graph 2"
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
            aria-label="Winner Distribution Stacked Bar Chart"
          >
            {/* Y Axis Gridlines and Labels */}
            {(displayMode === 'percent' ? [0, 25, 50, 75, 100] : [0, 0.25, 0.5, 0.75, 1]).map(
              (step) => {
                const ratio = displayMode === 'percent' ? step / 100 : step;
                const label =
                  displayMode === 'percent'
                    ? `${step}%`
                    : `${(step * maxCount).toFixed(0)}`;
                const y = margin.top + innerHeight * (1 - ratio);

                return (
                  <g key={step}>
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
                      {label}
                    </text>
                  </g>
                );
              }
            )}

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

            {/* Stacked Bars */}
            {data.map((d, i) => {
              const centerX = margin.left + i * groupWidth + groupWidth / 2;
              const barX = centerX - barWidth / 2;

              let v6Height = 0;
              let v4Height = 0;

              if (displayMode === 'percent') {
                v6Height = (d.v6Pct / 100) * innerHeight;
                v4Height = (d.v4Pct / 100) * innerHeight;
              } else {
                v6Height = maxCount > 0 ? (d.ipv6Wins / maxCount) * innerHeight : 0;
                v4Height = maxCount > 0 ? (d.ipv4Wins / maxCount) * innerHeight : 0;
              }

              const v6Y = height - margin.bottom - v6Height;
              const v4Y = v6Y - v4Height;

              return (
                <g
                  key={d.scenario}
                  className="cursor-pointer"
                  onMouseEnter={() => setHoveredItem(d)}
                  onMouseLeave={() => setHoveredItem(null)}
                >
                  {/* Scenario X Label */}
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-foreground"
                  >
                    {d.scenario}
                  </text>

                  {/* IPv6 Bar (Bottom Stack) */}
                  {v6Height > 0 && (
                    <rect
                      x={barX}
                      y={v6Y}
                      width={barWidth}
                      height={v6Height}
                      className="fill-emerald-600 dark:fill-emerald-500 hover:opacity-90 transition-opacity"
                    />
                  )}

                  {/* IPv4 Bar (Top Stack) */}
                  {v4Height > 0 && (
                    <rect
                      x={barX}
                      y={v4Y}
                      width={barWidth}
                      height={v4Height}
                      className="fill-blue-600 dark:fill-blue-500 hover:opacity-90 transition-opacity"
                    />
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Legend */}
        <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <span className="size-3 rounded-xs bg-emerald-600 dark:bg-emerald-500" />
            <span>IPv6 Preferred Winner</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-3 rounded-xs bg-blue-600 dark:bg-blue-500" />
            <span>IPv4 Fallback Winner</span>
          </div>
        </div>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div className="p-2 rounded bg-popover text-popover-foreground border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold">{hoveredItem.scenario} Breakdown:</span>
            <span className="font-mono ml-2 text-xs">
              <span className="text-emerald-700 dark:text-emerald-400 font-bold">
                IPv6: {hoveredItem.ipv6Wins} ({hoveredItem.v6Pct.toFixed(1)}%)
              </span>
              {' &bull; '}
              <span className="text-blue-700 dark:text-blue-400 font-bold">
                IPv4: {hoveredItem.ipv4Wins} ({hoveredItem.v4Pct.toFixed(1)}%)
              </span>
              <span className="text-muted-foreground ml-1">(total n={hoveredItem.total})</span>
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
