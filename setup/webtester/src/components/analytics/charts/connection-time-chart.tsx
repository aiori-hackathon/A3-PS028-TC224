import React, { useState } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { computeCohortMetrics } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';

interface ConnectionTimeChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

export const ConnectionTimeChart: React.FC<ConnectionTimeChartProps> = ({
  trials,
  globalScenarios,
  globalBrowser,
}) => {
  // Local card state
  const [metric, setMetric] = useState<'t_connect_ms' | 't_setup_total_ms'>('t_connect_ms');
  const [localBrowser, setLocalBrowser] = useState<BrowserFilterId | 'INHERIT'>('INHERIT');
  const [hoveredItem, setHoveredItem] = useState<{
    scenario: string;
    browser: string;
    value: number | null;
    sampleSize: number;
    x: number;
    y: number;
  } | null>(null);

  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold">Graph 1 — Connection Establishment Time</CardTitle>
          <CardDescription>Select at least one scenario to display connection timing.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-muted-foreground border border-dashed rounded-lg">
            No scenario selected
          </div>
        </CardContent>
      </Card>
    );
  }

  // Calculate cohort medians for each scenario
  const data = scenarios.map((scId) => {
    const chromeStats = computeCohortMetrics(trials, scId, 'google-chrome');
    const firefoxStats = computeCohortMetrics(trials, scId, 'firefox');

    const chromeVal =
      metric === 't_connect_ms' ? chromeStats.tConnectMedian : chromeStats.tSetupTotalMedian;
    const firefoxVal =
      metric === 't_connect_ms' ? firefoxStats.tConnectMedian : firefoxStats.tSetupTotalMedian;

    return {
      scenario: scId,
      chrome: chromeVal,
      chromeN: chromeStats.sampleSize,
      firefox: firefoxVal,
      firefoxN: firefoxStats.sampleSize,
    };
  });

  // Calculate chart scale
  const allValues = data
    .flatMap((d) => [
      effectiveBrowser === 'firefox' ? null : d.chrome,
      effectiveBrowser === 'google-chrome' ? null : d.firefox,
    ])
    .filter((v): v is number => typeof v === 'number');

  const maxVal = allValues.length > 0 ? Math.max(...allValues, 50) * 1.15 : 100;

  const width = 640;
  const height = 280;
  const margin = { top: 25, right: 30, bottom: 45, left: 55 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const groupWidth = innerWidth / scenarios.length;
  const barWidth = Math.min(30, (groupWidth * 0.7) / (effectiveBrowser === 'ALL' ? 2 : 1));

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-foreground">
              Graph 1 — Connection Establishment Time
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground mt-0.5">
              Grouped median comparison between Chrome and Firefox ({metric === 't_connect_ms' ? 'RFC 9293 Handshake' : 'Total Setup'}).
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Metric Toggle */}
            <div className="flex items-center rounded-md border bg-background p-0.5">
              <button
                type="button"
                onClick={() => setMetric('t_connect_ms')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  metric === 't_connect_ms'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                t_connect
              </button>
              <button
                type="button"
                onClick={() => setMetric('t_setup_total_ms')}
                className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                  metric === 't_setup_total_ms'
                    ? 'bg-primary text-primary-foreground font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                t_setup_total
              </button>
            </div>

            {/* Local Browser Filter */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-foreground"
              aria-label="Filter browser for Graph 1"
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
            aria-label="Connection Establishment Time Bar Chart"
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

            {/* X and Y Axis lines */}
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
              const groupX = margin.left + i * groupWidth;
              const centerX = groupX + groupWidth / 2;

              const chromeHeight =
                typeof d.chrome === 'number' ? (d.chrome / maxVal) * innerHeight : 0;
              const firefoxHeight =
                typeof d.firefox === 'number' ? (d.firefox / maxVal) * innerHeight : 0;

              const showChrome = effectiveBrowser === 'ALL' || effectiveBrowser === 'google-chrome';
              const showFirefox = effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox';

              const chromeX = effectiveBrowser === 'ALL' ? centerX - barWidth - 2 : centerX - barWidth / 2;
              const firefoxX = effectiveBrowser === 'ALL' ? centerX + 2 : centerX - barWidth / 2;

              return (
                <g key={d.scenario}>
                  {/* Scenario X label */}
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-foreground"
                  >
                    {d.scenario}
                  </text>

                  {/* Chrome Bar */}
                  {showChrome && (
                    <rect
                      x={chromeX}
                      y={height - margin.bottom - chromeHeight}
                      width={barWidth}
                      height={Math.max(2, chromeHeight)}
                      rx={3}
                      className="fill-blue-600 dark:fill-blue-500 hover:opacity-80 transition-opacity cursor-pointer"
                      onMouseEnter={(e) =>
                        setHoveredItem({
                          scenario: d.scenario,
                          browser: 'Google Chrome',
                          value: d.chrome,
                          sampleSize: d.chromeN,
                          x: e.clientX,
                          y: e.clientY,
                        })
                      }
                      onMouseLeave={() => setHoveredItem(null)}
                    />
                  )}

                  {/* Firefox Bar */}
                  {showFirefox && (
                    <rect
                      x={firefoxX}
                      y={height - margin.bottom - firefoxHeight}
                      width={barWidth}
                      height={Math.max(2, firefoxHeight)}
                      rx={3}
                      className="fill-amber-600 dark:fill-amber-500 hover:opacity-80 transition-opacity cursor-pointer"
                      onMouseEnter={(e) =>
                        setHoveredItem({
                          scenario: d.scenario,
                          browser: 'Mozilla Firefox',
                          value: d.firefox,
                          sampleSize: d.firefoxN,
                          x: e.clientX,
                          y: e.clientY,
                        })
                      }
                      onMouseLeave={() => setHoveredItem(null)}
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
              <span className="size-3 rounded-xs bg-blue-600 dark:bg-blue-500" />
              <span>Google Chrome (Median)</span>
            </div>
          )}
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-amber-600 dark:bg-amber-500" />
              <span>Mozilla Firefox (Median)</span>
            </div>
          )}
        </div>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div className="p-2 rounded bg-popover text-popover-foreground border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold">
              {hoveredItem.scenario} &bull; {hoveredItem.browser}:
            </span>
            <span className="font-mono ml-2 font-bold text-primary">
              {hoveredItem.value !== null ? `${hoveredItem.value.toFixed(2)} ms` : 'N/A'}{' '}
              <span className="text-muted-foreground font-sans font-normal">(n={hoveredItem.sampleSize})</span>
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
