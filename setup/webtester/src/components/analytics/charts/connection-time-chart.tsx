import React, { useState, useEffect } from 'react';
import type { HistoricalTrial } from '@/lib/historical-evidence';
import { computeCohortMetrics } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';

interface ConnectionTimeChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

interface SelectedConnectionEntry {
  scenario: string;
  browser: string;
  browserKey: 'google-chrome' | 'firefox';
  value: number | null;
  sampleSize: number;
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

  const [selectedEntry, setSelectedEntry] = useState<SelectedConnectionEntry | null>(null);

  const effectiveBrowser = localBrowser === 'INHERIT' ? globalBrowser : localBrowser;
  const scenarios = globalScenarios;

  // Clear or reconcile selection when filters change
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
    const scStats = computeCohortMetrics(trials, selectedEntry.scenario, selectedEntry.browserKey);
    const updatedVal = metric === 't_connect_ms' ? scStats.tConnectMedian : scStats.tSetupTotalMedian;
    setSelectedEntry((prev) =>
      prev ? { ...prev, value: updatedVal, sampleSize: scStats.sampleSize } : null
    );
  }, [scenarios, effectiveBrowser, metric, trials]);

  if (scenarios.length === 0) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold">Graph 1 — Connection Establishment Time</CardTitle>
          <CardDescription className="text-xs text-black">Select at least one scenario to display connection timing.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-black border border-dashed rounded-lg">
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

  const handleBarSelect = (item: SelectedConnectionEntry) => {
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

  // Find comparison metrics for active selection
  const comparisonInfo = selectedEntry
    ? (() => {
        const scData = data.find((d) => d.scenario === selectedEntry.scenario);
        if (!scData) return null;
        const isChrome = selectedEntry.browserKey === 'google-chrome';
        const compBrowserName = isChrome ? 'Mozilla Firefox' : 'Google Chrome';
        const compVal = isChrome ? scData.firefox : scData.chrome;
        const compN = isChrome ? scData.firefoxN : scData.chromeN;
        const diff =
          selectedEntry.value !== null && compVal !== null
            ? selectedEntry.value - compVal
            : null;
        return { compBrowserName, compVal, compN, diff };
      })()
    : null;

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

  const hasSelection = selectedEntry !== null;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-black">
              Graph 1 — Connection Establishment Time
            </CardTitle>
            <CardDescription className="text-xs text-black mt-0.5">
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
                    : 'text-black hover:opacity-80'
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
                    : 'text-black hover:opacity-80'
                }`}
              >
                t_setup_total
              </button>
            </div>

            {/* Local Browser Filter */}
            <select
              value={localBrowser}
              onChange={(e) => setLocalBrowser(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
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
                    className="text-[10px] fill-black text-black font-mono"
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

              const isChromeSelected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.browserKey === 'google-chrome';
              const isFirefoxSelected =
                selectedEntry?.scenario === d.scenario && selectedEntry?.browserKey === 'firefox';

              return (
                <g key={d.scenario}>
                  {/* Scenario X label */}
                  <text
                    x={centerX}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-xs font-semibold fill-black text-black"
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
                      role="button"
                      tabIndex={0}
                      aria-pressed={isChromeSelected}
                      aria-label={`Select ${d.scenario} Google Chrome ${metric}: ${d.chrome !== null ? `${d.chrome.toFixed(2)} ms` : 'N/A'}`}
                      stroke={isChromeSelected ? '#000000' : 'none'}
                      strokeWidth={isChromeSelected ? 3 : 0}
                      opacity={isChromeSelected ? 1 : hasSelection ? 0.45 : 1}
                      className="fill-blue-600 dark:fill-blue-500 hover:opacity-90 transition-all cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px]"
                      onClick={() =>
                        handleBarSelect({
                          scenario: d.scenario,
                          browser: 'Google Chrome',
                          browserKey: 'google-chrome',
                          value: d.chrome,
                          sampleSize: d.chromeN,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleBarSelect({
                            scenario: d.scenario,
                            browser: 'Google Chrome',
                            browserKey: 'google-chrome',
                            value: d.chrome,
                            sampleSize: d.chromeN,
                          });
                        }
                      }}
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
                      role="button"
                      tabIndex={0}
                      aria-pressed={isFirefoxSelected}
                      aria-label={`Select ${d.scenario} Mozilla Firefox ${metric}: ${d.firefox !== null ? `${d.firefox.toFixed(2)} ms` : 'N/A'}`}
                      stroke={isFirefoxSelected ? '#000000' : 'none'}
                      strokeWidth={isFirefoxSelected ? 3 : 0}
                      opacity={isFirefoxSelected ? 1 : hasSelection ? 0.45 : 1}
                      className="fill-amber-600 dark:fill-amber-500 hover:opacity-90 transition-all cursor-pointer outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px]"
                      onClick={() =>
                        handleBarSelect({
                          scenario: d.scenario,
                          browser: 'Mozilla Firefox',
                          browserKey: 'firefox',
                          value: d.firefox,
                          sampleSize: d.firefoxN,
                        })
                      }
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          handleBarSelect({
                            scenario: d.scenario,
                            browser: 'Mozilla Firefox',
                            browserKey: 'firefox',
                            value: d.firefox,
                            sampleSize: d.firefoxN,
                          });
                        }
                      }}
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

        {/* Selected Entry Detail Panel (Persistent until deselected or dismissed) */}
        {selectedEntry && (
          <div
            data-testid="graph-1-selected-panel"
            className="mt-3 p-3 rounded-lg border-2 border-black/30 bg-muted/30 text-black text-xs space-y-2 animate-fade-in"
          >
            <div className="flex items-center justify-between border-b border-black/15 pb-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-black text-white">
                  Active Selection
                </span>
                <span className="font-bold text-black text-sm">
                  {selectedEntry.scenario} &bull; {selectedEntry.browser}
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
                <span className="font-mono text-black">
                  {metric === 't_connect_ms' ? 't_connect (TCP)' : 't_setup_total (Total)'}
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Measured Median:</span>
                <span className="font-mono font-bold text-black">
                  {selectedEntry.value !== null ? `${selectedEntry.value.toFixed(2)} ms` : 'N/A'}
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Cohort Sample:</span>
                <span className="font-mono text-black">n = {selectedEntry.sampleSize} live trials</span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">
                  {comparisonInfo ? `Vs. ${comparisonInfo.compBrowserName}:` : 'Comparison:'}
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
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'google-chrome') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-blue-600 dark:bg-blue-500" />
              <span className="text-black font-medium">Google Chrome (Median)</span>
            </div>
          )}
          {(effectiveBrowser === 'ALL' || effectiveBrowser === 'firefox') && (
            <div className="flex items-center gap-1.5">
              <span className="size-3 rounded-xs bg-amber-600 dark:bg-amber-500" />
              <span className="text-black font-medium">Mozilla Firefox (Median)</span>
            </div>
          )}
        </div>

        {/* Floating Tooltip */}
        {hoveredItem && (
          <div className="p-2 rounded bg-popover text-black border text-xs shadow-md pointer-events-none mt-2 flex items-center justify-between">
            <span className="font-semibold text-black">
              {hoveredItem.scenario} &bull; {hoveredItem.browser}:
            </span>
            <span className="font-mono ml-2 font-bold text-black">
              {hoveredItem.value !== null ? `${hoveredItem.value.toFixed(2)} ms` : 'N/A'}{' '}
              <span className="text-black font-sans font-normal">(n={hoveredItem.sampleSize})</span>
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
