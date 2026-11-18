import React, { useState, useEffect } from 'react';
import type { HistoricalTrial, TimelineEvent } from '@/lib/historical-evidence';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import type { BrowserFilterId } from '@/lib/analytics/analytics-types';

interface ConnectionTimelineChartProps {
  trials: HistoricalTrial[];
  globalScenarios: string[];
  globalBrowser: BrowserFilterId;
}

export const ConnectionTimelineChart: React.FC<ConnectionTimelineChartProps> = ({
  trials,
  globalScenarios,
  globalBrowser,
}) => {
  const [selectedTrialId, setSelectedTrialId] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<'ALL' | 'HARNESS' | 'PCAP' | 'BROWSER_TELEMETRY'>('ALL');
  const [hoveredEvent, setHoveredEvent] = useState<TimelineEvent | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);

  // Filter available trials by selected scenarios & browser
  const availableTrials = trials.filter(
    (t) =>
      globalScenarios.includes(t.scenario_id) &&
      (globalBrowser === 'ALL' || t.browser === globalBrowser) &&
      t.validity_category === 'VALID_LIVE'
  );

  const activeTrial =
    availableTrials.find((t) => t.trial_id === selectedTrialId) ||
    availableTrials[0] ||
    null;

  // Filter events of the selected trial
  const rawEvents = activeTrial?.timeline_events || [];
  const filteredEvents = rawEvents.filter(
    (e) => sourceFilter === 'ALL' || e.source === sourceFilter
  );

  // Clear or reconcile selection when trial or source filter changes
  useEffect(() => {
    if (!selectedEvent) return;
    const exists = filteredEvents.some(
      (e) => e.timestamp === selectedEvent.timestamp && e.event_type === selectedEvent.event_type
    );
    if (!exists) {
      setSelectedEvent(null);
    }
  }, [activeTrial?.trial_id, sourceFilter, globalScenarios, globalBrowser]);

  if (availableTrials.length === 0 || !activeTrial) {
    return (
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base font-semibold text-black">Graph 7 — TCP Connection Event Timeline</CardTitle>
          <CardDescription className="text-xs text-black">Select at least one scenario to inspect protocol-level timeline events.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-xs text-black border border-dashed rounded-lg">
            No valid trials available for current selection
          </div>
        </CardContent>
      </Card>
    );
  }

  const handleEventSelect = (ev: TimelineEvent) => {
    if (
      selectedEvent &&
      selectedEvent.timestamp === ev.timestamp &&
      selectedEvent.event_type === ev.event_type &&
      selectedEvent.frame_number === ev.frame_number
    ) {
      setSelectedEvent(null);
    } else {
      setSelectedEvent(ev);
    }
  };

  // Calculate synchronized start and end timestamps
  const timestamps = rawEvents
    .map((e) => e.timestamp)
    .filter((ts): ts is number => typeof ts === 'number');

  const minTs = timestamps.length > 0 ? Math.min(...timestamps) : 0;
  const maxTs = timestamps.length > 0 ? Math.max(...timestamps) : 1;
  const durationSec = Math.max(0.001, maxTs - minTs);
  const durationMs = durationSec * 1000;

  // Split events into IPv6 lane, IPv4 lane, and General/Harness lane
  const v6Events = filteredEvents.filter((e) => e.family === 'IPv6');
  const v4Events = filteredEvents.filter((e) => e.family === 'IPv4');
  const systemEvents = filteredEvents.filter((e) => !e.family || e.source === 'HARNESS');

  const width = 800;
  const height = 280;
  const margin = { top: 35, right: 35, bottom: 45, left: 110 };
  const innerWidth = width - margin.left - margin.right;

  const lanes = [
    { id: 'v6', label: 'IPv6 Lane', events: v6Events, y: 70 },
    { id: 'v4', label: 'IPv4 Lane', events: v4Events, y: 130 },
    { id: 'sys', label: 'Harness / DNS', events: systemEvents, y: 190 },
  ];

  const getEventX = (ts: number) => {
    if (durationSec <= 0) return margin.left;
    const ratio = Math.max(0, Math.min(1, (ts - minTs) / durationSec));
    return margin.left + ratio * innerWidth;
  };

  const getSourceColor = (source: string) => {
    switch (source) {
      case 'PCAP':
        return 'fill-emerald-600 stroke-emerald-800 dark:fill-emerald-500';
      case 'BROWSER_TELEMETRY':
        return 'fill-blue-600 stroke-blue-800 dark:fill-blue-500';
      case 'HARNESS':
        return 'fill-amber-600 stroke-amber-800 dark:fill-amber-500';
      default:
        return 'fill-purple-600 stroke-purple-800 dark:fill-purple-500';
    }
  };

  const hasSelection = selectedEvent !== null;

  return (
    <Card className="shadow-xs overflow-hidden">
      <CardHeader className="pb-3 border-b bg-muted/15">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="text-base font-semibold text-black">
              Graph 7 — TCP Connection Event Timeline
            </CardTitle>
            <CardDescription className="text-xs text-black mt-0.5">
              Protocol-level Gantt view with synchronized HARNESS, PCAP, and BROWSER_TELEMETRY event markers.
            </CardDescription>
          </div>

          {/* Local Controls */}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* Trial Selector */}
            <div className="flex items-center gap-1">
              <span className="text-black font-medium">Trial:</span>
              <select
                value={activeTrial.trial_id}
                onChange={(e) => setSelectedTrialId(e.target.value)}
                className="px-2 py-0.5 text-[11px] rounded border bg-background text-black font-mono"
                aria-label="Select trial for timeline inspection"
              >
                {availableTrials.slice(0, 40).map((t) => (
                  <option key={t.trial_id} value={t.trial_id}>
                    {t.scenario_id} &bull; {t.browser === 'google-chrome' ? 'Chrome' : 'Firefox'} &bull; Rep {t.repetition} ({t.trial_id.slice(0, 12)})
                  </option>
                ))}
              </select>
            </div>

            {/* Source Filter */}
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value as any)}
              className="px-2 py-0.5 text-[11px] rounded border bg-background text-black"
              aria-label="Filter timeline sources"
            >
              <option value="ALL">All Event Sources</option>
              <option value="PCAP">PCAP Only</option>
              <option value="BROWSER_TELEMETRY">Telemetry Only</option>
              <option value="HARNESS">Harness Only</option>
            </select>
          </div>
        </div>
      </CardHeader>

      <CardContent className="pt-4 relative">
        <div className="w-full overflow-x-auto">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full h-auto min-w-[650px] select-none"
            aria-label="Interactive Protocol Event Timeline"
          >
            {/* Time Gridlines & Offsets */}
            {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
              const x = margin.left + ratio * innerWidth;
              const offsetMs = ratio * durationMs;

              return (
                <g key={ratio}>
                  <line
                    x1={x}
                    y1={margin.top}
                    x2={x}
                    y2={height - margin.bottom}
                    stroke="currentColor"
                    strokeDasharray="2 2"
                    className="text-border/40"
                  />
                  <text
                    x={x}
                    y={height - margin.bottom + 18}
                    textAnchor="middle"
                    className="text-[10px] fill-black text-black font-mono"
                  >
                    +{offsetMs.toFixed(1)} ms
                  </text>
                </g>
              );
            })}

            {/* Lane Tracks and Labels */}
            {lanes.map((lane) => (
              <g key={lane.id}>
                {/* Lane Track Line */}
                <line
                  x1={margin.left}
                  y1={lane.y}
                  x2={width - margin.right}
                  y2={lane.y}
                  stroke="currentColor"
                  strokeWidth={2}
                  className="text-border/60"
                />

                {/* Lane Name Label */}
                <text
                  x={margin.left - 12}
                  y={lane.y + 4}
                  textAnchor="end"
                  className="text-xs font-semibold fill-black text-black"
                >
                  {lane.label}
                </text>

                {/* Event Markers */}
                {lane.events.map((ev, idx) => {
                  const evX = getEventX(ev.timestamp);
                  const isHovered = hoveredEvent === ev;
                  const isSelected =
                    selectedEvent?.timestamp === ev.timestamp &&
                    selectedEvent?.event_type === ev.event_type &&
                    selectedEvent?.frame_number === ev.frame_number;

                  return (
                    <g
                      key={idx}
                      className="cursor-pointer outline-none transition-all"
                      opacity={isSelected ? 1 : hasSelection ? 0.45 : 1}
                      onMouseEnter={() => setHoveredEvent(ev)}
                      onMouseLeave={() => setHoveredEvent(null)}
                    >
                      {/* Vertical Pin Line */}
                      <line
                        x1={evX}
                        y1={lane.y - (isSelected ? 16 : 12)}
                        x2={evX}
                        y2={lane.y + (isSelected ? 16 : 12)}
                        stroke={isSelected ? '#000000' : isHovered ? 'currentColor' : 'currentColor'}
                        strokeWidth={isSelected ? 2.5 : isHovered ? 2 : 1}
                        className={isSelected ? '' : isHovered ? 'text-primary' : 'text-border'}
                        onClick={() => handleEventSelect(ev)}
                      />

                      {/* Event Dot */}
                      <circle
                        cx={evX}
                        cy={lane.y}
                        r={isSelected ? 7 : isHovered ? 6 : 4}
                        role="button"
                        tabIndex={0}
                        aria-pressed={isSelected}
                        aria-label={`Select event: ${ev.event_type} at +${((ev.timestamp - minTs) * 1000).toFixed(1)} ms`}
                        stroke={isSelected ? '#000000' : undefined}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                        className={`${getSourceColor(ev.source)} cursor-pointer transition-all outline-none focus-visible:stroke-black focus-visible:stroke-[2.5px]`}
                        onClick={() => handleEventSelect(ev)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleEventSelect(ev);
                          }
                        }}
                      />
                    </g>
                  );
                })}
              </g>
            ))}
          </svg>
        </div>

        {/* Selected Entry Detail Panel */}
        {selectedEvent && (
          <div
            data-testid="graph-7-selected-panel"
            className="mt-3 p-3 rounded-lg border-2 border-black/30 bg-muted/30 text-black text-xs space-y-2 animate-fade-in"
          >
            <div className="flex items-center justify-between border-b border-black/15 pb-1.5">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-black text-white">
                  Active Selection
                </span>
                <span className="font-bold text-black text-sm">
                  {selectedEvent.event_type} {selectedEvent.family ? `(${selectedEvent.family})` : ''} &bull;{' '}
                  <span className="font-mono text-xs">{selectedEvent.source}</span>
                </span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedEvent(null)}
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
                <span className="font-semibold block text-[11px] text-black">Trial Cohort:</span>
                <span className="font-mono text-black">
                  {activeTrial.scenario_id} &bull; {activeTrial.browser === 'google-chrome' ? 'Chrome' : 'Firefox'} (Rep {activeTrial.repetition})
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Relative Offset:</span>
                <span className="font-mono font-bold text-black text-sm">
                  +{((selectedEvent.timestamp - minTs) * 1000).toFixed(2)} ms
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Absolute Timestamp:</span>
                <span className="font-mono text-black text-[11px]">
                  {selectedEvent.timestamp.toFixed(6)}s
                </span>
              </div>
              <div>
                <span className="font-semibold block text-[11px] text-black">Frame / Stream:</span>
                <span className="font-mono text-black">
                  Frame #{selectedEvent.frame_number ?? '—'} &bull; Stream: {selectedEvent.stream_id ?? 'N/A'}
                </span>
              </div>
            </div>

            <div className="pt-1.5 border-t border-black/10 text-black text-[11px]">
              <span className="font-semibold text-black">Event Details:</span>{' '}
              <span className="text-black">{selectedEvent.details}</span>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-between gap-2 mt-2 pt-2 border-t text-xs text-black">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-emerald-600 dark:bg-emerald-500" />
              <span className="text-black font-medium">PCAP Frame Event</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-blue-600 dark:bg-blue-500" />
              <span className="text-black font-medium">Browser Telemetry Event</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-amber-600 dark:bg-amber-500" />
              <span className="text-black font-medium">Harness Lifecycle Event</span>
            </div>
          </div>

          <div className="font-mono text-[11px] text-black">
            Total span: {durationMs.toFixed(2)} ms &bull; {filteredEvents.length} events
          </div>
        </div>

        {/* Floating Tooltip */}
        {hoveredEvent && (
          <div className="p-2.5 rounded bg-popover text-black border text-xs shadow-md mt-2 space-y-1">
            <div className="font-semibold flex items-center justify-between border-b pb-1 text-black">
              <span className="flex items-center gap-1.5 text-black">
                <span className="px-1.5 py-0.2 rounded bg-primary/20 text-black font-mono text-[10px]">
                  {hoveredEvent.source}
                </span>
                {hoveredEvent.event_type} {hoveredEvent.family ? `(${hoveredEvent.family})` : ''}
              </span>
              <span className="font-mono text-black text-[10px]">
                Frame #{hoveredEvent.frame_number ?? '—'}
              </span>
            </div>
            <div className="text-black text-[11px]">{hoveredEvent.details}</div>
            <div className="text-[10px] text-black font-mono flex items-center justify-between pt-0.5">
              <span>Epoch: {hoveredEvent.timestamp.toFixed(6)}s</span>
              <span>Stream ID: {hoveredEvent.stream_id ?? 'N/A'}</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
