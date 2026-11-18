import React from 'react';
import type { SupportedMetricKey } from '@/lib/analytics/analytics-types';
import { SUPPORTED_METRICS } from '@/lib/analytics/analytics-types';
import { SlidersHorizontal } from 'lucide-react';

interface MetricSelectorProps {
  selectedMetric: SupportedMetricKey;
  onChange: (metric: SupportedMetricKey) => void;
  allowedMetrics?: SupportedMetricKey[];
}

export const MetricSelector: React.FC<MetricSelectorProps> = ({
  selectedMetric,
  onChange,
  allowedMetrics,
}) => {
  const metricsToDisplay = allowedMetrics
    ? allowedMetrics.map((k) => SUPPORTED_METRICS[k])
    : Object.values(SUPPORTED_METRICS);

  return (
    <div className="flex items-center gap-1.5 bg-background p-1 rounded-lg border text-xs sm:text-sm">
      <div className="flex items-center gap-1 px-2 text-muted-foreground font-medium">
        <SlidersHorizontal className="size-3.5" />
        <span className="hidden sm:inline">Metric:</span>
      </div>
      <select
        value={selectedMetric}
        onChange={(e) => onChange(e.target.value as SupportedMetricKey)}
        className="px-2 py-1 text-xs rounded border-0 bg-transparent text-foreground font-medium focus:ring-0 cursor-pointer"
        aria-label="Select measurement metric"
      >
        {metricsToDisplay.map((m) => (
          <option key={m.key} value={m.key}>
            {m.label} ({m.unit})
          </option>
        ))}
      </select>
    </div>
  );
};
