import React from 'react';
import type { OverallSummaryStats } from '@/lib/analytics/analytics-types';
import {
  Activity,
  Layers,
  Clock,
  Compass,
  Network,
  RefreshCw,
  AlertCircle,
} from 'lucide-react';

interface AnalyticsSummaryProps {
  summary: OverallSummaryStats;
  selectedScenarios: string[];
}

export const AnalyticsSummary: React.FC<AnalyticsSummaryProps> = ({
  summary,
  selectedScenarios,
}) => {
  if (selectedScenarios.length === 0 || summary.validTrialsCount === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border p-6 text-center bg-card/40">
        <AlertCircle className="size-8 mx-auto text-muted-foreground mb-2" />
        <h4 className="font-semibold text-sm text-foreground">No Scenarios Selected</h4>
        <p className="text-xs text-muted-foreground mt-1">
          Select one or more scenarios from the selector above to calculate analytical statistics.
        </p>
      </div>
    );
  }

  const { baselineComparison } = summary;

  return (
    <div className="space-y-4">
      {/* 4-Card Primary Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {/* Card 1: Sample & Coverage */}
        <div className="p-3.5 rounded-lg border bg-card shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs font-medium">Cohort Coverage</span>
            <Layers className="size-4 text-primary" />
          </div>
          <div>
            <div className="text-xl sm:text-2xl font-bold font-mono text-foreground">
              {summary.validTrialsCount}
              <span className="text-xs text-muted-foreground font-sans ml-1 font-normal">trials</span>
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              {summary.selectedScenariosCount} scenario{summary.selectedScenariosCount > 1 ? 's' : ''} &bull;{' '}
              Chrome: {summary.chromeTrialsCount}, Firefox: {summary.firefoxTrialsCount}
            </div>
          </div>
        </div>

        {/* Card 2: Median t_connect */}
        <div className="p-3.5 rounded-lg border bg-card shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs font-medium">Median t_connect</span>
            <Clock className="size-4 text-primary" />
          </div>
          <div>
            <div className="text-xl sm:text-2xl font-bold font-mono text-foreground">
              {summary.tConnectMedian !== null ? `${summary.tConnectMedian.toFixed(2)}` : '—'}
              <span className="text-xs text-muted-foreground font-sans ml-1 font-normal">ms</span>
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              {baselineComparison?.tConnectDeltaMs !== null &&
              typeof baselineComparison?.tConnectDeltaMs === 'number' ? (
                <span
                  className={
                    baselineComparison.tConnectDeltaMs > 0
                      ? 'text-amber-700 dark:text-amber-400 font-medium'
                      : 'text-emerald-700 dark:text-emerald-400 font-medium'
                  }
                >
                  {baselineComparison.tConnectDeltaMs >= 0 ? '+' : ''}
                  {baselineComparison.tConnectDeltaMs.toFixed(2)} ms vs S0
                </span>
              ) : (
                'Strict winning TCP handshake'
              )}
            </div>
          </div>
        </div>

        {/* Card 3: Median t_setup_total */}
        <div className="p-3.5 rounded-lg border bg-card shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs font-medium">Median t_setup_total</span>
            <Activity className="size-4 text-primary" />
          </div>
          <div>
            <div className="text-xl sm:text-2xl font-bold font-mono text-foreground">
              {summary.tSetupTotalMedian !== null ? `${summary.tSetupTotalMedian.toFixed(2)}` : '—'}
              <span className="text-xs text-muted-foreground font-sans ml-1 font-normal">ms</span>
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              {baselineComparison?.tSetupDeltaMs !== null &&
              typeof baselineComparison?.tSetupDeltaMs === 'number' ? (
                <span
                  className={
                    baselineComparison.tSetupDeltaMs > 0
                      ? 'text-amber-700 dark:text-amber-400 font-medium'
                      : 'text-emerald-700 dark:text-emerald-400 font-medium'
                  }
                >
                  {baselineComparison.tSetupDeltaMs >= 0 ? '+' : ''}
                  {baselineComparison.tSetupDeltaMs.toFixed(2)} ms vs S0
                </span>
              ) : (
                'Total transport setup time'
              )}
            </div>
          </div>
        </div>

        {/* Card 4: Address Family Winner Ratio */}
        <div className="p-3.5 rounded-lg border bg-card shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground mb-1">
            <span className="text-xs font-medium">Winner Distribution</span>
            <Compass className="size-4 text-primary" />
          </div>
          <div>
            <div className="text-xl sm:text-2xl font-bold font-mono text-foreground flex items-center gap-1.5">
              <span className="text-emerald-700 dark:text-emerald-400">
                {summary.ipv6WinPercentage !== null ? `${summary.ipv6WinPercentage.toFixed(0)}%` : '—'}
              </span>
              <span className="text-xs text-muted-foreground font-normal font-sans">v6 /</span>
              <span className="text-blue-700 dark:text-blue-400">
                {summary.ipv4WinPercentage !== null ? `${summary.ipv4WinPercentage.toFixed(0)}%` : '—'}
              </span>
              <span className="text-xs text-muted-foreground font-normal font-sans">v4</span>
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              IPv6 wins: {summary.ipv6WinCount} &bull; IPv4 wins: {summary.ipv4WinCount}
            </div>
          </div>
        </div>
      </div>

      {/* Secondary Metrics Bar: DNS and Retransmission Statistics */}
      <div className="rounded-lg border bg-card/60 p-3 flex flex-wrap items-center justify-between gap-y-2 gap-x-6 text-xs text-muted-foreground">
        <div className="flex items-center gap-2">
          <Network className="size-3.5 text-primary" />
          <span className="font-medium text-foreground">DNS Latency Medians:</span>
          <span>
            A:{' '}
            <strong className="text-foreground font-mono">
              {summary.dnsAMedian !== null ? `${summary.dnsAMedian.toFixed(2)} ms` : '—'}
            </strong>
          </span>
          <span className="text-border">&bull;</span>
          <span>
            AAAA:{' '}
            <strong className="text-foreground font-mono">
              {summary.dnsAAAAMedian !== null ? `${summary.dnsAAAAMedian.toFixed(2)} ms` : '—'}
            </strong>
          </span>
          <span className="text-border">&bull;</span>
          <span>
            Resolution:{' '}
            <strong className="text-foreground font-mono">
              {summary.dnsResolutionMedian !== null
                ? `${summary.dnsResolutionMedian.toFixed(2)} ms`
                : '—'}
            </strong>
          </span>
        </div>

        <div className="flex items-center gap-2">
          <RefreshCw className="size-3.5 text-primary" />
          <span className="font-medium text-foreground">Observed SYN Retransmissions:</span>
          <span>
            IPv6:{' '}
            <strong className="text-foreground font-mono">{summary.retransIpv6Total}</strong> packets
          </span>
          <span className="text-border">&bull;</span>
          <span>
            IPv4:{' '}
            <strong className="text-foreground font-mono">{summary.retransIpv4Total}</strong> packets
          </span>
        </div>
      </div>
    </div>
  );
};
