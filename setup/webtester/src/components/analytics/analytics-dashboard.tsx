import React, { useState, useEffect, useMemo } from 'react';
import type { HistoricalDemoBundle, BundleProvenance, IntegrityEvaluation } from '@/lib/historical-evidence';
import { evaluateEvidenceIntegrity } from '@/lib/historical-evidence';
import { ALL_SCENARIOS } from '@/lib/analytics/analytics-filters';
import type { SupportedMetricKey, BrowserFilterId } from '@/lib/analytics/analytics-types';
import { computeOverallSummary } from '@/lib/analytics/analytics-calculations';
import { ScenarioSelector } from './scenario-selector';
import { BrowserSelector } from './browser-selector';
import { MetricSelector } from './metric-selector';
import { AnalyticsSummary } from './analytics-summary';
import { ConnectionTimeChart } from './charts/connection-time-chart';
import { WinnerDistributionChart } from './charts/winner-distribution-chart';
import { LatencyDistributionChart } from './charts/latency-distribution-chart';
import { DnsPerformanceChart } from './charts/dns-performance-chart';
import { RetransmissionChart } from './charts/retransmission-chart';
import { ScenarioHeatmap } from './charts/scenario-heatmap';
import { ConnectionTimelineChart } from './charts/connection-timeline-chart';
import { generateScenarioAnalysisPdf } from './reports/pdf-report-generator';
import {
  Download,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';

export const AnalyticsDashboard: React.FC = () => {
  const [bundle, setBundle] = useState<HistoricalDemoBundle | null>(null);
  const [provenance, setProvenance] = useState<BundleProvenance | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [computedSha256, setComputedSha256] = useState<string | null>(null);

  // Global Dashboard Filter State
  const [selectedScenarios, setSelectedScenarios] = useState<string[]>([...ALL_SCENARIOS]);
  const [selectedBrowser, setSelectedBrowser] = useState<BrowserFilterId>('ALL');
  const [selectedMetric, setSelectedMetric] = useState<SupportedMetricKey>('t_connect_ms');

  // PDF Generation State
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [pdfSuccessMessage, setPdfSuccessMessage] = useState<string | null>(null);
  const [pdfErrorMessage, setPdfErrorMessage] = useState<string | null>(null);

  // Load bundle and provenance sidecar on mount
  useEffect(() => {
    let isMounted = true;
    async function loadData() {
      try {
        setIsLoading(true);
        setLoadError(null);

        const [bundleRes, provRes] = await Promise.all([
          fetch('/data/demo_bundle.json'),
          fetch('/data/demo_bundle.json.provenance.json'),
        ]);

        if (!bundleRes.ok) {
          throw new Error(`Failed to load historical bundle: HTTP ${bundleRes.status} ${bundleRes.statusText}`);
        }
        if (!provRes.ok) {
          throw new Error(`Failed to load provenance sidecar: HTTP ${provRes.status} ${provRes.statusText}`);
        }

        const rawBundleBlob = await bundleRes.blob();
        const rawProvText = await provRes.text();

        // Calculate SHA-256 via SubtleCrypto
        let calculatedHash = '';
        if (window.crypto?.subtle) {
          const buffer = await rawBundleBlob.arrayBuffer();
          const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
          calculatedHash = Array.from(new Uint8Array(hashBuffer))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('');
        }

        const parsedBundle: HistoricalDemoBundle = JSON.parse(await rawBundleBlob.text());
        const parsedProv: BundleProvenance = JSON.parse(rawProvText);

        if (!isMounted) return;

        setBundle(parsedBundle);
        setProvenance(parsedProv);
        setComputedSha256(calculatedHash);
      } catch (err: any) {
        if (isMounted) {
          setLoadError(err.message || 'Unknown error loading historical evidence');
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    loadData();
    return () => {
      isMounted = false;
    };
  }, []);

  // Evidence integrity check
  const integrity: IntegrityEvaluation = useMemo(() => {
    return evaluateEvidenceIntegrity(computedSha256, provenance);
  }, [computedSha256, provenance]);

  // Valid trials array
  const allValidTrials = useMemo(() => {
    return (bundle?.trials ?? []).filter((t) => t.validity_category === 'VALID_LIVE');
  }, [bundle]);

  // Trial counts per scenario
  const trialCountsByScenario = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sc of ALL_SCENARIOS) {
      counts[sc] = allValidTrials.filter(
        (t) => t.scenario_id === sc && (selectedBrowser === 'ALL' || t.browser === selectedBrowser)
      ).length;
    }
    return counts;
  }, [allValidTrials, selectedBrowser]);

  // Overall analytical summary
  const summary = useMemo(() => {
    return computeOverallSummary(allValidTrials, selectedScenarios, selectedBrowser);
  }, [allValidTrials, selectedScenarios, selectedBrowser]);

  // PDF Download Handler
  const handleDownloadPdf = async () => {
    if (!bundle || selectedScenarios.length === 0) return;

    try {
      setIsGeneratingPdf(true);
      setPdfErrorMessage(null);
      setPdfSuccessMessage(null);

      const pdfBlob = await generateScenarioAnalysisPdf({
        bundle,
        provenance,
        integrity,
        selectedScenarios,
        selectedBrowser,
        selectedMetric,
        allTrials: allValidTrials,
      });

      // Trigger browser download
      const filename = `PS028_Scenario_Analytics_Report_${selectedScenarios.join('_')}.pdf`;
      const url = URL.createObjectURL(pdfBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setPdfSuccessMessage(`Report generated and downloaded: ${filename}`);
      setTimeout(() => setPdfSuccessMessage(null), 6000);
    } catch (err: any) {
      setPdfErrorMessage(err.message || 'Failed to generate PDF report');
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-[400px] flex flex-col items-center justify-center space-y-4">
        <div className="size-8 rounded-full border-2 border-primary border-t-transparent animate-spin" />
        <div className="text-sm font-medium text-foreground">
          Loading and verifying PS-028 historical evidence bundle...
        </div>
        <div className="text-xs text-muted-foreground">
          Validating cryptographic SHA-256 digests across 280 empirical live trials
        </div>
      </div>
    );
  }

  if (loadError || !bundle) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-6 space-y-3">
        <div className="flex items-center gap-2 text-destructive font-semibold">
          <AlertTriangle className="size-5" />
          <span>Failed to Load Experimental Evidence</span>
        </div>
        <div className="text-sm text-foreground">{loadError || 'Bundle unavailable.'}</div>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-xs font-medium cursor-pointer"
        >
          Retry
        </button>
      </div>
    );
  }

  const isDownloadDisabled = selectedScenarios.length === 0 || isGeneratingPdf;

  return (
    <div data-testid="analytics-dashboard-mounted" className="space-y-6">
      {/* Top Controls & Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl border bg-card/60 shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Integrity Badge */}
          <div
            data-testid="analytics-integrity-badge"
            className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium border ${
              integrity.isHashMatched
                ? 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-300 border-emerald-500/30'
                : 'bg-amber-500/10 text-amber-800 dark:text-amber-300 border-amber-500/30'
            }`}
          >
            {integrity.isHashMatched ? (
              <ShieldCheck className="size-4 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" />
            )}
            <span>{integrity.statusLabel}</span>
          </div>

          <div className="text-xs text-muted-foreground hidden md:inline">
            Campaign: <code className="font-mono text-foreground">{bundle.campaign_id}</code>
          </div>
        </div>

        {/* Action: Download PDF Report */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            data-testid="download-pdf-button"
            onClick={handleDownloadPdf}
            disabled={isDownloadDisabled}
            title={
              selectedScenarios.length === 0
                ? 'Select at least one scenario to generate a PDF report'
                : 'Download professional technical PDF report for selected scenarios'
            }
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs sm:text-sm font-semibold transition-all cursor-pointer shadow-xs ${
              isDownloadDisabled
                ? 'bg-muted text-muted-foreground opacity-50 cursor-not-allowed border'
                : 'bg-primary text-primary-foreground hover:bg-primary/90'
            }`}
          >
            {isGeneratingPdf ? (
              <>
                <div className="size-4 rounded-full border-2 border-primary-foreground border-t-transparent animate-spin" />
                <span>Generating PDF...</span>
              </>
            ) : (
              <>
                <Download className="size-4" />
                <span>Download Scenario Analysis PDF</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* PDF Generation Notification Banners */}
      {pdfSuccessMessage && (
        <div className="p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-900 dark:text-emerald-200 text-xs flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400" />
            <span>{pdfSuccessMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setPdfSuccessMessage(null)}
            className="text-xs text-muted-foreground hover:text-foreground cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {pdfErrorMessage && (
        <div className="p-3 rounded-lg border border-destructive/30 bg-destructive/10 text-destructive text-xs flex items-center justify-between animate-fade-in">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4" />
            <span>{pdfErrorMessage}</span>
          </div>
          <button
            type="button"
            onClick={() => setPdfErrorMessage(null)}
            className="text-xs hover:underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* SECTION 1: Scenario Selector */}
      <ScenarioSelector
        selectedScenarios={selectedScenarios}
        onChange={setSelectedScenarios}
        trialCountsByScenario={trialCountsByScenario}
      />

      {/* SECTION 2: Global Filters Bar (Browser & Metric) */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg border bg-card/40">
        <div className="flex flex-wrap items-center gap-3">
          <BrowserSelector selectedBrowser={selectedBrowser} onChange={setSelectedBrowser} />
          <MetricSelector selectedMetric={selectedMetric} onChange={setSelectedMetric} />
        </div>

        <div className="text-xs text-muted-foreground">
          Showing <strong className="text-foreground font-mono">{summary.validTrialsCount}</strong> valid live trials
        </div>
      </div>

      {/* SECTION 3: Selected-Scenario Analytical Summary */}
      <AnalyticsSummary summary={summary} selectedScenarios={selectedScenarios} />

      {/* SECTION 4: Analytical Graph Cards Grid */}
      <div className="space-y-6">
        {/* Row 1: Graph 1 & Graph 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div data-testid="graph-1-card">
            <ConnectionTimeChart
              trials={allValidTrials}
              globalScenarios={selectedScenarios}
              globalBrowser={selectedBrowser}
            />
          </div>
          <div data-testid="graph-2-card">
            <WinnerDistributionChart
              trials={allValidTrials}
              globalScenarios={selectedScenarios}
              globalBrowser={selectedBrowser}
            />
          </div>
        </div>

        {/* Row 2: Graph 3 & Graph 4 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div data-testid="graph-3-card">
            <LatencyDistributionChart
              trials={allValidTrials}
              globalScenarios={selectedScenarios}
              globalBrowser={selectedBrowser}
              globalMetric={selectedMetric}
            />
          </div>
          <div data-testid="graph-4-card">
            <DnsPerformanceChart
              trials={allValidTrials}
              globalScenarios={selectedScenarios}
              globalBrowser={selectedBrowser}
            />
          </div>
        </div>

        {/* Row 3: Graph 5 & Graph 6 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div data-testid="graph-5-card">
            <RetransmissionChart
              trials={allValidTrials}
              globalScenarios={selectedScenarios}
              globalBrowser={selectedBrowser}
            />
          </div>
          <div data-testid="graph-6-card">
            <ScenarioHeatmap
              trials={allValidTrials}
              globalScenarios={selectedScenarios}
              globalMetric={selectedMetric}
            />
          </div>
        </div>

        {/* Row 4 (Full Width): Graph 7 - TCP Connection Event Timeline */}
        <div data-testid="graph-7-card">
          <ConnectionTimelineChart
            trials={allValidTrials}
            globalScenarios={selectedScenarios}
            globalBrowser={selectedBrowser}
          />
        </div>
      </div>
    </div>
  );
};
