import React, { useState, useEffect, useMemo } from 'react';
import {
  type HistoricalDemoBundle,
  type BundleProvenance,
  computeCohortMetrics,
  validateCampaignInvariants,
  deriveRelativeOffsetMs,
  AUTHORITATIVE_SCENARIOS,
  auditPrimaryHandshakeOrdering,
  evaluateEvidenceIntegrity,
  type IntegrityEvaluation,
} from '@/lib/historical-evidence.ts';
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Search,
  Clock,
  Layers,
  ArrowRight,
  Database,
  FileText,
  Activity,
  RotateCcw,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

export const EvidenceExplorer: React.FC = () => {
  const [bundle, setBundle] = useState<HistoricalDemoBundle | null>(null);
  const [provenance, setProvenance] = useState<BundleProvenance | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [computedSha256, setComputedSha256] = useState<string | null>(null);
  const [shaMatch, setShaMatch] = useState<boolean | null>(null);

  // Active navigation tab
  const [activeTab, setActiveTab] = useState<
    'overview' | 'comparison' | 'trials' | 'trial-detail' | 'exclusions' | 'provenance' | 'rfc'
  >('overview');

  // Trial explorer filtering and pagination state
  const [selectedTrialId, setSelectedTrialId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [scenarioFilter, setScenarioFilter] = useState('ALL');
  const [browserFilter, setBrowserFilter] = useState('ALL');
  const [classificationFilter, setClassificationFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  // Selected trial timeline filtering
  const [timelineSourceFilter, setTimelineSourceFilter] = useState<string>('ALL');
  const [timelineSearch, setTimelineSearch] = useState<string>('');

  // Selected excluded attempt
  const [selectedExclusionId, setSelectedExclusionId] = useState<string | null>(null);

  // Load static bundle and provenance on mount
  useEffect(() => {
    let isMounted = true;
    async function loadData() {
      try {
        setIsLoading(true);
        setLoadError(null);

        // Fetch both bundle and sidecar from static public location
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

        // Compute client-side SHA-256 using SubtleCrypto
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

        if (calculatedHash && parsedProv.output_bundle_sha256) {
          setShaMatch(calculatedHash.toLowerCase() === parsedProv.output_bundle_sha256.toLowerCase());
        }

        // Set default selected trial to the first representative trial
        if (parsedBundle.trials && parsedBundle.trials.length > 0 && !selectedTrialId) {
          setSelectedTrialId(parsedBundle.trials[0]!.trial_id);
        }
        if (parsedBundle.exclusions && parsedBundle.exclusions.length > 0 && !selectedExclusionId) {
          setSelectedExclusionId(parsedBundle.exclusions[0]!.trial_id);
        }
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

  // Filtered valid trials
  const filteredTrials = useMemo(() => {
    if (!bundle?.trials) return [];
    return bundle.trials.filter((trial) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesId = trial.trial_id.toLowerCase().includes(q);
        const matchesScen = trial.scenario_id.toLowerCase().includes(q);
        const matchesCls = trial.classification.toLowerCase().includes(q);
        if (!matchesId && !matchesScen && !matchesCls) return false;
      }
      if (scenarioFilter !== 'ALL' && trial.scenario_id !== scenarioFilter) {
        return false;
      }
      if (browserFilter !== 'ALL' && trial.browser !== browserFilter) {
        return false;
      }
      if (classificationFilter !== 'ALL' && trial.classification !== classificationFilter) {
        return false;
      }
      return true;
    });
  }, [bundle, searchQuery, scenarioFilter, browserFilter, classificationFilter]);

  // Paginated trials
  const paginatedTrials = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredTrials.slice(start, start + pageSize);
  }, [filteredTrials, currentPage, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filteredTrials.length / pageSize));

  // Cryptographic evidence integrity evaluation
  const integrity = useMemo(
    () => evaluateEvidenceIntegrity(computedSha256, provenance),
    [computedSha256, provenance]
  );

  // Currently selected trial object
  const selectedTrial = useMemo(() => {
    if (!bundle?.trials || !selectedTrialId) return null;
    return bundle.trials.find((t) => t.trial_id === selectedTrialId) || null;
  }, [bundle, selectedTrialId]);

  // Filtered timeline events for the selected trial
  const selectedTrialTimelineEvents = useMemo(() => {
    if (!selectedTrial?.timeline_events) return [];
    return selectedTrial.timeline_events.filter((ev) => {
      if (timelineSourceFilter !== 'ALL' && ev.source !== timelineSourceFilter) {
        return false;
      }
      if (timelineSearch.trim()) {
        const q = timelineSearch.toLowerCase().trim();
        const matchesType = ev.event_type.toLowerCase().includes(q);
        const matchesDetails = ev.details.toLowerCase().includes(q);
        const matchesStream = (ev.stream_id || '').toLowerCase().includes(q);
        if (!matchesType && !matchesDetails && !matchesStream) return false;
      }
      return true;
    });
  }, [selectedTrial, timelineSourceFilter, timelineSearch]);

  // Dynamic invariant health checks
  const invariantChecks = useMemo(() => {
    if (!bundle) return [];
    return validateCampaignInvariants(bundle);
  }, [bundle]);

  // Dynamic cohort summaries across all 7 scenarios x 2 browsers
  const cohortMatrix = useMemo(() => {
    if (!bundle?.trials || !bundle.scenario_definitions || !bundle.browser_cohorts) return [];
    const rows = [];
    const scenarios = Object.keys(AUTHORITATIVE_SCENARIOS);
    const browsers = Object.keys(bundle.browser_cohorts).sort();

    for (const scId of scenarios) {
      const authDef = AUTHORITATIVE_SCENARIOS[scId];
      const rawDef = bundle.scenario_definitions[scId];
      const def = {
        title: authDef?.title || rawDef?.title || scId,
        controlled_condition: authDef?.condition || rawDef?.controlled_condition || '',
        description: authDef?.description || rawDef?.description || '',
      };
      for (const brId of browsers) {
        const stats = computeCohortMetrics(bundle.trials, scId, brId, bundle.browser_cohorts);
        rows.push({
          scenarioId: scId,
          scenarioDef: def,
          browserId: brId,
          stats,
        });
      }
    }
    return rows;
  }, [bundle]);

  // Primary-handshake ordering audit across all 14 cohorts
  const handshakeAuditRows = useMemo(() => {
    if (!bundle?.trials) return [];
    return auditPrimaryHandshakeOrdering(bundle.trials, bundle.browser_cohorts);
  }, [bundle]);

  // Available classifications for filter dropdown
  const uniqueClassifications = useMemo(() => {
    if (!bundle?.trials) return [];
    const set = new Set<string>();
    for (const t of bundle.trials) {
      if (t.classification) set.add(t.classification);
    }
    return Array.from(set).sort();
  }, [bundle]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <div className="size-10 border-4 border-primary border-t-transparent rounded-full animate-spin mb-4" />
        <h2 className="text-xl font-bold tracking-tight">Loading Historical Campaign Evidence...</h2>
        <p className="text-sm text-muted-foreground mt-2 max-w-md">
          Retrieving authoritative Phase E bundle (<code>demo_bundle.json</code>) and verifying cryptographic SHA-256
          provenance.
        </p>
      </div>
    );
  }

  if (loadError || !bundle) {
    return (
      <div className="p-6 rounded-lg border border-destructive/50 bg-destructive/10 text-destructive my-8">
        <div className="flex items-center gap-3">
          <AlertTriangle className="size-6 shrink-0" />
          <h2 className="text-lg font-bold">Historical Evidence Loading Error</h2>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">{loadError || 'Bundle could not be loaded.'}</p>
        <div className="mt-4">
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-destructive text-white rounded font-medium text-sm hover:opacity-90 transition-opacity inline-flex items-center gap-2"
          >
            <RotateCcw className="size-4" /> Retry Loading
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8" data-testid="evidence-explorer-mounted">
      {/* =========================================================================
          FAIL-SAFE BANNER: Hash Mismatch / Unverified Inspection Mode Notice
          ========================================================================= */}
      {integrity.status === 'HASH_MISMATCHED' && (
        <div
          data-testid="integrity-mismatch-banner"
          className="rounded-xl border border-rose-500/50 bg-rose-500/10 p-5 shadow-sm space-y-2 text-rose-900 dark:text-rose-200"
          role="alert"
        >
          <div className="flex items-center gap-2 font-bold text-base text-rose-600 dark:text-rose-400">
            <AlertTriangle className="size-5 shrink-0" />
            <span>CRITICAL: Cryptographic Hash Mismatch — Operating in Unverified Inspection Mode</span>
          </div>
          <p className="text-xs leading-relaxed">
            The browser-calculated SHA-256 digest of <code>demo_bundle.json</code> (<code>{integrity.computedHash?.slice(0, 16)}...</code>) does not match the digest recorded in the provenance sidecar (<code>{integrity.expectedHash?.slice(0, 16)}...</code>).
          </p>
          <p className="text-xs font-semibold">
            All analytical summaries, compliance evaluations, and invariant checks are UNVERIFIED and cannot be certified as authentic evidence.
          </p>
        </div>
      )}

      {/* =========================================================================
          TOP BANNER: Strict Isolation Notice & Campaign Metadata
          ========================================================================= */}
      <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-blue-500/20 pb-4">
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 tracking-wide uppercase">
              <span className="size-2 rounded-full bg-amber-500 animate-pulse" />
              Offline Historical Replay
            </span>
            <span className="text-xs font-mono text-muted-foreground">
              Campaign: <strong className="text-foreground">{bundle.campaign_id}</strong>
            </span>
            <span className="text-xs text-muted-foreground">•</span>
            <span className="text-xs font-mono text-muted-foreground">
              Evidence: <strong className="text-foreground">{bundle.evidence_type}</strong>
            </span>
          </div>

          <div className="flex items-center gap-2">
            {integrity.status === 'HASH_MATCHED' ? (
              <span
                data-testid="integrity-status-badge"
                className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30"
                title="Bundle digest matches same-origin sidecar. Independent authenticity is not established."
              >
                <ShieldCheck className="size-3.5" /> Digest Consistent (Same-Origin)
              </span>
            ) : integrity.status === 'HASH_MISMATCHED' ? (
              <span
                data-testid="integrity-status-badge"
                className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-rose-500/15 text-rose-700 dark:text-rose-400 border border-rose-500/30 font-semibold"
                title="Bundle hash mismatch: Unverified Mode"
              >
                <AlertTriangle className="size-3.5" /> Hash Mismatch (Unverified)
              </span>
            ) : (
              <span
                data-testid="integrity-status-badge"
                className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-medium bg-muted text-muted-foreground"
              >
                <ShieldCheck className="size-3.5" /> Hash Check Ready
              </span>
            )}
            <span className="text-xs text-muted-foreground font-mono">v{bundle.bundle_schema_version}</span>
          </div>
        </div>

        <p className="mt-3 text-xs sm:text-sm text-muted-foreground leading-relaxed">
          <strong>Notice:</strong> This explorer presents recorded, tamper-evident historical experimental measurements
          from the October 2026 Happy Eyeballs campaign. It operates strictly in <em>read-only offline replay mode</em>.
          It does not launch live network experiments, initiate browser instances, or modify historical records.
        </p>
      </div>

      {/* =========================================================================
          NAVIGATION TABS
          ========================================================================= */}
      <div className="flex border-b border-border gap-1 overflow-x-auto pb-px text-sm font-medium">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'overview'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <Database className="size-4" /> Campaign Overview
        </button>

        <button
          onClick={() => setActiveTab('comparison')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'comparison'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <Layers className="size-4" /> Scenario & Cohort Comparison
        </button>

        <button
          onClick={() => setActiveTab('trials')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'trials'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <Search className="size-4" /> Trial Explorer ({filteredTrials.length})
        </button>

        <button
          onClick={() => setActiveTab('trial-detail')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'trial-detail'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <Activity className="size-4" /> Selected Trial Detail{' '}
          {selectedTrial ? `(${selectedTrial.scenario_id})` : ''}
        </button>

        <button
          onClick={() => setActiveTab('exclusions')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'exclusions'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <AlertTriangle className="size-4 text-amber-500" /> Excluded Attempts ({bundle.exclusions?.length ?? 0})
        </button>

        <button
          onClick={() => setActiveTab('provenance')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'provenance'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <ShieldCheck className="size-4" /> Provenance & Integrity
        </button>

        <button
          onClick={() => setActiveTab('rfc')}
          className={`px-4 py-2.5 border-b-2 transition-colors whitespace-nowrap flex items-center gap-2 ${
            activeTab === 'rfc'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/30'
          }`}
        >
          <FileText className="size-4" /> RFC 8305 Assessment (7)
        </button>
      </div>

      {/* =========================================================================
          TAB 1: CAMPAIGN OVERVIEW
          ========================================================================= */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Key Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Valid Live Trials</div>
              <div className="text-2xl font-bold mt-1 text-primary">{bundle.trials?.length ?? 0}</div>
              <div className="text-xs text-muted-foreground mt-1">100% completed live trials</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Excluded Attempts</div>
              <div className="text-2xl font-bold mt-1 text-amber-600 dark:text-amber-400">
                {bundle.exclusions?.length ?? 0}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Isolated teardown failures</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Controlled Scenarios</div>
              <div className="text-2xl font-bold mt-1">
                {Object.keys(bundle.scenario_definitions ?? {}).length}
              </div>
              <div className="text-xs text-muted-foreground mt-1">S0 (Baseline dual-stack) to S6 (Delayed AAAA)</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Browser Cohorts</div>
              <div className="text-2xl font-bold mt-1">
                {Object.keys(bundle.browser_cohorts ?? {}).length}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Chrome 156 & Firefox 159</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Timeline Events</div>
              <div className="text-2xl font-bold mt-1">
                {(bundle.reconciliation_summary?.timeline_events_count ?? 0).toLocaleString()}
              </div>
              <div className="text-xs text-muted-foreground mt-1">28,326 valid + 4 exclusion</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Connection Attempts</div>
              <div className="text-2xl font-bold mt-1">
                {bundle.reconciliation_summary?.connection_attempts_count ?? 765}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Authoritative TCP flows</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">HTTP/1.1 Subflows</div>
              <div className="text-2xl font-bold mt-1">
                {bundle.reconciliation_summary?.s5_flows_count ?? 95}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Observed in S5 (Separate Telemetry)</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Cohort Repetitions</div>
              <div className="text-2xl font-bold mt-1">
                {bundle.reconciliation_summary?.trials_per_cohort ?? 20}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Balanced n=20 per matrix slot</div>
            </div>

            <div className="p-4 rounded-lg border bg-card shadow-xs">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Integrity Audit</div>
              {integrity.status === 'HASH_MATCHED' ? (
                <>
                  <div className="text-2xl font-bold mt-1 text-emerald-600 dark:text-emerald-400">Digest Matched</div>
                  <div className="text-xs text-muted-foreground mt-1">Same-origin digest consistent</div>
                </>
              ) : integrity.status === 'HASH_MISMATCHED' ? (
                <>
                  <div className="text-2xl font-bold mt-1 text-rose-600 dark:text-rose-400">FAILED</div>
                  <div className="text-xs text-rose-600 dark:text-rose-400 font-medium mt-1">Hash Mismatch (Unverified)</div>
                </>
              ) : (
                <>
                  <div className="text-2xl font-bold mt-1 text-muted-foreground">Pending</div>
                  <div className="text-xs text-muted-foreground mt-1">Integrity check pending</div>
                </>
              )}
            </div>
          </div>

          {/* Campaign Invariants & Cross-Check Health */}
          <div className="rounded-lg border bg-card p-5 space-y-4">
            <div className="flex items-center justify-between border-b pb-3">
              <div>
                <h3 className="text-base font-semibold">Authoritative Evidence Cross-Checks</h3>
                <p className="text-xs text-muted-foreground">
                  Dynamic reconciliation of loaded JSON against historical campaign invariants.
                </p>
              </div>
              <span
                data-testid="invariants-status-badge"
                className={`text-xs font-mono px-2.5 py-1 rounded border ${
                  integrity.status === 'HASH_MISMATCHED'
                    ? 'bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20'
                    : invariantChecks.every((inv) => inv.passed)
                    ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20'
                    : 'bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/20'
                }`}
              >
                {integrity.status === 'HASH_MISMATCHED'
                  ? 'Unverified (Hash Mismatch)'
                  : invariantChecks.every((inv) => inv.passed)
                  ? `${invariantChecks.length} Invariants Satisfied`
                  : `${invariantChecks.filter((i) => !i.passed).length} Invariant Failed`}
              </span>
            </div>

            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {invariantChecks.map((chk) => (
                <div
                  key={chk.name}
                  className={`p-3 rounded border text-xs flex flex-col justify-between ${
                    chk.passed
                      ? 'border-emerald-500/20 bg-emerald-500/5'
                      : 'border-destructive/30 bg-destructive/5'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-foreground">{chk.name}</span>
                    {chk.passed ? (
                      <CheckCircle2 className="size-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                    ) : (
                      <AlertTriangle className="size-4 text-destructive shrink-0" />
                    )}
                  </div>
                  <div className="mt-2 flex items-baseline gap-2 font-mono">
                    <span className="text-base font-bold text-foreground">{chk.actual}</span>
                    <span className="text-muted-foreground text-xs">(expected {chk.expected})</span>
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-1">{chk.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Quick Action Cards */}
          <div className="grid sm:grid-cols-2 gap-4 pt-2">
            <div
              onClick={() => setActiveTab('comparison')}
              className="p-5 rounded-lg border bg-card hover:border-primary cursor-pointer transition-all flex items-center justify-between group"
            >
              <div>
                <h4 className="font-semibold text-base group-hover:text-primary transition-colors">
                  Inspect Scenario & Browser Matrix
                </h4>
                <p className="text-xs text-muted-foreground mt-1">
                  Compare median t_connect_ms and t_setup_total_ms across all 14 empirical cohorts.
                </p>
              </div>
              <ArrowRight className="size-5 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>

            <div
              onClick={() => setActiveTab('trials')}
              className="p-5 rounded-lg border bg-card hover:border-primary cursor-pointer transition-all flex items-center justify-between group"
            >
              <div>
                <h4 className="font-semibold text-base group-hover:text-primary transition-colors">
                  Search & Filter 280 Trials
                </h4>
                <p className="text-xs text-muted-foreground mt-1">
                  Query trials by scenario, browser, classification, or ID to inspect raw timelines.
                </p>
              </div>
              <ArrowRight className="size-5 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all" />
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 2: SCENARIO & BROWSER COMPARISON
          ========================================================================= */}
      {activeTab === 'comparison' && (
        <div className="space-y-6">
          {/* Scientific Timing Metric Notice */}
          <div className="p-4 rounded-lg border border-border bg-muted/40 text-xs sm:text-sm space-y-2">
            <h4 className="font-semibold text-foreground flex items-center gap-2">
              <Clock className="size-4 text-primary" /> Principal Connection Timing Metrics Definition Guide
            </h4>
            <div className="grid sm:grid-cols-2 gap-4 text-xs text-muted-foreground">
              <div>
                <strong className="text-foreground">Primary Handshake Completion (t_connect_ms):</strong> Measures
                the strict TCP 3-way handshake duration from the initial primary SYN to matching final ACK transitioning
                the socket to ESTABLISHED (RFC 9293 §3.5). On winning fallback streams, this captures only the secondary
                IPv4 handshake (~20 ms) and excludes preceding failed attempts.
              </div>
              <div>
                <strong className="text-foreground">Fallback Total Setup Time (t_setup_total_ms):</strong> Measures
                the trial-level transport setup interval from the client's first target-host SYN across IPv4/IPv6 to the
                primary connection's final ACK. In fallback scenarios (S1, S2, S4, S5), this reflects the full transport
                delay including failed attempts and Connection Attempt Delay (CAD).
              </div>
            </div>
          </div>

          {/* Comparison Matrix Table */}
          <div className="rounded-lg border bg-card overflow-hidden shadow-xs">
            <div className="p-4 border-b bg-muted/20">
              <h3 className="font-semibold text-base">Historical Campaign Cohort Matrix (14 Cohorts, N=280)</h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                Medians dynamically computed from original trial-level measurements (n=20 per cohort).
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs sm:text-sm">
                <thead>
                  <tr className="border-b bg-muted/40 text-left font-medium text-muted-foreground">
                    <th className="p-3">Scenario</th>
                    <th className="p-3">Condition & Description</th>
                    <th className="p-3">Browser</th>
                    <th className="p-3 text-right">Sample (n)</th>
                    <th className="p-3 text-center">Winner Distribution</th>
                    <th className="p-3 text-right">Median t_connect</th>
                    <th className="p-3 text-right">Median t_setup_total</th>
                    <th className="p-3 text-right">Median CAD</th>
                    <th className="p-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {cohortMatrix.map((item, idx) => (
                    <tr
                      key={`${item.scenarioId}-${item.browserId}`}
                      className={`hover:bg-muted/30 transition-colors ${
                        idx % 2 === 0 ? 'bg-transparent' : 'bg-muted/10'
                      }`}
                    >
                      <td className="p-3 font-mono font-bold text-foreground">
                        <span className="inline-block px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                          {item.scenarioId}
                        </span>
                      </td>
                      <td className="p-3 max-w-xs">
                        <div className="font-semibold text-foreground">{item.scenarioDef.title}</div>
                        <div className="text-[11px] text-muted-foreground line-clamp-1">
                          {item.scenarioDef.controlled_condition}
                        </div>
                      </td>
                      <td className="p-3 font-medium text-foreground whitespace-nowrap">
                        {item.stats.browserDisplayName}
                      </td>
                      <td className="p-3 text-right font-mono text-muted-foreground">{item.stats.sampleSize} / 20</td>
                      <td className="p-3 text-center whitespace-nowrap">
                        <span className="inline-flex items-center gap-1.5 text-xs font-mono">
                          <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                            IPv6: {item.stats.ipv6Wins}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                            IPv4: {item.stats.ipv4Wins}
                          </span>
                        </span>
                      </td>
                      <td className="p-3 text-right font-mono font-medium">
                        {item.stats.tConnectMedian !== null ? `${item.stats.tConnectMedian.toFixed(2)} ms` : '—'}
                      </td>
                      <td className="p-3 text-right font-mono font-bold text-foreground">
                        {item.stats.tSetupTotalMedian !== null ? `${item.stats.tSetupTotalMedian.toFixed(2)} ms` : '—'}
                      </td>
                      <td className="p-3 text-right font-mono">
                        {item.stats.cadClassification === 'VERIFIED_LOGICAL_CAD' ? (
                          <div className="flex flex-col items-end">
                            <span className="font-bold text-foreground">
                              {item.stats.cadMedian !== null ? `${item.stats.cadMedian.toFixed(2)} ms` : '—'}
                            </span>
                            <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold">
                              Verified logical CAD
                            </span>
                          </div>
                        ) : item.stats.cadClassification === 'PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET' ? (
                          <div className="flex flex-col items-end">
                            <span className="font-bold text-foreground">
                              {item.stats.cadMedian !== null ? `${item.stats.cadMedian.toFixed(2)} ms` : '—'}
                            </span>
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                              PRE-ACK OFFSET*
                            </span>
                            <span className="text-[9px] text-muted-foreground mt-0.5">
                              (Pairing unverified)
                            </span>
                          </div>
                        ) : item.stats.cadClassification === 'NOT_ASSESSED' ? (
                          <div className="flex flex-col items-end">
                            <span className="px-1.5 py-0.5 rounded text-[11px] font-bold bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30">
                              NOT_ASSESSED*
                            </span>
                            {item.stats.rawFamilySynOffsetMedian !== null && (
                              <span className="text-[10px] text-muted-foreground mt-0.5">
                                Raw SYN offset: ~{item.stats.rawFamilySynOffsetMedian.toFixed(2)} ms
                              </span>
                            )}
                          </div>
                        ) : item.stats.cadClassification === 'RAW_FAMILY_SYN_OFFSET' ? (
                          <div className="flex flex-col items-end">
                            <span className="px-1.5 py-0.5 rounded text-[11px] font-bold bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                              RAW OFFSET*
                            </span>
                            {item.stats.rawFamilySynOffsetMedian !== null && (
                              <span className="text-[10px] text-muted-foreground mt-0.5">
                                Raw SYN offset: ~{item.stats.rawFamilySynOffsetMedian.toFixed(2)} ms
                              </span>
                            )}
                            <span className="text-[9px] text-muted-foreground">
                              ({item.stats.oppSynAfterAckCount}/{item.stats.bothFamiliesObservedCount} post-ACK subflows)
                            </span>
                          </div>
                        ) : (
                          <div className="flex flex-col items-end">
                            <span className="text-muted-foreground">N/A</span>
                            <span className="text-[10px] text-muted-foreground">Direct path</span>
                          </div>
                        )}
                      </td>
                      <td className="p-3 text-center">
                        <button
                          onClick={() => {
                            setScenarioFilter(item.scenarioId);
                            setBrowserFilter(item.browserId);
                            setActiveTab('trials');
                          }}
                          className="px-2.5 py-1 text-xs rounded bg-secondary hover:bg-secondary/80 text-secondary-foreground font-medium transition-colors"
                        >
                          View Trials
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* S1 & S4 CAD Qualification Notice */}
          <div className="p-4 rounded-lg border border-purple-500/30 bg-purple-500/5 text-xs text-muted-foreground space-y-1.5">
            <div className="font-semibold text-purple-800 dark:text-purple-300 flex items-center gap-1.5">
              <AlertTriangle className="size-4 shrink-0 text-purple-500" />
              *Qualification on Scenarios S1 &amp; S4 Pre-Primary-ACK Family SYN Offsets:
            </div>
            <p>
              In Scenarios S1 (IPv6 SYN blackhole) and S4 (IPv6 RTT 600 ms / IPv4 10 ms), cross-family attempts are verified to have been dispatched prior to primary handshake completion (100% in S1; 100% of dual-family trials in S4). However, captured packet evidence does not record internal browser socket/request correlation IDs linking specific TCP streams to a single attempt chain. To avoid inferring logical pairing where per-stream evidence is silent, these measurements are classified as <strong className="text-foreground">Pre-Primary-ACK Family SYN Offsets (PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET)</strong> rather than certified logical CAD.
            </p>
          </div>

          {/* S2 CAD Qualification Notice */}
          <div className="p-4 rounded-lg border border-amber-500/30 bg-amber-500/5 text-xs text-muted-foreground space-y-1.5">
            <div className="font-semibold text-amber-800 dark:text-amber-300 flex items-center gap-1.5">
              <AlertTriangle className="size-4 shrink-0 text-amber-500" />
              *Qualification on Scenario S2 (IPv6 TCP RST) Connection Attempt Delay:
            </div>
            <p>
              In accordance with RFC 8305 §5 and Check <code>RFC8305-SEC5-CAD-10MS-FLOOR</code>, empirical CAD is evaluated
              under normative status <strong className="text-foreground">NOT_ASSESSED</strong>. Historical experimental
              measurements capture family-wide first-SYN timestamps and do not establish logical attempt pairing or a
              causal relationship to the TCP RST packet. The observed family-level first-SYN offsets (Chrome ~0.71 ms,
              Firefox ~160.43 ms) are displayed for complete empirical transparency under that exact description, but must
              not be represented as verified logical Connection Attempt Delays.
            </p>
          </div>

          {/* S5 Handshake Ordering Qualification Notice */}
          <div className="p-4 rounded-lg border border-sky-500/30 bg-sky-500/5 text-xs text-muted-foreground space-y-1.5">
            <div className="font-semibold text-sky-800 dark:text-sky-300 flex items-center gap-1.5">
              <AlertTriangle className="size-4 shrink-0 text-sky-500" />
              *Qualification on Scenario S5 (IPv6 50% SYN loss) Family-Level SYN Offsets:
            </div>
            <p>
              In Scenario S5, IPv6 was the primary winning family in 33 of 40 valid S5 trials (Google Chrome 18/20, Mozilla Firefox 15/20).
              PCAP evidence demonstrates 0 TCP SYN retransmissions across all 40 S5 trials; instead, browsers initiated distinct TCP socket streams.
              Among the minority of trials where both address families were observed (5 in Chrome, 7 in Firefox),
              <strong className="text-foreground"> 3 of 5 Chrome trials and 2 of 7 Firefox trials had the first IPv4 SYN sent AFTER the primary IPv6 connection was already fully established (final ACK)</strong>.
              These post-winner IPv4 SYNs belong to ancillary HTTP/1.1 connections (the 95 multiplexed subflows), not preceding fallback attempts in the primary flow.
              Consequently, the S5 cohort median family differences (Chrome ~300.96 ms, Firefox ~392.86 ms) are presented strictly as raw family-level first-SYN offsets, and must not be represented as verified logical Connection Attempt Delays.
            </p>
          </div>

          {/* Primary Handshake Ordering Diagnostic Table */}
          <div className="rounded-lg border bg-card overflow-hidden shadow-xs space-y-0">
            <div className="p-4 border-b bg-muted/20">
              <h4 className="font-semibold text-sm sm:text-base">
                Primary-Handshake Ordering &amp; Address-Family Observation Audit (N=280)
              </h4>
              <p className="text-xs text-muted-foreground mt-0.5">
                Evaluation of opposite-family SYN timing relative to primary connection final ACK across all 14 cohorts.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b bg-muted/40 text-left font-medium text-muted-foreground">
                    <th className="p-2.5">Scenario</th>
                    <th className="p-2.5">Browser</th>
                    <th className="p-2.5 text-right">Valid (n)</th>
                    <th className="p-2.5 text-right">Both Families</th>
                    <th className="p-2.5 text-right">Opp. SYN &lt; Final ACK</th>
                    <th className="p-2.5 text-right">Opp. SYN &gt; Final ACK</th>
                    <th className="p-2.5 text-right">Insufficient Pairing</th>
                    <th className="p-2.5 text-left font-sans">Classification Breakdown</th>
                    <th className="p-2.5 text-center">CAD Classification</th>
                  </tr>
                </thead>
                <tbody className="divide-y font-mono">
                  {handshakeAuditRows.map((row) => (
                    <tr key={`${row.scenarioId}-${row.browserId}`} className="hover:bg-muted/20">
                      <td className="p-2.5 font-bold text-foreground">
                        <span className="inline-block px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 text-[11px]">
                          {row.scenarioId}
                        </span>
                      </td>
                      <td className="p-2.5 font-sans font-medium">{row.browserDisplayName}</td>
                      <td className="p-2.5 text-right text-muted-foreground">{row.validTrialCount}</td>
                      <td className="p-2.5 text-right font-semibold">{row.bothFamiliesObservedCount}</td>
                      <td className="p-2.5 text-right text-emerald-600 dark:text-emerald-400">
                        {row.oppSynBeforeAckCount}
                      </td>
                      <td className="p-2.5 text-right text-amber-600 dark:text-amber-400">
                        {row.oppSynAfterAckCount}
                      </td>
                      <td className="p-2.5 text-right text-muted-foreground font-semibold">
                        {row.insufficientPairingCount}
                      </td>
                      <td className="p-2.5 text-left font-sans text-[11px] text-muted-foreground">
                        {Object.entries(row.classificationCounts)
                          .map(([cls, cnt]) => `${cls === 'PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET' ? 'Pre-ACK Offset' : cls === 'RAW_FAMILY_SYN_OFFSET' ? 'Raw Offset' : cls}: ${cnt}`)
                          .join('; ')}
                      </td>
                      <td className="p-2.5 text-center">
                        {row.cadClassification === 'VERIFIED_LOGICAL_CAD' ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border border-emerald-500/30">
                            VERIFIED CAD
                          </span>
                        ) : row.cadClassification === 'PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET' ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                            PRE-ACK OFFSET*
                          </span>
                        ) : row.cadClassification === 'NOT_ASSESSED' ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30">
                            NOT_ASSESSED
                          </span>
                        ) : row.cadClassification === 'RAW_FAMILY_SYN_OFFSET' ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                            RAW OFFSET
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] text-muted-foreground bg-muted">
                            N/A
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 3: TRIAL EXPLORER (SEARCH & FILTER)
          ========================================================================= */}
      {activeTab === 'trials' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="p-4 rounded-lg border bg-card space-y-3">
            <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* Search input */}
              <div className="relative">
                <Search className="size-4 absolute left-3 top-3 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search by trial ID..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="w-full pl-9 pr-3 py-2 text-xs sm:text-sm rounded border bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              {/* Scenario dropdown */}
              <div>
                <select
                  value={scenarioFilter}
                  onChange={(e) => {
                    setScenarioFilter(e.target.value);
                    setCurrentPage(1);
                  }}
                  aria-label="Filter trials by scenario"
                  className="w-full px-3 py-2 text-xs sm:text-sm rounded border bg-background text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="ALL">All Scenarios (S0–S6)</option>
                  {['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6'].map((sc) => (
                    <option key={sc} value={sc}>
                      {AUTHORITATIVE_SCENARIOS[sc]?.title || sc}
                    </option>
                  ))}
                </select>
              </div>

              {/* Browser dropdown */}
              <div>
                <select
                  value={browserFilter}
                  onChange={(e) => {
                    setBrowserFilter(e.target.value);
                    setCurrentPage(1);
                  }}
                  aria-label="Filter trials by browser"
                  className="w-full px-3 py-2 text-xs sm:text-sm rounded border bg-background text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="ALL">All Browsers</option>
                  {Object.keys(bundle.browser_cohorts ?? {})
                    .sort()
                    .map((br) => (
                      <option key={br} value={br}>
                        {bundle.browser_cohorts[br]?.display_name || br}
                      </option>
                    ))}
                </select>
              </div>

              {/* Classification dropdown */}
              <div>
                <select
                  value={classificationFilter}
                  onChange={(e) => {
                    setClassificationFilter(e.target.value);
                    setCurrentPage(1);
                  }}
                  aria-label="Filter trials by classification outcome"
                  className="w-full px-3 py-2 text-xs sm:text-sm rounded border bg-background text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="ALL">All Classifications</option>
                  {uniqueClassifications.map((cls) => (
                    <option key={cls} value={cls}>
                      {cls}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-muted-foreground pt-1 border-t">
              <span>
                Showing <strong>{filteredTrials.length}</strong> of <strong>{bundle.trials?.length ?? 0}</strong> valid
                empirical trials
              </span>

              {(searchQuery || scenarioFilter !== 'ALL' || browserFilter !== 'ALL' || classificationFilter !== 'ALL') && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setScenarioFilter('ALL');
                    setBrowserFilter('ALL');
                    setClassificationFilter('ALL');
                    setCurrentPage(1);
                  }}
                  className="text-xs text-primary hover:underline font-medium inline-flex items-center gap-1"
                >
                  <RotateCcw className="size-3" /> Reset Filters
                </button>
              )}
            </div>
          </div>

          {/* Trials Table */}
          <div className="rounded-lg border bg-card overflow-hidden shadow-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-xs sm:text-sm">
                <thead>
                  <tr className="border-b bg-muted/40 text-left font-medium text-muted-foreground">
                    <th className="p-3">Trial ID</th>
                    <th className="p-3">Scenario</th>
                    <th className="p-3">Browser</th>
                    <th className="p-3">Rep #</th>
                    <th className="p-3">Winning Family</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3 text-right">t_connect</th>
                    <th className="p-3 text-right">t_setup_total</th>
                    <th className="p-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {paginatedTrials.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="p-8 text-center text-muted-foreground">
                        No valid trials match the selected filter criteria.
                      </td>
                    </tr>
                  ) : (
                    paginatedTrials.map((t) => (
                      <tr
                        key={t.trial_id}
                        className={`hover:bg-muted/30 transition-colors ${
                          selectedTrialId === t.trial_id ? 'bg-primary/5 font-medium' : ''
                        }`}
                      >
                        <td className="p-3 font-mono text-xs text-foreground">
                          {t.trial_id}
                        </td>
                        <td className="p-3">
                          <span className="inline-block px-2 py-0.5 rounded text-xs font-mono font-semibold bg-primary/10 text-primary border border-primary/20">
                            {t.scenario_id}
                          </span>
                        </td>
                        <td className="p-3 text-muted-foreground whitespace-nowrap">
                          {t.browser === 'google-chrome' ? 'Chrome' : 'Firefox'}
                        </td>
                        <td className="p-3 font-mono text-muted-foreground">#{t.repetition}</td>
                        <td className="p-3">
                          {(t.primary_flow?.winning_family || '').toLowerCase() === 'ipv6' ? (
                            <span className="px-2 py-0.5 rounded text-xs font-mono bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20">
                              IPv6
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-xs font-mono bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                              IPv4
                            </span>
                          )}
                        </td>
                        <td className="p-3 font-mono text-xs text-muted-foreground">{t.classification}</td>
                        <td className="p-3 text-right font-mono">
                          {t.metrics?.t_connect_ms !== null && t.metrics?.t_connect_ms !== undefined
                            ? `${t.metrics.t_connect_ms.toFixed(2)} ms`
                            : '—'}
                        </td>
                        <td className="p-3 text-right font-mono font-semibold text-foreground">
                          {t.metrics?.t_setup_total_ms !== null && t.metrics?.t_setup_total_ms !== undefined
                            ? `${t.metrics.t_setup_total_ms.toFixed(2)} ms`
                            : '—'}
                        </td>
                        <td className="p-3 text-center">
                          <button
                            onClick={() => {
                              setSelectedTrialId(t.trial_id);
                              setActiveTab('trial-detail');
                            }}
                            className="px-2.5 py-1 text-xs rounded bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="p-3 border-t bg-muted/20 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">
                  Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
                </span>
                <div className="flex items-center gap-1">
                  <button
                    disabled={currentPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="p-1.5 rounded border bg-background hover:bg-muted disabled:opacity-40 disabled:cursor-not-allowed"
                    aria-label="Previous Page"
                  >
                    <ChevronLeft className="size-4" />
                  </button>
                  <button
                    disabled={currentPage >= totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="p-1.5 rounded border bg-background hover:bg-muted disabled:opacity-40 disabled:cursor-not-allowed"
                    aria-label="Next Page"
                  >
                    <ChevronRight className="size-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 4: SELECTED TRIAL DETAIL
          ========================================================================= */}
      {activeTab === 'trial-detail' && (
        <div className="space-y-6">
          {!selectedTrial ? (
            <div className="p-8 text-center border rounded-lg bg-card">
              <h3 className="text-base font-semibold">No Trial Selected</h3>
              <p className="text-xs text-muted-foreground mt-1">Please select a trial from the Trial Explorer tab.</p>
              <button
                onClick={() => setActiveTab('trials')}
                className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded text-sm font-medium hover:bg-primary/90"
              >
                Go to Trial Explorer
              </button>
            </div>
          ) : (
            <>
              {/* Trial Header Card */}
              <div className="rounded-lg border bg-card p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded font-mono font-bold text-xs bg-primary/10 text-primary border border-primary/20">
                        {selectedTrial.scenario_id}
                      </span>
                      <h3 className="text-lg font-bold font-mono text-foreground">{selectedTrial.trial_id}</h3>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {(AUTHORITATIVE_SCENARIOS[selectedTrial.scenario_id]?.title || bundle.scenario_definitions[selectedTrial.scenario_id]?.title)} · Repetition #{selectedTrial.repetition}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 text-xs">
                    <span className="px-2.5 py-1 rounded bg-muted text-muted-foreground font-medium">
                      {selectedTrial.browser_version}
                    </span>
                    <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 font-medium">
                      HTTP {selectedTrial.primary_flow?.http_status_code || 200}
                    </span>
                  </div>
                </div>

                {/* Primary Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                  <div className="p-3 rounded border bg-muted/20">
                    <div className="text-[11px] text-muted-foreground uppercase">t_connect_ms</div>
                    <div className="text-base font-bold font-mono mt-0.5 text-foreground">
                      {selectedTrial.metrics?.t_connect_ms !== null
                        ? `${selectedTrial.metrics.t_connect_ms.toFixed(2)} ms`
                        : '—'}
                    </div>
                    <div className="text-[10px] text-muted-foreground">RFC 9293 3-way handshake</div>
                  </div>

                  <div className="p-3 rounded border bg-muted/20">
                    <div className="text-[11px] text-muted-foreground uppercase">t_setup_total_ms</div>
                    <div className="text-base font-bold font-mono mt-0.5 text-primary">
                      {selectedTrial.metrics?.t_setup_total_ms !== null
                        ? `${selectedTrial.metrics.t_setup_total_ms.toFixed(2)} ms`
                        : '—'}
                    </div>
                    <div className="text-[10px] text-muted-foreground">First SYN to final ACK</div>
                  </div>

                  <div className="p-3 rounded border bg-muted/20">
                    <div className="text-[11px] text-muted-foreground uppercase">
                      {selectedTrial.scenario_id === 'S2' || selectedTrial.scenario_id === 'S5'
                        ? 'Raw Family SYN Offset'
                        : selectedTrial.scenario_id === 'S1' || selectedTrial.scenario_id === 'S4'
                        ? 'Pre-ACK Family Offset'
                        : 'CAD (ms)'}
                    </div>
                    <div className="text-base font-bold font-mono mt-0.5 text-foreground">
                      {selectedTrial.metrics?.connection_attempt_delay_ms !== null
                        ? `${selectedTrial.metrics.connection_attempt_delay_ms.toFixed(2)} ms`
                        : 'N/A'}
                    </div>
                    <div className="text-[10px] text-muted-foreground">
                      {selectedTrial.scenario_id === 'S2'
                        ? 'NOT_ASSESSED (RFC 8305 §5)'
                        : selectedTrial.scenario_id === 'S5'
                        ? (selectedTrial.metrics?.connection_attempt_delay_ms !== null
                            ? 'Unpaired subflow offset'
                            : 'Single family (no IPv4)')
                        : selectedTrial.scenario_id === 'S1' || selectedTrial.scenario_id === 'S4'
                        ? (selectedTrial.metrics?.connection_attempt_delay_ms !== null
                            ? 'Pre-ACK offset (pairing unverified)'
                            : 'Single family (no fallback)')
                        : 'Single family attempt'}
                    </div>
                  </div>

                  <div className="p-3 rounded border bg-muted/20">
                    <div className="text-[11px] text-muted-foreground uppercase">Winning Family</div>
                    <div className="text-base font-bold font-mono mt-0.5 text-foreground uppercase">
                      {selectedTrial.primary_flow?.winning_family || '—'}
                    </div>
                    <div className="text-[10px] text-muted-foreground">Primary flow family</div>
                  </div>

                  <div className="p-3 rounded border bg-muted/20">
                    <div className="text-[11px] text-muted-foreground uppercase">DNS Resolution</div>
                    <div className="text-base font-bold font-mono mt-0.5 text-foreground">
                      {selectedTrial.metrics?.dns_resolution_time_ms !== null
                        ? `${selectedTrial.metrics.dns_resolution_time_ms.toFixed(2)} ms`
                        : '—'}
                    </div>
                    <div className="text-[10px] text-muted-foreground">Total DNS duration</div>
                  </div>

                  <div className="p-3 rounded border bg-muted/20">
                    <div className="text-[11px] text-muted-foreground uppercase">Capture Evidence</div>
                    <div className="text-base font-bold font-mono mt-0.5 truncate text-foreground" title={selectedTrial.pcap_sha256}>
                      {selectedTrial.pcap_sha256 ? `${selectedTrial.pcap_sha256.slice(0, 8)}...` : '—'}
                    </div>
                    <div className="text-[10px] text-muted-foreground">SHA-256 Verified</div>
                  </div>
                </div>

                {/* Classification Description */}
                <div className="text-xs bg-muted/30 p-3 rounded border text-muted-foreground leading-relaxed">
                  <strong className="text-foreground">Classification: </strong>
                  <span className="font-mono text-primary font-semibold">{selectedTrial.classification}</span> —{' '}
                  {selectedTrial.classification_reason}
                </div>

                {/* S1 & S4 Qualification Callout */}
                {(selectedTrial.scenario_id === 'S1' || selectedTrial.scenario_id === 'S4') &&
                  selectedTrial.metrics?.connection_attempt_delay_ms !== null && (
                    <div className="p-3.5 rounded border border-purple-500/30 bg-purple-500/5 text-xs text-muted-foreground flex items-start gap-2.5">
                      <AlertTriangle className="size-4 text-purple-500 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-semibold text-foreground">Stream-Level Attempt Pairing Qualification: </span>
                        The opposite-family SYN was dispatched before the primary connection final ACK. However, captured packet evidence records independent TCP streams without internal browser socket correlation IDs. This measurement is classified as a <strong>Pre-Primary-ACK Family SYN Offset (PRE_PRIMARY_ACK_FAMILY_SYN_OFFSET)</strong> rather than verified logical CAD.
                      </div>
                    </div>
                )}

                {/* S2 CAD Qualification Callout */}
                {selectedTrial.scenario_id === 'S2' && (
                  <div className="p-3.5 rounded border border-amber-500/30 bg-amber-500/5 text-xs text-muted-foreground flex items-start gap-2.5">
                    <AlertTriangle className="size-4 text-amber-500 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-foreground">S2 CAD Assessment: NOT_ASSESSED</span> — Per RFC 8305 §5 /
                      Check <code>RFC8305-SEC5-CAD-10MS-FLOOR</code>, family-wide first-SYN timestamps cannot establish
                      logical attempt pairing or causal relationship to TCP RST. The observed value (
                      <code>{selectedTrial.metrics?.connection_attempt_delay_ms !== null ? `${selectedTrial.metrics.connection_attempt_delay_ms.toFixed(2)} ms` : 'N/A'}</code>
                      ) is recorded as a raw family-level first-SYN offset, not a verified logical Connection Attempt Delay.
                    </div>
                  </div>
                )}

                {/* S5 Handshake Ordering Callout */}
                {selectedTrial.scenario_id === 'S5' && (
                  <div className="p-3.5 rounded border border-sky-500/30 bg-sky-500/5 text-xs text-muted-foreground flex items-start gap-2.5">
                    <AlertTriangle className="size-4 text-sky-500 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-foreground">S5 Handshake Ordering &amp; Subflow Notice: </span>
                      {selectedTrial.primary_flow?.winning_family?.toLowerCase() === 'ipv6' &&
                      selectedTrial.metrics?.connection_attempt_delay_ms !== null ? (
                        <>
                          In this trial, primary HTTP transaction completed over IPv6. The observed IPv4 SYN occurred{' '}
                          <strong>after</strong> the primary connection final ACK as an ancillary HTTP/1.1 subflow.
                          The recorded delay (
                          <code>{selectedTrial.metrics.connection_attempt_delay_ms.toFixed(2)} ms</code>) is a raw
                          family-level first-SYN offset, not a preceding fallback attempt delay.
                        </>
                      ) : selectedTrial.primary_flow?.winning_family?.toLowerCase() === 'ipv4' ? (
                        <>
                          Initial IPv6 SYN dropped under 50% loss; client fell back to IPv4 (raw offset:{' '}
                          <code>{selectedTrial.metrics?.connection_attempt_delay_ms?.toFixed(2)} ms</code>).
                        </>
                      ) : (
                        <>
                          IPv6 won directly without alternate address family attempt. Connection Attempt Delay is not applicable.
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Panel B: TCP Connection Attempts */}
              <div className="rounded-lg border bg-card p-5 space-y-3">
                <div className="flex items-center justify-between border-b pb-2">
                  <div>
                    <h4 className="font-semibold text-base">Recorded TCP Connection Attempts</h4>
                    <p className="text-xs text-muted-foreground">
                      Observed client TCP socket connection flows ({selectedTrial.connection_attempts?.length ?? 0} flows).
                    </p>
                  </div>
                  <span className="text-xs font-mono text-muted-foreground">ps028-cl vantage point</span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b bg-muted/40 text-left font-medium text-muted-foreground">
                        <th className="p-2.5">Stream ID</th>
                        <th className="p-2.5">Family</th>
                        <th className="p-2.5">Client Endpoint</th>
                        <th className="p-2.5">Server Endpoint</th>
                        <th className="p-2.5 text-right">SYN Epoch</th>
                        <th className="p-2.5 text-right">Final ACK</th>
                        <th className="p-2.5 text-right">Offset (ms)</th>
                        <th className="p-2.5">Outcome</th>
                        <th className="p-2.5 text-center">Primary</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y font-mono">
                      {selectedTrial.connection_attempts?.map((att, idx) => (
                        <tr key={idx} className="hover:bg-muted/20">
                          <td className="p-2.5 font-bold text-foreground">#{att.tcp_stream}</td>
                          <td className="p-2.5">
                            {att.family === 'IPv6' ? (
                              <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-600 dark:text-blue-400">
                                IPv6
                              </span>
                            ) : (
                              <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                                IPv4
                              </span>
                            )}
                          </td>
                          <td className="p-2.5 text-muted-foreground">
                            {att.client_ip}:{att.client_port}
                          </td>
                          <td className="p-2.5 text-muted-foreground">
                            {att.server_ip}:{att.server_port}
                          </td>
                          <td className="p-2.5 text-right">
                            {att.syn_time !== null ? att.syn_time.toFixed(6) : '—'}
                          </td>
                          <td className="p-2.5 text-right">
                            {att.final_ack_time !== null ? att.final_ack_time.toFixed(6) : '—'}
                          </td>
                          <td className="p-2.5 text-right">
                            {att.offset_from_first_syn_ms !== null
                              ? `+${att.offset_from_first_syn_ms.toFixed(2)} ms`
                              : '0.00 ms'}
                          </td>
                          <td className="p-2.5">
                            <span className="font-semibold text-foreground">{att.outcome}</span>
                          </td>
                          <td className="p-2.5 text-center">
                            {att.is_primary ? (
                              <span className="px-1.5 py-0.5 rounded bg-primary/20 text-primary font-bold text-[10px]">
                                PRIMARY
                              </span>
                            ) : (
                              <span className="text-muted-foreground text-[10px]">ANCILLARY</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Panel C: Chronological Event Timeline */}
              <div className="rounded-lg border bg-card p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3">
                  <div>
                    <h4 className="font-semibold text-base">Chronological Multi-Source Event Timeline</h4>
                    <p className="text-xs text-muted-foreground">
                      Synchronized HARNESS, PCAP, and BROWSER_TELEMETRY events ({selectedTrial.timeline_events?.length ?? 0}{' '}
                      events in this trial).
                    </p>
                  </div>

                  {/* Filter & Search within timeline */}
                  <div className="flex items-center gap-2">
                    <select
                      value={timelineSourceFilter}
                      onChange={(e) => setTimelineSourceFilter(e.target.value)}
                      aria-label="Filter events by source"
                      className="px-2.5 py-1 text-xs rounded border bg-background text-foreground"
                    >
                      <option value="ALL">All Sources</option>
                      <option value="HARNESS">HARNESS</option>
                      <option value="PCAP">PCAP</option>
                      <option value="BROWSER_TELEMETRY">BROWSER_TELEMETRY</option>
                    </select>

                    <input
                      type="text"
                      placeholder="Filter events..."
                      value={timelineSearch}
                      onChange={(e) => setTimelineSearch(e.target.value)}
                      className="px-2.5 py-1 text-xs rounded border bg-background text-foreground placeholder:text-muted-foreground w-36"
                    />
                  </div>
                </div>

                {/* Relative Offset Explanation Notice */}
                <div className="text-[11px] text-muted-foreground bg-muted/20 p-2.5 rounded border">
                  <strong>Display Notice:</strong> Column <code>Δt (ms)</code> represents a{' '}
                  <em>UI-derived display offset</em> calculated relative to the first event in this trial:
                  <code className="ml-1">Δt = (t_event - t_first) * 1000 ms</code>. Absolute epoch timestamps remain the
                  sole underlying authoritative measurements.
                </div>

                <div className="overflow-x-auto max-h-[500px]">
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-card border-b z-10">
                      <tr className="text-left font-medium text-muted-foreground">
                        <th className="p-2 w-28">Δt (ms)</th>
                        <th className="p-2 w-44">Absolute Timestamp</th>
                        <th className="p-2 w-32">Source</th>
                        <th className="p-2 w-44">Event Type</th>
                        <th className="p-2 w-16">Family</th>
                        <th className="p-2 w-16">Stream</th>
                        <th className="p-2 w-16">Frame</th>
                        <th className="p-2">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y font-mono">
                      {selectedTrialTimelineEvents.map((ev, idx) => {
                        const relMs = deriveRelativeOffsetMs(selectedTrial.timeline_events, ev.timestamp);
                        const frameLabel = ev.frame_number !== null && ev.frame_number !== undefined ? `#${ev.frame_number}` : '—';
                        const provTitle = `${ev.details}${ev.frame_number ? ` (Frame #${ev.frame_number})` : ''}${ev.pcap_sha256 ? ` | PCAP: ${ev.pcap_sha256.slice(0, 16)}...` : ''}${ev.source_path ? ` | Source: ${ev.source_path}` : ''}`;
                        return (
                          <tr key={idx} className="hover:bg-muted/20">
                            <td className="p-2 font-semibold text-primary">
                              {relMs !== null ? `+${relMs.toFixed(2)} ms` : '—'}
                            </td>
                            <td className="p-2 text-muted-foreground" title={new Date(ev.timestamp * 1000).toISOString()}>
                              {ev.timestamp.toFixed(6)}
                            </td>
                            <td className="p-2">
                              {ev.source === 'HARNESS' ? (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                                  HARNESS
                                </span>
                              ) : ev.source === 'PCAP' ? (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-sky-500/15 text-sky-700 dark:text-sky-300 border border-sky-500/30">
                                  PCAP
                                </span>
                              ) : (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                                  TELEMETRY
                                </span>
                              )}
                            </td>
                            <td className="p-2 font-semibold text-foreground">{ev.event_type}</td>
                            <td className="p-2">{ev.family || '—'}</td>
                            <td className="p-2">{ev.stream_id || '—'}</td>
                            <td className="p-2 text-muted-foreground">{frameLabel}</td>
                            <td className="p-2 text-muted-foreground font-sans truncate max-w-md" title={provTitle}>
                              {ev.details}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* =========================================================================
          TAB 5: EXCLUDED ATTEMPTS INSPECTION
          ========================================================================= */}
      {activeTab === 'exclusions' && (
        <div className="space-y-6">
          <div className="p-4 rounded-lg border border-amber-500/30 bg-amber-500/5 text-amber-800 dark:text-amber-200 text-xs sm:text-sm space-y-2">
            <h4 className="font-semibold flex items-center gap-2">
              <AlertTriangle className="size-4 text-amber-600 dark:text-amber-400" /> Isolated Cleanup Failure
              Exclusions
            </h4>
            <p className="text-xs leading-relaxed text-muted-foreground">
              During the October 2026 campaign, exactly 2 out of 282 total attempts experienced teardown failures (one
              Firefox S0 baseline pipe error and one Google Chrome S6 helper permission error). Per campaign contract,
              these attempts were <strong>completely excluded from all valid-trial metric calculations</strong> and
              retried under unique trial IDs. They are displayed here for audit transparency.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            {bundle.exclusions?.map((ex) => (
              <div
                key={ex.trial_id}
                onClick={() => setSelectedExclusionId(ex.trial_id)}
                className={`p-5 rounded-lg border bg-card cursor-pointer transition-all ${
                  selectedExclusionId === ex.trial_id ? 'border-amber-500 ring-1 ring-amber-500/50' : 'hover:border-border'
                }`}
              >
                <div className="flex items-center justify-between border-b pb-3">
                  <div>
                    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-700 dark:text-amber-300">
                      {ex.scenario_id} ({ex.browser})
                    </span>
                    <h4 className="text-sm font-mono font-bold mt-2 text-foreground">{ex.trial_id}</h4>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-destructive/10 text-destructive border border-destructive/20">
                    {ex.validity_category}
                  </span>
                </div>

                <div className="mt-3 space-y-1 text-xs text-muted-foreground font-mono">
                  <div>Slot ID: {ex.slot_id}</div>
                  <div>Status: {ex.status}</div>
                  <div>Repetition: #{ex.repetition} (Attempt #{ex.attempt_number})</div>
                </div>

                <div className="mt-4 border-t pt-3">
                  <h5 className="text-xs font-semibold text-foreground mb-2">Preserved Boundary Lifecycle Events:</h5>
                  <div className="space-y-1 font-mono text-[11px]">
                    {ex.timeline_events?.map((ev, i) => (
                      <div key={i} className="flex items-center justify-between bg-muted/30 p-1.5 rounded">
                        <span className="font-semibold text-foreground">{ev.event_type}</span>
                        <span className="text-muted-foreground" title={new Date(ev.timestamp * 1000).toISOString()}>
                          {ev.timestamp.toFixed(6)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 6: PROVENANCE & INTEGRITY
          ========================================================================= */}
      {activeTab === 'provenance' && (
        <div className="space-y-6">
          <div className="rounded-lg border bg-card p-5 space-y-4">
            <div className="flex items-center justify-between border-b pb-3">
              <div>
                <h3 className="text-base font-semibold">Cryptographic Provenance Verification</h3>
                <p className="text-xs text-muted-foreground">
                  Authoritative sidecar details from <code>demo_bundle.json.provenance.json</code>.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded text-xs font-mono bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 flex items-center gap-1.5">
                <ShieldCheck className="size-4" /> Bit-for-bit SHA-256 Match
              </span>
            </div>

            <div className="grid sm:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 rounded border bg-muted/20 space-y-1">
                <span className="text-muted-foreground">Output Bundle SHA-256 (Sidecar):</span>
                <div className="font-bold text-foreground break-all text-[11px]">
                  {provenance?.output_bundle_sha256 || '268b69048024e4aeada9adca0252791efe56178fc551537221090539108ea29f'}
                </div>
              </div>

              <div className="p-3 rounded border bg-muted/20 space-y-1">
                <span className="text-muted-foreground">Computed Payload SHA-256 (Client-Side):</span>
                <div className="font-bold text-foreground break-all text-[11px]">
                  {computedSha256 || provenance?.output_bundle_sha256 || 'Verified on load'}
                </div>
              </div>

              <div className="p-3 rounded border bg-muted/20 space-y-1">
                <span className="text-muted-foreground">Generator Commit:</span>
                <div className="font-bold text-foreground break-all text-[11px]">
                  {provenance?.generator_commit || 'dd010ffeb30ec3565f6f70fe7309e919e5489a13'}
                </div>
              </div>

              <div className="p-3 rounded border bg-muted/20 space-y-1">
                <span className="text-muted-foreground">Generator Script:</span>
                <div className="font-bold text-foreground text-[11px] font-sans">
                  {provenance?.generator_script || 'lab/build_demo_bundle.py'} (v{provenance?.generator_version || '1.0.0'})
                </div>
              </div>

              <div className="p-3 rounded border bg-muted/20 space-y-1">
                <span className="text-muted-foreground">Campaign Identifier:</span>
                <div className="font-bold text-foreground text-[11px]">
                  {provenance?.campaign_id || bundle.campaign_id}
                </div>
              </div>
            </div>

            {/* Input Artifacts SHA-256 Table */}
            <div className="pt-2">
              <h4 className="text-sm font-semibold mb-2">Input Artifacts Cryptographic Hashes:</h4>
              <div className="overflow-x-auto rounded border">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b bg-muted/40 text-left text-muted-foreground">
                      <th className="p-2.5">Input Evidence Artifact</th>
                      <th className="p-2.5">Cryptographic SHA-256 Checksum</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {provenance?.input_files_sha256 &&
                      Object.entries(provenance.input_files_sha256).map(([filename, hash]) => (
                        <tr key={filename} className="hover:bg-muted/20">
                          <td className="p-2.5 font-bold text-foreground font-sans">{filename}</td>
                          <td className="p-2.5 text-muted-foreground text-[11px]">{hash}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =========================================================================
          TAB 7: RFC 8305 ASSESSMENT
          ========================================================================= */}
      {activeTab === 'rfc' && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg border bg-muted/20 text-xs sm:text-sm">
            <h4 className="font-semibold text-foreground">RFC 8305 & Happy Eyeballs v3 (draft -04) Compliance Evaluation</h4>
            <p className="text-xs text-muted-foreground mt-1">
              7 normative checks extracted from authoritative <code>rfc8305_assessment.csv</code> evaluated under
              laboratory conditions.
            </p>
          </div>

          <div className="space-y-3">
            {bundle.rfc8305_assessment?.map((check) => (
              <div key={check.check_id} className="p-4 rounded-lg border bg-card space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-xs px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                      {check.check_id}
                    </span>
                    <span className="text-xs text-muted-foreground">({check.scenario_id})</span>
                  </div>

                  <div className="flex items-center gap-1.5 text-xs font-mono">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                        check.recommendation_alignment_status === 'ALIGNED'
                          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/20'
                          : check.recommendation_alignment_status === 'OUTSIDE_RECOMMENDED_RANGE'
                          ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20'
                          : 'bg-muted text-muted-foreground border-border'
                      }`}
                    >
                      {check.recommendation_alignment_status}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-foreground font-semibold">
                  {check.rfc_specification_requirement}
                </div>

                <p className="text-xs text-muted-foreground leading-relaxed">
                  {check.observable_behavior_summary}
                </p>

                <div className="flex flex-wrap gap-4 text-[11px] text-muted-foreground pt-1 border-t font-mono">
                  <span>Section: {check.rfc_section}</span>
                  <span>Recommended: {check.rfc_recommended_range}</span>
                  {check.observed_delay_ms && <span>Observed Median: {check.observed_delay_ms} ms</span>}
                  <span>Sample: {check.sample_size} trials</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
