/**
 * Analytics Data Types and Model Definitions for PS-028 Scenario Analytics
 *
 * Models authoritative data structures and analytical metrics derived from
 * lab/derived/phase-e/demo_bundle.json for interactive visualization and PDF generation.
 */

export type SupportedMetricKey =
  | 't_connect_ms'
  | 't_setup_total_ms'
  | 'dns_resolution_time_ms'
  | 'dns_latency_a_ms'
  | 'dns_latency_aaaa_ms'
  | 'dns_query_to_first_payload_ms'
  | 'retransmitted_syn_count_ipv4'
  | 'retransmitted_syn_count_ipv6';

export interface MetricDefinition {
  key: SupportedMetricKey;
  label: string;
  shortLabel: string;
  unit: string;
  description: string;
  category: 'timing' | 'dns' | 'retrans';
  rfcContext: string;
}

export const SUPPORTED_METRICS: Record<SupportedMetricKey, MetricDefinition> = {
  t_connect_ms: {
    key: 't_connect_ms',
    label: 'Primary Handshake Completion (t_connect)',
    shortLabel: 't_connect',
    unit: 'ms',
    description: 'Strict 3-way TCP handshake duration of the winning primary flow (RFC 9293 §3.5).',
    category: 'timing',
    rfcContext: 'RFC 9293 §3.5 — Handshake from winning flow SYN to final ACK',
  },
  t_setup_total_ms: {
    key: 't_setup_total_ms',
    label: 'Fallback Total Setup Time (t_setup_total)',
    shortLabel: 't_setup_total',
    unit: 'ms',
    description: 'Total transport setup elapsed time from first target SYN to primary final ACK, including fallback and delay.',
    category: 'timing',
    rfcContext: 'Trial-level transport duration including failed attempts and Connection Attempt Delay (CAD)',
  },
  dns_resolution_time_ms: {
    key: 'dns_resolution_time_ms',
    label: 'DNS Resolution Duration',
    shortLabel: 'DNS Resolution',
    unit: 'ms',
    description: 'Elapsed time from the first DNS query dispatch until the final required address record response.',
    category: 'dns',
    rfcContext: 'RFC 8305 §3 — DNS Resolution Duration before connection initiation',
  },
  dns_latency_a_ms: {
    key: 'dns_latency_a_ms',
    label: 'A Record (IPv4) DNS Latency',
    shortLabel: 'A Latency',
    unit: 'ms',
    description: 'Round-trip duration from A query transmission to authoritative response.',
    category: 'dns',
    rfcContext: 'IPv4 DNS query latency',
  },
  dns_latency_aaaa_ms: {
    key: 'dns_latency_aaaa_ms',
    label: 'AAAA Record (IPv6) DNS Latency',
    shortLabel: 'AAAA Latency',
    unit: 'ms',
    description: 'Round-trip duration from AAAA query transmission to authoritative response (delayed in S6).',
    category: 'dns',
    rfcContext: 'RFC 8305 §3 — Resolution Delay target parameter',
  },
  dns_query_to_first_payload_ms: {
    key: 'dns_query_to_first_payload_ms',
    label: 'DNS Query to First Payload Time',
    shortLabel: 'DNS to Payload',
    unit: 'ms',
    description: 'Complete user-perceived connection latency from initial DNS query to first HTTP request/response payload.',
    category: 'timing',
    rfcContext: 'End-to-end client setup latency',
  },
  retransmitted_syn_count_ipv4: {
    key: 'retransmitted_syn_count_ipv4',
    label: 'IPv4 SYN Retransmissions',
    shortLabel: 'IPv4 SYN Retrans',
    unit: 'packets',
    description: 'Count of observed TCP SYN retransmissions on IPv4 connection attempts.',
    category: 'retrans',
    rfcContext: 'Observed packet-level retransmissions',
  },
  retransmitted_syn_count_ipv6: {
    key: 'retransmitted_syn_count_ipv6',
    label: 'IPv6 SYN Retransmissions',
    shortLabel: 'IPv6 SYN Retrans',
    unit: 'packets',
    description: 'Count of observed TCP SYN retransmissions on IPv6 connection attempts.',
    category: 'retrans',
    rfcContext: 'Observed packet-level retransmissions',
  },
};

export type BrowserFilterId = 'ALL' | 'google-chrome' | 'firefox';

export interface BoxPlotStats {
  min: number;
  q1: number;
  median: number;
  q3: number;
  max: number;
  mean: number;
  iqr: number;
  outliers: number[];
  sampleSize: number;
}

export interface ScenarioCohortAggregates {
  scenarioId: string;
  browserId: string;
  sampleSize: number;
  tConnectMedian: number | null;
  tSetupTotalMedian: number | null;
  dnsResolutionMedian: number | null;
  dnsAMedian: number | null;
  dnsAAAAMedian: number | null;
  dnsPayloadMedian: number | null;
  ipv6Wins: number;
  ipv4Wins: number;
  retransIpv4Total: number;
  retransIpv6Total: number;
  retransIpv4Mean: number;
  retransIpv6Mean: number;
  metricStats: Record<SupportedMetricKey, BoxPlotStats | null>;
}

export interface DashboardFilterState {
  selectedScenarios: string[];
  selectedBrowser: BrowserFilterId;
  selectedMetric: SupportedMetricKey;
}

export interface OverallSummaryStats {
  selectedScenariosCount: number;
  validTrialsCount: number;
  chromeTrialsCount: number;
  firefoxTrialsCount: number;
  tConnectMedian: number | null;
  tSetupTotalMedian: number | null;
  ipv4WinCount: number;
  ipv6WinCount: number;
  ipv4WinPercentage: number | null;
  ipv6WinPercentage: number | null;
  dnsResolutionMedian: number | null;
  dnsAMedian: number | null;
  dnsAAAAMedian: number | null;
  retransIpv4Total: number;
  retransIpv6Total: number;
  baselineComparison?: {
    s0TConnectMedian: number | null;
    s0TSetupMedian: number | null;
    tConnectDeltaMs: number | null;
    tSetupDeltaMs: number | null;
  } | undefined;
}
