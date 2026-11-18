/**
 * Analytics Filter Helpers and Scenario Definitions
 *
 * Provides constants, filters, and state helpers for scenario analytics.
 */

import type { BrowserFilterId } from './analytics-types';

export interface ScenarioMeta {
  id: string;
  name: string;
  title: string;
  condition: string;
  description: string;
  targetFamily: 'IPv6' | 'IPv4' | 'Dual';
  expectedFallback: boolean;
  isCadAssessed: boolean;
}

export const SCENARIO_METADATA: Record<string, ScenarioMeta> = {
  S0: {
    id: 'S0',
    name: 'Baseline dual-stack',
    title: 'S0 — Baseline dual-stack',
    condition: 'Both paths available and healthy; IPv6 preferred per RFC 6724.',
    description: 'IPv4/IPv6 ~20ms RTT; healthy dual-stack reference control.',
    targetFamily: 'Dual',
    expectedFallback: false,
    isCadAssessed: false,
  },
  S1: {
    id: 'S1',
    name: 'IPv6 SYN blackhole',
    title: 'S1 — IPv6 SYN blackhole',
    condition: 'IPv6 TCP SYN dropped silently via router nftables.',
    description: 'IPv6 SYN dropped; client waits for CAD timer then connects over IPv4.',
    targetFamily: 'IPv6',
    expectedFallback: true,
    isCadAssessed: true,
  },
  S2: {
    id: 'S2',
    name: 'IPv6 TCP RST',
    title: 'S2 — IPv6 TCP RST',
    condition: 'IPv6 TCP SYN actively rejected with TCP RST via router nftables.',
    description: 'IPv6 SYN rejected with RST; triggers fallback to IPv4. Logical CAD is NOT_ASSESSED.',
    targetFamily: 'IPv6',
    expectedFallback: true,
    isCadAssessed: false,
  },
  S3: {
    id: 'S3',
    name: 'IPv6 RTT 150 ms',
    title: 'S3 — IPv6 RTT 150 ms',
    condition: '75ms delay added per direction on IPv6 link (150ms RTT).',
    description: 'IPv6 link has 150ms RTT; IPv6 completes before CAD timeout.',
    targetFamily: 'IPv6',
    expectedFallback: false,
    isCadAssessed: false,
  },
  S4: {
    id: 'S4',
    name: 'IPv6 RTT 600 ms with IPv4 10 ms',
    title: 'S4 — IPv6 RTT 600 ms with IPv4 10 ms',
    condition: '300ms delay per direction on IPv6 link (600ms RTT).',
    description: 'IPv6 has 600ms RTT; IPv4 attempt launched at CAD timer finishes first.',
    targetFamily: 'IPv6',
    expectedFallback: true,
    isCadAssessed: true,
  },
  S5: {
    id: 'S5',
    name: 'IPv6 50% SYN loss',
    title: 'S5 — IPv6 50% SYN loss',
    condition: '50% probability drop rule on initial IPv6 TCP SYN via router nftables.',
    description: '50% random loss on IPv6 SYN; tests retransmission behavior and fallback racing.',
    targetFamily: 'IPv6',
    expectedFallback: true,
    isCadAssessed: true,
  },
  S6: {
    id: 'S6',
    name: 'Delayed AAAA response',
    title: 'S6 — Delayed AAAA response',
    condition: 'DNS authoritative server delays AAAA responses by 500ms.',
    description: 'A response immediate; AAAA response delayed 500ms; tests DNS Resolution Delay.',
    targetFamily: 'IPv6',
    expectedFallback: false,
    isCadAssessed: false,
  },
};

export const ALL_SCENARIOS = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6'];

export const BROWSER_OPTIONS: { id: BrowserFilterId; label: string; shortLabel: string }[] = [
  { id: 'ALL', label: 'Both Browsers (Chrome & Firefox)', shortLabel: 'Both' },
  { id: 'google-chrome', label: 'Google Chrome 156', shortLabel: 'Chrome' },
  { id: 'firefox', label: 'Mozilla Firefox 159', shortLabel: 'Firefox' },
];
