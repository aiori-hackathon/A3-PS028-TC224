import React, { useEffect, useState } from "react";
import {
  HTTPSRecord,
  IPDelayType,
  IPVersion,
  Protocol,
  type ResponseHandlerResult,
  type Subtest,
  type TestPart,
  TestRunResultColor,
  type TestSettings,
} from "@/lib/test-run.ts";
import { TestSkeleton } from "@/components/test-skeleton.tsx";
import { generateHEv3TestUrl, generateRange } from "@/lib/test-utils";
import {
  buildInitialSettingsFromEnabledSettings,
  type EnabledTestSettings,
} from "@/lib/settings.ts";
import { fetchAvailableDelays } from "@/lib/he-configuration.ts";

export const HEv3CombinedTest: React.FC = () => {
  const [settings, setSettings] = useState<TestSettings>(
    buildInitialSettingsFromEnabledSettings(enabledSettings),
  );
  const [networkDelays, setNetworkDelays] = useState<number[]>([]);

  const protocolHandshakeDelays = generateRange(
    settings.protocolHandshakeDelayRange.from,
    settings.protocolHandshakeDelayRange.to,
    settings.protocolHandshakeDelayRange.step,
  );

  const ipHandshakeDelays = generateRange(
    settings.ipHandshakeDelayRange.from,
    settings.ipHandshakeDelayRange.to,
    settings.ipHandshakeDelayRange.step,
  );

  useEffect(() => {
    fetchAvailableDelays().then((delays) => setNetworkDelays(delays.v1_delays));
  }, []);

  const buildSubtests = async (testRunId: number): Promise<TestPart[]> => {
    const testParts: TestPart[] = [];

    const ipDelays =
      settings.ipDelayType === IPDelayType.Network
        ? networkDelays
        : ipHandshakeDelays;

    for (const ipDelay of ipDelays) {
      const subtests: Subtest[] = [];

      for (const protocolDelay of protocolHandshakeDelays) {
        const url =
          settings.ipDelayType === IPDelayType.Handshake
            ? await generateHEv3TestUrl(
                settings.randomizeDomains,
                settings.delayedIPVersion === IPVersion.IPv4 ? ipDelay : 0,
                settings.delayedIPVersion === IPVersion.IPv6 ? ipDelay : 0,
                settings.delayedProtocol === Protocol.QUIC ? protocolDelay : 0,
                settings.delayedProtocol === Protocol.TLS ? protocolDelay : 0,
                settings.httpsRecord,
                settings.ipDelayType,
                testRunId,
              )
            : await generateHEv3TestUrl(
                settings.randomizeDomains,
                0,
                ipDelay,
                settings.delayedProtocol === Protocol.QUIC ? protocolDelay : 0,
                settings.delayedProtocol === Protocol.TLS ? protocolDelay : 0,
                settings.httpsRecord,
                settings.ipDelayType,
                testRunId,
              );

        subtests.push({
          url,
          metadata: {
            [settings.ipDelayType === IPDelayType.Network
              ? "ipv6_delay"
              : `${settings.delayedIPVersion === "IPv4" ? "ipv4" : "ipv6"}_handshake_delay`]:
              ipDelay,
            [`${settings.delayedProtocol === Protocol.QUIC ? "quic" : "tls"}_handshake_delay`]:
              protocolDelay,
            https_record: settings.httpsRecord,
          },
          responseHandler,
          sleepAfterSubtest: 2000,
        } satisfies Subtest);
      }

      testParts.push({
        name: `${ipDelay} (${settings.ipDelayType === IPDelayType.Handshake ? "Handshake" : "Network"})`,
        subtests,
      } satisfies TestPart);
    }

    return testParts;
  };

  const buildEnabledSettings = (): EnabledTestSettings => {
    if (settings.ipDelayType === IPDelayType.Network) {
      // disable the "delayed ip version" and "ip delays" settings when the
      // delay type is network (only IPv6 delay is configured)
      const {
        delayedIPVersion,
        ipHandshakeDelayRange,
        ...remainingEnabledSettings
      } = enabledSettings;
      return remainingEnabledSettings;
    }

    return enabledSettings;
  };

  return (
    <TestSkeleton
      enabledSettings={buildEnabledSettings()}
      settings={settings}
      setSettings={setSettings}
      buildSubtests={buildSubtests}
      showSettingsDividers={true}
      requiresIPv4AndIPv6={false}
      resultsUrl="/results/hev3-combined"
      subtestColumnDescription="Protocol Handshake Delay [ms]"
      subtestColumnLabels={protocolHandshakeDelays.map((delay) =>
        delay.toString(),
      )}
      subtestRowDescription="IP Delay [ms]"
    />
  );
};

const enabledSettings: EnabledTestSettings = {
  repetitions: {
    options: [1, 2, 5, 10],
    defaultOption: 1,
  },
  httpsRecord: {
    options: [
      HTTPSRecord.H3H2,
      HTTPSRecord.H2H3,
      HTTPSRecord.H3,
      HTTPSRecord.H3NoDefault,
      HTTPSRecord.H2,
      HTTPSRecord.None,
    ],
    defaultOption: HTTPSRecord.H3H2,
  },
  ipDelayType: {
    options: [IPDelayType.Handshake, IPDelayType.Network],
    defaultOption: IPDelayType.Handshake,
  },
  delayedIPVersion: {
    options: [IPVersion.IPv4, IPVersion.IPv6],
    defaultOption: IPVersion.IPv6,
  },
  ipHandshakeDelayRange: {
    from: 0,
    to: 800,
    step: 200,
  },
  delayedProtocol: {
    options: [Protocol.QUIC, Protocol.TLS],
    defaultOption: Protocol.QUIC,
  },
  protocolHandshakeDelayRange: {
    from: 0,
    to: 800,
    step: 200,
  },
  randomizeDomains: true,
  autoTransmitResults: false,
  deviceInfo: {},
};

const responseHandler = async (
  response: Response,
): Promise<ResponseHandlerResult> => {
  const serverIP = response.headers.get("X-Server-IP");
  const protocol = response.headers.get("X-Protocol");
  if (!serverIP || !protocol) {
    throw new Error(
      'X-Server-IP" or X-Protocol header not present in response',
    );
  }

  const trace = await response.json();

  const isQUIC = protocol === "HTTP/3.0";
  const isIPv6 = serverIP.includes(":");

  return {
    value: `${isQUIC ? "QUIC" : "TLS"} / ${isIPv6 ? "IPv6" : "IPv4"}`,
    color: isIPv6
      ? isQUIC
        ? TestRunResultColor.Option1
        : TestRunResultColor.Option2
      : isQUIC
        ? TestRunResultColor.Option3
        : TestRunResultColor.Option4,
    connectionAttemptTrace: trace,
    metadata: {
      Protocol: protocol,
    },
  } satisfies ResponseHandlerResult;
};
