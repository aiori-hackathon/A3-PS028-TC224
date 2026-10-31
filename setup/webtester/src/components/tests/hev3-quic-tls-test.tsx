import React, { useState } from "react";
import {
  HTTPSRecord,
  IPDelayType,
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

export const HEv3QuicTlsTest: React.FC = () => {
  const [settings, setSettings] = useState<TestSettings>(
    buildInitialSettingsFromEnabledSettings(enabledSettings),
  );

  const handshakeDelays = generateRange(
    settings.protocolHandshakeDelayRange.from,
    settings.protocolHandshakeDelayRange.to,
    settings.protocolHandshakeDelayRange.step,
  );

  const buildSubtests = async (testRunId: number): Promise<TestPart[]> => {
    const testParts: TestPart[] = [];

    for (const part of [
      {
        name: "Delay QUIC",
        protocol: Protocol.QUIC,
      },
      {
        name: "Delay TLS/TCP",
        protocol: Protocol.TLS,
      },
    ]) {
      const subtests: Subtest[] = [];

      for (const delay of handshakeDelays) {
        const url = await generateHEv3TestUrl(
          settings.randomizeDomains,
          0,
          0,
          part.protocol === Protocol.QUIC ? delay : 0,
          part.protocol === Protocol.TLS ? delay : 0,
          (settings.httpsRecord as HTTPSRecord) ?? HTTPSRecord.H3H2,
          IPDelayType.Handshake,
          testRunId,
        );

        subtests.push({
          url,
          metadata: {
            [`${part.protocol === Protocol.QUIC ? "quic" : "tls"}_handshake_delay`]:
              delay,
            https_record: settings.httpsRecord,
          },
          responseHandler,
          sleepAfterSubtest: 2000,
        } satisfies Subtest);
      }

      testParts.push({ name: part.name, subtests } satisfies TestPart);
    }

    return testParts;
  };

  return (
    <TestSkeleton
      enabledSettings={enabledSettings}
      settings={settings}
      setSettings={setSettings}
      buildSubtests={buildSubtests}
      requiresIPv4AndIPv6={false}
      resultsUrl="/results/hev3-quic-tls"
      subtestColumnDescription="Protocol Handshake Delay [ms]"
      subtestColumnLabels={handshakeDelays.map((delay) => delay.toString())}
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

  return {
    value: isQUIC ? "QUIC" : "TLS",
    color: isQUIC ? TestRunResultColor.Option1 : TestRunResultColor.Option2,
    connectionAttemptTrace: trace,
    metadata: {
      Protocol: protocol,
      "Address Family": serverIP.includes(":") ? "IPv6" : "IPv4",
    },
  } satisfies ResponseHandlerResult;
};
