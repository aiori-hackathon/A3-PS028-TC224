import React, { useEffect, useState } from "react";
import {
  type Subtest,
  type TestPart,
  type TestSettings,
} from "@/lib/test-run.ts";
import { TestSkeleton } from "@/components/test-skeleton.tsx";
import {
  getHappyEyeballsTestDomain,
  fetchAvailableDelays,
} from "@/lib/he-configuration.ts";
import { generateRandomId } from "@/lib/test-utils";
import {
  buildInitialSettingsFromEnabledSettings,
  type EnabledTestSettings,
} from "@/lib/settings.ts";

export const ResolutionDelayTest: React.FC = () => {
  const [settings, setSettings] = useState<TestSettings>(
    buildInitialSettingsFromEnabledSettings(enabledSettings),
  );
  const [availableDelays, setAvailableDelays] = useState<number[]>([]);

  useEffect(() => {
    fetchAvailableDelays().then((delays) =>
      setAvailableDelays(delays.v2_delays),
    );
  }, []);

  const buildSubtests = async (testRunId: number): Promise<TestPart[]> => {
    const testParts: TestPart[] = [];

    for (const part of [
      { name: "Delay A", dnsRecordType: "a" as const },
      { name: "Delay AAAA", dnsRecordType: "aaaa" as const },
    ]) {
      const subtests: Subtest[] = [];

      for (let i = 0; i < availableDelays.length; i++) {
        const url = await generateResolutionDelayUrl(
          settings.randomizeDomains,
          availableDelays[i] ?? 0,
          part.dnsRecordType,
          testRunId,
        );

        subtests.push({
          url,
          metadata: { [`dns_${part.dnsRecordType}_delay`]: availableDelays[i] },
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
      requiresIPv4AndIPv6={true}
      resultsUrl="/results/resolution-delay"
      subtestColumnDescription="IPv6 Delay [ms]"
      subtestColumnLabels={availableDelays.map((delay) => delay.toString())}
    />
  );
};

const enabledSettings: EnabledTestSettings = {
  repetitions: {
    options: [1, 5, 10, 20, 30, 40, 50],
    defaultOption: 5,
  },
  randomizeDomains: true,
  autoTransmitResults: false,
  resolverAddresses: {},
  deviceInfo: {},
};

export const generateResolutionDelayUrl = async (
  randomizeDomain: boolean,
  dnsDelay: number,
  dnsRecordType: "a" | "aaaa",
  testRunId: number = 0,
): Promise<string> => {
  const happyEyeballsTestDomain = await getHappyEyeballsTestDomain();

  const id = randomizeDomain ? generateRandomId() : testRunId;

  return `https://v2delay_${dnsRecordType}-${id}_${dnsDelay}.v2.${happyEyeballsTestDomain}/trace`;
};
