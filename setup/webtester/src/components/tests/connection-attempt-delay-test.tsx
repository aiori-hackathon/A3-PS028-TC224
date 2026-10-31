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
import { generateRandomId } from "@/lib/test-utils.ts";
import {
  buildInitialSettingsFromEnabledSettings,
  type EnabledTestSettings,
} from "@/lib/settings.ts";

export const ConnectionAttemptDelayTest: React.FC = () => {
  const [settings, setSettings] = useState<TestSettings>(
    buildInitialSettingsFromEnabledSettings(enabledSettings),
  );
  const [availableDelays, setAvailableDelays] = useState<number[]>([]);

  useEffect(() => {
    fetchAvailableDelays().then((delays) =>
      setAvailableDelays(delays.v1_delays),
    );
  }, []);

  const buildSubtests = async (testRunId: number): Promise<TestPart[]> => {
    const subtests: Subtest[] = [];

    for (let i = 0; i < availableDelays.length; i++) {
      const url = await generateConnectAttemptDelayUrl(
        settings.randomizeDomains,
        availableDelays[i] ?? 0,
        testRunId,
      );

      subtests.push({
        url,
        metadata: { ipv6_delay: availableDelays[i] },
        sleepAfterSubtest: 500,
      } satisfies Subtest);
    }

    return [{ subtests }];
  };

  return (
    <TestSkeleton
      enabledSettings={enabledSettings}
      settings={settings}
      setSettings={setSettings}
      buildSubtests={buildSubtests}
      requiresIPv4AndIPv6={true}
      resultsUrl="/results/connection-attempt-delay"
      subtestColumnDescription="IPv6 Delay [ms]"
      subtestColumnLabels={availableDelays.map((delay) => delay.toString())}
    />
  );
};

const enabledSettings: EnabledTestSettings = {
  repetitions: {
    options: [1, 5, 10, 20, 30, 40, 50],
    defaultOption: 10,
  },
  randomizeDomains: true,
  autoTransmitResults: false,
  deviceInfo: {},
};

export const generateConnectAttemptDelayUrl = async (
  randomizeDomain: boolean,
  delay: number,
  testRunId: number = 0,
): Promise<string> => {
  const happyEyeballsTestDomain = await getHappyEyeballsTestDomain();

  if (randomizeDomain) {
    return `https://id-${generateRandomId()}.delay-${delay}.v1.${happyEyeballsTestDomain}/trace`;
  }

  return `https://id-${testRunId ?? 0}.delay-${delay}.v1.${happyEyeballsTestDomain}/trace`;
};
