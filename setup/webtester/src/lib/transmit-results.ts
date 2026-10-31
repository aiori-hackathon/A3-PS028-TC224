import type {
  Subtest,
  SubtestResult,
  TestRun,
  TestRunRepetition,
  TestSettings,
} from "@/lib/test-run.ts";
import { downloadJSONData } from "@/lib/test-utils.ts";

export const transmitResults = async (
  url: string,
  testRuns: TestRun[],
  settings: TestSettings,
): Promise<void> => {
  const results = mapTestRunsToResults(
    testRuns.filter((testRun) => !testRun.isTransmitted),
    settings,
  );

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(results),
  });

  if (!response.ok) {
    throw new Error(`Failed to transmit the results`);
  }

  for (const testRun of testRuns) {
    testRun.isTransmitted = true;
  }
};

export const downloadResults = async (
  testRuns: TestRun[],
  settings: TestSettings,
): Promise<void> => {
  downloadJSONData(
    `${Math.floor(Date.now() / 1000)}.json`,
    JSON.stringify(mapTestRunsToResults(testRuns, settings)),
  );
};

const mapTestRunsToResults = (testRuns: TestRun[], settings: TestSettings) => {
  const mapSubtestResult = (result: SubtestResult, subtest: Subtest) => ({
    ...(subtest.metadata ?? {}),
    url: result.url,
    value: result.value,
    error: result.error ?? null,
    metadata: result.metadata ?? {},
  });

  const mapSubtest = (subtest: Subtest) =>
    subtest.results && subtest.results.length === 1
      ? mapSubtestResult(subtest.results[0]!, subtest)
      : (subtest.results ?? []).map((result) =>
          mapSubtestResult(result, subtest),
        );

  const mapTestRunRepetitionResults = (testRunRepetition: TestRunRepetition) =>
    testRunRepetition.parts.length === 1
      ? testRunRepetition.parts[0]!.subtests.map(mapSubtest)
      : testRunRepetition.parts.reduce(
          (acc, testPart, testPartIndex) => ({
            ...acc,
            [testPart.name ?? `${testPartIndex}`]:
              testPart.subtests.map(mapSubtest),
          }),
          {},
        );

  return testRuns.flatMap((testRun) =>
    testRun.repetitions.map((testRunRepetition) => ({
      testRunId: testRun.testRunId,
      repetitionNumber: testRunRepetition.repetitionNumber,
      startedAt: testRunRepetition.startedAt,
      platform: window.navigator.platform,
      vendor: window.navigator.vendor,
      userAgent: window.navigator.userAgent,
      userInformation: settings.deviceInfo,
      resolverAddresses: settings.resolverAddresses,
      results: mapTestRunRepetitionResults(testRunRepetition),
    })),
  );
};
