import React, { useState } from "react";
import { SettingsSection } from "@/components/settings/settings-section.tsx";
import {
  type TestRun,
  type TestSettings,
  type TestPart,
  executeTestRun,
} from "@/lib/test-run.ts";
import { TestResultTable } from "@/components/test-result-table.tsx";
import { Spinner } from "@/components/ui/spinner.tsx";
import { Button } from "@/components/ui/button.tsx";
import { downloadResults, transmitResults } from "@/lib/transmit-results.ts";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import type { EnabledTestSettings } from "@/lib/settings.ts";
import { downloadJSONData, generateRandomId } from "@/lib/test-utils.ts";

type Props = {
  enabledSettings: EnabledTestSettings;
  settings: TestSettings;
  setSettings: (settings: TestSettings) => void;
  showSettingsDividers?: boolean;
  requiresIPv4AndIPv6: boolean;
  buildSubtests: (testRunId: number) => Promise<TestPart[]>;
  resultsUrl: string;
  subtestColumnDescription: string;
  subtestColumnLabels: string[];
  subtestRowDescription?: string;
};

export const TestSkeleton: React.FC<Props> = ({
  buildSubtests,
  enabledSettings,
  settings,
  setSettings,
  showSettingsDividers = false,
  requiresIPv4AndIPv6,
  resultsUrl,
  subtestColumnDescription,
  subtestRowDescription,
  subtestColumnLabels,
}) => {
  const [testRuns, setTestRuns] = useState<TestRun[]>([]);

  const [isUserInteractionDisabled, setIsUserInteractionDisabled] =
    useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<string>("");

  const forceTableRerender = () => setTestRuns((prev) => [...prev]);

  const withDisabledUserInteraction = async (fn: () => Promise<void>) => {
    try {
      setIsUserInteractionDisabled(true);
      setStatusMessage("");
      await fn();
    } catch (err) {
      alert(err);
    } finally {
      setStatusMessage("");
      setIsUserInteractionDisabled(false);
    }
  };

  const executeTest = () =>
    withDisabledUserInteraction(async () => {
      await executeTestRun(
        settings,
        resultsUrl,
        buildSubtests,
        (testRun) => setTestRuns((prev) => [...prev, testRun]),
        setStatusMessage,
        forceTableRerender,
        requiresIPv4AndIPv6,
      );
    });

  const downloadTestConfiguration = async () => {
    const testParts = await buildSubtests(generateRandomId());
    const configuration = testParts.flatMap((part) =>
      part.subtests.map((subtest) => ({
        ...subtest.metadata,
        url: subtest.url,
      })),
    );

    downloadJSONData("test-configuration.json", JSON.stringify(configuration));
  };

  const transmitTestResults = () =>
    withDisabledUserInteraction(async () => {
      setStatusMessage("Transmitting results...");

      await transmitResults(resultsUrl, testRuns, settings);
      forceTableRerender();
    });

  const allTestRunsTransmitted = testRuns.every(
    (testRun) => testRun.isTransmitted,
  );

  return (
    <div className="py-10 flex flex-col gap-y-10">
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <SettingsSection
            enabledSettings={enabledSettings}
            settings={settings}
            setSettings={setSettings}
            runTest={executeTest}
            downloadTestConfiguration={downloadTestConfiguration}
            showDividers={showSettingsDividers}
            disabled={isUserInteractionDisabled}
            disableProtocolHandshakeDelayRangeSetting={testRuns.length > 0}
          />
        </CardContent>
      </Card>

      {isUserInteractionDisabled && (
        <Alert className="dark">
          <Spinner />
          <AlertTitle>Test is running</AlertTitle>
          <AlertDescription>{statusMessage}</AlertDescription>
        </Alert>
      )}

      {testRuns.length > 0 && (
        <>
          <TestResultTable
            columnDescription={subtestColumnDescription}
            columns={subtestColumnLabels}
            testPartDescription={subtestRowDescription}
            testRuns={testRuns}
          />

          <div className="flex gap-4 items-center">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="default"
                  disabled={isUserInteractionDisabled || allTestRunsTransmitted}
                  onClick={transmitTestResults}
                >
                  Transmit results
                </Button>
              </TooltipTrigger>

              {isUserInteractionDisabled ? (
                <TooltipContent className="max-w-md">
                  Please wait until all test repetitions have finished executing
                </TooltipContent>
              ) : allTestRunsTransmitted ? (
                <TooltipContent className="max-w-md">
                  All test runs have been successfully transmitted. Thank you
                  for your help!
                </TooltipContent>
              ) : (
                <TooltipContent className="max-w-md">
                  If you choose to transmit your results, the web-tester
                  transmits the measurement data along with your user agent and
                  browser vendor information. We do not collect or store your IP
                  address. To help us better interpret the test results, you can
                  optionally provide details about your network environment in
                  the device and user information field.
                </TooltipContent>
              )}
            </Tooltip>

            <Button
              variant="secondary"
              disabled={isUserInteractionDisabled}
              onClick={() => downloadResults(testRuns, settings)}
            >
              Download results
            </Button>
          </div>
        </>
      )}
    </div>
  );
};
