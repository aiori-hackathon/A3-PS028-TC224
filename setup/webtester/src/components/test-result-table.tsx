import React from "react";
import { cn } from "@/lib/utils.ts";
import { TestResultBadge } from "@/components/test-result-badge.tsx";
import { Spinner } from "@/components/ui/spinner.tsx";
import { HTTPSRecord, type TestRun } from "@/lib/test-run.ts";
import { CloudUploadIcon, type LucideIcon, ShuffleIcon } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";

type Props = {
  columnDescription: string;
  columns: string[];
  testPartDescription: string | undefined;
  testRuns: TestRun[];
};

export const TestResultTable: React.FC<Props> = ({
  columnDescription,
  columns,
  testPartDescription,
  testRuns,
}) => {
  const hasTestPartName = testRuns.some((testRun) =>
    testRun.repetitions.some((repetition) =>
      repetition.parts.some((testPart) => testPart.name),
    ),
  );

  return (
    <div className="relative">
      <div className="overflow-x-auto pb-2">
        <table className="w-full text-sm">
          <thead>
            <tr>
              <th className="text-left whitespace-nowrap px-3 pt-5 border-r w-30">
                Test Run #
              </th>
              <th className="text-left whitespace-nowrap px-3 pt-5 border-r w-30">
                Started At
              </th>
              {hasTestPartName && (
                <th className="text-left whitespace-nowrap px-3 pt-5 border-r w-30">
                  {testPartDescription ?? "Part"}
                </th>
              )}
              <th
                className="text-left whitespace-nowrap px-3 pt-5"
                colSpan={columns.length}
              >
                {columnDescription}
              </th>
            </tr>
            <tr>
              <th className="border-r" />
              <th className="border-r" />
              {hasTestPartName && <th className="border-r" />}
              {columns.map((column, index) => (
                <th
                  key={column}
                  className={cn(
                    "p-3 align-top",
                    index < columns.length - 1 && "border-r",
                  )}
                >
                  <div className="[writing-mode:vertical-rl] rotate-180 text-right inline whitespace-pre m-auto">
                    {column}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {testRuns.flatMap((testRun, testRunNumber) =>
              testRun.repetitions.flatMap((repetition) =>
                repetition.parts.map((testPart, testPartIndex) => (
                  <tr
                    key={`${testRun.testRunId}|${repetition.repetitionNumber}|${testPartIndex}`}
                    className="border-t"
                  >
                    {testPartIndex === 0 && (
                      <>
                        <td
                          className="whitespace-nowrap px-3 border-r"
                          rowSpan={repetition.parts.length}
                        >
                          <div className="flex gap-2 items-center font-bold">
                            <Tooltip>
                              <TooltipTrigger className="mr-2">
                                {testRun.settings.repetitions
                                  ? `#${testRunNumber + 1} (${repetition.repetitionNumber} / ${testRun.settings.repetitions})`
                                  : `#${testRunNumber + 1}`}
                              </TooltipTrigger>
                              <TooltipContent>
                                <span className="font-semibold">
                                  Test Run ID:
                                </span>{" "}
                                {testRun.testRunId}
                              </TooltipContent>
                            </Tooltip>

                            {testRun.settings.randomizeDomains && (
                              <TestRunInfoBadge
                                icon={ShuffleIcon}
                                tooltip="Randomized domains"
                              />
                            )}

                            {testRun.isTransmitted && (
                              <TestRunInfoBadge
                                icon={CloudUploadIcon}
                                tooltip="Transmitted"
                              />
                            )}
                          </div>
                        </td>

                        <td
                          className="whitespace-break-spaces px-3 border-r"
                          rowSpan={repetition.parts.length}
                        >
                          {repetition.startedAt.toLocaleString()}
                        </td>
                      </>
                    )}

                    {hasTestPartName && (
                      <td className="whitespace-nowrap p-3 border-r">
                        {testPart.name}
                      </td>
                    )}

                    {testPart.subtests.map((subtest, index) => (
                      <td
                        key={index}
                        className={cn(
                          "p-3",
                          index < columns.length - 1 && "border-r",
                        )}
                      >
                        <div className="grid justify-items-center gap-1">
                          {subtest.results &&
                            subtest.results.map((result, index) => (
                              <TestResultBadge
                                result={result}
                                key={index}
                                testRunMetadata={[
                                  ...(subtest.numberOfRequests
                                    ? [
                                        {
                                          key: "Request",
                                          value: `${index + 1} / ${subtest.numberOfRequests}`,
                                        },
                                      ]
                                    : []),
                                  ...(testRun.settings.httpsRecord !==
                                  HTTPSRecord.None
                                    ? [
                                        {
                                          key: "HTTPS RR",
                                          value: testRun.settings.httpsRecord,
                                        },
                                      ]
                                    : []),
                                ]}
                              />
                            ))}

                          {subtest.isRunning && <Spinner />}
                        </div>
                      </td>
                    ))}
                  </tr>
                )),
              ),
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const TestRunInfoBadge: React.FC<{
  icon: LucideIcon;
  tooltip: string;
}> = ({ icon: Icon, tooltip }) => (
  <Tooltip>
    <TooltipTrigger>
      <div className="size-7 bg-secondary text-secondary-foreground grid place-items-center rounded-md">
        <Icon className="size-3.5" />
      </div>
    </TooltipTrigger>
    <TooltipContent>{tooltip}</TooltipContent>
  </Tooltip>
);
