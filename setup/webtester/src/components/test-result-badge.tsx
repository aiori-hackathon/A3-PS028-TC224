import React, { useState } from "react";
import {
  type ConnectionAttemptTrace,
  type SubtestResult,
} from "@/lib/test-run.ts";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip.tsx";

type Props = {
  result: SubtestResult;
  testRunMetadata?: { key: string; value: string }[];
};

export const TestResultBadge: React.FC<Props> = ({
  result,
  testRunMetadata,
}) => {
  const [isTooltipOpen, setTooltipOpen] = useState(false);

  return (
    <Tooltip open={isTooltipOpen} onOpenChange={setTooltipOpen}>
      <TooltipTrigger asChild={true}>
        <div
          style={{
            background: result.color,
          }}
          className="w-max px-4 py-1 rounded-full text-white"
          onClick={(event) => {
            event.preventDefault();
            setTooltipOpen((open) => !open);
          }}
        >
          {result.value}
        </div>
      </TooltipTrigger>
      <TooltipContent>
        <ResultBadgeTooltipContent
          result={result}
          testRunMetadata={testRunMetadata ?? []}
        />
      </TooltipContent>
    </Tooltip>
  );
};

const ResultBadgeTooltipContent: React.FC<Props> = ({
  result,
  testRunMetadata,
}) => {
  return (
    <>
      <KeyValueTable>
        <KeyValueTableRow name="URL">
          <a
            href={result.url}
            className="underline underline-offset-4 cursor-pointer hover:opacity-80"
          >
            {result.url}
          </a>
        </KeyValueTableRow>

        {testRunMetadata?.map(({ key, value }) => (
          <KeyValueTableRow name={key} key={key}>
            {value}
          </KeyValueTableRow>
        ))}

        {result.error && (
          <KeyValueTableRow name="Error">{result.error}</KeyValueTableRow>
        )}
      </KeyValueTable>

      {result.metadata && Object.entries(result.metadata).length > 0 && (
        <KeyValueTable>
          {Object.entries(result.metadata).map(([key, value]) => (
            <KeyValueTableRow name={key} key={key}>
              {value}
            </KeyValueTableRow>
          ))}
        </KeyValueTable>
      )}

      {result.requestTiming && (
        <KeyValueTable>
          <KeyValueTableRow name="Total Fetch Duration">
            {result.requestTiming.totalDurationMs.toFixed(2)} ms
          </KeyValueTableRow>

          <KeyValueTableRow name="DNS Lookup Duration">
            {result.requestTiming.dnsLookupDurationMs.toFixed(2)} ms
          </KeyValueTableRow>

          <KeyValueTableRow name="Connect Duration">
            {`${result.requestTiming.connectionEstablishmentDurationMs.toFixed(
              2,
            )} ms (TLS negotiation: ${result.requestTiming.tlsNegotiationDurationMs.toFixed(
              2,
            )} ms)`}
          </KeyValueTableRow>

          <KeyValueTableRow name="Request Duration">
            {result.requestTiming.requestDurationMs.toFixed(2)} ms
          </KeyValueTableRow>
        </KeyValueTable>
      )}

      {result.connectionAttemptTrace &&
        result.connectionAttemptTrace.length > 0 && (
          <KeyValueTable>
            <KeyValueTableRow name="Connection Attempt Trace">
              <ConnectionAttemptTraceVisualization
                trace={result.connectionAttemptTrace}
              />
            </KeyValueTableRow>
          </KeyValueTable>
        )}
    </>
  );
};

const KeyValueTable: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-[11em_1fr] gap-x-4 gap-y-1.5 p-2">
      {children}
    </div>
  );
};

const KeyValueTableRow: React.FC<{
  name: string;
  children?: React.ReactNode | string;
}> = ({ name, children }) => {
  return (
    <>
      <div className="text-muted font-semibold mt-3 sm:mt-0 sm:text-right">
        {name}
      </div>
      <div>{children}</div>
    </>
  );
};

const ConnectionAttemptTraceVisualization: React.FC<{
  trace: ConnectionAttemptTrace;
}> = ({ trace }) => {
  const baseTimestamp = trace[0]?.timestamp ?? 0;

  return (
    <div className="grid grid-cols-[max-content_max-content_max-content_max-content] gap-x-4 gap-y-1.5">
      <div className="text-right">Relative Time</div>
      <div>Protocol</div>
      <div>IP Version</div>
      <div className="max-sm:hidden">Source Address</div>
      <div className="sm:hidden">Source Port</div>

      {trace.map((attempt, index) => (
        <React.Fragment key={index}>
          <pre className="text-right">
            T+{attempt.timestamp - baseTimestamp} ms
          </pre>
          <pre>{attempt.protocol}</pre>
          <pre>{attempt.ipVersion}</pre>
          <pre className="max-sm:hidden">{attempt.sourceAddress}</pre>
          <pre className="sm:hidden">{attempt.sourcePort}</pre>
        </React.Fragment>
      ))}
    </div>
  );
};
