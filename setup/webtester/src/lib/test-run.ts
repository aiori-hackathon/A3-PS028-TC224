import { checkIfIPv4AndIPv6AreAvailable } from "@/lib/client-ip-address.ts";
import { transmitResults } from "@/lib/transmit-results.ts";
import { generateRandomId, sleep } from "@/lib/test-utils.ts";

export const executeTestRun = async (
  settings: TestSettings,
  resultsUrl: string,
  buildSubtests: (testRunId: number) => Promise<TestPart[]>,
  addTestRunToTable: (testRun: TestRun) => void,
  setStatusMessage: (message: string) => void,
  forceTableRerender: () => void,
  requiresIPv4AndIPv6: boolean,
) => {
  if (requiresIPv4AndIPv6) {
    setStatusMessage("Checking if IPv4 and IPv6 are available...");
    await checkIfIPv4AndIPv6AreAvailable();
  }

  const testRun: TestRun = {
    testRunId: generateRandomId(),
    settings,
    isTransmitted: false,
    repetitions: [],
  };
  addTestRunToTable(testRun);

  for (
    let repetition = 1;
    repetition <= (settings.repetitions ?? 1);
    repetition++
  ) {
    const parts = await buildSubtests(testRun.testRunId);

    testRun.repetitions.push({
      repetitionNumber: repetition,
      startedAt: new Date(),
      parts,
    } satisfies TestRunRepetition);

    for (const part of parts) {
      for (const subtest of part.subtests) {
        setStatusMessage(
          settings.repetitions
            ? `Running tests in repetition ${repetition} / ${settings.repetitions}...`
            : `Running tests...`,
        );

        subtest.isRunning = true;
        forceTableRerender();

        subtest.results ??= [];

        const numberOfRequests = subtest.numberOfRequests ?? 1;
        for (let i = 0; i < numberOfRequests; i++) {
          const result = await executeSubtest(subtest).catch(
            (error: Error) =>
              ({
                value: "ERR",
                color: TestRunResultColor.Error,
                url: subtest.url,
                error: error.message,
              }) satisfies SubtestResult,
          );

          subtest.results.push(result);
          forceTableRerender();

          if (subtest.sleepBetweenRequests && i < numberOfRequests - 1) {
            await sleep(subtest.sleepBetweenRequests);
          }
        }

        subtest.isRunning = false;
        forceTableRerender();

        if (subtest.sleepAfterSubtest) {
          setStatusMessage(
            `Waiting for ${subtest.sleepAfterSubtest} ms before continuing...`,
          );
          await sleep(subtest.sleepAfterSubtest);
        }
      }
    }

    if (repetition < (settings.repetitions ?? 1)) {
      setStatusMessage(
        `Waiting for 5 seconds before starting the next repetition...`,
      );
      await sleep(5000);
    }
  }

  if (settings.autoTransmitResults) {
    setStatusMessage("Transmitting results...");

    await transmitResults(resultsUrl, [testRun], settings);
    forceTableRerender();
  }
};

const executeSubtest = async (subtest: Subtest): Promise<SubtestResult> => {
  const observer = observeRequestTiming(subtest.url);

  const response = await fetch(subtest.url, { cache: "no-store" });

  if (!response.ok) {
    throw new Error(
      `Response has status code: ${response.status} ${response.statusText}`,
    );
  }

  const responseHandler = subtest.responseHandler ?? defaultResponseHandler;
  const result = await responseHandler(response);

  const requestTiming = await observer;

  return {
    value: result.value,
    color: result.color,
    url: subtest.url,
    requestTiming,
    connectionAttemptTrace: result.connectionAttemptTrace ?? [],
    metadata: result.metadata ?? {},
  } satisfies SubtestResult;
};

const observeRequestTiming = (url: string): Promise<RequestTiming> =>
  new Promise((resolve) => {
    const observer = new PerformanceObserver((list, observer) => {
      const entries = list.getEntriesByType("resource");

      const entry = entries.find((entry) => entry.name === url);
      if (entry && entry instanceof PerformanceResourceTiming) {
        // https://developer.mozilla.org/en-US/docs/Web/API/PerformanceResourceTiming
        resolve({
          totalDurationMs: entry.responseEnd - entry.fetchStart,
          dnsLookupDurationMs: entry.domainLookupEnd - entry.domainLookupStart,
          connectionEstablishmentDurationMs:
            entry.connectEnd - entry.connectStart,
          tlsNegotiationDurationMs:
            entry.requestStart - entry.secureConnectionStart,
          requestDurationMs: entry.responseStart - entry.requestStart,
        } satisfies RequestTiming);

        observer.disconnect();
      }
    });

    observer.observe({ type: "resource", buffered: false });
  });

const defaultResponseHandler = async (
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

  const isIPv6 = serverIP.includes(":");

  return {
    value: isIPv6 ? "IPv6" : "IPv4",
    color: isIPv6 ? TestRunResultColor.Option1 : TestRunResultColor.Option2,
    connectionAttemptTrace: trace,
    metadata: {
      Protocol: protocol,
    },
  };
};

export type TestSettings = {
  repetitions: number;

  httpsRecord: HTTPSRecord;
  ipDelayType: IPDelayType;
  delayedIPVersion: IPVersion;
  delayedProtocol: Protocol;
  protocolHandshakeDelayRange: DelayRange;
  ipHandshakeDelayRange: DelayRange;

  autoTransmitResults: boolean;
  randomizeDomains: boolean;
  resolverAddresses: string;
  deviceInfo: string;
};

export type TestRun = {
  testRunId: number;
  settings: TestSettings;
  isTransmitted: boolean;
  repetitions: TestRunRepetition[];
};

export type TestRunRepetition = {
  repetitionNumber: number;
  startedAt: Date;
  parts: TestPart[];
};

export type TestPart = {
  name?: string;
  subtests: Subtest[];
};

export type Subtest = {
  url: string;
  isRunning?: boolean;
  results?: SubtestResult[];
  responseHandler?: (response: Response) => Promise<ResponseHandlerResult>;
  numberOfRequests?: number;
  sleepBetweenRequests?: number;
  sleepAfterSubtest?: number;
  metadata?: Record<string, string | number | undefined>;
};

export type SubtestResult = {
  value: string;
  color: TestRunResultColor;
  url: string;
  error?: string;
  requestTiming?: RequestTiming;
  connectionAttemptTrace?: ConnectionAttemptTrace;
  metadata?: SubtestResultMetadata;
};

export type RequestTiming = {
  totalDurationMs: number;
  dnsLookupDurationMs: number;
  connectionEstablishmentDurationMs: number;
  tlsNegotiationDurationMs: number;
  requestDurationMs: number;
};

// https://ui.shadcn.com/colors
export const enum TestRunResultColor {
  Error = "#b91c1c", // red-700
  Option1 = "#0e7490", // cyan-700
  Option2 = "#b45309", // amber-700
  Option3 = "#6d28d9", // violet-700
  Option4 = "#4d7c0f", // lime-700
}

export type SubtestResultMetadata = Record<string, string>;

export type ConnectionAttemptInfo = {
  timestamp: number;
  ipVersion: string;
  protocol: string;
  sourceAddress: string;
  sourcePort: number;
};

export type ConnectionAttemptTrace = ConnectionAttemptInfo[];

export type ResponseHandlerResult = {
  value: string;
  color: TestRunResultColor;
  connectionAttemptTrace?: ConnectionAttemptTrace;
  metadata?: SubtestResultMetadata;
};

export type DelayRange = {
  from: number;
  to: number;
  step: number;
};

export const enum IPVersion {
  IPv4 = "IPv4",
  IPv6 = "IPv6",
}

export const enum Protocol {
  QUIC = "QUIC",
  TLS = "TLS/TCP",
}

export const enum IPDelayType {
  Handshake = "Handshake (introduced once during QUIC or TLS handshake)",
  Network = "Network latency (introduced for every packet)",
}

export const enum HTTPSRecord {
  H3H2 = "alpn=h3,h2",
  H2H3 = "alpn=h2,h3",
  H3 = "alpn=h3",
  H3NoDefault = "alpn=h3 no-default-alpn",
  H2 = "alpn=h2",
  None = "NONE",
}
