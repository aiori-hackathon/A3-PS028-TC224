import { IPDelayType, HTTPSRecord } from "@/lib/test-run.ts";
import { getHappyEyeballsTestDomain } from "@/lib/he-configuration.ts";

export const generateRandomId = (): number => {
  const max = 100000;
  const min = 0;

  return Math.floor(Math.random() * (max - min + 1)) + min;
};

export const sleep = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const generateHEv3TestUrl = async (
  randomizeDomain: boolean,
  ipv4Delay: number,
  ipv6Delay: number,
  quicDelay: number,
  tlsDelay: number,
  httpsRecord: HTTPSRecord,
  delayType: IPDelayType,
  testRunId: number = 0,
): Promise<string> => {
  const happyEyeballsTestDomain = await getHappyEyeballsTestDomain();

  const id = randomizeDomain ? generateRandomId() : testRunId;

  const httpsRR: string = {
    [HTTPSRecord.H3H2]: "h3h2",
    [HTTPSRecord.H2H3]: "h2h3",
    [HTTPSRecord.H3]: "h3",
    [HTTPSRecord.H3NoDefault]: "h3-no-default",
    [HTTPSRecord.H2]: "h2",
    [HTTPSRecord.None]: "none",
  }[httpsRecord];

  const layer: string = {
    [IPDelayType.Handshake]: "l4",
    [IPDelayType.Network]: "l3",
  }[delayType];

  return `https://${layer}_https-${httpsRR}_ipv4-${ipv4Delay}_ipv6-${ipv6Delay}_quic-${quicDelay}_tls-${tlsDelay}_id-${id}.v3-quic.${happyEyeballsTestDomain}/trace`;
};

export const generateRange = (
  start: number,
  end: number,
  step: number,
): number[] => {
  const range: number[] = [];

  for (let i = start; i <= end; i += step) {
    range.push(i);
  }

  if (range.length === 0) {
    range.push(start);
  }

  return range;
};

export const downloadJSONData = (fileName: string, data: string) => {
  const blob = new Blob([data], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link); // Required for Firefox
  link.click();

  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
