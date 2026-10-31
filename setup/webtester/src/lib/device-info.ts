import {
  checkIfIPv4AndIPv6AreAvailable,
  getClientIPAddress,
} from "@/lib/client-ip-address.ts";

export const getDeviceInfo = async (): Promise<string> => {
  await checkIfIPv4AndIPv6AreAvailable();

  const userIPv4Address = await getClientIPAddress(4);
  const userIPv6Address = await getClientIPAddress(6);

  const deviceInfo = {
    platform: window.navigator.platform,
    vendor: window.navigator.vendor,
    clientIPv4: anonymizeIPv4Address(userIPv4Address),
    clientIPv6: anonymizeIPv6Address(userIPv6Address),
    other: "",
  };

  return JSON.stringify(deviceInfo);
};

const anonymizeIPv4Address = (ipAddress: string): string => {
  const octets = ipAddress.split(".");
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
};

const anonymizeIPv6Address = (ipAddress: string): string => {
  const fullIpv6 = expandIPv6(ipAddress);

  const parts = fullIpv6.split(":");
  return `${parts[0]}:${parts[1]}:${parts[2]}::/48`;
};

const expandIPv6 = (shortAddress: string): string => {
  if ((shortAddress.match(/:/g) || []).length === 7) {
    return shortAddress;
  }

  if (shortAddress.includes("::")) {
    const parts = shortAddress.split("::");
    const beforeParts = parts[0]?.split(":") ?? [];
    const afterParts = parts[1]?.split(":") ?? [];

    const zeroGroups = Array(8 - beforeParts.length - afterParts.length).fill(
      "0",
    );

    return [...beforeParts, ...zeroGroups, ...afterParts].join(":");
  }

  throw new Error("Error at expanding IPv6 address");
};
