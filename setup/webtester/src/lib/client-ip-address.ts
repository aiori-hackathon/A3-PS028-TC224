import { getHappyEyeballsTestDomain } from "@/lib/he-configuration.ts";

let clientIPAddress: string[] = [];

export const getClientIPAddress = async (ipVersion: 4 | 6): Promise<string> => {
  if (clientIPAddress[ipVersion]) {
    return clientIPAddress[ipVersion];
  }

  const ipAddress = await fetchClientIPAddress(ipVersion);
  clientIPAddress[ipVersion] = ipAddress;
  return ipAddress;
};

const fetchClientIPAddress = async (ipVersion: 4 | 6): Promise<string> => {
  const happyEyeballsTestDomain = await getHappyEyeballsTestDomain();

  const response = await fetch(
    `https://ipv${ipVersion}-only.v1.${happyEyeballsTestDomain}/my-ip`,
    { cache: "no-cache" },
  );

  if (!response.ok) {
    throw new Error(`Failed to fetch the client ${ipVersion} address`);
  }

  return (await response.text()).trim();
};

export const checkIfIPv4AndIPv6AreAvailable = async (): Promise<void> => {
  await getClientIPAddress(4).catch((_) => {
    throw new Error("No IPv4 address available");
  });

  await getClientIPAddress(6).catch((_) => {
    throw new Error("No IPv6 address available");
  });
};
