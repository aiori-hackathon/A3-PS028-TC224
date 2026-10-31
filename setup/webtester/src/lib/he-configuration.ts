let happyEyeballsTestsDomain: string | null = null;

export const getHappyEyeballsTestDomain = async (): Promise<string> => {
  if (happyEyeballsTestsDomain) {
    return happyEyeballsTestsDomain;
  }

  const response = await fetch("/he-test-domain", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Failed to fetch the Happy Eyeballs test domain");
  }

  const domain = (await response.text()).trim();
  happyEyeballsTestsDomain = domain;
  return domain;
};

export const fetchAvailableDelays = async (): Promise<Delays> => {
  const response = await fetch("/delays.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Failed to fetch the available delays");
  }

  return await response.json() as Delays;
};

export type Delays = {
  v1_delays: number[];
  v2_delays: number[];
};
