import { describe, expect, it } from "vitest";

import { loadDemoConfig } from "../src/config.js";

const controlledContract = {
  EXPECTED_VCT:
    "http://host.docker.internal:3099/vct/local-controlled-employee",
  EXPECTED_VTJSC_ID:
    "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json",
  ROGUE_VERIFIER_DID: "did:web:rogue.localhost",
  VERANA_RESOLVER_URL: "http://host.docker.internal:3099/v1/trust",
} as const;

function validEnvironment(
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    PLAYGROUND_APP_CLIENT_SECRET: "c".repeat(43),
    SESSION_SECRET: "s".repeat(43),
    ...overrides,
  };
}

describe("demo configuration", () => {
  it("requires the complete rogue denial contract in LOCAL_CONTROLLED", () => {
    const config = loadDemoConfig(
      validEnvironment({
        EVIDENCE_MODE: "LOCAL_CONTROLLED",
        ...controlledContract,
      }),
    );

    expect(config).toMatchObject(controlledContract);
  });

  it.each(Object.keys(controlledContract))(
    "rejects LOCAL_CONTROLLED when %s is absent",
    (missing) => {
      const environment = validEnvironment({
        EVIDENCE_MODE: "LOCAL_CONTROLLED",
        ...controlledContract,
      });
      delete environment[missing];

      expect(() => loadDemoConfig(environment)).toThrow();
    },
  );

  it("preserves the LIVE_VERANA defaults without a rogue denial contract", () => {
    const config = loadDemoConfig(validEnvironment());

    expect(config.EVIDENCE_MODE).toBe("LIVE_VERANA");
  });
});
