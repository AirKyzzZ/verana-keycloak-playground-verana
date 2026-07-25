import { describe, expect, it } from "vitest";

import { loadBrokerConfig } from "../src/config.js";
import { authorizeReceipt } from "../src/policy.js";
import type { ExpectedReceipt } from "../src/types.js";
import {
  EXPECTED_VCT,
  EXPECTED_VTJSC_ID,
  positiveSession,
} from "./fixtures/positive-receipt.js";

// The registry block used to be pinned by three zod literals. These are the
// exact values those literals accepted, and the tuple the broker is configured
// with below, so "accepted by the new check" and "accepted by the old literals"
// are directly comparable.
const LEGACY_NETWORK = "vna-testnet-1";
const LEGACY_TRUST_REGISTRY = 184;
const LEGACY_SCHEMA = 249;

const legacyExpected: ExpectedReceipt = {
  sessionId: "vs-1",
  vct: EXPECTED_VCT,
  vtjscId: EXPECTED_VTJSC_ID,
  network: LEGACY_NETWORK,
  ecosystemId: LEGACY_TRUST_REGISTRY,
  credentialSchemaId: LEGACY_SCHEMA,
};

const minimalEnvironment = {
  BROKER_CLIENT_SECRET: "broker-client-secret-at-least-32-bytes",
  BROKER_COOKIE_SECRET: "broker-cookie-secret-at-least-32-bytes",
  EXPECTED_VCT: "https://credentials.example/employee",
  EXPECTED_VTJSC_ID: "employee-schema",
  PAIRWISE_SUB_SECRET: "pairwise-sub-secret-at-least-32-bytes",
};

function authorizeWithRegistry(
  registry: Record<string, unknown>,
  expected: ExpectedReceipt = legacyExpected,
): string {
  const receipt = structuredClone(positiveSession) as unknown as {
    receipt: { registry: Record<string, unknown> };
  };
  receipt.receipt.registry = { vtjscId: EXPECTED_VTJSC_ID, ...registry };

  try {
    authorizeReceipt(receipt, expected);
    return "authorized";
  } catch (error) {
    return error instanceof Error ? error.message : "non_error_thrown";
  }
}

const legacyTuple = {
  network: LEGACY_NETWORK,
  trustRegistry: LEGACY_TRUST_REGISTRY,
  schema: LEGACY_SCHEMA,
};

describe("registry tuple: configured check versus the removed zod literals", () => {
  it("authorizes the one tuple the removed literals accepted", () => {
    expect(authorizeWithRegistry(legacyTuple)).toBe("authorized");
  });

  it.each([
    ["a neighbouring network", { ...legacyTuple, network: "vna-testnet-2" }],
    ["mainnet", { ...legacyTuple, network: "vna-mainnet-1" }],
    ["the controlled network", { ...legacyTuple, network: "local-controlled" }],
    ["a trailing space", { ...legacyTuple, network: `${LEGACY_NETWORK} ` }],
    ["a leading space", { ...legacyTuple, network: ` ${LEGACY_NETWORK}` }],
    ["a case variant", { ...legacyTuple, network: "VNA-TESTNET-1" }],
    ["a whitespace network", { ...legacyTuple, network: " " }],
    ["an empty network", { ...legacyTuple, network: "" }],
    ["a numeric network", { ...legacyTuple, network: LEGACY_TRUST_REGISTRY }],
    ["a null network", { ...legacyTuple, network: null }],
    ["an array network", { ...legacyTuple, network: [LEGACY_NETWORK] }],
    ["a missing network", { trustRegistry: 184, schema: 249 }],
    ["a neighbouring registry", { ...legacyTuple, trustRegistry: 185 }],
    ["registry zero", { ...legacyTuple, trustRegistry: 0 }],
    ["a negative registry", { ...legacyTuple, trustRegistry: -184 }],
    ["a fractional registry", { ...legacyTuple, trustRegistry: 184.5 }],
    ["a NaN registry", { ...legacyTuple, trustRegistry: Number.NaN }],
    [
      "an infinite registry",
      { ...legacyTuple, trustRegistry: Number.POSITIVE_INFINITY },
    ],
    [
      "an unsafe registry",
      { ...legacyTuple, trustRegistry: Number.MAX_SAFE_INTEGER + 2 },
    ],
    ["a stringified registry", { ...legacyTuple, trustRegistry: "184" }],
    ["a null registry", { ...legacyTuple, trustRegistry: null }],
    ["a boolean registry", { ...legacyTuple, trustRegistry: true }],
    ["a missing registry", { network: LEGACY_NETWORK, schema: 249 }],
    ["a neighbouring schema", { ...legacyTuple, schema: 250 }],
    ["schema zero", { ...legacyTuple, schema: 0 }],
    ["a negative schema", { ...legacyTuple, schema: -249 }],
    ["a fractional schema", { ...legacyTuple, schema: 249.5 }],
    ["a stringified schema", { ...legacyTuple, schema: "249" }],
    ["a null schema", { ...legacyTuple, schema: null }],
    ["a missing schema", { network: LEGACY_NETWORK, trustRegistry: 184 }],
    [
      "a swapped pair",
      { network: LEGACY_NETWORK, trustRegistry: 249, schema: 184 },
    ],
  ])("refuses %s", (_label, registry) => {
    expect(authorizeWithRegistry(registry)).not.toBe("authorized");
  });

  it("never leaks the smuggled value in the denial message", () => {
    const denial = authorizeWithRegistry({
      ...legacyTuple,
      network: "attacker-controlled-network-name",
    });

    expect(denial).not.toContain("attacker-controlled-network-name");
    expect(denial).not.toContain(LEGACY_NETWORK);
  });

  it("compares the configured tuple strictly, never by coercion", () => {
    expect(
      authorizeWithRegistry(legacyTuple, {
        ...legacyExpected,
        ecosystemId: "184" as unknown as number,
      }),
    ).toBe("registry_mismatch");
    expect(
      authorizeWithRegistry(legacyTuple, {
        ...legacyExpected,
        credentialSchemaId: "249" as unknown as number,
      }),
    ).toBe("registry_mismatch");
    expect(
      authorizeWithRegistry(legacyTuple, {
        ...legacyExpected,
        network: undefined as unknown as string,
      }),
    ).toBe("registry_mismatch");
  });

  it("cannot be disabled by a wildcard-looking configured tuple", () => {
    for (const network of ["*", "", " ", "any"]) {
      expect(
        authorizeWithRegistry(legacyTuple, { ...legacyExpected, network }),
      ).toBe("registry_mismatch");
    }
  });
});

describe("registry tuple configuration hygiene", () => {
  it("defaults a missing tuple to the controlled network and testnet ids", () => {
    const config = loadBrokerConfig(minimalEnvironment);

    expect(config.EXPECTED_NETWORK).toBe("local-controlled");
    expect(config.EXPECTED_ECOSYSTEM_ID).toBe(184);
    expect(config.EXPECTED_CREDENTIAL_SCHEMA_ID).toBe(249);
  });

  it("fails closed when the defaulted tuple meets a testnet receipt", () => {
    const config = loadBrokerConfig(minimalEnvironment);

    expect(
      authorizeWithRegistry(legacyTuple, {
        ...legacyExpected,
        network: config.EXPECTED_NETWORK,
        ecosystemId: config.EXPECTED_ECOSYSTEM_ID,
        credentialSchemaId: config.EXPECTED_CREDENTIAL_SCHEMA_ID,
      }),
    ).toBe("registry_mismatch");
  });

  it("rejects a blank network rather than defaulting it", () => {
    expect(() =>
      loadBrokerConfig({ ...minimalEnvironment, EXPECTED_NETWORK: "" }),
    ).toThrow();
  });

  it.each(["not-a-number", "-1", "1.5"])(
    "rejects the unusable ecosystem id %s at startup",
    (value) => {
      expect(() =>
        loadBrokerConfig({
          ...minimalEnvironment,
          EXPECTED_ECOSYSTEM_ID: value,
        }),
      ).toThrow();
    },
  );

  // Defect: `z.coerce.number()` turns a blank env value into 0 instead of
  // failing, so `EXPECTED_ECOSYSTEM_ID=` silently binds the broker to
  // ecosystem 0 rather than refusing to start. Flip this to `it.each(...)`
  // once config parsing rejects blank registry ids.
  it.fails.each(["", " ", "\n"])(
    "rejects the blank ecosystem id %j at startup",
    (value) => {
      expect(() =>
        loadBrokerConfig({
          ...minimalEnvironment,
          EXPECTED_ECOSYSTEM_ID: value,
          EXPECTED_CREDENTIAL_SCHEMA_ID: value,
        }),
      ).toThrow();
    },
  );

  it.each(["", " ", "\n"])(
    "moves the authorization boundary to registry zero for the blank id %j",
    (value) => {
      const config = loadBrokerConfig({
        ...minimalEnvironment,
        EXPECTED_ECOSYSTEM_ID: value,
        EXPECTED_CREDENTIAL_SCHEMA_ID: value,
      });

      expect(config.EXPECTED_ECOSYSTEM_ID).toBe(0);
      expect(config.EXPECTED_CREDENTIAL_SCHEMA_ID).toBe(0);
      expect(
        authorizeWithRegistry(legacyTuple, {
          ...legacyExpected,
          network: config.EXPECTED_NETWORK,
          ecosystemId: config.EXPECTED_ECOSYSTEM_ID,
          credentialSchemaId: config.EXPECTED_CREDENTIAL_SCHEMA_ID,
        }),
      ).toBe("registry_mismatch");
    },
  );
});
