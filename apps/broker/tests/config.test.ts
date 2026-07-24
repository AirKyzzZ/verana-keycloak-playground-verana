import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { loadBrokerConfig } from "../src/config.js";

const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));
const requiredEnvironment = {
  BROKER_CLIENT_SECRET: "broker-client-secret-at-least-32-bytes",
  BROKER_COOKIE_SECRET: "broker-cookie-secret-at-least-32-bytes",
  EXPECTED_VCT: "https://credentials.example/employee",
  EXPECTED_VTJSC_ID: "employee-schema",
  PAIRWISE_SUB_SECRET: "pairwise-sub-secret-at-least-32-bytes",
};

describe("broker generated-data paths", () => {
  it("resolves a relative JWKS path from the repository root when cwd is the broker package", () => {
    const previousCwd = process.cwd();
    process.chdir(join(repositoryRoot, "apps", "broker"));
    try {
      const config = loadBrokerConfig({
        ...requiredEnvironment,
        BROKER_JWKS_PATH: ".data/broker-jwks.json",
      });

      expect(config.BROKER_JWKS_PATH).toBe(
        join(repositoryRoot, ".data", "broker-jwks.json"),
      );
      expect(isAbsolute(config.BROKER_JWKS_PATH)).toBe(true);
    } finally {
      process.chdir(previousCwd);
    }
  });

  it("preserves an absolute JWKS override", () => {
    const absolutePath = join(
      repositoryRoot,
      "custom-data",
      "broker-jwks.json",
    );

    const config = loadBrokerConfig({
      ...requiredEnvironment,
      BROKER_JWKS_PATH: absolutePath,
    });

    expect(config.BROKER_JWKS_PATH).toBe(absolutePath);
  });
});
