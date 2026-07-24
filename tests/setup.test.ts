import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { generateLocalData } from "../scripts/setup.js";

const generatedSecretNames = [
  "PLAYGROUND_APP_CLIENT_SECRET",
  "BROKER_CLIENT_SECRET",
  "PAIRWISE_SUB_SECRET",
  "SESSION_SECRET",
  "BROKER_COOKIE_SECRET",
] as const;

const assertGeneratedSecrets = (contents: string): void => {
  const secrets = new Map(
    contents
      .trim()
      .split("\n")
      .map((line) => line.split("=", 2) as [string, string]),
  );
  const values = generatedSecretNames.map((name) => secrets.get(name));
  const valid =
    secrets.size === generatedSecretNames.length &&
    values.every((value) => typeof value === "string" && value.length === 43) &&
    new Set(values).size === generatedSecretNames.length;

  if (!valid) {
    throw new Error("Generated secret contract mismatch");
  }
};

const assertPrivateKeyMaterial = (value: unknown): void => {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Generated private JWK material is missing");
  }
};

describe("generateLocalData", () => {
  it("generates private secrets and a private ES256 JWK", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-"));
    try {
      await generateLocalData(output);

      const env = await readFile(join(output, ".env"), "utf8");
      const jwks = JSON.parse(
        await readFile(join(output, "broker-jwks.json"), "utf8"),
      );
      const key = jwks.keys?.[0];

      assertGeneratedSecrets(env);
      expect(jwks.keys?.length).toBe(1);
      expect(key?.kty).toBe("EC");
      expect(key?.crv).toBe("P-256");
      expect(key?.use).toBe("sig");
      assertPrivateKeyMaterial(key?.d);
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });
});
