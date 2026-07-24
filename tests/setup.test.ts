import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { generateLocalData } from "../scripts/setup.js";

describe("generateLocalData", () => {
  it("generates private secrets and a private ES256 JWK", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-"));
    await generateLocalData(output);

    const env = await readFile(join(output, ".env"), "utf8");
    const jwks = JSON.parse(
      await readFile(join(output, "broker-jwks.json"), "utf8"),
    );

    expect(env).toContain("PAIRWISE_SUB_SECRET=");
    expect(jwks.keys[0]).toMatchObject({
      kty: "EC",
      crv: "P-256",
      use: "sig",
    });
    expect(jwks.keys[0].d).toEqual(expect.any(String));
  });
});
