import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { LOCAL_CONTROLLED } from "../scripts/local-controlled-config.js";
import { generateLocalControlledData } from "../scripts/setup-local-controlled.js";

const VS_SOURCE = "/tmp/reviewed-vs-agent";

function parseEnv(contents: string): Record<string, string> {
  return Object.fromEntries(
    contents
      .trim()
      .split("\n")
      .map((line) => line.split("=", 2) as [string, string]),
  );
}

describe("generateLocalControlledData", () => {
  it("writes unique mode-0600 wallet secrets and exact local identifiers", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-controlled-"));
    try {
      await generateLocalControlledData(output, VS_SOURCE);
      const env = parseEnv(
        await readFile(join(output, "local-controlled.env"), "utf8"),
      );

      expect(env.EVIDENCE_MODE).toBe("LOCAL_CONTROLLED");
      expect(env.VS_AGENT_SOURCE_PATH).toBe(VS_SOURCE);
      expect(env.EXPECTED_ISSUER_DID).toBe("did:web:issuer.localhost%3A3443");
      expect(env.EXPECTED_VERIFIER_DID).toBe(
        "did:web:verifier.localhost%3A3443",
      );
      expect(
        new Set([
          env.ISSUER_WALLET_KEY,
          env.HOLDER_WALLET_KEY,
          env.VERIFIER_WALLET_KEY,
        ]).size,
      ).toBe(3);
      expect(
        new Set([
          env.ISSUER_WALLET_ID,
          env.HOLDER_WALLET_ID,
          env.VERIFIER_WALLET_ID,
        ]).size,
      ).toBe(3);
      const mode = (await stat(join(output, "local-controlled.env"))).mode;
      expect(mode & 0o777).toBe(0o600);
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });

  it("rejects a relative VS Agent source path", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-controlled-"));
    try {
      await expect(
        generateLocalControlledData(output, "../keycloak-subject-claim"),
      ).rejects.toThrow("VS Agent source path must be absolute");
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });

  it("extends the local broker and demo environment without placeholders", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-controlled-"));
    try {
      await generateLocalControlledData(output, VS_SOURCE);
      const controlled = await readFile(
        join(output, "local-controlled.env"),
        "utf8",
      );
      const localEnv = parseEnv(await readFile(join(output, ".env"), "utf8"));

      expect(controlled).not.toMatch(/__[A-Z0-9_]+__/);
      expect(localEnv.EVIDENCE_MODE).toBe("LOCAL_CONTROLLED");
      expect(localEnv.BROKER_ISSUER).toBe("http://localhost:3001");
      expect(localEnv.DEMO_APP_BASE_URL).toBe("http://localhost:3000");
      expect(localEnv.VS_AGENT_ISSUER_BASE_URL).toBe("http://localhost:3101");
      expect(localEnv.VS_AGENT_HOLDER_BASE_URL).toBe("http://localhost:3111");
      expect(localEnv.VS_AGENT_VERIFIER_BASE_URL).toBe("http://localhost:3201");
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });

  it("pins the DID-bound controlled trust contract for the agents", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-controlled-"));
    try {
      await generateLocalControlledData(output, VS_SOURCE);
      const env = parseEnv(
        await readFile(join(output, "local-controlled.env"), "utf8"),
      );

      expect(env.EXPECTED_HOLDER_DID).toBe("did:web:holder.localhost%3A3443");
      expect(env.ROGUE_VERIFIER_DID).toBe(
        "did:web:verifier.localhost%3A3443:rogue",
      );
      expect(env.VERANA_RESOLVER_URL).toBe("https://resolver.localhost:3443");
      expect(env.UNFOLD_VCT).toBe(
        "https://resolver.localhost:3443/vct/local-controlled-employee",
      );
      expect(env.UNFOLD_VTJSC_ID).toBe(
        "https://resolver.localhost:3443/vtjsc/local-controlled-employee.json",
      );
      expect(env.VS_AGENT_IMAGE).toBe(
        "verana-keycloak-local-controlled-vs-agent:747f8f1",
      );
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });

  it("keeps host orchestration on loopback HTTP while expecting controlled identities", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-controlled-"));
    try {
      await generateLocalControlledData(output, VS_SOURCE);
      const env = parseEnv(await readFile(join(output, ".env"), "utf8"));

      expect(env.EXPECTED_ISSUER_DID).toBe(LOCAL_CONTROLLED.issuerDid);
      expect(env.EXPECTED_VERIFIER_DID).toBe(LOCAL_CONTROLLED.verifierDid);
      expect(env.EXPECTED_VCT).toBe(LOCAL_CONTROLLED.vct);
      expect(env.EXPECTED_VTJSC_ID).toBe(LOCAL_CONTROLLED.vtjscId);
      for (const name of [
        "VS_AGENT_ISSUER_BASE_URL",
        "VS_AGENT_HOLDER_BASE_URL",
        "VS_AGENT_VERIFIER_BASE_URL",
        "DEMO_APP_BASE_URL",
        "BROKER_ISSUER",
      ]) {
        expect(env[name]).toMatch(/^http:\/\/localhost:\d+$/);
      }
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });

  it("keeps a high-entropy resolver control token only in the host environment", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-controlled-"));
    try {
      await generateLocalControlledData(output, VS_SOURCE);
      const hostEnvironment = parseEnv(
        await readFile(join(output, ".env"), "utf8"),
      );
      const composeEnvironment = await readFile(
        join(output, "local-controlled.env"),
        "utf8",
      );
      const token = hostEnvironment.LOCAL_RESOLVER_CONTROL_TOKEN;

      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(composeEnvironment).not.toContain("LOCAL_RESOLVER_CONTROL_TOKEN");
      expect(composeEnvironment).not.toContain(token);
      expect((await stat(join(output, ".env"))).mode & 0o777).toBe(0o600);
    } finally {
      await rm(output, { recursive: true, force: true });
    }
  });
});
