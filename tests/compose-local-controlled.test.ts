import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

import { LOCAL_CONTROLLED } from "../scripts/local-controlled-config.js";
import { LOCAL_TLS_HOSTNAMES } from "../scripts/local-tls-certificates.js";

const composePath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "compose.local-controlled.yaml",
);
const agentServices = 3;

let compose = "";

function occurrences(needle: string): number {
  return compose.split(needle).length - 1;
}

beforeAll(async () => {
  compose = await readFile(composePath, "utf8");
});

describe("controlled Compose definition", () => {
  it("publishes the port-encoded agent DIDs and controlled HTTPS origins", () => {
    for (const [did, url] of [
      [LOCAL_CONTROLLED.issuerDid, LOCAL_CONTROLLED.issuerUrl],
      [LOCAL_CONTROLLED.holderDid, LOCAL_CONTROLLED.holderUrl],
      [LOCAL_CONTROLLED.verifierDid, LOCAL_CONTROLLED.verifierUrl],
    ]) {
      expect(occurrences(`AGENT_PUBLIC_DID: ${did}`)).toBe(1);
      expect(occurrences(`PUBLIC_API_BASE_URL: ${url}`)).toBe(1);
    }
    expect(compose).not.toContain("did:web:issuer.localhost\n");
    expect(compose).not.toContain("did:web:holder.localhost\n");
    expect(compose).not.toContain("did:web:verifier.localhost\n");
  });

  it("signs every positive issuance and request with a DID", () => {
    expect(occurrences("OID4VC_ISSUER_SIGNER: did")).toBe(agentServices);
    expect(occurrences("OID4VC_REQUEST_SIGNER: did")).toBe(agentServices);
    expect(compose).not.toContain("x5c");
  });

  it("declares the exact local-controlled registry tuple on every agent", () => {
    expect(
      occurrences(`VERANA_NETWORK_ID: ${LOCAL_CONTROLLED.networkId}`),
    ).toBe(agentServices);
    expect(
      occurrences(`VERANA_ECOSYSTEM_ID: "${LOCAL_CONTROLLED.ecosystemId}"`),
    ).toBe(agentServices);
    expect(
      occurrences(
        `VERANA_CREDENTIAL_SCHEMA_ID: "${LOCAL_CONTROLLED.credentialSchemaId}"`,
      ),
    ).toBe(agentServices);
  });

  it("binds the credential issuer URL to the exact issuer DID", () => {
    const bindings = /OID4VC_CREDENTIAL_ISSUER_BINDINGS_JSON: '(.+)'/g;
    const declared = [...compose.matchAll(bindings)].map((match) => match[1]);

    expect(declared).toHaveLength(agentServices);
    for (const value of declared) {
      expect(JSON.parse(value ?? "null")).toEqual(
        LOCAL_CONTROLLED.credentialIssuerBindings,
      );
    }
  });

  it("requires the exact Linked-VP service fragments on every agent", () => {
    const fragments = LOCAL_CONTROLLED.requiredLinkedVpFragments.join(",");
    expect(
      occurrences(`OID4VC_REQUIRED_LINKED_VP_FRAGMENTS: "${fragments}"`),
    ).toBe(agentServices);
  });

  it("resolves trust through the controlled HTTPS base without a legacy path", () => {
    expect(
      compose.match(/^ {6}VERANA_RESOLVER_URL: \$\{VERANA_RESOLVER_URL}$/gm),
    ).toHaveLength(agentServices);
    expect(LOCAL_CONTROLLED.resolverUrl).toBe(
      "https://resolver.localhost:3443",
    );
    expect(compose).not.toContain("/v1/trust");
    expect(compose).not.toContain("host.docker.internal:3099");
  });

  it("trusts only the per-run CA certificate, read-only", () => {
    expect(
      occurrences("NODE_EXTRA_CA_CERTS: /run/verana-local-ca/ca.pem"),
    ).toBe(agentServices);
    expect(
      occurrences("- ./.data/tls/ca.pem:/run/verana-local-ca/ca.pem:ro"),
    ).toBe(agentServices);
    for (const secret of ["ca-key.pem", "server-key.pem", "server.pem"]) {
      expect(compose).not.toContain(secret);
    }
    expect(compose).not.toContain("NODE_TLS_REJECT_UNAUTHORIZED");
    expect(compose).not.toContain("allowInsecureHttpUrls");
  });

  it("maps every controlled hostname to the single loopback gateway", () => {
    for (const hostname of LOCAL_TLS_HOSTNAMES) {
      expect(occurrences(`- "${hostname}:host-gateway"`)).toBe(agentServices);
    }
    expect(occurrences('- "host.docker.internal:host-gateway"')).toBe(
      agentServices,
    );
  });

  it("publishes every agent port on loopback only", () => {
    const published = [...compose.matchAll(/^ {6}- "(.+)"$/gm)]
      .map((match) => match[1] ?? "")
      .filter((entry) => /^\d|^\d+\.\d/.test(entry));

    expect(published.length).toBeGreaterThan(0);
    for (const entry of published) {
      expect(entry.startsWith("127.0.0.1:")).toBe(true);
      expect(entry).not.toContain(String(LOCAL_CONTROLLED.tlsPort));
    }
  });
});
