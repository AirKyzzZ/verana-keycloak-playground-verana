import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  type LocalFlowConfig,
  runLocalFlow,
} from "../scripts/verify-local-flow.js";

const ISSUER_DID = "did:web:issuer.example";
const VERIFIER_DID = "did:web:verifier.example";
const VCT = "https://issuer.example/vct/badge";
const VTJSC = "https://issuer.example/vt/badge.json";
const SUBJECT = "call-demo-user";
const SENSITIVE_MARKER = "raw-secret-presentation-token";

interface FakeBehavior {
  capability?: {
    contractVersion: number;
    offerClaims: string[];
    disclosedClaims: string[];
  };
  failWithSensitiveBody?: boolean;
  issuerQ1Did?: string;
  issuerQ1Production?: boolean;
  issuerQ1TrustStatus?: string;
  issuerQ2Authorized?: boolean;
  issuerQ2Did?: string;
  issuerQ2Vtjsc?: string;
  verifierQ1Did?: string;
  verifierQ1Production?: boolean;
  verifierQ1TrustStatus?: string;
  verifierQ3Authorized?: boolean;
  verifierQ3Did?: string;
  verifierQ3Vtjsc?: string;
}

interface FakeServices {
  baseUrl: string;
  close(): Promise<void>;
  issues: () => number;
  shares: () => number;
}

const servers = new Set<FakeServices>();

afterEach(async () => {
  await Promise.all([...servers].map((server) => server.close()));
  servers.clear();
});

describe("local flow verification", () => {
  it.each([
    ["issuer Q1 DID", { issuerQ1Did: "did:web:other.example" }],
    ["issuer Q1 trust", { issuerQ1TrustStatus: "PARTIAL" }],
    ["issuer Q1 production", { issuerQ1Production: false }],
    ["issuer Q2 DID", { issuerQ2Did: "did:web:other.example" }],
    ["issuer Q2 VTJSC", { issuerQ2Vtjsc: "https://other.example/schema" }],
    ["issuer Q2 authorization", { issuerQ2Authorized: false }],
    ["verifier Q1 DID", { verifierQ1Did: "did:web:other.example" }],
    ["verifier Q1 trust", { verifierQ1TrustStatus: "UNTRUSTED" }],
    ["verifier Q1 production", { verifierQ1Production: false }],
    ["verifier Q3 DID", { verifierQ3Did: "did:web:other.example" }],
    ["verifier Q3 VTJSC", { verifierQ3Vtjsc: "https://other.example/schema" }],
    ["verifier Q3 authorization", { verifierQ3Authorized: false }],
  ])("fails closed on an inexact %s response", async (_name, behavior) => {
    const services = await startFakeServices(behavior);
    const lines: string[] = [];

    await expect(
      runLocalFlow(flowConfig(services.baseUrl), {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(1);

    expect(lines).toEqual([
      "STAGE TRUST_PREFLIGHT",
      "FAIL BLOCKED_TRUST_PREFLIGHT",
    ]);
    expect(services.issues()).toBe(0);
  });

  it.each([
    [
      "contract version",
      {
        contractVersion: 2,
        offerClaims: ["subjectId", "organization", "role"],
        disclosedClaims: ["subject_id", "organization", "role"],
      },
    ],
    [
      "offer subject claim",
      {
        contractVersion: 1,
        offerClaims: ["organization", "role"],
        disclosedClaims: ["subject_id", "organization", "role"],
      },
    ],
    [
      "disclosed subject claim",
      {
        contractVersion: 1,
        offerClaims: ["subjectId", "organization", "role"],
        disclosedClaims: ["organization", "role"],
      },
    ],
  ])("blocks an inexact %s capability contract", async (_name, capability) => {
    const services = await startFakeServices({ capability });
    const lines: string[] = [];

    await expect(
      runLocalFlow(flowConfig(services.baseUrl), {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(1);

    expect(lines.at(-1)).toBe("FAIL BLOCKED_SUBJECT_CONTRACT");
    expect(services.issues()).toBe(0);
    expect(services.shares()).toBe(0);
  });

  it("runs two trusted presentations with a stable pairwise subject and denies rogue disclosure", async () => {
    const services = await startFakeServices();
    const lines: string[] = [];

    await expect(
      runLocalFlow(flowConfig(services.baseUrl), {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(0);

    expect(lines).toEqual([
      "STAGE TRUST_PREFLIGHT",
      "VERDICT ISSUER_Q2 TRUSTED_AUTHORIZED",
      "VERDICT VERIFIER_Q3 TRUSTED_AUTHORIZED",
      "STAGE SUBJECT_CONTRACT",
      "STAGE COMPONENT_READINESS",
      "STAGE CREDENTIAL",
      "STAGE PRESENTATION_1",
      "VERDICT PRESENTATION_1_ISSUER TRUSTED_AUTHORIZED",
      "VERDICT PRESENTATION_1_VERIFIER TRUSTED_AUTHORIZED",
      "STAGE PRESENTATION_2",
      "VERDICT PRESENTATION_2_ISSUER TRUSTED_AUTHORIZED",
      "VERDICT PRESENTATION_2_VERIFIER TRUSTED_AUTHORIZED",
      "VERDICT SUBJECT STABLE",
      "STAGE ROGUE_PRESENTATION",
      "VERDICT ROGUE DENIED",
      "PASS",
    ]);
    expect(services.shares()).toBe(2);
  });

  it("never emits upstream bodies and keeps every output line bounded", async () => {
    const services = await startFakeServices({
      failWithSensitiveBody: true,
    });
    const lines: string[] = [];

    await expect(
      runLocalFlow(flowConfig(services.baseUrl), {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(1);

    const output = lines.join("\n");
    expect(output).not.toContain(SENSITIVE_MARKER);
    expect(lines.every((line) => line.length <= 80)).toBe(true);
    expect(lines.at(-1)).toBe("FAIL BLOCKED_TRUST_PREFLIGHT");
  });
});

function flowConfig(baseUrl: string): LocalFlowConfig {
  return {
    brokerIssuer: `${baseUrl}/broker`,
    demoAppBaseUrl: `${baseUrl}/demo`,
    expectedIssuerDid: ISSUER_DID,
    expectedVerifierDid: VERIFIER_DID,
    expectedVct: VCT,
    expectedVtjscId: VTJSC,
    holderBaseUrl: `${baseUrl}/holder`,
    issuerBaseUrl: `${baseUrl}/issuer`,
    keycloakIssuer: `${baseUrl}/keycloak`,
    pairwiseSubSecret: new TextEncoder().encode(
      "test-secret-at-least-32-bytes-long",
    ),
    resolverUrl: `${baseUrl}/trust`,
    sectorIdentifier: "verana-playground",
    verifierBaseUrl: `${baseUrl}/verifier`,
  };
}

async function startFakeServices(
  behavior: FakeBehavior = {},
): Promise<FakeServices> {
  let issueCount = 0;
  let shareCount = 0;
  let trustedRequestCount = 0;
  const capability = behavior.capability ?? {
    contractVersion: 1,
    offerClaims: ["subjectId", "organization", "role"],
    disclosedClaims: ["subject_id", "organization", "role"],
  };

  const server = createServer(async (request, response) => {
    if (behavior.failWithSensitiveBody && request.url?.startsWith("/trust/")) {
      json(response, 200, {
        detail: SENSITIVE_MARKER,
        padding: "x".repeat(70 * 1_024),
      });
      return;
    }

    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const did = url.searchParams.get("did");
    const vtjscId = url.searchParams.get("vtjscId");

    if (url.pathname === "/trust/resolve") {
      const issuer = did === ISSUER_DID;
      json(response, 200, {
        did: issuer
          ? (behavior.issuerQ1Did ?? ISSUER_DID)
          : (behavior.verifierQ1Did ?? VERIFIER_DID),
        trustStatus: issuer
          ? (behavior.issuerQ1TrustStatus ?? "TRUSTED")
          : (behavior.verifierQ1TrustStatus ?? "TRUSTED"),
        production: issuer
          ? (behavior.issuerQ1Production ?? true)
          : (behavior.verifierQ1Production ?? true),
      });
      return;
    }
    if (url.pathname === "/trust/issuer-authorization") {
      json(response, 200, {
        did: behavior.issuerQ2Did ?? did,
        vtjscId: behavior.issuerQ2Vtjsc ?? vtjscId,
        authorized: behavior.issuerQ2Authorized ?? true,
      });
      return;
    }
    if (url.pathname === "/trust/verifier-authorization") {
      json(response, 200, {
        did: behavior.verifierQ3Did ?? did,
        vtjscId: behavior.verifierQ3Vtjsc ?? vtjscId,
        authorized: behavior.verifierQ3Authorized ?? true,
      });
      return;
    }
    if (
      request.method === "GET" &&
      ["/issuer", "/holder", "/verifier"].some(
        (prefix) => url.pathname === `${prefix}/oid4vc-demo/capabilities`,
      )
    ) {
      json(response, 200, capability);
      return;
    }
    if (
      request.method === "GET" &&
      url.pathname === "/broker/.well-known/openid-configuration"
    ) {
      json(response, 200, { issuer: `${origin(server)}/broker` });
      return;
    }
    if (
      request.method === "GET" &&
      url.pathname === "/keycloak/.well-known/openid-configuration"
    ) {
      json(response, 200, { issuer: `${origin(server)}/keycloak` });
      return;
    }
    if (request.method === "GET" && url.pathname === "/demo/") {
      response.writeHead(200, { "content-type": "text/html" }).end("healthy");
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/issuer/oid4vc-demo/offers"
    ) {
      issueCount += 1;
      const body = await readJson(request);
      if (body.subjectId !== SUBJECT) {
        json(response, 400, {});
        return;
      }
      json(response, 200, {
        credentialOffer: "offer",
        credentialOfferObject: {},
        issuanceSessionId: "issuance-1",
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/holder/oid4vc-demo/wallet/accept-offer"
    ) {
      json(response, 200, {
        id: "credential-1",
        vct: VCT,
        claims: {
          subject_id: SUBJECT,
          organization: "ACME",
          role: "employee",
        },
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/verifier/oid4vc-demo/verifier/requests"
    ) {
      const body = await readJson(request);
      if (body.tenant === "trusted") {
        trustedRequestCount += 1;
        json(response, 200, {
          authorizationRequest: `trusted-request-${trustedRequestCount}`,
          sessionId: `trusted-${trustedRequestCount}`,
        });
        return;
      }
      json(response, 200, {
        authorizationRequest: "rogue-request",
        sessionId: "rogue-1",
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/holder/oid4vc-demo/wallet/resolve-request"
    ) {
      const body = await readJson(request);
      const rogue = body.authorizationRequest === "rogue-request";
      json(response, 200, {
        gateId: rogue ? "gate-rogue" : `gate-${trustedRequestCount}`,
        verdict: rogue ? "TRUSTED_NOT_AUTHORIZED" : "TRUSTED_AUTHORIZED",
        evidence: {
          did: rogue ? "did:web:rogue.example" : VERIFIER_DID,
          trustStatus: "TRUSTED",
          authorized: !rogue,
          vtjscId: VTJSC,
          queries: [],
        },
        request: {
          clientId: "x509_san_dns:verifier.example",
          clientIdPrefix: "x509_san_dns",
          verifierDid: rogue ? "did:web:rogue.example" : VERIFIER_DID,
          requestedVct: VCT,
          requestedClaims: ["subject_id", "organization", "role"],
        },
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/holder/oid4vc-demo/wallet/share"
    ) {
      shareCount += 1;
      json(response, 200, { shared: true, status: 200 });
      return;
    }
    if (
      request.method === "GET" &&
      url.pathname.startsWith(
        "/verifier/oid4vc-demo/verifier/sessions/trusted-",
      )
    ) {
      const sessionId = url.pathname.split("/").at(-1) ?? "";
      json(response, 200, positiveSession(sessionId));
      return;
    }

    json(response, 404, {});
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const service = {
    baseUrl: origin(server),
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
    issues: () => issueCount,
    shares: () => shareCount,
  };
  servers.add(service);
  return service;
}

function positiveSession(sessionId: string) {
  return {
    state: "ResponseVerified",
    receipt: {
      exchange: {
        protocol: "OID4VP 1.0",
        vct: VCT,
        sessionId,
        tenant: "trusted",
        verifiedAt: "2026-07-24T17:00:00.000Z",
      },
      verifier: {
        did: VERIFIER_DID,
        verdict: "TRUSTED_AUTHORIZED",
        evidence: {
          did: VERIFIER_DID,
          trustStatus: "TRUSTED",
          authorized: true,
          vtjscId: VTJSC,
          queries: [],
        },
      },
      issuer: {
        did: ISSUER_DID,
        iss: "https://issuer.example",
        verdict: "TRUSTED_AUTHORIZED",
        evidence: {
          did: ISSUER_DID,
          trustStatus: "TRUSTED",
          authorized: true,
          vtjscId: VTJSC,
          queries: [],
        },
      },
      credential: {
        vct: VCT,
        disclosedClaims: {
          subject_id: SUBJECT,
          organization: "ACME",
          role: "employee",
        },
      },
      registry: {
        network: "vna-testnet-1",
        trustRegistry: 184,
        schema: 249,
        vtjscId: VTJSC,
      },
    },
  };
}

async function readJson(
  request: IncomingMessage,
): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<
    string,
    unknown
  >;
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response
    .writeHead(status, { "content-type": "application/json" })
    .end(JSON.stringify(body));
}

function origin(server: ReturnType<typeof createServer>): string {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test server has no TCP address");
  }
  return `http://127.0.0.1:${address.port}`;
}
