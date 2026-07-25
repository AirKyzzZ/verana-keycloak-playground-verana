import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";

import { afterEach, describe, expect, it } from "vitest";
import { LOCAL_CONTROLLED } from "../scripts/local-controlled-config.js";
import {
  type LocalFlowConfig,
  runLocalFlow,
} from "../scripts/verify-local-flow.js";

const ISSUER_DID = "did:web:issuer.example";
const VERIFIER_DID = "did:web:verifier.example";
const VCT = "https://issuer.example/vct/badge";
const VTJSC = "https://issuer.example/vt/badge.json";
const SUBJECT = "call-demo-user";
const CONTROLLED_SUBJECT = "local-controlled-user";
const SENSITIVE_MARKER = "raw-secret-presentation-token";
const ROGUE_Q1_QUERY = `${LOCAL_CONTROLLED.resolverUrl}/resolve?did=${encodeURIComponent(
  LOCAL_CONTROLLED.rogueDid,
)}`;

interface FakeBehavior {
  capability?: {
    contractVersion: number;
    offerClaims: string[];
    disclosedClaims: string[];
  };
  capabilityExtra?: boolean;
  failWithSensitiveBody?: boolean;
  includeResolverMetadata?: boolean;
  issuerQ1Did?: string;
  issuerQ1Extra?: boolean;
  issuerQ1Production?: boolean;
  issuerQ1TrustStatus?: string;
  issuerQ2Authorized?: unknown;
  issuerQ2Did?: string;
  issuerQ2Extra?: boolean;
  issuerQ2Vtjsc?: string;
  keycloakUsers?: number;
  malformedJsonAt?: "resolver" | "verifier";
  mediaTypeAt?: "resolver" | "verifier";
  oversizedAt?: "resolver" | "verifier";
  invalidUtf8At?: "resolver" | "verifier";
  replaySecondGate?: boolean;
  replaySecondRequest?: boolean;
  resolverUnavailable?: boolean;
  resolutionEvidenceDid?: string;
  resolutionEvidenceVtjsc?: string;
  resolutionRequestedClaims?: string[];
  resolutionRequestedVct?: string;
  resolutionVerifierDid?: string;
  receiptExtra?: boolean;
  receiptIssuerDid?: string;
  receiptOrganization?: unknown;
  receiptRole?: unknown;
  receiptSubjectByPresentation?: readonly [string, string];
  receiptVerifierDid?: string;
  receiptVerdict?: string;
  receiptVct?: string;
  receiptVtjsc?: string;
  sessionNeverCompletes?: boolean;
  shareTimeout?: boolean;
  rogueAuthorized?: boolean | null;
  rogueEvidenceDid?: string | null;
  rogueEvidenceTrustStatus?: string | null;
  rogueEvidenceVtjsc?: string | null;
  rogueQueries?: string[];
  rogueRequestedClaims?: string[];
  rogueRequestedVct?: string | null;
  rogueRequestVerifierDid?: string | null;
  rogueVerdict?: string;
  trustedResolutionVerdict?: string;
  acceptedClaims?: {
    subject_id: string;
    organization: unknown;
    role: unknown;
  };
  acceptedVct?: string;
  capabilities?: Partial<
    Record<
      "issuer" | "holder" | "verifier",
      {
        contractVersion: number;
        offerClaims: string[];
        disclosedClaims: string[];
      }
    >
  >;
  verifierQ1Did?: string;
  verifierQ1Production?: boolean;
  verifierQ1TrustStatus?: string;
  verifierQ3Authorized?: boolean;
  verifierQ3Did?: string;
  verifierQ3Vtjsc?: string;
}

interface FakeServices {
  baseUrl: string;
  brokerCalls: () => number;
  close(): Promise<void>;
  fetch: typeof fetch;
  issues: () => number;
  keycloakReads: () => number;
  keycloakUnexpectedRequests: () => number;
  requests: () => number;
  shareGateIds: () => string[];
  shareAttempts: () => number;
  shares: () => number;
  trustedPresentations: () => number;
  walletAcceptBodies: () => Record<string, unknown>[];
}

const servers = new Set<FakeServices>();

afterEach(async () => {
  await Promise.all([...servers].map((server) => server.close()));
  servers.clear();
});

describe("local flow verification", () => {
  it.each([
    [
      "equal issuer and verifier DIDs",
      (config: LocalFlowConfig) => ({
        ...config,
        expectedVerifierDid: config.expectedIssuerDid,
      }),
    ],
    [
      "verifier URL aliases issuer",
      (config: LocalFlowConfig) => ({
        ...config,
        verifierBaseUrl: `${config.issuerBaseUrl}/`,
      }),
    ],
    [
      "verifier URL aliases holder",
      (config: LocalFlowConfig) => ({
        ...config,
        verifierBaseUrl: `${config.holderBaseUrl}/`,
      }),
    ],
  ])("blocks topology before any request for %s", async (_name, alter) => {
    const services = await startFakeServices();
    const lines: string[] = [];
    const config = alter(flowConfig(services.baseUrl));

    await expect(
      runLocalFlow(config, {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(1);

    expect(lines).toEqual(["FAIL BLOCKED_TOPOLOGY"]);
    expect(lines.every((line) => line.length <= 80)).toBe(true);
    expect(services.requests()).toBe(0);
    expect(services.issues()).toBe(0);
  });

  it.each([
    ["issuer Q1 DID", { issuerQ1Did: "did:web:other.example" }],
    ["issuer Q1 trust", { issuerQ1TrustStatus: "PARTIAL" }],
    ["issuer Q1 production", { issuerQ1Production: false }],
    ["issuer Q2 DID", { issuerQ2Did: "did:web:other.example" }],
    ["issuer Q2 VTJSC", { issuerQ2Vtjsc: "https://other.example/schema" }],
    ["issuer Q2 authorization", { issuerQ2Authorized: false }],
    ["issuer Q2 authorization type", { issuerQ2Authorized: "true" }],
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
    ["Q1", { issuerQ1Extra: true }, "BLOCKED_TRUST_PREFLIGHT"],
    ["Q2", { issuerQ2Extra: true }, "BLOCKED_TRUST_PREFLIGHT"],
    ["capability", { capabilityExtra: true }, "BLOCKED_SUBJECT_CONTRACT"],
  ])(
    "rejects an undocumented extra field in the %s contract",
    async (_name, behavior, code) => {
      const services = await startFakeServices(behavior);
      const lines: string[] = [];

      await expect(
        runLocalFlow(flowConfig(services.baseUrl), {
          sleep: async () => undefined,
          write: (line) => lines.push(line),
        }),
      ).resolves.toBe(1);

      expect(lines.at(-1)).toBe(`FAIL ${code}`);
      expect(services.issues()).toBe(0);
    },
  );

  it("accepts only the documented bounded resolver metadata", async () => {
    const services = await startFakeServices({
      includeResolverMetadata: true,
    });
    const lines: string[] = [];

    await expect(
      runLocalFlow(flowConfig(services.baseUrl), {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(0);

    expect(lines.at(-1)).toBe("PASS");
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

  it("rejects an extra field in the exact nested receipt", async () => {
    const services = await startFakeServices({ receiptExtra: true });
    const lines: string[] = [];

    await expect(
      runLocalFlow(flowConfig(services.baseUrl), {
        sleep: async () => undefined,
        write: (line) => lines.push(line),
      }),
    ).resolves.toBe(1);

    expect(lines.at(-1)).toBe("FAIL FAIL_SMOKE");
  });

  it("prints PASS LOCAL_CONTROLLED only after two stable complete flows", async () => {
    const services = await startFakeServices();
    const { lines, result } = await runControlledFlow(services);

    expect(result).toBe(0);
    expect(lines.at(-1)).toBe("PASS LOCAL_CONTROLLED");
    expect(services.issues()).toBe(2);
    expect(services.trustedPresentations()).toBe(2);
    expect(services.shares()).toBe(2);
    expect(services.keycloakReads()).toBe(3);
    expect(services.brokerCalls()).toBe(0);
    expect(services.keycloakUnexpectedRequests()).toBe(0);
    expect(services.walletAcceptBodies()).toEqual([
      { credentialOffer: "offer-1" },
      { credentialOffer: "offer-2" },
    ]);
  });

  it("requires zero initial Keycloak users before controlled API work", async () => {
    const services = await startFakeServices({ keycloakUsers: 1 });
    const { lines, result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(lines).toEqual(["FAIL BLOCKED_KEYCLOAK_STATE"]);
    expect(services.keycloakReads()).toBe(1);
    expect(services.requests()).toBeGreaterThan(0);
    expect(services.issues()).toBe(0);
    expect(services.shares()).toBe(0);
  });

  it.each([
    [
      "resolver URL",
      (config: LocalFlowConfig) => ({
        ...config,
        resolverUrl: "http://localhost:3098/v1/trust",
      }),
    ],
    [
      "issuer DID",
      (config: LocalFlowConfig) => ({
        ...config,
        expectedIssuerDid: "did:web:other.localhost",
      }),
    ],
    [
      "verifier DID",
      (config: LocalFlowConfig) => ({
        ...config,
        expectedVerifierDid: "did:web:other.localhost",
      }),
    ],
    [
      "VCT",
      (config: LocalFlowConfig) => ({
        ...config,
        expectedVct: "http://localhost:3099/vct/other",
      }),
    ],
    [
      "VTJSC",
      (config: LocalFlowConfig) => ({
        ...config,
        expectedVtjscId: "http://localhost:3099/vtjsc/other.json",
      }),
    ],
    [
      "issuer origin",
      (config: LocalFlowConfig) => ({
        ...config,
        issuerBaseUrl: config.holderBaseUrl,
      }),
    ],
    [
      "holder origin",
      (config: LocalFlowConfig) => ({
        ...config,
        holderBaseUrl: "http://localhost:3112",
      }),
    ],
    [
      "verifier origin",
      (config: LocalFlowConfig) => ({
        ...config,
        verifierBaseUrl: "http://localhost:3202",
      }),
    ],
    [
      "Keycloak origin",
      (config: LocalFlowConfig) => ({
        ...config,
        keycloakIssuer: "http://127.0.0.1:8080/realms/verana-playground",
      }),
    ],
    [
      "demo origin",
      (config: LocalFlowConfig) => ({
        ...config,
        demoAppBaseUrl: "http://127.0.0.1:3000",
      }),
    ],
    [
      "broker origin",
      (config: LocalFlowConfig) => ({
        ...config,
        brokerIssuer: "http://127.0.0.1:3001",
      }),
    ],
  ])(
    "blocks an inexact controlled %s before requests",
    async (_name, alter) => {
      const services = await startFakeServices();
      const lines: string[] = [];

      await expect(
        runLocalFlow(alter(controlledFlowConfig()), {
          fetch: services.fetch,
          sleep: async () => undefined,
          write: (line) => lines.push(line),
        }),
      ).resolves.toBe(1);

      expect(lines).toEqual(["FAIL BLOCKED_CONTROLLED_CONFIG"]);
      expect(services.requests()).toBe(0);
    },
  );

  it.each(["issuer", "holder", "verifier"] as const)(
    "blocks %s capability drift before issuance or disclosure",
    async (role) => {
      const services = await startFakeServices({
        capabilities: {
          [role]: {
            contractVersion: 1,
            offerClaims: ["subjectId", "organization", "role"],
            disclosedClaims: ["subject_id", "organization"],
          },
        },
      });
      const { result } = await runControlledFlow(services);

      expect(result).toBe(1);
      expect(services.issues()).toBe(0);
      expect(services.shares()).toBe(0);
      expect(services.brokerCalls()).toBe(0);
    },
  );

  it.each([
    [
      "wrong holder evidence DID",
      { resolutionEvidenceDid: "did:web:wrong.localhost" },
    ],
    [
      "wrong holder evidence VTJSC",
      { resolutionEvidenceVtjsc: "https://wrong.example/vtjsc.json" },
    ],
    [
      "wrong holder request verifier DID",
      { resolutionVerifierDid: "did:web:wrong.localhost" },
    ],
    [
      "wrong holder requested VCT",
      { resolutionRequestedVct: "https://wrong.example/vct" },
    ],
    [
      "wrong holder requested claims",
      { resolutionRequestedClaims: ["subject_id", "role"] },
    ],
  ])("denies %s before sharing a presentation", async (_name, behavior) => {
    const services = await startFakeServices(behavior);
    const { result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(services.shareAttempts()).toBe(0);
    expect(services.shares()).toBe(0);
    expect(services.brokerCalls()).toBe(0);
  });

  it.each([
    [
      "different second-flow subject",
      {
        receiptSubjectByPresentation: [
          CONTROLLED_SUBJECT,
          "different-controlled-user",
        ] as const,
      },
    ],
    ["wrong accepted VCT", { acceptedVct: "https://wrong.example/vct" }],
    [
      "wrong accepted subject",
      {
        acceptedClaims: {
          subject_id: "attacker-controlled-user",
          organization: "ACME",
          role: "employee",
        },
      },
    ],
    [
      "wrong accepted organization",
      {
        acceptedClaims: {
          subject_id: CONTROLLED_SUBJECT,
          organization: "OTHER",
          role: "employee",
        },
      },
    ],
    [
      "wrong accepted role",
      {
        acceptedClaims: {
          subject_id: CONTROLLED_SUBJECT,
          organization: "ACME",
          role: "admin",
        },
      },
    ],
    [
      "receipt issuer DID mismatch",
      { receiptIssuerDid: "did:web:wrong.localhost" },
    ],
    [
      "receipt verifier DID mismatch",
      { receiptVerifierDid: "did:web:wrong.localhost" },
    ],
    [
      "receipt VTJSC mismatch",
      { receiptVtjsc: "https://wrong.example/vtjsc.json" },
    ],
    ["receipt VCT mismatch", { receiptVct: "https://wrong.example/vct" }],
    ["receipt organization mismatch", { receiptOrganization: "OTHER" }],
    ["receipt role mismatch", { receiptRole: "admin" }],
    ["receipt verdict mismatch", { receiptVerdict: "PARTIAL" }],
  ])("fails closed for %s", async (_name, behavior) => {
    const services = await startFakeServices(behavior);
    const { lines, result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(lines).not.toContain("PASS LOCAL_CONTROLLED");
    expect(services.brokerCalls()).toBe(0);
    expect(services.keycloakReads()).toBeGreaterThanOrEqual(2);
  });

  it("rejects a replayed second presentation before sharing it", async () => {
    const services = await startFakeServices({ replaySecondRequest: true });
    const { result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(services.shareAttempts()).toBe(1);
    expect(services.shares()).toBe(1);
    expect(services.brokerCalls()).toBe(0);
  });

  it("rejects a replayed holder gate before sharing the stale gate twice", async () => {
    const services = await startFakeServices({ replaySecondGate: true });
    const { result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(services.shareAttempts()).toBe(1);
    expect(services.shares()).toBe(1);
    expect(services.shareGateIds()).toEqual(["gate-1"]);
    expect(services.brokerCalls()).toBe(0);
    expect(services.keycloakUnexpectedRequests()).toBe(0);
  });

  it("does not replay an uncertain share request", async () => {
    const services = await startFakeServices({ shareTimeout: true });
    const { result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(services.shareAttempts()).toBe(1);
    expect(services.shares()).toBe(0);
    expect(services.brokerCalls()).toBe(0);
  });

  it("fails a presentation that never reaches ResponseVerified", async () => {
    const services = await startFakeServices({
      sessionNeverCompletes: true,
    });
    const { result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(services.shareAttempts()).toBe(1);
    expect(services.shares()).toBe(1);
    expect(services.trustedPresentations()).toBe(0);
    expect(services.brokerCalls()).toBe(0);
  });

  it.each([
    ["resolver unavailable", { resolverUnavailable: true }],
    ["wrong Q1 DID", { issuerQ1Did: "did:web:wrong.localhost" }],
    ["production false", { issuerQ1Production: false }],
    ["wrong Q2 VTJSC", { issuerQ2Vtjsc: "https://wrong.example/vtjsc.json" }],
    ["wrong Q3 DID", { verifierQ3Did: "did:web:wrong.localhost" }],
    ["resolver malformed JSON", { malformedJsonAt: "resolver" as const }],
    ["resolver invalid UTF-8", { invalidUtf8At: "resolver" as const }],
    ["oversized resolver body", { oversizedAt: "resolver" as const }],
    ["resolver non-JSON media type", { mediaTypeAt: "resolver" as const }],
    ["verifier malformed JSON", { malformedJsonAt: "verifier" as const }],
    ["verifier invalid UTF-8", { invalidUtf8At: "verifier" as const }],
    ["oversized verifier body", { oversizedAt: "verifier" as const }],
    ["verifier non-JSON media type", { mediaTypeAt: "verifier" as const }],
  ])(
    "does not disclose or cross the broker for %s",
    async (_name, behavior) => {
      const services = await startFakeServices(behavior);
      const { result } = await runControlledFlow(services);

      expect(result).toBe(1);
      expect(services.brokerCalls()).toBe(0);
      expect(services.keycloakUnexpectedRequests()).toBe(0);
      expect(services.shares()).toBe(0);
      expect(services.keycloakReads()).toBe(2);
    },
  );

  it("denies a rogue verifier without sharing or creating a Keycloak user", async () => {
    const services = await startFakeServices({
      rogueVerdict: "TRUSTED_AUTHORIZED",
    });
    const { result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(services.shareAttempts()).toBe(2);
    expect(services.shares()).toBe(2);
    expect(services.keycloakReads()).toBe(3);
    expect(services.brokerCalls()).toBe(0);
    expect(services.keycloakUnexpectedRequests()).toBe(0);
  });

  it.each([
    [
      "wrong request DID",
      { rogueRequestVerifierDid: "did:web:wrong.localhost" },
    ],
    ["missing request DID", { rogueRequestVerifierDid: null }],
    ["wrong evidence DID", { rogueEvidenceDid: "did:web:wrong.localhost" }],
    ["missing evidence DID", { rogueEvidenceDid: null }],
    ["TRUSTED evidence", { rogueEvidenceTrustStatus: "TRUSTED" }],
    ["false authorization result", { rogueAuthorized: false }],
    ["unexpected authorization", { rogueAuthorized: true }],
    ["wrong VTJSC", { rogueEvidenceVtjsc: "https://wrong.example/vtjsc.json" }],
    ["missing VTJSC", { rogueEvidenceVtjsc: null }],
    ["wrong VCT", { rogueRequestedVct: "https://wrong.example/vct" }],
    ["wrong claims", { rogueRequestedClaims: ["subject_id", "organization"] }],
    ["non-Q1 resolver queries", { rogueQueries: [] }],
    ["different denial verdict", { rogueVerdict: "TRUSTED_NOT_AUTHORIZED" }],
  ])("rejects rogue denial with %s", async (_name, behavior) => {
    const services = await startFakeServices(behavior);
    const { lines, result } = await runControlledFlow(services);

    expect(result).toBe(1);
    expect(lines).not.toContain("VERDICT ROGUE DENIED");
    expect(services.shareAttempts()).toBe(2);
    expect(services.shares()).toBe(2);
    expect(services.brokerCalls()).toBe(0);
    expect(services.keycloakUnexpectedRequests()).toBe(0);
  });
});

function flowConfig(baseUrl: string): LocalFlowConfig {
  return {
    brokerIssuer: `${baseUrl}/broker`,
    demoAppBaseUrl: `${baseUrl}/demo`,
    evidenceMode: "LIVE_VERANA",
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

function controlledFlowConfig(): LocalFlowConfig {
  return {
    brokerIssuer: "http://localhost:3001",
    demoAppBaseUrl: "http://localhost:3000",
    evidenceMode: "LOCAL_CONTROLLED",
    expectedIssuerDid: LOCAL_CONTROLLED.issuerDid,
    expectedVerifierDid: LOCAL_CONTROLLED.verifierDid,
    expectedVct: LOCAL_CONTROLLED.vct,
    expectedVtjscId: LOCAL_CONTROLLED.vtjscId,
    holderBaseUrl: "http://localhost:3111",
    issuerBaseUrl: "http://localhost:3101",
    keycloakIssuer: "http://localhost:8080/realms/verana-playground",
    pairwiseSubSecret: new TextEncoder().encode(
      "test-secret-at-least-32-bytes-long",
    ),
    resolverUrl: "http://localhost:3099/v1/trust",
    sectorIdentifier: "verana-playground",
    verifierBaseUrl: "http://localhost:3201",
  };
}

async function runControlledFlow(services: FakeServices): Promise<{
  lines: string[];
  result: 0 | 1;
}> {
  const lines: string[] = [];
  const result = await runLocalFlow(controlledFlowConfig(), {
    fetch: services.fetch,
    sleep: async () => undefined,
    write: (line) => lines.push(line),
  });
  return { lines, result };
}

async function startFakeServices(
  behavior: FakeBehavior = {},
): Promise<FakeServices> {
  let brokerCallCount = 0;
  let issueCount = 0;
  let keycloakReadCount = 0;
  let keycloakUnexpectedRequestCount = 0;
  let requestCount = 0;
  let shareAttemptCount = 0;
  let shareCount = 0;
  let trustedRequestCount = 0;
  let trustedPresentationCount = 0;
  const shareGateIds: string[] = [];
  const walletAcceptBodies: Record<string, unknown>[] = [];
  const capability = behavior.capability ?? {
    contractVersion: 1,
    offerClaims: ["subjectId", "organization", "role"],
    disclosedClaims: ["subject_id", "organization", "role"],
  };

  const server = createServer(async (request, response) => {
    requestCount += 1;
    if (behavior.failWithSensitiveBody && request.url?.startsWith("/trust/")) {
      json(response, 200, {
        detail: SENSITIVE_MARKER,
        padding: "x".repeat(70 * 1_024),
      });
      return;
    }

    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (
      url.pathname.startsWith("/broker") &&
      !(
        request.method === "GET" &&
        url.pathname === "/broker/.well-known/openid-configuration"
      )
    ) {
      brokerCallCount += 1;
    }
    if (
      url.pathname.startsWith("/keycloak") &&
      !isAllowedKeycloakRequest(request, url)
    ) {
      keycloakUnexpectedRequestCount += 1;
    }
    const did = url.searchParams.get("did");
    const vtjscId = url.searchParams.get("vtjscId");

    if (url.pathname === "/trust/resolve") {
      if (behavior.resolverUnavailable) {
        json(response, 503, { error: "resolver_unavailable" });
        return;
      }
      if (behavior.malformedJsonAt === "resolver") {
        raw(response, 200, "application/json", Buffer.from("{"));
        return;
      }
      if (behavior.invalidUtf8At === "resolver") {
        raw(
          response,
          200,
          "application/json",
          Buffer.from([
            0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d,
          ]),
        );
        return;
      }
      if (behavior.mediaTypeAt === "resolver") {
        raw(response, 200, "text/plain", Buffer.from("{}"));
        return;
      }
      if (behavior.oversizedAt === "resolver") {
        raw(
          response,
          200,
          "application/json",
          Buffer.from(`{"padding":"${"x".repeat(70 * 1_024)}"}`),
        );
        return;
      }
      const issuer = did === ISSUER_DID;
      const controlledIssuer = did === LOCAL_CONTROLLED.issuerDid;
      const expectedDid = controlledIssuer
        ? LOCAL_CONTROLLED.issuerDid
        : did === LOCAL_CONTROLLED.verifierDid
          ? LOCAL_CONTROLLED.verifierDid
          : issuer
            ? ISSUER_DID
            : VERIFIER_DID;
      json(response, 200, {
        did:
          issuer || controlledIssuer
            ? (behavior.issuerQ1Did ?? expectedDid)
            : (behavior.verifierQ1Did ?? expectedDid),
        trustStatus:
          issuer || controlledIssuer
            ? (behavior.issuerQ1TrustStatus ?? "TRUSTED")
            : (behavior.verifierQ1TrustStatus ?? "TRUSTED"),
        production:
          issuer || controlledIssuer
            ? (behavior.issuerQ1Production ?? true)
            : (behavior.verifierQ1Production ?? true),
        ...(behavior.includeResolverMetadata
          ? {
              evaluatedAt: "2026-07-24T17:38:31.649Z",
              evaluatedAtBlock: 4_488_868,
              expiresAt: "2026-07-24T18:38:31.649Z",
            }
          : {}),
        ...((issuer || controlledIssuer) && behavior.issuerQ1Extra
          ? { undocumented: "reject-me" }
          : {}),
      });
      return;
    }
    if (url.pathname === "/trust/issuer-authorization") {
      json(response, 200, {
        did: behavior.issuerQ2Did ?? did,
        vtjscId: behavior.issuerQ2Vtjsc ?? vtjscId,
        authorized: behavior.issuerQ2Authorized ?? true,
        ...(behavior.includeResolverMetadata
          ? {
              evaluatedAt: "2026-07-24T17:46:35.631Z",
              evaluatedAtBlock: {},
              fees: {},
              permission: {},
              permissionChain: {},
            }
          : {}),
        ...(behavior.issuerQ2Extra ? { undocumented: "reject-me" } : {}),
      });
      return;
    }
    if (url.pathname === "/trust/verifier-authorization") {
      json(response, 200, {
        did: behavior.verifierQ3Did ?? did,
        vtjscId: behavior.verifierQ3Vtjsc ?? vtjscId,
        authorized: behavior.verifierQ3Authorized ?? true,
        ...(behavior.includeResolverMetadata
          ? {
              evaluatedAt: "2026-07-24T17:46:37.578Z",
              evaluatedAtBlock: {},
              fees: {},
              permission: {},
              permissionChain: {},
            }
          : {}),
      });
      return;
    }
    if (
      request.method === "GET" &&
      ["/issuer", "/holder", "/verifier"].some(
        (prefix) => url.pathname === `${prefix}/oid4vc-demo/capabilities`,
      )
    ) {
      const role = url.pathname.split("/")[1] as
        | "issuer"
        | "holder"
        | "verifier";
      json(response, 200, {
        ...(behavior.capabilities?.[role] ?? capability),
        ...(behavior.capabilityExtra ? { undocumented: "reject-me" } : {}),
      });
      return;
    }
    if (
      request.method === "GET" &&
      url.pathname === "/broker/.well-known/openid-configuration"
    ) {
      json(response, 200, {
        issuer: controlledRequest(request)
          ? "http://localhost:3001"
          : `${origin(server)}/broker`,
      });
      return;
    }
    if (
      request.method === "GET" &&
      (url.pathname === "/keycloak/.well-known/openid-configuration" ||
        url.pathname ===
          "/keycloak/realms/verana-playground/.well-known/openid-configuration")
    ) {
      json(response, 200, {
        issuer: controlledRequest(request)
          ? "http://localhost:8080/realms/verana-playground"
          : `${origin(server)}/keycloak`,
      });
      return;
    }
    if (request.method === "GET" && url.pathname === "/demo/") {
      response.writeHead(200, { "content-type": "text/html" }).end("healthy");
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/keycloak/realms/master/protocol/openid-connect/token"
    ) {
      json(response, 200, {
        access_token: "bounded-admin-token",
        expires_in: 60,
        refresh_expires_in: 0,
        token_type: "Bearer",
        "not-before-policy": 0,
        scope: "profile email",
      });
      return;
    }
    if (
      request.method === "GET" &&
      url.pathname === "/keycloak/admin/realms/verana-playground/users"
    ) {
      keycloakReadCount += 1;
      if (request.headers.authorization !== "Bearer bounded-admin-token") {
        json(response, 401, { error: "unauthorized" });
        return;
      }
      json(
        response,
        200,
        Array.from({ length: behavior.keycloakUsers ?? 0 }, (_, index) => ({
          id: `user-${index + 1}`,
          username: `user-${index + 1}`,
          attributes: {
            verana_subject: [`pairwise-${index + 1}`],
          },
        })),
      );
      return;
    }
    if (
      request.method === "GET" &&
      /^\/keycloak\/admin\/realms\/verana-playground\/users\/[^/]+\/groups$/.test(
        url.pathname,
      )
    ) {
      json(response, 200, [
        {
          id: "group-1",
          name: "acme",
          path: "/organizations/acme",
          subGroupCount: 0,
          subGroups: [],
        },
      ]);
      return;
    }
    if (
      request.method === "GET" &&
      /^\/keycloak\/admin\/realms\/verana-playground\/users\/[^/]+\/role-mappings\/realm\/composite$/.test(
        url.pathname,
      )
    ) {
      json(response, 200, [
        {
          id: "role-1",
          name: "employee",
          description: "Employee",
          composite: false,
          clientRole: false,
          containerId: "verana-playground",
        },
      ]);
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/issuer/oid4vc-demo/offers"
    ) {
      issueCount += 1;
      const body = await readJson(request);
      const expectedSubject = controlledRequest(request)
        ? CONTROLLED_SUBJECT
        : SUBJECT;
      if (
        body.subjectId !== expectedSubject ||
        body.organization !== "ACME" ||
        body.role !== "employee" ||
        Object.keys(body).length !== 3
      ) {
        json(response, 400, {});
        return;
      }
      json(response, 200, {
        credentialOffer: `offer-${issueCount}`,
        credentialOfferObject: {},
        issuanceSessionId: `issuance-${issueCount}`,
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/holder/oid4vc-demo/wallet/accept-offer"
    ) {
      const body = await readJson(request);
      walletAcceptBodies.push(body);
      const acceptedClaims = behavior.acceptedClaims ?? {
        subject_id:
          issueCount === 2 && behavior.receiptSubjectByPresentation
            ? behavior.receiptSubjectByPresentation[1]
            : controlledRequest(request)
              ? CONTROLLED_SUBJECT
              : SUBJECT,
        organization: "ACME",
        role: "employee",
      };
      json(response, 200, {
        id: `credential-${issueCount}`,
        vct:
          behavior.acceptedVct ??
          (controlledRequest(request) ? LOCAL_CONTROLLED.vct : VCT),
        claims: {
          vct: controlledRequest(request) ? LOCAL_CONTROLLED.vct : VCT,
          ...acceptedClaims,
        },
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/verifier/oid4vc-demo/verifier/requests"
    ) {
      if (writeFaultResponse(response, "verifier", behavior)) {
        return;
      }
      const body = await readJson(request);
      if (body.tenant === "trusted") {
        trustedRequestCount += 1;
        const requestNumber =
          behavior.replaySecondRequest && trustedRequestCount === 2
            ? 1
            : trustedRequestCount;
        json(response, 200, {
          authorizationRequest: `trusted-request-${requestNumber}`,
          sessionId: `trusted-${requestNumber}`,
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
      const gateId =
        !rogue && behavior.replaySecondGate && trustedRequestCount === 2
          ? "gate-1"
          : rogue
            ? "gate-rogue"
            : `gate-${trustedRequestCount}`;
      const rogueEvidenceDid = hasOwn(behavior, "rogueEvidenceDid")
        ? behavior.rogueEvidenceDid
        : LOCAL_CONTROLLED.rogueDid;
      const rogueRequestVerifierDid = hasOwn(
        behavior,
        "rogueRequestVerifierDid",
      )
        ? behavior.rogueRequestVerifierDid
        : LOCAL_CONTROLLED.rogueDid;
      const rogueAuthorized = hasOwn(behavior, "rogueAuthorized")
        ? behavior.rogueAuthorized
        : null;
      const rogueEvidenceVtjsc = hasOwn(behavior, "rogueEvidenceVtjsc")
        ? behavior.rogueEvidenceVtjsc
        : LOCAL_CONTROLLED.vtjscId;
      const rogueRequestedVct = hasOwn(behavior, "rogueRequestedVct")
        ? behavior.rogueRequestedVct
        : LOCAL_CONTROLLED.vct;
      json(response, 200, {
        gateId,
        verdict: rogue
          ? (behavior.rogueVerdict ?? "UNTRUSTED")
          : (behavior.trustedResolutionVerdict ?? "TRUSTED_AUTHORIZED"),
        evidence: {
          did: rogue
            ? rogueEvidenceDid
            : (behavior.resolutionEvidenceDid ??
              (controlledRequest(request)
                ? LOCAL_CONTROLLED.verifierDid
                : VERIFIER_DID)),
          trustStatus: rogue
            ? (behavior.rogueEvidenceTrustStatus ?? "UNTRUSTED")
            : "TRUSTED",
          authorized: rogue ? rogueAuthorized : true,
          vtjscId: rogue
            ? rogueEvidenceVtjsc
            : (behavior.resolutionEvidenceVtjsc ??
              (controlledRequest(request) ? LOCAL_CONTROLLED.vtjscId : VTJSC)),
          queries: rogue ? (behavior.rogueQueries ?? [ROGUE_Q1_QUERY]) : [],
        },
        request: {
          clientId: "x509_san_dns:verifier.example",
          clientIdPrefix: "x509_san_dns",
          verifierDid: rogue
            ? rogueRequestVerifierDid
            : (behavior.resolutionVerifierDid ??
              (controlledRequest(request)
                ? LOCAL_CONTROLLED.verifierDid
                : VERIFIER_DID)),
          requestedVct: rogue
            ? rogueRequestedVct
            : (behavior.resolutionRequestedVct ??
              (controlledRequest(request) ? LOCAL_CONTROLLED.vct : VCT)),
          requestedClaims: rogue
            ? (behavior.rogueRequestedClaims ?? [
                "subject_id",
                "organization",
                "role",
              ])
            : (behavior.resolutionRequestedClaims ?? [
                "subject_id",
                "organization",
                "role",
              ]),
        },
      });
      return;
    }
    if (
      request.method === "POST" &&
      url.pathname === "/holder/oid4vc-demo/wallet/share"
    ) {
      shareAttemptCount += 1;
      if (behavior.shareTimeout) {
        return;
      }
      const body = await readJson(request);
      if (typeof body.gateId === "string") shareGateIds.push(body.gateId);
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
      if (behavior.sessionNeverCompletes) {
        json(response, 200, { state: "RequestCreated" });
        return;
      }
      const sessionId = url.pathname.split("/").at(-1) ?? "";
      trustedPresentationCount += 1;
      json(
        response,
        200,
        positiveSession(sessionId, {
          controlled: controlledRequest(request),
          extra: behavior.receiptExtra === true,
          issuerDid: behavior.receiptIssuerDid,
          organization: behavior.receiptOrganization,
          role: behavior.receiptRole,
          subject:
            behavior.receiptSubjectByPresentation?.[
              trustedPresentationCount === 1 ? 0 : 1
            ],
          verifierDid: behavior.receiptVerifierDid,
          verdict: behavior.receiptVerdict,
          vct: behavior.receiptVct,
          vtjsc: behavior.receiptVtjsc,
        }),
      );
      return;
    }

    json(response, 404, {});
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const baseUrl = origin(server);
  const fetchFixture: typeof fetch = async (input, init) => {
    const original =
      input instanceof Request ? new URL(input.url) : new URL(input.toString());
    const mapped = mapControlledUrl(original, baseUrl);
    if (
      mapped.controlled &&
      behavior.shareTimeout &&
      mapped.url.pathname.endsWith("/wallet/share")
    ) {
      shareAttemptCount += 1;
      throw new DOMException("request timed out", "TimeoutError");
    }
    const headers = new Headers(
      input instanceof Request ? input.headers : undefined,
    );
    if (init?.headers) {
      for (const [name, value] of new Headers(init.headers)) {
        headers.set(name, value);
      }
    }
    if (mapped.controlled) headers.set("x-fixture-controlled", "true");
    return await fetch(mapped.url, {
      ...(input instanceof Request
        ? {
            method: input.method,
            body:
              input.method === "GET" || input.method === "HEAD"
                ? undefined
                : await input.clone().arrayBuffer(),
          }
        : {}),
      ...init,
      headers,
    });
  };
  const service = {
    baseUrl,
    brokerCalls: () => brokerCallCount,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    },
    fetch: fetchFixture,
    issues: () => issueCount,
    keycloakReads: () => keycloakReadCount,
    keycloakUnexpectedRequests: () => keycloakUnexpectedRequestCount,
    requests: () => requestCount,
    shareGateIds: () => shareGateIds,
    shareAttempts: () => shareAttemptCount,
    shares: () => shareCount,
    trustedPresentations: () => trustedPresentationCount,
    walletAcceptBodies: () => walletAcceptBodies,
  };
  servers.add(service);
  return service;
}

interface PositiveSessionOptions {
  controlled: boolean;
  extra?: boolean;
  issuerDid?: string;
  organization?: unknown;
  role?: unknown;
  subject?: string;
  verifierDid?: string;
  verdict?: string;
  vct?: string;
  vtjsc?: string;
}

function positiveSession(
  sessionId: string,
  options: PositiveSessionOptions = { controlled: false },
) {
  const issuerDid =
    options.issuerDid ??
    (options.controlled ? LOCAL_CONTROLLED.issuerDid : ISSUER_DID);
  const verifierDid =
    options.verifierDid ??
    (options.controlled ? LOCAL_CONTROLLED.verifierDid : VERIFIER_DID);
  const vct = options.vct ?? (options.controlled ? LOCAL_CONTROLLED.vct : VCT);
  const vtjsc =
    options.vtjsc ?? (options.controlled ? LOCAL_CONTROLLED.vtjscId : VTJSC);
  const subject =
    options.subject ?? (options.controlled ? CONTROLLED_SUBJECT : SUBJECT);
  const verdict = options.verdict ?? "TRUSTED_AUTHORIZED";
  return {
    state: "ResponseVerified",
    receipt: {
      exchange: {
        protocol: "OID4VP 1.0",
        vct,
        sessionId,
        tenant: "trusted",
        verifiedAt: "2026-07-24T17:00:00.000Z",
      },
      verifier: {
        did: verifierDid,
        verdict,
        evidence: {
          did: verifierDid,
          trustStatus: "TRUSTED",
          authorized: true,
          vtjscId: vtjsc,
          queries: [],
        },
      },
      issuer: {
        did: issuerDid,
        iss: "https://issuer.example",
        verdict,
        evidence: {
          did: issuerDid,
          trustStatus: "TRUSTED",
          authorized: true,
          vtjscId: vtjsc,
          queries: [],
        },
      },
      credential: {
        vct,
        disclosedClaims: {
          subject_id: subject,
          organization: options.organization ?? "ACME",
          role: options.role ?? "employee",
        },
      },
      registry: {
        network: "vna-testnet-1",
        trustRegistry: 184,
        schema: 249,
        vtjscId: vtjsc,
      },
      ...(options.extra ? { undocumented: "reject-me" } : {}),
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

function raw(
  response: ServerResponse,
  status: number,
  contentType: string,
  body: Buffer,
): void {
  response.writeHead(status, { "content-type": contentType }).end(body);
}

function writeFaultResponse(
  response: ServerResponse,
  component: "resolver" | "verifier",
  behavior: FakeBehavior,
): boolean {
  if (behavior.malformedJsonAt === component) {
    raw(response, 200, "application/json", Buffer.from("{"));
    return true;
  }
  if (behavior.invalidUtf8At === component) {
    raw(
      response,
      200,
      "application/json",
      Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d]),
    );
    return true;
  }
  if (behavior.mediaTypeAt === component) {
    raw(response, 200, "text/plain", Buffer.from("{}"));
    return true;
  }
  if (behavior.oversizedAt === component) {
    raw(
      response,
      200,
      "application/json",
      Buffer.from(`{"padding":"${"x".repeat(70 * 1_024)}"}`),
    );
    return true;
  }
  return false;
}

function controlledRequest(request: IncomingMessage): boolean {
  return request.headers["x-fixture-controlled"] === "true";
}

function hasOwn(value: object, key: PropertyKey): boolean {
  return Object.hasOwn(value, key);
}

function isAllowedKeycloakRequest(request: IncomingMessage, url: URL): boolean {
  if (
    request.method === "GET" &&
    (url.pathname === "/keycloak/.well-known/openid-configuration" ||
      url.pathname ===
        "/keycloak/realms/verana-playground/.well-known/openid-configuration")
  ) {
    return true;
  }
  if (
    request.method === "POST" &&
    url.pathname === "/keycloak/realms/master/protocol/openid-connect/token"
  ) {
    return true;
  }
  return (
    request.method === "GET" &&
    (url.pathname === "/keycloak/admin/realms/verana-playground/users" ||
      /^\/keycloak\/admin\/realms\/verana-playground\/users\/[^/]+\/groups$/.test(
        url.pathname,
      ) ||
      /^\/keycloak\/admin\/realms\/verana-playground\/users\/[^/]+\/role-mappings\/realm\/composite$/.test(
        url.pathname,
      ))
  );
}

function mapControlledUrl(
  url: URL,
  fixtureBaseUrl: string,
): { controlled: boolean; url: URL } {
  const routes = new Map([
    ["localhost:3000", "/demo"],
    ["localhost:3001", "/broker"],
    ["localhost:3099", "/trust"],
    ["localhost:3101", "/issuer"],
    ["localhost:3111", "/holder"],
    ["localhost:3201", "/verifier"],
    ["localhost:8080", "/keycloak"],
  ]);
  const prefix = routes.get(url.host);
  if (!prefix) return { controlled: false, url };

  const mapped = new URL(fixtureBaseUrl);
  const resolverPath =
    prefix === "/trust" && url.pathname.startsWith("/v1/trust/")
      ? url.pathname.slice("/v1/trust".length)
      : url.pathname;
  mapped.pathname = `${prefix}${resolverPath}`;
  mapped.search = url.search;
  return { controlled: true, url: mapped };
}

function origin(server: ReturnType<typeof createServer>): string {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test server has no TCP address");
  }
  return `http://127.0.0.1:${address.port}`;
}
