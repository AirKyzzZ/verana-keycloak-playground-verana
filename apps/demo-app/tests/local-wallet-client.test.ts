/// <reference types="node" />

import { createServer, type IncomingMessage, type Server } from "node:http";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  LocalWalletClient,
  type ResolvedPresentation,
  type ReviewedOffer,
} from "../src/local-wallet-client.js";

interface CapturedRequest {
  body: unknown;
  method: string;
  path: string;
}

interface FakeAgent {
  baseUrl: string;
  requests: CapturedRequest[];
  server: Server;
}

const servers: Server[] = [];

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  const body = Buffer.concat(chunks).toString("utf8");
  return body ? JSON.parse(body) : undefined;
}

async function startAgent(
  respond: (request: CapturedRequest) =>
    | {
        body: unknown;
        headers?: Record<string, string>;
        status?: number;
      }
    | undefined,
): Promise<FakeAgent> {
  const requests: CapturedRequest[] = [];
  const server = createServer(async (incoming, response) => {
    const request = {
      body: await readJson(incoming),
      method: incoming.method ?? "",
      path: incoming.url ?? "",
    };
    requests.push(request);
    const result = respond(request);
    if (!result) {
      response.writeHead(404).end();
      return;
    }
    response
      .writeHead(result.status ?? 200, {
        "content-type": "application/json",
        ...result.headers,
      })
      .end(
        typeof result.body === "string"
          ? result.body
          : JSON.stringify(result.body),
      );
  });
  servers.push(server);
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("listen_failed");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    server,
  };
}

function positiveReview(): ReviewedOffer {
  return {
    gateId: "gate-issuance-1",
    verdict: "TRUSTED_AUTHORIZED",
    issuerDid: "did:webvh:test:issuer",
    credentialIssuer: "https://issuer.example/oid4vci/unfold",
    evidence: {
      did: "did:webvh:test:issuer",
      trustStatus: "TRUSTED",
      authorized: true,
      vtjscId: "https://issuer.example/schema.json",
      queries: ["https://resolver.example/v4/verifiable-trust/resolve"],
    },
  };
}

function positiveResolution(): ResolvedPresentation {
  return {
    gateId: "gate-trusted-1",
    verdict: "TRUSTED_AUTHORIZED",
    evidence: {
      did: "did:webvh:test:verifier",
      trustStatus: "TRUSTED",
      authorized: true,
      vtjscId: "https://issuer.example/schema.json",
      queries: ["https://resolver.example/resolve"],
    },
    request: {
      clientId: "x509_hash:verifier",
      clientIdPrefix: "x509_hash",
      verifierDid: "did:webvh:test:verifier",
      unverifiedClaimedDid: "did:webvh:test:verifier",
      requestedVct: "https://issuer.example/vct",
      requestedClaims: [
        "credentialSchema.id",
        "subject_id",
        "organization",
        "role",
      ],
    },
  };
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.closeAllConnections();
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        }),
    ),
  );
});

describe("LocalWalletClient", () => {
  it("creates and resolves the fixed rogue request without exposing a caller-selected tenant or request", async () => {
    const verifier = await startAgent((request) => {
      if (request.path !== "/oid4vc-demo/verifier/requests") return undefined;
      return {
        body: {
          authorizationRequest: "openid4vp://rogue-sensitive-request",
          sessionId: "rogue-verification-1",
        },
      };
    });
    const holder = await startAgent((request) => {
      if (request.path !== "/oid4vc-demo/wallet/resolve-request") {
        return undefined;
      }
      return {
        body: {
          ...positiveResolution(),
          gateId: "gate-rogue-sensitive",
          verdict: "UNTRUSTED",
          evidence: {
            did: "did:web:rogue.localhost",
            trustStatus: "UNTRUSTED",
            authorized: null,
            vtjscId:
              "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json",
            queries: [
              "http://host.docker.internal:3099/v1/trust/resolve?did=did%3Aweb%3Arogue.localhost",
            ],
          },
          request: {
            ...positiveResolution().request,
            verifierDid: "did:web:rogue.localhost",
            requestedVct:
              "http://host.docker.internal:3099/vct/local-controlled-employee",
            requestedClaims: ["subject_id", "organization", "role"],
          },
        },
      };
    });
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: holder.baseUrl,
      verifierBaseUrl: verifier.baseUrl,
    });

    const result = await client.testRogueDenial();

    expect(result.verdict).toBe("UNTRUSTED");
    expect(verifier.requests).toEqual([
      {
        body: { tenant: "rogue" },
        method: "POST",
        path: "/oid4vc-demo/verifier/requests",
      },
    ]);
    expect(holder.requests).toEqual([
      {
        body: {
          authorizationRequest: "openid4vp://rogue-sensitive-request",
        },
        method: "POST",
        path: "/oid4vc-demo/wallet/resolve-request",
      },
    ]);
  });

  it("uses separate issuer, holder, and verifier origins for each role", async () => {
    const issuer = await startAgent((request) => {
      if (request.path !== "/oid4vc-demo/offers") return undefined;
      return {
        body: {
          credentialOffer: "openid-credential-offer://local",
          credentialOfferObject: {},
          issuanceSessionId: "issuance-1",
        },
      };
    });
    const holder = await startAgent((request) => {
      if (request.path === "/oid4vc-demo/wallet/review-offer") {
        return { body: positiveReview() };
      }
      if (request.path === "/oid4vc-demo/wallet/accept-offer") {
        return {
          body: {
            id: "credential-1",
            vct: "https://issuer.example/vct",
            claims: {
              subject_id: "local-user",
              organization: "ACME",
              role: "employee",
            },
          },
        };
      }
      if (request.path === "/oid4vc-demo/wallet/resolve-request") {
        return { body: positiveResolution() };
      }
      if (request.path === "/oid4vc-demo/wallet/share") {
        return { body: { shared: true, status: 200 } };
      }
      return undefined;
    });
    const verifier = await startAgent((request) => {
      if (request.path === "/oid4vc-demo/verifier/requests") {
        return {
          body: {
            authorizationRequest: "openid4vp://trusted-request",
            sessionId: "verification-1",
          },
        };
      }
      if (request.path === "/oid4vc-demo/verifier/sessions/verification-1") {
        return {
          body: {
            state: "ResponseVerified",
            receipt: {},
          },
        };
      }
      return undefined;
    });
    const client = new LocalWalletClient({
      issuerBaseUrl: issuer.baseUrl,
      holderBaseUrl: holder.baseUrl,
      verifierBaseUrl: verifier.baseUrl,
    });

    const offer = await client.issueBadge("local-user");
    await client.acceptOffer(await client.reviewOffer(offer.credentialOffer));
    const presentation = await client.createPresentationRequest();
    const resolved = await client.resolveRequest(
      presentation.authorizationRequest,
    );
    await client.share(resolved);
    await client.getPresentationStatus(presentation.sessionId);

    expect(issuer.requests).toEqual([
      {
        body: {
          subjectId: "local-user",
          organization: "ACME",
          role: "employee",
        },
        method: "POST",
        path: "/oid4vc-demo/offers",
      },
    ]);
    expect(holder.requests.map(({ path }) => path)).toEqual([
      "/oid4vc-demo/wallet/review-offer",
      "/oid4vc-demo/wallet/accept-offer",
      "/oid4vc-demo/wallet/resolve-request",
      "/oid4vc-demo/wallet/share",
    ]);
    expect(verifier.requests.map(({ path }) => path)).toEqual([
      "/oid4vc-demo/verifier/requests",
      "/oid4vc-demo/verifier/sessions/verification-1",
    ]);
  });

  it("shares only the gate ID returned by a positive resolution", async () => {
    let shareBody: unknown;
    const holder = await startAgent((request) => {
      if (request.path !== "/oid4vc-demo/wallet/share") return undefined;
      shareBody = request.body;
      return { body: { shared: true, status: 202 } };
    });
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: holder.baseUrl,
      verifierBaseUrl: "http://127.0.0.1:2",
    });

    await expect(client.share(positiveResolution())).resolves.toEqual({
      shared: true,
      status: 202,
    });
    expect(shareBody).toEqual({ gateId: "gate-trusted-1" });
  });

  it("rejects a successful HTTP response whose share receipt reports a failure status", async () => {
    const holder = await startAgent((request) => {
      if (request.path !== "/oid4vc-demo/wallet/share") return undefined;
      return { body: { shared: true, status: 500 } };
    });
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: holder.baseUrl,
      verifierBaseUrl: "http://127.0.0.1:2",
    });

    await expect(client.share(positiveResolution())).rejects.toThrow(
      "vs_agent_unavailable",
    );
  });

  it.each([
    "TRUSTED_NOT_AUTHORIZED",
    "UNTRUSTED",
    "RESOLVER_UNAVAILABLE",
  ] as const)("never calls share for the %s verdict", async (verdict) => {
    const holder = await startAgent(() => ({
      body: { shared: true, status: 200 },
    }));
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: holder.baseUrl,
      verifierBaseUrl: "http://127.0.0.1:2",
    });

    await expect(
      client.share({ ...positiveResolution(), verdict }),
    ).rejects.toThrow("verifier_not_authorized");
    expect(holder.requests).toHaveLength(0);
  });

  it.each([
    {
      status: 503,
      body: { error: "sensitive-upstream-body" },
    },
    {
      status: 200,
      body: "not-json",
    },
    {
      status: 200,
      body: {
        gateId: "gate",
        verdict: "TRUSTED_AUTHORIZED",
        evidence: {},
        request: {},
        unexpected: "strict parsing must reject this",
      },
    },
  ])(
    "maps non-positive or malformed upstream responses to one safe error",
    async ({ body, status }) => {
      const holder = await startAgent(() => ({ body, status }));
      const client = new LocalWalletClient({
        issuerBaseUrl: "http://127.0.0.1:1",
        holderBaseUrl: holder.baseUrl,
        verifierBaseUrl: "http://127.0.0.1:2",
      });

      const result = client.resolveRequest("openid4vp://sensitive-request");

      await expect(result).rejects.toThrow("vs_agent_unavailable");
      await expect(result).rejects.not.toThrow("sensitive-upstream-body");
    },
  );

  it("bounds requests to three seconds and disables fetch caching", async () => {
    const issuer = await startAgent(() => ({
      body: {
        credentialOffer: "openid-credential-offer://local",
        credentialOfferObject: {},
        issuanceSessionId: "issuance-1",
      },
    }));
    const nativeFetch = globalThis.fetch;
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation((input, init) => nativeFetch(input, init));
    try {
      const client = new LocalWalletClient({
        issuerBaseUrl: issuer.baseUrl,
        holderBaseUrl: "http://127.0.0.1:1",
        verifierBaseUrl: "http://127.0.0.1:2",
      });

      await client.issueBadge("local-user");

      expect(fetchSpy.mock.calls[0]?.[1]).toMatchObject({ cache: "no-store" });
      expect(fetchSpy.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("rejects an oversized valid-shaped chunked response without exposing its body", async () => {
    const sensitiveMarker = "oversized-sensitive-receipt";
    const verifier = await startAgent(() => ({
      body: JSON.stringify({
        state: "ResponseVerified",
        receipt: {
          padding: `${sensitiveMarker}${"x".repeat(70 * 1024)}`,
        },
      }),
    }));
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: "http://127.0.0.1:2",
      verifierBaseUrl: verifier.baseUrl,
    });

    const result = client.getPresentationStatus("verification-1");

    await expect(result).rejects.toThrow("vs_agent_unavailable");
    await expect(result).rejects.not.toThrow(sensitiveMarker);
  });

  it("rejects an oversized declared Content-Length before parsing", async () => {
    const verifier = await startAgent(() => ({
      body: JSON.stringify({
        state: "ResponseVerified",
        receipt: { padding: "x".repeat(70 * 1024) },
      }),
      headers: { "content-length": String(70 * 1024) },
    }));
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: "http://127.0.0.1:2",
      verifierBaseUrl: verifier.baseUrl,
    });

    await expect(
      client.getPresentationStatus("verification-1"),
    ).rejects.toThrow("vs_agent_unavailable");
  });

  it("rejects real-shaped responses with unbounded claim arrays", async () => {
    const holder = await startAgent(() => ({
      body: {
        ...positiveResolution(),
        request: {
          ...positiveResolution().request,
          requestedClaims: Array.from(
            { length: 33 },
            (_, index) => `claim-${index}`,
          ),
        },
      },
    }));
    const client = new LocalWalletClient({
      issuerBaseUrl: "http://127.0.0.1:1",
      holderBaseUrl: holder.baseUrl,
      verifierBaseUrl: "http://127.0.0.1:2",
    });

    await expect(
      client.resolveRequest("openid4vp://sensitive-request"),
    ).rejects.toThrow("vs_agent_unavailable");
  });
});
