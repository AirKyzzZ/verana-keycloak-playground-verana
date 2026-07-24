/// <reference types="node" />

import request from "supertest";
import { describe, expect, it, vi } from "vitest";

import type {
  AuthorizationTransaction,
  KeycloakIdentity,
} from "../src/keycloak-client.js";
import type {
  AcceptedBadge,
  IssuedBadge,
  ResolvedPresentation,
  SharedPresentation,
} from "../src/local-wallet-client.js";
import { createDemoServer, type DemoServerOptions } from "../src/server.js";

const config: DemoServerOptions["config"] = {
  DEMO_APP_PORT: 3000,
  PLAYGROUND_APP_CLIENT_SECRET: "c".repeat(43),
  SESSION_SECRET: "s".repeat(43),
  KEYCLOAK_ISSUER: "http://localhost:8080/realms/verana-playground",
  KEYCLOAK_CLIENT_ID: "playground-app",
  DEMO_APP_REDIRECT_URI: "http://localhost:3000/callback",
  VS_AGENT_ISSUER_BASE_URL: "http://localhost:3101",
  VS_AGENT_HOLDER_BASE_URL: "http://localhost:3102",
  VS_AGENT_VERIFIER_BASE_URL: "http://localhost:3201",
};

const transaction: AuthorizationTransaction = {
  state: "expected-state",
  nonce: "expected-nonce",
  pkceVerifier: "v".repeat(43),
};

const authorizedIdentity: KeycloakIdentity = {
  issuer: config.KEYCLOAK_ISSUER,
  audience: [config.KEYCLOAK_CLIENT_ID],
  subject: "keycloak-user-1",
  veranaSubject: "pairwise-subject-123",
  groups: ["/organizations/acme"],
  realmRoles: ["employee"],
};

const issuedBadge: IssuedBadge = {
  credentialOffer: "openid-credential-offer://sensitive-offer",
  issuanceSessionId: "issuance-1",
};

const acceptedBadge: AcceptedBadge = {
  credentialId: "credential-1",
  subjectId: "local-user",
  vct: "https://issuer.example/vct",
};

const positiveResolution: ResolvedPresentation = {
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
    requestedVct: "https://issuer.example/vct",
    requestedClaims: ["subject_id", "organization", "role"],
  },
};

function createOptions(
  identity: KeycloakIdentity = authorizedIdentity,
): DemoServerOptions & {
  keycloakClient: DemoServerOptions["keycloakClient"] & {
    exchangeCallback: ReturnType<typeof vi.fn>;
    startAuthorization: ReturnType<typeof vi.fn>;
  };
  walletClient: DemoServerOptions["walletClient"] & {
    acceptOffer: ReturnType<typeof vi.fn>;
    issueBadge: ReturnType<typeof vi.fn>;
    resolveRequest: ReturnType<typeof vi.fn>;
    share: ReturnType<typeof vi.fn>;
  };
} {
  const startAuthorization = vi.fn(async () => ({
    url: `${config.KEYCLOAK_ISSUER}/protocol/openid-connect/auth?state=${transaction.state}`,
    transaction,
  }));
  const exchangeCallback = vi.fn(async () => identity);
  const issueBadge = vi.fn(async () => issuedBadge);
  const acceptOffer = vi.fn(async () => acceptedBadge);
  const resolveRequest = vi.fn(async () => positiveResolution);
  const share = vi.fn(
    async (): Promise<SharedPresentation> => ({ shared: true, status: 200 }),
  );

  return {
    config,
    keycloakClient: {
      exchangeCallback,
      startAuthorization,
    },
    walletClient: {
      acceptOffer,
      createPresentationRequest: vi.fn(),
      getPresentationStatus: vi.fn(),
      issueBadge,
      resolveRequest,
      share,
    },
  };
}

function cookieValue(
  response: request.Response,
  name: string,
): string | undefined {
  const setCookie = response.headers["set-cookie"];
  const headers = Array.isArray(setCookie)
    ? setCookie
    : setCookie
      ? [setCookie]
      : [];
  return headers.find((value) => value.startsWith(`${name}=`));
}

async function login(options = createOptions()): Promise<{
  agent: ReturnType<typeof request.agent>;
  options: ReturnType<typeof createOptions>;
}> {
  const app = createDemoServer(options);
  const agent = request.agent(app.callback());
  await agent.get("/login").expect(302);
  await agent
    .get("/callback")
    .query({ code: "authorization-code", state: transaction.state })
    .expect(302)
    .expect("Location", "/profile");
  return { agent, options };
}

describe("OIDC application routes", () => {
  it("/login stores an opaque transaction and sets an HttpOnly SameSite=Lax cookie", async () => {
    const options = createOptions();
    const response = await request(createDemoServer(options).callback())
      .get("/login")
      .expect(302);
    const cookie = cookieValue(response, "verana_auth");

    expect(options.keycloakClient.startAuthorization).toHaveBeenCalledOnce();
    expect(response.headers.location).toContain("state=expected-state");
    expect(cookie).toMatch(/^verana_auth=[A-Za-z0-9_-]{43};/);
    expect(cookie).toContain("path=/");
    expect(cookie).toContain("httponly");
    expect(cookie).toContain("samesite=lax");
    expect(cookie).not.toContain("secure");
    expect(cookie).not.toContain(transaction.state);
    expect(cookie).not.toContain(transaction.nonce);
    expect(cookie).not.toContain(transaction.pkceVerifier);
  });

  it.each([
    ["missing", undefined],
    ["mismatched", "wrong-state"],
  ])(
    "rejects a %s callback state without token exchange",
    async (_name, state) => {
      const options = createOptions();
      const agent = request.agent(createDemoServer(options).callback());
      await agent.get("/login").expect(302);
      const callback = agent
        .get("/callback")
        .query({ code: "authorization-code" });
      if (state) callback.query({ state });

      const response = await callback.expect(400);

      expect(response.text).toContain("Invalid login callback");
      expect(options.keycloakClient.exchangeCallback).not.toHaveBeenCalled();
    },
  );

  it("passes the stored state, nonce, and PKCE verifier into token exchange", async () => {
    const options = createOptions();
    const agent = request.agent(createDemoServer(options).callback());
    await agent.get("/login").expect(302);

    await agent
      .get("/callback")
      .query({ code: "authorization-code", state: transaction.state })
      .expect(302);

    expect(options.keycloakClient.exchangeCallback).toHaveBeenCalledWith(
      new URL(
        `${config.DEMO_APP_REDIRECT_URI}?code=authorization-code&state=expected-state`,
      ),
      transaction,
    );
  });

  it.each([
    {
      name: "issuer",
      identity: { ...authorizedIdentity, issuer: "https://attacker.example" },
    },
    {
      name: "audience",
      identity: { ...authorizedIdentity, audience: ["different-client"] },
    },
  ])("does not create a session for an invalid $name", async ({ identity }) => {
    const options = createOptions(identity);
    const agent = request.agent(createDemoServer(options).callback());
    await agent.get("/login").expect(302);

    const response = await agent
      .get("/callback")
      .query({ code: "authorization-code", state: transaction.state })
      .expect(401);

    expect(response.text).toContain("Login verification failed");
    await agent.get("/profile").expect(401);
  });

  it("renders only an identity with the exact group, role, and nonempty Verana subject", async () => {
    const { agent } = await login();

    const response = await agent.get("/profile").expect(200);

    expect(response.text).toContain("pairwise-subject-123");
    expect(response.text).toContain("/organizations/acme");
    expect(response.text).toContain("employee");
  });

  it.each([
    {
      name: "Verana subject",
      identity: { ...authorizedIdentity, veranaSubject: "   " },
    },
    {
      name: "ACME group",
      identity: { ...authorizedIdentity, groups: ["/organizations/other"] },
    },
    {
      name: "employee role",
      identity: { ...authorizedIdentity, realmRoles: ["viewer"] },
    },
  ])(
    "refuses to render a profile without the required $name",
    async ({ identity }) => {
      const { agent } = await login(createOptions(identity));

      const response = await agent.get("/profile").expect(403);

      expect(response.text).toContain("Identity is not authorized");
      expect(response.text).not.toContain("keycloak-user-1");
    },
  );

  it("requires a server-side opaque session cookie", async () => {
    const options = createOptions();
    const app = createDemoServer(options);

    await request(app.callback()).get("/profile").expect(401);
    await request(app.callback())
      .get("/profile")
      .set(
        "Cookie",
        `verana_session=${Buffer.from(JSON.stringify(authorizedIdentity)).toString("base64url")}`,
      )
      .expect(401);
  });

  it("sets the authenticated session cookie HttpOnly and SameSite=Lax", async () => {
    const options = createOptions();
    const agent = request.agent(createDemoServer(options).callback());
    await agent.get("/login").expect(302);

    const response = await agent
      .get("/callback")
      .query({ code: "authorization-code", state: transaction.state })
      .expect(302);
    const cookie = cookieValue(response, "verana_session");

    expect(cookie).toMatch(/^verana_session=[A-Za-z0-9_-]{43};/);
    expect(cookie).toContain("httponly");
    expect(cookie).toContain("samesite=lax");
    expect(cookie).not.toContain("secure");
    expect(cookie).not.toContain("pairwise-subject-123");
  });

  it("logout destroys local state and expires the cookie", async () => {
    const { agent } = await login();

    const response = await agent.post("/logout").expect(302);

    expect(cookieValue(response, "verana_session")).toContain("expires=");
    await agent.get("/profile").expect(401);
  });
});

describe("local-holder routes", () => {
  it("issues exact ACME employee claims and accepts only through the local holder", async () => {
    const options = createOptions();
    const agent = request.agent(createDemoServer(options).callback());

    const response = await agent
      .post("/wallet/issue")
      .type("form")
      .send({ subjectId: "local-user" })
      .expect(200);

    expect(options.walletClient.issueBadge).toHaveBeenCalledWith("local-user");
    expect(options.walletClient.acceptOffer).toHaveBeenCalledWith(
      issuedBadge.credentialOffer,
    );
    expect(response.text).toContain("credential-1");
    expect(response.text).not.toContain(issuedBadge.credentialOffer);
  });

  it("shows the honest local-only evidence labels and sequence", async () => {
    const response = await request(createDemoServer(createOptions()).callback())
      .get("/wallet")
      .expect(200);

    expect(response.text).toContain("LOCAL HOLDER");
    expect(response.text).toContain("TESTNET");
    expect(response.text).toContain("not physical-wallet evidence");
    expect(response.text).toContain("Issue and accept");
    expect(response.text).toContain("broker authorization request");
    expect(response.text).toContain("Review Q1/Q3");
  });

  it("shares only the server-stored gate returned by a positive resolution", async () => {
    const options = createOptions();
    const agent = request.agent(createDemoServer(options).callback());
    await agent
      .post("/wallet/resolve")
      .type("form")
      .send({ authorizationRequest: "openid4vp://broker-request" })
      .expect(200);

    const response = await agent
      .post("/wallet/share")
      .type("form")
      .send({ gateId: "browser-forged-gate", verdict: "UNTRUSTED" })
      .expect(200);

    expect(options.walletClient.share).toHaveBeenCalledWith(positiveResolution);
    expect(response.text).toContain("Presentation shared");
  });

  it.each([
    "TRUSTED_NOT_AUTHORIZED",
    "UNTRUSTED",
    "RESOLVER_UNAVAILABLE",
  ] as const)("renders a refusal and never shares for %s", async (verdict) => {
    const options = createOptions();
    options.walletClient.resolveRequest.mockResolvedValueOnce({
      ...positiveResolution,
      verdict,
    });
    const agent = request.agent(createDemoServer(options).callback());

    const resolved = await agent
      .post("/wallet/resolve")
      .type("form")
      .send({ authorizationRequest: "openid4vp://broker-request" })
      .expect(200);
    const shared = await agent.post("/wallet/share").expect(403);

    expect(resolved.text).toContain("Sharing refused");
    expect(shared.text).toContain("Sharing refused");
    expect(options.walletClient.share).not.toHaveBeenCalled();
  });

  it("escapes all dynamic wallet values", async () => {
    const options = createOptions();
    options.walletClient.resolveRequest.mockResolvedValueOnce({
      ...positiveResolution,
      request: {
        ...positiveResolution.request,
        verifierDid: "<script>alert(1)</script>",
        requestedClaims: ['"><img src=x onerror=alert(1)>'],
      },
    });

    const response = await request(createDemoServer(options).callback())
      .post("/wallet/resolve")
      .type("form")
      .send({ authorizationRequest: "openid4vp://broker-request" })
      .expect(200);

    expect(response.text).not.toContain("<script>alert(1)</script>");
    expect(response.text).not.toContain("<img src=x onerror=alert(1)>");
    expect(response.text).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("maps proxy errors to a safe page without upstream bodies", async () => {
    const options = createOptions();
    options.walletClient.resolveRequest.mockRejectedValueOnce(
      new Error("upstream credential and authorization request body"),
    );

    const response = await request(createDemoServer(options).callback())
      .post("/wallet/resolve")
      .type("form")
      .send({ authorizationRequest: "openid4vp://sensitive-request" })
      .expect(502);

    expect(response.text).toContain("Local VS Agent unavailable");
    expect(response.text).not.toContain("upstream credential");
    expect(response.text).not.toContain("openid4vp://sensitive-request");
  });
});
