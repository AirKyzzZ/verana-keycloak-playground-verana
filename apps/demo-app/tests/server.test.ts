/// <reference types="node" />

import { createServer, type Server } from "node:http";

import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";

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
  EVIDENCE_MODE: "LIVE_VERANA",
};
const APP_ORIGIN = new URL(config.DEMO_APP_REDIRECT_URI).origin;
const CONTROLLED_ROGUE_DID = "did:web:rogue.localhost";
const CONTROLLED_VCT =
  "http://host.docker.internal:3099/vct/local-controlled-employee";
const CONTROLLED_VTJSC =
  "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json";
const CONTROLLED_RESOLVER = "http://host.docker.internal:3099/v1/trust";
const servers: Server[] = [];

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

const exactRogueDenial: ResolvedPresentation = {
  gateId: "gate-rogue-sensitive",
  verdict: "UNTRUSTED",
  evidence: {
    did: CONTROLLED_ROGUE_DID,
    trustStatus: "UNTRUSTED",
    authorized: null,
    vtjscId: CONTROLLED_VTJSC,
    queries: [`${CONTROLLED_RESOLVER}/resolve?did=did%3Aweb%3Arogue.localhost`],
  },
  request: {
    clientId: "x509_hash:rogue-verifier",
    clientIdPrefix: "x509_hash",
    verifierDid: CONTROLLED_ROGUE_DID,
    requestedVct: CONTROLLED_VCT,
    requestedClaims: ["subject_id", "organization", "role"],
  },
};

function createOptions(
  identity: KeycloakIdentity = authorizedIdentity,
  evidenceMode: DemoServerOptions["config"]["EVIDENCE_MODE"] = config.EVIDENCE_MODE,
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
    testRogueDenial: ReturnType<typeof vi.fn>;
  };
} {
  const startAuthorization = vi.fn(async () => ({
    url: `${config.KEYCLOAK_ISSUER}/protocol/openid-connect/auth?state=${transaction.state}`,
    transaction,
  }));
  const exchangeCallback = vi.fn(async () => identity);
  const issueBadge = vi.fn(async () => issuedBadge);
  const acceptOffer = vi.fn(async () =>
    evidenceMode === "LOCAL_CONTROLLED"
      ? { ...acceptedBadge, subjectId: "local-controlled-user" }
      : acceptedBadge,
  );
  const resolveRequest = vi.fn(async () => positiveResolution);
  const share = vi.fn(
    async (): Promise<SharedPresentation> => ({ shared: true, status: 200 }),
  );
  const testRogueDenial = vi.fn(async () => exactRogueDenial);

  return {
    config: Object.assign(
      { ...config, EVIDENCE_MODE: evidenceMode },
      evidenceMode === "LOCAL_CONTROLLED"
        ? {
            EXPECTED_VCT: CONTROLLED_VCT,
            EXPECTED_VTJSC_ID: CONTROLLED_VTJSC,
            ROGUE_VERIFIER_DID: CONTROLLED_ROGUE_DID,
            VERANA_RESOLVER_URL: CONTROLLED_RESOLVER,
          }
        : {},
    ),
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
      testRogueDenial,
    },
  };
}

async function startDemoServer(
  options: DemoServerOptions = createOptions(),
): Promise<Server> {
  const server = createServer(createDemoServer(options).callback());
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  servers.push(server);
  return server;
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

function csrfToken(response: request.Response): string {
  const match = response.text.match(
    /<input[^>]+name="csrfToken"[^>]+value="([^"]+)"/,
  );
  if (!match?.[1]) throw new Error("csrf_token_not_rendered");
  return match[1];
}

async function openWallet(
  agent: ReturnType<typeof request.agent>,
): Promise<string> {
  return csrfToken(await agent.get("/wallet").expect(200));
}

function walletMutation(
  agent: ReturnType<typeof request.agent>,
  path:
    | "/wallet/issue"
    | "/wallet/resolve"
    | "/wallet/share"
    | "/wallet/test-rogue-denial",
  token: string,
  body: Record<string, string> = {},
) {
  return agent
    .post(path)
    .set("Origin", APP_ORIGIN)
    .type("form")
    .send({ ...body, csrfToken: token });
}

async function login(options = createOptions()): Promise<{
  agent: ReturnType<typeof request.agent>;
  options: ReturnType<typeof createOptions>;
}> {
  const agent = request.agent(await startDemoServer(options));
  await agent.get("/login").expect(302);
  await agent
    .get("/callback")
    .query({ code: "authorization-code", state: transaction.state })
    .expect(302)
    .expect("Location", "/profile");
  return { agent, options };
}

describe("OIDC application routes", () => {
  it("labels every controlled-local page without rendering protocol secrets", async () => {
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    const home = await request(await startDemoServer(options))
      .get("/")
      .expect(200);
    const wallet = await request(await startDemoServer(options))
      .get("/wallet")
      .expect(200);
    const signedOut = await request(await startDemoServer(options))
      .get("/profile")
      .expect(401);
    const error = await request(await startDemoServer(options))
      .get("/callback")
      .expect(400);
    const { agent } = await login(options);
    const profile = await agent.get("/profile").expect(200);

    for (const response of [home, wallet, signedOut, error, profile]) {
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.text).toContain("LOCAL_CONTROLLED");
      expect(response.text).toContain("controlled local trust resolver");
      expect(response.text).toContain("not Verana testnet");
      expect(response.text).not.toContain(
        '><span class="badge">TESTNET</span>',
      );
      expect(response.text).not.toContain("raw-secret-presentation-token");
    }
  });

  it("uses same-origin referrer policy so Chrome preserves the exact Origin required by CSRF checks", async () => {
    const response = await request(await startDemoServer())
      .get("/")
      .expect(200);

    expect(response.headers["referrer-policy"]).toBe("same-origin");
  });

  it("/login stores an opaque transaction and sets an HttpOnly SameSite=Lax cookie", async () => {
    const options = createOptions();
    const response = await request(await startDemoServer(options))
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
      const agent = request.agent(await startDemoServer(options));
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
    const agent = request.agent(await startDemoServer(options));
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
    const agent = request.agent(await startDemoServer(options));
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

  it("renders a random server-bound CSRF token in the authenticated logout form", async () => {
    const { agent } = await login();

    const response = await agent.get("/profile").expect(200);
    const token = csrfToken(response);

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(response.text.match(/name="csrfToken"/g)).toHaveLength(1);
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
    const server = await startDemoServer(options);

    await request(server).get("/profile").expect(401);
    await request(server)
      .get("/profile")
      .set(
        "Cookie",
        `verana_session=${Buffer.from(JSON.stringify(authorizedIdentity)).toString("base64url")}`,
      )
      .expect(401);
  });

  it("sets the authenticated session cookie HttpOnly and SameSite=Lax", async () => {
    const options = createOptions();
    const agent = request.agent(await startDemoServer(options));
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

  it("cross-port forced logout is rejected without terminating the session", async () => {
    const { agent } = await login();
    const token = csrfToken(await agent.get("/profile").expect(200));

    const response = await agent
      .post("/logout")
      .set("Origin", "http://localhost:9999")
      .type("form")
      .send({ csrfToken: token })
      .expect(403);

    expect(response.text).toContain("Invalid logout request");
    await agent.get("/profile").expect(200);
  });

  it.each([
    { name: "missing Origin", origin: undefined, submittedToken: "valid" },
    { name: "null Origin", origin: "null", submittedToken: "valid" },
    {
      name: "wrong Origin",
      origin: "http://localhost:4000",
      submittedToken: "valid",
    },
    { name: "missing token", origin: APP_ORIGIN, submittedToken: undefined },
    { name: "null token", origin: APP_ORIGIN, submittedToken: "null" },
    {
      name: "wrong token",
      origin: APP_ORIGIN,
      submittedToken: "wrong-csrf-token",
    },
  ])(
    "rejects logout with $name without terminating the session",
    async ({ origin, submittedToken }) => {
      const { agent } = await login();
      const validToken = csrfToken(await agent.get("/profile").expect(200));
      const mutation = agent.post("/logout").type("form");
      if (origin) mutation.set("Origin", origin);
      if (submittedToken) {
        mutation.send({
          csrfToken: submittedToken === "valid" ? validToken : submittedToken,
        });
      }

      const response = await mutation.expect(403);

      expect(response.text).toContain("Invalid logout request");
      await agent.get("/profile").expect(200);
    },
  );

  it("valid logout destroys local state and expires the cookie", async () => {
    const { agent } = await login();
    const token = csrfToken(await agent.get("/profile").expect(200));

    const response = await agent
      .post("/logout")
      .set("Origin", APP_ORIGIN)
      .type("form")
      .send({ csrfToken: token })
      .expect(302);

    expect(cookieValue(response, "verana_session")).toContain("expires=");
    await agent.get("/profile").expect(401);
  });
});

describe("local-holder routes", () => {
  it("renders a fixed readonly controlled holder subject and keeps the LIVE_VERANA input unchanged", async () => {
    const controlled = await request(
      await startDemoServer(
        createOptions(authorizedIdentity, "LOCAL_CONTROLLED"),
      ),
    )
      .get("/wallet")
      .expect(200);
    const live = await request(await startDemoServer())
      .get("/wallet")
      .expect(200);

    expect(controlled.text).toContain("local-controlled-user");
    expect(controlled.text).toContain("readonly");
    expect(controlled.text).not.toContain('name="subjectId"');
    expect(controlled.text).toContain("Test rogue verifier denial");
    expect(live.text).toContain('name="subjectId"');
    expect(live.text).toContain('value="local-demo-user"');
    expect(live.text).not.toContain("Test rogue verifier denial");
  });

  it("uses the exact fixed controlled subject and rejects every browser override", async () => {
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    await walletMutation(agent, "/wallet/issue", token).expect(200);
    expect(options.walletClient.issueBadge).toHaveBeenCalledWith(
      "local-controlled-user",
    );

    const override = await walletMutation(agent, "/wallet/issue", token, {
      subjectId: "attacker-selected-subject",
    }).expect(400);

    expect(override.text).toContain("Invalid badge request");
    expect(options.walletClient.issueBadge).toHaveBeenCalledOnce();
  });

  it("fails closed when the controlled holder returns a different subject", async () => {
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    options.walletClient.acceptOffer.mockResolvedValueOnce({
      ...acceptedBadge,
      subjectId: "upstream-subject-drift",
    });
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    const response = await walletMutation(agent, "/wallet/issue", token).expect(
      502,
    );

    expect(response.text).toContain("Local VS Agent unavailable");
    expect(response.text).not.toContain("upstream-subject-drift");
  });

  it("does not expose the rogue denial route in LIVE_VERANA", async () => {
    const options = createOptions();
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    await walletMutation(agent, "/wallet/test-rogue-denial", token).expect(404);

    expect(options.walletClient.testRogueDenial).not.toHaveBeenCalled();
  });

  it.each(["", "null", "http://localhost:4000"])(
    "rejects controlled rogue denial with Origin %j before any upstream call",
    async (origin) => {
      const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
      const agent = request.agent(await startDemoServer(options));
      const token = await openWallet(agent);
      const mutation = agent
        .post("/wallet/test-rogue-denial")
        .type("form")
        .send({ csrfToken: token });
      if (origin) mutation.set("Origin", origin);

      await mutation.expect(403);

      expect(options.walletClient.testRogueDenial).not.toHaveBeenCalled();
    },
  );

  it.each([undefined, "wrong-csrf-token"])(
    "rejects controlled rogue denial with CSRF token %j before any upstream call",
    async (submittedToken) => {
      const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
      const agent = request.agent(await startDemoServer(options));
      const token = await openWallet(agent);

      await agent
        .post("/wallet/test-rogue-denial")
        .set("Origin", APP_ORIGIN)
        .type("form")
        .send({ csrfToken: submittedToken ?? "" })
        .expect(403);

      expect(token).not.toBe(submittedToken);
      expect(options.walletClient.testRogueDenial).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["tenant", "attacker-selected-tenant"],
    ["authorizationRequest", "openid4vp://attacker-request"],
    ["verifierDid", "did:web:attacker.example"],
    ["requestedVct", "https://attacker.example/vct"],
    ["vtjscId", "https://attacker.example/vtjsc"],
    ["requestedClaims", "admin"],
  ])(
    "rejects browser-supplied rogue protocol field %s",
    async (field, value) => {
      const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
      const agent = request.agent(await startDemoServer(options));
      const token = await openWallet(agent);

      const response = await walletMutation(
        agent,
        "/wallet/test-rogue-denial",
        token,
        { [field]: value },
      ).expect(400);

      expect(response.text).not.toContain(value);
      expect(options.walletClient.testRogueDenial).not.toHaveBeenCalled();
    },
  );

  it("renders only the terminal controlled denial summary and never crosses share or Keycloak", async () => {
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    const response = await walletMutation(
      agent,
      "/wallet/test-rogue-denial",
      token,
    ).expect(200);

    expect(response.text).toContain("LOCAL_CONTROLLED");
    expect(response.text).toContain(CONTROLLED_ROGUE_DID);
    expect(response.text).toContain("UNTRUSTED");
    expect(response.text).toContain("Sharing refused");
    expect(response.text).not.toContain("gate-rogue-sensitive");
    expect(response.text).not.toContain(CONTROLLED_VCT);
    expect(response.text).not.toContain(CONTROLLED_VTJSC);
    expect(response.text).not.toContain("subject_id");
    expect(response.text).not.toContain("authorizationRequest");
    expect(response.text).not.toContain("Share approved claims");
    expect(response.text).not.toContain('action="/wallet/share"');
    expect(options.walletClient.testRogueDenial).toHaveBeenCalledOnce();
    expect(options.walletClient.share).not.toHaveBeenCalled();
    expect(options.keycloakClient.startAuthorization).not.toHaveBeenCalled();
    expect(options.keycloakClient.exchangeCallback).not.toHaveBeenCalled();
  });

  it.each([
    [
      "verdict",
      { ...exactRogueDenial, verdict: "TRUSTED_AUTHORIZED" as const },
    ],
    [
      "request DID",
      {
        ...exactRogueDenial,
        request: {
          ...exactRogueDenial.request,
          verifierDid: "did:web:wrong.localhost",
        },
      },
    ],
    [
      "evidence DID",
      {
        ...exactRogueDenial,
        evidence: {
          ...exactRogueDenial.evidence,
          did: "did:web:wrong.localhost",
        },
      },
    ],
    [
      "trust",
      {
        ...exactRogueDenial,
        evidence: {
          ...exactRogueDenial.evidence,
          trustStatus: "TRUSTED" as const,
        },
      },
    ],
    [
      "authorization",
      {
        ...exactRogueDenial,
        evidence: { ...exactRogueDenial.evidence, authorized: true },
      },
    ],
    [
      "VTJSC",
      {
        ...exactRogueDenial,
        evidence: {
          ...exactRogueDenial.evidence,
          vtjscId: "https://wrong.example/vtjsc",
        },
      },
    ],
    [
      "VCT",
      {
        ...exactRogueDenial,
        request: {
          ...exactRogueDenial.request,
          requestedVct: "https://wrong.example/vct",
        },
      },
    ],
    [
      "claims",
      {
        ...exactRogueDenial,
        request: {
          ...exactRogueDenial.request,
          requestedClaims: ["subject_id", "organization"],
        },
      },
    ],
    [
      "resolver evidence",
      {
        ...exactRogueDenial,
        evidence: { ...exactRogueDenial.evidence, queries: [] },
      },
    ],
  ])("fails closed on rogue denial drift in %s", async (_name, resolution) => {
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    options.walletClient.testRogueDenial.mockResolvedValueOnce(resolution);
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    const response = await walletMutation(
      agent,
      "/wallet/test-rogue-denial",
      token,
    ).expect(502);

    expect(response.text).toContain(
      "Rogue verifier denial could not be verified",
    );
    expect(response.text).not.toContain("gate-rogue-sensitive");
    expect(response.text).not.toContain("Share approved claims");
    expect(response.text).not.toContain('action="/wallet/share"');
    expect(options.walletClient.share).not.toHaveBeenCalled();
    expect(options.keycloakClient.startAuthorization).not.toHaveBeenCalled();
    expect(options.keycloakClient.exchangeCallback).not.toHaveBeenCalled();
  });

  it("fails closed on a rogue client error without exposing the error or a share control", async () => {
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    options.walletClient.testRogueDenial.mockRejectedValueOnce(
      new Error("raw rogue authorization request and secret"),
    );
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    const response = await walletMutation(
      agent,
      "/wallet/test-rogue-denial",
      token,
    ).expect(502);

    expect(response.text).toContain(
      "Rogue verifier denial could not be verified",
    );
    expect(response.text).not.toContain("raw rogue authorization request");
    expect(response.text).not.toContain("secret");
    expect(response.text).not.toContain("Share approved claims");
    expect(response.text).not.toContain('action="/wallet/share"');
    expect(options.walletClient.share).not.toHaveBeenCalled();
  });

  it("invalidates a prior trusted gate before awaiting the controlled rogue denial", async () => {
    let releaseRogue: (() => void) | undefined;
    const roguePending = new Promise<ResolvedPresentation>((resolve) => {
      releaseRogue = () => resolve(exactRogueDenial);
    });
    const options = createOptions(authorizedIdentity, "LOCAL_CONTROLLED");
    options.walletClient.testRogueDenial.mockImplementationOnce(
      async () => await roguePending,
    );
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://trusted-request",
    }).expect(200);

    const pendingRogue = walletMutation(
      agent,
      "/wallet/test-rogue-denial",
      token,
    ).then((response) => response);
    await vi.waitFor(() => {
      expect(options.walletClient.testRogueDenial).toHaveBeenCalledOnce();
    });
    const share = await walletMutation(agent, "/wallet/share", token);
    releaseRogue?.();
    const denied = await pendingRogue;

    expect(share.status).toBe(409);
    expect(denied.status).toBe(200);
    expect(options.walletClient.share).not.toHaveBeenCalled();
  });

  it("renders one cryptographically random server-bound CSRF token into every wallet form", async () => {
    const agent = request.agent(await startDemoServer());

    const response = await agent.get("/wallet").expect(200);
    const token = csrfToken(response);

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(response.text.match(/name="csrfToken"/g)).toHaveLength(2);
    expect(
      response.text.match(new RegExp(`value="${token}"`, "g")),
    ).toHaveLength(2);
  });

  it.each(["", "null", "http://localhost:4000"])(
    "rejects wallet issue with Origin %j before any upstream call",
    async (origin) => {
      const options = createOptions();
      const agent = request.agent(await startDemoServer(options));
      const token = await openWallet(agent);
      const mutation = agent
        .post("/wallet/issue")
        .type("form")
        .send({ csrfToken: token, subjectId: "local-user" });
      if (origin) mutation.set("Origin", origin);

      const response = await mutation.expect(403);

      expect(response.text).toContain("Invalid wallet request");
      expect(options.walletClient.issueBadge).not.toHaveBeenCalled();
      expect(options.walletClient.acceptOffer).not.toHaveBeenCalled();
    },
  );

  it.each([undefined, "wrong-csrf-token"])(
    "rejects wallet issue with CSRF token %j before any upstream call",
    async (token) => {
      const options = createOptions();
      const agent = request.agent(await startDemoServer(options));
      await openWallet(agent);
      const body = {
        ...(token ? { csrfToken: token } : {}),
        subjectId: "local-user",
      };

      const response = await agent
        .post("/wallet/issue")
        .set("Origin", APP_ORIGIN)
        .type("form")
        .send(body)
        .expect(403);

      expect(response.text).toContain("Invalid wallet request");
      expect(options.walletClient.issueBadge).not.toHaveBeenCalled();
      expect(options.walletClient.acceptOffer).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["/wallet/issue", "issueBadge"],
    ["/wallet/resolve", "resolveRequest"],
    ["/wallet/share", "share"],
  ] as const)(
    "protects %s even when a localhost cross-port page submits the form",
    async (path, method) => {
      const options = createOptions();
      const agent = request.agent(await startDemoServer(options));
      await openWallet(agent);

      const response = await agent
        .post(path)
        .set("Origin", "http://localhost:9999")
        .type("form")
        .send({
          csrfToken: "attacker-token",
          subjectId: "local-user",
          authorizationRequest: "openid4vp://attacker-request",
        })
        .expect(403);

      expect(response.text).toContain("Invalid wallet request");
      expect(options.walletClient[method]).not.toHaveBeenCalled();
    },
  );

  it("issues exact ACME employee claims and accepts only through the local holder", async () => {
    const options = createOptions();
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    const response = await walletMutation(agent, "/wallet/issue", token, {
      subjectId: "local-user",
    }).expect(200);

    expect(options.walletClient.issueBadge).toHaveBeenCalledWith("local-user");
    expect(options.walletClient.acceptOffer).toHaveBeenCalledWith(
      issuedBadge.credentialOffer,
    );
    expect(response.text).toContain("credential-1");
    expect(response.text).not.toContain(issuedBadge.credentialOffer);
  });

  it("shows the honest local-only evidence labels and sequence", async () => {
    const response = await request(await startDemoServer())
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
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://broker-request",
    }).expect(200);

    const response = await walletMutation(agent, "/wallet/share", token, {
      gateId: "browser-forged-gate",
      verdict: "UNTRUSTED",
    }).expect(200);

    expect(options.walletClient.share).toHaveBeenCalledWith(positiveResolution);
    expect(response.text).toContain("Presentation shared");
    expect(response.text).not.toContain("Share approved claims");
    expect(response.text).not.toContain("Sharing refused");
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
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);

    const resolved = await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://broker-request",
    }).expect(200);
    const shared = await walletMutation(agent, "/wallet/share", token).expect(
      403,
    );

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

    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    const response = await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://broker-request",
    }).expect(200);

    expect(response.text).not.toContain("<script>alert(1)</script>");
    expect(response.text).not.toContain("<img src=x onerror=alert(1)>");
    expect(response.text).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("maps proxy errors to a safe page without upstream bodies", async () => {
    const options = createOptions();
    options.walletClient.resolveRequest.mockRejectedValueOnce(
      new Error("upstream credential and authorization request body"),
    );

    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    const response = await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://sensitive-request",
    }).expect(502);

    expect(response.text).toContain("Local VS Agent unavailable");
    expect(response.text).not.toContain("upstream credential");
    expect(response.text).not.toContain("openid4vp://sensitive-request");
  });

  it("claims a positive gate before awaiting share so concurrent posts call the holder once", async () => {
    let releaseShare: (() => void) | undefined;
    const shareGate = new Promise<void>((resolve) => {
      releaseShare = resolve;
    });
    const options = createOptions();
    options.walletClient.share.mockImplementationOnce(async () => {
      await shareGate;
      return { shared: true, status: 200 };
    });
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://broker-request",
    }).expect(200);

    const firstShare = walletMutation(agent, "/wallet/share", token).then(
      (response) => response,
    );
    await vi.waitFor(() => {
      expect(options.walletClient.share).toHaveBeenCalledOnce();
    });
    const secondResponse = await walletMutation(agent, "/wallet/share", token);
    releaseShare?.();
    const firstResponse = await firstShare;

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(409);
    expect(secondResponse.text).toContain("Sharing already in progress");
    expect(options.walletClient.share).toHaveBeenCalledOnce();
  });

  it("blocks retry after an uncertain upstream share failure", async () => {
    const options = createOptions();
    options.walletClient.share.mockRejectedValueOnce(
      new Error("holder response lost after submission"),
    );
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://broker-request",
    }).expect(200);

    await walletMutation(agent, "/wallet/share", token).expect(502);
    const retry = await walletMutation(agent, "/wallet/share", token).expect(
      409,
    );

    expect(retry.text).toContain("Sharing outcome is uncertain");
    expect(options.walletClient.share).toHaveBeenCalledOnce();
  });

  it("invalidates a previous positive gate before awaiting a new resolve", async () => {
    let rejectResolve: ((error: Error) => void) | undefined;
    const secondResolve = new Promise<ResolvedPresentation>(
      (_resolve, reject) => {
        rejectResolve = reject;
      },
    );
    const options = createOptions();
    options.walletClient.resolveRequest
      .mockResolvedValueOnce(positiveResolution)
      .mockImplementationOnce(async () => await secondResolve);
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://first-request",
    }).expect(200);

    const pendingResolve = walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://second-request",
    }).then((response) => response);
    await vi.waitFor(() => {
      expect(options.walletClient.resolveRequest).toHaveBeenCalledTimes(2);
    });
    const shareWhileResolving = await walletMutation(
      agent,
      "/wallet/share",
      token,
    );
    rejectResolve?.(new Error("new resolver failure"));
    const failedResolve = await pendingResolve;

    expect(shareWhileResolving.status).toBe(409);
    expect(failedResolve.status).toBe(502);
    expect(options.walletClient.share).not.toHaveBeenCalled();
  });

  it("keeps a failed replacement resolve from exposing the previous positive gate", async () => {
    const options = createOptions();
    options.walletClient.resolveRequest
      .mockResolvedValueOnce(positiveResolution)
      .mockRejectedValueOnce(new Error("new resolver failure"));
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://first-request",
    }).expect(200);

    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://replacement-request",
    }).expect(502);
    const share = await walletMutation(agent, "/wallet/share", token).expect(
      409,
    );

    expect(share.text).toContain("Resolve and review a new request");
    expect(options.walletClient.share).not.toHaveBeenCalled();
  });

  it("clears stale shared success when a new request resolves", async () => {
    const options = createOptions();
    options.walletClient.resolveRequest
      .mockResolvedValueOnce(positiveResolution)
      .mockResolvedValueOnce({
        ...positiveResolution,
        gateId: "gate-denied-2",
        verdict: "TRUSTED_NOT_AUTHORIZED",
      });
    const agent = request.agent(await startDemoServer(options));
    const token = await openWallet(agent);
    await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://first-request",
    }).expect(200);
    await walletMutation(agent, "/wallet/share", token).expect(200);

    const replacement = await walletMutation(agent, "/wallet/resolve", token, {
      authorizationRequest: "openid4vp://replacement-request",
    }).expect(200);

    expect(replacement.text).toContain("Sharing refused");
    expect(replacement.text).not.toContain("Presentation shared");
  });
});
