import { exportJWK, generateKeyPair } from "jose";
import type Provider from "oidc-provider";
import request from "supertest";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { AccountStore } from "../src/account-store.js";
import type { BrokerConfig } from "../src/config.js";
import { LoginService } from "../src/login-service.js";
import { createOidcProvider } from "../src/oidc-provider.js";
import { derivePairwiseSub } from "../src/pairwise-sub.js";
import { attachInteractionRoutes } from "../src/server.js";
import { TransactionStore } from "../src/transaction-store.js";
import type { VsAgentClient, VsAgentSession } from "../src/vs-agent-client.js";
import {
  EXPECTED_VCT,
  EXPECTED_VTJSC_ID,
  positiveSession,
} from "./fixtures/positive-receipt.js";

const SECRET = new Uint8Array(32).fill(7);
const SECTOR_IDENTIFIER = "verana-playground";

const config: BrokerConfig = {
  BROKER_ISSUER: "http://localhost:3001",
  BROKER_PORT: 3001,
  BROKER_CLIENT_ID: "keycloak-playground",
  BROKER_CLIENT_SECRET: "broker-client-secret-at-least-32-bytes",
  BROKER_COOKIE_SECRET: "broker-cookie-secret-at-least-32-bytes",
  KEYCLOAK_BROKER_REDIRECT_URI:
    "http://localhost:8080/realms/verana-playground/broker/verana-wallet/endpoint",
  VS_AGENT_VERIFIER_BASE_URL: "http://localhost:3201",
  EXPECTED_VCT,
  EXPECTED_VTJSC_ID,
  EXPECTED_NETWORK: "vna-testnet-1",
  EXPECTED_ECOSYSTEM_ID: 184,
  EXPECTED_CREDENTIAL_SCHEMA_ID: 249,
  SECTOR_IDENTIFIER,
  PAIRWISE_SUB_SECRET: "pairwise-sub-secret-at-least-32-bytes",
  BROKER_JWKS_PATH: ".data/broker-jwks.json",
  EVIDENCE_MODE: "LIVE_VERANA",
};

const positiveAccountId = derivePairwiseSub({
  secret: SECRET,
  issuerDid: "did:web:issuer.example",
  subjectId: "user-1",
  sectorIdentifier: SECTOR_IDENTIFIER,
});

type Receipt = typeof positiveSession;
type TestAgent = ReturnType<typeof request.agent>;

let privateJwks: Parameters<typeof createOidcProvider>[0]["privateJwks"];

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  privateJwks = {
    keys: [
      {
        ...(await exportJWK(privateKey)),
        alg: "ES256",
        kid: "broker-test",
        use: "sig",
      },
    ],
  };
});

interface Harness {
  accounts: AccountStore;
  agent: TestAgent;
  provider: Provider;
  transactions: TransactionStore;
  cookies: string[];
}

function createHarness(mutate: (receipt: Receipt) => void = () => {}): Harness {
  const transactions = new TransactionStore(() => 1_000);
  const accounts = new AccountStore();
  const cookies: string[] = [];
  let issuedSessions = 0;
  const vsAgentClient = {
    createRequest: async () => {
      issuedSessions += 1;
      return {
        authorizationRequest: "openid4vp://request",
        sessionId: `vs-${issuedSessions}`,
      };
    },
    getSession: async (sessionId: string) => {
      const receipt = structuredClone(positiveSession);
      receipt.receipt.exchange.sessionId = sessionId;
      mutate(receipt);
      return receipt as VsAgentSession;
    },
  } satisfies Pick<VsAgentClient, "createRequest" | "getSession">;

  const provider = createOidcProvider({
    accountStore: accounts,
    config,
    privateJwks,
  });
  attachInteractionRoutes(provider, {
    evidenceMode: config.EVIDENCE_MODE,
    loginService: new LoginService({
      vsAgentClient,
      transactionStore: transactions,
      accountStore: accounts,
      expectedVct: config.EXPECTED_VCT,
      expectedVtjscId: config.EXPECTED_VTJSC_ID,
      expectedNetwork: config.EXPECTED_NETWORK,
      expectedEcosystemId: config.EXPECTED_ECOSYSTEM_ID,
      expectedCredentialSchemaId: config.EXPECTED_CREDENTIAL_SCHEMA_ID,
      sectorIdentifier: config.SECTOR_IDENTIFIER,
      pairwiseSubSecret: SECRET,
    }),
    transactionStore: transactions,
  });

  const agent = request.agent(provider.callback());
  const originalGet = agent.get.bind(agent);
  agent.get = ((url: string) =>
    originalGet(url).on(
      "response",
      (response: { headers: Record<string, string[]> }) => {
        cookies.push(...(response.headers["set-cookie"] ?? []));
      },
    )) as TestAgent["get"];

  return { accounts, agent, provider, transactions, cookies };
}

async function beginLogin(
  agent: TestAgent,
): Promise<{ path: string; uid: string }> {
  const response = await agent.get("/auth").query({
    client_id: config.BROKER_CLIENT_ID,
    code_challenge: "a".repeat(43),
    code_challenge_method: "S256",
    redirect_uri: config.KEYCLOAK_BROKER_REDIRECT_URI,
    response_type: "code",
    scope: "openid",
    state: "state-1",
  });

  expect(response.status, response.text).toBe(303);
  const path = new URL(response.headers.location, config.BROKER_ISSUER)
    .pathname;
  await agent.get(path).expect(200);

  return { path, uid: path.split("/").at(-1) ?? "" };
}

function hasSessionCookie(cookies: string[]): boolean {
  return cookies.some((cookie) => cookie.startsWith("_session="));
}

describe("denied wallet logins never establish a broker session", () => {
  it.each([
    [
      "TRUSTED_NOT_AUTHORIZED verifier",
      (receipt: Receipt) => {
        Object.assign(receipt.receipt.verifier, {
          verdict: "TRUSTED_NOT_AUTHORIZED",
        });
      },
      "verifier_not_authorized",
    ],
    [
      "RESOLVER_UNAVAILABLE issuer",
      (receipt: Receipt) => {
        Object.assign(receipt.receipt.issuer, {
          verdict: "RESOLVER_UNAVAILABLE",
        });
      },
      "issuer_not_authorized",
    ],
    [
      "rogue tenant",
      (receipt: Receipt) => {
        receipt.receipt.exchange.tenant = "rogue";
      },
      "tenant_not_allowed",
    ],
    [
      "foreign network",
      (receipt: Receipt) => {
        Object.assign(receipt.receipt.registry, { network: "vna-mainnet-1" });
      },
      "registry_mismatch",
    ],
    [
      "unknown nested field",
      (receipt: Receipt) => {
        Object.assign(receipt.receipt.verifier.evidence, { smuggled: "x" });
      },
      "invalid_receipt",
    ],
  ] as const)(
    "refuses to complete a login with a %s",
    async (_label, mutate, errorCode) => {
      const { accounts, agent, cookies, provider, transactions } =
        createHarness(mutate);
      const { path, uid } = await beginLogin(agent);
      const finish = vi.spyOn(provider, "interactionFinished");

      const status = await agent.get(`${path}/status`);
      const complete = await agent.get(`${path}/complete`);
      const resumed = await agent.get(`/auth/${uid}`);

      expect(status.body).toEqual({ status: "denied", errorCode });
      expect(status.body).not.toHaveProperty("accountId");
      expect(complete.status).toBe(409);
      expect(finish).not.toHaveBeenCalled();
      expect(accounts.findAccount(positiveAccountId)).toBeUndefined();
      expect(transactions.get(uid)).toMatchObject({ status: "pending" });
      expect(transactions.get(uid)?.accountId).toBeUndefined();
      expect(resumed.headers.location ?? "").not.toContain("code=");
      expect(hasSessionCookie(cookies)).toBe(false);
    },
  );

  it("refuses to resume the authorization endpoint after a denial", async () => {
    const { accounts, agent, cookies, transactions } = createHarness(
      (receipt) => {
        Object.assign(receipt.receipt.verifier, { verdict: "UNTRUSTED" });
      },
    );
    const { path, uid } = await beginLogin(agent);
    await agent.get(`${path}/complete`).expect(409);

    const resumed = await agent.get(`/auth/${uid}`);

    expect(resumed.status).toBe(303);
    expect(resumed.headers.location).not.toContain("code=");
    expect(resumed.headers.location).not.toContain(
      config.KEYCLOAK_BROKER_REDIRECT_URI,
    );
    expect(accounts.findAccount(positiveAccountId)).toBeUndefined();
    expect(transactions.get(uid)).toMatchObject({ status: "pending" });
    expect(hasSessionCookie(cookies)).toBe(false);
  });
});

describe("authorized wallet logins establish exactly one broker session", () => {
  it("completes a positive login and establishes one broker session", async () => {
    const { accounts, agent, cookies, provider, transactions } =
      createHarness();
    const { path, uid } = await beginLogin(agent);
    const finish = vi.spyOn(provider, "interactionFinished");

    const status = await agent.get(`${path}/status`);
    const complete = await agent.get(`${path}/complete`);
    await agent.get(
      new URL(complete.headers.location, config.BROKER_ISSUER).pathname,
    );

    expect(status.body).toEqual({ status: "verified" });
    expect(complete.status).toBe(303);
    expect(finish).toHaveBeenCalledOnce();
    expect(finish.mock.calls[0]?.[2]).toEqual({
      login: { accountId: positiveAccountId },
    });
    expect(hasSessionCookie(cookies)).toBe(true);
    expect(accounts.findAccount(positiveAccountId)).toBeDefined();
    expect(transactions.get(uid)).toMatchObject({
      status: "used",
      accountId: positiveAccountId,
    });
  });

  it("issues an authorization code for a fully authorized login", async () => {
    const { agent } = createHarness();
    const { path } = await beginLogin(agent);
    const complete = await agent.get(`${path}/complete`);

    const resumed = await agent.get(
      new URL(complete.headers.location, config.BROKER_ISSUER).pathname,
    );

    expect(resumed.status).toBe(303);
    expect(resumed.headers.location).toContain(
      config.KEYCLOAK_BROKER_REDIRECT_URI,
    );
    expect(resumed.headers.location).toContain("code=");
  });

  it("keeps the interaction cookie http-only and scoped to its own interaction", async () => {
    const { agent, cookies } = createHarness();
    const { path } = await beginLogin(agent);

    const interactionCookie = cookies
      .find((cookie) => cookie.startsWith("_interaction="))
      ?.toLowerCase();

    expect(interactionCookie).toBeDefined();
    expect(interactionCookie).toContain("httponly");
    expect(interactionCookie).toContain(`path=${path.toLowerCase()}`);
    expect(interactionCookie).not.toContain("samesite=none");
  });

  // The interaction cookie is SameSite=Lax while `/complete` is a
  // state-changing GET, so a top-level cross-site navigation to a known uid
  // still carries it. Flip this to `it(...)` once completion requires POST.
  it.fails("carries no interaction cookie on a cross-site GET", async () => {
    const { agent, cookies } = createHarness();
    await beginLogin(agent);

    const interactionCookie = cookies
      .find((cookie) => cookie.startsWith("_interaction="))
      ?.toLowerCase();

    expect(interactionCookie).toContain("samesite=strict");
  });

  it("refuses to complete the same login twice", async () => {
    const { agent, provider, transactions } = createHarness();
    const { path, uid } = await beginLogin(agent);
    await agent.get(`${path}/complete`).expect(303);
    const finish = vi.spyOn(provider, "interactionFinished");

    const replayed = await agent.get(`${path}/complete`);

    expect(replayed.status).toBe(409);
    expect(finish).not.toHaveBeenCalled();
    expect(transactions.get(uid)).toMatchObject({
      status: "used",
      accountId: positiveAccountId,
    });
  });

  it("exposes only the pairwise subject and the allowlisted claims", async () => {
    const { accounts, agent } = createHarness();
    const { path } = await beginLogin(agent);
    await agent.get(`${path}/complete`).expect(303);

    const account = accounts.findAccount(positiveAccountId);
    const claims = account?.claims("id_token", "openid", {}, []) as Record<
      string,
      unknown
    >;

    expect(account?.accountId).toBe(positiveAccountId);
    expect(claims.sub).toBe(positiveAccountId);
    expect(JSON.stringify(claims)).not.toContain("user-1");
    expect(Object.keys(claims).sort()).toEqual([
      "organization",
      "preferred_username",
      "role",
      "sub",
      "verana_issuer_did",
      "verana_verifier_did",
    ]);
  });
});
