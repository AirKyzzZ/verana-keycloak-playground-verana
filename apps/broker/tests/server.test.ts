import { exportJWK, generateKeyPair } from "jose";
import type Provider from "oidc-provider";
import request, { type SuperAgentTest } from "supertest";
import { beforeAll, describe, expect, it, vi } from "vitest";

import { AccountStore } from "../src/account-store.js";
import type { BrokerConfig } from "../src/config.js";
import { renderInteractionPage } from "../src/html.js";
import type { LoginService } from "../src/login-service.js";
import { createOidcProvider } from "../src/oidc-provider.js";
import { attachInteractionRoutes } from "../src/server.js";
import { TransactionStore } from "../src/transaction-store.js";
import type { LoginTransaction } from "../src/types.js";

const config: BrokerConfig = {
  BROKER_ISSUER: "http://localhost:3001",
  BROKER_PORT: 3001,
  BROKER_CLIENT_ID: "keycloak-playground",
  BROKER_CLIENT_SECRET: "broker-client-secret-at-least-32-bytes",
  KEYCLOAK_BROKER_REDIRECT_URI:
    "http://localhost:8080/realms/verana-playground/broker/verana-wallet/endpoint",
  VS_AGENT_VERIFIER_BASE_URL: "http://localhost:3201",
  EXPECTED_VCT: "https://credentials.example/employee",
  EXPECTED_VTJSC_ID: "employee-schema",
  SECTOR_IDENTIFIER: "verana-playground",
  PAIRWISE_SUB_SECRET: "pairwise-sub-secret-at-least-32-bytes",
  BROKER_JWKS_PATH: ".data/broker-jwks.json",
};

const authorizationRequest = `openid4vp://authorize?<script>&"'</script>`;

type LoginState = Pick<LoginTransaction, "status" | "accountId" | "errorCode">;

class FakeLoginService implements Pick<LoginService, "start" | "poll"> {
  startCalls = 0;
  readonly states = new Map<string, LoginState>();

  constructor(private readonly transactions: TransactionStore) {}

  async start(uid: string): Promise<LoginTransaction> {
    this.startCalls += 1;
    return this.transactions.create({
      uid,
      vsSessionId: `vs-${uid}`,
      authorizationRequest,
    });
  }

  async poll(uid: string): Promise<LoginTransaction> {
    const transaction = this.transactions.get(uid);
    if (!transaction) throw new Error("transaction_not_found");
    return { ...transaction, ...this.states.get(uid) };
  }
}

let privateJwks: Parameters<typeof createOidcProvider>[0]["privateJwks"];

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
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

async function beginInteraction(
  agent: SuperAgentTest,
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
  return { path, uid: path.split("/").at(-1) ?? "" };
}

function createHarness(now: () => number = () => 1_000): {
  agent: SuperAgentTest;
  loginService: FakeLoginService;
  provider: Provider;
  transactions: TransactionStore;
} {
  const transactions = new TransactionStore(now);
  const loginService = new FakeLoginService(transactions);
  const provider = createOidcProvider({
    accountStore: new AccountStore(),
    config,
    privateJwks,
  });
  attachInteractionRoutes(provider, {
    loginService,
    transactionStore: transactions,
  });

  return {
    agent: request.agent(provider.callback()),
    loginService,
    provider,
    transactions,
  };
}

describe("wallet interaction server", () => {
  it("creates one verifier request and reuses it on refresh", async () => {
    const { agent, loginService } = createHarness();
    const { path } = await beginInteraction(agent);

    const first = await agent.get(path);
    const refreshed = await agent.get(path);

    expect(first.status).toBe(200);
    expect(refreshed.status).toBe(200);
    expect(loginService.startCalls).toBe(1);
    expect(first.headers["cache-control"]).toBe("no-store");
    expect(first.text).toContain("Sign in with a Verana credential");
    expect(first.text).toContain("LOCAL DEMO");
    expect(first.text).toContain("TESTNET");
    expect(first.text).toContain("data:image/png;base64,");
    expect(first.text).toContain("Copy request");
  });

  it("polls with only status and an optional error code", async () => {
    const { agent, loginService } = createHarness();
    const { path, uid } = await beginInteraction(agent);
    await agent.get(path);

    const pending = await agent.get(`${path}/status`);
    expect(pending.status).toBe(200);
    expect(pending.headers["cache-control"]).toBe("no-store");
    expect(pending.body).toEqual({ status: "pending" });

    loginService.states.set(uid, {
      status: "denied",
      errorCode: "verifier_not_authorized",
      accountId: "must-not-leak",
    });
    const denied = await agent.get(`${path}/status`);
    expect(denied.body).toEqual({
      status: "denied",
      errorCode: "verifier_not_authorized",
    });
  });

  it("finishes the provider interaction only after verification", async () => {
    const { agent, loginService, provider, transactions } = createHarness();
    const { path, uid } = await beginInteraction(agent);
    await agent.get(path);
    loginService.states.set(uid, {
      status: "verified",
      accountId: "pairwise-account",
    });
    const finish = vi
      .spyOn(provider, "interactionFinished")
      .mockImplementation(async (_request, response) => {
        response.statusCode = 303;
        response.setHeader("Location", "/resume");
        response.end();
      });

    const response = await agent.get(`${path}/complete`);

    expect(response.status).toBe(303);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(finish).toHaveBeenCalledOnce();
    expect(finish.mock.calls[0]?.[2]).toEqual({
      login: { accountId: "pairwise-account" },
    });
    expect(transactions.get(uid)).toMatchObject({
      status: "used",
      accountId: "pairwise-account",
    });
  });

  it.each(["denied", "unavailable"] as const)(
    "does not finish a %s transaction",
    async (status) => {
      const { agent, loginService, provider } = createHarness();
      const { path, uid } = await beginInteraction(agent);
      await agent.get(path);
      loginService.states.set(uid, {
        status,
        errorCode:
          status === "denied"
            ? "verifier_not_authorized"
            : "vs_agent_unavailable",
      });
      const finish = vi.spyOn(provider, "interactionFinished");

      const response = await agent.get(`${path}/complete`);

      expect(response.status).toBe(409);
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(finish).not.toHaveBeenCalled();
    },
  );

  it("does not finish an expired transaction", async () => {
    let now = 1_000;
    const { agent, provider } = createHarness(() => now);
    const { path } = await beginInteraction(agent);
    await agent.get(path);
    now += 5 * 60 * 1_000;
    const finish = vi.spyOn(provider, "interactionFinished");

    const response = await agent.get(`${path}/complete`);

    expect(response.status).toBe(409);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(finish).not.toHaveBeenCalled();
  });

  it("does not finish a used transaction twice", async () => {
    const { agent, provider, transactions } = createHarness();
    const { path, uid } = await beginInteraction(agent);
    await agent.get(path);
    transactions.complete(uid, "pairwise-account");
    const finish = vi.spyOn(provider, "interactionFinished");

    const response = await agent.get(`${path}/complete`);

    expect(response.status).toBe(409);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(finish).not.toHaveBeenCalled();
  });

  it("escapes every dynamic value rendered into the page", () => {
    const html = renderInteractionPage({
      authorizationRequest,
      errorCode: `<img src=x onerror="alert(1)">`,
      qrDataUrl: `data:image/png;base64,"><script>alert(1)</script>`,
      status: "denied",
      uid: `uid"><script>alert(1)</script>`,
    });

    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  });
});
