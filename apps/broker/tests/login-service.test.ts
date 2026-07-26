import { describe, expect, it } from "vitest";

import {
  type LoginAccountClaims,
  type LoginAccountStore,
  LoginService,
} from "../src/login-service.js";
import { derivePairwiseSub } from "../src/pairwise-sub.js";
import { TransactionStore } from "../src/transaction-store.js";
import type { VsAgentClient, VsAgentSession } from "../src/vs-agent-client.js";
import {
  EXPECTED_VCT,
  EXPECTED_VTJSC_ID,
  positiveSession,
} from "./fixtures/positive-receipt.js";

class FakeAccountStore implements LoginAccountStore {
  readonly saved = new Map<string, LoginAccountClaims>();

  save(accountId: string, claims: LoginAccountClaims): void {
    this.saved.set(accountId, claims);
  }
}

function createService(getSession: () => Promise<VsAgentSession>): {
  accounts: FakeAccountStore;
  service: LoginService;
  transactions: TransactionStore;
} {
  const transactions = new TransactionStore(() => 1_000);
  const accounts = new FakeAccountStore();
  const client = {
    createRequest: async () => ({
      authorizationRequest: "openid4vp://request",
      sessionId: "vs-1",
    }),
    getSession,
  } satisfies Pick<VsAgentClient, "createRequest" | "getSession">;

  return {
    accounts,
    service: new LoginService({
      vsAgentClient: client,
      transactionStore: transactions,
      accountStore: accounts,
      expectedVct: EXPECTED_VCT,
      expectedVtjscId: EXPECTED_VTJSC_ID,
      expectedNetwork: "vna-testnet-1",
      expectedEcosystemId: 184,
      expectedCredentialSchemaId: 249,
      sectorIdentifier: "verana-playground",
      pairwiseSubSecret: new Uint8Array(32).fill(7),
    }),
    transactions,
  };
}

describe("LoginService", () => {
  it("starts one trusted verifier session and stores the login transaction", async () => {
    const { service, transactions } = createService(async () => ({
      state: "RequestCreated",
    }));

    await expect(service.start("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      vsSessionId: "vs-1",
      authorizationRequest: "openid4vp://request",
      status: "pending",
    });
    expect(transactions.get("tx-1")).toMatchObject({
      vsSessionId: "vs-1",
      status: "pending",
    });
  });

  it("keeps a non-verified verifier session pending", async () => {
    const { accounts, service } = createService(async () => ({
      state: "RequestCreated",
    }));
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "pending",
    });
    expect(accounts.saved.size).toBe(0);
  });

  it("authorizes a positive receipt and stores pairwise account claims", async () => {
    const secret = new Uint8Array(32).fill(7);
    const expectedSubject = derivePairwiseSub({
      secret,
      issuerDid: "did:web:issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "verana-playground",
    });
    const { accounts, service } = createService(async () => positiveSession);
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "verified",
      accountId: expectedSubject,
    });
    expect(accounts.saved.get(expectedSubject)).toEqual({
      sub: expectedSubject,
      organization: "ACME",
      role: "employee",
      verana_verifier_did: "did:web:verifier.example",
      verana_issuer_did: "did:web:issuer.example",
    });
  });

  it("does not overwrite a completed transaction with cached verification", async () => {
    const { service, transactions } = createService(
      async () => positiveSession,
    );
    await service.start("tx-1");
    const verified = await service.poll("tx-1");
    transactions.complete("tx-1", verified.accountId ?? "");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "used",
      accountId: verified.accountId,
    });
  });

  it("denies a non-positive verdict without creating an account", async () => {
    const denied = structuredClone(positiveSession);
    denied.receipt.verifier.verdict = "PARTIAL";
    const { accounts, service } = createService(async () => denied);
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "denied",
      errorCode: "verifier_not_authorized",
    });
    expect(accounts.saved.size).toBe(0);
  });

  it("denies a rogue verifier tenant without creating an account", async () => {
    const denied = structuredClone(positiveSession);
    denied.receipt.exchange.tenant = "rogue";
    const { accounts, service } = createService(async () => denied);
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "denied",
      errorCode: "tenant_not_allowed",
    });
    expect(accounts.saved.size).toBe(0);
  });

  it("denies a receipt carrying a __proto__ own key without creating an account", async () => {
    const polluted = structuredClone(positiveSession);
    Object.defineProperty(polluted.receipt.verifier.evidence, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      writable: true,
      configurable: true,
    });
    const { accounts, service } = createService(async () => polluted);
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "denied",
      errorCode: "invalid_receipt",
    });
    expect(accounts.saved.size).toBe(0);
  });

  it("marks an unavailable verifier session without creating an account", async () => {
    const { accounts, service } = createService(async () => {
      throw new Error("vs_agent_unavailable");
    });
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      uid: "tx-1",
      status: "unavailable",
      errorCode: "vs_agent_unavailable",
    });
    expect(accounts.saved.size).toBe(0);
  });
});
