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

const EXPECTED_NETWORK = "vna-testnet-1";
const EXPECTED_ECOSYSTEM_ID = 184;
const EXPECTED_CREDENTIAL_SCHEMA_ID = 249;
const SECRET = new Uint8Array(32).fill(7);

class FakeAccountStore implements LoginAccountStore {
  readonly saved = new Map<string, LoginAccountClaims>();

  save(accountId: string, claims: LoginAccountClaims): void {
    this.saved.set(accountId, claims);
  }
}

function createService(
  getSession: () => Promise<VsAgentSession>,
  overrides: { sectorIdentifier?: string } = {},
) {
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
    transactions,
    service: new LoginService({
      vsAgentClient: client,
      transactionStore: transactions,
      accountStore: accounts,
      expectedVct: EXPECTED_VCT,
      expectedVtjscId: EXPECTED_VTJSC_ID,
      expectedNetwork: EXPECTED_NETWORK,
      expectedEcosystemId: EXPECTED_ECOSYSTEM_ID,
      expectedCredentialSchemaId: EXPECTED_CREDENTIAL_SCHEMA_ID,
      sectorIdentifier: overrides.sectorIdentifier ?? "verana-playground",
      pairwiseSubSecret: SECRET,
    }),
  };
}

// Every denial below asserts on the ACCOUNT STORE, not merely on a thrown
// error: the property under test is that no Keycloak account and no session
// come into existence, not that some code path happened to throw.
async function expectNoAccount(
  mutate: (session: typeof positiveSession) => void,
): Promise<string | undefined> {
  const denied = structuredClone(positiveSession);
  mutate(denied);
  const { accounts, service, transactions } = createService(async () => denied);
  await service.start("tx-1");

  const result = await service.poll("tx-1");

  expect(result.status).not.toBe("verified");
  expect(result.accountId).toBeUndefined();
  expect(accounts.saved.size).toBe(0);
  expect(transactions.get("tx-1")?.accountId).toBeUndefined();
  return result.errorCode;
}

const DENIED_VERDICTS = [
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
  "PARTIAL",
] as const;

describe("Keycloak account creation is bound to a positive receipt", () => {
  it.each(DENIED_VERDICTS)(
    "creates nothing when the verifier verdict is %s",
    async (verdict) => {
      const code = await expectNoAccount((session) => {
        session.receipt.verifier.verdict = verdict;
      });
      expect(code).toBe("verifier_not_authorized");
    },
  );

  it.each(DENIED_VERDICTS)(
    "creates nothing when the issuer verdict is %s",
    async (verdict) => {
      const code = await expectNoAccount((session) => {
        session.receipt.issuer.verdict = verdict;
      });
      expect(code).toBe("issuer_not_authorized");
    },
  );

  // A receipt can claim TRUSTED_AUTHORIZED while its own evidence disagrees.
  // The verdict alone must never be sufficient.
  it.each([
    [
      "authorized false",
      (e: { authorized: boolean | null }) => (e.authorized = false),
    ],
    [
      "trustStatus not TRUSTED",
      (e: { trustStatus: string | null }) => (e.trustStatus = "UNTRUSTED"),
    ],
    [
      "evidence DID disagreeing",
      (e: { did: string | null }) => (e.did = "did:web:other.example"),
    ],
  ] as const)(
    "creates nothing for an internally inconsistent verifier: %s",
    async (_label, mutate) => {
      const code = await expectNoAccount((session) => {
        mutate(session.receipt.verifier.evidence as never);
      });
      expect(code).toBe("verifier_not_authorized");
    },
  );

  it.each([
    [
      "authorized false",
      (e: { authorized: boolean | null }) => (e.authorized = false),
    ],
    [
      "trustStatus not TRUSTED",
      (e: { trustStatus: string | null }) => (e.trustStatus = "UNTRUSTED"),
    ],
    [
      "evidence DID disagreeing",
      (e: { did: string | null }) => (e.did = "did:web:other.example"),
    ],
  ] as const)(
    "creates nothing for an internally inconsistent issuer: %s",
    async (_label, mutate) => {
      const code = await expectNoAccount((session) => {
        mutate(session.receipt.issuer.evidence as never);
      });
      expect(code).toBe("issuer_not_authorized");
    },
  );

  it("creates nothing for the rogue tenant", async () => {
    const code = await expectNoAccount((session) => {
      session.receipt.exchange.tenant = "rogue";
    });
    expect(code).toBe("tenant_not_allowed");
  });

  it.each([
    [
      "session id",
      (s: typeof positiveSession) => (s.receipt.exchange.sessionId = "other"),
    ],
    [
      "exchange vct",
      (s: typeof positiveSession) =>
        (s.receipt.exchange.vct = "https://other.example/vct"),
    ],
    [
      "credential vct",
      (s: typeof positiveSession) =>
        (s.receipt.credential.vct = "https://other.example/vct"),
    ],
    [
      "vtjscId",
      (s: typeof positiveSession) =>
        (s.receipt.registry.vtjscId = "https://other.example/schema"),
    ],
  ] as const)("creates nothing on %s mismatch", async (_label, mutate) => {
    const code = await expectNoAccount(mutate);
    expect(code).toBeDefined();
  });

  // The registry tuple moved from hardcoded testnet literals to configured
  // values; each field must still be load-bearing.
  it.each([
    [
      "network",
      (s: typeof positiveSession) =>
        (s.receipt.registry.network = "other-network"),
    ],
    [
      "trustRegistry",
      (s: typeof positiveSession) => (s.receipt.registry.trustRegistry = 185),
    ],
    [
      "schema",
      (s: typeof positiveSession) => (s.receipt.registry.schema = 250),
    ],
  ] as const)(
    "creates nothing when the registry %s does not match the configured tuple",
    async (_label, mutate) => {
      const code = await expectNoAccount(mutate);
      expect(code).toBe("registry_mismatch");
    },
  );

  it.each([
    [
      "organization",
      (s: typeof positiveSession) =>
        (s.receipt.credential.disclosedClaims.organization = "OTHER"),
    ],
    [
      "role",
      (s: typeof positiveSession) =>
        (s.receipt.credential.disclosedClaims.role = "contractor"),
    ],
  ] as const)("creates nothing on disallowed %s", async (_label, mutate) => {
    const code = await expectNoAccount(mutate);
    expect(code).toBe(`${_label}_not_allowed`);
  });

  it("creates nothing when an unknown nested field is present", async () => {
    const code = await expectNoAccount((session) => {
      Object.assign(session.receipt.verifier.evidence, { unexpected: "x" });
    });
    expect(code).toBe("invalid_receipt");
  });

  it("creates nothing when the verifier session is unreachable", async () => {
    const { accounts, service } = createService(async () => {
      throw new Error("vs_agent_unavailable");
    });
    await service.start("tx-1");

    const result = await service.poll("tx-1");

    expect(result.status).toBe("unavailable");
    expect(accounts.saved.size).toBe(0);
  });
});

describe("pairwise subject stability", () => {
  it("reuses one account across repeated logins of the same subject", async () => {
    const { accounts, service } = createService(async () => positiveSession);
    await service.start("tx-1");
    const first = await service.poll("tx-1");
    await service.start("tx-2");
    const second = await service.poll("tx-2");

    expect(first.accountId).toBe(second.accountId);
    expect(accounts.saved.size).toBe(1);
  });

  it("does not create a second account when a verified receipt is replayed", async () => {
    const { accounts, service, transactions } = createService(
      async () => positiveSession,
    );
    await service.start("tx-1");
    const verified = await service.poll("tx-1");
    transactions.complete("tx-1", verified.accountId ?? "");

    const replayed = await service.poll("tx-1");

    expect(replayed.status).toBe("used");
    expect(replayed.accountId).toBe(verified.accountId);
    expect(accounts.saved.size).toBe(1);
  });

  it("derives a different subject per sector identifier", async () => {
    const base = derivePairwiseSub({
      secret: SECRET,
      issuerDid: "did:web:issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "verana-playground",
    });
    const other = derivePairwiseSub({
      secret: SECRET,
      issuerDid: "did:web:issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "another-sector",
    });

    expect(other).not.toBe(base);
  });

  it("derives a different subject per issuer DID", async () => {
    const base = derivePairwiseSub({
      secret: SECRET,
      issuerDid: "did:web:issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "verana-playground",
    });
    const other = derivePairwiseSub({
      secret: SECRET,
      issuerDid: "did:web:other-issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "verana-playground",
    });

    expect(other).not.toBe(base);
  });
});
