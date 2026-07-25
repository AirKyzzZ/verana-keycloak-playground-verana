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
const SECTOR_IDENTIFIER = "verana-playground";
const SECRET = new Uint8Array(32).fill(7);
const TRANSACTION_TTL_MS = 5 * 60 * 1_000;

type Receipt = typeof positiveSession;
type Mutate = (receipt: Receipt) => void;

class RecordingAccountStore implements LoginAccountStore {
  readonly saved = new Map<string, LoginAccountClaims>();
  saveCalls = 0;

  save(accountId: string, claims: LoginAccountClaims): void {
    this.saveCalls += 1;
    this.saved.set(accountId, { ...claims });
  }
}

interface HarnessOptions {
  expectedNetwork?: string;
  expectedEcosystemId?: number;
  expectedCredentialSchemaId?: number;
  sectorIdentifier?: string;
}

interface Harness {
  accounts: RecordingAccountStore;
  service: LoginService;
  transactions: TransactionStore;
  advance(milliseconds: number): void;
}

function receiptFor(sessionId: string, mutate: Mutate = () => {}): Receipt {
  const receipt = structuredClone(positiveSession);
  receipt.receipt.exchange.sessionId = sessionId;
  mutate(receipt);
  return receipt;
}

function createHarness(
  getSession: (sessionId: string) => Promise<unknown>,
  options: HarnessOptions = {},
): Harness {
  let now = 1_000;
  let issuedSessions = 0;
  const transactions = new TransactionStore(() => now);
  const accounts = new RecordingAccountStore();
  const client = {
    createRequest: async () => {
      issuedSessions += 1;
      return {
        authorizationRequest: "openid4vp://request",
        sessionId: `vs-${issuedSessions}`,
      };
    },
    getSession: async (sessionId: string) =>
      (await getSession(sessionId)) as VsAgentSession,
  } satisfies Pick<VsAgentClient, "createRequest" | "getSession">;

  return {
    accounts,
    transactions,
    advance(milliseconds) {
      now += milliseconds;
    },
    service: new LoginService({
      vsAgentClient: client,
      transactionStore: transactions,
      accountStore: accounts,
      expectedVct: EXPECTED_VCT,
      expectedVtjscId: EXPECTED_VTJSC_ID,
      expectedNetwork: options.expectedNetwork ?? EXPECTED_NETWORK,
      expectedEcosystemId: options.expectedEcosystemId ?? EXPECTED_ECOSYSTEM_ID,
      expectedCredentialSchemaId:
        options.expectedCredentialSchemaId ?? EXPECTED_CREDENTIAL_SCHEMA_ID,
      sectorIdentifier: options.sectorIdentifier ?? SECTOR_IDENTIFIER,
      pairwiseSubSecret: SECRET,
    }),
  };
}

async function expectDenied(
  mutate: Mutate,
  errorCode: string,
  options: HarnessOptions = {},
): Promise<void> {
  const { accounts, service, transactions } = createHarness(
    async (sessionId) => receiptFor(sessionId, mutate),
    options,
  );
  await service.start("tx-1");

  const polled = await service.poll("tx-1");
  const repolled = await service.poll("tx-1");

  expect(polled).toMatchObject({ uid: "tx-1", status: "denied", errorCode });
  expect(polled.accountId).toBeUndefined();
  expect(repolled).toMatchObject({ status: "denied", errorCode });
  expect(repolled.accountId).toBeUndefined();
  expect(accounts.saveCalls).toBe(0);
  expect(accounts.saved.size).toBe(0);
  expect(transactions.get("tx-1")).toMatchObject({ status: "pending" });
  expect(transactions.get("tx-1")?.accountId).toBeUndefined();
}

async function expectMalformed(
  mutate: (session: Record<string, unknown>) => void,
): Promise<void> {
  const { accounts, service, transactions } = createHarness(
    async (sessionId) => {
      const session = receiptFor(sessionId) as unknown as Record<
        string,
        unknown
      >;
      mutate(session);
      return session;
    },
  );
  await service.start("tx-1");

  await expect(service.poll("tx-1")).resolves.toMatchObject({
    status: "denied",
    errorCode: "invalid_receipt",
  });
  expect(accounts.saveCalls).toBe(0);
  expect(accounts.saved.size).toBe(0);
  expect(transactions.get("tx-1")).toMatchObject({ status: "pending" });
}

describe("LoginService evidence-consistency enforcement", () => {
  it.each(["verifier", "issuer"] as const)(
    "creates no account when %s evidence.authorized is null",
    async (party) => {
      await expectDenied((receipt) => {
        Object.assign(receipt.receipt[party].evidence, { authorized: null });
      }, `${party}_not_authorized`);
    },
  );

  it.each(["verifier", "issuer"] as const)(
    "creates no account when %s evidence.trustStatus is null",
    async (party) => {
      await expectDenied((receipt) => {
        Object.assign(receipt.receipt[party].evidence, { trustStatus: null });
      }, `${party}_not_authorized`);
    },
  );

  // A bare `evidence.did === party.did` check would let a receipt that omits
  // both dids authorize on null === null.
  it.each(["verifier", "issuer"] as const)(
    "creates no account when %s did and evidence.did are both null",
    async (party) => {
      await expectDenied((receipt) => {
        Object.assign(receipt.receipt[party], { did: null });
        Object.assign(receipt.receipt[party].evidence, { did: null });
      }, `${party}_not_authorized`);
    },
  );
});

describe("LoginService binding enforcement", () => {
  it("creates no account when the contract-nullable vct is null on both sides", async () => {
    await expectDenied((receipt) => {
      Object.assign(receipt.receipt.exchange, { vct: null });
      Object.assign(receipt.receipt.credential, { vct: null });
    }, "vct_mismatch");
  });
});

describe("LoginService registry-tuple binding", () => {
  it("creates no account for a testnet receipt when configured for the controlled network", async () => {
    await expectDenied(() => {}, "registry_mismatch", {
      expectedNetwork: "local-controlled",
      expectedEcosystemId: 1,
      expectedCredentialSchemaId: 2,
    });
  });

  it("creates no account when only the network differs from the controlled tuple", async () => {
    await expectDenied(
      (receipt) => {
        Object.assign(receipt.receipt.registry, {
          network: "vna-testnet-1",
          trustRegistry: 1,
          schema: 2,
        });
      },
      "registry_mismatch",
      {
        expectedNetwork: "local-controlled",
        expectedEcosystemId: 1,
        expectedCredentialSchemaId: 2,
      },
    );
  });

  it("authorizes the controlled tuple only when it is the configured tuple", async () => {
    const controlled = {
      expectedNetwork: "local-controlled",
      expectedEcosystemId: 1,
      expectedCredentialSchemaId: 2,
    };
    const mutate: Mutate = (receipt) => {
      Object.assign(receipt.receipt.registry, {
        network: "local-controlled",
        trustRegistry: 1,
        schema: 2,
      });
    };
    const { accounts, service } = createHarness(
      async (sessionId) => receiptFor(sessionId, mutate),
      controlled,
    );
    await service.start("tx-1");

    await expect(service.poll("tx-1")).resolves.toMatchObject({
      status: "verified",
    });
    expect(accounts.saved.size).toBe(1);

    await expectDenied(mutate, "registry_mismatch");
  });
});

describe("LoginService claim enforcement", () => {
  it.each([
    ["organization", "acme", "organization_not_allowed"],
    ["organization", 1, "organization_not_allowed"],
    ["organization", { toString: "ACME" }, "organization_not_allowed"],
    ["role", "Employee", "role_not_allowed"],
    ["role", true, "role_not_allowed"],
  ] as const)(
    "creates no account when %s is %s",
    async (claim, value, errorCode) => {
      await expectDenied((receipt) => {
        Object.assign(receipt.receipt.credential.disclosedClaims, {
          [claim]: value,
        });
      }, errorCode);
    },
  );

  // Both claims are optional in the receipt contract, so an omitted claim
  // parses cleanly and has to be caught by the allowlist instead.
  it.each(["organization", "role"] as const)(
    "creates no account when %s is absent",
    async (claim) => {
      await expectDenied((receipt) => {
        delete (
          receipt.receipt.credential.disclosedClaims as Record<string, unknown>
        )[claim];
      }, `${claim}_not_allowed`);
    },
  );

  it.each([
    ["absent", (claims: Record<string, unknown>) => delete claims.subject_id],
    [
      "empty",
      (claims: Record<string, unknown>) => {
        claims.subject_id = "";
      },
    ],
    [
      "null",
      (claims: Record<string, unknown>) => {
        claims.subject_id = null;
      },
    ],
    [
      "numeric",
      (claims: Record<string, unknown>) => {
        claims.subject_id = 1;
      },
    ],
    [
      "oversized",
      (claims: Record<string, unknown>) => {
        claims.subject_id = "a".repeat(201);
      },
    ],
  ] as const)(
    "creates no account for a %s subject_id",
    async (_label, mutate) => {
      await expectMalformed((session) => {
        const receipt = (session.receipt as Record<string, unknown>)
          .credential as Record<string, unknown>;
        mutate(receipt.disclosedClaims as Record<string, unknown>);
      });
    },
  );
});

describe("LoginService receipt shape enforcement", () => {
  it.each([
    ["root", (session: Record<string, unknown>) => session],
    ["receipt", (session: Record<string, unknown>) => session.receipt],
    [
      "exchange",
      (session: Record<string, unknown>) =>
        (session.receipt as Record<string, unknown>).exchange,
    ],
    [
      "verifier",
      (session: Record<string, unknown>) =>
        (session.receipt as Record<string, unknown>).verifier,
    ],
    [
      "verifier.evidence",
      (session: Record<string, unknown>) =>
        (
          (session.receipt as Record<string, unknown>).verifier as Record<
            string,
            unknown
          >
        ).evidence,
    ],
    [
      "issuer",
      (session: Record<string, unknown>) =>
        (session.receipt as Record<string, unknown>).issuer,
    ],
    [
      "issuer.evidence",
      (session: Record<string, unknown>) =>
        (
          (session.receipt as Record<string, unknown>).issuer as Record<
            string,
            unknown
          >
        ).evidence,
    ],
    [
      "credential",
      (session: Record<string, unknown>) =>
        (session.receipt as Record<string, unknown>).credential,
    ],
    [
      "credential.disclosedClaims",
      (session: Record<string, unknown>) =>
        (
          (session.receipt as Record<string, unknown>).credential as Record<
            string,
            unknown
          >
        ).disclosedClaims,
    ],
    [
      "registry",
      (session: Record<string, unknown>) =>
        (session.receipt as Record<string, unknown>).registry,
    ],
  ] as const)(
    "creates no account for an unknown field under %s",
    async (_label, select) => {
      await expectMalformed((session) => {
        Object.assign(select(session) as Record<string, unknown>, {
          smuggled: "attacker-controlled",
        });
      });
    },
  );

  it("creates no account for a positive receipt that is not yet verified", async () => {
    const { accounts, service, transactions } = createHarness(
      async (sessionId) => {
        const session = receiptFor(sessionId) as unknown as Record<
          string,
          unknown
        >;
        session.state = "ResponseReceived";
        return session;
      },
    );
    await service.start("tx-1");

    const polled = await service.poll("tx-1");

    expect(polled.status).toBe("pending");
    expect(polled.accountId).toBeUndefined();
    expect(accounts.saveCalls).toBe(0);
    expect(transactions.get("tx-1")).toMatchObject({ status: "pending" });
  });

  it("creates no account for a foreign presentation protocol", async () => {
    await expectMalformed((session) => {
      Object.assign(
        (session.receipt as Record<string, unknown>).exchange as Record<
          string,
          unknown
        >,
        { protocol: "OID4VP 0.9" },
      );
    });
  });

  it("never lets a smuggled __proto__ key reach Object.prototype or the claims", async () => {
    const { accounts, service } = createHarness(async (sessionId) =>
      JSON.parse(
        JSON.stringify(receiptFor(sessionId)).replace(
          '"queries"',
          '"__proto__":{"polluted":"yes"},"queries"',
        ),
      ),
    );
    await service.start("tx-1");

    await service.poll("tx-1");

    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(JSON.stringify([...accounts.saved.values()])).not.toContain(
      "polluted",
    );
  });
});

describe("LoginService transaction lifecycle", () => {
  it("creates no account for an expired login transaction", async () => {
    const harness = createHarness(async (sessionId) => receiptFor(sessionId));
    await harness.service.start("tx-1");
    harness.advance(TRANSACTION_TTL_MS);

    await expect(harness.service.poll("tx-1")).rejects.toThrow(
      "transaction_not_found",
    );
    expect(harness.accounts.saveCalls).toBe(0);
    expect(harness.accounts.saved.size).toBe(0);
    expect(harness.transactions.get("tx-1")).toBeUndefined();
  });

  it("creates no account for an unknown login transaction", async () => {
    const harness = createHarness(async (sessionId) => receiptFor(sessionId));

    await expect(harness.service.poll("tx-unknown")).rejects.toThrow(
      "transaction_not_found",
    );
    expect(harness.accounts.saved.size).toBe(0);
  });

  it("does not re-save the account when the same login is polled repeatedly", async () => {
    const harness = createHarness(async (sessionId) => receiptFor(sessionId));
    await harness.service.start("tx-1");

    const first = await harness.service.poll("tx-1");
    const second = await harness.service.poll("tx-1");
    const third = await harness.service.poll("tx-1");

    expect(first.accountId).toBe(second.accountId);
    expect(second.accountId).toBe(third.accountId);
    expect(harness.accounts.saveCalls).toBe(1);
    expect(harness.accounts.saved.size).toBe(1);
  });

  it("creates no account when a verified receipt is replayed onto a fresh login", async () => {
    const stolen = receiptFor("vs-1");
    const harness = createHarness(async () => stolen);
    await harness.service.start("tx-1");
    const verified = await harness.service.poll("tx-1");
    harness.transactions.complete("tx-1", verified.accountId ?? "");

    await harness.service.start("tx-2");
    const replayed = await harness.service.poll("tx-2");

    expect(verified.status).toBe("verified");
    expect(replayed).toMatchObject({
      status: "denied",
      errorCode: "session_mismatch",
    });
    expect(replayed.accountId).toBeUndefined();
    expect(harness.accounts.saveCalls).toBe(1);
    expect(harness.accounts.saved.size).toBe(1);
    expect(harness.transactions.get("tx-2")).toMatchObject({
      status: "pending",
    });
    expect(harness.transactions.get("tx-1")).toMatchObject({
      status: "used",
      accountId: verified.accountId,
    });
  });

  it("keeps a denied login denied even after a positive receipt appears", async () => {
    let sabotage = true;
    const harness = createHarness(async (sessionId) =>
      receiptFor(sessionId, (receipt) => {
        if (sabotage) {
          Object.assign(receipt.receipt.verifier, { verdict: "UNTRUSTED" });
        }
      }),
    );
    await harness.service.start("tx-1");
    await harness.service.poll("tx-1");
    sabotage = false;

    const repolled = await harness.service.poll("tx-1");

    expect(repolled).toMatchObject({
      status: "denied",
      errorCode: "verifier_not_authorized",
    });
    expect(harness.accounts.saveCalls).toBe(0);
    expect(harness.accounts.saved.size).toBe(0);
  });
});

describe("LoginService pairwise subject stability", () => {
  it("derives a different subject for a different sector identifier", async () => {
    const first = createHarness(async (sessionId) => receiptFor(sessionId));
    const other = createHarness(async (sessionId) => receiptFor(sessionId), {
      sectorIdentifier: "other-relying-party",
    });

    await first.service.start("tx-1");
    await other.service.start("tx-1");
    const firstLogin = await first.service.poll("tx-1");
    const otherLogin = await other.service.poll("tx-1");

    expect(firstLogin.accountId).toBeDefined();
    expect(otherLogin.accountId).toBeDefined();
    expect(otherLogin.accountId).not.toBe(firstLogin.accountId);
  });

  it("derives a different subject for a different issuer did", async () => {
    const baseline = createHarness(async (sessionId) => receiptFor(sessionId));
    const rebranded = createHarness(async (sessionId) =>
      receiptFor(sessionId, (receipt) => {
        Object.assign(receipt.receipt.issuer, {
          did: "did:web:issuer-two.example",
        });
        Object.assign(receipt.receipt.issuer.evidence, {
          did: "did:web:issuer-two.example",
        });
      }),
    );

    await baseline.service.start("tx-1");
    await rebranded.service.start("tx-1");
    const baselineLogin = await baseline.service.poll("tx-1");
    const rebrandedLogin = await rebranded.service.poll("tx-1");

    expect(baselineLogin.status).toBe("verified");
    expect(rebrandedLogin.status).toBe("verified");
    expect(rebrandedLogin.accountId).not.toBe(baselineLogin.accountId);
    expect(rebrandedLogin.accountId).toBe(
      derivePairwiseSub({
        secret: SECRET,
        issuerDid: "did:web:issuer-two.example",
        subjectId: "user-1",
        sectorIdentifier: SECTOR_IDENTIFIER,
      }),
    );
  });

  it("derives a different subject for a different subject_id", async () => {
    const baseline = createHarness(async (sessionId) => receiptFor(sessionId));
    const other = createHarness(async (sessionId) =>
      receiptFor(sessionId, (receipt) => {
        Object.assign(receipt.receipt.credential.disclosedClaims, {
          subject_id: "user-2",
        });
      }),
    );

    await baseline.service.start("tx-1");
    await other.service.start("tx-1");
    const baselineLogin = await baseline.service.poll("tx-1");
    const otherLogin = await other.service.poll("tx-1");

    expect(otherLogin.accountId).not.toBe(baselineLogin.accountId);
  });

  it("never emits the raw subject_id as the account id", async () => {
    const harness = createHarness(async (sessionId) => receiptFor(sessionId));
    await harness.service.start("tx-1");

    const verified = await harness.service.poll("tx-1");

    expect(verified.accountId).not.toBe("user-1");
    expect(verified.accountId).toHaveLength(43);
    expect(verified.accountId).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(JSON.stringify([...harness.accounts.saved.values()])).not.toContain(
      "user-1",
    );
  });
});
