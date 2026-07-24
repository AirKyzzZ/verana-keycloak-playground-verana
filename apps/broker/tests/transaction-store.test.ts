import { describe, expect, it } from "vitest";

import { TransactionStore } from "../src/transaction-store.js";

describe("TransactionStore", () => {
  it("expires pending transactions after five minutes", () => {
    let now = 1_000;
    const store = new TransactionStore(() => now);

    store.create({
      uid: "tx-1",
      vsSessionId: "vs-1",
      authorizationRequest: "request",
    });
    expect(store.get("tx-1")?.expiresAt).toBe(now + 5 * 60 * 1_000);

    now += 5 * 60 * 1_000;
    expect(() => store.complete("tx-1", "account-1")).toThrow(
      "transaction_expired",
    );
  });

  it("rejects replay after a transaction has been completed", () => {
    const store = new TransactionStore(() => 1_000);
    store.create({
      uid: "tx-1",
      vsSessionId: "vs-1",
      authorizationRequest: "request",
    });

    expect(store.complete("tx-1", "account-1")).toMatchObject({
      status: "used",
      accountId: "account-1",
    });
    expect(() => store.complete("tx-1", "account-1")).toThrow(
      "transaction_not_pending",
    );
  });

  it("rejects missing transactions", () => {
    const store = new TransactionStore(() => 1_000);

    expect(() => store.complete("unknown", "account-1")).toThrow(
      "transaction_not_found",
    );
  });
});
