import type { CreateLoginTransaction, LoginTransaction } from "./types.js";

const TRANSACTION_TTL_MS = 5 * 60 * 1_000;

export class TransactionStore {
  readonly #transactions = new Map<string, LoginTransaction>();
  readonly #now: () => number;

  constructor(now: () => number = Date.now) {
    this.#now = now;
  }

  create(input: CreateLoginTransaction): LoginTransaction {
    if (this.#transactions.has(input.uid))
      throw new Error("transaction_exists");

    const createdAt = this.#now();
    const transaction: LoginTransaction = {
      ...input,
      createdAt,
      expiresAt: createdAt + TRANSACTION_TTL_MS,
      status: "pending",
    };

    this.#transactions.set(transaction.uid, transaction);

    return { ...transaction };
  }

  get(uid: string): LoginTransaction | undefined {
    const transaction = this.#transactions.get(uid);

    if (!transaction || this.#isExpired(transaction)) return undefined;

    return { ...transaction };
  }

  complete(uid: string, accountId: string): LoginTransaction {
    const transaction = this.#transactions.get(uid);

    if (!transaction) throw new Error("transaction_not_found");
    if (this.#isExpired(transaction)) throw new Error("transaction_expired");
    if (transaction.status !== "pending")
      throw new Error("transaction_not_pending");

    transaction.status = "used";
    transaction.accountId = accountId;

    return { ...transaction };
  }

  #isExpired(transaction: LoginTransaction): boolean {
    return this.#now() >= transaction.expiresAt;
  }
}
