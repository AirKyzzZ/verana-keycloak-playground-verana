import { derivePairwiseSub } from "./pairwise-sub.js";
import { authorizeReceipt } from "./policy.js";
import type { TransactionStore } from "./transaction-store.js";
import type { LoginTransaction } from "./types.js";
import type { VsAgentClient } from "./vs-agent-client.js";

export interface LoginAccountClaims {
  sub: string;
  organization: "ACME";
  role: "employee";
  verana_verifier_did: string;
  verana_issuer_did: string;
}

export interface LoginAccountStore {
  save(accountId: string, claims: LoginAccountClaims): void | Promise<void>;
}

export interface LoginServiceOptions {
  vsAgentClient: Pick<VsAgentClient, "createRequest" | "getSession">;
  transactionStore: TransactionStore;
  accountStore: LoginAccountStore;
  expectedVct: string;
  expectedVtjscId: string;
  sectorIdentifier: string;
  pairwiseSubSecret: Uint8Array;
}

type LoginState = Pick<LoginTransaction, "status" | "accountId" | "errorCode">;

const denialCodes = new Set([
  "invalid_receipt",
  "session_mismatch",
  "vct_mismatch",
  "schema_mismatch",
  "tenant_not_allowed",
  "verifier_not_authorized",
  "issuer_not_authorized",
  "organization_not_allowed",
  "role_not_allowed",
]);

export class LoginService {
  readonly #accountStore: LoginAccountStore;
  readonly #expectedVct: string;
  readonly #expectedVtjscId: string;
  readonly #pairwiseSubSecret: Uint8Array;
  readonly #sectorIdentifier: string;
  readonly #states = new Map<string, LoginState>();
  readonly #transactionStore: TransactionStore;
  readonly #vsAgentClient: Pick<VsAgentClient, "createRequest" | "getSession">;

  constructor(options: LoginServiceOptions) {
    this.#accountStore = options.accountStore;
    this.#expectedVct = options.expectedVct;
    this.#expectedVtjscId = options.expectedVtjscId;
    this.#pairwiseSubSecret = options.pairwiseSubSecret;
    this.#sectorIdentifier = options.sectorIdentifier;
    this.#transactionStore = options.transactionStore;
    this.#vsAgentClient = options.vsAgentClient;
  }

  async start(uid: string): Promise<LoginTransaction> {
    const request = await this.#vsAgentClient.createRequest("trusted");

    return this.#transactionStore.create({
      uid,
      vsSessionId: request.sessionId,
      authorizationRequest: request.authorizationRequest,
    });
  }

  async poll(uid: string): Promise<LoginTransaction> {
    const transaction = this.#transactionStore.get(uid);
    if (!transaction) throw new Error("transaction_not_found");
    if (transaction.status !== "pending") return transaction;

    const knownState = this.#states.get(uid);
    if (knownState) return { ...transaction, ...knownState };

    let session: Awaited<ReturnType<VsAgentClient["getSession"]>>;
    try {
      session = await this.#vsAgentClient.getSession(transaction.vsSessionId);
    } catch {
      return this.#setState(transaction, {
        status: "unavailable",
        errorCode: "vs_agent_unavailable",
      });
    }

    if (session.state !== "ResponseVerified") return transaction;

    let identity: ReturnType<typeof authorizeReceipt>;
    try {
      identity = authorizeReceipt(session, {
        sessionId: transaction.vsSessionId,
        vct: this.#expectedVct,
        vtjscId: this.#expectedVtjscId,
      });
    } catch (error) {
      const errorCode =
        error instanceof Error && denialCodes.has(error.message)
          ? error.message
          : "invalid_receipt";

      return this.#setState(transaction, {
        status: "denied",
        errorCode,
      });
    }

    const accountId = derivePairwiseSub({
      secret: this.#pairwiseSubSecret,
      issuerDid: identity.issuerDid,
      subjectId: identity.subjectId,
      sectorIdentifier: this.#sectorIdentifier,
    });

    await this.#accountStore.save(accountId, {
      sub: accountId,
      organization: identity.organization,
      role: identity.role,
      verana_verifier_did: identity.verifierDid,
      verana_issuer_did: identity.issuerDid,
    });

    return this.#setState(transaction, {
      status: "verified",
      accountId,
    });
  }

  #setState(
    transaction: LoginTransaction,
    state: LoginState,
  ): LoginTransaction {
    this.#states.set(transaction.uid, state);
    return { ...transaction, ...state };
  }
}
