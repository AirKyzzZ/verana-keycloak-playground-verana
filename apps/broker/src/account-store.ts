import type { Account } from "oidc-provider";

import type { LoginAccountClaims, LoginAccountStore } from "./login-service.js";

export class AccountStore implements LoginAccountStore {
  readonly #accounts = new Map<string, LoginAccountClaims>();

  save(accountId: string, claims: LoginAccountClaims): void {
    if (claims.sub !== accountId) throw new Error("account_id_mismatch");
    this.#accounts.set(accountId, { ...claims });
  }

  findAccount(accountId: string): Account | undefined {
    const storedClaims = this.#accounts.get(accountId);
    if (!storedClaims) return undefined;

    const claims = {
      ...storedClaims,
      preferred_username: accountId,
    };

    return {
      accountId,
      claims: () => ({ ...claims }),
    };
  }
}
