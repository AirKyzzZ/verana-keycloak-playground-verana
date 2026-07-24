import { createHmac, randomBytes } from "node:crypto";

interface StoredValue<T> {
  expiresAt: number;
  value: T;
}

export interface OpaqueStoreOptions {
  clock?: () => number;
  randomToken?: () => string;
  ttlMs: number;
}

const defaultRandomToken = () => randomBytes(32).toString("base64url");

export class OpaqueStore<T> {
  readonly #clock: () => number;
  readonly #purpose: string;
  readonly #randomToken: () => string;
  readonly #secret: string;
  readonly #ttlMs: number;
  readonly #values = new Map<string, StoredValue<T>>();

  constructor(secret: string, purpose: string, options: OpaqueStoreOptions) {
    this.#clock = options.clock ?? Date.now;
    this.#purpose = purpose;
    this.#randomToken = options.randomToken ?? defaultRandomToken;
    this.#secret = secret;
    this.#ttlMs = options.ttlMs;
  }

  create(value: T): string {
    const token = this.#randomToken();
    this.#values.set(this.#key(token), {
      expiresAt: this.#clock() + this.#ttlMs,
      value,
    });
    return token;
  }

  get(token: string): T | undefined {
    const key = this.#key(token);
    const stored = this.#values.get(key);
    if (!stored) return undefined;
    if (this.#clock() >= stored.expiresAt) {
      this.#values.delete(key);
      return undefined;
    }
    return stored.value;
  }

  replace(token: string, value: T): boolean {
    const key = this.#key(token);
    const stored = this.#values.get(key);
    if (!stored || this.#clock() >= stored.expiresAt) {
      this.#values.delete(key);
      return false;
    }
    this.#values.set(key, { ...stored, value });
    return true;
  }

  take(token: string): T | undefined {
    const value = this.get(token);
    this.delete(token);
    return value;
  }

  delete(token: string): void {
    this.#values.delete(this.#key(token));
  }

  #key(token: string): string {
    return createHmac("sha256", this.#secret)
      .update(this.#purpose)
      .update("\0")
      .update(token)
      .digest("base64url");
  }
}
