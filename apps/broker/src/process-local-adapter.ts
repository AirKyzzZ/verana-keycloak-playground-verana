import type { Adapter, AdapterFactory, AdapterPayload } from "oidc-provider";

interface StoredPayload {
  expiresAt: number;
  payload: AdapterPayload;
}

const grantableModels = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
  "PreAuthorizedCode",
]);

export function createProcessLocalAdapterFactory(): AdapterFactory {
  const storage = new Map<string, StoredPayload>();
  const grantIndex = new Map<string, Set<string>>();
  const sessionUidIndex = new Map<string, string>();
  const userCodeIndex = new Map<string, string>();

  const read = (key: string): AdapterPayload | undefined => {
    const stored = storage.get(key);
    if (!stored) return undefined;
    if (Date.now() >= stored.expiresAt) {
      storage.delete(key);
      return undefined;
    }
    return stored.payload;
  };

  return (model: string): Adapter => {
    const keyFor = (id: string) => `${model}:${id}`;

    return {
      async upsert(id, payload, expiresIn) {
        const key = keyFor(id);
        storage.set(key, {
          expiresAt: Date.now() + expiresIn * 1_000,
          payload,
        });

        if (model === "Session" && payload.uid) {
          sessionUidIndex.set(payload.uid, id);
        }

        if (grantableModels.has(model) && typeof payload.grantId === "string") {
          const keys = grantIndex.get(payload.grantId) ?? new Set<string>();
          keys.add(key);
          grantIndex.set(payload.grantId, keys);
        }

        if (typeof payload.userCode === "string") {
          userCodeIndex.set(payload.userCode, id);
        }
      },

      async find(id) {
        return read(keyFor(id));
      },

      async findByUid(uid) {
        const id = sessionUidIndex.get(uid);
        return id ? read(keyFor(id)) : undefined;
      },

      async findByUserCode(userCode) {
        const id = userCodeIndex.get(userCode);
        return id ? read(keyFor(id)) : undefined;
      },

      async consume(id) {
        const key = keyFor(id);
        const stored = storage.get(key);
        if (!stored || Date.now() >= stored.expiresAt) {
          storage.delete(key);
          return;
        }
        stored.payload.consumed = Math.floor(Date.now() / 1_000);
      },

      async destroy(id) {
        storage.delete(keyFor(id));
      },

      async revokeByGrantId(grantId) {
        const keys = grantIndex.get(grantId);
        if (!keys) return;
        for (const key of keys) storage.delete(key);
        grantIndex.delete(grantId);
      },
    };
  };
}
