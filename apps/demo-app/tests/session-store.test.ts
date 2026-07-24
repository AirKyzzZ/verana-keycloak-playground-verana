import { describe, expect, it } from "vitest";

import { OpaqueStore } from "../src/session-store.js";

describe("OpaqueStore bounds", () => {
  it("sweeps abandoned expired records before storing new state", () => {
    let now = 0;
    let sequence = 0;
    const store = new OpaqueStore<string>("s".repeat(32), "test", {
      clock: () => now,
      maxEntries: 10,
      randomToken: () => `token-${sequence++}`,
      ttlMs: 10,
    });

    const expired = store.create("expired");
    now = 11;
    const active = store.create("active");

    expect(store.size).toBe(1);
    expect(store.get(expired)).toBeUndefined();
    expect(store.get(active)).toBe("active");
  });

  it("evicts the oldest record when the local-demo bound is reached", () => {
    let sequence = 0;
    const store = new OpaqueStore<string>("s".repeat(32), "test", {
      maxEntries: 2,
      randomToken: () => `token-${sequence++}`,
      ttlMs: 10_000,
    });

    const oldest = store.create("oldest");
    const retained = store.create("retained");
    const newest = store.create("newest");

    expect(store.size).toBe(2);
    expect(store.get(oldest)).toBeUndefined();
    expect(store.get(retained)).toBe("retained");
    expect(store.get(newest)).toBe("newest");
  });
});
