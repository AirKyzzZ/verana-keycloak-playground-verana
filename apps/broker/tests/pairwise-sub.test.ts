import { describe, expect, it } from "vitest";

import { derivePairwiseSub } from "../src/pairwise-sub.js";

describe("derivePairwiseSub", () => {
  it("is stable for identical inputs", () => {
    const input = {
      secret: new Uint8Array(32).fill(7),
      issuerDid: "did:web:issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "client.example",
    };

    expect(derivePairwiseSub(input)).toBe(derivePairwiseSub(input));
  });

  it("changes by sector and returns a 43-character base64url value", () => {
    const input = {
      secret: new Uint8Array(32).fill(7),
      issuerDid: "did:web:issuer.example",
      subjectId: "user-1",
      sectorIdentifier: "client.example",
    };

    const subject = derivePairwiseSub(input);

    expect(subject).toHaveLength(43);
    expect(subject).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(
      derivePairwiseSub({ ...input, sectorIdentifier: "other.example" }),
    ).not.toBe(subject);
  });
});
