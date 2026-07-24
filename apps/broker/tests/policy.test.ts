import { describe, expect, it } from "vitest";

import { authorizeReceipt } from "../src/policy.js";

const expected = {
  sessionId: "vs-1",
  vct: "https://demo/vct",
  vtjscId: "https://demo/schema",
};

const positive = {
  state: "ResponseVerified",
  receipt: {
    exchange: {
      protocol: "OID4VP 1.0",
      vct: "https://demo/vct",
      sessionId: "vs-1",
      tenant: "trusted",
      verifiedAt: "2026-07-24T10:00:00.000Z",
    },
    verifier: {
      did: "did:web:verifier.example",
      verdict: "TRUSTED_AUTHORIZED",
    },
    issuer: { did: "did:web:issuer.example", verdict: "TRUSTED_AUTHORIZED" },
    credential: {
      vct: "https://demo/vct",
      disclosedClaims: {
        subject_id: "user-1",
        organization: "ACME",
        role: "employee",
      },
    },
    registry: { vtjscId: "https://demo/schema" },
  },
};

describe("authorizeReceipt", () => {
  it("authorizes an exactly matching trusted receipt", () => {
    expect(authorizeReceipt(positive, expected)).toEqual({
      subjectId: "user-1",
      organization: "ACME",
      role: "employee",
      issuerDid: "did:web:issuer.example",
      verifierDid: "did:web:verifier.example",
    });
  });

  it.each([
    "PARTIAL",
    "TRUSTED_NOT_AUTHORIZED",
    "UNTRUSTED",
    "RESOLVER_UNAVAILABLE",
  ])("denies a non-positive verifier verdict: %s", (verdict) => {
    expect(() =>
      authorizeReceipt(
        {
          ...positive,
          receipt: {
            ...positive.receipt,
            verifier: { ...positive.receipt.verifier, verdict },
          },
        },
        expected,
      ),
    ).toThrow("verifier_not_authorized");
  });

  it("denies a non-positive issuer verdict", () => {
    expect(() =>
      authorizeReceipt(
        {
          ...positive,
          receipt: {
            ...positive.receipt,
            issuer: { ...positive.receipt.issuer, verdict: "PARTIAL" },
          },
        },
        expected,
      ),
    ).toThrow("issuer_not_authorized");
  });

  it.each([
    ["sessionId", "vs-other", "session_mismatch"],
    ["vct", "https://demo/other-vct", "vct_mismatch"],
    ["vtjscId", "https://demo/other-schema", "schema_mismatch"],
  ] as const)("denies a mismatched %s", (field, value, errorCode) => {
    const receipt = structuredClone(positive);

    if (field === "sessionId") receipt.receipt.exchange.sessionId = value;
    if (field === "vct") receipt.receipt.credential.vct = value;
    if (field === "vtjscId") receipt.receipt.registry.vtjscId = value;

    expect(() => authorizeReceipt(receipt, expected)).toThrow(errorCode);
  });

  it.each([
    ["organization", "OTHER", "organization_not_allowed"],
    ["role", "admin", "role_not_allowed"],
  ] as const)("denies a non-allowlisted %s", (claim, value, errorCode) => {
    const receipt = structuredClone(positive);
    receipt.receipt.credential.disclosedClaims[claim] = value;

    expect(() => authorizeReceipt(receipt, expected)).toThrow(errorCode);
  });

  it("denies malformed receipts without exposing parser details", () => {
    expect(() =>
      authorizeReceipt({ state: "ResponseVerified" }, expected),
    ).toThrow("invalid_receipt");
  });
});
