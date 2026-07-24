import { describe, expect, it } from "vitest";

import { authorizeReceipt } from "../src/policy.js";
import {
  EXPECTED_VCT,
  EXPECTED_VTJSC_ID,
  positiveSession,
} from "./fixtures/positive-receipt.js";

const expected = {
  sessionId: "vs-1",
  vct: EXPECTED_VCT,
  vtjscId: EXPECTED_VTJSC_ID,
};

function authorizationError(receipt: unknown): string {
  try {
    authorizeReceipt(receipt, expected);
    return "authorization_succeeded";
  } catch (error) {
    return error instanceof Error ? error.message : "non_error_thrown";
  }
}

describe("authorizeReceipt", () => {
  it("authorizes the exact real receipt shape", () => {
    expect(authorizeReceipt(positiveSession, expected)).toEqual({
      subjectId: "user-1",
      organization: "ACME",
      role: "employee",
      issuerDid: "did:web:issuer.example",
      verifierDid: "did:web:verifier.example",
    });
  });

  it("accepts the receipt contract's nullable issuer iss", () => {
    const receipt = structuredClone(positiveSession);
    Object.assign(receipt.receipt.issuer, { iss: null });

    expect(authorizeReceipt(receipt, expected).issuerDid).toBe(
      "did:web:issuer.example",
    );
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
          ...positiveSession,
          receipt: {
            ...positiveSession.receipt,
            verifier: { ...positiveSession.receipt.verifier, verdict },
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
          ...positiveSession,
          receipt: {
            ...positiveSession.receipt,
            issuer: { ...positiveSession.receipt.issuer, verdict: "PARTIAL" },
          },
        },
        expected,
      ),
    ).toThrow("issuer_not_authorized");
  });

  it.each([
    ["sessionId", "vs-other", "session_mismatch"],
    ["vct", "https://demo.example/other-vct", "vct_mismatch"],
    ["vtjscId", "https://demo.example/other-schema", "schema_mismatch"],
  ] as const)("denies a mismatched %s", (field, value, errorCode) => {
    const receipt = structuredClone(positiveSession);

    if (field === "sessionId") receipt.receipt.exchange.sessionId = value;
    if (field === "vct") receipt.receipt.credential.vct = value;
    if (field === "vtjscId") receipt.receipt.registry.vtjscId = value;

    expect(() => authorizeReceipt(receipt, expected)).toThrow(errorCode);
  });

  it.each([
    ["organization", "OTHER", "organization_not_allowed"],
    ["role", "admin", "role_not_allowed"],
  ] as const)("denies a non-allowlisted %s", (claim, value, errorCode) => {
    const receipt = structuredClone(positiveSession);
    receipt.receipt.credential.disclosedClaims[claim] = value;

    expect(() => authorizeReceipt(receipt, expected)).toThrow(errorCode);
  });

  it.each([
    ["verifier", "did", "did:web:other.example"],
    ["verifier", "vtjscId", "https://demo.example/other-schema"],
    ["verifier", "trustStatus", "PARTIAL"],
    ["verifier", "authorized", false],
    ["issuer", "did", "did:web:other.example"],
    ["issuer", "vtjscId", "https://demo.example/other-schema"],
    ["issuer", "trustStatus", "PARTIAL"],
    ["issuer", "authorized", false],
  ] as const)("denies inconsistent %s evidence %s", (party, field, value) => {
    const receipt = structuredClone(positiveSession);
    Object.assign(receipt.receipt[party].evidence, { [field]: value });

    expect(authorizationError(receipt)).toBe(`${party}_not_authorized`);
  });

  it.each([
    ["network", "other-network"],
    ["trustRegistry", 185],
    ["schema", 250],
  ] as const)("denies unexpected registry %s metadata", (field, value) => {
    const receipt = structuredClone(positiveSession);
    Object.assign(receipt.receipt.registry, { [field]: value });

    expect(authorizationError(receipt)).toBe("invalid_receipt");
  });

  it("rejects unknown nested fields without exposing parser or body details", () => {
    const receipt = structuredClone(positiveSession);
    Object.assign(receipt.receipt.verifier.evidence, {
      unexpected: "sensitive-body-detail",
    });

    expect(authorizationError(receipt)).toBe("invalid_receipt");
    expect(authorizationError(receipt)).not.toContain("unexpected");
    expect(authorizationError(receipt)).not.toContain("sensitive-body-detail");
  });
});
