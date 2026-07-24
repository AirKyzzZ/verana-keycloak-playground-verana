import { z } from "zod";

import type { AuthorizedIdentity, ExpectedReceipt } from "./types.js";

const deniedVerdicts = [
  "PARTIAL",
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
] as const;

const verdictSchema = z.enum(["TRUSTED_AUTHORIZED", ...deniedVerdicts]);

const receiptSchema = z.strictObject({
  state: z.literal("ResponseVerified"),
  receipt: z.strictObject({
    exchange: z.strictObject({
      protocol: z.literal("OID4VP 1.0"),
      vct: z.string().min(1),
      sessionId: z.string().min(1),
      tenant: z.string().min(1),
      verifiedAt: z.string().datetime(),
    }),
    verifier: z.strictObject({
      did: z.string().min(1),
      verdict: verdictSchema,
    }),
    issuer: z.strictObject({
      did: z.string().min(1),
      verdict: verdictSchema,
    }),
    credential: z.strictObject({
      vct: z.string().min(1),
      disclosedClaims: z.strictObject({
        subject_id: z.string().min(1).max(200),
        organization: z.string(),
        role: z.string(),
      }),
    }),
    registry: z.strictObject({
      vtjscId: z.string().min(1),
    }),
  }),
});

export function authorizeReceipt(
  receipt: unknown,
  expected: ExpectedReceipt,
): AuthorizedIdentity {
  const parsed = receiptSchema.safeParse(receipt);

  if (!parsed.success) throw new Error("invalid_receipt");

  const verifiedReceipt = parsed.data.receipt;

  if (verifiedReceipt.exchange.sessionId !== expected.sessionId) {
    throw new Error("session_mismatch");
  }

  if (
    verifiedReceipt.exchange.vct !== expected.vct ||
    verifiedReceipt.credential.vct !== expected.vct
  ) {
    throw new Error("vct_mismatch");
  }

  if (verifiedReceipt.registry.vtjscId !== expected.vtjscId) {
    throw new Error("schema_mismatch");
  }

  if (verifiedReceipt.verifier.verdict !== "TRUSTED_AUTHORIZED") {
    throw new Error("verifier_not_authorized");
  }

  if (verifiedReceipt.issuer.verdict !== "TRUSTED_AUTHORIZED") {
    throw new Error("issuer_not_authorized");
  }

  if (verifiedReceipt.credential.disclosedClaims.organization !== "ACME") {
    throw new Error("organization_not_allowed");
  }

  if (verifiedReceipt.credential.disclosedClaims.role !== "employee") {
    throw new Error("role_not_allowed");
  }

  return {
    subjectId: verifiedReceipt.credential.disclosedClaims.subject_id,
    organization: "ACME",
    role: "employee",
    issuerDid: verifiedReceipt.issuer.did,
    verifierDid: verifiedReceipt.verifier.did,
  };
}
