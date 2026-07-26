import { z } from "zod";

import type { AuthorizedIdentity, ExpectedReceipt } from "./types.js";

const deniedVerdicts = [
  "PARTIAL",
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
] as const;

const verdictSchema = z.enum(["TRUSTED_AUTHORIZED", ...deniedVerdicts]);

const nullableNonEmptyStringSchema = z
  .string()
  .min(1)
  .refine((value) => value.trim().length > 0)
  .nullable();

const trustEvidenceSchema = z.strictObject({
  did: nullableNonEmptyStringSchema,
  trustStatus: z.enum(["TRUSTED", "PARTIAL", "UNTRUSTED"]).nullable(),
  authorized: z.boolean().nullable(),
  vtjscId: nullableNonEmptyStringSchema,
  queries: z.array(z.string()),
  note: z.string().optional(),
});

const receiptSchema = z.strictObject({
  state: z.literal("ResponseVerified"),
  receipt: z.strictObject({
    exchange: z.strictObject({
      protocol: z.literal("OID4VP 1.0"),
      vct: nullableNonEmptyStringSchema,
      sessionId: z.string().min(1),
      tenant: z.enum(["trusted", "rogue"]),
      verifiedAt: z.string().datetime(),
    }),
    verifier: z.strictObject({
      did: nullableNonEmptyStringSchema,
      verdict: verdictSchema,
      evidence: trustEvidenceSchema,
    }),
    issuer: z.strictObject({
      did: nullableNonEmptyStringSchema,
      iss: nullableNonEmptyStringSchema,
      verdict: verdictSchema,
      evidence: trustEvidenceSchema,
    }),
    credential: z.strictObject({
      vct: nullableNonEmptyStringSchema,
      disclosedClaims: z.strictObject({
        subject_id: z.string().min(1).max(200),
        organization: z.unknown().optional(),
        role: z.unknown().optional(),
      }),
    }),
    registry: z.strictObject({
      network: z.string().min(1),
      trustRegistry: z.number().int().nonnegative(),
      schema: z.number().int().nonnegative(),
      vtjscId: z.string().min(1),
    }),
  }),
});

// zod strictObject rejects unknown keys, but a literal "__proto__" own key
// (as produced by JSON.parse) is silently tolerated; reject it here so such a
// receipt is denied like any other unknown key rather than slipping through.
function carriesProtoKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(carriesProtoKey);
  if (value !== null && typeof value === "object") {
    if (Object.hasOwn(value, "__proto__")) return true;
    return Object.values(value).some(carriesProtoKey);
  }
  return false;
}

export function authorizeReceipt(
  receipt: unknown,
  expected: ExpectedReceipt,
): AuthorizedIdentity {
  if (carriesProtoKey(receipt)) throw new Error("invalid_receipt");

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

  // The registry tuple is configured, not assumed: a receipt from a different
  // network, ecosystem, or credential schema must never open a session.
  if (
    verifiedReceipt.registry.network !== expected.network ||
    verifiedReceipt.registry.trustRegistry !== expected.ecosystemId ||
    verifiedReceipt.registry.schema !== expected.credentialSchemaId
  ) {
    throw new Error("registry_mismatch");
  }

  if (verifiedReceipt.exchange.tenant !== "trusted") {
    throw new Error("tenant_not_allowed");
  }

  if (verifiedReceipt.verifier.verdict !== "TRUSTED_AUTHORIZED") {
    throw new Error("verifier_not_authorized");
  }

  if (
    !verifiedReceipt.verifier.did ||
    verifiedReceipt.verifier.evidence.did !== verifiedReceipt.verifier.did ||
    verifiedReceipt.verifier.evidence.vtjscId !== expected.vtjscId ||
    verifiedReceipt.verifier.evidence.trustStatus !== "TRUSTED" ||
    verifiedReceipt.verifier.evidence.authorized !== true
  ) {
    throw new Error("verifier_not_authorized");
  }

  if (verifiedReceipt.issuer.verdict !== "TRUSTED_AUTHORIZED") {
    throw new Error("issuer_not_authorized");
  }

  if (
    !verifiedReceipt.issuer.did ||
    verifiedReceipt.issuer.evidence.did !== verifiedReceipt.issuer.did ||
    verifiedReceipt.issuer.evidence.vtjscId !== expected.vtjscId ||
    verifiedReceipt.issuer.evidence.trustStatus !== "TRUSTED" ||
    verifiedReceipt.issuer.evidence.authorized !== true
  ) {
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
