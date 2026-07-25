import { z } from "zod";

const REQUEST_TIMEOUT_MS = 3_000;
const MAX_EXCHANGE_VALUE_LENGTH = 10_000;
const MAX_IDENTIFIER_LENGTH = 200;
const MAX_URL_LENGTH = 2_048;
const MAX_COLLECTION_ITEMS = 32;
const MAX_OBJECT_KEYS = 64;

// Demo responses contain summaries, not credentials. 64 KiB leaves ample room
// for trust evidence while bounding compressed, chunked, and declared bodies.
const MAX_RESPONSE_BODY_BYTES = 64 * 1_024;

const verdictSchema = z.enum([
  "TRUSTED_AUTHORIZED",
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
]);

const issuedBadgeResponseSchema = z.strictObject({
  credentialOffer: z.string().trim().min(1).max(MAX_EXCHANGE_VALUE_LENGTH),
  credentialOfferObject: z
    .record(z.string().max(MAX_IDENTIFIER_LENGTH), z.unknown())
    .refine((value) => Object.keys(value).length <= MAX_OBJECT_KEYS),
  issuanceSessionId: z.string().trim().min(1).max(MAX_IDENTIFIER_LENGTH),
});

const acceptedBadgeResponseSchema = z.strictObject({
  id: z.string().trim().min(1).max(MAX_IDENTIFIER_LENGTH),
  vct: z.string().max(MAX_URL_LENGTH).url(),
  claims: z
    .record(z.string().max(MAX_IDENTIFIER_LENGTH), z.unknown())
    .refine((value) => Object.keys(value).length <= MAX_OBJECT_KEYS),
});

const evidenceSchema = z.strictObject({
  did: z.string().max(MAX_URL_LENGTH).nullable(),
  trustStatus: z.enum(["TRUSTED", "PARTIAL", "UNTRUSTED"]).nullable(),
  authorized: z.boolean().nullable(),
  vtjscId: z.string().max(MAX_URL_LENGTH).nullable(),
  queries: z.array(z.string().max(MAX_URL_LENGTH)).max(MAX_COLLECTION_ITEMS),
  note: z.string().max(500).optional(),
});

// A refused review carries an empty gate id: the agent mints a gate only for an
// exact TRUSTED_AUTHORIZED verdict. Enforcing both directions here means a
// response claiming a refusal can never smuggle in a usable gate.
const gateIdSchema = z.string().trim().max(MAX_IDENTIFIER_LENGTH);

function gateMatchesVerdict(value: {
  gateId: string;
  verdict: z.infer<typeof verdictSchema>;
}): boolean {
  return value.verdict === "TRUSTED_AUTHORIZED"
    ? value.gateId.length > 0
    : value.gateId.length === 0;
}

const GATE_INVARIANT_MESSAGE =
  "a gate id is present only for a TRUSTED_AUTHORIZED verdict";

const reviewedOfferSchema = z.strictObject({
  gateId: gateIdSchema,
  verdict: verdictSchema,
  issuerDid: z.string().max(MAX_URL_LENGTH).nullable(),
  credentialIssuer: z.string().max(MAX_URL_LENGTH),
  evidence: evidenceSchema,
}).refine(gateMatchesVerdict, { message: GATE_INVARIANT_MESSAGE });

const resolvedPresentationSchema = z.strictObject({
  gateId: gateIdSchema,
  verdict: verdictSchema,
  evidence: evidenceSchema,
  request: z.strictObject({
    clientId: z.string().trim().min(1).max(MAX_URL_LENGTH),
    clientIdPrefix: z.string().trim().min(1).max(MAX_IDENTIFIER_LENGTH),
    verifierDid: z.string().max(MAX_URL_LENGTH).nullable(),
    // Present but never authenticated: the DID a request merely claims, which
    // must never be treated as identity.
    unverifiedClaimedDid: z.string().max(MAX_URL_LENGTH).nullable(),
    requestedVct: z.string().max(MAX_URL_LENGTH).nullable(),
    requestedClaims: z
      .array(z.string().max(MAX_IDENTIFIER_LENGTH))
      .max(MAX_COLLECTION_ITEMS),
  }),
}).refine(gateMatchesVerdict, { message: GATE_INVARIANT_MESSAGE });

const presentationRequestSchema = z.strictObject({
  authorizationRequest: z.string().trim().min(1).max(MAX_EXCHANGE_VALUE_LENGTH),
  sessionId: z.string().trim().min(1).max(MAX_IDENTIFIER_LENGTH),
});

const pendingPresentationSchema = z.strictObject({
  state: z
    .string()
    .trim()
    .min(1)
    .max(MAX_IDENTIFIER_LENGTH)
    .refine((state) => state !== "ResponseVerified"),
});
const verifiedPresentationSchema = z.strictObject({
  state: z.literal("ResponseVerified"),
  receipt: z.unknown(),
});
const presentationStatusSchema = z.union([
  verifiedPresentationSchema,
  pendingPresentationSchema,
]);

const sharedPresentationSchema = z.strictObject({
  shared: z.literal(true),
  status: z.number().int().min(200).max(299),
});

export type VeranaVerdict = z.infer<typeof verdictSchema>;
export type ReviewedOffer = z.infer<typeof reviewedOfferSchema>;
export type ResolvedPresentation = z.infer<typeof resolvedPresentationSchema>;
export type PresentationRequest = z.infer<typeof presentationRequestSchema>;
export type PresentationStatus = z.infer<typeof presentationStatusSchema>;
export type SharedPresentation = z.infer<typeof sharedPresentationSchema>;

export interface IssuedBadge {
  credentialOffer: string;
  issuanceSessionId: string;
}

export interface AcceptedBadge {
  credentialId: string;
  subjectId: string;
  vct: string;
}

export interface LocalWalletClientConfig {
  holderBaseUrl: string;
  issuerBaseUrl: string;
  verifierBaseUrl: string;
}

export interface LocalWalletClientContract {
  reviewOffer(credentialOffer: string): Promise<ReviewedOffer>;
  acceptOffer(reviewed: ReviewedOffer): Promise<AcceptedBadge>;
  createPresentationRequest(): Promise<PresentationRequest>;
  getPresentationStatus(sessionId: string): Promise<PresentationStatus>;
  issueBadge(subjectId: string): Promise<IssuedBadge>;
  resolveRequest(authorizationRequest: string): Promise<ResolvedPresentation>;
  share(resolved: ResolvedPresentation): Promise<SharedPresentation>;
  testRogueDenial(): Promise<ResolvedPresentation>;
}

export class LocalWalletClient implements LocalWalletClientContract {
  readonly #holderBaseUrl: string;
  readonly #issuerBaseUrl: string;
  readonly #verifierBaseUrl: string;

  constructor(config: LocalWalletClientConfig) {
    this.#issuerBaseUrl = normalizeBaseUrl(config.issuerBaseUrl);
    this.#holderBaseUrl = normalizeBaseUrl(config.holderBaseUrl);
    this.#verifierBaseUrl = normalizeBaseUrl(config.verifierBaseUrl);
  }

  async issueBadge(subjectId: string): Promise<IssuedBadge> {
    const response = await this.#request(
      this.#issuerBaseUrl,
      "/oid4vc-demo/offers",
      {
        method: "POST",
        body: JSON.stringify({
          subjectId,
          organization: "ACME",
          role: "employee",
        }),
      },
      issuedBadgeResponseSchema,
    );
    return {
      credentialOffer: response.credentialOffer,
      issuanceSessionId: response.issuanceSessionId,
    };
  }

  async reviewOffer(credentialOffer: string): Promise<ReviewedOffer> {
    return await this.#request(
      this.#holderBaseUrl,
      "/oid4vc-demo/wallet/review-offer",
      {
        method: "POST",
        body: JSON.stringify({ credentialOffer }),
      },
      reviewedOfferSchema,
    );
  }

  // Acceptance is gated on the review verdict, so a refused issuer never reaches
  // the token request or credential storage.
  async acceptOffer(reviewed: ReviewedOffer): Promise<AcceptedBadge> {
    if (reviewed.verdict !== "TRUSTED_AUTHORIZED" || !reviewed.gateId) {
      throw new Error("issuer_not_authorized");
    }
    const response = await this.#request(
      this.#holderBaseUrl,
      "/oid4vc-demo/wallet/accept-offer",
      {
        method: "POST",
        body: JSON.stringify({ gateId: reviewed.gateId }),
      },
      acceptedBadgeResponseSchema,
    );
    const subjectId = response.claims.subject_id;
    if (
      typeof subjectId !== "string" ||
      !subjectId.trim() ||
      response.claims.organization !== "ACME" ||
      response.claims.role !== "employee"
    ) {
      throw new Error("vs_agent_unavailable");
    }
    return {
      credentialId: response.id,
      subjectId,
      vct: response.vct,
    };
  }

  async createPresentationRequest(): Promise<PresentationRequest> {
    return await this.#request(
      this.#verifierBaseUrl,
      "/oid4vc-demo/verifier/requests",
      {
        method: "POST",
        body: JSON.stringify({ tenant: "trusted" }),
      },
      presentationRequestSchema,
    );
  }

  async testRogueDenial(): Promise<ResolvedPresentation> {
    const request = await this.#request(
      this.#verifierBaseUrl,
      "/oid4vc-demo/verifier/requests",
      {
        method: "POST",
        body: JSON.stringify({ tenant: "rogue" }),
      },
      presentationRequestSchema,
    );
    return await this.#request(
      this.#holderBaseUrl,
      "/oid4vc-demo/wallet/resolve-request",
      {
        method: "POST",
        body: JSON.stringify({
          authorizationRequest: request.authorizationRequest,
        }),
      },
      resolvedPresentationSchema,
    );
  }

  async resolveRequest(
    authorizationRequest: string,
  ): Promise<ResolvedPresentation> {
    return await this.#request(
      this.#holderBaseUrl,
      "/oid4vc-demo/wallet/resolve-request",
      {
        method: "POST",
        body: JSON.stringify({ authorizationRequest }),
      },
      resolvedPresentationSchema,
    );
  }

  async getPresentationStatus(sessionId: string): Promise<PresentationStatus> {
    return await this.#request(
      this.#verifierBaseUrl,
      `/oid4vc-demo/verifier/sessions/${encodeURIComponent(sessionId)}`,
      { method: "GET" },
      presentationStatusSchema,
    );
  }

  async share(resolved: ResolvedPresentation): Promise<SharedPresentation> {
    if (resolved.verdict !== "TRUSTED_AUTHORIZED" || !resolved.gateId) {
      throw new Error("verifier_not_authorized");
    }
    return await this.#request(
      this.#holderBaseUrl,
      "/oid4vc-demo/wallet/share",
      {
        method: "POST",
        body: JSON.stringify({ gateId: resolved.gateId }),
      },
      sharedPresentationSchema,
    );
  }

  async #request<T>(
    baseUrl: string,
    path: string,
    init: RequestInit,
    schema: z.ZodType<T>,
  ): Promise<T> {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        ...init,
        cache: "no-store",
        headers: {
          accept: "application/json",
          ...(init.body ? { "content-type": "application/json" } : {}),
        },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error("request_failed");
      if (
        !response.headers
          .get("content-type")
          ?.toLowerCase()
          .startsWith("application/json")
      ) {
        throw new Error("response_content_type_invalid");
      }
      return schema.parse(await readBoundedJson(response));
    } catch {
      throw new Error("vs_agent_unavailable");
    }
  }
}

function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength)) {
      throw new Error("response_length_invalid");
    }
    if (Number(declaredLength) > MAX_RESPONSE_BODY_BYTES) {
      await response.body?.cancel();
      throw new Error("response_too_large");
    }
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error("response_body_missing");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BODY_BYTES) {
        await reader.cancel();
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  return JSON.parse(text);
}
