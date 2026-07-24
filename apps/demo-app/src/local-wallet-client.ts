import { z } from "zod";

const REQUEST_TIMEOUT_MS = 3_000;
const MAX_EXCHANGE_VALUE_LENGTH = 10_000;

const verdictSchema = z.enum([
  "TRUSTED_AUTHORIZED",
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
]);

const issuedBadgeResponseSchema = z.strictObject({
  credentialOffer: z.string().trim().min(1).max(MAX_EXCHANGE_VALUE_LENGTH),
  credentialOfferObject: z.record(z.string(), z.unknown()),
  issuanceSessionId: z.string().trim().min(1).max(200),
});

const acceptedBadgeResponseSchema = z.strictObject({
  id: z.string().trim().min(1).max(200),
  vct: z.string().url(),
  claims: z.record(z.string(), z.unknown()),
});

const evidenceSchema = z.strictObject({
  did: z.string().nullable(),
  trustStatus: z.enum(["TRUSTED", "PARTIAL", "UNTRUSTED"]).nullable(),
  authorized: z.boolean().nullable(),
  vtjscId: z.string().nullable(),
  queries: z.array(z.string()),
  note: z.string().optional(),
});

const resolvedPresentationSchema = z.strictObject({
  gateId: z.string().trim().min(1).max(200),
  verdict: verdictSchema,
  evidence: evidenceSchema,
  request: z.strictObject({
    clientId: z.string().trim().min(1),
    clientIdPrefix: z.string().trim().min(1),
    verifierDid: z.string().nullable(),
    requestedVct: z.string().nullable(),
    requestedClaims: z.array(z.string()),
  }),
});

const presentationRequestSchema = z.strictObject({
  authorizationRequest: z.string().trim().min(1).max(MAX_EXCHANGE_VALUE_LENGTH),
  sessionId: z.string().trim().min(1).max(200),
});

const pendingPresentationSchema = z.strictObject({
  state: z
    .string()
    .trim()
    .min(1)
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
  status: z.number().int().min(100).max(599),
});

export type VeranaVerdict = z.infer<typeof verdictSchema>;
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
  acceptOffer(credentialOffer: string): Promise<AcceptedBadge>;
  createPresentationRequest(): Promise<PresentationRequest>;
  getPresentationStatus(sessionId: string): Promise<PresentationStatus>;
  issueBadge(subjectId: string): Promise<IssuedBadge>;
  resolveRequest(authorizationRequest: string): Promise<ResolvedPresentation>;
  share(resolved: ResolvedPresentation): Promise<SharedPresentation>;
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

  async acceptOffer(credentialOffer: string): Promise<AcceptedBadge> {
    const response = await this.#request(
      this.#holderBaseUrl,
      "/oid4vc-demo/wallet/accept-offer",
      {
        method: "POST",
        body: JSON.stringify({ credentialOffer }),
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
    if (resolved.verdict !== "TRUSTED_AUTHORIZED") {
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
      return schema.parse(await response.json());
    } catch {
      throw new Error("vs_agent_unavailable");
    }
  }
}

function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}
