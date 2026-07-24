import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { derivePairwiseSub } from "../apps/broker/src/pairwise-sub.js";
import { authorizeReceipt } from "../apps/broker/src/policy.js";

const MAX_RESPONSE_BYTES = 64 * 1_024;
const REQUEST_TIMEOUT_MS = 5_000;
const COMPONENT_ATTEMPTS = 10;
const COMPONENT_RETRY_MS = 500;
const PRESENTATION_ATTEMPTS = 20;
const PRESENTATION_RETRY_MS = 500;
const SUBJECT_ID = "call-demo-user";
const DEFAULT_RESOLVER_URL = "https://resolver.testnet.verana.network/v1/trust";
const DEFAULT_ISSUER_DID =
  "did:webvh:QmPjKbgpLykjtHGTUfVRNoHra94mjitQsFniXYCTgmNYzG:unfold-org.77.42.86.24.sslip.io";
const DEFAULT_VERIFIER_DID =
  "did:webvh:QmZ9BT7AsWf62ubssns11KfiuauuoVk2v3zL8HYbGSFVTU:unfold-verifier.77.42.86.24.sslip.io";
const DEFAULT_VCT =
  "https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation";
const DEFAULT_VTJSC_ID =
  "https://unfold-org.77.42.86.24.sslip.io/vt/schemas-unfold-attestation-jsc.json";
const MAX_IDENTIFIER_LENGTH = 200;
const MAX_URL_LENGTH = 2_048;
const MAX_EXCHANGE_LENGTH = 10_000;
const MAX_COLLECTION_ITEMS = 32;
const MAX_OBJECT_KEYS = 64;
const DENIED_VERDICTS = [
  "PARTIAL",
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
] as const;

type TrustStatus = "TRUSTED" | "PARTIAL" | "UNTRUSTED";
type Verdict = "TRUSTED_AUTHORIZED" | (typeof DENIED_VERDICTS)[number];

interface StrictSchema<T> {
  parse(value: unknown): T;
}

interface TrustResponse {
  did: string;
  trustStatus: TrustStatus;
  production: boolean;
}

interface AuthorizationResponse {
  authorized: boolean;
  did: string;
  vtjscId: string;
}

interface Resolution {
  gateId: string;
  verdict: Verdict;
}

interface PresentationStatus {
  state: string;
  receipt?: unknown;
}

const trustResponseSchema = schema(parseTrustResponse);
const authorizationResponseSchema = schema(parseAuthorizationResponse);
const capabilitySchema = schema(parseCapability);
const discoverySchema = schema(parseDiscovery);
const offerSchema = schema(parseOffer);
const acceptedBadgeSchema = schema(parseAcceptedBadge);
const resolutionSchema = schema(parseResolution);
const sharedSchema = schema(parseShared);
const presentationRequestSchema = schema(parsePresentationRequest);
const presentationStatusSchema = schema(parsePresentationStatus);

type FailureCode =
  | "BLOCKED_COMPONENT"
  | "BLOCKED_SUBJECT_CONTRACT"
  | "BLOCKED_TOPOLOGY"
  | "BLOCKED_TRUST_PREFLIGHT"
  | "FAIL_SMOKE";

class FlowFailure extends Error {
  constructor(readonly code: FailureCode) {
    super(code);
  }
}

export interface LocalFlowConfig {
  brokerIssuer: string;
  demoAppBaseUrl: string;
  expectedIssuerDid: string;
  expectedVerifierDid: string;
  expectedVct: string;
  expectedVtjscId: string;
  holderBaseUrl: string;
  issuerBaseUrl: string;
  keycloakIssuer: string;
  pairwiseSubSecret: Uint8Array;
  resolverUrl: string;
  sectorIdentifier: string;
  verifierBaseUrl: string;
}

interface LocalFlowDependencies {
  fetch?: typeof fetch;
  sleep?: (milliseconds: number) => Promise<void>;
  write?: (line: string) => void;
}

interface PresentationIdentity {
  issuerDid: string;
  pairwiseSubject: string;
  subjectId: string;
  verifierDid: string;
}

export async function runLocalFlow(
  config: LocalFlowConfig,
  dependencies: LocalFlowDependencies = {},
): Promise<0 | 1> {
  const fetchImpl = dependencies.fetch ?? fetch;
  const sleep = dependencies.sleep ?? defaultSleep;
  const write = dependencies.write ?? console.log;

  try {
    verifyTopology(config);

    write("STAGE TRUST_PREFLIGHT");
    await verifyTrustPreflight(config, fetchImpl);
    write("VERDICT ISSUER_Q2 TRUSTED_AUTHORIZED");
    write("VERDICT VERIFIER_Q3 TRUSTED_AUTHORIZED");

    write("STAGE SUBJECT_CONTRACT");
    await verifySubjectContract(config, fetchImpl, sleep);

    write("STAGE COMPONENT_READINESS");
    await verifyComponentReadiness(config, fetchImpl, sleep);

    write("STAGE CREDENTIAL");
    await createAndAcceptBadge(config, fetchImpl);

    write("STAGE PRESENTATION_1");
    const first = await runTrustedPresentation(config, fetchImpl, sleep);
    write("VERDICT PRESENTATION_1_ISSUER TRUSTED_AUTHORIZED");
    write("VERDICT PRESENTATION_1_VERIFIER TRUSTED_AUTHORIZED");

    write("STAGE PRESENTATION_2");
    const second = await runTrustedPresentation(config, fetchImpl, sleep);
    write("VERDICT PRESENTATION_2_ISSUER TRUSTED_AUTHORIZED");
    write("VERDICT PRESENTATION_2_VERIFIER TRUSTED_AUTHORIZED");

    if (
      first.subjectId !== second.subjectId ||
      first.issuerDid !== second.issuerDid ||
      first.verifierDid !== second.verifierDid ||
      first.pairwiseSubject !== second.pairwiseSubject
    ) {
      throw new FlowFailure("FAIL_SMOKE");
    }
    write("VERDICT SUBJECT STABLE");

    write("STAGE ROGUE_PRESENTATION");
    await assertRoguePresentationDenied(config, fetchImpl);
    write("VERDICT ROGUE DENIED");
    write("PASS");
    return 0;
  } catch (error) {
    write(`FAIL ${safeFailureCode(error)}`);
    return 1;
  }
}

function verifyTopology(config: LocalFlowConfig): void {
  try {
    const issuerUrl = canonicalBaseUrl(config.issuerBaseUrl);
    const holderUrl = canonicalBaseUrl(config.holderBaseUrl);
    const verifierUrl = canonicalBaseUrl(config.verifierBaseUrl);
    if (
      config.expectedIssuerDid.trim() === config.expectedVerifierDid.trim() ||
      verifierUrl === issuerUrl ||
      verifierUrl === holderUrl
    ) {
      throw new Error("topology_alias");
    }
  } catch {
    throw new FlowFailure("BLOCKED_TOPOLOGY");
  }
}

export function loadLocalFlowConfig(
  environment: NodeJS.ProcessEnv = process.env,
): LocalFlowConfig {
  const localSecrets = parseLocalSecrets(
    readFileSync(".data/.env", { encoding: "utf8" }),
  );
  return {
    brokerIssuer: environment.BROKER_ISSUER ?? "http://localhost:3001",
    demoAppBaseUrl:
      environment.DEMO_APP_BASE_URL ??
      demoOrigin(environment.DEMO_APP_REDIRECT_URI),
    expectedIssuerDid: environment.EXPECTED_ISSUER_DID ?? DEFAULT_ISSUER_DID,
    expectedVerifierDid:
      environment.EXPECTED_VERIFIER_DID ?? DEFAULT_VERIFIER_DID,
    expectedVct: environment.EXPECTED_VCT ?? DEFAULT_VCT,
    expectedVtjscId: environment.EXPECTED_VTJSC_ID ?? DEFAULT_VTJSC_ID,
    holderBaseUrl:
      environment.VS_AGENT_HOLDER_BASE_URL ?? "http://localhost:3101",
    issuerBaseUrl:
      environment.VS_AGENT_ISSUER_BASE_URL ?? "http://localhost:3101",
    keycloakIssuer:
      environment.KEYCLOAK_ISSUER ??
      "http://localhost:8080/realms/verana-playground",
    pairwiseSubSecret: new TextEncoder().encode(
      requireSecret(localSecrets, "PAIRWISE_SUB_SECRET"),
    ),
    resolverUrl: environment.VERANA_RESOLVER_URL ?? DEFAULT_RESOLVER_URL,
    sectorIdentifier: environment.SECTOR_IDENTIFIER ?? "verana-playground",
    verifierBaseUrl:
      environment.VS_AGENT_VERIFIER_BASE_URL ?? "http://localhost:3201",
  };
}

async function verifyTrustPreflight(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
): Promise<void> {
  try {
    const issuerQ1 = await requestJson(
      resolverUrl(config.resolverUrl, "resolve", {
        did: config.expectedIssuerDid,
      }),
      {},
      fetchImpl,
      trustResponseSchema,
    );
    requireExactTrust(issuerQ1, config.expectedIssuerDid);

    const issuerQ2 = await requestJson(
      resolverUrl(config.resolverUrl, "issuer-authorization", {
        did: config.expectedIssuerDid,
        vtjscId: config.expectedVtjscId,
      }),
      {},
      fetchImpl,
      authorizationResponseSchema,
    );
    requireExactAuthorization(
      issuerQ2,
      config.expectedIssuerDid,
      config.expectedVtjscId,
    );

    const verifierQ1 = await requestJson(
      resolverUrl(config.resolverUrl, "resolve", {
        did: config.expectedVerifierDid,
      }),
      {},
      fetchImpl,
      trustResponseSchema,
    );
    requireExactTrust(verifierQ1, config.expectedVerifierDid);

    const verifierQ3 = await requestJson(
      resolverUrl(config.resolverUrl, "verifier-authorization", {
        did: config.expectedVerifierDid,
        vtjscId: config.expectedVtjscId,
      }),
      {},
      fetchImpl,
      authorizationResponseSchema,
    );
    requireExactAuthorization(
      verifierQ3,
      config.expectedVerifierDid,
      config.expectedVtjscId,
    );
  } catch {
    throw new FlowFailure("BLOCKED_TRUST_PREFLIGHT");
  }
}

async function verifySubjectContract(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<void> {
  try {
    for (const baseUrl of [
      config.issuerBaseUrl,
      config.holderBaseUrl,
      config.verifierBaseUrl,
    ]) {
      await retry(
        () =>
          requestJson(
            `${normalizeBaseUrl(baseUrl)}/oid4vc-demo/capabilities`,
            {},
            fetchImpl,
            capabilitySchema,
          ),
        COMPONENT_ATTEMPTS,
        COMPONENT_RETRY_MS,
        sleep,
      );
    }
  } catch {
    throw new FlowFailure("BLOCKED_SUBJECT_CONTRACT");
  }
}

async function verifyComponentReadiness(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<void> {
  try {
    const broker = await retry(
      () =>
        requestJson(
          `${normalizeBaseUrl(config.brokerIssuer)}/.well-known/openid-configuration`,
          {},
          fetchImpl,
          discoverySchema,
        ),
      COMPONENT_ATTEMPTS,
      COMPONENT_RETRY_MS,
      sleep,
    );
    if (broker.issuer !== config.brokerIssuer) {
      throw new Error("broker_issuer_mismatch");
    }

    const keycloak = await retry(
      () =>
        requestJson(
          `${normalizeBaseUrl(config.keycloakIssuer)}/.well-known/openid-configuration`,
          {},
          fetchImpl,
          discoverySchema,
        ),
      COMPONENT_ATTEMPTS,
      COMPONENT_RETRY_MS,
      sleep,
    );
    if (keycloak.issuer !== config.keycloakIssuer) {
      throw new Error("keycloak_issuer_mismatch");
    }

    await retry(
      () =>
        requestOk(`${normalizeBaseUrl(config.demoAppBaseUrl)}/`, {}, fetchImpl),
      COMPONENT_ATTEMPTS,
      COMPONENT_RETRY_MS,
      sleep,
    );
  } catch {
    throw new FlowFailure("BLOCKED_COMPONENT");
  }
}

async function createAndAcceptBadge(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
): Promise<void> {
  try {
    const offer = await requestJson(
      `${normalizeBaseUrl(config.issuerBaseUrl)}/oid4vc-demo/offers`,
      jsonRequest({
        subjectId: SUBJECT_ID,
        organization: "ACME",
        role: "employee",
      }),
      fetchImpl,
      offerSchema,
    );
    const credentialOffer = offer.credentialOffer;

    const accepted = await requestJson(
      `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/accept-offer`,
      jsonRequest({ credentialOffer }),
      fetchImpl,
      acceptedBadgeSchema,
    );
    if (
      accepted.vct !== config.expectedVct ||
      accepted.claims.subject_id !== SUBJECT_ID
    ) {
      throw new Error("credential_mismatch");
    }
  } catch {
    throw new FlowFailure("FAIL_SMOKE");
  }
}

async function runTrustedPresentation(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<PresentationIdentity> {
  try {
    const request = await createPresentationRequest(
      config,
      fetchImpl,
      "trusted",
    );
    const resolution = await requestJson(
      `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/resolve-request`,
      jsonRequest({ authorizationRequest: request.authorizationRequest }),
      fetchImpl,
      resolutionSchema,
    );
    if (resolution.verdict !== "TRUSTED_AUTHORIZED") {
      throw new Error("holder_denied");
    }
    const gateId = resolution.gateId;

    await requestJson(
      `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/share`,
      jsonRequest({ gateId }),
      fetchImpl,
      sharedSchema,
    );

    const verified = await pollVerifiedSession(
      config,
      request.sessionId,
      fetchImpl,
      sleep,
    );
    const identity = authorizeReceipt(verified, {
      sessionId: request.sessionId,
      vct: config.expectedVct,
      vtjscId: config.expectedVtjscId,
    });
    if (
      identity.issuerDid !== config.expectedIssuerDid ||
      identity.verifierDid !== config.expectedVerifierDid ||
      identity.subjectId !== SUBJECT_ID
    ) {
      throw new Error("receipt_identity_mismatch");
    }
    return {
      issuerDid: identity.issuerDid,
      pairwiseSubject: derivePairwiseSub({
        issuerDid: identity.issuerDid,
        sectorIdentifier: config.sectorIdentifier,
        secret: config.pairwiseSubSecret,
        subjectId: identity.subjectId,
      }),
      subjectId: identity.subjectId,
      verifierDid: identity.verifierDid,
    };
  } catch {
    throw new FlowFailure("FAIL_SMOKE");
  }
}

async function assertRoguePresentationDenied(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
): Promise<void> {
  try {
    const request = await createPresentationRequest(config, fetchImpl, "rogue");
    const resolution = await requestJson(
      `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/resolve-request`,
      jsonRequest({ authorizationRequest: request.authorizationRequest }),
      fetchImpl,
      resolutionSchema,
    );
    if (resolution.verdict === "TRUSTED_AUTHORIZED") {
      throw new Error("rogue_not_denied");
    }
  } catch {
    throw new FlowFailure("FAIL_SMOKE");
  }
}

async function createPresentationRequest(
  config: LocalFlowConfig,
  fetchImpl: typeof fetch,
  tenant: "trusted" | "rogue",
): Promise<{ authorizationRequest: string; sessionId: string }> {
  return await requestJson(
    `${normalizeBaseUrl(config.verifierBaseUrl)}/oid4vc-demo/verifier/requests`,
    jsonRequest({ tenant }),
    fetchImpl,
    presentationRequestSchema,
  );
}

async function pollVerifiedSession(
  config: LocalFlowConfig,
  sessionId: string,
  fetchImpl: typeof fetch,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<unknown> {
  for (let attempt = 0; attempt < PRESENTATION_ATTEMPTS; attempt += 1) {
    const status = await requestJson(
      `${normalizeBaseUrl(config.verifierBaseUrl)}/oid4vc-demo/verifier/sessions/${encodeURIComponent(sessionId)}`,
      {},
      fetchImpl,
      presentationStatusSchema,
    );
    if (status.state === "ResponseVerified") {
      return status;
    }
    if (attempt + 1 < PRESENTATION_ATTEMPTS) {
      await sleep(PRESENTATION_RETRY_MS);
    }
  }
  throw new Error("presentation_timeout");
}

async function requestJson<T>(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
  responseSchema: StrictSchema<T>,
): Promise<T> {
  const response = await request(url, init, fetchImpl);
  const contentType = response.headers.get("content-type")?.toLowerCase();
  if (!contentType?.startsWith("application/json")) {
    await response.body?.cancel();
    throw new Error("response_content_type_invalid");
  }
  const bytes = await readBoundedBody(response);
  return responseSchema.parse(
    JSON.parse(new TextDecoder().decode(bytes)) as unknown,
  );
}

async function requestOk(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
): Promise<void> {
  const response = await request(url, init, fetchImpl);
  await readBoundedBody(response);
}

async function request(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
): Promise<Response> {
  const response = await fetchImpl(url, {
    ...init,
    cache: "no-store",
    headers: {
      accept: "application/json",
      ...init.headers,
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error("request_failed");
  }
  return response;
}

async function readBoundedBody(response: Response): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) ||
      Number(declaredLength) > MAX_RESPONSE_BYTES)
  ) {
    await response.body?.cancel();
    throw new Error("response_too_large");
  }
  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("response_body_missing");
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
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
  return body;
}

async function retry<T>(
  operation: () => Promise<T>,
  attempts: number,
  delayMs: number,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) {
        await sleep(delayMs);
      }
    }
  }
  throw lastError;
}

function schema<T>(parser: (value: unknown) => T): StrictSchema<T> {
  return { parse: parser };
}

function parseTrustResponse(value: unknown): TrustResponse {
  const response = strictRecord(value, [
    "did",
    "evaluatedAt",
    "evaluatedAtBlock",
    "expiresAt",
    "production",
    "trustStatus",
  ]);
  validateOptionalTimestamp(response.evaluatedAt);
  validateOptionalTimestamp(response.expiresAt);
  validateOptionalBlockMetadata(response.evaluatedAtBlock);
  return {
    did: boundedString(response.did, MAX_URL_LENGTH),
    trustStatus: trustStatus(response.trustStatus),
    production: boolean(response.production),
  };
}

function parseAuthorizationResponse(value: unknown): AuthorizationResponse {
  const response = strictRecord(value, [
    "authorized",
    "did",
    "evaluatedAt",
    "evaluatedAtBlock",
    "fees",
    "permission",
    "permissionChain",
    "vtjscId",
  ]);
  validateOptionalTimestamp(response.evaluatedAt);
  validateOptionalBlockMetadata(response.evaluatedAtBlock);
  for (const metadata of [
    response.fees,
    response.permission,
    response.permissionChain,
  ]) {
    if (metadata !== undefined) requireEmptyRecord(metadata);
  }
  return {
    authorized: boolean(response.authorized),
    did: boundedString(response.did, MAX_URL_LENGTH),
    vtjscId: boundedUrl(response.vtjscId),
  };
}

function parseCapability(value: unknown): {
  contractVersion: 1;
  offerClaims: ["subjectId", "organization", "role"];
  disclosedClaims: ["subject_id", "organization", "role"];
} {
  const response = strictRecord(value, [
    "contractVersion",
    "disclosedClaims",
    "offerClaims",
  ]);
  if (response.contractVersion !== 1) throw new Error("schema_invalid");
  exactStringArray(response.offerClaims, ["subjectId", "organization", "role"]);
  exactStringArray(response.disclosedClaims, [
    "subject_id",
    "organization",
    "role",
  ]);
  return {
    contractVersion: 1,
    offerClaims: ["subjectId", "organization", "role"],
    disclosedClaims: ["subject_id", "organization", "role"],
  };
}

function parseDiscovery(value: unknown): { issuer: string } {
  const response = record(value);
  return { issuer: boundedUrl(response.issuer) };
}

function parseOffer(value: unknown): {
  credentialOffer: string;
  issuanceSessionId: string;
} {
  const response = strictRecord(value, [
    "credentialOffer",
    "credentialOfferObject",
    "issuanceSessionId",
  ]);
  boundedRecord(response.credentialOfferObject);
  return {
    credentialOffer: boundedString(
      response.credentialOffer,
      MAX_EXCHANGE_LENGTH,
    ),
    issuanceSessionId: boundedString(
      response.issuanceSessionId,
      MAX_IDENTIFIER_LENGTH,
    ),
  };
}

function parseAcceptedBadge(value: unknown): {
  id: string;
  vct: string;
  claims: {
    subject_id: string;
    organization: "ACME";
    role: "employee";
  };
} {
  const response = strictRecord(value, ["claims", "id", "vct"]);
  const claims = record(response.claims);
  boundedRecord(claims);
  if (claims.organization !== "ACME" || claims.role !== "employee") {
    throw new Error("schema_invalid");
  }
  return {
    id: boundedString(response.id, MAX_IDENTIFIER_LENGTH),
    vct: boundedUrl(response.vct),
    claims: {
      subject_id: boundedString(claims.subject_id, MAX_IDENTIFIER_LENGTH),
      organization: "ACME",
      role: "employee",
    },
  };
}

function parseResolution(value: unknown): Resolution {
  const response = strictRecord(value, [
    "evidence",
    "gateId",
    "request",
    "verdict",
  ]);
  parseEvidence(response.evidence);
  const request = strictRecord(response.request, [
    "clientId",
    "clientIdPrefix",
    "requestedClaims",
    "requestedVct",
    "verifierDid",
  ]);
  boundedString(request.clientId, MAX_URL_LENGTH);
  boundedString(request.clientIdPrefix, MAX_IDENTIFIER_LENGTH);
  nullableBoundedString(request.verifierDid, MAX_URL_LENGTH);
  nullableBoundedString(request.requestedVct, MAX_URL_LENGTH);
  boundedStringArray(
    request.requestedClaims,
    MAX_COLLECTION_ITEMS,
    MAX_IDENTIFIER_LENGTH,
  );
  return {
    gateId: boundedString(response.gateId, MAX_IDENTIFIER_LENGTH),
    verdict: verdict(response.verdict),
  };
}

function parseEvidence(value: unknown): void {
  const evidence = strictRecord(value, [
    "authorized",
    "did",
    "note",
    "queries",
    "trustStatus",
    "vtjscId",
  ]);
  nullableBoundedString(evidence.did, MAX_URL_LENGTH);
  nullableTrustStatus(evidence.trustStatus);
  nullableBoolean(evidence.authorized);
  nullableBoundedString(evidence.vtjscId, MAX_URL_LENGTH);
  boundedStringArray(evidence.queries, MAX_COLLECTION_ITEMS, MAX_URL_LENGTH);
  if (evidence.note !== undefined) boundedString(evidence.note, 500);
}

function parseShared(value: unknown): { shared: true; status: number } {
  const response = strictRecord(value, ["shared", "status"]);
  if (response.shared !== true) throw new Error("schema_invalid");
  const status = integer(response.status);
  if (status < 200 || status > 299) throw new Error("schema_invalid");
  return { shared: true, status };
}

function parsePresentationRequest(value: unknown): {
  authorizationRequest: string;
  sessionId: string;
} {
  const response = strictRecord(value, ["authorizationRequest", "sessionId"]);
  return {
    authorizationRequest: boundedString(
      response.authorizationRequest,
      MAX_EXCHANGE_LENGTH,
    ),
    sessionId: boundedString(response.sessionId, MAX_IDENTIFIER_LENGTH),
  };
}

function parsePresentationStatus(value: unknown): PresentationStatus {
  const response = record(value);
  const state = boundedString(response.state, MAX_IDENTIFIER_LENGTH);
  if (state === "ResponseVerified") {
    strictRecord(value, ["receipt", "state"]);
    record(response.receipt);
    return { state, receipt: response.receipt };
  }
  strictRecord(value, ["state"]);
  return { state };
}

function strictRecord(
  value: unknown,
  allowedKeys: readonly string[],
): Record<string, unknown> {
  const parsed = record(value);
  const allowed = new Set(allowedKeys);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) {
    throw new Error("schema_invalid");
  }
  return parsed;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("schema_invalid");
  }
  return value as Record<string, unknown>;
}

function boundedRecord(value: unknown): void {
  const parsed = record(value);
  if (
    Object.keys(parsed).length > MAX_OBJECT_KEYS ||
    Object.keys(parsed).some(
      (key) => !key || key.length > MAX_IDENTIFIER_LENGTH,
    )
  ) {
    throw new Error("schema_invalid");
  }
}

function boundedString(value: unknown, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new Error("schema_invalid");
  }
  return value;
}

function boundedUrl(value: unknown): string {
  const parsed = boundedString(value, MAX_URL_LENGTH);
  new URL(parsed);
  return parsed;
}

function nullableBoundedString(value: unknown, maximum: number): string | null {
  return value === null ? null : boundedString(value, maximum);
}

function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("schema_invalid");
  return value;
}

function nullableBoolean(value: unknown): boolean | null {
  return value === null ? null : boolean(value);
}

function integer(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error("schema_invalid");
  }
  return value;
}

function trustStatus(value: unknown): TrustStatus {
  if (value !== "TRUSTED" && value !== "PARTIAL" && value !== "UNTRUSTED") {
    throw new Error("schema_invalid");
  }
  return value;
}

function nullableTrustStatus(value: unknown): TrustStatus | null {
  return value === null ? null : trustStatus(value);
}

function verdict(value: unknown): Verdict {
  if (value === "TRUSTED_AUTHORIZED") return value;
  if (
    value === "PARTIAL" ||
    value === "TRUSTED_NOT_AUTHORIZED" ||
    value === "UNTRUSTED" ||
    value === "RESOLVER_UNAVAILABLE"
  ) {
    return value;
  }
  throw new Error("schema_invalid");
}

function exactStringArray(value: unknown, expected: readonly string[]): void {
  if (
    !Array.isArray(value) ||
    value.length !== expected.length ||
    value.some((item, index) => item !== expected[index])
  ) {
    throw new Error("schema_invalid");
  }
}

function boundedStringArray(
  value: unknown,
  maximumItems: number,
  maximumLength: number,
): void {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new Error("schema_invalid");
  }
  for (const item of value) boundedString(item, maximumLength);
}

function validateOptionalTimestamp(value: unknown): void {
  if (value === undefined) return;
  const timestamp = boundedString(value, 64);
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new Error("schema_invalid");
  }
}

function validateOptionalBlockMetadata(value: unknown): void {
  if (value === undefined) return;
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return;
  }
  requireEmptyRecord(value);
}

function requireEmptyRecord(value: unknown): void {
  if (Object.keys(record(value)).length !== 0) {
    throw new Error("schema_invalid");
  }
}

function requireExactTrust(response: TrustResponse, expectedDid: string): void {
  if (
    response.did !== expectedDid ||
    response.trustStatus !== "TRUSTED" ||
    response.production !== true
  ) {
    throw new Error("trust_mismatch");
  }
}

function requireExactAuthorization(
  response: AuthorizationResponse,
  expectedDid: string,
  expectedVtjscId: string,
): void {
  if (
    response.did !== expectedDid ||
    response.vtjscId !== expectedVtjscId ||
    response.authorized !== true
  ) {
    throw new Error("authorization_mismatch");
  }
}

function resolverUrl(
  baseUrl: string,
  route: string,
  parameters: Record<string, string>,
): string {
  const url = new URL(`${normalizeBaseUrl(baseUrl)}/${route}`);
  for (const [key, value] of Object.entries(parameters)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

function jsonRequest(body: unknown): RequestInit {
  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

function canonicalBaseUrl(value: string): string {
  const url = new URL(value);
  url.username = "";
  url.password = "";
  url.hash = "";
  url.search = "";
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/+$/, "");
}

function demoOrigin(redirectUri: string | undefined): string {
  return redirectUri ? new URL(redirectUri).origin : "http://localhost:3000";
}

function parseLocalSecrets(value: string): Map<string, string> {
  const secrets = new Map<string, string>();
  for (const line of value.split(/\r?\n/)) {
    const separator = line.indexOf("=");
    if (separator <= 0) continue;
    secrets.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return secrets;
}

function requireSecret(secrets: Map<string, string>, key: string): string {
  const value = secrets.get(key);
  if (!value || value.length < 32) {
    throw new FlowFailure("BLOCKED_COMPONENT");
  }
  return value;
}

function safeFailureCode(error: unknown): FailureCode {
  return error instanceof FlowFailure ? error.code : "BLOCKED_COMPONENT";
}

function defaultSleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function main(): Promise<void> {
  try {
    process.exitCode = await runLocalFlow(loadLocalFlowConfig());
  } catch (error) {
    console.log(`FAIL ${safeFailureCode(error)}`);
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
