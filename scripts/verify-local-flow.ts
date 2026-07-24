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
const EXPECTED_OFFER_CLAIMS = ["subjectId", "organization", "role"];
const EXPECTED_DISCLOSED_CLAIMS = ["subject_id", "organization", "role"];
const ALLOWED_DENIED_VERDICTS = new Set([
  "TRUSTED_NOT_AUTHORIZED",
  "UNTRUSTED",
  "RESOLVER_UNAVAILABLE",
]);

type FailureCode =
  | "BLOCKED_COMPONENT"
  | "BLOCKED_SUBJECT_CONTRACT"
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
    const issuerQ1 = object(
      await requestJson(
        resolverUrl(config.resolverUrl, "resolve", {
          did: config.expectedIssuerDid,
        }),
        {},
        fetchImpl,
      ),
    );
    requireExactTrust(issuerQ1, config.expectedIssuerDid);

    const issuerQ2 = object(
      await requestJson(
        resolverUrl(config.resolverUrl, "issuer-authorization", {
          did: config.expectedIssuerDid,
          vtjscId: config.expectedVtjscId,
        }),
        {},
        fetchImpl,
      ),
    );
    requireExactAuthorization(
      issuerQ2,
      config.expectedIssuerDid,
      config.expectedVtjscId,
    );

    const verifierQ1 = object(
      await requestJson(
        resolverUrl(config.resolverUrl, "resolve", {
          did: config.expectedVerifierDid,
        }),
        {},
        fetchImpl,
      ),
    );
    requireExactTrust(verifierQ1, config.expectedVerifierDid);

    const verifierQ3 = object(
      await requestJson(
        resolverUrl(config.resolverUrl, "verifier-authorization", {
          did: config.expectedVerifierDid,
          vtjscId: config.expectedVtjscId,
        }),
        {},
        fetchImpl,
      ),
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
      const value = await retry(
        () =>
          requestJson(
            `${normalizeBaseUrl(baseUrl)}/oid4vc-demo/capabilities`,
            {},
            fetchImpl,
          ),
        COMPONENT_ATTEMPTS,
        COMPONENT_RETRY_MS,
        sleep,
      );
      const capability = object(value);
      if (
        capability.contractVersion !== 1 ||
        !exactStringArray(capability.offerClaims, EXPECTED_OFFER_CLAIMS) ||
        !exactStringArray(capability.disclosedClaims, EXPECTED_DISCLOSED_CLAIMS)
      ) {
        throw new Error("capability_mismatch");
      }
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
    const broker = object(
      await retry(
        () =>
          requestJson(
            `${normalizeBaseUrl(config.brokerIssuer)}/.well-known/openid-configuration`,
            {},
            fetchImpl,
          ),
        COMPONENT_ATTEMPTS,
        COMPONENT_RETRY_MS,
        sleep,
      ),
    );
    if (broker.issuer !== config.brokerIssuer) {
      throw new Error("broker_issuer_mismatch");
    }

    const keycloak = object(
      await retry(
        () =>
          requestJson(
            `${normalizeBaseUrl(config.keycloakIssuer)}/.well-known/openid-configuration`,
            {},
            fetchImpl,
          ),
        COMPONENT_ATTEMPTS,
        COMPONENT_RETRY_MS,
        sleep,
      ),
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
    const offer = object(
      await requestJson(
        `${normalizeBaseUrl(config.issuerBaseUrl)}/oid4vc-demo/offers`,
        jsonRequest({
          subjectId: SUBJECT_ID,
          organization: "ACME",
          role: "employee",
        }),
        fetchImpl,
      ),
    );
    const credentialOffer = nonEmptyString(offer.credentialOffer);
    nonEmptyString(offer.issuanceSessionId);

    const accepted = object(
      await requestJson(
        `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/accept-offer`,
        jsonRequest({ credentialOffer }),
        fetchImpl,
      ),
    );
    const claims = object(accepted.claims);
    if (
      accepted.vct !== config.expectedVct ||
      claims.subject_id !== SUBJECT_ID ||
      claims.organization !== "ACME" ||
      claims.role !== "employee"
    ) {
      throw new Error("credential_mismatch");
    }
    nonEmptyString(accepted.id);
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
    const resolution = object(
      await requestJson(
        `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/resolve-request`,
        jsonRequest({ authorizationRequest: request.authorizationRequest }),
        fetchImpl,
      ),
    );
    if (resolution.verdict !== "TRUSTED_AUTHORIZED") {
      throw new Error("holder_denied");
    }
    const gateId = nonEmptyString(resolution.gateId);

    const shared = object(
      await requestJson(
        `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/share`,
        jsonRequest({ gateId }),
        fetchImpl,
      ),
    );
    if (
      shared.shared !== true ||
      typeof shared.status !== "number" ||
      shared.status < 200 ||
      shared.status > 299
    ) {
      throw new Error("share_failed");
    }

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
    const resolution = object(
      await requestJson(
        `${normalizeBaseUrl(config.holderBaseUrl)}/oid4vc-demo/wallet/resolve-request`,
        jsonRequest({ authorizationRequest: request.authorizationRequest }),
        fetchImpl,
      ),
    );
    if (
      typeof resolution.verdict !== "string" ||
      !ALLOWED_DENIED_VERDICTS.has(resolution.verdict)
    ) {
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
  const response = object(
    await requestJson(
      `${normalizeBaseUrl(config.verifierBaseUrl)}/oid4vc-demo/verifier/requests`,
      jsonRequest({ tenant }),
      fetchImpl,
    ),
  );
  return {
    authorizationRequest: nonEmptyString(response.authorizationRequest),
    sessionId: nonEmptyString(response.sessionId),
  };
}

async function pollVerifiedSession(
  config: LocalFlowConfig,
  sessionId: string,
  fetchImpl: typeof fetch,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<unknown> {
  for (let attempt = 0; attempt < PRESENTATION_ATTEMPTS; attempt += 1) {
    const status = object(
      await requestJson(
        `${normalizeBaseUrl(config.verifierBaseUrl)}/oid4vc-demo/verifier/sessions/${encodeURIComponent(sessionId)}`,
        {},
        fetchImpl,
      ),
    );
    if (status.state === "ResponseVerified") {
      return status;
    }
    if (typeof status.state !== "string" || !status.state.trim()) {
      throw new Error("session_state_invalid");
    }
    if (attempt + 1 < PRESENTATION_ATTEMPTS) {
      await sleep(PRESENTATION_RETRY_MS);
    }
  }
  throw new Error("presentation_timeout");
}

async function requestJson(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
): Promise<unknown> {
  const response = await request(url, init, fetchImpl);
  const contentType = response.headers.get("content-type")?.toLowerCase();
  if (!contentType?.startsWith("application/json")) {
    await response.body?.cancel();
    throw new Error("response_content_type_invalid");
  }
  const bytes = await readBoundedBody(response);
  return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
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

function requireExactTrust(
  response: Record<string, unknown>,
  expectedDid: string,
): void {
  if (
    response.did !== expectedDid ||
    response.trustStatus !== "TRUSTED" ||
    response.production !== true
  ) {
    throw new Error("trust_mismatch");
  }
}

function requireExactAuthorization(
  response: Record<string, unknown>,
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

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("object_expected");
  }
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown): string {
  if (typeof value !== "string" || !value.trim() || value.length > 10_000) {
    throw new Error("string_expected");
  }
  return value;
}

function exactStringArray(value: unknown, expected: string[]): boolean {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  );
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
