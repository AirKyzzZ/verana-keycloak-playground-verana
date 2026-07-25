import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import type { ResolverFaultMode } from "../apps/local-resolver/src/server.js";
import {
  parseKeycloakStatusArguments,
  sanitizeKeycloakStatus,
} from "./keycloak-status.js";
import {
  type KeycloakUserStatus,
  readKeycloakUserStatus,
} from "./keycloak-verification.js";

const CONTROL_URL = "http://127.0.0.1:3099/_local-controlled/resolver-fault";
const VERIFIER_REQUEST_URL =
  "http://127.0.0.1:3201/oid4vc-demo/verifier/requests";
const HOLDER_RESOLVE_URL =
  "http://127.0.0.1:3111/oid4vc-demo/wallet/resolve-request";
const REQUEST_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 64 * 1_024;
const FAULT_MODES = [
  "unavailable",
  "malformed-json",
  "oversized-body",
] as const satisfies readonly ResolverFaultMode[];

interface ResolverFaultStatus {
  armed: boolean;
  mode?: ResolverFaultMode;
}

export interface LocalAdversaryDependencies {
  armFault?: (mode: ResolverFaultMode, token: string) => Promise<void>;
  loadControlToken?: () => Promise<string>;
  readFaultStatus?: (token: string) => Promise<ResolverFaultStatus>;
  readKeycloakStatus?: (expectedCount: 0 | 1) => Promise<KeycloakUserStatus>;
  resetFault?: (token: string) => Promise<void>;
  runRogueProbe?: () => Promise<void>;
  runTrustedProbe?: (mode: ResolverFaultMode) => Promise<void>;
  write?: (line: string) => void;
}

export async function runLocalAdversaries(
  arguments_: readonly string[],
  dependencies: LocalAdversaryDependencies = {},
): Promise<void> {
  const requested = parseKeycloakStatusArguments(arguments_);
  const readStatus =
    dependencies.readKeycloakStatus ??
    (async (expectedCount: 0 | 1) =>
      await readKeycloakUserStatus({ expectedCount }));
  const initial = sanitizeKeycloakStatus(
    requested,
    await readStatus(requested.expectedCount),
  );
  const expected = {
    ...(initial.accountRef ? { expectedAccountRef: initial.accountRef } : {}),
    expectedCount: initial.count,
    ...(initial.subjectRef ? { expectedSubjectRef: initial.subjectRef } : {}),
  } as const;
  const loadControlToken =
    dependencies.loadControlToken ?? loadResolverControlToken;
  const armFault = dependencies.armFault ?? armResolverFault;
  const resetFault = dependencies.resetFault ?? resetResolverFault;
  const readFaultStatus =
    dependencies.readFaultStatus ?? readResolverFaultStatus;
  const runTrustedProbe =
    dependencies.runTrustedProbe ?? runTrustedResolverProbe;
  const runRogueProbe = dependencies.runRogueProbe ?? runRogueResolverProbe;
  const write = dependencies.write ?? console.log;
  const token = await loadControlToken();

  for (const mode of FAULT_MODES) {
    let failure: Error | undefined;
    try {
      await armFault(mode, token);
      await runTrustedProbe(mode);
      const faultStatus = await readFaultStatus(token);
      if (faultStatus.armed) {
        failure = new Error("LOCAL_CONTROLLED resolver fault did not reset");
      }
    } catch {
      failure = new Error("LOCAL_CONTROLLED adversarial verification failed");
    } finally {
      try {
        await resetFault(token);
      } catch {
        failure = new Error("LOCAL_CONTROLLED adversarial verification failed");
      }
    }
    if (failure) throw failure;

    sanitizeKeycloakStatus(expected, await readStatus(expected.expectedCount));
    write(`PASS RESOLVER ${mode} DENIED`);
  }

  try {
    await runRogueProbe();
  } catch {
    throw new Error("LOCAL_CONTROLLED adversarial verification failed");
  }
  sanitizeKeycloakStatus(expected, await readStatus(expected.expectedCount));
  write("PASS ROGUE DENIED");
  write("PASS LOCAL_CONTROLLED ADVERSARIAL");
}

async function loadResolverControlToken(): Promise<string> {
  let contents: string;
  try {
    contents = await readFile(".data/.env", "utf8");
  } catch {
    throw new Error(
      "LOCAL_CONTROLLED resolver control configuration is invalid",
    );
  }
  const values = contents
    .split("\n")
    .filter((line) => line.startsWith("LOCAL_RESOLVER_CONTROL_TOKEN="));
  if (values.length !== 1) {
    throw new Error(
      "LOCAL_CONTROLLED resolver control configuration is invalid",
    );
  }
  const token = values[0]?.slice("LOCAL_RESOLVER_CONTROL_TOKEN=".length);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    throw new Error(
      "LOCAL_CONTROLLED resolver control configuration is invalid",
    );
  }
  return token;
}

async function armResolverFault(
  mode: ResolverFaultMode,
  token: string,
): Promise<void> {
  const response = await controlRequest(
    `${CONTROL_URL}/${mode}`,
    "POST",
    token,
  );
  if (
    response.status !== 201 ||
    !isRecord(response.body) ||
    response.body.armed !== true ||
    response.body.mode !== mode
  ) {
    throw new Error("LOCAL_CONTROLLED resolver control request failed");
  }
}

async function resetResolverFault(token: string): Promise<void> {
  const response = await controlRequest(CONTROL_URL, "DELETE", token);
  if (
    response.status !== 200 ||
    !isRecord(response.body) ||
    response.body.armed !== false
  ) {
    throw new Error("LOCAL_CONTROLLED resolver control request failed");
  }
}

export async function readResolverFaultStatus(
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<ResolverFaultStatus> {
  const response = await controlRequest(CONTROL_URL, "GET", token, fetchImpl);
  if (
    response.status !== 200 ||
    !isRecord(response.body) ||
    typeof response.body.armed !== "boolean"
  ) {
    throw new Error("LOCAL_CONTROLLED resolver control request failed");
  }
  if (!response.body.armed) return { armed: false };
  const mode = response.body.mode;
  if (
    mode !== "malformed-json" &&
    mode !== "oversized-body" &&
    mode !== "unavailable"
  ) {
    throw new Error("LOCAL_CONTROLLED resolver control request failed");
  }
  return { armed: true, mode };
}

async function controlRequest(
  url: string,
  method: "DELETE" | "GET" | "POST",
  token: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ body: unknown; status: number }> {
  const response = await fetchImpl(url, {
    cache: "no-store",
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
    },
    method,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const body = await readJson(response, 4_096);
  return { body, status: response.status };
}

async function runTrustedResolverProbe(
  _mode: ResolverFaultMode,
): Promise<void> {
  const request = await createPresentationRequest("trusted");
  await assertDeniedResolution(request.authorizationRequest);
}

async function runRogueResolverProbe(): Promise<void> {
  const request = await createPresentationRequest("rogue");
  await assertDeniedResolution(request.authorizationRequest, "UNTRUSTED");
}

async function createPresentationRequest(
  tenant: "rogue" | "trusted",
): Promise<{ authorizationRequest: string }> {
  const response = await fetch(VERIFIER_REQUEST_URL, {
    ...jsonRequest({ tenant }),
    cache: "no-store",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error("LOCAL_CONTROLLED verifier request failed");
  }
  const body = await readJson(response, MAX_RESPONSE_BYTES);
  if (
    !isRecord(body) ||
    typeof body.authorizationRequest !== "string" ||
    body.authorizationRequest.length < 1 ||
    body.authorizationRequest.length > 10_000 ||
    typeof body.sessionId !== "string" ||
    body.sessionId.length < 1 ||
    body.sessionId.length > 200
  ) {
    throw new Error("LOCAL_CONTROLLED verifier response is invalid");
  }
  return { authorizationRequest: body.authorizationRequest };
}

async function assertDeniedResolution(
  authorizationRequest: string,
  exactVerdict?: "UNTRUSTED",
): Promise<void> {
  const response = await fetch(HOLDER_RESOLVE_URL, {
    ...jsonRequest({ authorizationRequest }),
    cache: "no-store",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    await response.body?.cancel();
    if (exactVerdict) {
      throw new Error("LOCAL_CONTROLLED holder denial is invalid");
    }
    return;
  }
  const body = await readJson(response, MAX_RESPONSE_BYTES);
  if (!isRecord(body) || typeof body.verdict !== "string") {
    throw new Error("LOCAL_CONTROLLED holder denial is invalid");
  }
  const allowedVerdicts = exactVerdict
    ? [exactVerdict]
    : [
        "PARTIAL",
        "RESOLVER_UNAVAILABLE",
        "TRUSTED_NOT_AUTHORIZED",
        "UNTRUSTED",
      ];
  if (!allowedVerdicts.includes(body.verdict)) {
    throw new Error("LOCAL_CONTROLLED holder denial is invalid");
  }
}

async function readJson(
  response: Response,
  maximumBytes: number,
): Promise<unknown> {
  if (
    !response.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  ) {
    await response.body?.cancel();
    throw new Error("LOCAL_CONTROLLED response is invalid");
  }
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes)
  ) {
    await response.body?.cancel();
    throw new Error("LOCAL_CONTROLLED response is invalid");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("LOCAL_CONTROLLED response is invalid");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error("LOCAL_CONTROLLED response is invalid");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    ) as unknown;
  } catch {
    throw new Error("LOCAL_CONTROLLED response is invalid");
  }
}

function jsonRequest(body: unknown): RequestInit {
  return {
    body: JSON.stringify(body),
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    method: "POST",
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const passedArguments = process.argv.slice(2);
    const arguments_ = passedArguments.some((argument) =>
      argument.startsWith("--expect-count="),
    )
      ? passedArguments
      : ["--expect-count=0", ...passedArguments];
    await runLocalAdversaries(arguments_);
  } catch {
    console.error("FAIL LOCAL_CONTROLLED ADVERSARIAL");
    process.exitCode = 1;
  }
}
