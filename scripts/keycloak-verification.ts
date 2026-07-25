import { timingSafeEqual } from "node:crypto";

const DEFAULT_KEYCLOAK_BASE_URL = "http://127.0.0.1:8080";
const DEFAULT_KEYCLOAK_REALM = "verana-playground";
const DEFAULT_ADMIN_USERNAME = "admin";
const DEFAULT_ADMIN_PASSWORD = "local-development-only";
const KEYCLOAK_REQUEST_TIMEOUT_MS = 2_000;
const MAX_KEYCLOAK_RESPONSE_BYTES = 64 * 1_024;
const MAX_KEYCLOAK_USERS = 100;

export interface LocalSecrets {
  PLAYGROUND_APP_CLIENT_SECRET: string;
  BROKER_CLIENT_SECRET: string;
}

const secretsMatch = (actual: unknown, expected: string): boolean => {
  if (typeof actual !== "string") return false;

  const actualBytes = Buffer.from(actual);
  const expectedBytes = Buffer.from(expected);
  return (
    actualBytes.length === expectedBytes.length &&
    timingSafeEqual(actualBytes, expectedBytes)
  );
};

export function assertSecretMatch(
  actual: unknown,
  expected: string,
  message: string,
): asserts actual is string {
  if (!secretsMatch(actual, expected)) {
    throw new Error(message);
  }
}

export interface ClientSecretPost {
  body: string;
  authorizationHeader: string | undefined;
  expectedSecret: string;
}

export function assertClientSecretPost({
  body,
  authorizationHeader,
  expectedSecret,
}: ClientSecretPost): void {
  const parameters = new URLSearchParams(body);
  if (
    authorizationHeader !== undefined ||
    parameters.get("client_id") !== "keycloak-playground" ||
    parameters.get("grant_type") !== "authorization_code"
  ) {
    throw new Error("Identity-provider client authentication is invalid");
  }

  assertSecretMatch(
    parameters.get("client_secret"),
    expectedSecret,
    "Imported identity-provider secret mismatch",
  );
}

export function assertExactNames(
  items: ReadonlyArray<{ name?: string }>,
  expectedNames: readonly string[],
  message: string,
): void {
  const actualNames = items.map(({ name }) => name).sort();
  const sortedExpectedNames = [...expectedNames].sort();
  const matches =
    actualNames.length === sortedExpectedNames.length &&
    actualNames.every((name, index) => name === sortedExpectedNames[index]);

  if (!matches) {
    throw new Error(message);
  }
}

export function parseLocalSecrets(contents: string): LocalSecrets {
  const values = new Map<string, string>();

  for (const line of contents.split("\n")) {
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    values.set(line.slice(0, separator), line.slice(separator + 1));
  }

  const appSecret = values.get("PLAYGROUND_APP_CLIENT_SECRET");
  const brokerSecret = values.get("BROKER_CLIENT_SECRET");
  if (!appSecret || !brokerSecret) {
    throw new Error("Local Keycloak verification secrets are missing");
  }

  return {
    PLAYGROUND_APP_CLIENT_SECRET: appSecret,
    BROKER_CLIENT_SECRET: brokerSecret,
  };
}

export interface KeycloakUserSummary {
  id: string;
  username: string;
  veranaSubject: string | null;
  groups: string[];
  roles: string[];
}

export type KeycloakUserStatus =
  | { count: 0 }
  | { count: 1; user: KeycloakUserSummary };

export interface KeycloakVerificationOptions {
  adminPassword?: string;
  adminUsername?: string;
  baseUrl?: string;
  expectedCount?: 0 | 1;
  fetch?: typeof fetch;
  realm?: string;
}

export async function readKeycloakUsers(
  options: KeycloakVerificationOptions = {},
): Promise<KeycloakUserSummary[]> {
  const fetchImpl = options.fetch ?? fetch;
  const baseUrl = normalizeBaseUrl(
    options.baseUrl ?? DEFAULT_KEYCLOAK_BASE_URL,
  );
  const realm = options.realm ?? DEFAULT_KEYCLOAK_REALM;
  const accessToken = await readAdminAccessToken({
    adminPassword: options.adminPassword ?? DEFAULT_ADMIN_PASSWORD,
    adminUsername: options.adminUsername ?? DEFAULT_ADMIN_USERNAME,
    baseUrl,
    fetchImpl,
  });
  const users = parseUsers(
    await requestKeycloakJson(
      `${baseUrl}/admin/realms/${encodeURIComponent(realm)}/users?max=${MAX_KEYCLOAK_USERS}`,
      {
        headers: { authorization: `Bearer ${accessToken}` },
      },
      fetchImpl,
    ),
  );

  return await Promise.all(
    users.map(
      async (user) =>
        await readKeycloakUserDetails(
          user,
          baseUrl,
          realm,
          accessToken,
          fetchImpl,
        ),
    ),
  );
}

export async function readKeycloakUserStatus(
  options: KeycloakVerificationOptions = {},
): Promise<KeycloakUserStatus> {
  const fetchImpl = options.fetch ?? fetch;
  const baseUrl = normalizeBaseUrl(
    options.baseUrl ?? DEFAULT_KEYCLOAK_BASE_URL,
  );
  const realm = options.realm ?? DEFAULT_KEYCLOAK_REALM;
  const accessToken = await readAdminAccessToken({
    adminPassword: options.adminPassword ?? DEFAULT_ADMIN_PASSWORD,
    adminUsername: options.adminUsername ?? DEFAULT_ADMIN_USERNAME,
    baseUrl,
    fetchImpl,
  });
  const realmUsersUrl = `${baseUrl}/admin/realms/${encodeURIComponent(realm)}/users`;
  const count = parseControlledUserCount(
    await requestKeycloakJson(
      `${realmUsersUrl}/count`,
      { headers: { authorization: `Bearer ${accessToken}` } },
      fetchImpl,
    ),
  );
  if (options.expectedCount !== undefined && count !== options.expectedCount) {
    throw new Error("Keycloak user count mismatch");
  }
  if (count === 0) return { count: 0 };

  const users = parseUsers(
    await requestKeycloakJson(
      `${realmUsersUrl}?first=0&max=1&briefRepresentation=true`,
      { headers: { authorization: `Bearer ${accessToken}` } },
      fetchImpl,
    ),
  );
  if (users.length !== 1) {
    throw new Error("Keycloak user response is invalid");
  }
  const user = users[0];
  if (!user) throw new Error("Keycloak user response is invalid");
  return {
    count: 1,
    user: await readKeycloakUserDetails(
      user,
      baseUrl,
      realm,
      accessToken,
      fetchImpl,
    ),
  };
}

export async function assertKeycloakUserCount(
  expectedCount: number,
  options: KeycloakVerificationOptions = {},
): Promise<KeycloakUserSummary[]> {
  if (!Number.isInteger(expectedCount) || expectedCount < 0) {
    throw new Error("Expected Keycloak user count is invalid");
  }
  const users = await readKeycloakUsers(options);
  if (users.length !== expectedCount) {
    throw new Error("Keycloak user count mismatch");
  }
  return users;
}

interface AdminTokenInput {
  adminPassword: string;
  adminUsername: string;
  baseUrl: string;
  fetchImpl: typeof fetch;
}

async function readAdminAccessToken({
  adminPassword,
  adminUsername,
  baseUrl,
  fetchImpl,
}: AdminTokenInput): Promise<string> {
  const token = await requestKeycloakJson(
    `${baseUrl}/realms/master/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: "admin-cli",
        username: adminUsername,
        password: adminPassword,
      }).toString(),
    },
    fetchImpl,
  );
  if (
    !isRecord(token) ||
    typeof token.access_token !== "string" ||
    token.access_token.length < 1 ||
    token.access_token.length > 16_384
  ) {
    throw new Error("Keycloak admin token response is invalid");
  }
  return token.access_token;
}

async function readKeycloakUserDetails(
  user: {
    id: string;
    username: string;
    veranaSubject: string | null;
  },
  baseUrl: string,
  realm: string,
  accessToken: string,
  fetchImpl: typeof fetch,
): Promise<KeycloakUserSummary> {
  const encodedId = encodeURIComponent(user.id);
  const userBaseUrl = `${baseUrl}/admin/realms/${encodeURIComponent(realm)}/users/${encodedId}`;
  const [groups, roles] = await Promise.all([
    requestKeycloakJson(
      `${userBaseUrl}/groups`,
      { headers: { authorization: `Bearer ${accessToken}` } },
      fetchImpl,
    ),
    requestKeycloakJson(
      `${userBaseUrl}/role-mappings/realm/composite`,
      { headers: { authorization: `Bearer ${accessToken}` } },
      fetchImpl,
    ),
  ]);
  return {
    id: user.id,
    username: user.username,
    veranaSubject: user.veranaSubject,
    groups: parseNamedValues(groups, "path"),
    roles: parseNamedValues(roles, "name"),
  };
}

async function requestKeycloakJson(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetchImpl(url, {
      ...init,
      cache: "no-store",
      headers: {
        accept: "application/json",
        ...init.headers,
      },
      signal: AbortSignal.timeout(KEYCLOAK_REQUEST_TIMEOUT_MS),
    });
  } catch {
    throw new Error("Keycloak request failed");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error("Keycloak request failed");
  }
  if (
    !response.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  ) {
    await response.body?.cancel();
    throw new Error("Keycloak response is invalid");
  }
  const bytes = await readBoundedResponse(response);
  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    ) as unknown;
  } catch {
    throw new Error("Keycloak response is invalid");
  }
}

async function readBoundedResponse(response: Response): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) ||
      Number(declaredLength) > MAX_KEYCLOAK_RESPONSE_BYTES)
  ) {
    await response.body?.cancel();
    throw new Error("Keycloak response is invalid");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Keycloak response is invalid");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_KEYCLOAK_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Keycloak response is invalid");
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

function parseUsers(value: unknown): Array<{
  id: string;
  username: string;
  veranaSubject: string | null;
}> {
  if (!Array.isArray(value) || value.length > MAX_KEYCLOAK_USERS) {
    throw new Error("Keycloak user response is invalid");
  }
  return value.map((entry) => {
    if (
      !isRecord(entry) ||
      typeof entry.id !== "string" ||
      !entry.id ||
      entry.id.length > 200 ||
      typeof entry.username !== "string" ||
      !entry.username ||
      entry.username.length > 200
    ) {
      throw new Error("Keycloak user response is invalid");
    }
    const attributes = entry.attributes;
    let veranaSubject: string | null = null;
    if (attributes !== undefined) {
      if (!isRecord(attributes)) {
        throw new Error("Keycloak user response is invalid");
      }
      const values = attributes.verana_subject;
      if (values !== undefined) {
        if (
          !Array.isArray(values) ||
          values.length !== 1 ||
          typeof values[0] !== "string" ||
          !values[0] ||
          values[0].length > 200
        ) {
          throw new Error("Keycloak user response is invalid");
        }
        veranaSubject = values[0];
      }
    }
    return { id: entry.id, username: entry.username, veranaSubject };
  });
}

function parseControlledUserCount(value: unknown): 0 | 1 {
  if (value === 0 || value === 1) return value;
  throw new Error("Keycloak user count is outside the controlled bound");
}

function parseNamedValues(value: unknown, field: "name" | "path"): string[] {
  if (!Array.isArray(value) || value.length > 100) {
    throw new Error("Keycloak user response is invalid");
  }
  const values = value.map((entry) => {
    if (
      !isRecord(entry) ||
      typeof entry[field] !== "string" ||
      !entry[field] ||
      entry[field].length > 500
    ) {
      throw new Error("Keycloak user response is invalid");
    }
    return entry[field];
  });
  return values.sort();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Keycloak base URL is invalid");
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/+$/, "");
}
