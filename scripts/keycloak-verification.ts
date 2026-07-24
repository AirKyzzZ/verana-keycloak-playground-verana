import { timingSafeEqual } from "node:crypto";

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
