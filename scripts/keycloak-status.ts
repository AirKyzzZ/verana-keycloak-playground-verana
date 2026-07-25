import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  type KeycloakUserStatus,
  readKeycloakUserStatus,
} from "./keycloak-verification.js";

const ACCOUNT_REFERENCE_DOMAIN = "verana-keycloak-playground:account-ref:v1";
const SUBJECT_REFERENCE_DOMAIN = "verana-keycloak-playground:subject-ref:v1";
const REFERENCE_PATTERN = /^[0-9a-f]{64}$/;

export interface KeycloakStatusArguments {
  expectedAccountRef?: string;
  expectedCount: 0 | 1;
  expectedSubjectRef?: string;
}

export interface SanitizedKeycloakStatus {
  accountRef?: string;
  count: 0 | 1;
  lines: string[];
  subjectRef?: string;
}

export interface KeycloakStatusDependencies {
  readStatus?: (expectedCount: 0 | 1) => Promise<KeycloakUserStatus>;
  write?: (line: string) => void;
}

export function parseKeycloakStatusArguments(
  arguments_: readonly string[],
): KeycloakStatusArguments {
  let expectedCount: 0 | 1 | undefined;
  let expectedAccountRef: string | undefined;
  let expectedSubjectRef: string | undefined;

  for (const argument of arguments_) {
    if (argument === "--expect-count=0" || argument === "--expect-count=1") {
      if (expectedCount !== undefined) return invalidArguments();
      expectedCount = argument.endsWith("=0") ? 0 : 1;
      continue;
    }
    if (argument.startsWith("--expect-account-ref=")) {
      if (expectedAccountRef !== undefined) return invalidArguments();
      const value = argument.slice("--expect-account-ref=".length);
      if (!REFERENCE_PATTERN.test(value)) return invalidArguments();
      expectedAccountRef = value;
      continue;
    }
    if (argument.startsWith("--expect-subject-ref=")) {
      if (expectedSubjectRef !== undefined) return invalidArguments();
      const value = argument.slice("--expect-subject-ref=".length);
      if (!REFERENCE_PATTERN.test(value)) return invalidArguments();
      expectedSubjectRef = value;
      continue;
    }
    return invalidArguments();
  }

  if (expectedCount === undefined) return invalidArguments();
  return {
    ...(expectedAccountRef ? { expectedAccountRef } : {}),
    expectedCount,
    ...(expectedSubjectRef ? { expectedSubjectRef } : {}),
  };
}

export function sanitizeKeycloakStatus(
  expected: KeycloakStatusArguments,
  status: KeycloakUserStatus,
): SanitizedKeycloakStatus {
  if (status.count !== expected.expectedCount) return mappingMismatch();
  if (status.count === 0) {
    if (expected.expectedAccountRef || expected.expectedSubjectRef) {
      return mappingMismatch();
    }
    return { count: 0, lines: ["KEYCLOAK USERS 0"] };
  }

  const { user } = status;
  if (
    !user.groups.includes("/organizations/acme") ||
    !user.roles.includes("employee") ||
    typeof user.veranaSubject !== "string" ||
    user.veranaSubject.length === 0
  ) {
    return mappingMismatch();
  }
  const accountRef = reference(ACCOUNT_REFERENCE_DOMAIN, user.id);
  const subjectRef = reference(SUBJECT_REFERENCE_DOMAIN, user.veranaSubject);
  if (
    (expected.expectedAccountRef &&
      expected.expectedAccountRef !== accountRef) ||
    (expected.expectedSubjectRef && expected.expectedSubjectRef !== subjectRef)
  ) {
    return mappingMismatch();
  }

  return {
    accountRef,
    count: 1,
    lines: [
      "KEYCLOAK USERS 1",
      `KEYCLOAK ACCOUNT_REF ${accountRef}`,
      `KEYCLOAK SUBJECT_REF ${subjectRef}`,
      "PASS KEYCLOAK GROUP ACME",
      "PASS KEYCLOAK ROLE employee",
      "PASS KEYCLOAK SUBJECT mapped",
    ],
    subjectRef,
  };
}

export async function runKeycloakStatus(
  arguments_: readonly string[],
  dependencies: KeycloakStatusDependencies = {},
): Promise<SanitizedKeycloakStatus> {
  const expected = parseKeycloakStatusArguments(arguments_);
  const status = dependencies.readStatus
    ? await dependencies.readStatus(expected.expectedCount)
    : await readKeycloakUserStatus({ expectedCount: expected.expectedCount });
  const sanitized = sanitizeKeycloakStatus(expected, status);
  const write = dependencies.write ?? console.log;
  for (const line of sanitized.lines) write(line);
  return sanitized;
}

function reference(domain: string, value: string): string {
  return createHash("sha256")
    .update(domain)
    .update("\0")
    .update(value)
    .digest("hex");
}

function invalidArguments(): never {
  throw new Error("LOCAL_CONTROLLED keycloak status arguments are invalid");
}

function mappingMismatch(): never {
  throw new Error("LOCAL_CONTROLLED Keycloak mapping mismatch");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    await runKeycloakStatus(process.argv.slice(2));
  } catch {
    console.error("FAIL LOCAL_CONTROLLED KEYCLOAK STATUS");
    process.exitCode = 1;
  }
}
