import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertClientSecretPost,
  assertExactNames,
  assertKeycloakUserCount,
  assertSecretMatch,
  parseLocalSecrets,
  readKeycloakUserStatus,
  readKeycloakUsers,
} from "../scripts/keycloak-verification.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const servers = new Set<ReturnType<typeof createServer>>();

afterEach(async () => {
  await Promise.all(
    [...servers].map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        }),
    ),
  );
  servers.clear();
});

describe("Keycloak verification helpers", () => {
  it("rejects extra configured names with a static error", () => {
    expect(() =>
      assertExactNames(
        [{ name: "expected" }, { name: "unexpected" }],
        ["expected"],
        "Mapper allowlist mismatch",
      ),
    ).toThrowError("Mapper allowlist mismatch");
  });

  it("rejects secret mismatches without including either value", () => {
    const actual = "actual-secret-value";
    const expected = "expected-secret-value";
    let failure: unknown;

    try {
      assertSecretMatch(actual, expected, "Imported secret mismatch");
    } catch (error) {
      failure = error;
    }

    expect(failure instanceof Error).toBe(true);
    expect(
      failure instanceof Error &&
        failure.message === "Imported secret mismatch",
    ).toBe(true);
    expect(failure instanceof Error && failure.message.includes(actual)).toBe(
      false,
    );
    expect(failure instanceof Error && failure.message.includes(expected)).toBe(
      false,
    );
  });

  it("accepts matching secrets", () => {
    expect(() =>
      assertSecretMatch(
        "matching-secret-value",
        "matching-secret-value",
        "Imported secret mismatch",
      ),
    ).not.toThrow();
  });

  it("accepts the exact broker client_secret_post request", () => {
    expect(() =>
      assertClientSecretPost({
        body: new URLSearchParams({
          client_id: "keycloak-playground",
          client_secret: "broker-secret-value",
          grant_type: "authorization_code",
        }).toString(),
        authorizationHeader: undefined,
        expectedSecret: "broker-secret-value",
      }),
    ).not.toThrow();
  });

  it("rejects a stale broker secret without including either value", () => {
    const actual = "stale-broker-secret";
    const expected = "generated-broker-secret";
    let failure: unknown;

    try {
      assertClientSecretPost({
        body: new URLSearchParams({
          client_id: "keycloak-playground",
          client_secret: actual,
          grant_type: "authorization_code",
        }).toString(),
        authorizationHeader: undefined,
        expectedSecret: expected,
      });
    } catch (error) {
      failure = error;
    }

    expect(
      failure instanceof Error &&
        failure.message === "Imported identity-provider secret mismatch",
    ).toBe(true);
    expect(failure instanceof Error && failure.message.includes(actual)).toBe(
      false,
    );
    expect(failure instanceof Error && failure.message.includes(expected)).toBe(
      false,
    );
  });

  it("parses only the generated secrets needed for live verification", () => {
    const secrets = parseLocalSecrets(
      [
        "PLAYGROUND_APP_CLIENT_SECRET=app-secret-value",
        "BROKER_CLIENT_SECRET=broker-secret-value",
        "OTHER_SECRET=ignored-secret-value",
        "",
      ].join("\n"),
    );

    expect(secrets.PLAYGROUND_APP_CLIENT_SECRET === "app-secret-value").toBe(
      true,
    );
    expect(secrets.BROKER_CLIENT_SECRET === "broker-secret-value").toBe(true);
    expect(Object.keys(secrets).sort()).toEqual([
      "BROKER_CLIENT_SECRET",
      "PLAYGROUND_APP_CLIENT_SECRET",
    ]);
  });

  it("keeps generated setup secrets and private JWKs out of matchers", async () => {
    const source = await readFile(join(root, "tests", "setup.test.ts"), "utf8");
    const unsafeMatcherPatterns = [
      /expect\(env\)/,
      /expect\(jwks(?:\.keys\[[^\]]+\])?\)/,
      /expect\(secrets\.[A-Z0-9_]+\)/,
    ];

    expect(unsafeMatcherPatterns.some((pattern) => pattern.test(source))).toBe(
      false,
    );
    expect(
      source.includes("finally") &&
        source.includes("rm(output, { recursive: true, force: true })"),
    ).toBe(true);
  });

  it("bounds all three identity-provider behavior probe fetches", async () => {
    const source = await readFile(
      join(root, "scripts", "verify-keycloak.ts"),
      "utf8",
    );

    expect(
      source.includes("const overallDeadline = AbortSignal.timeout("),
    ).toBe(true);
    expect(source.includes("AbortSignal.timeout(requestTimeoutMs)")).toBe(true);
    expect(
      source.match(/await fetchForIdentityProviderProbe\(/g)?.length ?? 0,
    ).toBe(3);
  });

  it("reads only bounded Keycloak user summaries", async () => {
    const keycloak = await startKeycloakFixture([
      {
        id: "user-1",
        username: "pairwise-user",
        attributes: {
          verana_subject: ["stable-pairwise-subject"],
          ignored_private_attribute: ["must-not-leak"],
        },
        credentials: [{ id: "credential-1", value: "must-not-leak" }],
      },
    ]);

    await expect(
      readKeycloakUsers({ baseUrl: keycloak.baseUrl }),
    ).resolves.toEqual([
      {
        id: "user-1",
        username: "pairwise-user",
        veranaSubject: "stable-pairwise-subject",
        groups: ["/organizations/acme"],
        roles: ["employee"],
      },
    ]);

    expect(keycloak.authorizationHeaders()).toEqual([
      "Bearer bounded-admin-token",
      "Bearer bounded-admin-token",
      "Bearer bounded-admin-token",
    ]);
  });

  it("asserts the exact Keycloak user count without returning admin material", async () => {
    const keycloak = await startKeycloakFixture([]);

    await expect(
      assertKeycloakUserCount(0, { baseUrl: keycloak.baseUrl }),
    ).resolves.toEqual([]);
    await expect(
      assertKeycloakUserCount(1, { baseUrl: keycloak.baseUrl }),
    ).rejects.toThrowError("Keycloak user count mismatch");
  });

  it("counts first and reads at most one account through read-only endpoints", async () => {
    const keycloak = await startKeycloakFixture([
      {
        id: "user-1",
        username: "pairwise-user",
        attributes: {
          verana_subject: ["stable-pairwise-subject"],
        },
      },
    ]);

    await expect(
      readKeycloakUserStatus({ baseUrl: keycloak.baseUrl }),
    ).resolves.toEqual({
      count: 1,
      user: {
        id: "user-1",
        username: "pairwise-user",
        veranaSubject: "stable-pairwise-subject",
        groups: ["/organizations/acme"],
        roles: ["employee"],
      },
    });

    expect(keycloak.requests().slice(0, 3)).toEqual([
      "POST /realms/master/protocol/openid-connect/token",
      "GET /admin/realms/verana-playground/users/count",
      "GET /admin/realms/verana-playground/users?first=0&max=1&briefRepresentation=true",
    ]);
    expect(keycloak.requests().slice(3).sort()).toEqual([
      "GET /admin/realms/verana-playground/users/user-1/groups",
      "GET /admin/realms/verana-playground/users/user-1/role-mappings/realm/composite",
    ]);
  });

  it("does not read account details when the exact count is zero or unsupported", async () => {
    const empty = await startKeycloakFixture([]);
    const mismatched = await startKeycloakFixture([
      {
        id: "user-1",
        username: "pairwise-user",
        attributes: {
          verana_subject: ["stable-pairwise-subject"],
        },
      },
    ]);
    const tooMany = await startKeycloakFixture([
      {
        id: "user-1",
        username: "first",
      },
      {
        id: "user-2",
        username: "second",
      },
    ]);

    await expect(
      readKeycloakUserStatus({ baseUrl: empty.baseUrl }),
    ).resolves.toEqual({ count: 0 });
    await expect(
      readKeycloakUserStatus({
        baseUrl: mismatched.baseUrl,
        expectedCount: 0,
      }),
    ).rejects.toThrow("Keycloak user count mismatch");
    await expect(
      readKeycloakUserStatus({ baseUrl: tooMany.baseUrl }),
    ).rejects.toThrow("Keycloak user count is outside the controlled bound");

    expect(empty.requests()).toEqual([
      "POST /realms/master/protocol/openid-connect/token",
      "GET /admin/realms/verana-playground/users/count",
    ]);
    expect(mismatched.requests()).toEqual([
      "POST /realms/master/protocol/openid-connect/token",
      "GET /admin/realms/verana-playground/users/count",
    ]);
    expect(tooMany.requests()).toEqual([
      "POST /realms/master/protocol/openid-connect/token",
      "GET /admin/realms/verana-playground/users/count",
    ]);
  });

  it("rejects malformed Keycloak user attributes without leaking token bodies", async () => {
    const keycloak = await startKeycloakFixture([
      {
        id: "user-1",
        username: "pairwise-user",
        attributes: {
          verana_subject: ["first", "second"],
        },
      },
    ]);
    let failure: unknown;

    try {
      await readKeycloakUsers({ baseUrl: keycloak.baseUrl });
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    expect(failure instanceof Error && failure.message).toBe(
      "Keycloak user response is invalid",
    );
    expect(JSON.stringify(failure)).not.toContain("bounded-admin-token");
    expect(JSON.stringify(failure)).not.toContain("first");
  });
});

interface KeycloakFixture {
  authorizationHeaders(): string[];
  baseUrl: string;
  requests(): string[];
}

async function startKeycloakFixture(
  users: ReadonlyArray<Record<string, unknown>>,
): Promise<KeycloakFixture> {
  const authorizationHeaders: string[] = [];
  const requests: string[] = [];
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(
      `${request.method ?? "UNKNOWN"} ${url.pathname}${url.search}`,
    );
    if (
      request.method === "POST" &&
      url.pathname === "/realms/master/protocol/openid-connect/token"
    ) {
      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({
          access_token: "bounded-admin-token",
          expires_in: 60,
          refresh_expires_in: 0,
          token_type: "Bearer",
          "not-before-policy": 0,
          scope: "profile email",
        }),
      );
      return;
    }

    const authorization = request.headers.authorization;
    if (authorization) authorizationHeaders.push(authorization);
    if (
      authorization !== "Bearer bounded-admin-token" ||
      request.method !== "GET"
    ) {
      response
        .writeHead(401, { "content-type": "application/json" })
        .end(JSON.stringify({ error: "unauthorized" }));
      return;
    }

    if (url.pathname === "/admin/realms/verana-playground/users") {
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(users));
      return;
    }

    if (url.pathname === "/admin/realms/verana-playground/users/count") {
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(users.length));
      return;
    }

    const groupsMatch = url.pathname.match(
      /^\/admin\/realms\/verana-playground\/users\/([^/]+)\/groups$/,
    );
    if (groupsMatch) {
      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify([
          {
            id: "group-1",
            name: "acme",
            path: "/organizations/acme",
            subGroupCount: 0,
            subGroups: [],
          },
        ]),
      );
      return;
    }

    const rolesMatch = url.pathname.match(
      /^\/admin\/realms\/verana-playground\/users\/([^/]+)\/role-mappings\/realm\/composite$/,
    );
    if (rolesMatch) {
      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify([
          {
            id: "role-1",
            name: "employee",
            description: "Employee",
            composite: false,
            clientRole: false,
            containerId: "verana-playground",
          },
        ]),
      );
      return;
    }

    response
      .writeHead(404, { "content-type": "application/json" })
      .end(JSON.stringify({ error: "not_found" }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  servers.add(server);
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Keycloak fixture has no TCP address");
  }
  return {
    authorizationHeaders: () => authorizationHeaders,
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests: () => requests,
  };
}
