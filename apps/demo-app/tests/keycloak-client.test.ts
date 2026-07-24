/// <reference types="node" />

import { createServer, type IncomingMessage, type Server } from "node:http";

import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createKeycloakClient,
  type KeycloakIdentity,
} from "../src/keycloak-client.js";

const CLIENT_ID = "playground-app";
const CLIENT_SECRET = "c".repeat(43);
const REDIRECT_URI = "http://localhost:3000/callback";

interface TokenOverrides {
  audience?: string | string[];
  issuer?: string;
  nonce?: string;
}

interface FakeKeycloak {
  issuer: string;
  server: Server;
  setTokenOverrides(overrides: TokenOverrides): void;
  tokenRequests: URLSearchParams[];
}

const servers: Server[] = [];

async function requestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

async function startFakeKeycloak(): Promise<FakeKeycloak> {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const publicJwk = {
    ...(await exportJWK(publicKey)),
    alg: "ES256",
    kid: "test-signing-key",
    use: "sig",
  };
  const tokenRequests: URLSearchParams[] = [];
  let tokenOverrides: TokenOverrides = {};
  let issuer = "";

  const server = createServer(async (request, response) => {
    if (
      request.method === "GET" &&
      request.url ===
        "/realms/verana-playground/.well-known/openid-configuration"
    ) {
      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
          token_endpoint: `${issuer}/protocol/openid-connect/token`,
          jwks_uri: `${issuer}/protocol/openid-connect/certs`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["ES256"],
          token_endpoint_auth_methods_supported: ["client_secret_post"],
          code_challenge_methods_supported: ["S256"],
        }),
      );
      return;
    }

    if (
      request.method === "GET" &&
      request.url === "/realms/verana-playground/protocol/openid-connect/certs"
    ) {
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }

    if (
      request.method === "POST" &&
      request.url === "/realms/verana-playground/protocol/openid-connect/token"
    ) {
      const body = new URLSearchParams(await requestBody(request));
      tokenRequests.push(body);
      const idToken = await createIdToken({
        privateKey,
        issuer: tokenOverrides.issuer ?? issuer,
        audience: tokenOverrides.audience ?? CLIENT_ID,
        nonce: tokenOverrides.nonce ?? body.get("test_nonce") ?? "",
      });

      response.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({
          access_token: "not-persisted",
          refresh_token: "must-not-be-persisted",
          token_type: "Bearer",
          expires_in: 60,
          id_token: idToken,
        }),
      );
      return;
    }

    response.writeHead(404).end();
  });
  servers.push(server);

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("listen_failed");
  issuer = `http://127.0.0.1:${address.port}/realms/verana-playground`;

  return {
    issuer,
    server,
    setTokenOverrides(overrides) {
      tokenOverrides = overrides;
    },
    tokenRequests,
  };
}

async function createIdToken(input: {
  audience: string | string[];
  issuer: string;
  nonce: string;
  privateKey: KeyLike;
}): Promise<string> {
  return await new SignJWT({
    nonce: input.nonce,
    verana_subject: "pairwise-subject-123",
    groups: ["/organizations/acme"],
    realm_access: { roles: ["employee"] },
  })
    .setProtectedHeader({ alg: "ES256", kid: "test-signing-key", typ: "JWT" })
    .setIssuer(input.issuer)
    .setAudience(input.audience)
    .setSubject("keycloak-user-1")
    .setIssuedAt()
    .setExpirationTime("2m")
    .sign(input.privateKey);
}

function callbackUrl(state: string): URL {
  const url = new URL(REDIRECT_URI);
  url.searchParams.set("code", "authorization-code");
  url.searchParams.set("state", state);
  return url;
}

async function exchange(
  fake: FakeKeycloak,
  overrides: TokenOverrides = {},
): Promise<{
  identity: KeycloakIdentity;
  transaction: Awaited<
    ReturnType<
      Awaited<ReturnType<typeof createKeycloakClient>>["startAuthorization"]
    >
  >["transaction"];
}> {
  const client = await createKeycloakClient({
    KEYCLOAK_ISSUER: fake.issuer,
    KEYCLOAK_CLIENT_ID: CLIENT_ID,
    PLAYGROUND_APP_CLIENT_SECRET: CLIENT_SECRET,
    DEMO_APP_REDIRECT_URI: REDIRECT_URI,
  });
  const started = await client.startAuthorization();
  fake.setTokenOverrides({
    ...overrides,
    nonce: overrides.nonce ?? started.transaction.nonce,
  });

  const identity = await client.exchangeCallback(
    callbackUrl(started.transaction.state),
    started.transaction,
  );
  return { identity, transaction: started.transaction };
}

beforeEach(() => {
  servers.length = 0;
});

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.closeAllConnections();
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        }),
    ),
  );
});

describe("KeycloakClient", () => {
  it("builds Authorization Code requests with random state, nonce, and S256 PKCE", async () => {
    const fake = await startFakeKeycloak();
    const client = await createKeycloakClient({
      KEYCLOAK_ISSUER: fake.issuer,
      KEYCLOAK_CLIENT_ID: CLIENT_ID,
      PLAYGROUND_APP_CLIENT_SECRET: CLIENT_SECRET,
      DEMO_APP_REDIRECT_URI: REDIRECT_URI,
    });

    const first = await client.startAuthorization();
    const second = await client.startAuthorization();
    const url = new URL(first.url);

    expect(url.origin + url.pathname).toBe(
      `${fake.issuer}/protocol/openid-connect/auth`,
    );
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("scope")).toBe("openid");
    expect(url.searchParams.get("prompt")).toBe("login");
    expect(url.searchParams.get("state")).toBe(first.transaction.state);
    expect(url.searchParams.get("nonce")).toBe(first.transaction.nonce);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toMatch(
      /^[A-Za-z0-9_-]{43}$/,
    );
    expect(url.searchParams.get("code_challenge")).not.toBe(
      first.transaction.pkceVerifier,
    );
    expect(first.transaction.state).not.toBe(second.transaction.state);
    expect(first.transaction.nonce).not.toBe(second.transaction.nonce);
    expect(first.transaction.pkceVerifier).not.toBe(
      second.transaction.pkceVerifier,
    );
  });

  it("exchanges with the stored PKCE verifier, expected state, and expected nonce", async () => {
    const fake = await startFakeKeycloak();
    const { identity, transaction } = await exchange(fake);
    const tokenRequest = fake.tokenRequests[0];

    expect(tokenRequest?.get("code_verifier")).toBe(transaction.pkceVerifier);
    expect(tokenRequest?.get("client_id")).toBe(CLIENT_ID);
    expect(tokenRequest?.get("client_secret")).toBe(CLIENT_SECRET);
    expect(identity).toEqual({
      issuer: fake.issuer,
      audience: [CLIENT_ID],
      subject: "keycloak-user-1",
      veranaSubject: "pairwise-subject-123",
      groups: ["/organizations/acme"],
      realmRoles: ["employee"],
    });
    expect(identity).not.toHaveProperty("access_token");
    expect(identity).not.toHaveProperty("refresh_token");
  });

  it("rejects a mismatched callback state before creating an identity", async () => {
    const fake = await startFakeKeycloak();
    const client = await createKeycloakClient({
      KEYCLOAK_ISSUER: fake.issuer,
      KEYCLOAK_CLIENT_ID: CLIENT_ID,
      PLAYGROUND_APP_CLIENT_SECRET: CLIENT_SECRET,
      DEMO_APP_REDIRECT_URI: REDIRECT_URI,
    });
    const started = await client.startAuthorization();
    fake.setTokenOverrides({ nonce: started.transaction.nonce });

    await expect(
      client.exchangeCallback(callbackUrl("wrong-state"), started.transaction),
    ).rejects.toThrow("keycloak_callback_invalid");
    expect(fake.tokenRequests).toHaveLength(0);
  });

  it("rejects an ID token with the wrong issuer", async () => {
    const fake = await startFakeKeycloak();

    await expect(
      exchange(fake, { issuer: "https://attacker.example/realms/other" }),
    ).rejects.toThrow("keycloak_callback_invalid");
  });

  it("rejects an ID token without the playground-app audience", async () => {
    const fake = await startFakeKeycloak();

    await expect(
      exchange(fake, { audience: "different-client" }),
    ).rejects.toThrow("keycloak_callback_invalid");
  });

  it("rejects an ID token with the wrong nonce", async () => {
    const fake = await startFakeKeycloak();

    await expect(exchange(fake, { nonce: "wrong-nonce" })).rejects.toThrow(
      "keycloak_callback_invalid",
    );
  });
});
