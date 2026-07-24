import { exportJWK, generateKeyPair } from "jose";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";

import { AccountStore } from "../src/account-store.js";
import type { BrokerConfig } from "../src/config.js";
import { createOidcProvider, loginOnlyPolicy } from "../src/oidc-provider.js";

const config: BrokerConfig = {
  BROKER_ISSUER: "http://localhost:3001",
  BROKER_PORT: 3001,
  BROKER_CLIENT_ID: "keycloak-playground",
  BROKER_CLIENT_SECRET: "broker-client-secret-at-least-32-bytes",
  BROKER_COOKIE_SECRET: "broker-cookie-secret-at-least-32-bytes",
  KEYCLOAK_BROKER_REDIRECT_URI:
    "http://localhost:8080/realms/verana-playground/broker/verana-wallet/endpoint",
  VS_AGENT_VERIFIER_BASE_URL: "http://localhost:3201",
  EXPECTED_VCT: "https://credentials.example/employee",
  EXPECTED_VTJSC_ID: "employee-schema",
  SECTOR_IDENTIFIER: "verana-playground",
  PAIRWISE_SUB_SECRET: "pairwise-sub-secret-at-least-32-bytes",
  BROKER_JWKS_PATH: ".data/broker-jwks.json",
};

let privateJwks: Parameters<typeof createOidcProvider>[0]["privateJwks"];

beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  });
  privateJwks = {
    keys: [
      {
        ...(await exportJWK(privateKey)),
        alg: "ES256",
        kid: "broker-test",
        use: "sig",
      },
    ],
  };
});

describe("OIDC provider", () => {
  it("advertises only Authorization Code with S256", async () => {
    const provider = createOidcProvider({
      accountStore: new AccountStore(),
      config,
      privateJwks,
    });

    const response = await request(provider.callback()).get(
      "/.well-known/openid-configuration",
    );

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
    });
    expect(new URL(response.body.authorization_endpoint).pathname).toBe(
      "/auth",
    );
    expect(new URL(response.body.token_endpoint).pathname).toBe("/token");
    expect(new URL(response.body.jwks_uri).pathname).toBe("/jwks");
  });

  it("registers only the exact Keycloak client and redirect URI", async () => {
    const provider = createOidcProvider({
      accountStore: new AccountStore(),
      config,
      privateJwks,
    });

    await expect(
      provider.Client.find("unregistered-client"),
    ).resolves.toBeUndefined();
    await expect(
      provider.Client.find(config.BROKER_CLIENT_ID),
    ).resolves.toEqual(
      expect.objectContaining({
        clientId: config.BROKER_CLIENT_ID,
        clientSecret: config.BROKER_CLIENT_SECRET,
        grantTypes: ["authorization_code"],
        redirectUris: [config.KEYCLOAK_BROKER_REDIRECT_URI],
        responseTypes: ["code"],
        tokenEndpointAuthMethod: "client_secret_post",
      }),
    );
  });

  it("requires S256 PKCE from the confidential Keycloak client", async () => {
    const provider = createOidcProvider({
      accountStore: new AccountStore(),
      config,
      privateJwks,
    });

    const response = await request(provider.callback()).get("/auth").query({
      client_id: config.BROKER_CLIENT_ID,
      redirect_uri: config.KEYCLOAK_BROKER_REDIRECT_URI,
      response_type: "code",
      scope: "openid",
      state: "state-1",
    });

    expect(response.status).toBe(303);
    const redirect = new URL(response.headers.location);
    expect(redirect.origin + redirect.pathname).toBe(
      config.KEYCLOAK_BROKER_REDIRECT_URI,
    );
    expect(redirect.searchParams.get("error")).toBe("invalid_request");
    expect(redirect.searchParams.get("error_description")).toContain("PKCE");
  });

  it("uses only the login prompt for the first-party client", () => {
    expect(loginOnlyPolicy.map(({ name }) => name)).toEqual(["login"]);
  });

  it("exposes only the configured public ES256 signing key", async () => {
    const provider = createOidcProvider({
      accountStore: new AccountStore(),
      config,
      privateJwks,
    });

    const response = await request(provider.callback()).get("/jwks");

    expect(response.status).toBe(200);
    expect(response.body.keys).toHaveLength(1);
    expect(response.body.keys[0]).toMatchObject({
      alg: "ES256",
      crv: "P-256",
      kid: "broker-test",
      kty: "EC",
      use: "sig",
      x: expect.any(String),
      y: expect.any(String),
    });
    expect(response.body.keys[0]).not.toHaveProperty("d");
  });

  it("isolates process-local OIDC state between provider instances", async () => {
    const first = createOidcProvider({
      accountStore: new AccountStore(),
      config,
      privateJwks,
    });
    const second = createOidcProvider({
      accountStore: new AccountStore(),
      config,
      privateJwks,
    });
    await first.Interaction.adapter.upsert(
      "shared-interaction",
      { uid: "shared-interaction" },
      300,
    );

    await expect(
      first.Interaction.adapter.find("shared-interaction"),
    ).resolves.toMatchObject({ uid: "shared-interaction" });
    await expect(
      second.Interaction.adapter.find("shared-interaction"),
    ).resolves.toBeUndefined();
  });
});
