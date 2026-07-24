import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { generateLocalData } from "../scripts/setup.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const templatePath = join(root, "keycloak", "realm.template.json");

const readTemplate = async () =>
  JSON.parse(await readFile(templatePath, "utf8"));

describe("Keycloak realm contract", () => {
  it("configures the exact disposable broker realm", async () => {
    const realm = await readTemplate();
    const client = realm.clients.find(
      ({ clientId }: { clientId: string }) => clientId === "playground-app",
    );
    const identityProvider = realm.identityProviders.find(
      ({ alias }: { alias: string }) => alias === "verana-wallet",
    );
    const firstLoginFlow = realm.authenticationFlows.find(
      ({ alias }: { alias: string }) => alias === "verana first broker login",
    );
    const groupMapper = realm.identityProviderMappers.find(
      ({ name }: { name: string }) => name === "ACME organization group",
    );
    const roleMapper = realm.identityProviderMappers.find(
      ({ name }: { name: string }) => name === "Employee role",
    );
    const subjectMapper = realm.identityProviderMappers.find(
      ({ name }: { name: string }) => name === "Verana pairwise subject",
    );

    expect(realm).toMatchObject({
      realm: "verana-playground",
      enabled: true,
      sslRequired: "none",
      registrationAllowed: false,
      resetPasswordAllowed: false,
    });
    expect(client).toMatchObject({
      secret: "__PLAYGROUND_APP_CLIENT_SECRET__",
      publicClient: false,
      standardFlowEnabled: true,
      implicitFlowEnabled: false,
      directAccessGrantsEnabled: false,
      redirectUris: ["http://localhost:3000/callback"],
      webOrigins: ["http://localhost:3000"],
      protocol: "openid-connect",
      attributes: { "pkce.code.challenge.method": "S256" },
    });
    expect(identityProvider).toMatchObject({
      providerId: "oidc",
      enabled: true,
      trustEmail: false,
      storeToken: false,
      firstBrokerLoginFlowAlias: "verana first broker login",
      config: {
        authorizationUrl: "http://localhost:3001/auth",
        tokenUrl: "http://host.docker.internal:3001/token",
        jwksUrl: "http://host.docker.internal:3001/jwks",
        issuer: "http://localhost:3001",
        clientId: "keycloak-playground",
        clientSecret: "__BROKER_CLIENT_SECRET__",
        clientAuthMethod: "client_secret_post",
        defaultScope: "openid",
        useJwksUrl: "true",
        validateSignature: "true",
        pkceEnabled: "true",
        pkceMethod: "S256",
        syncMode: "FORCE",
      },
    });
    expect(firstLoginFlow.authenticationExecutions).toEqual([
      {
        authenticator: "idp-create-user-if-unique",
        authenticatorFlow: false,
        requirement: "REQUIRED",
        priority: 10,
        userSetupAllowed: false,
      },
    ]);
    expect(realm.roles.realm).toContainEqual({ name: "employee" });
    expect(realm.groups).toContainEqual({
      name: "organizations",
      subGroups: [{ name: "acme" }],
    });
    expect(groupMapper).toMatchObject({
      identityProviderAlias: "verana-wallet",
      identityProviderMapper: "oidc-advanced-group-idp-mapper",
      config: {
        syncMode: "FORCE",
        claims: '[{"key":"organization","value":"ACME"}]',
        "are.claim.values.regex": "false",
        group: "/organizations/acme",
      },
    });
    expect(roleMapper).toMatchObject({
      identityProviderAlias: "verana-wallet",
      identityProviderMapper: "oidc-role-idp-mapper",
      config: {
        syncMode: "FORCE",
        claim: "role",
        "claim.value": "employee",
        role: "employee",
      },
    });
    expect(subjectMapper).toMatchObject({
      identityProviderAlias: "verana-wallet",
      identityProviderMapper: "oidc-user-attribute-idp-mapper",
      config: {
        syncMode: "FORCE",
        claim: "sub",
        "user.attribute": "verana_subject",
        "allow.nullable.property": "false",
      },
    });
    expect(client.protocolMappers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "verana subject",
          protocolMapper: "oidc-usermodel-attribute-mapper",
          config: expect.objectContaining({
            "user.attribute": "verana_subject",
            "claim.name": "verana_subject",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
          }),
        }),
        expect.objectContaining({
          name: "organization groups",
          protocolMapper: "oidc-group-membership-mapper",
          config: expect.objectContaining({
            "full.path": "true",
            "claim.name": "groups",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
          }),
        }),
        expect.objectContaining({
          name: "realm roles",
          protocolMapper: "oidc-usermodel-realm-role-mapper",
          config: expect.objectContaining({
            "claim.name": "realm_access.roles",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
          }),
        }),
      ]),
    );
    expect(realm.users ?? []).toHaveLength(0);
  });

  it("renders generated secrets into a private realm import", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-realm-"));
    await generateLocalData(output);

    const env = await readFile(join(output, ".env"), "utf8");
    const realmText = await readFile(join(output, "realm.json"), "utf8");
    const realm = JSON.parse(realmText);
    const secrets = Object.fromEntries(
      env
        .trim()
        .split("\n")
        .map((line) => line.split("=", 2)),
    );
    const client = realm.clients.find(
      ({ clientId }: { clientId: string }) => clientId === "playground-app",
    );
    const identityProvider = realm.identityProviders.find(
      ({ alias }: { alias: string }) => alias === "verana-wallet",
    );

    expect(realmText).not.toMatch(/__[A-Z0-9_]+__/);
    expect(client.secret).toBe(secrets.PLAYGROUND_APP_CLIENT_SECRET);
    expect(identityProvider.config.clientSecret).toBe(
      secrets.BROKER_CLIENT_SECRET,
    );
    expect((await stat(join(output, "realm.json"))).mode & 0o777).toBe(0o600);
  });
});
