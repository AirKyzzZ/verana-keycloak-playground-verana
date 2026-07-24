import {
  allowInsecureRequests,
  authorizationCodeGrant,
  buildAuthorizationUrl,
  ClientSecretPost,
  type Configuration,
  calculatePKCECodeChallenge,
  discovery,
  type IDToken,
  randomNonce,
  randomPKCECodeVerifier,
  randomState,
} from "openid-client";

export interface KeycloakClientConfig {
  DEMO_APP_REDIRECT_URI: string;
  KEYCLOAK_CLIENT_ID: string;
  KEYCLOAK_ISSUER: string;
  PLAYGROUND_APP_CLIENT_SECRET: string;
}

export interface AuthorizationTransaction {
  nonce: string;
  pkceVerifier: string;
  state: string;
}

export interface AuthorizationStart {
  transaction: AuthorizationTransaction;
  url: string;
}

export interface KeycloakIdentity {
  audience: string[];
  groups: string[];
  issuer: string;
  realmRoles: string[];
  subject: string;
  veranaSubject?: string;
}

export interface KeycloakClientContract {
  exchangeCallback(
    callbackUrl: URL,
    transaction: AuthorizationTransaction,
  ): Promise<KeycloakIdentity>;
  startAuthorization(): Promise<AuthorizationStart>;
}

export class KeycloakClient implements KeycloakClientContract {
  readonly #configuration: Configuration;
  readonly #expectedAudience: string;
  readonly #expectedIssuer: string;
  readonly #redirectUri: string;

  constructor(configuration: Configuration, config: KeycloakClientConfig) {
    this.#configuration = configuration;
    this.#expectedAudience = config.KEYCLOAK_CLIENT_ID;
    this.#expectedIssuer = config.KEYCLOAK_ISSUER;
    this.#redirectUri = config.DEMO_APP_REDIRECT_URI;
  }

  async startAuthorization(): Promise<AuthorizationStart> {
    const pkceVerifier = randomPKCECodeVerifier();
    const challenge = await calculatePKCECodeChallenge(pkceVerifier);
    const state = randomState();
    const nonce = randomNonce();
    const url = buildAuthorizationUrl(this.#configuration, {
      redirect_uri: this.#redirectUri,
      scope: "openid",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      nonce,
    });

    return {
      url: url.href,
      transaction: { nonce, pkceVerifier, state },
    };
  }

  async exchangeCallback(
    callbackUrl: URL,
    transaction: AuthorizationTransaction,
  ): Promise<KeycloakIdentity> {
    try {
      if (callbackTarget(callbackUrl) !== callbackTarget(this.#redirectUri)) {
        throw new Error("unexpected_callback_target");
      }

      const tokens = await authorizationCodeGrant(
        this.#configuration,
        callbackUrl,
        {
          pkceCodeVerifier: transaction.pkceVerifier,
          expectedState: transaction.state,
          expectedNonce: transaction.nonce,
        },
      );
      const claims = tokens.claims();
      if (!claims) throw new Error("id_token_missing");

      return parseIdentityClaims(
        claims,
        this.#expectedIssuer,
        this.#expectedAudience,
      );
    } catch {
      throw new Error("keycloak_callback_invalid");
    }
  }
}

export async function createKeycloakClient(
  config: KeycloakClientConfig,
): Promise<KeycloakClient> {
  const issuer = new URL(config.KEYCLOAK_ISSUER);
  const clientMetadata = {
    client_secret: config.PLAYGROUND_APP_CLIENT_SECRET,
    redirect_uris: [config.DEMO_APP_REDIRECT_URI],
  };

  try {
    const configuration =
      issuer.protocol === "http:"
        ? await discoverLoopbackIssuer(config, issuer, clientMetadata)
        : await discovery(
            issuer,
            config.KEYCLOAK_CLIENT_ID,
            clientMetadata,
            ClientSecretPost(config.PLAYGROUND_APP_CLIENT_SECRET),
            { timeout: 3 },
          );
    return new KeycloakClient(configuration, config);
  } catch {
    throw new Error("keycloak_configuration_invalid");
  }
}

function parseIdentityClaims(
  claims: IDToken,
  expectedIssuer: string,
  expectedAudience: string,
): KeycloakIdentity {
  const audience =
    typeof claims.aud === "string"
      ? [claims.aud]
      : Array.isArray(claims.aud)
        ? claims.aud
        : [];
  if (
    claims.iss !== expectedIssuer ||
    !audience.includes(expectedAudience) ||
    typeof claims.sub !== "string" ||
    !claims.sub
  ) {
    throw new Error("id_token_claims_invalid");
  }

  const groups = stringArray(claims.groups);
  const realmAccess = claims.realm_access;
  const realmRoles =
    realmAccess &&
    typeof realmAccess === "object" &&
    !Array.isArray(realmAccess) &&
    "roles" in realmAccess
      ? stringArray(realmAccess.roles)
      : [];
  const veranaSubject =
    typeof claims.verana_subject === "string"
      ? claims.verana_subject
      : undefined;

  return {
    issuer: claims.iss,
    audience,
    subject: claims.sub,
    groups,
    realmRoles,
    ...(veranaSubject === undefined ? {} : { veranaSubject }),
  };
}

async function discoverLoopbackIssuer(
  config: KeycloakClientConfig,
  issuer: URL,
  clientMetadata: {
    client_secret: string;
    redirect_uris: string[];
  },
): Promise<Configuration> {
  if (!["localhost", "127.0.0.1", "::1"].includes(issuer.hostname)) {
    throw new Error("insecure_keycloak_issuer");
  }
  return await discovery(
    issuer,
    config.KEYCLOAK_CLIENT_ID,
    clientMetadata,
    ClientSecretPost(config.PLAYGROUND_APP_CLIENT_SECRET),
    { timeout: 3, execute: [allowInsecureRequests] },
  );
}

function callbackTarget(value: string | URL): string {
  const url = value instanceof URL ? value : new URL(value);
  return `${url.origin}${url.pathname}`;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}
