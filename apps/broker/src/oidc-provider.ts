import Provider, { interactionPolicy, type JWKS } from "oidc-provider";

import type { AccountStore } from "./account-store.js";
import type { BrokerConfig } from "./config.js";
import { createProcessLocalAdapterFactory } from "./process-local-adapter.js";

export const loginOnlyPolicy = interactionPolicy.base();
loginOnlyPolicy.remove("consent");

export interface CreateOidcProviderOptions {
  accountStore: AccountStore;
  config: BrokerConfig;
  privateJwks: JWKS;
}

export function createOidcProvider({
  accountStore,
  config,
  privateJwks,
}: CreateOidcProviderOptions): Provider {
  return new Provider(config.BROKER_ISSUER, {
    adapter: createProcessLocalAdapterFactory(),
    clients: [
      {
        client_id: config.BROKER_CLIENT_ID,
        client_secret: config.BROKER_CLIENT_SECRET,
        redirect_uris: [config.KEYCLOAK_BROKER_REDIRECT_URI],
        response_types: ["code"],
        grant_types: ["authorization_code"],
        id_token_signed_response_alg: "ES256",
        token_endpoint_auth_method: "client_secret_post",
      },
    ],
    jwks: privateJwks,
    claims: {
      openid: [
        "sub",
        "preferred_username",
        "organization",
        "role",
        "verana_verifier_did",
        "verana_issuer_did",
      ],
    },
    scopes: ["openid"],
    responseTypes: ["code"],
    clientAuthMethods: ["client_secret_post"],
    cookies: {
      keys: [config.BROKER_COOKIE_SECRET],
    },
    pkce: {
      required: () => true,
    },
    features: {
      devInteractions: { enabled: false },
    },
    interactions: {
      policy: loginOnlyPolicy,
      url: (_context, interaction) => `/interaction/${interaction.uid}`,
    },
    findAccount: async (_context, accountId) =>
      accountStore.findAccount(accountId),
    // consent prompt is removed, so the openid grant must be created here or
    // every login resolves access_denied ("no scope was granted")
    loadExistingGrant: async (context) => {
      const client = context.oidc.client;
      const session = context.oidc.session;
      if (client?.clientId !== config.BROKER_CLIENT_ID || !session?.accountId) {
        return undefined;
      }
      const grantId = session.grantIdFor(client.clientId);
      if (grantId) {
        const existing = await context.oidc.provider.Grant.find(grantId);
        if (existing) return existing;
      }
      const grant = new context.oidc.provider.Grant({
        clientId: client.clientId,
        accountId: session.accountId,
      });
      grant.addOIDCScope("openid");
      await grant.save();
      return grant;
    },
    ttl: {
      AuthorizationCode: 60,
      Interaction: 300,
      Session: 300,
    },
  });
}
