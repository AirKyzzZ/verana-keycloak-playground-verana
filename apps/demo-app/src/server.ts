import Router from "@koa/router";
import Koa, { type Context } from "koa";
import bodyParser from "koa-bodyparser";

import type { DemoConfig } from "./config.js";
import {
  renderErrorPage,
  renderHomePage,
  renderProfilePage,
  renderWalletPage,
  type WalletPageState,
} from "./html.js";
import type {
  AuthorizationTransaction,
  KeycloakClientContract,
  KeycloakIdentity,
} from "./keycloak-client.js";
import type {
  LocalWalletClientContract,
  ResolvedPresentation,
} from "./local-wallet-client.js";
import { OpaqueStore } from "./session-store.js";

const AUTH_COOKIE = "verana_auth";
const SESSION_COOKIE = "verana_session";
const WALLET_COOKIE = "verana_wallet";
const AUTH_TTL_MS = 5 * 60 * 1_000;
const SESSION_TTL_MS = 60 * 60 * 1_000;
const WALLET_TTL_MS = 30 * 60 * 1_000;

interface WalletWorkflow extends WalletPageState {
  resolution?: ResolvedPresentation;
}

export interface DemoServerOptions {
  config: DemoConfig;
  keycloakClient: KeycloakClientContract;
  walletClient: LocalWalletClientContract;
}

export function createDemoServer(options: DemoServerOptions): Koa {
  const { config, keycloakClient, walletClient } = options;
  const secureCookies =
    new URL(config.DEMO_APP_REDIRECT_URI).protocol === "https:";
  const authStore = new OpaqueStore<AuthorizationTransaction>(
    config.SESSION_SECRET,
    "authorization",
    { ttlMs: AUTH_TTL_MS },
  );
  const sessionStore = new OpaqueStore<KeycloakIdentity>(
    config.SESSION_SECRET,
    "session",
    { ttlMs: SESSION_TTL_MS },
  );
  const walletStore = new OpaqueStore<WalletWorkflow>(
    config.SESSION_SECRET,
    "wallet",
    { ttlMs: WALLET_TTL_MS },
  );
  const app = new Koa();
  const router = new Router();

  app.use(async (context, next) => {
    context.set("Cache-Control", "no-store");
    context.set("X-Content-Type-Options", "nosniff");
    context.set("Referrer-Policy", "no-referrer");
    context.set(
      "Content-Security-Policy",
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    await next();
  });
  app.use(
    bodyParser({
      enableTypes: ["form"],
      formLimit: "16kb",
    }),
  );

  router.get("/", (context) => {
    html(context, 200, renderHomePage());
  });

  router.get("/login", async (context) => {
    const started = await keycloakClient.startAuthorization();
    const token = authStore.create(started.transaction);
    setOpaqueCookie(context, AUTH_COOKIE, token, secureCookies, AUTH_TTL_MS);
    context.redirect(started.url);
  });

  router.get("/callback", async (context) => {
    const authToken = context.cookies.get(AUTH_COOKIE);
    clearCookie(context, AUTH_COOKIE, secureCookies);
    const transaction = authToken ? authStore.take(authToken) : undefined;
    const state = singleQueryValue(context.query.state);
    if (!transaction || !state || state !== transaction.state) {
      html(
        context,
        400,
        renderErrorPage(
          "Invalid login callback",
          "Start a new Keycloak login.",
        ),
      );
      return;
    }

    try {
      const callbackUrl = new URL(config.DEMO_APP_REDIRECT_URI);
      callbackUrl.search = context.querystring;
      const identity = await keycloakClient.exchangeCallback(
        callbackUrl,
        transaction,
      );
      if (
        identity.issuer !== config.KEYCLOAK_ISSUER ||
        !identity.audience.includes(config.KEYCLOAK_CLIENT_ID)
      ) {
        throw new Error("identity_binding_invalid");
      }
      const sessionToken = sessionStore.create(identity);
      setOpaqueCookie(
        context,
        SESSION_COOKIE,
        sessionToken,
        secureCookies,
        SESSION_TTL_MS,
      );
      context.redirect("/profile");
    } catch {
      html(
        context,
        401,
        renderErrorPage(
          "Login verification failed",
          "The Keycloak response could not be verified.",
        ),
      );
    }
  });

  router.get("/profile", (context) => {
    const sessionToken = context.cookies.get(SESSION_COOKIE);
    const identity = sessionToken ? sessionStore.get(sessionToken) : undefined;
    if (!identity) {
      html(
        context,
        401,
        renderErrorPage("Authentication required", "Sign in through Keycloak."),
      );
      return;
    }
    const authorized = authorizedProfile(identity);
    if (!authorized) {
      html(
        context,
        403,
        renderErrorPage(
          "Identity is not authorized",
          "The exact ACME group, employee role, and Verana subject are required.",
        ),
      );
      return;
    }
    html(context, 200, renderProfilePage(authorized));
  });

  router.post("/logout", (context) => {
    const sessionToken = context.cookies.get(SESSION_COOKIE);
    if (sessionToken) sessionStore.delete(sessionToken);
    clearCookie(context, SESSION_COOKIE, secureCookies);
    context.redirect("/");
  });

  router.get("/wallet", (context) => {
    const workflow = readWalletWorkflow(context, walletStore);
    html(context, 200, renderWalletPage(workflow));
  });

  router.post("/wallet/issue", async (context) => {
    const subjectId = formString(context, "subjectId", 200);
    if (!subjectId) {
      html(
        context,
        400,
        renderErrorPage(
          "Invalid badge request",
          "An opaque subject of at most 200 characters is required.",
        ),
      );
      return;
    }
    try {
      const issued = await walletClient.issueBadge(subjectId);
      const acceptedBadge = await walletClient.acceptOffer(
        issued.credentialOffer,
      );
      const existing = readWalletWorkflow(context, walletStore);
      const workflow: WalletWorkflow = { ...existing, acceptedBadge };
      saveWalletWorkflow(context, walletStore, workflow, secureCookies);
      html(context, 200, renderWalletPage(workflow));
    } catch {
      renderVsAgentUnavailable(context);
    }
  });

  router.post("/wallet/resolve", async (context) => {
    const authorizationRequest = formString(
      context,
      "authorizationRequest",
      10_000,
    );
    if (!authorizationRequest) {
      html(
        context,
        400,
        renderErrorPage(
          "Invalid authorization request",
          "Paste a nonempty broker authorization request.",
        ),
      );
      return;
    }
    try {
      const resolution =
        await walletClient.resolveRequest(authorizationRequest);
      const existing = readWalletWorkflow(context, walletStore);
      const workflow: WalletWorkflow = { ...existing, resolution };
      saveWalletWorkflow(context, walletStore, workflow, secureCookies);
      html(context, 200, renderWalletPage(workflow));
    } catch {
      renderVsAgentUnavailable(context);
    }
  });

  router.post("/wallet/share", async (context) => {
    const workflow = readWalletWorkflow(context, walletStore);
    const resolution = workflow.resolution;
    if (!resolution) {
      html(
        context,
        400,
        renderErrorPage(
          "No reviewed request",
          "Resolve and review a broker request before sharing.",
        ),
      );
      return;
    }
    if (resolution.verdict !== "TRUSTED_AUTHORIZED") {
      html(
        context,
        403,
        renderErrorPage(
          "Sharing refused",
          "The verifier is not both trusted and authorized.",
        ),
      );
      return;
    }
    if (workflow.shared) {
      html(
        context,
        409,
        renderErrorPage(
          "Request already shared",
          "Resolve a new broker request before sharing again.",
        ),
      );
      return;
    }

    try {
      const shared = await walletClient.share(resolution);
      const updated = { ...workflow, shared };
      saveWalletWorkflow(context, walletStore, updated, secureCookies);
      html(context, 200, renderWalletPage(updated));
    } catch {
      renderVsAgentUnavailable(context);
    }
  });

  app.use(router.routes());
  app.use(router.allowedMethods());
  return app;
}

function authorizedProfile(
  identity: KeycloakIdentity,
): (KeycloakIdentity & { veranaSubject: string }) | undefined {
  const veranaSubject = identity.veranaSubject?.trim();
  if (
    !veranaSubject ||
    !identity.groups.includes("/organizations/acme") ||
    !identity.realmRoles.includes("employee")
  ) {
    return undefined;
  }
  return { ...identity, veranaSubject };
}

function clearCookie(context: Context, name: string, secure: boolean): void {
  context.cookies.set(name, null, {
    httpOnly: true,
    overwrite: true,
    path: "/",
    sameSite: "lax",
    secure,
  });
}

function formString(
  context: Context,
  field: string,
  maxLength: number,
): string | undefined {
  const body = (context.request as typeof context.request & { body?: unknown })
    .body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return undefined;
  }
  const value = (body as Record<string, unknown>)[field];
  if (typeof value !== "string" || !value.trim() || value.length > maxLength) {
    return undefined;
  }
  return value.trim();
}

function html(context: Context, status: number, body: string): void {
  context.status = status;
  context.type = "text/html";
  context.body = body;
}

function readWalletWorkflow(
  context: Context,
  store: OpaqueStore<WalletWorkflow>,
): WalletWorkflow {
  const token = context.cookies.get(WALLET_COOKIE);
  return (token ? store.get(token) : undefined) ?? {};
}

function renderVsAgentUnavailable(context: Context): void {
  html(
    context,
    502,
    renderErrorPage(
      "Local VS Agent unavailable",
      "The bounded local request failed. Try again after checking the role-specific services.",
    ),
  );
}

function saveWalletWorkflow(
  context: Context,
  store: OpaqueStore<WalletWorkflow>,
  workflow: WalletWorkflow,
  secure: boolean,
): void {
  const currentToken = context.cookies.get(WALLET_COOKIE);
  if (currentToken && store.replace(currentToken, workflow)) return;
  const token = store.create(workflow);
  setOpaqueCookie(context, WALLET_COOKIE, token, secure, WALLET_TTL_MS);
}

function setOpaqueCookie(
  context: Context,
  name: string,
  token: string,
  secure: boolean,
  maxAge: number,
): void {
  context.cookies.set(name, token, {
    httpOnly: true,
    maxAge,
    overwrite: true,
    path: "/",
    sameSite: "lax",
    secure,
  });
}

function singleQueryValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
