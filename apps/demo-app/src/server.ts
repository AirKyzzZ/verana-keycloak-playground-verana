import { randomBytes, timingSafeEqual } from "node:crypto";

import Router from "@koa/router";
import Koa, { type Context } from "koa";
import bodyParser from "koa-bodyparser";

import type { DemoConfig, EvidenceMode } from "./config.js";
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
import type { LocalWalletClientContract } from "./local-wallet-client.js";
import { OpaqueStore } from "./session-store.js";

const AUTH_COOKIE = "verana_auth";
const SESSION_COOKIE = "verana_session";
const WALLET_COOKIE = "verana_wallet";
const AUTH_TTL_MS = 5 * 60 * 1_000;
const SESSION_TTL_MS = 60 * 60 * 1_000;
const WALLET_TTL_MS = 30 * 60 * 1_000;
const AUTH_MAX_ENTRIES = 1_024;
const SESSION_MAX_ENTRIES = 1_024;
const WALLET_MAX_ENTRIES = 512;

interface WalletWorkflow extends WalletPageState {
  operationId?: string;
}

interface WalletAccess {
  token: string;
  workflow: WalletWorkflow;
}

interface AuthenticatedSession {
  csrfToken: string;
  identity: KeycloakIdentity;
}

export interface DemoServerOptions {
  config: DemoConfig;
  keycloakClient: KeycloakClientContract;
  walletClient: LocalWalletClientContract;
}

export function createDemoServer(options: DemoServerOptions): Koa {
  const { config, keycloakClient, walletClient } = options;
  const applicationUrl = new URL(config.DEMO_APP_REDIRECT_URI);
  const expectedOrigin = applicationUrl.origin;
  const secureCookies = applicationUrl.protocol === "https:";
  const authStore = new OpaqueStore<AuthorizationTransaction>(
    config.SESSION_SECRET,
    "authorization",
    { maxEntries: AUTH_MAX_ENTRIES, ttlMs: AUTH_TTL_MS },
  );
  const sessionStore = new OpaqueStore<AuthenticatedSession>(
    config.SESSION_SECRET,
    "session",
    { maxEntries: SESSION_MAX_ENTRIES, ttlMs: SESSION_TTL_MS },
  );
  const walletStore = new OpaqueStore<WalletWorkflow>(
    config.SESSION_SECRET,
    "wallet",
    { maxEntries: WALLET_MAX_ENTRIES, ttlMs: WALLET_TTL_MS },
  );
  const app = new Koa();
  const router = new Router();

  app.use(async (context, next) => {
    context.set("Cache-Control", "no-store");
    context.set("X-Content-Type-Options", "nosniff");
    context.set("Referrer-Policy", "same-origin");
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
    html(context, 200, renderHomePage(config.EVIDENCE_MODE));
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
          config.EVIDENCE_MODE,
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
      const sessionToken = sessionStore.create({
        csrfToken: randomOpaqueValue(),
        identity,
      });
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
          config.EVIDENCE_MODE,
          "Login verification failed",
          "The Keycloak response could not be verified.",
        ),
      );
    }
  });

  router.get("/profile", (context) => {
    const sessionToken = context.cookies.get(SESSION_COOKIE);
    const session = sessionToken ? sessionStore.get(sessionToken) : undefined;
    if (!session) {
      html(
        context,
        401,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Authentication required",
          "Sign in through Keycloak.",
        ),
      );
      return;
    }
    const authorized = authorizedProfile(session.identity);
    if (!authorized) {
      html(
        context,
        403,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Identity is not authorized",
          "The exact ACME group, employee role, and Verana subject are required.",
        ),
      );
      return;
    }
    html(
      context,
      200,
      renderProfilePage(config.EVIDENCE_MODE, authorized, session.csrfToken),
    );
  });

  router.post("/logout", (context) => {
    const sessionToken = context.cookies.get(SESSION_COOKIE);
    const session = sessionToken ? sessionStore.get(sessionToken) : undefined;
    const submittedToken = formString(context, "csrfToken", 100);
    if (
      context.get("Origin") !== expectedOrigin ||
      !sessionToken ||
      !session ||
      !submittedToken ||
      !tokensEqual(session.csrfToken, submittedToken)
    ) {
      html(
        context,
        403,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Invalid logout request",
          "Reload the protected profile before trying again.",
        ),
      );
      return;
    }
    sessionStore.delete(sessionToken);
    clearCookie(context, SESSION_COOKIE, secureCookies);
    context.redirect("/");
  });

  router.get("/wallet", (context) => {
    const { workflow } = ensureWalletWorkflow(
      context,
      walletStore,
      secureCookies,
    );
    html(context, 200, renderWalletPage(config.EVIDENCE_MODE, workflow));
  });

  router.post("/wallet/issue", async (context) => {
    const access = requireWalletMutation(
      context,
      walletStore,
      expectedOrigin,
      config.EVIDENCE_MODE,
    );
    if (!access) return;
    const subjectId = formString(context, "subjectId", 200);
    if (!subjectId) {
      html(
        context,
        400,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Invalid badge request",
          "An opaque subject of at most 200 characters is required.",
        ),
      );
      return;
    }
    if (isOperationInProgress(access.workflow.workflowStatus)) {
      renderWorkflowConflict(
        context,
        config.EVIDENCE_MODE,
        access.workflow.workflowStatus,
      );
      return;
    }
    const operationId = randomOpaqueValue();
    const pending: WalletWorkflow = {
      csrfToken: access.workflow.csrfToken,
      operationId,
      workflowStatus: "issuing",
    };
    if (!walletStore.replace(access.token, pending)) {
      renderExpiredWallet(context, config.EVIDENCE_MODE);
      return;
    }

    try {
      const issued = await walletClient.issueBadge(subjectId);
      const acceptedBadge = await walletClient.acceptOffer(
        issued.credentialOffer,
      );
      if (
        !isCurrentOperation(walletStore, access.token, "issuing", operationId)
      ) {
        renderSupersededWallet(context, config.EVIDENCE_MODE);
        return;
      }
      const workflow: WalletWorkflow = {
        acceptedBadge,
        csrfToken: access.workflow.csrfToken,
        workflowStatus: "idle",
      };
      walletStore.replace(access.token, workflow);
      html(context, 200, renderWalletPage(config.EVIDENCE_MODE, workflow));
    } catch {
      replaceCurrentOperation(
        walletStore,
        access.token,
        "issuing",
        operationId,
        {
          csrfToken: access.workflow.csrfToken,
          workflowStatus: "issue_failed",
        },
      );
      renderVsAgentUnavailable(context, config.EVIDENCE_MODE);
    }
  });

  router.post("/wallet/resolve", async (context) => {
    const access = requireWalletMutation(
      context,
      walletStore,
      expectedOrigin,
      config.EVIDENCE_MODE,
    );
    if (!access) return;
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
          config.EVIDENCE_MODE,
          "Invalid authorization request",
          "Paste a nonempty broker authorization request.",
        ),
      );
      return;
    }
    if (
      access.workflow.workflowStatus === "issuing" ||
      access.workflow.workflowStatus === "sharing"
    ) {
      renderWorkflowConflict(
        context,
        config.EVIDENCE_MODE,
        access.workflow.workflowStatus,
      );
      return;
    }
    const operationId = randomOpaqueValue();
    const pending: WalletWorkflow = {
      ...(access.workflow.acceptedBadge
        ? { acceptedBadge: access.workflow.acceptedBadge }
        : {}),
      csrfToken: access.workflow.csrfToken,
      operationId,
      workflowStatus: "resolving",
    };
    if (!walletStore.replace(access.token, pending)) {
      renderExpiredWallet(context, config.EVIDENCE_MODE);
      return;
    }

    try {
      const resolution =
        await walletClient.resolveRequest(authorizationRequest);
      if (
        !isCurrentOperation(walletStore, access.token, "resolving", operationId)
      ) {
        renderSupersededWallet(context, config.EVIDENCE_MODE);
        return;
      }
      const workflow: WalletWorkflow = {
        ...(access.workflow.acceptedBadge
          ? { acceptedBadge: access.workflow.acceptedBadge }
          : {}),
        csrfToken: access.workflow.csrfToken,
        resolution,
        workflowStatus: "resolved",
      };
      walletStore.replace(access.token, workflow);
      html(context, 200, renderWalletPage(config.EVIDENCE_MODE, workflow));
    } catch {
      replaceCurrentOperation(
        walletStore,
        access.token,
        "resolving",
        operationId,
        {
          ...(access.workflow.acceptedBadge
            ? { acceptedBadge: access.workflow.acceptedBadge }
            : {}),
          csrfToken: access.workflow.csrfToken,
          workflowStatus: "resolve_failed",
        },
      );
      renderVsAgentUnavailable(context, config.EVIDENCE_MODE);
    }
  });

  router.post("/wallet/share", async (context) => {
    const access = requireWalletMutation(
      context,
      walletStore,
      expectedOrigin,
      config.EVIDENCE_MODE,
    );
    if (!access) return;
    if (access.workflow.workflowStatus === "sharing") {
      html(
        context,
        409,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Sharing already in progress",
          "Wait for the local holder response before taking another action.",
        ),
      );
      return;
    }
    if (access.workflow.workflowStatus === "share_uncertain") {
      html(
        context,
        409,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Sharing outcome is uncertain",
          "Resolve and review a new request before any further sharing attempt.",
        ),
      );
      return;
    }
    const resolution = access.workflow.resolution;
    if (
      access.workflow.workflowStatus !== "resolved" ||
      resolution === undefined
    ) {
      html(
        context,
        409,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "No current reviewed request",
          "Resolve and review a new request before sharing.",
        ),
      );
      return;
    }
    if (resolution.verdict !== "TRUSTED_AUTHORIZED") {
      html(
        context,
        403,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Sharing refused",
          "The verifier is not both trusted and authorized.",
        ),
      );
      return;
    }
    const operationId = randomOpaqueValue();
    const pending: WalletWorkflow = {
      ...(access.workflow.acceptedBadge
        ? { acceptedBadge: access.workflow.acceptedBadge }
        : {}),
      csrfToken: access.workflow.csrfToken,
      operationId,
      workflowStatus: "sharing",
    };
    if (!walletStore.replace(access.token, pending)) {
      renderExpiredWallet(context, config.EVIDENCE_MODE);
      return;
    }

    try {
      const shared = await walletClient.share(resolution);
      if (
        !isCurrentOperation(walletStore, access.token, "sharing", operationId)
      ) {
        renderSupersededWallet(context, config.EVIDENCE_MODE);
        return;
      }
      const updated: WalletWorkflow = {
        ...(access.workflow.acceptedBadge
          ? { acceptedBadge: access.workflow.acceptedBadge }
          : {}),
        csrfToken: access.workflow.csrfToken,
        resolution,
        shared,
        workflowStatus: "shared",
      };
      walletStore.replace(access.token, updated);
      html(context, 200, renderWalletPage(config.EVIDENCE_MODE, updated));
    } catch {
      replaceCurrentOperation(
        walletStore,
        access.token,
        "sharing",
        operationId,
        {
          ...(access.workflow.acceptedBadge
            ? { acceptedBadge: access.workflow.acceptedBadge }
            : {}),
          csrfToken: access.workflow.csrfToken,
          workflowStatus: "share_uncertain",
        },
      );
      html(
        context,
        502,
        renderErrorPage(
          config.EVIDENCE_MODE,
          "Sharing outcome is uncertain",
          "The holder response was not verified. Resolve and review a new request before any further sharing attempt.",
        ),
      );
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

function ensureWalletWorkflow(
  context: Context,
  store: OpaqueStore<WalletWorkflow>,
  secure: boolean,
): WalletAccess {
  const currentToken = context.cookies.get(WALLET_COOKIE);
  const currentWorkflow = currentToken ? store.get(currentToken) : undefined;
  if (currentToken && currentWorkflow) {
    return { token: currentToken, workflow: currentWorkflow };
  }
  const workflow: WalletWorkflow = {
    csrfToken: randomOpaqueValue(),
    workflowStatus: "idle",
  };
  const token = store.create(workflow);
  setOpaqueCookie(context, WALLET_COOKIE, token, secure, WALLET_TTL_MS);
  return { token, workflow };
}

function isCurrentOperation(
  store: OpaqueStore<WalletWorkflow>,
  token: string,
  status: WalletWorkflow["workflowStatus"],
  operationId: string,
): boolean {
  const workflow = store.get(token);
  return (
    workflow?.workflowStatus === status && workflow.operationId === operationId
  );
}

function isOperationInProgress(
  status: WalletWorkflow["workflowStatus"],
): boolean {
  return status === "issuing" || status === "resolving" || status === "sharing";
}

function randomOpaqueValue(): string {
  return randomBytes(32).toString("base64url");
}

function replaceCurrentOperation(
  store: OpaqueStore<WalletWorkflow>,
  token: string,
  status: WalletWorkflow["workflowStatus"],
  operationId: string,
  replacement: WalletWorkflow,
): void {
  if (isCurrentOperation(store, token, status, operationId)) {
    store.replace(token, replacement);
  }
}

function requireWalletMutation(
  context: Context,
  store: OpaqueStore<WalletWorkflow>,
  expectedOrigin: string,
  evidenceMode: EvidenceMode,
): WalletAccess | undefined {
  const token = context.cookies.get(WALLET_COOKIE);
  const workflow = token ? store.get(token) : undefined;
  const submittedToken = formString(context, "csrfToken", 100);
  if (
    context.get("Origin") !== expectedOrigin ||
    !token ||
    !workflow ||
    !submittedToken ||
    !tokensEqual(workflow.csrfToken, submittedToken)
  ) {
    html(
      context,
      403,
      renderErrorPage(
        evidenceMode,
        "Invalid wallet request",
        "Reload the local holder page before trying again.",
      ),
    );
    return undefined;
  }
  return { token, workflow };
}

function tokensEqual(expected: string, actual: string): boolean {
  const expectedBytes = Buffer.from(expected, "utf8");
  const actualBytes = Buffer.from(actual, "utf8");
  return (
    expectedBytes.byteLength === actualBytes.byteLength &&
    timingSafeEqual(expectedBytes, actualBytes)
  );
}

function renderVsAgentUnavailable(
  context: Context,
  evidenceMode: EvidenceMode,
): void {
  html(
    context,
    502,
    renderErrorPage(
      evidenceMode,
      "Local VS Agent unavailable",
      "The bounded local request failed. Try again after checking the role-specific services.",
    ),
  );
}

function renderExpiredWallet(
  context: Context,
  evidenceMode: EvidenceMode,
): void {
  html(
    context,
    409,
    renderErrorPage(
      evidenceMode,
      "Local holder session expired",
      "Reload the local holder page before trying again.",
    ),
  );
}

function renderSupersededWallet(
  context: Context,
  evidenceMode: EvidenceMode,
): void {
  html(
    context,
    409,
    renderErrorPage(
      evidenceMode,
      "Wallet workflow changed",
      "Reload the local holder page to review the current state.",
    ),
  );
}

function renderWorkflowConflict(
  context: Context,
  evidenceMode: EvidenceMode,
  status: WalletWorkflow["workflowStatus"],
): void {
  const action =
    status === "issuing"
      ? "Badge issuance"
      : status === "resolving"
        ? "Request resolution"
        : "Presentation sharing";
  html(
    context,
    409,
    renderErrorPage(
      evidenceMode,
      `${action} already in progress`,
      "Wait for the current operation before taking another action.",
    ),
  );
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
