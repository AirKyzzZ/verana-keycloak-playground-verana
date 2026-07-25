import { timingSafeEqual } from "node:crypto";
import Router, { type RouterContext } from "@koa/router";
import Koa from "koa";

import { authorization, LOCAL_CONTROLLED_CONTRACT, q1 } from "./contract.js";

const LOCAL_VCT = Object.freeze({
  vct: LOCAL_CONTROLLED_CONTRACT.vct,
});

const LOCAL_VTJSC = Object.freeze({
  id: LOCAL_CONTROLLED_CONTRACT.vtjscId,
});
const CONTROL_PATH = "/_local-controlled/resolver-fault";
const FAULT_TTL_MS = 30_000;
const OVERSIZED_BODY = JSON.stringify({ padding: "x".repeat(65_536) });

export type ResolverFaultMode =
  | "malformed-json"
  | "oversized-body"
  | "unavailable";

export interface LocalResolverOptions {
  controlToken?: string;
  evidenceMode?: "LIVE_VERANA" | "LOCAL_CONTROLLED";
  now?: () => number;
}

interface ArmedFault {
  expiresAt: number;
  mode: ResolverFaultMode;
}

function requiredQuery(
  value: string | string[] | undefined,
): string | undefined {
  if (typeof value !== "string" || value.trim().length === 0) return undefined;
  return value;
}

function trustDid(ctx: RouterContext): string | undefined {
  return requiredQuery(ctx.query.did);
}

function authorizationQuery(
  ctx: RouterContext,
): { did: string; vtjscId: string } | undefined {
  const did = requiredQuery(ctx.query.did);
  const vtjscId = requiredQuery(ctx.query.vtjscId);
  if (!did || !vtjscId) return undefined;
  return { did, vtjscId };
}

export function createLocalResolver(options: LocalResolverOptions = {}): Koa {
  const app = new Koa();
  const router = new Router();
  const now = options.now ?? Date.now;
  const controlToken =
    options.evidenceMode === "LOCAL_CONTROLLED" &&
    typeof options.controlToken === "string" &&
    options.controlToken.length >= 43
      ? options.controlToken
      : undefined;
  let armedFault: ArmedFault | undefined;

  const currentFault = (): ArmedFault | undefined => {
    if (armedFault && armedFault.expiresAt <= now()) armedFault = undefined;
    return armedFault;
  };

  const consumeVerifierFault = (): ResolverFaultMode | undefined => {
    const fault = currentFault();
    if (!fault) return undefined;
    armedFault = undefined;
    return fault.mode;
  };

  app.use(async (ctx, next) => {
    ctx.set("Cache-Control", "no-store");
    await next();
  });

  router.get("/health", (ctx) => {
    ctx.body = { status: "ok" };
  });

  router.get("/v1/trust/resolve", (ctx) => {
    const did = trustDid(ctx);
    if (!did) {
      ctx.status = 400;
      ctx.body = { error: "invalid_query" };
      return;
    }
    if (did === LOCAL_CONTROLLED_CONTRACT.verifierDid) {
      const fault = consumeVerifierFault();
      if (fault === "unavailable") {
        ctx.status = 503;
        ctx.body = { error: "resolver_unavailable" };
        return;
      }
      if (fault === "malformed-json") {
        ctx.type = "application/json";
        ctx.body = '{"did":';
        return;
      }
      if (fault === "oversized-body") {
        ctx.type = "application/json";
        ctx.body = OVERSIZED_BODY;
        return;
      }
    }
    ctx.body = q1(did);
  });

  router.get("/v1/trust/issuer-authorization", (ctx) => {
    const query = authorizationQuery(ctx);
    if (!query) {
      ctx.status = 400;
      ctx.body = { error: "invalid_query" };
      return;
    }
    ctx.body = authorization("issuer", query.did, query.vtjscId);
  });

  router.get("/v1/trust/verifier-authorization", (ctx) => {
    const query = authorizationQuery(ctx);
    if (!query) {
      ctx.status = 400;
      ctx.body = { error: "invalid_query" };
      return;
    }
    ctx.body = authorization("verifier", query.did, query.vtjscId);
  });

  router.get("/vct/local-controlled-employee", (ctx) => {
    ctx.body = LOCAL_VCT;
  });

  router.get("/vtjsc/local-controlled-employee.json", (ctx) => {
    ctx.body = LOCAL_VTJSC;
  });

  if (controlToken) {
    router.get(CONTROL_PATH, (ctx) => {
      if (!hasBearerToken(ctx, controlToken)) {
        unauthorized(ctx);
        return;
      }
      const fault = currentFault();
      ctx.body = fault
        ? {
            armed: true,
            expiresAt: new Date(fault.expiresAt).toISOString(),
            mode: fault.mode,
          }
        : { armed: false };
    });

    router.post(`${CONTROL_PATH}/:mode`, (ctx) => {
      if (!hasBearerToken(ctx, controlToken)) {
        unauthorized(ctx);
        return;
      }
      const mode = parseFaultMode(ctx.params.mode);
      if (!mode) {
        ctx.status = 404;
        ctx.body = { error: "not_found" };
        return;
      }
      if (currentFault()) {
        ctx.status = 409;
        ctx.body = { error: "fault_already_armed" };
        return;
      }
      armedFault = { expiresAt: now() + FAULT_TTL_MS, mode };
      ctx.status = 201;
      ctx.body = { armed: true, mode };
    });

    router.delete(CONTROL_PATH, (ctx) => {
      if (!hasBearerToken(ctx, controlToken)) {
        unauthorized(ctx);
        return;
      }
      armedFault = undefined;
      ctx.body = { armed: false };
    });
  }

  app.use(router.routes());
  app.use((ctx) => {
    if (ctx.status === 404) {
      ctx.body = { error: "not_found" };
      ctx.status = 404;
    }
  });
  return app;
}

function parseFaultMode(
  value: string | undefined,
): ResolverFaultMode | undefined {
  if (
    value === "malformed-json" ||
    value === "oversized-body" ||
    value === "unavailable"
  ) {
    return value;
  }
  return undefined;
}

function hasBearerToken(ctx: RouterContext, expectedToken: string): boolean {
  const header = ctx.get("authorization");
  const expected = `Bearer ${expectedToken}`;
  const actualBytes = Buffer.from(header);
  const expectedBytes = Buffer.from(expected);
  return (
    actualBytes.length === expectedBytes.length &&
    timingSafeEqual(actualBytes, expectedBytes)
  );
}

function unauthorized(ctx: RouterContext): void {
  ctx.status = 401;
  ctx.body = { error: "unauthorized" };
}
