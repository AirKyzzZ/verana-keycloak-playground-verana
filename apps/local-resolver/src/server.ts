import Router, { type RouterContext } from "@koa/router";
import Koa from "koa";

import { authorization, LOCAL_CONTROLLED_CONTRACT, q1 } from "./contract.js";

const LOCAL_VCT = Object.freeze({
  vct: LOCAL_CONTROLLED_CONTRACT.vct,
});

const LOCAL_VTJSC = Object.freeze({
  id: LOCAL_CONTROLLED_CONTRACT.vtjscId,
});

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

export function createLocalResolver(): Koa {
  const app = new Koa();
  const router = new Router();

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

  app.use(router.routes());
  app.use((ctx) => {
    if (ctx.status === 404) {
      ctx.body = { error: "not_found" };
      ctx.status = 404;
    }
  });
  return app;
}
