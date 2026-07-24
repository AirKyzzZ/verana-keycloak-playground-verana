import type { Server } from "node:http";

import type Koa from "koa";

import { createLocalResolver } from "./server.js";

function localResolverPort(value: string | undefined): number {
  if (value === undefined) return 3099;
  if (!/^\d+$/.test(value))
    throw new Error("LOCAL_RESOLVER_PORT must be an integer");

  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("LOCAL_RESOLVER_PORT must be between 1 and 65535");
  }
  return port;
}

export function startLocalResolver(app: Koa, port: number): Server {
  return app.listen(port, "127.0.0.1");
}

const app = createLocalResolver();
startLocalResolver(app, localResolverPort(process.env.LOCAL_RESOLVER_PORT));
