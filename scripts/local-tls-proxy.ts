import type { IncomingMessage, ServerResponse } from "node:http";
import { request as httpRequest } from "node:http";
import { createServer, type Server } from "node:https";
import type { Socket } from "node:net";
import type { TLSSocket } from "node:tls";

export const LOCAL_TLS_ROUTES = Object.freeze({
  "issuer.localhost": 3101,
  "holder.localhost": 3111,
  "verifier.localhost": 3201,
  "resolver.localhost": 3099,
});

export const LOCAL_TLS_GATEWAY_PORT = 3443;

const DEFAULT_MAXIMUM_BODY_BYTES = 8 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 15_000;
const SHUTDOWN_GRACE_MS = 5_000;

const SANITIZED_FAILURE = JSON.stringify({
  error: "local_controlled_gateway_failure",
});

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const BLOCKED_METHODS = new Set(["CONNECT", "TRACE", "TRACK"]);

export interface LocalTlsProxyOptions {
  certificate: Buffer;
  privateKey: Buffer;
  routes?: Readonly<Record<string, number>>;
  requestTimeoutMs?: number;
  maximumBodyBytes?: number;
}

type GatewayEvent =
  | "LOCAL_CONTROLLED TLS_GATEWAY_READY"
  | "LOCAL_CONTROLLED TLS_GATEWAY_REJECTED"
  | "LOCAL_CONTROLLED TLS_GATEWAY_UPSTREAM_FAILED";

function emit(event: GatewayEvent): void {
  process.stdout.write(`${event}\n`);
}

function respond(res: ServerResponse, status: number): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(SANITIZED_FAILURE),
  });
  res.end(SANITIZED_FAILURE);
}

// The Host header must be exactly an allowlisted name, optionally carrying the
// gateway port. Anything else, including a second Host header, is refused
// before an upstream is selected.
function resolveHost(
  header: string | string[] | undefined,
  routes: Readonly<Record<string, number>>,
): string | null {
  if (typeof header !== "string") return null;
  const [name, port, ...rest] = header.trim().split(":");
  if (rest.length > 0) return null;
  if (!name) return null;
  if (port !== undefined && port !== String(LOCAL_TLS_GATEWAY_PORT))
    return null;
  return Object.hasOwn(routes, name) ? name : null;
}

// Node keeps only the first Host when a request carries several, so the
// duplicate has to be counted on the raw header list to be refused at all.
function countHostHeaders(rawHeaders: readonly string[]): number {
  let count = 0;
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index]?.toLowerCase() === "host") count += 1;
  }
  return count;
}

function forwardableHeaders(
  headers: IncomingMessage["headers"],
): Record<string, string | string[]> {
  const nominated = new Set<string>();
  const connection = headers.connection;
  if (typeof connection === "string") {
    for (const token of connection.split(",")) {
      const name = token.trim().toLowerCase();
      if (name) nominated.add(name);
    }
  }

  const result: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower) || nominated.has(lower)) continue;
    if (value === undefined) continue;
    result[lower] = value;
  }
  return result;
}

export function createLocalTlsProxy(options: LocalTlsProxyOptions): Server {
  const routes: Readonly<Record<string, number>> =
    options.routes ?? LOCAL_TLS_ROUTES;
  const maximumBodyBytes =
    options.maximumBodyBytes ?? DEFAULT_MAXIMUM_BODY_BYTES;
  const timeoutMs = options.requestTimeoutMs ?? UPSTREAM_TIMEOUT_MS;

  const sockets = new Set<Socket>();

  const server = createServer(
    {
      cert: options.certificate,
      key: options.privateKey,
      minVersion: "TLSv1.2",
      maxHeaderSize: 16 * 1024,
      requestTimeout: timeoutMs,
      headersTimeout: timeoutMs,
      keepAliveTimeout: SHUTDOWN_GRACE_MS,
    },
    (req, res) => {
      const method = req.method ?? "";
      if (BLOCKED_METHODS.has(method.toUpperCase())) {
        emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
        respond(res, 405);
        return;
      }

      if (countHostHeaders(req.rawHeaders) !== 1) {
        emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
        respond(res, 421);
        return;
      }

      const hostname = resolveHost(req.headers.host, routes);
      const servername = (req.socket as TLSSocket).servername;
      if (
        !hostname ||
        typeof servername !== "string" ||
        servername !== hostname
      ) {
        emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
        respond(res, 421);
        return;
      }

      const port = routes[hostname];
      if (port === undefined) {
        emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
        respond(res, 421);
        return;
      }

      const declared = Number(req.headers["content-length"] ?? "0");
      if (Number.isFinite(declared) && declared > maximumBodyBytes) {
        emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
        respond(res, 413);
        return;
      }

      const upstream = httpRequest(
        {
          host: "127.0.0.1",
          port,
          method,
          path: req.url ?? "/",
          headers: forwardableHeaders(req.headers),
          timeout: timeoutMs,
        },
        (upstreamRes) => {
          const declaredResponse = Number(
            upstreamRes.headers["content-length"] ?? "0",
          );
          if (
            Number.isFinite(declaredResponse) &&
            declaredResponse > maximumBodyBytes
          ) {
            emit("LOCAL_CONTROLLED TLS_GATEWAY_UPSTREAM_FAILED");
            upstreamRes.destroy();
            respond(res, 502);
            return;
          }

          res.writeHead(
            upstreamRes.statusCode ?? 502,
            forwardableHeaders(upstreamRes.headers),
          );

          let streamed = 0;
          upstreamRes.on("data", (chunk: Buffer) => {
            streamed += chunk.length;
            if (streamed > maximumBodyBytes) {
              // Headers are already sent, so the only safe action is to abort
              // both sides rather than imply a complete response.
              emit("LOCAL_CONTROLLED TLS_GATEWAY_UPSTREAM_FAILED");
              upstreamRes.destroy();
              res.destroy();
              return;
            }
            res.write(chunk);
          });
          upstreamRes.on("end", () => res.end());
          upstreamRes.on("error", () => res.destroy());
        },
      );

      upstream.on("timeout", () => upstream.destroy());
      upstream.on("error", () => {
        emit("LOCAL_CONTROLLED TLS_GATEWAY_UPSTREAM_FAILED");
        respond(res, 502);
      });

      let received = 0;
      req.on("data", (chunk: Buffer) => {
        received += chunk.length;
        if (received > maximumBodyBytes) {
          emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
          upstream.destroy();
          respond(res, 413);
          return;
        }
        upstream.write(chunk);
      });
      req.on("end", () => upstream.end());
      req.on("error", () => upstream.destroy());
    },
  );

  server.on("connection", (socket: Socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });

  server.on("upgrade", (_req, socket: Socket) => {
    emit("LOCAL_CONTROLLED TLS_GATEWAY_REJECTED");
    socket.destroy();
  });

  server.on("listening", () => emit("LOCAL_CONTROLLED TLS_GATEWAY_READY"));

  Reflect.set(server, Symbol.for("localTlsSockets"), sockets);
  return server;
}

export async function closeLocalTlsProxy(server: Server): Promise<void> {
  const sockets =
    (Reflect.get(server, Symbol.for("localTlsSockets")) as
      | Set<Socket>
      | undefined) ?? new Set<Socket>();

  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve();
    };

    server.close(() => finish());
    server.closeIdleConnections();

    const timer = setTimeout(() => {
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      finish();
    }, SHUTDOWN_GRACE_MS);
    timer.unref();
  });
}
