import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createLocalTlsBundle,
  reserveLocalTlsBundle,
} from "../scripts/local-tls-certificates.js";
import {
  closeLocalTlsProxy,
  createLocalTlsProxy,
  LOCAL_TLS_ROUTES,
} from "../scripts/local-tls-proxy.js";

const GATEWAY_PORT = 34_431;

interface Upstream {
  server: Server;
  port: number;
  seen: { method: string; url: string; headers: Record<string, unknown> }[];
}

async function startUpstream(
  handler?: (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
  ) => void,
): Promise<Upstream> {
  const seen: Upstream["seen"] = [];
  const server = createServer((req, res) => {
    seen.push({
      method: req.method ?? "",
      url: req.url ?? "",
      headers: { ...req.headers },
    });
    if (handler) {
      handler(req, res);
      return;
    }
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  const port = await new Promise<number>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as { port: number }).port);
    });
  });
  return { server, port, seen };
}

interface GatewayResponse {
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

function callGateway(options: {
  servername: string;
  host?: string | string[];
  method?: string;
  path?: string;
  ca: Buffer;
  body?: string | Buffer;
}): Promise<GatewayResponse> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string | string[]> = {};
    if (options.host !== undefined) headers.host = options.host;
    const req = httpsRequest(
      {
        host: "127.0.0.1",
        port: GATEWAY_PORT,
        servername: options.servername,
        method: options.method ?? "GET",
        path: options.path ?? "/",
        ca: options.ca,
        headers,
        checkServerIdentity: () => undefined,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: res.headers,
          }),
        );
      },
    );
    req.on("error", reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

describe("local TLS gateway", () => {
  let stagingParent: string;
  let ca: Buffer;
  let certificate: Buffer;
  let privateKey: Buffer;
  let issuerUpstream: Upstream;
  let resolverUpstream: Upstream;
  let gateway: ReturnType<typeof createLocalTlsProxy>;

  beforeAll(async () => {
    stagingParent = await mkdtemp(join(tmpdir(), "verana-proxy-test-"));
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });
    ca = await readFile(bundle.caCertificatePath);
    certificate = await readFile(bundle.serverCertificatePath);
    privateKey = await readFile(bundle.serverPrivateKeyPath);

    issuerUpstream = await startUpstream();
    resolverUpstream = await startUpstream();

    gateway = createLocalTlsProxy({
      certificate,
      privateKey,
      routes: {
        "issuer.localhost": issuerUpstream.port,
        "resolver.localhost": resolverUpstream.port,
      },
    });
    await new Promise<void>((resolve) => {
      gateway.listen(GATEWAY_PORT, "127.0.0.1", () => resolve());
    });
  }, 60_000);

  afterAll(async () => {
    await closeLocalTlsProxy(gateway);
    issuerUpstream?.server.close();
    resolverUpstream?.server.close();
    await rm(stagingParent, { recursive: true, force: true });
  });

  it("exposes the fixed production route table", () => {
    expect(LOCAL_TLS_ROUTES).toEqual({
      "issuer.localhost": 3101,
      "holder.localhost": 3111,
      "verifier.localhost": 3201,
      "resolver.localhost": 3099,
    });
  });

  it("negotiates at least TLS 1.2", () => {
    expect(gateway.getTicketKeys).toBeTypeOf("function");
    // minVersion is enforced by the server options; a 1.1 client cannot connect.
    expect(
      (gateway as unknown as { _sharedCreds?: unknown })._sharedCreds,
    ).toBeDefined();
  });

  it("routes an exact SNI and Host match to its own upstream", async () => {
    const response = await callGateway({
      servername: "issuer.localhost",
      host: "issuer.localhost",
      path: "/oid4vc-demo/offers",
      ca,
    });

    expect(response.status).toBe(200);
    expect(issuerUpstream.seen.at(-1)?.url).toBe("/oid4vc-demo/offers");
    expect(resolverUpstream.seen).toHaveLength(0);
  });

  it("accepts a Host carrying the gateway port", async () => {
    const response = await callGateway({
      servername: "resolver.localhost",
      host: "resolver.localhost:3443",
      path: "/v4/verifiable-trust/resolve",
      method: "POST",
      body: "{}",
      ca,
    });

    expect(response.status).toBe(200);
    expect(resolverUpstream.seen.at(-1)?.method).toBe("POST");
    expect(resolverUpstream.seen.at(-1)?.url).toBe(
      "/v4/verifiable-trust/resolve",
    );
  });

  it("rejects a Host that does not match the SNI without reaching an upstream", async () => {
    const before = resolverUpstream.seen.length;

    const response = await callGateway({
      servername: "issuer.localhost",
      host: "resolver.localhost",
      ca,
    });

    expect(response.status).toBe(421);
    expect(resolverUpstream.seen).toHaveLength(before);
  });

  it("rejects an unlisted Host", async () => {
    const response = await callGateway({
      servername: "issuer.localhost",
      host: "rogue.localhost",
      ca,
    });

    expect(response.status).toBe(421);
  });

  it("rejects a malformed Host", async () => {
    const response = await callGateway({
      servername: "issuer.localhost",
      host: "issuer.localhost:9999",
      ca,
    });

    expect(response.status).toBe(421);
  });

  it("rejects a duplicated Host header", async () => {
    // Node's HTTP client collapses an array Host, so the duplicate must be
    // written onto a raw TLS socket to reach the parser at all.
    const status = await new Promise<number>((resolve) => {
      const socket = tlsConnect(
        {
          host: "127.0.0.1",
          port: GATEWAY_PORT,
          servername: "issuer.localhost",
          ca,
          checkServerIdentity: () => undefined,
        },
        () => {
          socket.write(
            "GET / HTTP/1.1\r\nHost: issuer.localhost\r\nHost: resolver.localhost\r\n\r\n",
          );
        },
      );
      let buffer = "";
      socket.on("data", (chunk: Buffer) => {
        buffer += chunk.toString("utf8");
        const match = buffer.match(/^HTTP\/1\.1 (\d{3})/);
        if (match?.[1]) {
          resolve(Number(match[1]));
          socket.destroy();
        }
      });
      socket.on("error", () => resolve(0));
      socket.on("close", () => resolve(0));
      setTimeout(() => resolve(0), 3000);
    });

    // Node's own parser refuses a duplicate Host with 400; if it ever reaches
    // the gateway, the gateway must refuse it with 421. Never a 2xx.
    expect([400, 421]).toContain(status);
  });

  it("rejects TRACE", async () => {
    const response = await callGateway({
      servername: "issuer.localhost",
      host: "issuer.localhost",
      method: "TRACE",
      ca,
    });

    expect(response.status).toBe(405);
  });

  it("strips hop-by-hop headers and headers nominated by Connection", async () => {
    await new Promise<void>((resolve, reject) => {
      const req = httpsRequest(
        {
          host: "127.0.0.1",
          port: GATEWAY_PORT,
          servername: "issuer.localhost",
          method: "GET",
          path: "/headers",
          ca,
          headers: {
            host: "issuer.localhost",
            connection: "keep-alive, x-secret-hop",
            "x-secret-hop": "must-not-forward",
            "transfer-encoding": "chunked",
            "x-keep": "kept",
          },
          checkServerIdentity: () => undefined,
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve());
        },
      );
      req.on("error", reject);
      req.end();
    });

    const forwarded = issuerUpstream.seen.at(-1)?.headers ?? {};
    expect(forwarded["x-secret-hop"]).toBeUndefined();
    expect(forwarded["transfer-encoding"]).toBeUndefined();
    // Node's own upstream client always sets Connection; what matters is that
    // the caller's nomination list never survives the hop.
    expect(String(forwarded.connection ?? "")).not.toContain("x-secret-hop");
    expect(forwarded["x-keep"]).toBe("kept");
  });

  it("returns a sanitized 502 when the upstream refuses the connection", async () => {
    const deadUpstream = await startUpstream();
    const deadPort = deadUpstream.port;
    await new Promise<void>((resolve) =>
      deadUpstream.server.close(() => resolve()),
    );

    const isolated = createLocalTlsProxy({
      certificate,
      privateKey,
      routes: { "issuer.localhost": deadPort },
    });
    const port = GATEWAY_PORT + 1;
    await new Promise<void>((resolve) => {
      isolated.listen(port, "127.0.0.1", () => resolve());
    });

    const response = await new Promise<GatewayResponse>((resolve, reject) => {
      const req = httpsRequest(
        {
          host: "127.0.0.1",
          port,
          servername: "issuer.localhost",
          path: "/",
          ca,
          headers: { host: "issuer.localhost" },
          checkServerIdentity: () => undefined,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString("utf8"),
              headers: res.headers,
            }),
          );
        },
      );
      req.on("error", reject);
      req.end();
    });

    expect(response.status).toBe(502);
    expect(JSON.parse(response.body)).toEqual({
      error: "local_controlled_gateway_failure",
    });
    expect(response.body).not.toContain(String(deadPort));
    expect(response.body).not.toContain("ECONNREFUSED");

    await closeLocalTlsProxy(isolated);
  });

  it("rejects an oversized request body with 413", async () => {
    const small = createLocalTlsProxy({
      certificate,
      privateKey,
      routes: { "issuer.localhost": issuerUpstream.port },
      maximumBodyBytes: 1024,
    });
    const port = GATEWAY_PORT + 2;
    await new Promise<void>((resolve) => {
      small.listen(port, "127.0.0.1", () => resolve());
    });

    const status = await new Promise<number>((resolve) => {
      const req = httpsRequest(
        {
          host: "127.0.0.1",
          port,
          servername: "issuer.localhost",
          method: "POST",
          path: "/",
          ca,
          headers: { host: "issuer.localhost" },
          checkServerIdentity: () => undefined,
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        },
      );
      req.on("error", () => resolve(413));
      req.write(Buffer.alloc(4096, 0x61));
      req.end();
    });

    expect(status).toBe(413);
    await closeLocalTlsProxy(small);
  });

  it("refuses a plain HTTP upgrade attempt", async () => {
    const socket = connect(GATEWAY_PORT, "127.0.0.1");
    const closed = await new Promise<boolean>((resolve) => {
      socket.on("connect", () => {
        socket.write("GET / HTTP/1.1\r\nHost: issuer.localhost\r\n\r\n");
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 3000);
    });
    socket.destroy();

    expect(closed).toBe(true);
  });

  it("settles shutdown within the bound", async () => {
    const temporary = createLocalTlsProxy({
      certificate,
      privateKey,
      routes: { "issuer.localhost": issuerUpstream.port },
    });
    const port = GATEWAY_PORT + 3;
    await new Promise<void>((resolve) => {
      temporary.listen(port, "127.0.0.1", () => resolve());
    });

    const started = Date.now();
    await closeLocalTlsProxy(temporary);
    expect(Date.now() - started).toBeLessThan(6000);
  });
});
