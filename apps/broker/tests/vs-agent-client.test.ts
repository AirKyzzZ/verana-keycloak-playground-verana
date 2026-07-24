/// <reference types="node" />

import { createServer, type Server } from "node:http";

import { afterEach, describe, expect, it, vi } from "vitest";

import { loadBrokerConfig } from "../src/config.js";
import { VsAgentClient } from "../src/vs-agent-client.js";

const servers: Server[] = [];

async function listen(
  handler: Parameters<typeof createServer>[0],
): Promise<{ baseUrl: string; server: Server }> {
  const server = createServer(handler);
  servers.push(server);

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  const address = server.address();
  if (!address || typeof address === "string") throw new Error("listen_failed");

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    server,
  };
}

afterEach(async () => {
  vi.restoreAllMocks();

  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.closeAllConnections();
          server.close((error) => {
            if (error) reject(error);
            else resolve();
          });
        }),
    ),
  );
});

describe("broker configuration", () => {
  it("keeps the broker and verifier VS Agent on distinct default ports", () => {
    const config = loadBrokerConfig({
      BROKER_CLIENT_SECRET: "b".repeat(32),
      EXPECTED_VCT: "https://demo.example/vct",
      EXPECTED_VTJSC_ID: "https://demo.example/schema",
      PAIRWISE_SUB_SECRET: "p".repeat(32),
    });

    expect(config.BROKER_ISSUER).toBe("http://localhost:3001");
    expect(config.BROKER_PORT).toBe(3001);
    expect(config.VS_AGENT_VERIFIER_BASE_URL).toBe("http://localhost:3201");
  });
});

describe("VsAgentClient", () => {
  it("creates a trusted request from a strictly parsed response", async () => {
    let requestBody: unknown;
    const { baseUrl } = await listen((request, response) => {
      if (
        request.method !== "POST" ||
        request.url !== "/oid4vc-demo/verifier/requests"
      ) {
        response.writeHead(404).end();
        return;
      }

      const chunks: Buffer[] = [];
      request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      request.on("end", () => {
        requestBody = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        response.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            authorizationRequest: "openid4vp://request",
            sessionId: "vs-1",
          }),
        );
      });
    });
    const nativeFetch = globalThis.fetch;
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation((input, init) => nativeFetch(input, init));

    await expect(
      new VsAgentClient(baseUrl).createRequest("trusted"),
    ).resolves.toEqual({
      authorizationRequest: "openid4vp://request",
      sessionId: "vs-1",
    });
    expect(requestBody).toEqual({ tenant: "trusted" });
    expect(fetchSpy.mock.calls[0]?.[1]).toMatchObject({
      cache: "no-store",
    });
    expect(fetchSpy.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
  });

  it.each([
    {
      authorizationRequest: "",
      sessionId: "vs-1",
    },
    {
      authorizationRequest: "openid4vp://request",
      sessionId: "",
    },
    {
      authorizationRequest: "openid4vp://request",
      sessionId: "vs-1",
      unexpected: true,
    },
  ])("rejects an invalid request response", async (body) => {
    const { baseUrl } = await listen((_request, response) => {
      response
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(body));
    });

    await expect(
      new VsAgentClient(baseUrl).createRequest("trusted"),
    ).rejects.toThrow("vs_agent_unavailable");
  });

  it.each([
    {
      status: 503,
      body: JSON.stringify({ error: "sensitive-upstream-message" }),
    },
    { status: 200, body: "not-json" },
  ])(
    "maps non-2xx and malformed JSON to vs_agent_unavailable",
    async ({ status, body }) => {
      const { baseUrl } = await listen((_request, response) => {
        response
          .writeHead(status, { "content-type": "application/json" })
          .end(body);
      });

      await expect(
        new VsAgentClient(baseUrl).getSession("vs-1"),
      ).rejects.toThrow("vs_agent_unavailable");
    },
  );

  it("aborts polling after three seconds", async () => {
    const { baseUrl } = await listen((_request, _response) => {});
    const startedAt = performance.now();

    await expect(new VsAgentClient(baseUrl).getSession("vs-1")).rejects.toThrow(
      "vs_agent_unavailable",
    );

    const elapsed = performance.now() - startedAt;
    expect(elapsed).toBeGreaterThanOrEqual(2_800);
    expect(elapsed).toBeLessThan(4_500);
  }, 6_000);
});
