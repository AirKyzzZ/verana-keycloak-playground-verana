import request from "supertest";
import { describe, expect, it } from "vitest";

import { createLocalResolver } from "../src/server.js";

const ISSUER = "did:web:issuer.localhost";
const VERIFIER = "did:web:verifier.localhost";
const ROGUE = "did:web:rogue.localhost";
const VCT = "http://host.docker.internal:3099/vct/local-controlled-employee";
const VTJSC =
  "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json";
const CONTROL_TOKEN =
  "test-control-token-with-at-least-thirty-two-bytes-of-entropy";
const CONTROL_PATH = "/_local-controlled/resolver-fault";

function resolver() {
  return request(createLocalResolver().callback());
}

function controlledResolver(now: () => number = () => Date.now()) {
  return request(
    createLocalResolver({
      controlToken: CONTROL_TOKEN,
      evidenceMode: "LOCAL_CONTROLLED",
      now,
    }).callback(),
  );
}

function authorize<T extends { set(name: string, value: string): T }>(
  operation: T,
): T {
  return operation.set("authorization", `Bearer ${CONTROL_TOKEN}`);
}

describe("controlled local trust resolver", () => {
  it.each([
    [ISSUER, { did: ISSUER, trustStatus: "TRUSTED", production: true }],
    [VERIFIER, { did: VERIFIER, trustStatus: "TRUSTED", production: true }],
    [ROGUE, { did: ROGUE, trustStatus: "UNTRUSTED", production: false }],
  ])("returns exact Q1 for %s", async (did, expected) => {
    const response = await resolver().get("/v1/trust/resolve").query({ did });

    expect(response.status).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toEqual(expected);
  });

  it.each([
    ["/v1/trust/issuer-authorization", ISSUER, true],
    ["/v1/trust/issuer-authorization", VERIFIER, false],
    ["/v1/trust/verifier-authorization", VERIFIER, true],
    ["/v1/trust/verifier-authorization", ROGUE, false],
  ])(
    "binds authorization to role, DID, and VTJSC",
    async (path, did, authorized) => {
      const response = await resolver()
        .get(path)
        .query({ did, vtjscId: VTJSC });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({ did, vtjscId: VTJSC, authorized });
    },
  );

  it.each([
    ["/v1/trust/resolve", {}],
    ["/v1/trust/resolve", { did: "" }],
    ["/v1/trust/resolve?did=first&did=second", undefined],
    ["/v1/trust/issuer-authorization", { did: ISSUER }],
    ["/v1/trust/issuer-authorization", { vtjscId: VTJSC }],
    ["/v1/trust/verifier-authorization", { did: "", vtjscId: VTJSC }],
    ["/v1/trust/verifier-authorization", { did: VERIFIER, vtjscId: "" }],
    [
      `/v1/trust/issuer-authorization?did=${encodeURIComponent(ISSUER)}&vtjscId=one&vtjscId=two`,
      undefined,
    ],
  ])("rejects malformed required queries", async (path, query) => {
    const response = query
      ? await resolver().get(path).query(query)
      : await resolver().get(path);

    expect(response.status).toBe(400);
    expect(response.type).toBe("application/json");
    expect(response.headers["cache-control"]).toBe("no-store");
  });

  it("returns untrusted Q1 for an unknown DID", async () => {
    const response = await resolver()
      .get("/v1/trust/resolve")
      .query({ did: "did:web:unknown.localhost" });

    expect(response.body).toEqual({
      did: "did:web:unknown.localhost",
      trustStatus: "UNTRUSTED",
      production: false,
    });
  });

  it("rejects a correct issuer DID with a different VTJSC", async () => {
    const response = await resolver()
      .get("/v1/trust/issuer-authorization")
      .query({ did: ISSUER, vtjscId: "http://example.test/other.json" });

    expect(response.body).toEqual({
      did: ISSUER,
      vtjscId: "http://example.test/other.json",
      authorized: false,
    });
  });

  it("exposes the exact health payload", async () => {
    const response = await resolver().get("/health");

    expect(response.status).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toEqual({ status: "ok" });
  });

  it("serves local VCT and VTJSC documents with their exact identifiers", async () => {
    const [vct, vtjsc] = await Promise.all([
      resolver().get("/vct/local-controlled-employee"),
      resolver().get("/vtjsc/local-controlled-employee.json"),
    ]);

    expect(vct.status).toBe(200);
    expect(vct.type).toBe("application/json");
    expect(vct.headers["cache-control"]).toBe("no-store");
    expect(vct.body.vct).toBe(VCT);
    expect(vtjsc.status).toBe(200);
    expect(vtjsc.type).toBe("application/json");
    expect(vtjsc.headers["cache-control"]).toBe("no-store");
    expect(vtjsc.body.id).toBe(VTJSC);
  });

  it.each([
    "/health",
    "/v1/trust/resolve?did=did%3Aweb%3Aissuer.localhost",
    `/v1/trust/issuer-authorization?did=${encodeURIComponent(ISSUER)}&vtjscId=${encodeURIComponent(VTJSC)}`,
    "/vct/local-controlled-employee",
    "/vtjsc/local-controlled-employee.json",
  ])(
    "keeps the serialized response below 65,536 bytes for %s",
    async (path) => {
      const response = await resolver().get(path);

      expect(Buffer.byteLength(response.text)).toBeLessThan(65_536);
    },
  );

  it.each([
    ["POST", "/health"],
    ["POST", "/v1/trust/resolve"],
    ["POST", "/v1/trust/issuer-authorization"],
    ["POST", "/v1/trust/verifier-authorization"],
    ["POST", "/vct/local-controlled-employee"],
    ["POST", "/vtjsc/local-controlled-employee.json"],
    ["GET", "/not-a-route"],
  ])(
    "returns 404 for unknown paths and method mismatches",
    async (method, path) => {
      const response =
        method === "GET"
          ? await resolver().get(path)
          : await resolver().post(path);

      expect(response.status).toBe(404);
      expect(response.type).toBe("application/json");
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.body).toEqual({ error: "not_found" });
    },
  );
});

describe("controlled local resolver faults", () => {
  it("does not register control routes without both explicit controlled mode and a token", async () => {
    const withoutOptions = await resolver().get(CONTROL_PATH);
    const liveWithToken = await request(
      createLocalResolver({
        controlToken: CONTROL_TOKEN,
        evidenceMode: "LIVE_VERANA",
      }).callback(),
    )
      .get(CONTROL_PATH)
      .set("authorization", `Bearer ${CONTROL_TOKEN}`);

    expect(withoutOptions.status).toBe(404);
    expect(liveWithToken.status).toBe(404);
  });

  it("requires the exact bearer token without reflecting rejected credentials", async () => {
    const missing = await controlledResolver().get(CONTROL_PATH);
    const rejectedToken = "different-control-token-that-must-not-be-reflected";
    const wrong = await controlledResolver()
      .get(CONTROL_PATH)
      .set("authorization", `Bearer ${rejectedToken}`);

    expect(missing.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(missing.body).toEqual({ error: "unauthorized" });
    expect(wrong.body).toEqual({ error: "unauthorized" });
    expect(wrong.text).not.toContain(rejectedToken);
    expect(wrong.text).not.toContain(CONTROL_TOKEN);
  });

  it("targets only the next exact verifier Q1 request and consumes before responding", async () => {
    const agent = controlledResolver();

    const armed = await authorize(agent.post(`${CONTROL_PATH}/unavailable`));
    const issuerQ1 = await agent
      .get("/v1/trust/resolve")
      .query({ did: ISSUER });
    const verifierQ3 = await agent
      .get("/v1/trust/verifier-authorization")
      .query({ did: VERIFIER, vtjscId: VTJSC });
    const verifierQ1 = await agent
      .get("/v1/trust/resolve")
      .query({ did: VERIFIER });
    const statusAfterFault = await authorize(agent.get(CONTROL_PATH));
    const verifierRetry = await agent
      .get("/v1/trust/resolve")
      .query({ did: VERIFIER });

    expect(armed.status).toBe(201);
    expect(issuerQ1.body).toEqual({
      did: ISSUER,
      trustStatus: "TRUSTED",
      production: true,
    });
    expect(verifierQ3.body.authorized).toBe(true);
    expect(verifierQ1.status).toBe(503);
    expect(Buffer.byteLength(verifierQ1.text)).toBeLessThan(1_024);
    expect(verifierQ1.body).toEqual({ error: "resolver_unavailable" });
    expect(statusAfterFault.body).toEqual({ armed: false });
    expect(verifierRetry.status).toBe(200);
    expect(verifierRetry.body.trustStatus).toBe("TRUSTED");
  });

  it.each(["malformed-json", "oversized-body"] as const)(
    "serves one exact %s fault and then restores normal Q1",
    async (mode) => {
      const agent = controlledResolver();
      await authorize(agent.post(`${CONTROL_PATH}/${mode}`)).expect(201);

      const fault = await agent
        .get("/v1/trust/resolve")
        .query({ did: VERIFIER })
        .buffer(true)
        .parse((response, callback) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () =>
            callback(null, Buffer.concat(chunks).toString("utf8")),
          );
        });
      const retry = await agent
        .get("/v1/trust/resolve")
        .query({ did: VERIFIER });

      expect(fault.status).toBe(200);
      expect(fault.type).toBe("application/json");
      if (mode === "malformed-json") {
        expect(fault.body).toBe('{"did":');
      } else {
        expect(Buffer.byteLength(fault.body as string)).toBeGreaterThan(65_536);
      }
      expect(retry.status).toBe(200);
      expect(retry.body.trustStatus).toBe("TRUSTED");
    },
  );

  it("expires an armed fault after thirty seconds", async () => {
    let now = Date.parse("2026-07-25T00:00:00.000Z");
    const agent = controlledResolver(() => now);
    await authorize(agent.post(`${CONTROL_PATH}/unavailable`)).expect(201);

    now += 30_001;
    const status = await authorize(agent.get(CONTROL_PATH));
    const verifierQ1 = await agent
      .get("/v1/trust/resolve")
      .query({ did: VERIFIER });

    expect(status.body).toEqual({ armed: false });
    expect(verifierQ1.status).toBe(200);
  });

  it("rejects overwrite while armed and supports authenticated reset", async () => {
    const agent = controlledResolver();
    await authorize(agent.post(`${CONTROL_PATH}/unavailable`)).expect(201);

    const overwrite = await authorize(
      agent.post(`${CONTROL_PATH}/malformed-json`),
    );
    const reset = await authorize(agent.delete(CONTROL_PATH));
    const status = await authorize(agent.get(CONTROL_PATH));

    expect(overwrite.status).toBe(409);
    expect(overwrite.body).toEqual({ error: "fault_already_armed" });
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ armed: false });
    expect(status.body).toEqual({ armed: false });
  });
});
