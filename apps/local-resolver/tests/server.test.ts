import request from "supertest";
import { describe, expect, it } from "vitest";

import { createLocalResolver } from "../src/server.js";

const ISSUER = "did:web:issuer.localhost";
const VERIFIER = "did:web:verifier.localhost";
const ROGUE = "did:web:rogue.localhost";
const VCT = "http://host.docker.internal:3099/vct/local-controlled-employee";
const VTJSC =
  "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json";

function resolver() {
  return request(createLocalResolver().callback());
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
