import request from "supertest";
import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_SCHEMA_ID,
  ECOSYSTEM_ID,
  LINKED_VP_SERVICE_FRAGMENT,
  LOCAL_CONTROLLED_CONTRACT,
} from "../src/contract.js";
import {
  ECOSYSTEM_VERIFICATION_METHOD,
  verifyLinkedVerifiablePresentation,
} from "../src/ecosystem.js";
import { createLocalResolver } from "../src/server.js";

const ISSUER = LOCAL_CONTROLLED_CONTRACT.issuerDid;
const VERIFIER = LOCAL_CONTROLLED_CONTRACT.verifierDid;
const ROGUE = LOCAL_CONTROLLED_CONTRACT.rogueDid;
const RESOLVE_PATH = "/v4/verifiable-trust/resolve";
const CONTROL_TOKEN =
  "test-control-token-with-at-least-thirty-two-bytes-of-entropy";
const CONTROL_PATH = "/_local-controlled/resolver-fault";

const Q1_SELECTORS = {
  ecsCredentials: true,
  services: true,
  presentations: {
    unresolvableCredentialIds: true,
    invalidCredentialIds: true,
  },
  ecosystems: { credentialSchemas: { includeArchived: false } },
};

function q1Body(did: string) {
  return { did, ...Q1_SELECTORS };
}

function participationBody(did: string) {
  return { did, participations: { states: ["ACTIVE"] }, ...Q1_SELECTORS };
}

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

const UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

describe("controlled local v4 trust resolver", () => {
  it.each([ISSUER, VERIFIER])("returns a trusted Q1 for %s", async (did) => {
    const response = await resolver().post(RESOLVE_PATH).send(q1Body(did));

    expect(response.status).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body.did).toBe(did);
    expect(response.body.trusted).toBe(true);
    expect(response.body.evaluatedAtTime).toMatch(UTC_PATTERN);
    expect(response.body.expiresAtTime).toBeNull();
  });

  it("omits participations from a Q1 response and includes them for Q2", async () => {
    const [q1, q2] = await Promise.all([
      resolver().post(RESOLVE_PATH).send(q1Body(ISSUER)),
      resolver().post(RESOLVE_PATH).send(participationBody(ISSUER)),
    ]);

    expect(Object.hasOwn(q1.body, "participations")).toBe(false);
    expect(Object.hasOwn(q2.body, "participations")).toBe(true);
  });

  it("returns exactly the keys the strict v4 parser allows", async () => {
    const q1 = await resolver().post(RESOLVE_PATH).send(q1Body(ISSUER));
    const q2 = await resolver()
      .post(RESOLVE_PATH)
      .send(participationBody(ISSUER));

    const core = [
      "did",
      "trusted",
      "evaluatedAtTime",
      "evaluatedAtBlock",
      "expiresAtTime",
      "corporationId",
      "ecsCredentials",
      "presentations",
      "services",
      "ecosystems",
    ];
    expect(Object.keys(q1.body).sort()).toEqual([...core].sort());
    expect(Object.keys(q2.body).sort()).toEqual(
      [...core, "participations"].sort(),
    );
  });

  it("binds participation to the role the DID actually holds", async () => {
    const [issuer, verifier] = await Promise.all([
      resolver().post(RESOLVE_PATH).send(participationBody(ISSUER)),
      resolver().post(RESOLVE_PATH).send(participationBody(VERIFIER)),
    ]);

    expect(issuer.body.participations).toHaveLength(1);
    expect(issuer.body.participations[0].role).toBe("ISSUER");
    expect(issuer.body.participations[0].state).toBe("ACTIVE");
    expect(issuer.body.participations[0].ecosystemId).toBe(ECOSYSTEM_ID);
    expect(issuer.body.participations[0].credentialSchemaId).toBe(
      CREDENTIAL_SCHEMA_ID,
    );

    expect(verifier.body.participations[0].role).toBe("VERIFIER");
    // An issuer must never appear as a VERIFIER participant, and vice versa.
    expect(
      issuer.body.participations.some(
        (entry: { role: string }) => entry.role === "VERIFIER",
      ),
    ).toBe(false);
  });

  it("serves complete Linked-VP evidence for a trusted party", async () => {
    const response = await resolver().post(RESOLVE_PATH).send(q1Body(ISSUER));

    expect(response.body.presentations).toHaveLength(1);
    const presentation = response.body.presentations[0];
    expect(presentation.serviceId).toBe(
      `${ISSUER}${LINKED_VP_SERVICE_FRAGMENT}`,
    );
    expect(presentation.unresolvableCredentialIds).toEqual([]);
    expect(presentation.invalidCredentialIds).toEqual([]);
    expect(
      presentation.vtcCredentials.some(
        (reference: { ecosystemId: number; credentialSchemaId: number }) =>
          reference.ecosystemId === ECOSYSTEM_ID &&
          reference.credentialSchemaId === CREDENTIAL_SCHEMA_ID,
      ),
    ).toBe(true);
  });

  it("serves the ECS service and organization credentials", async () => {
    const response = await resolver().post(RESOLVE_PATH).send(q1Body(ISSUER));

    const schemas = response.body.ecsCredentials.map(
      (credential: { ecsSchema: string }) => credential.ecsSchema,
    );
    expect(schemas).toContain("ServiceCredential");
    expect(schemas).toContain("OrganizationCredential");
  });

  it.each([ROGUE, "did:web:unknown.localhost"])(
    "returns an untrusted, evidence-free response for %s",
    async (did) => {
      const response = await resolver().post(RESOLVE_PATH).send(q1Body(did));

      expect(response.status).toBe(200);
      expect(response.body.did).toBe(did);
      expect(response.body.trusted).toBe(false);
      expect(response.body.ecsCredentials).toEqual([]);
      expect(response.body.presentations).toEqual([]);
      expect(response.body.services).toEqual([]);
      expect(response.body.ecosystems).toEqual([]);
    },
  );

  it("returns no participations for an untrusted DID", async () => {
    const response = await resolver()
      .post(RESOLVE_PATH)
      .send(participationBody(ROGUE));

    expect(response.body.participations).toEqual([]);
  });

  it.each([
    ["missing did", {}],
    ["non-did string", { did: "https://issuer.localhost" }],
    ["array body", []],
    ["null did", { did: null }],
  ])("rejects a malformed request body: %s", async (_label, body) => {
    const response = await resolver().post(RESOLVE_PATH).send(body);

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_request" });
  });

  it("keeps a trusted response below the 64 KiB client bound", async () => {
    const response = await resolver()
      .post(RESOLVE_PATH)
      .send(participationBody(ISSUER));

    expect(Buffer.byteLength(response.text)).toBeLessThan(65_536);
  });

  it("exposes the exact health payload", async () => {
    const response = await resolver().get("/health");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("serves local VCT and VTJSC documents over the gateway origin", async () => {
    const [vct, vtjsc] = await Promise.all([
      resolver().get("/vct/local-controlled-employee"),
      resolver().get("/vtjsc/local-controlled-employee.json"),
    ]);

    expect(vct.body.vct).toBe(LOCAL_CONTROLLED_CONTRACT.vct);
    expect(vtjsc.body.id).toBe(LOCAL_CONTROLLED_CONTRACT.vtjscId);
    expect(LOCAL_CONTROLLED_CONTRACT.vct.startsWith("https://")).toBe(true);
  });

  it.each([
    ["GET", RESOLVE_PATH],
    ["GET", "/v1/trust/resolve"],
    ["GET", "/not-a-route"],
  ])("returns 404 for %s %s", async (method, path) => {
    const response =
      method === "GET"
        ? await resolver().get(path)
        : await resolver().post(path);

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "not_found" });
  });
});

describe("controlled local resolver faults", () => {
  it("does not register control routes without both controlled mode and a token", async () => {
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
    expect(wrong.text).not.toContain(rejectedToken);
    expect(wrong.text).not.toContain(CONTROL_TOKEN);
  });

  it("targets only the next verifier Q1 and leaves Q2 and issuance intact", async () => {
    const agent = controlledResolver();

    const armed = await authorize(agent.post(`${CONTROL_PATH}/unavailable`));
    const issuerQ1 = await agent.post(RESOLVE_PATH).send(q1Body(ISSUER));
    const verifierQ3 = await agent
      .post(RESOLVE_PATH)
      .send(participationBody(VERIFIER));
    const verifierQ1 = await agent.post(RESOLVE_PATH).send(q1Body(VERIFIER));
    const statusAfterFault = await authorize(agent.get(CONTROL_PATH));
    const verifierRetry = await agent.post(RESOLVE_PATH).send(q1Body(VERIFIER));

    expect(armed.status).toBe(201);
    expect(issuerQ1.body.trusted).toBe(true);
    expect(verifierQ3.body.participations[0].role).toBe("VERIFIER");
    expect(verifierQ1.status).toBe(503);
    expect(verifierQ1.body).toEqual({ error: "resolver_unavailable" });
    expect(statusAfterFault.body).toEqual({ armed: false });
    expect(verifierRetry.status).toBe(200);
    expect(verifierRetry.body.trusted).toBe(true);
  });

  it.each(["malformed-json", "oversized-body"] as const)(
    "serves one exact %s fault and then restores a normal Q1",
    async (mode) => {
      const agent = controlledResolver();
      await authorize(agent.post(`${CONTROL_PATH}/${mode}`)).expect(201);

      const fault = await agent
        .post(RESOLVE_PATH)
        .send(q1Body(VERIFIER))
        .buffer(true)
        .parse((response, callback) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.on("end", () =>
            callback(null, Buffer.concat(chunks).toString("utf8")),
          );
        });
      const retry = await agent.post(RESOLVE_PATH).send(q1Body(VERIFIER));

      expect(fault.status).toBe(200);
      if (mode === "malformed-json") {
        expect(fault.body).toBe('{"did":');
      } else {
        expect(Buffer.byteLength(fault.body as string)).toBeGreaterThan(65_536);
      }
      expect(retry.status).toBe(200);
      expect(retry.body.trusted).toBe(true);
    },
  );

  it("expires an armed fault after thirty seconds", async () => {
    let now = Date.parse("2026-07-25T00:00:00.000Z");
    const agent = controlledResolver(() => now);
    await authorize(agent.post(`${CONTROL_PATH}/unavailable`)).expect(201);

    now += 30_001;
    const status = await authorize(agent.get(CONTROL_PATH));
    const verifierQ1 = await agent.post(RESOLVE_PATH).send(q1Body(VERIFIER));

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

    expect(overwrite.status).toBe(409);
    expect(reset.status).toBe(200);
    expect(reset.body).toEqual({ armed: false });
  });
});

describe("ecosystem DID document and Linked VP", () => {
  it("serves a DID document whose id and verification method share one base DID", async () => {
    const response = await resolver().get("/ecosystem/did.json");

    expect(response.status).toBe(200);
    expect(response.type).toBe("application/did+ld+json");
    expect(response.body.id).toBe(LOCAL_CONTROLLED_CONTRACT.ecosystemDid);

    const method = response.body.verificationMethod[0];
    expect(method.id).toBe(ECOSYSTEM_VERIFICATION_METHOD);
    expect(
      method.id.startsWith(`${LOCAL_CONTROLLED_CONTRACT.ecosystemDid}#`),
    ).toBe(true);
    expect(method.controller).toBe(LOCAL_CONTROLLED_CONTRACT.ecosystemDid);
    expect(method.publicKeyJwk.crv).toBe("Ed25519");
    expect(response.body.assertionMethod).toContain(
      ECOSYSTEM_VERIFICATION_METHOD,
    );
  });

  it("keeps the published verification method stable across restarts", async () => {
    const [first, second] = await Promise.all([
      resolver().get("/ecosystem/did.json"),
      resolver().get("/ecosystem/did.json"),
    ]);

    expect(first.body.verificationMethod[0].publicKeyJwk).toEqual(
      second.body.verificationMethod[0].publicKeyJwk,
    );
  });

  it.each([
    ["2", LOCAL_CONTROLLED_CONTRACT.issuerDid],
    ["3", LOCAL_CONTROLLED_CONTRACT.verifierDid],
  ])(
    "serves a Linked VP for participant %s that verifies against the published key",
    async (participantId, holderDid) => {
      const response = await resolver().get(
        `/presentations/${participantId}-vtjsc-vp.jwt`,
      );

      expect(response.status).toBe(200);
      expect(response.type).toBe("application/jwt");

      const token = response.text;
      expect(verifyLinkedVerifiablePresentation(token)).toBe(true);

      const payloadPart = token.split(".")[1] ?? "";
      const payload = JSON.parse(
        Buffer.from(payloadPart, "base64url").toString("utf8"),
      );
      expect(payload.iss).toBe(LOCAL_CONTROLLED_CONTRACT.ecosystemDid);
      expect(payload.sub).toBe(holderDid);
      expect(payload.vp.holder).toBe(holderDid);
      expect(
        payload.vp.verifiableCredential[0].credentialSubject.serviceId,
      ).toBe(`${holderDid}${LINKED_VP_SERVICE_FRAGMENT}`);
    },
  );

  it("rejects a tampered Linked VP", async () => {
    const response = await resolver().get("/presentations/2-vtjsc-vp.jwt");
    const [header, payload, signature] = response.text.split(".");
    const forged = JSON.parse(
      Buffer.from(payload ?? "", "base64url").toString("utf8"),
    );
    forged.sub = LOCAL_CONTROLLED_CONTRACT.rogueDid;
    const tampered = `${header}.${Buffer.from(JSON.stringify(forged)).toString(
      "base64url",
    )}.${signature}`;

    expect(verifyLinkedVerifiablePresentation(tampered)).toBe(false);
  });

  it("returns 404 for an unknown participant presentation", async () => {
    const response = await resolver().get("/presentations/99-vtjsc-vp.jwt");

    expect(response.status).toBe(404);
  });

  it("advertises the served presentation URL as the service endpoint", async () => {
    const [trust, presentation] = await Promise.all([
      resolver().post(RESOLVE_PATH).send(q1Body(ISSUER)),
      resolver().get("/presentations/2-vtjsc-vp.jwt"),
    ]);

    const endpoint = trust.body.services[0].serviceEndpoint as string;
    expect(endpoint).toContain("/presentations/2-vtjsc-vp.jwt");
    expect(presentation.status).toBe(200);
  });
});
