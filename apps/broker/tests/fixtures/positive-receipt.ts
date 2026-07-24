import type { VsAgentSession } from "../../src/vs-agent-client.js";

export const EXPECTED_VCT = "https://demo.example/vct";
export const EXPECTED_VTJSC_ID = "https://demo.example/schema";

export const positiveSession = {
  state: "ResponseVerified",
  receipt: {
    exchange: {
      protocol: "OID4VP 1.0",
      vct: EXPECTED_VCT,
      sessionId: "vs-1",
      tenant: "trusted",
      verifiedAt: "2026-07-24T10:00:00.000Z",
    },
    verifier: {
      did: "did:web:verifier.example",
      verdict: "TRUSTED_AUTHORIZED",
      evidence: {
        did: "did:web:verifier.example",
        trustStatus: "TRUSTED",
        authorized: true,
        vtjscId: EXPECTED_VTJSC_ID,
        queries: ["q1", "q3"],
        note: "trusted verifier fixture",
      },
    },
    issuer: {
      did: "did:web:issuer.example",
      iss: "https://issuer.example",
      verdict: "TRUSTED_AUTHORIZED",
      evidence: {
        did: "did:web:issuer.example",
        trustStatus: "TRUSTED",
        authorized: true,
        vtjscId: EXPECTED_VTJSC_ID,
        queries: ["q1", "q2"],
      },
    },
    credential: {
      vct: EXPECTED_VCT,
      disclosedClaims: {
        subject_id: "user-1",
        organization: "ACME",
        role: "employee",
      },
    },
    registry: {
      network: "vna-testnet-1",
      trustRegistry: 184,
      schema: 249,
      vtjscId: EXPECTED_VTJSC_ID,
    },
  },
} satisfies VsAgentSession;
