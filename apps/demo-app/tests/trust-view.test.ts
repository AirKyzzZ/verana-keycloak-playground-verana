import { describe, expect, it } from "vitest";

import type {
  ResolvedPresentation,
  ReviewedOffer,
} from "../src/local-wallet-client.js";
import {
  holderTrustState,
  offerProofOfTrust,
  presentationProofOfTrust,
} from "../src/trust-view.js";

const BLOCK_ORDER = [
  "Trust status",
  "Service",
  "Operator",
  "Other credentials",
  "Trust chain and failures",
];

function resolution(
  overrides: Partial<ResolvedPresentation> = {},
): ResolvedPresentation {
  return {
    gateId: "gate-1",
    verdict: "TRUSTED_AUTHORIZED",
    evidence: {
      did: "did:web:verifier.localhost%3A3443",
      trustStatus: "TRUSTED",
      authorized: true,
      vtjscId: "https://resolver.localhost:3443/vtjsc/x.json",
      queries: ["https://resolver.localhost:3443/v4/verifiable-trust/resolve"],
    },
    request: {
      clientId: "verifier.localhost",
      clientIdPrefix: "decentralized_identifier",
      verifierDid: "did:web:verifier.localhost%3A3443",
      unverifiedClaimedDid: "did:web:verifier.localhost%3A3443",
      requestedVct: "https://resolver.localhost:3443/vct/employee",
      requestedClaims: ["subject_id", "organization", "role"],
    },
    ...overrides,
  } as ResolvedPresentation;
}

function review(overrides: Partial<ReviewedOffer> = {}): ReviewedOffer {
  return {
    gateId: "gate-1",
    verdict: "TRUSTED_AUTHORIZED",
    issuerDid: "did:web:issuer.localhost%3A3443",
    credentialIssuer: "https://issuer.localhost:3443/oid4vci/unfold",
    evidence: {
      did: "did:web:issuer.localhost%3A3443",
      trustStatus: "TRUSTED",
      authorized: true,
      vtjscId: "https://resolver.localhost:3443/vtjsc/x.json",
      queries: ["https://resolver.localhost:3443/v4/verifiable-trust/resolve"],
    },
    ...overrides,
  } as ReviewedOffer;
}

describe("holder trust state mapping", () => {
  it("treats only an exact TRUSTED_AUTHORIZED as trusted", () => {
    expect(holderTrustState("TRUSTED_AUTHORIZED")).toBe("TRUSTED");
  });

  // The whole point of the mapping: a trusted-but-unauthorized party must never
  // render as trusted, or the UI would show a green check for a party with no
  // authority over this credential.
  it("never renders TRUSTED_NOT_AUTHORIZED as trusted", () => {
    expect(holderTrustState("TRUSTED_NOT_AUTHORIZED")).toBe("UNTRUSTED");
  });

  it("maps an unreachable resolver to UNVERIFIED, not UNTRUSTED", () => {
    expect(holderTrustState("RESOLVER_UNAVAILABLE")).toBe("UNVERIFIED");
  });

  it("maps UNTRUSTED to UNTRUSTED", () => {
    expect(holderTrustState("UNTRUSTED")).toBe("UNTRUSTED");
  });
});

describe("proof-of-trust blocks", () => {
  it.each([
    ["presentation", () => presentationProofOfTrust(resolution())],
    ["offer", () => offerProofOfTrust(review())],
  ])("renders the five %s blocks in the required order", (_name, build) => {
    expect(build().blocks.map((block) => block.title)).toEqual(BLOCK_ORDER);
  });

  it("separates the authenticated DID from the merely claimed one", () => {
    const view = presentationProofOfTrust(
      resolution({
        verdict: "UNTRUSTED",
        request: {
          ...resolution().request,
          verifierDid: null,
          unverifiedClaimedDid: "did:web:verifier.localhost%3A3443:rogue",
        },
      }),
    );

    const service = view.blocks.find((block) => block.title === "Service");
    expect(
      service?.rows.find((row) => row.label === "Authenticated verifier DID")
        ?.value,
    ).toBe("Not available");
    expect(
      service?.rows.find((row) => row.label.startsWith("Claimed DID"))?.value,
    ).toBe("did:web:verifier.localhost%3A3443:rogue");
  });

  it("says plainly when identity failed before any registry lookup", () => {
    const view = presentationProofOfTrust(
      resolution({
        verdict: "UNTRUSTED",
        evidence: { ...resolution().evidence, queries: [] },
      }),
    );

    const chain = view.blocks.at(-1);
    expect(chain?.rows[0]?.value).toContain("before any registry lookup");
  });

  it("headlines a refused verifier without implying disclosure", () => {
    const view = presentationProofOfTrust(
      resolution({ verdict: "TRUSTED_NOT_AUTHORIZED" }),
    );

    expect(view.state).toBe("UNTRUSTED");
    expect(view.headline).toContain("Nothing is disclosed");
  });

  it("distinguishes an unverifiable resolver from a refusal", () => {
    const view = offerProofOfTrust(
      review({ verdict: "RESOLVER_UNAVAILABLE", gateId: "" }),
    );

    expect(view.state).toBe("UNVERIFIED");
    expect(view.headline).toContain("did not answer");
  });
});

describe("issuance refusal rendering", () => {
  it("renders the refusal as a proof-of-trust view, not a transport error", () => {
    const view = offerProofOfTrust(
      review({ verdict: "TRUSTED_NOT_AUTHORIZED", gateId: "" }),
    );

    expect(view.state).toBe("UNTRUSTED");
    expect(view.blocks.map((block) => block.title)).toEqual(BLOCK_ORDER);
    expect(view.headline).not.toContain("failed");
  });
});
