import type {
  ResolvedPresentation,
  ReviewedOffer,
  VeranaVerdict,
} from "./local-wallet-client.js";

export type HolderTrustState =
  | "RESOLVING"
  | "TRUSTED"
  | "UNTRUSTED"
  | "UNVERIFIED";

export interface TrustBlock {
  title: string;
  rows: { label: string; value: string }[];
}

export interface ProofOfTrustView {
  state: HolderTrustState;
  verdict: VeranaVerdict;
  headline: string;
  blocks: TrustBlock[];
}

const UNAVAILABLE = "Not available";

// The agent's four verdicts do not map one-to-one onto the four holder states.
// TRUSTED_NOT_AUTHORIZED is deliberately shown as UNTRUSTED: a party that is a
// trusted service but is NOT an authorized participant for this credential must
// never render as a green check. Only an exact TRUSTED_AUTHORIZED is TRUSTED.
export function holderTrustState(verdict: VeranaVerdict): HolderTrustState {
  switch (verdict) {
    case "TRUSTED_AUTHORIZED":
      return "TRUSTED";
    case "RESOLVER_UNAVAILABLE":
      return "UNVERIFIED";
    default:
      return "UNTRUSTED";
  }
}

export function trustHeadline(
  state: HolderTrustState,
  party: "issuer" | "verifier",
): string {
  switch (state) {
    case "TRUSTED":
      return `This ${party} is a trusted, authorized participant.`;
    case "UNVERIFIED":
      return `This ${party} could not be verified. The trust registry did not answer.`;
    case "RESOLVING":
      return `Checking this ${party} against the trust registry.`;
    default:
      return `This ${party} is not both trusted and authorized. Nothing is disclosed.`;
  }
}

function chainRows(
  queries: readonly string[],
  note: string | undefined,
): { label: string; value: string }[] {
  const rows = queries.map((query, index) => ({
    label: `Registry query ${index + 1}`,
    value: query,
  }));
  if (rows.length === 0) {
    rows.push({
      label: "Registry queries",
      value: "None. Identity failed before any registry lookup.",
    });
  }
  if (note) rows.push({ label: "Reason", value: note });
  return rows;
}

// Five ordered blocks: trust status, service, operator, other credentials, then
// the trust chain and any failures.
export function presentationProofOfTrust(
  resolution: ResolvedPresentation,
): ProofOfTrustView {
  const state = holderTrustState(resolution.verdict);
  return {
    state,
    verdict: resolution.verdict,
    headline: trustHeadline(state, "verifier"),
    blocks: [
      {
        title: "Trust status",
        rows: [
          { label: "Holder state", value: state },
          { label: "Agent verdict", value: resolution.verdict },
          {
            label: "Registry trust status",
            value: resolution.evidence.trustStatus ?? UNAVAILABLE,
          },
          {
            label: "Authorized for this credential",
            value:
              resolution.evidence.authorized === null
                ? UNAVAILABLE
                : String(resolution.evidence.authorized),
          },
        ],
      },
      {
        title: "Service",
        rows: [
          {
            label: "Authenticated verifier DID",
            value: resolution.request.verifierDid ?? UNAVAILABLE,
          },
          {
            label: "Claimed DID (unauthenticated)",
            value: resolution.request.unverifiedClaimedDid ?? UNAVAILABLE,
          },
          {
            label: "Client identifier",
            value: `${resolution.request.clientIdPrefix}:${resolution.request.clientId}`,
          },
        ],
      },
      {
        title: "Operator",
        rows: [
          {
            label: "Registry-resolved DID",
            value: resolution.evidence.did ?? UNAVAILABLE,
          },
          {
            label: "Credential schema (VTJSC)",
            value: resolution.evidence.vtjscId ?? UNAVAILABLE,
          },
        ],
      },
      {
        title: "Other credentials",
        rows: [
          {
            label: "Requested credential type",
            value: resolution.request.requestedVct ?? UNAVAILABLE,
          },
          {
            label: "Requested claims",
            value:
              resolution.request.requestedClaims.join(", ") ||
              "None requested.",
          },
        ],
      },
      {
        title: "Trust chain and failures",
        rows: chainRows(resolution.evidence.queries, resolution.evidence.note),
      },
    ],
  };
}

export function offerProofOfTrust(review: ReviewedOffer): ProofOfTrustView {
  const state = holderTrustState(review.verdict);
  return {
    state,
    verdict: review.verdict,
    headline: trustHeadline(state, "issuer"),
    blocks: [
      {
        title: "Trust status",
        rows: [
          { label: "Holder state", value: state },
          { label: "Agent verdict", value: review.verdict },
          {
            label: "Registry trust status",
            value: review.evidence.trustStatus ?? UNAVAILABLE,
          },
          {
            label: "Authorized to issue",
            value:
              review.evidence.authorized === null
                ? UNAVAILABLE
                : String(review.evidence.authorized),
          },
        ],
      },
      {
        title: "Service",
        rows: [
          {
            label: "Authenticated issuer DID",
            value: review.issuerDid ?? UNAVAILABLE,
          },
          { label: "Credential issuer", value: review.credentialIssuer },
        ],
      },
      {
        title: "Operator",
        rows: [
          {
            label: "Registry-resolved DID",
            value: review.evidence.did ?? UNAVAILABLE,
          },
          {
            label: "Credential schema (VTJSC)",
            value: review.evidence.vtjscId ?? UNAVAILABLE,
          },
        ],
      },
      {
        title: "Other credentials",
        rows: [
          {
            label: "Offered credential type",
            value: review.evidence.vtjscId ? "Employee badge" : UNAVAILABLE,
          },
        ],
      },
      {
        title: "Trust chain and failures",
        rows: chainRows(review.evidence.queries, review.evidence.note),
      },
    ],
  };
}
