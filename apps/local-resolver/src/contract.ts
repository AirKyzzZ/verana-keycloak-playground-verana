export const ECOSYSTEM_ID = 184;
export const CREDENTIAL_SCHEMA_ID = 249;

// A CredentialSchema is one digestSri-identified document, so each ECS type has
// its own id and its own Participant entry, per the spec's worked example.
export const SERVICE_CREDENTIAL_SCHEMA_ID = 250;
export const ORGANIZATION_CREDENTIAL_SCHEMA_ID = 251;

export const LINKED_VP_SERVICE_FRAGMENT = "#vpr-schemas-249-vtjsc-vp";

const GATEWAY_ORIGIN = "https://resolver.localhost:3443";

export const LOCAL_CONTROLLED_CONTRACT = Object.freeze({
  issuerDid: "did:web:issuer.localhost%3A3443",
  holderDid: "did:web:holder.localhost%3A3443",
  verifierDid: "did:web:verifier.localhost%3A3443",
  rogueDid: "did:web:verifier.localhost%3A3443:rogue",
  ecosystemDid: "did:web:resolver.localhost%3A3443:ecosystem",
  vct: `${GATEWAY_ORIGIN}/vct/local-controlled-employee`,
  vtjscId: `${GATEWAY_ORIGIN}/vtjsc/local-controlled-employee.json`,
});

const PARTICIPANT_IDS = Object.freeze({
  ecosystem: 1,
  issuer: 2,
  verifier: 3,
  serviceCredential: 601,
  organizationCredential: 602,
  serviceCredentialIssuer: 801,
  organizationCredentialIssuer: 802,
});

const CORPORATION_ID = 1;
const EVALUATED_AT_BLOCK = 1_500_000;
const VS_OPERATOR = "verana1localcontrolledoperator";
const WEIGHT = "100uvna";
const VALID_FROM = "2026-01-01T00:00:00Z";
const VALID_UNTIL = "2027-01-01T00:00:00Z";
const EGF_ACTIVE_SINCE = "2026-01-01T00:00:00Z";
const EGF_DIGEST = "sha256-9lIug0Xn2WLGRMSGnGRQpQY1fHnMLtqZ4Nd0LzYuFmU=";
const SCHEMA_DIGEST =
  "sha384-VmZ0b3AwbGVnaXRkaWdlc3RmaXh0dXJlZm9ybG9jYWxjb250cm9sbGVk";

export type ParticipantRole =
  | "HOLDER"
  | "ISSUER"
  | "VERIFIER"
  | "ISSUER_GRANTOR"
  | "VERIFIER_GRANTOR"
  | "ECOSYSTEM";

export interface ResolveSelection {
  did: string;
  withParticipations: boolean;
  withEcsCredentials: boolean;
  withServices: boolean;
  withPresentations: boolean;
  withPresentationCredentialIds: boolean;
  withEcosystems: boolean;
}

// The strict v4 parser rejects any timestamp carrying a sub-second component.
function utc(milliseconds: number): string {
  return `${new Date(milliseconds).toISOString().slice(0, 19)}Z`;
}

function participantIdFor(did: string): number {
  if (did === LOCAL_CONTROLLED_CONTRACT.issuerDid)
    return PARTICIPANT_IDS.issuer;
  if (did === LOCAL_CONTROLLED_CONTRACT.verifierDid) {
    return PARTICIPANT_IDS.verifier;
  }
  return 0;
}

export function isTrustedDid(did: string): boolean {
  return (
    did === LOCAL_CONTROLLED_CONTRACT.issuerDid ||
    did === LOCAL_CONTROLLED_CONTRACT.verifierDid
  );
}

function roleFor(did: string): ParticipantRole | undefined {
  if (did === LOCAL_CONTROLLED_CONTRACT.issuerDid) return "ISSUER";
  if (did === LOCAL_CONTROLLED_CONTRACT.verifierDid) return "VERIFIER";
  return undefined;
}

function ecsCredentials(did: string): unknown[] {
  const participantId = participantIdFor(did);
  return [
    {
      id: `${GATEWAY_ORIGIN}/credentials/ecs-service-${participantId}`,
      ecsSchema: "ServiceCredential",
      ecsSchemaVersion: "1.0",
      credentialSchemaId: SERVICE_CREDENTIAL_SCHEMA_ID,
      issuerParticipantId: PARTICIPANT_IDS.serviceCredentialIssuer,
      ecosystemId: ECOSYSTEM_ID,
      participantId: PARTICIPANT_IDS.serviceCredential,
      validFrom: VALID_FROM,
      validUntil: VALID_UNTIL,
      credentialSubject: {
        id: did,
        name: "Local Controlled Employee Service",
        type: "VerifiableService",
        description:
          "LOCAL_CONTROLLED fixture service for the FIDES playground.",
      },
    },
    {
      id: `${GATEWAY_ORIGIN}/credentials/ecs-org-${participantId}`,
      ecsSchema: "OrganizationCredential",
      ecsSchemaVersion: "1.0",
      credentialSchemaId: ORGANIZATION_CREDENTIAL_SCHEMA_ID,
      issuerParticipantId: PARTICIPANT_IDS.organizationCredentialIssuer,
      ecosystemId: ECOSYSTEM_ID,
      participantId: PARTICIPANT_IDS.organizationCredential,
      validFrom: VALID_FROM,
      validUntil: VALID_UNTIL,
      credentialSubject: {
        id: did,
        name: "Local Controlled Organization",
        countryCode: "FR",
        registryId: "LOCAL-CONTROLLED-0001",
      },
    },
  ];
}

// Exactly one presentation per required Linked-VP fragment, fully resolvable
// and carrying a VTC reference for this ecosystem and schema. Any deviation
// makes the agent downgrade the party to UNTRUSTED.
function presentations(did: string, withCredentialIds: boolean): unknown[] {
  const participantId = participantIdFor(did);
  return [
    {
      id: `${GATEWAY_ORIGIN}/presentations/${participantId}-vtjsc-vp.jwt`,
      serviceId: `${did}${LINKED_VP_SERVICE_FRAGMENT}`,
      vtcCredentials: [
        {
          id: LOCAL_CONTROLLED_CONTRACT.vtjscId,
          credentialSchemaId: CREDENTIAL_SCHEMA_ID,
          ecosystemId: ECOSYSTEM_ID,
          participantId,
          issuerParticipantId: PARTICIPANT_IDS.ecosystem,
        },
      ],
      ...(withCredentialIds
        ? { unresolvableCredentialIds: [], invalidCredentialIds: [] }
        : {}),
    },
  ];
}

// Per the request schema, services[] carries only NON-LinkedVerifiablePresentation
// entries. The Linked VP is surfaced through presentations[] instead.
function services(did: string): unknown[] {
  return [
    {
      id: `${did}#didcomm`,
      type: "DIDCommMessaging",
      serviceEndpoint: `${GATEWAY_ORIGIN}/didcomm`,
      accept: ["didcomm/v2"],
    },
  ];
}

function ecosystems(): unknown[] {
  return [
    {
      id: ECOSYSTEM_ID,
      corporationId: CORPORATION_ID,
      archived: false,
      egf: {
        version: 1,
        activeSince: EGF_ACTIVE_SINCE,
        documents: [
          {
            language: "en",
            url: `${GATEWAY_ORIGIN}/egf/local-controlled-governance.pdf`,
            digestSri: EGF_DIGEST,
          },
        ],
      },
      credentialSchemas: [
        {
          id: CREDENTIAL_SCHEMA_ID,
          type: "JsonSchema",
          digestSri: SCHEMA_DIGEST,
          archived: false,
        },
      ],
    },
  ];
}

// A DID participates only in the single role it actually holds, so an issuer
// asked about VERIFIER authorization resolves to not authorized.
function participations(did: string): unknown[] {
  const role = roleFor(did);
  if (!role) return [];
  return [
    {
      id: participantIdFor(did),
      vsOperator: VS_OPERATOR,
      role,
      state: "ACTIVE",
      credentialSchemaId: CREDENTIAL_SCHEMA_ID,
      ecosystemId: ECOSYSTEM_ID,
      weight: WEIGHT,
      validatorParticipantId: PARTICIPANT_IDS.ecosystem,
    },
  ];
}

export function resolveResponse(
  selection: ResolveSelection,
  nowMilliseconds: number,
): Record<string, unknown> {
  const trusted = isTrustedDid(selection.did);
  const response: Record<string, unknown> = {
    did: selection.did,
    trusted,
    evaluatedAtTime: utc(nowMilliseconds),
    evaluatedAtBlock: EVALUATED_AT_BLOCK,
    expiresAtTime: trusted ? VALID_UNTIL : null,
    corporationId: CORPORATION_ID,
  };

  if (selection.withEcsCredentials) {
    response.ecsCredentials = trusted ? ecsCredentials(selection.did) : [];
  }
  if (selection.withPresentations) {
    response.presentations = trusted
      ? presentations(selection.did, selection.withPresentationCredentialIds)
      : [];
  }
  if (selection.withServices) {
    response.services = trusted ? services(selection.did) : [];
  }
  if (selection.withEcosystems) {
    response.ecosystems = trusted ? ecosystems() : [];
  }
  if (selection.withParticipations) {
    response.participations = trusted ? participations(selection.did) : [];
  }

  return response;
}
