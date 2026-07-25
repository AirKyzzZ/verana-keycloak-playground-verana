import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

import {
  CREDENTIAL_SCHEMA_ID,
  ECOSYSTEM_ID,
  LINKED_VP_SERVICE_FRAGMENT,
  LOCAL_CONTROLLED_CONTRACT,
} from "./contract.js";

const ASSERTION_FRAGMENT = "#ecosystem-assertion";

// A fixed seed keeps the ecosystem DID document byte-stable across restarts, so
// the published verification method does not change under a running stack. This
// is a LOCAL_CONTROLLED fixture key and carries no production meaning.
// Exactly 32 bytes, as Ed25519 requires; do not rely on the PKCS8 parser to
// ignore a trailing byte.
const SEED = Buffer.from(
  "4c4f43414c5f434f4e54524f4c4c45445f65636f73797374656d5f736565645f",
  "hex",
);

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_ED25519_PREFIX, SEED]),
  format: "der",
  type: "pkcs8",
});

const publicKey = createPublicKey({
  key: privateKey.export({ format: "pem", type: "pkcs8" }),
  format: "pem",
});

function publicJwk(): Record<string, string> {
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
  return { kty: jwk.kty ?? "OKP", crv: jwk.crv ?? "Ed25519", x: jwk.x ?? "" };
}

function base64Url(value: Buffer | string): string {
  return Buffer.from(value).toString("base64url");
}

export const ECOSYSTEM_VERIFICATION_METHOD = `${LOCAL_CONTROLLED_CONTRACT.ecosystemDid}${ASSERTION_FRAGMENT}`;

export function ecosystemDidDocument(): Record<string, unknown> {
  const verificationMethod = {
    id: ECOSYSTEM_VERIFICATION_METHOD,
    type: "JsonWebKey2020",
    controller: LOCAL_CONTROLLED_CONTRACT.ecosystemDid,
    publicKeyJwk: publicJwk(),
  };

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    id: LOCAL_CONTROLLED_CONTRACT.ecosystemDid,
    verificationMethod: [verificationMethod],
    assertionMethod: [ECOSYSTEM_VERIFICATION_METHOD],
    authentication: [ECOSYSTEM_VERIFICATION_METHOD],
    service: [
      {
        id: `${LOCAL_CONTROLLED_CONTRACT.ecosystemDid}#vpr-ecosystem`,
        type: "VerifiablePublicRegistry",
        serviceEndpoint: "https://resolver.localhost:3443/v4/verifiable-trust",
      },
    ],
  };
}

// A JWT-secured Verifiable Presentation avoids JSON-LD canonicalization while
// still carrying a real Ed25519 signature over the exact payload served here.
export function linkedVerifiablePresentation(
  holderDid: string,
  issuedAtSeconds: number,
): string {
  const header = {
    alg: "EdDSA",
    typ: "JWT",
    kid: ECOSYSTEM_VERIFICATION_METHOD,
  };
  const payload = {
    iss: LOCAL_CONTROLLED_CONTRACT.ecosystemDid,
    sub: holderDid,
    iat: issuedAtSeconds,
    vp: {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://identity.foundation/linked-vp/contexts/v1",
      ],
      type: ["VerifiablePresentation"],
      holder: holderDid,
      verifiableCredential: [
        {
          id: LOCAL_CONTROLLED_CONTRACT.vtjscId,
          type: ["VerifiableCredential", "VerifiableTrustCredential"],
          issuer: LOCAL_CONTROLLED_CONTRACT.ecosystemDid,
          credentialSubject: {
            id: holderDid,
            ecosystemId: ECOSYSTEM_ID,
            credentialSchemaId: CREDENTIAL_SCHEMA_ID,
            serviceId: `${holderDid}${LINKED_VP_SERVICE_FRAGMENT}`,
          },
        },
      ],
    },
  };

  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(
    JSON.stringify(payload),
  )}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${base64Url(signature)}`;
}

export function verifyLinkedVerifiablePresentation(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) return false;
  return verify(
    null,
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    publicKey,
    Buffer.from(encodedSignature, "base64url"),
  );
}
