export const LOCAL_CONTROLLED_CONTRACT = Object.freeze({
  issuerDid: "did:web:issuer.localhost",
  holderDid: "did:web:holder.localhost",
  verifierDid: "did:web:verifier.localhost",
  rogueDid: "did:web:rogue.localhost",
  vct: "http://host.docker.internal:3099/vct/local-controlled-employee",
  vtjscId:
    "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json",
});

export function q1(did: string) {
  if (
    did === LOCAL_CONTROLLED_CONTRACT.issuerDid ||
    did === LOCAL_CONTROLLED_CONTRACT.verifierDid
  ) {
    return { did, trustStatus: "TRUSTED" as const, production: true };
  }
  return { did, trustStatus: "UNTRUSTED" as const, production: false };
}

export function authorization(
  role: "issuer" | "verifier",
  did: string,
  vtjscId: string,
) {
  const expectedDid =
    role === "issuer"
      ? LOCAL_CONTROLLED_CONTRACT.issuerDid
      : LOCAL_CONTROLLED_CONTRACT.verifierDid;
  return {
    did,
    vtjscId,
    authorized:
      did === expectedDid && vtjscId === LOCAL_CONTROLLED_CONTRACT.vtjscId,
  };
}
