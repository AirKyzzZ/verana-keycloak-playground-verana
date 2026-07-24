export const LOCAL_CONTROLLED = Object.freeze({
  evidenceMode: "LOCAL_CONTROLLED" as const,
  composeProject: "verana-keycloak-local-controlled",
  requiredVsCommit: "e2bba78",
  twitterContainer: "twitter-bot-vs-agent",
  issuerDid: "did:web:issuer.localhost",
  holderDid: "did:web:holder.localhost",
  verifierDid: "did:web:verifier.localhost",
  rogueDid: "did:web:rogue.localhost",
  resolverUrl: "http://host.docker.internal:3099/v1/trust",
  vct: "http://host.docker.internal:3099/vct/local-controlled-employee",
  vtjscId:
    "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json",
  ports: [3000, 3001, 3099, 3100, 3101, 3110, 3111, 3200, 3201] as const,
});
