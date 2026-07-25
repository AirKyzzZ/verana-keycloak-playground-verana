export const LOCAL_CONTROLLED = Object.freeze({
  evidenceMode: "LOCAL_CONTROLLED" as const,
  composeProject: "verana-keycloak-local-controlled",
  requiredVsCommit: "747f8f1",
  twitterContainer: "twitter-bot-vs-agent",
  networkId: "local-controlled",
  ecosystemId: 184,
  credentialSchemaId: 249,
  tlsPort: 3443,
  issuerUrl: "https://issuer.localhost:3443",
  holderUrl: "https://holder.localhost:3443",
  verifierUrl: "https://verifier.localhost:3443",
  issuerDid: "did:web:issuer.localhost%3A3443",
  holderDid: "did:web:holder.localhost%3A3443",
  verifierDid: "did:web:verifier.localhost%3A3443",
  rogueDid: "did:web:verifier.localhost%3A3443:rogue",
  ecosystemDid: "did:web:resolver.localhost%3A3443:ecosystem",
  // Containers reach the resolver through the TLS gateway; host-side processes
  // and verification scripts talk to it directly on loopback, because the
  // gateway's per-run private CA is deliberately not in any host trust store.
  resolverUrl: "https://resolver.localhost:3443",
  hostResolverUrl: "http://localhost:3099",
  vct: "https://resolver.localhost:3443/vct/local-controlled-employee",
  vtjscId:
    "https://resolver.localhost:3443/vtjsc/local-controlled-employee.json",
  // The binding key is the exact OID4VCI credential issuer identifier, which
  // carries the issuer path, not merely the origin. An origin-only key never
  // matches and every offer is refused as unbound.
  credentialIssuerBindings: Object.freeze({
    "https://issuer.localhost:3443/oid4vci/unfold":
      "did:web:issuer.localhost%3A3443",
  }),
  // The verifier's DCQL pins the credential to the gated VTJSC, so
  // credentialSchema.id is always requested alongside the demo claims.
  requestedClaims: Object.freeze([
    "credentialSchema.id",
    "subject_id",
    "organization",
    "role",
  ]),
  requiredLinkedVpFragments: Object.freeze([
    "#vpr-schemas-service-vtc-vp",
    "#vpr-schemas-org-vtc-vp",
    "#vpr-schemas-249-vtjsc-vp",
  ]),
  ports: [3000, 3001, 3099, 3100, 3101, 3110, 3111, 3200, 3201, 3443] as const,
});
