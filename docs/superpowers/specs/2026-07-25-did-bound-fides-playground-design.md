# DID-Bound FIDES and Keycloak Playground Design

Date: 2026-07-25

Status: architecture approved by Maxime on 2026-07-25; written specification pending review

## Purpose

Build a reusable local foundation for FIDES credential issuance, holder
decisions, credential presentation, Verana trust resolution, and Keycloak
identity brokering. The foundation must be secure enough to reuse in later
Verana Labs playground integrations without treating local fixtures as testnet
or production evidence.

This design replaces:

- `docs/superpowers/specs/2026-07-24-local-controlled-auth-stack-design.md`;
- the identity and resolver assumptions in
  `docs/superpowers/plans/2026-07-24-local-controlled-auth-stack.md`;
- `docs/superpowers/plans/2026-07-25-local-controlled-openid4vc-tls.md`.

The existing implementation remains useful, but its unported `did:web`
identifiers, X.509 URI-SAN identity extraction, legacy three-GET resolver
contract, and combined issue-and-accept action are not the target state.

## Authority and Evidence Boundary

The implementation is based on these reviewed snapshots:

- `verana-spec` main at `eaac693`;
- playground PR #13 at `372e9ff`;
- VS Agent OpenID4VC worktree at `e2bba78`;
- playground worktree at `2010f84`.

Merged Verana v4 specifications govern the resolver wire contract. PR #13
provides the pending playground integration and Proof-of-Trust requirements.
Where they conflict, the merged v4 resolver contract is implemented and the
disagreement is documented. The implementation must be easy to update after
PR #13 changes or merges.

Every local result is labelled:

```text
LOCAL_CONTROLLED
```

This label proves only that real local protocol components ran against a
controlled Verana data fixture. It does not prove:

- Verana testnet authorization;
- public DID resolution;
- public-CA TLS;
- physical or third-party wallet interoperability;
- full Verifiable Service conformance;
- playground acceptance;
- production readiness.

No code, image, branch, comment, review, or deployment is sent externally
without separate approval.

## Goals

- Use real VS Agent OpenID4VCI and OpenID4VP implementations.
- Bind every positive issuer and verifier decision to an authenticated DID
  signing key.
- Resolve local `did:web` identifiers through real controlled HTTPS.
- Publish resolvable DID Documents and locally signed Linked Verifiable
  Presentations for the service and organization evidence displayed by the
  holder.
- Use the merged v4 `POST /v4/verifiable-trust/resolve` contract.
- Evaluate Q1 independently from Q2 and Q3.
- Run Q1 and Q2 before the holder can accept an issuance.
- Run Q1 and Q3 before the holder can share a presentation.
- Render the four trust states and five ordered Proof-of-Trust blocks defined
  by playground PR #13.
- Create a Keycloak account and session only from a cryptographically verified
  `TRUSTED_AUTHORIZED` receipt.
- Preserve stable pairwise subject reuse across repeated login.
- Prove that identity, trust, authorization, protocol, and transport failures
  create no Keycloak account or session.
- Start and stop the complete local stack without affecting unrelated Docker
  resources.
- Leave reusable configuration boundaries for later FIDES wallet, business
  wallet, issuer, verifier, and ecosystem demo pages.

## Non-Goals

- Adding all personal and business wallets in this implementation cycle.
- Registering local DIDs or participants on Verana testnet.
- Implementing Participant Sessions or fee settlement.
- Claiming the local holder is a full Verifiable User Agent.
- Defining a new PKI-to-DID profile.
- Accepting a DID copied into an X.509 URI SAN as authenticated identity.
- Replacing Keycloak with a custom Java SPI.
- Adding public ingress, deployment configuration, monitoring, backups, or
  production storage.
- Modifying or deleting unrelated containers, volumes, images, keys, or source
  checkouts.

## System Boundaries

The implementation uses two existing isolated worktrees:

```text
/Users/samsepiol/Downloads/GithubRepos/Work/Verana/verana-keycloak-playground/.worktrees/auth-demo
/Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim
```

The playground builds one reviewed VS Agent image from the second worktree and
runs isolated issuer, holder, and verifier instances. It does not copy VS Agent
source into the playground repository.

The runtime contains:

```text
Chrome
  -> protected demo application
  -> Keycloak
  -> TypeScript OIDC broker
  -> verifier VS Agent
  -> holder VS Agent
  -> issuer VS Agent
  -> controlled v4 Verana resolver
  -> DID Documents and Linked VPs over controlled TLS
```

The controlled resolver and controlled Verana records are the only registry
test doubles. Issuance, credential verification, presentation, broker policy,
Keycloak, and application OIDC remain real local implementations.

## Controlled HTTPS and DID Contract

One loopback TLS gateway listens on `127.0.0.1:3443`. It routes by the exact
HTTP `Host` header:

| Public origin | Upstream |
| --- | --- |
| `https://issuer.localhost:3443` | issuer VS Agent public API |
| `https://holder.localhost:3443` | holder VS Agent public API |
| `https://verifier.localhost:3443` | verifier VS Agent public API |
| `https://resolver.localhost:3443` | controlled resolver |

On the Docker network, the gateway owns network aliases for those four
hostnames. On macOS, the same names resolve to loopback. The public URLs
therefore keep one identity while both containers and host-side verification
reach the same gateway.

The identifiers are:

```text
issuer:    did:web:issuer.localhost%3A3443
holder:    did:web:holder.localhost%3A3443
verifier:  did:web:verifier.localhost%3A3443
rogue:     did:web:verifier.localhost%3A3443:rogue
ecosystem: did:web:resolver.localhost%3A3443:ecosystem
```

They resolve at:

```text
https://issuer.localhost:3443/.well-known/did.json
https://holder.localhost:3443/.well-known/did.json
https://verifier.localhost:3443/.well-known/did.json
https://verifier.localhost:3443/rogue/did.json
https://resolver.localhost:3443/ecosystem/did.json
```

Every live readiness gate verifies:

- HTTP 200 over the controlled CA;
- `Content-Type: application/did+ld+json` or
  `application/did+json`;
- exact DID Document `id`;
- the signing verification method belongs to the same base DID;
- required service identifiers and endpoints are exact;
- no document or route is available under a different host.

The gateway uses a per-run private CA and per-run leaf certificate. The CA is
trusted only inside the disposable stack and explicit test clients. It is not
installed into the macOS system trust store. Private keys use mode `0600` and
are deleted during guarded teardown.

All container-to-container HTTPS clients receive only the per-run CA through
their existing runtime trust mechanism. No `NODE_TLS_REJECT_UNAUTHORIZED=0`,
insecure client flag, certificate bypass, or system trust-store mutation is
allowed.

## DID-Signed Positive Protocol Paths

### Issuance

The positive issuer uses:

```text
OID4VC_ISSUER_SIGNER=did
```

VS Agent resolves an assertion method from the issuer DID Document and signs
the SD-JWT VC with that DID URL. A verified credential is eligible for Q1/Q2
only when:

1. the credential signature verifies;
2. the decoded issuer method is `did`;
3. the authenticated signer DID URL has the expected issuer as its base DID;
4. the verified `iss` claim equals that base DID;
5. the credential issuer metadata came from the configured exact HTTPS
   `credential_issuer`;
6. the configured `credential_issuer` maps to the exact expected issuer DID;
7. that DID resolves and contains the verification method used by the
   credential.

The local mapping is:

```text
https://issuer.localhost:3443
  -> did:web:issuer.localhost%3A3443
```

OID4VCI does not provide this Verana-specific URL-to-DID rule. The mapping is
an explicit local profile decision and remains configurable for later
playground integrations.

### Presentation request

The positive verifier uses:

```text
OID4VC_REQUEST_SIGNER=did
```

The request object uses the OpenID4VP v1 decentralized-identifier client
identifier scheme. A request is eligible for Q1/Q3 only when:

1. the request-object signature verifies;
2. the signer method is `did`;
3. the signer DID URL resolves to a verification method;
4. `clientIdPrefix` is exactly `decentralized_identifier`;
5. `effectiveClientId` is exactly
   `decentralized_identifier:<base-verifier-did>`;
6. the signer DID URL base equals the verifier DID selected for trust
   resolution.

Any malformed DID URL, unsupported signer, wrong prefix, mismatched client ID,
or unresolved signing method is rejected before a Verana trust request and
before creating a holder share gate.

### X.509 compatibility and rogue evidence

X.509-signed credentials and request objects may be decoded for controlled
negative tests, but a DID copied from a certificate URI SAN is not an
authenticated Verana identity. It cannot produce
`TRUSTED_AUTHORIZED`.

The rogue verifier uses X.509 to prove this failure mode. A forged certificate
containing the trusted verifier DID must fail before Q1/Q3 authorization. A
certificate URI SAN may be displayed only as an explicitly unverified claim,
never as the resolved service DID or operator identity. A
future X.509 positive path requires a separately approved profile that
validates the certificate chain and binds its PKI identity to the Verana DID.

## Verana v4 Trust Adapter

The reusable VS Agent boundary is:

```ts
type ParticipationRole = "ISSUER" | "VERIFIER";

interface ExpectedParticipation {
  ecosystemId: number;
  credentialSchemaId: number;
  role: ParticipationRole;
}

interface ResolveTrustInput {
  did: string;
  expectedParticipation?: ExpectedParticipation;
  atBlockHeight?: number;
}

interface ResolveTrustResult {
  did: string;
  trusted: boolean;
  authorized: boolean | null;
  evaluatedAtTime: string;
  evaluatedAtBlock: number;
  expiresAtTime: string | null;
  corporationId: number;
  matchedParticipantId: number | null;
}

interface VeranaTrustAdapter {
  resolve(input: ResolveTrustInput): Promise<ResolveTrustResult>;
}
```

Wire requests use:

```http
POST /v4/verifiable-trust/resolve
Accept: application/json
Content-Type: application/json
```

Q1 body:

```json
{
  "did": "<exact authenticated DID>",
  "ecsCredentials": true,
  "services": true,
  "presentations": {
    "unresolvableCredentialIds": true,
    "invalidCredentialIds": true
  },
  "ecosystems": {
    "credentialSchemas": {
      "includeArchived": false
    }
  }
}
```

Q2/Q3 body:

```json
{
  "did": "<exact authenticated DID>",
  "participations": {
    "states": ["ACTIVE"]
  },
  "ecsCredentials": true,
  "services": true,
  "presentations": {
    "unresolvableCredentialIds": true,
    "invalidCredentialIds": true
  },
  "ecosystems": {
    "credentialSchemas": {
      "includeArchived": false
    }
  }
}
```

An `At-Block-Height` header is sent only for an explicit positive integer
historical query. Current decisions omit it.

Q1 passes only when:

- response DID exactly equals the requested DID;
- `trusted` is exactly `true`;
- `expiresAtTime` is `null` or strictly later than the decision time;
- all required core fields pass strict parsing.

Q2 additionally requires one exact active participation with:

```text
role=ISSUER
ecosystemId=184
credentialSchemaId=249
```

Q3 uses the same tuple with:

```text
role=VERIFIER
```

Trust never implies authorization. The VTJSC URL is evidence and
dereferencing metadata, not the v4 authorization key. Its verified VPR schema
reference must bind to:

```text
vpr:verana:vna-testnet-1:cs:249
```

The controlled fixture uses unique positive integer corporation and
participant IDs. The untrusted rogue fixture also uses a positive integer
corporation ID because the current merged response schema requires it. It has
`trusted: false` and no matching active participation. No `0` or `null`
sentinel is invented.

The adapter retains the existing receipt-facing
`trustStatus`/`authorized`/`vtjscId` fields only as an internal compatibility
projection. The broker and demo app never call the legacy resolver wire
contract. The accepted path does not expose a `PARTIAL` state: a v4 response
is trusted, untrusted, or unavailable/invalid, which maps to the four holder
states defined below.

The old three GET routes may remain temporarily behind an explicit
`LEGACY_LOCAL_CONTROLLED` mode for regression comparison. They are disabled in
the accepted demo configuration and must not be documented as reusable or
normative.

## Linked Verifiable Presentations

The issuer and verifier DID Documents expose locally signed, locally
verifiable Linked VP services for:

1. ECS-Service;
2. ECS-Organization;
3. the local employee badge schema evidence;
4. the local ecosystem VTJSC.

Service and organization Linked VPs are owned by the service DID origin. The
ecosystem VTJSC VP is owned by the ecosystem DID and served under:

```text
https://resolver.localhost:3443/ecosystem/vp/schemas/249-vtjsc
```

Required fragment conventions are preserved, including:

```text
#vpr-schemas-service-vtc-vp
#vpr-schemas-org-vtc-vp
#vpr-schemas-<schema>-vtjsc-vp
```

Each VP:

- is signed by the DID that publishes it;
- contains only bounded local fixture claims;
- is fetched over the controlled CA;
- is verified before its claims enter Proof-of-Trust;
- is rejected on wrong signer, wrong subject, wrong schema, malformed JSON,
  invalid signature, missing service entry, or oversized body.

The gateway proxies agent-owned DID Documents and Linked VP endpoints. It does
not rewrite DID identities or silently fabricate a document for a failed
agent.

## Holder State Machine

Issuance is split into two operations:

```text
offer received
  -> RESOLVING
  -> Q1 plus Q2 plus Linked VP verification
  -> TRUSTED, UNTRUSTED, or UNVERIFIED
  -> explicit single-use accept gate
  -> credential request and storage
```

Presentation follows:

```text
authorization request received
  -> RESOLVING
  -> authenticated verifier DID
  -> Q1 plus Q3 plus Linked VP verification
  -> TRUSTED, UNTRUSTED, or UNVERIFIED
  -> explicit single-use share gate
  -> presentation submission
```

The only user-visible trust states are:

- `RESOLVING`;
- `TRUSTED`;
- `UNTRUSTED`;
- `UNVERIFIED`.

`UNVERIFIED` means the resolver, DID, Linked VP, or required evidence could not
be verified. It offers a fresh retry and is never rendered as trusted or
untrusted.

Trusted gates are:

- bound to the exact offer or authorization request;
- bound to the authenticated service DID and expected schema tuple;
- single use;
- short lived;
- invalidated by a new resolve, retry, failure, logout, or conflicting
  operation;
- consumed before the irreversible protocol submission;
- never replayed after an uncertain submission response.

The accepted local policy hard-blocks issuance and sharing unless the result is
`TRUSTED_AUTHORIZED`.

## Proof-of-Trust UI

Every consent screen renders five blocks in this order:

1. Status band with state, exact service DID, evaluation time and block.
2. Service claims from a verified ECS-Service credential.
3. Operator claims from a verified ECS-Organization credential.
4. Every additional verified credential, including its schema, issuer, and
   ecosystem.
5. Trust chains and failures for every credential, including resolver reasons
   and safe registry links.

Claims from invalid credentials appear only as labelled failure evidence. They
are never rendered as facts.

The issuance screen also states the Q2 result in words before showing the
accept action. The presentation screen states the Q3 result before showing the
share action. Unauthorized actions are disabled and cannot be re-enabled by a
caller-selected form value.

The local demo includes:

- trusted issuer;
- unauthorized or untrusted issuer;
- trusted verifier;
- rogue or unauthorized verifier;
- resolver unavailable;
- malformed trust evidence;
- retry after `UNVERIFIED`;
- trust expiry or changed result requiring fresh acknowledgment.

The demo application may use its existing visual style. Block order, state
semantics, wording meaning, and positive/negative/unknown icon semantics are
invariants.

## Keycloak IAM Boundary

Keycloak remains a separate client-IAM demonstration, not the anonymous public
playground account model.

The existing TypeScript OIDC broker:

- accepts only a verified receipt from the VS Agent verifier;
- requires exact issuer and verifier `TRUSTED_AUTHORIZED` verdicts;
- requires exact expected issuer DID, verifier DID, VCT, schema tuple, and
  disclosed claims;
- derives a stable pairwise external subject;
- emits an Authorization Code response consumed by Keycloak.

Keycloak 26.7.0:

- uses the disposable `verana-playground` realm;
- runs Authorization Code with S256;
- JIT provisions through the standard external identity-broker flow;
- stores the external pairwise subject as read-only `verana_subject`;
- maps exact allowlisted `organization=ACME` to
  `/organizations/acme`;
- maps exact allowlisted `role=employee` to the pre-created realm role;
- starts with zero users.

No non-positive or malformed path may create an account, federated identity,
group membership, role mapping, or authenticated session.

Logout forces a new wallet interaction through `prompt=login`. Repeated trusted
login reuses the same Keycloak user and pairwise subject.

## Runtime and Lifecycle Safety

All host ports bind to `127.0.0.1`. The Docker network is internal except for
explicit loopback publications required by Chrome.

Startup:

1. validates clean expected worktrees and reviewed commit ancestry;
2. records the exact pre-run state of `twitter-bot-vs-agent`;
3. stops that container only if it is running and owns a required port;
4. refuses unrelated port owners;
5. writes the lifecycle journal before generating disposable keys;
6. generates per-run secrets and TLS material with restrictive modes;
7. builds one VS Agent image;
8. starts resolver, agents, broker, Keycloak, application, and gateway;
9. waits on bounded health and DID-readiness checks;
10. verifies exact capability, resolver, signer, and zero-user contracts;
11. prints only local URLs and the `LOCAL_CONTROLLED` boundary.

Teardown:

1. stops only recorded playground resources;
2. removes only named playground containers, networks, volumes, and generated
   files;
3. preserves source, images, unrelated containers, and unrelated volumes;
4. restores `twitter-bot-vs-agent` only if it was running before startup;
5. verifies that every playground listener is gone;
6. verifies that disposable credentials, tokens, protocol payloads, and TLS
   private keys are gone.

No Docker prune, broad recursive deletion, system CA installation, or image
removal is part of the lifecycle.

## Failure Policy

The stack fails closed on:

- unsupported or unauthenticated signer methods;
- malformed DID URLs;
- wrong DID base or verification method;
- wrong OpenID4VP prefix or effective client ID;
- issuer metadata URL-to-DID mismatch;
- verified issuer `iss` mismatch;
- unresolved or wrong-host DID Documents;
- missing or invalid Linked VPs;
- `did:key` or `did:jwk` service identity;
- response DID mismatch;
- `trusted` not exactly `true`;
- expired trust;
- missing exact active participation;
- wrong role, ecosystem, or credential schema;
- resolver timeout, malformed JSON, invalid UTF-8, wrong media type, or body
  over 64 KiB;
- unknown, expired, consumed, or conflicting consent gates;
- uncertain protocol submission;
- broker state, nonce, PKCE, callback, CSRF, cookie, or replay failure.

Failures return bounded user-safe reasons and sanitized evidence. They never
return credentials, presentations, authorization requests, tokens, private
keys, or raw signed receipts to browser logs or persistent application state.

## Verification Strategy

### TDD and focused tests

Every behavior change begins with a failing test and records the expected
failure before implementation.

VS Agent tests cover:

- DID-signed credential issuer extraction;
- payload `iss` equality;
- DID-signed request-object extraction;
- exact `decentralized_identifier` binding;
- foreign verification-method rejection;
- X.509 URI-SAN positive denial;
- v4 response strict parsing;
- response DID and expiry checks;
- exact active participation matching;
- bounded transport failures.

Playground tests cover:

- port-encoded DIDs and exact routes;
- certificate generation and explicit CA trust;
- wrong-host and wrong-document denial;
- controlled v4 issuer, verifier, and rogue fixtures;
- offer-review and single-use acceptance;
- presentation-review and single-use sharing;
- all four states and five Proof-of-Trust blocks;
- unauthorized issuer and verifier paths;
- lifecycle journaling, cleanup, and unrelated-resource preservation.

### Live local API evidence

The live verifier must:

1. resolve every controlled DID Document over TLS;
2. verify every required Linked VP;
3. complete DID-signed OpenID4VCI;
4. show Q1/Q2 before acceptance;
5. accept and store the credential;
6. complete DID-signed OpenID4VP;
7. show Q1/Q3 before sharing;
8. verify the presentation and receipt;
9. complete Keycloak JIT login;
10. repeat with the same pairwise subject and account;
11. run every adversarial identity, resolver, consent, broker, and Keycloak
    case;
12. prove denied cases leave the account and session counts unchanged.

### Real Chrome evidence

Using Maxime's existing Chrome profile:

1. inspect the issuer Proof-of-Trust and Q2 result;
2. accept the trusted credential;
3. inspect the verifier Proof-of-Trust and Q3 result;
4. share the approved claims;
5. complete Keycloak login and inspect the protected identity;
6. log out and repeat through a fresh wallet interaction;
7. verify stable account and subject reuse;
8. run unauthorized issuer and verifier paths;
9. run an `UNVERIFIED` resolver failure and retry;
10. confirm no denied path creates another account or session;
11. inspect console and relevant network requests for errors and secret
    exposure.

Screenshots and evidence files must be sanitized and labelled
`LOCAL_CONTROLLED`. Raw credentials, presentations, tokens, secrets, and
private keys are not retained.

## Acceptance Criteria

The local demo is accepted only when:

- the revised design and implementation plans have independent reviews with no
  open load-bearing finding;
- every focused and full supported test, lint, typecheck, and build gate passes
  freshly in both worktrees;
- the real API sequence completes twice with stable subject and account reuse;
- DID Documents and Linked VPs resolve and verify over the controlled CA;
- the forged X.509 trusted-DID attack fails before authorization;
- every Q1/Q2/Q3, trust expiry, resolver, consent, and broker adversary fails
  closed;
- unauthorized paths create no additional Keycloak user or session;
- real Chrome completes the trusted flow and displays every required trust
  state and block;
- teardown removes only disposable playground state and restores the recorded
  Twitter container state;
- evidence clearly separates local, automated, browser, testnet, external
  wallet, and unproven claims;
- nothing is pushed, deployed, reviewed, or commented externally.

## Next Local Playground Phase

After this foundation is accepted, the same Mac-hosted environment becomes a
configurable demo catalog rather than a one-off page.

The next design cycle will model:

- personal wallets;
- business and cloud wallets;
- issuers;
- verifiers;
- ecosystems and credential schemas;
- individual integration pages;
- supported protocols, credential formats, DID methods, and trust capabilities;
- reproducible evidence and integration status per demo.

Every integration page will consume the same contracts defined here:

- issuer URL-to-DID binding;
- verifier client-ID-to-DID binding;
- v4 trust adapter;
- Proof-of-Trust view model;
- controlled versus live evidence labels;
- reusable issuance, presentation, and Keycloak IAM journeys.

The catalog does not begin by claiming seven or eight completed wallet
integrations. Each wallet is added only after its own protocol, trust, device,
and evidence gates pass. The local catalog can later move to Verana Labs
infrastructure by replacing origins, secrets, storage, and controlled registry
fixtures without rewriting the trust and consent boundaries.
