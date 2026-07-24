# Verana Keycloak Playground Design

Date: 2026-07-24

Status: approved architecture, awaiting written-spec review

## Purpose

Build a local demonstration in which a person presents a Verana-gated
OpenID4VP credential and receives a normal Keycloak login session. The demo
must prove that Verana can supply trusted external identity to a traditional
IAM system without making Keycloak understand wallets, credentials, DIDs, or
the Verana registry directly.

The demonstration is the first implementation slice of the Verana Playground
story described by `verana-spec` PR #13:

1. an employee holds a demo badge issued over OpenID4VCI;
2. an IAM login service requests the badge over OpenID4VP;
3. Verana Q1 and Q3 checks are evaluated before disclosure;
4. a verified, authorized presentation becomes a Keycloak session.

The local credential is explicitly a playground employee badge. It is not
represented as the final testnet ECS-Badge while that schema remains an open
specification and testnet dependency.

## Goals

- Demonstrate passwordless Keycloak login from an OpenID4VP presentation.
- Use Keycloak's standard OpenID Connect identity-brokering interface.
- Provision a Keycloak user just in time on the first successful login.
- Give the brokered user a stable, pairwise OIDC `sub`.
- Map approved credential claims to a pre-created Keycloak group and role.
- Fail closed when presentation verification or Verana authorization fails.
- Support a complete local-holder flow that does not depend on a physical
  wallet.
- Preserve the same QR protocol boundary for a physical wallet when the
  verifier is available through trusted HTTPS.
- Retain inspectable evidence for the successful and denied paths.

## Non-goals

- Production deployment, high availability, multi-tenancy, or account recovery.
- Replacing Keycloak's user store or authorization model.
- A custom Keycloak Java SPI.
- Dynamic creation of Keycloak groups or privileged roles from credential text.
- Email-based identity or fabricated email claims.
- Final ECS-Badge governance, schema, or testnet provisioning.
- Production-grade subject continuity across credential replacement.
- Publishing, pushing, or deploying any artifact without separate approval.

## Chosen Architecture

The playground uses a small Verana OIDC broker between Keycloak and VS Agent.
Keycloak sees the broker as a normal external OpenID Connect identity
provider. The broker translates a successful VS Agent OpenID4VP verification
session into a signed OIDC authorization response.

```text
Demo application
  -> Keycloak authorization endpoint
  -> "Verana Wallet" external identity provider
  -> Verana OIDC broker
  -> VS Agent OpenID4VP verifier
  -> wallet or local holder
  -> VS Agent proof-of-trust receipt
  -> broker policy gate
  -> signed OIDC code and ID token
  -> Keycloak first broker login
  -> demo application session
```

This is preferred over a Keycloak authenticator SPI because it:

- uses a stable, documented Keycloak extension boundary;
- avoids Java and Keycloak-version-specific plugin packaging;
- keeps Verana-specific policy in a separately testable service;
- lets other IAM products consume the same broker later;
- allows the wallet and VS Agent integration to evolve independently.

An application-specific callback bridge is rejected because it would bypass
Keycloak's normal trust boundary and would not demonstrate a reusable IAM
integration.

## Repository Boundary

The new local repository is:

`/Users/samsepiol/Downloads/GithubRepos/Work/Verana/verana-keycloak-playground`

It owns:

- Docker Compose orchestration for the disposable Keycloak realm;
- the OIDC broker;
- a minimal protected demonstration application;
- realm import and non-secret demo configuration;
- local-holder demonstration pages and scripts;
- focused tests and evidence documentation.

It does not copy VS Agent. It consumes the HTTP interface of a separately run
VS Agent OpenID4VC plugin.

A separate isolated VS Agent worktree may receive the smallest required
extension to expose a stable demo subject claim in the proof-of-trust receipt.
The existing dirty VS Agent checkout must not be modified.

## Components

### 1. Keycloak

Keycloak 26.7.0 runs in development mode in Docker and imports a disposable
`verana-playground` realm.

The realm contains:

- confidential OIDC client `playground-app`;
- external OIDC identity provider `verana-wallet`;
- group `/organizations/acme`;
- realm role `employee`;
- claim-to-group and claim-to-role mappers with exact expected values;
- an identity-provider mapper that stores the external pairwise `sub` as the
  read-only `verana_subject` user attribute;
- a client protocol mapper that includes `verana_subject` in the demo
  application's ID token;
- a first-broker-login flow that creates the user without requesting an email
  address or password.

Keycloak validates broker ID-token signatures through the broker's JWKS
endpoint. Browser endpoints use localhost URLs. Keycloak backchannel endpoints
use Docker-reachable URLs configured separately in the realm import.

### 2. Verana OIDC Broker

The broker is a strict TypeScript service using established OIDC libraries
rather than implementing OAuth or JWT primitives by hand.

It provides:

- OIDC discovery;
- authorization endpoint;
- token endpoint;
- JWKS endpoint;
- short-lived login transaction storage;
- QR and progress page;
- VS Agent request creation and session polling;
- proof-of-trust policy enforcement;
- authorization-code issuance to Keycloak.

The implementation uses Authorization Code flow. Keycloak is the only
registered client. Redirect URIs and origins are exact allowlists.

### 3. VS Agent Adapter

The broker talks to the existing VS Agent demo endpoints:

- `POST /oid4vc-demo/verifier/requests`;
- `GET /oid4vc-demo/verifier/sessions/:id`.

The VS Agent verifier remains responsible for:

- creating the signed OpenID4VP request;
- verifying the wallet response and holder binding;
- extracting only verified disclosed claims;
- resolving verifier Q1 and Q3;
- resolving issuer Q1 and Q2;
- returning the proof-of-trust receipt.

The receipt used for login must include a verified opaque `subject_id` in
addition to `organization` and `role`. The demo issuer selects the
`subject_id`; the wallet cannot override it during presentation. It is an
SD-JWT selectively disclosed claim and is disclosed only for this authorized
login request.

The presentation query requests exactly:

- the configured `vct`;
- the configured Verana credential-schema identifier;
- `subject_id`;
- `organization`;
- `role`.

### 4. Demo Application

The application is an ordinary OIDC relying party of Keycloak. It contains:

- signed-out page with a single "Sign in with Keycloak" action;
- protected page showing the Keycloak subject, external pairwise subject,
  organization, and role;
- logout action;
- no application-local password or user database.

It validates Keycloak issuer, audience, signature, nonce, state, and PKCE
before creating its local session.

### 5. Local Demo Holder

The reliable tonight path uses the existing VS Agent holder capability through
a small local page:

1. obtain the playground employee badge from the local issuer;
2. open or paste the displayed OpenID4VP request;
3. display the verifier trust result and requested claims;
4. require an explicit share action;
5. submit the presentation.

This is not described as physical-wallet interoperability evidence.

The QR shown by the broker contains the same OpenID4VP authorization request.
A real wallet can replace the local holder without changing Keycloak or the
broker. Physical-wallet use requires a verifier URL reachable through trusted
HTTPS and a wallet compatible with the selected OpenID4VC profile.

## Identity Contract

The credential contains an opaque, issuer-controlled `subject_id`. It is not
an email, DID, display name, employee number, or database primary key exposed
outside the demo.

The broker derives the OIDC subject as:

```text
sub = base64url(
  HMAC-SHA-256(
    pairwiseSubSecret,
    issuerDid || 0x1f || subjectId || 0x1f || sectorIdentifier
  )
)
```

The sector identifier is fixed to the Keycloak playground realm. Reusing the
same valid credential in this realm produces the same `sub`; a different
sector produces a different `sub`.

The broker emits these ID-token claims:

```json
{
  "sub": "<pairwise opaque value>",
  "organization": "ACME",
  "role": "employee",
  "verana_verifier_did": "<trusted verifier DID>",
  "verana_issuer_did": "<trusted issuer DID>"
}
```

The raw `subject_id`, full credential, raw authorization request, raw
presentation, access tokens, and proof material are not added to the Keycloak
ID token or application session.

For production, continuity across badge replacement or issuer-DID rotation
needs a separately agreed issuer subject lifecycle or an account-linking
policy. The MVP does not imply that this policy is settled.

## Authorization Policy

The broker creates an OIDC authorization code only when every condition below
is true:

- the VS Agent session state is `ResponseVerified`;
- the receipt protocol is `OID4VP 1.0`;
- the receipt belongs to the broker's exact one-time session;
- the receipt tenant is `trusted`;
- the presented `vct` equals the configured demo badge type;
- the schema identifier equals the configured Verana schema identifier;
- verifier verdict is `TRUSTED_AUTHORIZED`;
- issuer verdict is `TRUSTED_AUTHORIZED`;
- verifier DID and issuer DID are present;
- `subject_id` is a non-empty bounded string;
- `organization` is exactly `ACME`;
- `role` is exactly `employee`;
- the login transaction is unexpired and unused.

`PARTIAL`, `TRUSTED_NOT_AUTHORIZED`, `UNTRUSTED`, resolver failure, timeout,
malformed data, mismatched claims, or missing evidence all deny login.

Keycloak mappings are defense in depth. The broker already enforces the claim
allowlist, and Keycloak maps only the exact accepted values to pre-created
objects. Arbitrary credential values never create groups or roles.

## Transaction and Error Handling

Each login receives:

- cryptographically random transaction identifier;
- OIDC state and nonce;
- PKCE challenge;
- VS Agent session identifier;
- five-minute absolute expiry;
- one-time completion marker.

The broker polls VS Agent at a bounded interval and stops at terminal success,
terminal failure, or expiry. Refreshing the browser resumes only the same
server-side transaction. It does not create additional presentation requests.

User-facing terminal states are:

- `verified`: redirecting to Keycloak;
- `denied`: presentation or trust policy failed;
- `expired`: start a new login;
- `unavailable`: VS Agent or resolver could not complete verification.

The browser receives a short error code and safe explanation. Detailed server
logs may contain transaction IDs and verdict categories, but never raw
credentials, presentations, authorization requests, tokens, secrets, or
private keys.

## Local Configuration

Non-secret values are committed in example configuration. Secrets are
generated locally or supplied through ignored environment files.

Required secrets:

- broker OIDC signing key;
- pairwise-sub HMAC secret;
- Keycloak broker client secret;
- demo application Keycloak client secret;
- server-side session secret.

The repository includes a preconfigured development realm but no real
credentials. Development defaults are visibly marked and are unsuitable for
deployment.

## Demonstration Script

The successful path is:

1. start Keycloak, broker, application, and the compatible local VS Agent;
2. issue the local holder an ACME playground employee badge;
3. open the protected application;
4. choose Keycloak and then Verana Wallet;
5. review the displayed QR and presentation status;
6. approve disclosure in the local holder;
7. observe Keycloak JIT-provision the user;
8. land on the protected page with the expected subject, organization, and
   employee role;
9. log out and repeat with the same credential to prove subject stability.

The denied path uses the rogue verifier tenant or a non-authorized trust
fixture and proves that no Keycloak session or user is created.

The live demonstration requires the configured Verana resolver to be
reachable. Resolver failure is demonstrated as a denied login, never replaced
by a positive local fixture. Deterministic trust fixtures are used only inside
automated tests and are labelled as test doubles.

## Testing Strategy

### Broker unit tests

- pairwise-sub determinism and sector separation;
- exact claim allowlists;
- receipt schema validation;
- every non-positive Verana verdict denies login;
- expiry and one-time transaction enforcement;
- safe error serialization and redacted logging.

### Broker integration tests

- OIDC discovery and JWKS validation;
- authorization code flow with state, nonce, and PKCE;
- mocked VS Agent pending, verified, denied, unavailable, and malformed
  responses;
- code replay rejection;
- redirect URI and client allowlists.

### Keycloak integration tests

- realm imports successfully;
- broker signature validation is enabled;
- first successful login creates one user;
- repeated login reuses the same external identity;
- ACME and employee mappings are applied;
- unexpected claims do not create groups or roles;
- denied verification creates neither a user nor an application session.

### Local end-to-end evidence

- full local issuance and presentation login;
- protected-page result;
- repeated-login subject stability;
- rogue or unauthorized denial;
- exact commands, commit hashes, and limitations recorded without secrets.

Passing automated tests is not physical-wallet evidence. A physical-wallet
claim requires separate trusted-HTTPS and device proof.

## Planned Repository Shape

```text
verana-keycloak-playground/
  apps/
    broker/
    demo-app/
  keycloak/
    realm-import/
  docs/
    superpowers/specs/
    evidence/
  scripts/
  compose.yaml
  package.json
  pnpm-workspace.yaml
  README.md
```

## Acceptance Criteria

The MVP is ready for the call when:

- one documented command sequence starts every local component;
- Keycloak is reachable and the realm imports reproducibly;
- a local holder can acquire the configured demo badge;
- presenting it through the trusted verifier creates a Keycloak user and
  application session;
- the application shows the same pairwise subject on a repeated login;
- organization and employee authorization are present;
- the rogue or unauthorized path creates no user and no session;
- automated broker and Keycloak integration checks pass;
- the README clearly distinguishes local evidence, real-wallet evidence, and
  unresolved ECS-Badge/testnet work;
- no secret, raw credential, token, or private key is committed;
- no push, publication, or deployment has occurred.
