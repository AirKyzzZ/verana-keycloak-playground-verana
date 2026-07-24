# Local Controlled Verana Authentication Stack Design

Date: 2026-07-24

Status: approved concept, awaiting written-spec review

## Purpose

Run the complete Verana-to-Keycloak authentication playground temporarily on
Maxime's MacBook Pro before any Verana Labs infrastructure deployment.

The local stack must exercise the actual reviewed VS Agent OpenID4VC plugin,
credential issuance, holder acceptance, presentation verification, proof of
trust receipt, OIDC broker, Keycloak JIT provisioning, protected application,
logout, and repeated login. The only controlled substitute is the Verana trust
resolver because locally generated DIDs do not have real testnet Q2/Q3
permissions.

The successful result is local integration evidence. It is not Verana testnet,
trusted-HTTPS, physical-wallet, or production evidence.

## Goals

- Run issuer, holder, and verifier as three isolated instances of the actual
  VS Agent image built from commit `e2bba78`.
- Issue and accept a real SD-JWT credential through OpenID4VCI.
- Present and verify that credential through OpenID4VP.
- Evaluate exact Q1, Q2, and Q3 response contracts through a controlled local
  resolver.
- Create a Keycloak user only from a `TRUSTED_AUTHORIZED` receipt.
- Prove stable pairwise subject reuse across two complete logins.
- Prove that a rogue verifier, malformed input, resolver failure, or bounded
  response violation cannot create a Keycloak session or user.
- Exercise the user-facing flow in Maxime's real Chrome profile.
- Start and stop the complete stack reproducibly without retaining credentials,
  presentations, tokens, screenshots, or disposable agent wallets.
- Restore the unrelated Twitter VS Agent after the test.

## Non-goals

- Registering local DIDs or permissions on Verana testnet.
- Copying private keys or agent wallet data from `clawdbot`.
- Modifying the existing `/opt/unfold` services.
- Public HTTPS or physical-wallet testing.
- Production hardening, high availability, backups, monitoring, or upgrades.
- Treating controlled resolver verdicts as proof of real Verana authorization.
- Pushing branches, deploying to Verana Labs, or commenting on specifications.
- Deleting unrelated Docker images, volumes, databases, or project state.

## Proof Boundary

Every successful page, command, and evidence record must use the label:

```text
LOCAL_CONTROLLED
```

`LOCAL_CONTROLLED` means:

- the credential and presentation are produced and verified by real VS Agent
  OpenID4VC code;
- issuer, holder, verifier, broker, Keycloak, and application boundaries are
  real local processes;
- the local resolver deterministically substitutes Verana Q1/Q2/Q3 for an
  exact allowlist of local DIDs and one exact VTJSC;
- the result does not establish testnet authorization or device
  interoperability.

No fixture service may replace issuance, holder acceptance, presentation
verification, the broker, Keycloak, or the protected application.

## Repository and Runtime Boundaries

The playground worktree remains:

```text
/Users/samsepiol/Downloads/GithubRepos/Work/Verana/verana-keycloak-playground/.worktrees/auth-demo
```

The reviewed VS Agent worktree remains:

```text
/Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim
```

The VS Agent source is not copied into the playground repository. Docker builds
one shared image from the second worktree and runs that image with three
isolated configurations and volumes.

All services bind to loopback or to an internal Docker network. Nothing is
published to the LAN or internet.

## Architecture

```text
Chrome
  -> demo app :3000
  -> Keycloak :8080
  -> Verana OIDC broker :3001
  -> verifier VS Agent :3201
  -> holder VS Agent :3111
  -> issuer VS Agent :3101
  -> controlled resolver :3099
  -> proof-of-trust receipt
  -> broker policy
  -> Keycloak JIT user
  -> protected profile
```

The controlled resolver is the only test double. All other arrows cross real
runtime and protocol boundaries.

## Services and Ports

| Service | Host binding | Container/public role |
| --- | --- | --- |
| Controlled resolver | `127.0.0.1:3099` | Q1/Q2/Q3, local VCT and VTJSC |
| Demo application | `127.0.0.1:3000` | Keycloak relying party and local holder UI |
| OIDC broker | `127.0.0.1:3001` | External Keycloak IdP |
| Keycloak | `127.0.0.1:8080` | Disposable `verana-playground` realm |
| Issuer admin | `127.0.0.1:3100` | VS Agent admin API |
| Issuer public | `127.0.0.1:3101` | OpenID4VCI issuer |
| Holder admin | `127.0.0.1:3110` | VS Agent admin API |
| Holder public | `127.0.0.1:3111` | OpenID4VC holder |
| Verifier admin | `127.0.0.1:3200` | VS Agent admin API |
| Verifier public | `127.0.0.1:3201` | OpenID4VP verifier |

Docker services use `host.docker.internal` when an OpenID4VC URL must be
reachable from both containers and the host.

## Local Identity and Credential Contract

The controlled identities are:

```text
issuer DID:   did:web:issuer.localhost
holder DID:   did:web:holder.localhost
verifier DID: did:web:verifier.localhost
rogue DID:    did:web:rogue.localhost
```

The issuer and verifier create their own keys and x5c certificates inside
their disposable wallets. The issuer certificate SAN carries the exact issuer
DID. The trusted verifier receipt carries the exact verifier DID. No key is
imported from the VPS or Verana testnet.

The local resolver serves one local VCT and one local VTJSC. All services use
those exact identifiers. The credential contains:

```json
{
  "subject_id": "local-controlled-user",
  "organization": "ACME",
  "role": "employee"
}
```

The holder cannot override these issuer-selected values.

## Controlled Resolver Contract

The resolver binds only to `127.0.0.1:3099` and implements:

- `GET /v1/trust/resolve?did=...`;
- `GET /v1/trust/issuer-authorization?did=...&vtjscId=...`;
- `GET /v1/trust/verifier-authorization?did=...&vtjscId=...`;
- `GET /vct/local-controlled-employee`;
- `GET /vtjsc/local-controlled-employee.json`;
- `GET /health`.

Positive Q1 requires exact issuer or verifier DID equality and returns:

```json
{
  "did": "<exact requested allowlisted DID>",
  "trustStatus": "TRUSTED",
  "production": true
}
```

Positive Q2 is returned only for the exact issuer DID and exact local VTJSC.
Positive Q3 is returned only for the exact verifier DID and exact local VTJSC.
Every other DID or schema is untrusted or unauthorized. The rogue DID is
always untrusted.

Responses use `application/json`, remain under 64 KiB, and contain only fields
accepted by the reviewed strict parsers.

The resolver source and UI must call this production-equivalent trust shape
while visibly labelling the mode `LOCAL_CONTROLLED`. The `production: true`
value exercises the same strict Q1 code path but is not represented as a real
network production verdict.

## VS Agent Isolation

One Docker image is built from VS Agent commit `e2bba78` using target
`vs-agent-openid4vc`.

Three containers run the same image:

- issuer enables only the issuer role;
- holder enables only the holder role;
- verifier enables only the verifier role.

Each container has:

- a unique `AGENT_WALLET_ID`;
- a generated unique `AGENT_WALLET_KEY`;
- a distinct named SQLite wallet volume;
- its own public DID;
- its own public and admin ports;
- `VS_AGENT_PLUGINS=messaging,openid4vc`;
- the controlled resolver URL;
- x5c issuer and verifier request signing;
- no shared Redis, PostgreSQL, keys, or wallet files.

The capability endpoint must return this exact contract on all three roles:

```json
{
  "contractVersion": 1,
  "offerClaims": ["subjectId", "organization", "role"],
  "disclosedClaims": ["subject_id", "organization", "role"]
}
```

## Keycloak and Application

Keycloak 26.7.0 uses the existing generated disposable realm and fresh local
secrets. Before the run, setup recreates `.data` and Keycloak is recreated
from the new realm import.

The realm continues to enforce:

- confidential `playground-app`;
- Authorization Code flow with S256;
- signed broker ID tokens and exact broker JWKS;
- JIT create-if-unique first login;
- exact `/organizations/acme` group mapping;
- exact `employee` realm-role mapping;
- external pairwise `sub` stored as `verana_subject`;
- no pre-created user.

Every application authorization includes `prompt=login`, so local logout
cannot reuse the existing Keycloak SSO session without a fresh wallet
presentation.

The demo application and broker display `LOCAL_CONTROLLED` without putting raw
credential, presentation, authorization request, tokens, receipts, or wallet
keys into the application session or browser logs.

## Mac Resource and Conflict Policy

The Mac has approximately 19 GB RAM, while Docker currently has a 3.8 GB
memory allocation. The test stack reuses the existing Keycloak image and one
shared VS Agent image.

Before startup:

1. record whether `twitter-bot-vs-agent` is running;
2. stop only `twitter-bot-vs-agent`, which owns ports 3000 and 3001;
3. leave `twitter-bot-redis`, project databases, and all volumes untouched;
4. fail before startup if any required port remains occupied;
5. fail rather than delete images or volumes when disk capacity is
   insufficient.

No Docker prune or unrelated cleanup is authorized by this design.

After teardown, restore `twitter-bot-vs-agent` only if it was running before
the test.

## Startup and Teardown

The implementation provides one guarded startup command and one guarded
teardown command.

Startup must:

1. verify exact Git commits or newer reviewed descendants;
2. verify Node 24 and Docker availability;
3. verify the expected port owner before stopping the Twitter container;
4. generate disposable secrets with mode `0600`;
5. build the single VS Agent image;
6. recreate Keycloak from the disposable realm;
7. start resolver, issuer, holder, verifier, broker, and demo app;
8. wait on bounded health checks;
9. verify all capability contracts and zero Keycloak users;
10. print only local URLs and the `LOCAL_CONTROLLED` boundary.

Teardown must:

1. stop playground processes and containers;
2. remove only playground-created containers, networks, and named volumes;
3. remove `.data` disposable secrets and retained protocol artifacts only
   after confirming their exact paths;
4. leave source code, images, unrelated containers, and unrelated volumes
   untouched;
5. restart `twitter-bot-vs-agent` only when startup recorded it as initially
   running;
6. confirm ports 3000, 3001, 3099, 3100, 3101, 3110, 3111, 3200, and 3201 no
   longer belong to the playground.

Image removal is optional and requires separate approval because a rebuilt
image is reusable for the later infrastructure deployment.

## Failure Handling

- A failed preflight starts no positive login.
- A failed service health check stops startup and reports the exact component.
- A non-positive Q1/Q2/Q3 result denies disclosure or session creation.
- Missing or inexact DID, VTJSC, VCT, capability, claim, issuer, verifier, or
  subject fields fail closed.
- Resolver timeout, non-JSON response, malformed JSON, invalid UTF-8, or body
  larger than 64 KiB fails closed.
- Share operations with an uncertain response are not replayed.
- A failed teardown preserves unrelated containers and reports exact remaining
  playground resources.
- A failed Twitter-container restoration is reported without deleting or
  recreating its state.

## Test and Evidence Plan

### Automated gates

- playground lint, typecheck, 172 tests, and both builds;
- VS Agent OpenID4VC 80 tests and package build;
- controlled resolver focused tests;
- Compose rendering and secret scan;
- Keycloak realm verification with zero users.

### Live local API flow

The live script must:

1. pass exact controlled issuer Q1/Q2;
2. pass exact controlled verifier Q1/Q3;
3. issue and accept the configured badge;
4. resolve and share a trusted request;
5. receive a `ResponseVerified` receipt;
6. assert both receipt verdicts are `TRUSTED_AUTHORIZED`;
7. repeat the flow and assert stable pairwise subject derivation;
8. run the rogue verifier and assert denial before share;
9. print `PASS LOCAL_CONTROLLED`.

### Real Chrome flow

Using Maxime's existing Chrome profile:

1. open `http://localhost:3000`;
2. start Keycloak login;
3. choose Verana Wallet;
4. complete issuance and holder acceptance;
5. inspect the requested VCT and claims;
6. approve the presentation;
7. complete Keycloak JIT login;
8. assert the profile shows a non-empty `verana_subject`, ACME, and employee;
9. locally log out;
10. repeat and confirm fresh wallet interaction plus the same Keycloak account;
11. attempt a rogue flow and confirm no additional user or session;
12. verify the browser console and relevant network requests contain no
    unexpected errors or sensitive bodies.

### Adversarial gates

- wrong, missing, or non-string Q1 DID;
- `production` false or missing;
- wrong, missing, or non-string Q2/Q3 DID and VTJSC;
- non-boolean authorization;
- rogue verifier;
- malformed and oversized resolver responses;
- malformed and oversized broker-to-verifier responses;
- state, nonce, PKCE, callback, CSRF, cookie, replay, and logout checks;
- resolver unavailable during a new login;
- no Keycloak user created by any denied path.

## Acceptance Criteria

The local stack is accepted only when:

- every automated gate passes on supported Node 24;
- the real local API script prints `PASS LOCAL_CONTROLLED`;
- the full Chrome login succeeds twice with stable subject/account reuse;
- the rogue and resolver-failure paths create no user or session;
- the independent final review has no Critical or Important findings;
- evidence distinguishes automated, controlled-local, browser, and unproven
  testnet/device claims;
- teardown removes only disposable playground state;
- the previously running Twitter VS Agent is restored;
- both Git worktrees remain clean;
- nothing is pushed or deployed externally.

## Later Verana Infrastructure Migration

The later migration replaces only:

- controlled local resolver URL with the Verana resolver;
- local issuer and verifier DIDs with instances controlling authorized DIDs;
- loopback HTTP endpoints with trusted HTTPS endpoints;
- disposable local state with infrastructure-managed secrets and storage.

The broker policy, pairwise subject derivation, Keycloak mapping, application
OIDC integration, capability contract, receipt schema, and test sequence remain
unchanged.
