# FIDES Playground Corrected Execution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development`
> (recommended) or `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax.

Date: 2026-07-25

**This document supersedes:**

- `docs/superpowers/plans/2026-07-25-next-agent-fides-playground-handoff.md`
- `docs/superpowers/plans/2026-07-25-local-controlled-openid4vc-tls.md`

Both are retained for history only. Where they disagree with this plan or with
`docs/superpowers/specs/2026-07-25-did-bound-fides-playground-design.md`, the
design spec governs and this plan implements it.

**Why a rewrite:** the prior handoff instructed the next agent to execute the
controlled-TLS plan, but the approved design spec explicitly lists that plan
among the documents it replaces, and the TLS plan hardcodes a legacy `/v1/trust`
resolver URL plus non-port-encoded `did:web` identifiers that the design
forbids. The handoff also understated the largest remaining gap: the controlled
resolver still speaks the legacy three-GET v1 contract while the reviewed VS
Agent branch requires `POST /v4/verifiable-trust/resolve`. Those two documents
are folded into this one so there is a single authoritative sequence.

**Goal:** get the complete DID-bound local demo working end to end — controlled
TLS, resolvable `did:web` identities, real v4 trust resolution, holder consent
gates, Proof-of-Trust UI, and Keycloak brokering — then inventory the wallet
integrations against that working foundation.

**Standing direction from Maxime (2026-07-25):** keep everything local for now.
Make it work properly first, with all the integrations. Upstream contribution
and exact-spec reconciliation come after, not during.

---

## Verified Starting State

Every value below was checked against the live working copies on 2026-07-25.
Re-verify before starting; do not trust this table if the date has moved.

| Repo / worktree | Branch | HEAD | Tree |
| --- | --- | --- | --- |
| `verana-keycloak-playground/.worktrees/auth-demo` | `codex/auth-demo` | `5f7d387` | clean (untracked `docs/superpowers/.DS_Store` only) |
| `Verana/worktrees/keycloak-subject-claim` (VS Agent) | `codex/keycloak-subject-claim` | `73c096f` | clean |
| `Verana/verana-spec` | `main` | `eaac693` | clean, level with `origin/main` |

VS Agent SDD ledger (`.superpowers/sdd/2026-07-25-did-bound-openid4vc-v4-trust/progress.md`):
Tasks 1–7 complete and independently approved; **Task 8 next, Task 9 pending**.

Last recorded VS Agent evidence at `73c096f`: focused tests 25/25, package tests
237/237, compile / typecheck / ESLint / Prettier / `git diff --check` all passed.

Playground baseline (pre-integration, do **not** re-present as post-integration
proof): 412/412 tests, typecheck passed, lifecycle inactive, controlled ports clear.

### What already exists in playground code

- `apps/broker/` — 13 modules, ~1190 lines. OIDC provider, policy, login service,
  pairwise sub, account/transaction stores, VS Agent client.
- `apps/demo-app/` — 7 modules, ~1990 lines. Keycloak client, local wallet client,
  session store, HTML views.
- `apps/local-resolver/` — 3 modules, ~287 lines. **Legacy v1 contract.**
- `scripts/` — 10 modules including `local-stack.ts` (49 KB), `verify-local-flow.ts`
  (36 KB), `verify-keycloak.ts` (20 KB), `verify-local-adversaries.ts` (10 KB).

### What does not exist yet

- **No TLS code at all.** No `scripts/local-tls-certificates.ts`, no gateway, no
  certificate material. The controlled-TLS work is 100% unstarted.
- **No v4 resolver.** `apps/local-resolver/src/server.ts` serves
  `GET /v1/trust/resolve`, `GET /v1/trust/issuer-authorization`,
  `GET /v1/trust/verifier-authorization`. `contract.ts` returns
  `{did, trustStatus, production}` and `{did, vtjscId, authorized}`.
- **No new VS Agent config in Compose.** `compose.local-controlled.yaml` is missing
  all five new variables, still sets `OID4VC_REQUEST_SIGNER: x5c` and
  `OID4VC_ISSUER_SIGNER: x5c`, uses non-port-encoded `did:web:issuer.localhost`,
  and points vct/vtjsc at plain `http://host.docker.internal:3099`.
- **No offer review step.** `apps/demo-app/src/local-wallet-client.ts` calls
  `POST /oid4vc-demo/wallet/accept-offer` with a raw `credentialOffer`. The
  presentation side already threads `gateId` through `resolve-request` → `share`.
- **No DID Documents, no Linked VPs, no ecosystem DID.**

---

## Global Constraints

Local-only, fail-closed, evidence-honest.

- Work locally only. Do not push, deploy, publish, open or approve PRs, or comment
  on GitHub. This applies to every repo touched, including wallet repos.
- Do not modify `main` in any repo. Use the two worktrees named above.
- Do not weaken DID, trust, Linked-VP, consent-gate, broker, or Keycloak checks to
  make a demo pass. A failing demo is a result; a loosened check is a defect.
- Positive issuer identity requires a Credo-verified DID credential signer and an
  exact `iss` match. Positive verifier identity requires a Credo-verified DID
  request-object signer and exact `decentralized_identifier` binding.
- X.509 URI SAN values are negative/legacy evidence only. A DID copied into a SAN
  is never authenticated identity.
- Q1 and Q2/Q3 are independent resolver requests. Trust never implies authorization.
- Do not set `allowInsecureHttpUrls`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, or any
  certificate bypass. Do not install the ephemeral CA into the macOS, Chrome,
  Docker, or global Node trust stores.
- Label all local evidence `LOCAL_CONTROLLED`. It never proves testnet
  authorization, public DID resolution, public-CA TLS, external-wallet
  interoperability, or production readiness.
- Never claim an external wallet works without protocol, device/browser, and
  trusted-HTTPS evidence.
- Preserve every wallet's source changes, Git/LFS history, APKs, and evidence.
  Six wallet repos currently carry ~168 uncommitted files (see Phase G).
- Do not delete caches, artifacts, containers, or volumes without a fresh target
  check and explicit approval. Journal owned resources before mutation.
- Never log request paths, queries, headers, bodies, credentials, presentations,
  receipts, tokens, cookies, private keys, or control tokens.
- Keep updates concise. Use artifact files and the SDD progress ledger rather than
  replaying context in chat.

---

## Authoritative Reading Order

Read the design spec first. It governs.

1. Playground `docs/superpowers/specs/2026-07-25-did-bound-fides-playground-design.md`
2. This plan
3. VS Agent `docs/superpowers/plans/2026-07-25-did-bound-openid4vc-v4-trust.md` (Tasks 8–9)
4. VS Agent `.superpowers/sdd/2026-07-25-did-bound-openid4vc-v4-trust/progress.md`
5. Playground `README.md` and `compose.local-controlled.yaml`

Normative resolver schemas, `verana-spec` at `eaac693`:

- `v4/verana-indexer/schemas/v4/vt/request.schema.json`
- `v4/verana-indexer/schemas/v4/vt/response.schema.json`
- `v4/verana-indexer/spec.md`

The July 24 designs and plans are historical. They must not override the
July 25 design spec.

---

## Phase A — Finish the VS Agent branch

Do this before touching the playground. The playground consumes this API, and
re-wiring against an unproven branch wastes the integration work.

### Task A1: VS Agent Task 8 — prove fail-closed behavior

Execute Task 8 exactly as written in the VS Agent plan (lines 660–712).

**Files:** `packages/plugin-openid4vc/tests/flow.integration.test.ts`,
`packages/plugin-openid4vc/tests/helpers/resolverStub.ts`,
`packages/plugin-openid4vc/README.md`

- [ ] Confirm the VS Agent worktree is clean at `73c096f` (`git status --short --branch`).
- [ ] Generate the Task 8 SDD brief from the plan and execute with a fresh implementer.
- [ ] Prove each case fails closed: unmapped issuer URL never requests a token;
      trusted issuer review required before request/storage; credential signer
      mismatch never stores; forged verifier SAN never reaches the resolver or
      submits; trusted-tenant X.509 session never yields a positive receipt;
      unknown / expired / consumed / conflicting gates blocked; resolver
      unavailable and malformed v4 responses resolve to `RESOLVER_UNAVAILABLE`,
      never trusted.
- [ ] Prove Q1 and Q2/Q3 are recorded as distinct POST requests.
- [ ] Document the `local-controlled` configuration contract in the README,
      including the X.509 negative-only boundary, and state plainly that package
      tests do not prove live TLS, real `did:web`, Linked-VP fixtures, Keycloak,
      browser, testnet, or external-wallet interoperability.
- [ ] Run the full gate:

```bash
pnpm --filter @verana-labs/vs-agent-plugin-openid4vc test -- --run
pnpm --filter @verana-labs/vs-agent-plugin-openid4vc compile
pnpm --filter @verana-labs/vs-agent test -- --run
pnpm check-format
pnpm check-types
pnpm build
git diff --check
```

- [ ] Require independent spec and code-quality approval.
- [ ] Commit: `test(openid4vc): prove DID trust boundary`.

### Task A2: VS Agent Task 9 — security review record

**Files:** create `docs/superpowers/reviews/2026-07-25-did-bound-openid4vc-v4-trust.md`

- [ ] Review the complete branch `2b2cc4c..HEAD`: issuer/verifier provenance,
      exact URL-to-DID binding, independent Q1/Q2/Q3, complete v4 schema parsing,
      expiry handling, exact active participation, Linked-VP failure modes, gate
      invalidation and concurrency, request-signer session binding, receipt
      compatibility, and absence of sensitive logging.
- [ ] For every Critical or Important finding: add a focused RED regression,
      observe it fail, implement the minimum correction, observe GREEN, rerun A1.
- [ ] Record scope, reviewed commits, exact commands with fresh output, a verdict
      per area, open findings, and the proof boundary.
- [ ] Commit: `docs: review DID-bound OpenID4VC trust`.

**Phase A exit:** VS Agent branch green, reviewed, no open load-bearing finding.

---

## Phase B — Controlled TLS gateway

Absorbed from the superseded TLS plan, corrected to the design spec's identifier
and resolver contract.

### Task B1: Ephemeral CA and leaf certificate

The superseded TLS plan's Task 1 is reusable essentially verbatim; port it.

**Files:** create `tsconfig.scripts.json`, `scripts/local-tls-certificates.ts`,
`tests/local-tls-certificates.test.ts`

- [ ] Write failing tests first. Export `LOCAL_TLS_HOSTNAMES` as the exact four
      names `issuer.localhost`, `holder.localhost`, `verifier.localhost`,
      `resolver.localhost`.
- [ ] Generate a per-run private CA and one leaf certificate carrying all four
      SANs, using only Node's built-in `tls`/`fs` APIs and the OpenSSL 3 CLI via
      `execFile` with exact arguments. No `mkcert`, no npm certificate package.
- [ ] Private keys (`ca-key.pem`, `server-key.pem`) are mode `0600` and host-only.
- [ ] Test that regeneration is deterministic in shape and that keys are never
      world-readable.
- [ ] Run `pnpm check`.

### Task B2: Loopback HTTPS gateway with DID routes

Corrected from the TLS plan's Task 2: adds Docker network aliases and DID
document routing, both required by the design spec and absent from the old plan.

- [ ] Bind the gateway to `127.0.0.1:3443` only. Route by exact `Host` header:

```text
https://issuer.localhost:3443    -> http://127.0.0.1:3101
https://holder.localhost:3443    -> http://127.0.0.1:3111
https://verifier.localhost:3443  -> http://127.0.0.1:3201
https://resolver.localhost:3443  -> http://127.0.0.1:3099
```

- [ ] Give the gateway Docker network aliases for the same four hostnames so
      containers and host-side verification reach one identity. **This is new
      relative to the superseded plan, which only handled host-side loopback.**
- [ ] Mount only `ca.pem` into containers, read-only, via `NODE_EXTRA_CA_CERTS`.
      Never mount `ca-key.pem`, `server-key.pem`, or `server.pem`.
- [ ] Keep Chrome on `http://localhost:3000` and Keycloak on `http://localhost:8080`.
      Keep host orchestration on loopback HTTP `127.0.0.1:{3101,3111,3201,3099}`.
- [ ] Leave DIDComm `AGENT_ENDPOINTS` unchanged unless a separate reviewed task
      proves DIDComm TLS is required.
- [ ] Reject any request whose `Host` is not one of the four exact names.
- [ ] Run `pnpm check`.

### Task B3: Guarded lifecycle integration

- [ ] Wire certificate generation and gateway startup into `scripts/local-stack.ts`
      and `scripts/setup-local-controlled.ts`.
- [ ] Journal every owned process, file, port, and Docker resource before mutation.
- [ ] Teardown deletes all generated TLS material and leaves unrelated Docker
      resources untouched.
- [ ] Run `pnpm check` and an independent review of the TLS slice.

**Phase B exit:** all four origins serve valid HTTPS over the per-run CA; nothing
was installed into a system trust store.

---

## Phase C — Real identities and the v4 resolver

The largest remaining work. Treat C1 as a rewrite, not an edit.

### Task C1: Rewrite the controlled resolver to the merged v4 contract

**Decision (Maxime, 2026-07-25): full-fidelity v4 fixture.** Emit complete,
schema-valid v4 responses, not the minimum that satisfies the parser. The fixture
is reused by the later wallet catalog, so shortcuts here are paid for repeatedly.

**Decision (Maxime, 2026-07-25): merged v4 only.** Implement `eaac693` strictly.
`verana-spec` PRs #22 and #23 are open and rewrite this exact contract (regex
pattern, Participant retention, expiry gate, DID bindings, endpoint gates,
EcsCredential keying, error contract, traversal pagination). Do **not**
pre-implement them. Record the deltas in the acceptance report so the migration is
a known scoped task.

**Files:** rewrite `apps/local-resolver/src/contract.ts` and
`apps/local-resolver/src/server.ts`; create focused tests beside each.

- [ ] Delete the three legacy GET routes. Serve `POST /v4/verifiable-trust/resolve`.
- [ ] Honour the client's constraints: 5 s timeout budget, responses under 64 KiB.
- [ ] Support Q1 (selectors only: `ecsCredentials`, `services`, `presentations`
      with `unresolvableCredentialIds`/`invalidCredentialIds`, `ecosystems` with
      `credentialSchemas.includeArchived: false`).
- [ ] Support Q2/Q3 (Q1 selectors plus `expectedParticipation: {role, ecosystemId,
      credentialSchemaId}` where role is `ISSUER` for Q2 and `VERIFIER` for Q3).
- [ ] Emit valid `participants` with roles drawn from `HOLDER | ISSUER | VERIFIER |
      ISSUER_GRANTOR | VERIFIER_GRANTOR | ECOSYSTEM` and states from `ACTIVE |
      FUTURE | INACTIVE | EXPIRED | REVOKED | SLASHED | REPAID`.
- [ ] Emit valid ECS credentials from `ServiceCredential | OrganizationCredential |
      PersonaCredential | UserAgentCredential`.
- [ ] Respect the client's strict formats: UTC timestamps `YYYY-MM-DDTHH:MM:SSZ`,
      DIDs matching `^did:`, bech32 `^verana1[a-z0-9]+$`, coin `^[0-9]+[a-z][a-z0-9]*$`,
      SRI digests `^sha(256|384|512)-`. Undocumented fields must be rejected by the
      client — verify that they are.
- [ ] Keep the existing control-plane endpoints for adversarial modes (resolver
      down, malformed, expired, unauthorized) and extend them to v4 shapes.
- [ ] Write failing tests first for every positive and adversarial shape.

### Task C2: Serve DID Documents and Linked VPs

**Files:** `apps/local-resolver/src/server.ts`, `scripts/setup-local-controlled.ts`,
plus focused tests.

- [ ] Serve these exact identifiers and routes:

```text
did:web:issuer.localhost%3A3443            https://issuer.localhost:3443/.well-known/did.json
did:web:holder.localhost%3A3443            https://holder.localhost:3443/.well-known/did.json
did:web:verifier.localhost%3A3443          https://verifier.localhost:3443/.well-known/did.json
did:web:verifier.localhost%3A3443:rogue    https://verifier.localhost:3443/rogue/did.json
did:web:resolver.localhost%3A3443:ecosystem https://resolver.localhost:3443/ecosystem/did.json
```

- [ ] Every readiness gate verifies: HTTP 200 over the controlled CA;
      `Content-Type` is `application/did+ld+json` or `application/did+json`;
      exact document `id`; the signing verification method belongs to the same
      base DID; required service identifiers and endpoints are exact; and no
      document is reachable under a different host.
- [ ] Sign the ecosystem VTJSC VP with the ecosystem DID. **If this requires a
      fourth VS Agent instance, stop and update the design spec and this plan
      explicitly before writing code.** Do not improvise a fourth agent.
- [ ] Write failing tests first for: wrong host, wrong document `id`, missing
      verification method, foreign signer, invalid Linked VP, missing Linked VP,
      wrong schema, expired credential, missing participation.

### Task C3: Wire the new VS Agent configuration

**Files:** `compose.local-controlled.yaml`, `scripts/local-controlled-config.ts`

- [ ] Add the five missing variables to all three agent services:

```yaml
VERANA_NETWORK_ID: local-controlled
VERANA_ECOSYSTEM_ID: "184"
VERANA_CREDENTIAL_SCHEMA_ID: "249"
OID4VC_CREDENTIAL_ISSUER_BINDINGS_JSON: '{"https://issuer.localhost:3443":"did:web:issuer.localhost%3A3443"}'
OID4VC_REQUIRED_LINKED_VP_FRAGMENTS: '[...]'
```

- [ ] Switch `OID4VC_REQUEST_SIGNER` and `OID4VC_ISSUER_SIGNER` from `x5c` to `did`
      on the positive issuer and verifier. Keep an `x5c` path only for the rogue
      negative fixture.
- [ ] Replace all `AGENT_PUBLIC_DID` values with the port-encoded forms.
- [ ] Move `VERANA_RESOLVER_URL`, `UNFOLD_VCT`, and `UNFOLD_VTJSC_ID` onto
      `https://resolver.localhost:3443`. Note the superseded TLS plan specified
      `/v1/trust` here; that is wrong — the client appends
      `/v4/verifiable-trust/resolve` itself, so `VERANA_RESOLVER_URL` is the base.
- [ ] Verify the strict config parser accepts the result (it rejects malformed
      bindings and non-numeric registry ids).

### Task C4: Migrate the playground to the consent-gate API

**Files:** `apps/demo-app/src/local-wallet-client.ts`, `apps/demo-app/src/server.ts`,
plus focused tests.

- [ ] Replace raw `acceptOffer(credentialOffer)` with `reviewOffer(offerUri)` then
      `acceptOffer(gateId)`, threading the gate id and surfacing the verdict.
- [ ] Confirm the presentation path already uses `resolveRequest` → `share(gateId)`
      and that it now renders the DID-signed request review.
- [ ] Prove the rogue X.509 request never reaches a positive resolver decision.
- [ ] Run focused tests, `pnpm check`, and an independent security review.

**Phase C exit:** the holder resolves real `did:web` documents over the controlled
CA, gets real v4 verdicts, and cannot accept or share without a valid gate.

---

## Phase D — Proof-of-Trust UI and Keycloak authorization

**Files:** `apps/demo-app/src/html.ts`, `apps/demo-app/src/server.ts`,
`apps/broker/src/policy.ts`, `apps/broker/src/login-service.ts`,
`apps/broker/src/oidc-provider.ts`, `keycloak/realm.template.json`, plus tests.

- [ ] Render the four holder states: `RESOLVING`, `TRUSTED`, `UNTRUSTED`,
      `UNVERIFIED`. Map them from the VS Agent `Verdict` union
      (`TRUSTED_AUTHORIZED`, `TRUSTED_NOT_AUTHORIZED`, `UNTRUSTED`,
      `RESOLVER_UNAVAILABLE`) and document the mapping — the two vocabularies are
      not identical and the difference must be deliberate, not accidental.
- [ ] Render five blocks in order: trust status, service, operator, other
      credentials, trust chain / failures.
- [ ] Show Q1/Q2 before acceptance and Q1/Q3 before sharing.
- [ ] Permit Keycloak JIT provisioning and session creation **only** for an exact
      `TRUSTED_AUTHORIZED` receipt bound to the session signer.
- [ ] Store a stable pairwise `sub` and `verana_subject`. Repeat login must map to
      the same account.
- [ ] Prove denied, replayed, expired, resolver-down, wrong-DID, and X.509-forged
      cases leave Keycloak account and session counts unchanged.
- [ ] Run focused broker/demo tests and full `pnpm check`.

---

## Phase E — Live local and real-Chrome evidence

**Files:** playground verification scripts, `docs/evidence/README.md`.
Store only bounded, non-secret evidence under the existing evidence policy.

- [ ] `pnpm local:setup`, `pnpm local:up`, `pnpm local:status`.
- [ ] Resolve every DID Document and required Linked VP over the controlled CA.
- [ ] Complete: DID-signed issuance review → acceptance → credential storage →
      presentation review → share → verifier receipt → Keycloak login → repeat
      login with stable subject.
- [ ] `pnpm local:verify` and `pnpm local:adversarial`.
- [ ] Real Chrome for user-visible issuance, presentation, Keycloak callback,
      session, and repeat login. Capture every trust state and all five blocks.
- [ ] Run all adversarial identity, resolver, Linked-VP, consent, broker, and
      Keycloak cases.
- [ ] `pnpm local:down`, then prove unrelated containers, volumes, and ports are
      untouched and any recorded pre-existing container state is restored.
- [ ] Record exact commands, timestamps, results, and proof boundaries.

---

## Phase F — Acceptance report

**Files:** create `docs/evidence/2026-07-25-did-bound-local-acceptance.md`

- [ ] Re-fetch `verana-spec`, record its exact HEAD, and separate merged normative
      requirements from open-PR direction. As of this writing: merged at `eaac693`;
      open PRs #22, #23 (resolver contract), #13 (playground spec, referenced by the
      design at `372e9ff`).
- [ ] List the C1 fixture deltas against PRs #22/#23 as a known future migration.
- [ ] List proven local claims, unproven external claims, failures, and remaining
      integration gaps.
- [ ] Do not mark the demo accepted unless every design acceptance criterion
      (design spec lines 681–702) is evidenced.

---

## Phase G — Wallet integration inventory

Evidence table only. **No wallet implementation changes in this phase.**

**Files:** create `docs/evidence/2026-07-25-wallet-integration-inventory.md`

Verified repository state on 2026-07-25 — start here, re-check before use:

| Repo | Branch | HEAD | Uncommitted |
| --- | --- | --- | --- |
| `paradym-wallet` | `feat/verana-trust-integration` | `63bb895` | 9 |
| `sphereon-mobile-wallet` | `feat/verana-trust-integration` | `53335f5` | 20 |
| `procivis-one-wallet` | `codex/procivis-verana` | `77bdbda` | 18 |
| `procivis-one-core` | `codex/procivis-verana` | `ee5a2d02` | 33 |
| `procivis-react-native-one-core` | `codex/procivis-verana` | `74ec258` | 4 |
| `eidch-android-wallet-swiyu-probe` | `feat/verana-trust-integration` | `8c02755` | 48 |
| `AltMe` | `feat/verana-trust-integration` | `0a23047` | 36 |
| `bc-wallet-mobile` | `main` | `05c483a` | 0 |
| `eudi-wallet-oid4vc-android-igrant-probe` | detached | `9a743cc` | 0 |
| `wallet-frontend` | `master` | `2f73bc1` | 0 |
| `wallet-backend-server` | `master` | `7c1a496` | 0 |
| `unfold-verana-integration` | `main` | `63772b1` | 1 |
| `hologram-verifiable-services` | `main` | `1bda024` | 3 |
| `mosip-playground` | `demo/playground-polished` | `a60561d` | 0 |

- [ ] **First, before anything else: confirm the ~168 uncommitted files across the
      six dirty repos are represented in `verana-fides-integrations/artifacts/diffs/`.**
      Twelve patch/diff files exist there. Any uncommitted change not captured is
      work at risk. Report gaps; do not clean, stash, or check out anything.
- [ ] Resolve what "the eight wallets" means and state the list explicitly. Current
      integration docs exist for: Paradym, Sphereon, Procivis, SWIYU, Talao/AltMe,
      EUDI reference Android, iGrant. Wave-0 Verana-native / existing: Hologram,
      MOSIP/Inji, Unfold.
- [ ] Per wallet record: repo, branch, commit, dirty state, protocol support, build
      status, artifact checksum, device/browser evidence, issuer compatibility,
      verifier compatibility, blockers.
- [ ] Distinguish source/build evidence from real external interoperability.
- [ ] Do not rebuild all wallets. Use focused checks and existing evidence first.

---

## Phase H — Next-session audit prompt

**Files:** create `docs/superpowers/prompts/2026-07-25-fides-wallet-issuer-audit.md`

- [ ] Include exact repos, worktrees, branches, commits, dirty-state warnings,
      tests, runtime evidence, and unresolved findings from Phases A–G.
- [ ] Require live browsing of `https://fides.community/ecosystem-explorer/issuer-catalog/`.
- [ ] Require an issuer table: organization, credential types, issuance protocol,
      wallet compatibility, verifier path, trust evidence, public/test environment,
      authentication prerequisites, integration risk.
- [ ] Require cross-comparison of every wallet against every relevant FIDES issuer
      and the completed Keycloak flow.
- [ ] Require every claim classified `PROVEN_LOCAL`, `PROVEN_EXTERNAL`, `PARTIAL`,
      `BLOCKED`, or `UNKNOWN`.
- [ ] Require a recommended information architecture for the real playground:
      personal wallets, business wallets, issuers, verifiers, ecosystems,
      credentials, Keycloak demos, per-integration pages, evidence.
- [ ] Require a sequenced implementation plan with security gates, test strategy,
      ownership, dependencies, demo fixtures, deployment boundary, and non-goals.
- [ ] Forbid implementation during the audit session until Maxime approves the
      resulting architecture and plan.

---

## Appendix — Verified integration contract

Read directly from source at `73c096f`. Use these, not the prose in older docs.

### Holder API — `packages/plugin-openid4vc/src/services/WalletService.ts`

```ts
reviewOffer(offerUri: string): Promise<{
  gateId: string
  verdict: Verdict
  issuerDid: string | null
  credentialIssuer: string
  evidence: TrustEvidence
}>
acceptOffer(gateId: string)
resolveRequest(authorizationRequest: string)
share(gateId: string)
listCredentials()
clearCredentials()
invalidateGates(): void
```

HTTP surface — `src/nestjs/WalletController.ts`:

```text
POST /oid4vc-demo/wallet/review-offer
POST /oid4vc-demo/wallet/accept-offer
POST /oid4vc-demo/wallet/resolve-request
POST /oid4vc-demo/wallet/share
GET  /oid4vc-demo/wallet/credentials
```

### Verdict — `src/trust/types.ts`

```ts
type Verdict = 'TRUSTED_AUTHORIZED' | 'TRUSTED_NOT_AUTHORIZED' | 'UNTRUSTED' | 'RESOLVER_UNAVAILABLE'
```

Gates are single-use, expiring, and operation-bound (`'issuance'` vs presentation).
`acceptOffer` throws `GateBlockedError` on unknown, expired, consumed, or
non-`TRUSTED_AUTHORIZED` gates.

### Plugin options — `src/types.ts`

```ts
interface OpenId4VcPluginOptions {
  publicApiBaseUrl: string
  issuerEnabled: boolean
  verifierEnabled: boolean
  holderEnabled: boolean
  resolverUrl: string
  vct: string
  vtjscId: string
  rogueVerifierDid: string
  requestSignerMethod: 'x5c' | 'did'
  issuerSignerMethod: 'x5c' | 'did'
  issuerDisplayName: string
  credentialDisplayName: string
  verifierDisplayName: string
  networkId: string
  ecosystemId: number
  credentialSchemaId: number
  credentialIssuerBindings: Readonly<Record<string, string>>
  requiredLinkedVpServiceFragments: readonly string[]
}
```

### Environment contract

Existing: `AGENT_PUBLIC_DID`, `OID4VC_REQUEST_SIGNER`, `OID4VC_ISSUER_SIGNER`,
`VERANA_RESOLVER_URL`, `UNFOLD_VCT`, `UNFOLD_VTJSC_ID`, `ROGUE_VERIFIER_DID`.

New and currently absent from Compose: `VERANA_NETWORK_ID`,
`VERANA_ECOSYSTEM_ID`, `VERANA_CREDENTIAL_SCHEMA_ID`,
`OID4VC_CREDENTIAL_ISSUER_BINDINGS_JSON`, `OID4VC_REQUIRED_LINKED_VP_FRAGMENTS`.
Parsed by `apps/vs-agent` (see `tests/openid4vcTrustConfig.test.ts`), which
expects `local-controlled` / `184` / `249` for this environment.

### Resolver wire contract — `src/trust/TrustClient.ts`

`POST {resolverUrl}/v4/verifiable-trust/resolve`, 5 s timeout, 64 KiB response cap.

Q1 body carries selectors only. Q2/Q3 add
`expectedParticipation: { role, ecosystemId, credentialSchemaId }`.
Parsing is strict: unknown fields and format violations throw
`invalid trust resolver response: …`.

---

## Completion Definition

Complete only when:

1. VS Agent Tasks 8–9 are reviewed and green.
2. Controlled TLS, DID Documents, Linked VPs, holder gates, receipts, and Keycloak
   are proven live locally.
3. Full API, adversarial, teardown, and real-Chrome evidence is recorded.
4. Merged v4 is implemented and the open-PR deltas are documented, not implemented.
5. Wallet integrations are inventoried with no work lost.
6. The audit prompt is written for the separate issuer/wallet planning session.
