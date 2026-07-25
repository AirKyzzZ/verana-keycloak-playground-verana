# FIDES Playground Next-Agent Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resume the DID-bound VS Agent, Keycloak, and FIDES playground work from the exact reviewed local state, finish live local proof, and leave a separate evidence-led audit prompt for the eight wallets and FIDES issuers.

**Architecture:** VS Agent is the security boundary for OpenID4VC issuer/verifier identity, Verana v4 trust, Linked-VP evidence, consent gates, and proof receipts. The playground supplies controlled TLS, resolvable `did:web` identities, the local resolver, Keycloak brokering, UI, lifecycle isolation, adversarial fixtures, and real-browser proof. Wallet and issuer expansion happens only after this foundation is green.

**Tech Stack:** TypeScript, Node.js, pnpm, Vitest, NestJS, Credo TS, Docker Compose, Keycloak 26.7.0, OpenID4VCI, OpenID4VP, SD-JWT VC, Verana v4 resolver, Playwright/real Chrome.

## Global Constraints

- Work locally only. Do not push, deploy, publish, approve PRs, or comment on GitHub.
- Do not modify `main`; use the existing isolated worktrees and branches below.
- Do not weaken DID, trust, Linked-VP, gate, broker, or Keycloak checks to make a demo pass.
- Positive issuer identity requires a Credo-verified DID credential signer and exact `iss`.
- Positive verifier identity requires a Credo-verified DID request-object signer and exact `decentralized_identifier` binding.
- X.509 URI SAN values are negative/legacy evidence only.
- Q1 and Q2/Q3 are independent resolver requests. Trust never implies authorization.
- Local evidence is `LOCAL_CONTROLLED`, never testnet or external-wallet acceptance.
- Never claim an external wallet works without protocol, device/browser, and trusted-HTTPS evidence.
- Preserve every wallet's source changes, Git/LFS history, APKs, and evidence.
- Do not delete caches, artifacts, containers, or volumes without fresh target checks and explicit approval.
- Keep updates and reports concise. Use artifact files and the progress ledger rather than replaying context in chat.

## Authoritative Files and Worktrees

### Playground

```text
Worktree: /Users/samsepiol/Downloads/GithubRepos/Work/Verana/verana-keycloak-playground/.worktrees/auth-demo
Branch: codex/auth-demo
HEAD: af2c101
```

Read in this order:

1. `docs/superpowers/specs/2026-07-25-did-bound-fides-playground-design.md`
2. `docs/superpowers/plans/2026-07-25-local-controlled-openid4vc-tls.md`
3. `docs/superpowers/plans/2026-07-25-next-agent-fides-playground-handoff.md`
4. `README.md`
5. `compose.local-controlled.yaml`

The approved design at `af2c101` governs architecture. The older July 24 designs are historical and must not override it.

### VS Agent

```text
Worktree: /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim
Branch: codex/keycloak-subject-claim
HEAD: 73c096f1e0c20ca72e4b5daad0e87aafbf32e29c
```

Read:

1. `docs/superpowers/plans/2026-07-25-did-bound-openid4vc-v4-trust.md`
2. `.superpowers/sdd/2026-07-25-did-bound-openid4vc-v4-trust/progress.md`
3. Task reports in that same SDD directory.

### Verana specifications

```text
Repository: /Users/samsepiol/Downloads/GithubRepos/Work/Verana/verana-spec
Branch at last review: main
Last reviewed HEAD: eaac693
```

Normative resolver schemas:

- `v4/verana-indexer/schemas/v4/vt/request.schema.json`
- `v4/verana-indexer/schemas/v4/vt/response.schema.json`
- `v4/verana-indexer/spec.md`

Fetch before making current-spec claims. Do not silently implement an unmerged PR contract over merged v4.

## Completed and Reviewed Work

The following VS Agent commits are complete and received independent spec and code-quality approval:

| Commit | Result |
|---|---|
| `2b2cc4c` | Configure explicit registry, issuer URL-to-DID, and Linked-VP policy |
| `257248f` | Parse required trust configuration only when OpenID4VC is enabled |
| `6fb96ea` | Strict independent Verana v4 Q1 and Q2/Q3 resolver adapter |
| `be29196` | Strict DID verification-method and Linked-VP evidence helpers |
| `a334b78` | Two-minute, operation-bound, single-use consent gates |
| `3740ef9` | Split credential-offer review from token/credential acceptance |
| `bc6b399` | Prevent stale asynchronous reviews from recreating gates |
| `b5b0242` | Bind holder presentation review to the DID-signed verifier request |
| `73c096f` | Bind verifier receipts to the exact session signer and credential issuer |

Fresh evidence after `73c096f`:

```text
Focused Task 7 tests: 25/25 passed
OpenID4VC package tests: 237/237 passed
Package compile: passed
Workspace typecheck: passed
ESLint: passed
Prettier: passed
git diff --check: passed
```

Playground baseline before the VS Agent changes:

```text
Playground tests: 412/412 passed
Workspace typecheck: passed
Lifecycle: inactive
Controlled ports: clear
```

Rerun playground evidence after wiring the new VS Agent API. Do not present the old baseline as post-integration proof.

---

### Task 1: Finish VS Agent package integration proof

**Files:**

- Modify: VS Agent `packages/plugin-openid4vc/tests/flow.integration.test.ts`
- Modify: VS Agent `packages/plugin-openid4vc/tests/helpers/resolverStub.ts`
- Modify: VS Agent `packages/plugin-openid4vc/README.md`

**Consumes:** VS Agent commits through `73c096f`.

**Produces:** Task 8 of `2026-07-25-did-bound-openid4vc-v4-trust.md`.

- [ ] Run `git status --short --branch` and confirm the VS Agent worktree is clean at `73c096f`.
- [ ] Generate Task 8's SDD brief from the existing plan and execute it with a fresh implementer.
- [ ] Prove unmapped issuer, X.509 issuer, forged verifier SAN, malformed resolver, unavailable resolver, expired/consumed/conflicting gates, and trusted-tenant X.509 session all fail closed.
- [ ] Prove Q1 and Q2/Q3 are recorded as distinct POST requests.
- [ ] Run:

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
- [ ] Commit with `test(openid4vc): prove DID trust boundary`.

### Task 2: Complete the VS Agent security review record

**Files:**

- Create: VS Agent `docs/superpowers/reviews/2026-07-25-did-bound-openid4vc-v4-trust.md`

**Consumes:** Complete VS Agent Task 8 diff and fresh verification output.

**Produces:** Task 9 of the VS Agent plan.

- [ ] Review issuer/verifier provenance, exact URL-to-DID binding, Q1/Q2/Q3 separation, strict v4 parsing, expiry, participation tuple, Linked-VP evidence, consent concurrency, session signer binding, receipt compatibility, and sensitive logging.
- [ ] Add RED regressions and minimum fixes for every Critical or Important finding.
- [ ] Record reviewed commits, exact commands/results, proof boundaries, and unresolved findings.
- [ ] State explicitly that package tests do not prove controlled TLS, real DID Documents, live Linked VPs, Keycloak, Chrome, testnet, or external wallets.
- [ ] Commit with `docs: review DID-bound OpenID4VC trust`.

### Task 3: Implement the controlled TLS plan

**Files:** Follow exact ownership in playground `docs/superpowers/plans/2026-07-25-local-controlled-openid4vc-tls.md`.

**Consumes:** Reviewed VS Agent branch from Tasks 1–2.

**Produces:** Ephemeral CA/leaf certificates, loopback HTTPS gateway, guarded lifecycle integration, and TLS review evidence.

- [ ] Execute Tasks 1–4 from the TLS plan sequentially with TDD and per-task review.
- [ ] Preserve exact hostnames and port-encoded DIDs:

```text
issuer.localhost:3443   -> did:web:issuer.localhost%3A3443
holder.localhost:3443   -> did:web:holder.localhost%3A3443
verifier.localhost:3443 -> did:web:verifier.localhost%3A3443
resolver.localhost:3443 -> ecosystem/resolver identity
```

- [ ] Never install the ephemeral CA into the macOS system trust store.
- [ ] Journal owned processes/resources before mutation and preserve unrelated Docker resources.
- [ ] Run `pnpm check` after each accepted slice.

### Task 4: Wire real DID Documents, Linked VPs, and the new VS Agent APIs

**Files:**

- Modify: playground `compose.local-controlled.yaml`
- Modify: playground `scripts/local-controlled-config.ts`
- Modify: playground `scripts/setup-local-controlled.ts`
- Modify: playground `scripts/local-stack.ts`
- Modify: playground `scripts/verify-local-flow.ts`
- Modify: playground `apps/local-resolver/src/contract.ts`
- Modify: playground `apps/local-resolver/src/server.ts`
- Create focused tests beside every modified module.

**Consumes:** Controlled TLS gateway and reviewed VS Agent APIs.

**Produces:** Live DID-signed issuer and verifier, resolvable DID Documents, locally signed Linked VPs, and strict v4 fixtures.

- [ ] Write failing tests for exact DID routes, wrong host/document, missing verification method, foreign signer, invalid/missing Linked VP, wrong schema, expiry, and missing participation.
- [ ] Configure `VERANA_NETWORK_ID=local-controlled`, ecosystem `184`, schema `249`, and the exact issuer URL-to-DID mapping.
- [ ] Serve/proxy DID Documents and required service fragments without rewriting identities.
- [ ] Ensure the ecosystem VTJSC VP is signed by the ecosystem DID. If this requires a fourth VS Agent instance, update the approved design and implementation plan explicitly before code.
- [ ] Migrate the playground from raw offer acceptance to `reviewOffer` then `acceptOffer(gateId)`.
- [ ] Migrate presentation flow to DID-signed request review then `share(gateId)`.
- [ ] Prove the rogue X.509 request never reaches a positive resolver decision.
- [ ] Run focused tests, `pnpm check`, and an independent security review.

### Task 5: Complete Proof-of-Trust UI and Keycloak authorization

**Files:**

- Modify: playground `apps/demo-app/src/html.ts`
- Modify: playground `apps/demo-app/src/server.ts`
- Modify: playground `apps/broker/src/policy.ts`
- Modify: playground `apps/broker/src/login-service.ts`
- Modify: playground `apps/broker/src/oidc-provider.ts`
- Modify: playground `keycloak/realm.template.json`
- Add focused tests in corresponding `tests/` directories.

**Consumes:** Verified VS Agent receipt and holder review responses.

**Produces:** Four-state holder UI, five evidence blocks, fail-closed broker, pairwise Keycloak identity.

- [ ] Render `RESOLVING`, `TRUSTED`, `UNTRUSTED`, and `UNVERIFIED`.
- [ ] Render five blocks in order: trust status, service, operator, other credentials, trust chain/failures.
- [ ] Show Q1/Q2 before acceptance and Q1/Q3 before sharing.
- [ ] Permit Keycloak JIT/session creation only for the exact `TRUSTED_AUTHORIZED` receipt.
- [ ] Store stable pairwise `sub` and `verana_subject`; repeat login must map to the same account.
- [ ] Denied, replayed, expired, resolver-down, wrong-DID, and X.509-forged cases must leave account/session counts unchanged.
- [ ] Run focused broker/demo tests and full `pnpm check`.

### Task 6: Deep local API and real-Chrome proof

**Files:**

- Modify: playground verification scripts and `docs/evidence/README.md`
- Store only bounded, non-secret evidence under the existing evidence policy.

**Consumes:** Tasks 1–5.

**Produces:** Fresh local runtime and browser evidence.

- [ ] Run `pnpm local:setup`, `pnpm local:up`, and `pnpm local:status`.
- [ ] Resolve every DID Document and required Linked VP over the controlled CA.
- [ ] Complete DID-signed issuance review, acceptance, credential storage, presentation review, sharing, verifier receipt, Keycloak login, and repeat login.
- [ ] Run `pnpm local:verify` and `pnpm local:adversarial`.
- [ ] Use real Chrome for user-visible issuance, presentation, Keycloak callback, session, and repeat-login proof.
- [ ] Run all adversarial identity, resolver, Linked-VP, consent, broker, and Keycloak cases.
- [ ] Tear down with `pnpm local:down` and prove unrelated containers/ports remain untouched.
- [ ] Record exact commands, timestamps, results, and proof boundaries.

### Task 7: Reconcile current specs and produce the local-demo acceptance report

**Files:**

- Create: playground `docs/evidence/2026-07-25-did-bound-local-acceptance.md`

**Consumes:** Fresh Task 6 evidence and current fetched `verana-spec`.

**Produces:** One defensible acceptance report.

- [ ] Fetch `verana-spec`, record its exact HEAD, and review merged v4 plus relevant open PRs.
- [ ] Separate merged normative requirements from open proposal direction.
- [ ] List proven local claims, unproven external claims, failures, and remaining integration gaps.
- [ ] Do not mark the demo accepted unless every design acceptance criterion is evidenced.

### Task 8: Inventory the eight wallet integrations without changing them

**Files:**

- Create: playground `docs/evidence/2026-07-25-wallet-integration-inventory.md`

**Consumes:** Existing wallet repositories, Git state, build artifacts, prior evidence, and accepted local foundation.

**Produces:** Evidence table only; no wallet implementation changes.

- [ ] Discover the exact eight wallet repositories under `/Users/samsepiol/Downloads/GithubRepos/Work/Verana`.
- [ ] For each wallet record: repository/branch/commit, dirty changes, protocol support, build status, artifact checksum, device/browser evidence, issuer compatibility, verifier compatibility, and blockers.
- [ ] Distinguish source/build evidence from real external interoperability.
- [ ] Preserve Procivis, SWIYU, Sphereon, Paradym, AltMe, BC Wallet, and every other discovered wallet's uncommitted work and artifacts.
- [ ] Do not rebuild all wallets during inventory; use focused checks and existing evidence first.

### Task 9: Write the next-session deep audit prompt

**Files:**

- Create: playground `docs/superpowers/prompts/2026-07-25-fides-wallet-issuer-audit.md`

**Consumes:** Tasks 1–8, the wallet inventory, Keycloak evidence, current specs, and the live FIDES issuer catalog.

**Produces:** A self-contained prompt for a new Claude Code/Codex session that decides how to implement the real playground.

- [ ] Include exact repositories, worktrees, branches, commits, dirty-state warnings, tests, runtime evidence, and unresolved findings.
- [ ] Require live browsing of:

```text
https://fides.community/ecosystem-explorer/issuer-catalog/
```

- [ ] Require an issuer table with organization, credential types, issuance protocol, wallet compatibility, verifier path, trust evidence, public/test environment, authentication prerequisites, and integration risk.
- [ ] Require cross-comparison of all eight wallets against every relevant FIDES issuer and the completed Keycloak flow.
- [ ] Require the agent to classify every claim as `PROVEN_LOCAL`, `PROVEN_EXTERNAL`, `PARTIAL`, `BLOCKED`, or `UNKNOWN`.
- [ ] Require a recommended real-playground information architecture covering personal wallets, business wallets, issuers, verifiers, ecosystems, credentials, Keycloak demos, individual integration pages, and evidence.
- [ ] Require a sequenced implementation plan with security gates, test strategy, ownership, dependencies, demo fixtures, deployment boundary, and explicit non-goals.
- [ ] Forbid implementation during the audit session until Maxime approves the resulting architecture and plan.

## Completion Definition

This handoff is complete only when:

1. VS Agent Tasks 8–9 are reviewed and green.
2. Controlled TLS, DID Documents, Linked VPs, holder gates, receipts, and Keycloak are proven live locally.
3. Full API, adversarial, teardown, and real-Chrome evidence is recorded.
4. Current specs are reconciled without treating open PRs as merged.
5. Eight wallet integrations are inventoried without losing work.
6. The deep audit prompt is written for the separate issuer/wallet planning session.

