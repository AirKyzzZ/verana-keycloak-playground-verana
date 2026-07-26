# DID-Bound Local FIDES Playground — Acceptance & Status Report

Date: 2026-07-26 (overnight autonomous session)
Evidence label: **LOCAL_CONTROLLED**
Branch: `codex/auth-demo` (playground), `codex/keycloak-subject-claim` (VS Agent)

> This report is deliberately conservative. Every claim is marked with what kind
> of evidence backs it: **PROVEN_LIVE** (ran against the running stack),
> **PROVEN_UNIT** (test suite only), **PARTIAL**, or **NOT_YET**. `LOCAL_CONTROLLED`
> means real local protocol components ran against a controlled local trust
> fixture. It is NOT testnet, public-CA-TLS, physical-wallet, external-wallet,
> or production evidence.

---

## 1. What was built (the whole DID-bound foundation)

The playground now runs the complete DID-bound credential lifecycle locally:
controlled TLS, resolvable `did:web` identities over that TLS, real merged-v4
Verana trust resolution, holder consent gates, a Proof-of-Trust UI, and Keycloak
brokering — every positive decision bound to an authenticated DID signature and
every negative path failing closed.

Component map:

| Layer | Where | Status |
| --- | --- | --- |
| Ephemeral CA + leaf, four `.localhost` SANs, 0600 keys | `scripts/local-tls-certificates.ts` | PROVEN_UNIT (12 tests) |
| Loopback HTTPS gateway, exact SNI+Host routing, hop-by-hop stripping, bounded body, sanitized 502 | `scripts/local-tls-proxy.ts` | PROVEN_UNIT (14 tests) |
| Merged-v4 trust resolver fixture (`POST /v4/verifiable-trust/resolve`) | `apps/local-resolver/` | PROVEN_LIVE + PROVEN_UNIT (38 tests) |
| Ecosystem DID document + Ed25519-signed Linked VPs (one per required fragment) | `apps/local-resolver/src/ecosystem.ts` | PROVEN_LIVE + PROVEN_UNIT |
| Three-stage guarded lifecycle (Keycloak → host gateway → agents), journaled teardown | `scripts/local-stack.ts` | PROVEN_LIVE + PROVEN_UNIT (73 tests) |
| Demo app: two-step consent issuance, Proof-of-Trust view model, refusal rendering | `apps/demo-app/` | PROVEN_LIVE + PROVEN_UNIT (112 tests) |
| Broker: receipt policy bound to a configured registry tuple, pairwise subjects | `apps/broker/` | PROVEN_UNIT (206 tests, incl. 30 adversarial account-state tests) |
| VS Agent: DID-bound OpenID4VCI/VP, independent Q1/Q2/Q3, fail-closed gates | `worktrees/keycloak-subject-claim/packages/plugin-openid4vc` | PROVEN_UNIT (242 tests) |

---

## 2. Live end-to-end evidence (PROVEN_LIVE)

Against the running stack (4 healthy containers + host process), both gates pass:

**`pnpm local:verify` → `PASS LOCAL_CONTROLLED`**
```
STAGE TRUST_PREFLIGHT
VERDICT ISSUER_Q2 TRUSTED_AUTHORIZED       # real v4 Q1+Q2, issuer DID-bound
VERDICT VERIFIER_Q3 TRUSTED_AUTHORIZED     # real v4 Q1+Q3, verifier DID-bound
STAGE SUBJECT_CONTRACT / COMPONENT_READINESS
STAGE CREDENTIAL_1 / PRESENTATION_1
VERDICT PRESENTATION_1_ISSUER TRUSTED_AUTHORIZED
VERDICT PRESENTATION_1_VERIFIER TRUSTED_AUTHORIZED
STAGE CREDENTIAL_2 / PRESENTATION_2  →  VERDICT SUBJECT STABLE
STAGE ROGUE_PRESENTATION  →  VERDICT ROGUE DENIED
KEYCLOAK USERS 0   (before, between, and after — no account from any denied path)
PASS LOCAL_CONTROLLED
```

This proves live: DID-bound issuance review + acceptance + storage, credential
schema gate, two trusted presentations with a **stable pairwise subject and a
fresh credential each time**, rogue-verifier denial, and zero Keycloak users
throughout.

**`pnpm local:adversarial` → `PASS LOCAL_CONTROLLED ADVERSARIAL`**
```
PASS RESOLVER unavailable DENIED       # resolver 503 → RESOLVER_UNAVAILABLE, no disclosure
PASS RESOLVER malformed-json DENIED    # unparseable body → fail closed
PASS RESOLVER oversized-body DENIED    # >64 KiB → fail closed
PASS ROGUE DENIED                      # rogue verifier, exact UNTRUSTED, no resolver query
PASS LOCAL_CONTROLLED ADVERSARIAL
```

Each fault is a single-shot armed condition on the verifier's Q1; the holder
fails closed and the fault self-consumes, with the broker never crossed and no
Keycloak user created.

**Real-browser evidence (PARTIAL):** the demo app home, the local holder
workflow, live badge issuance (`Badge accepted`, a real credential record), the
Keycloak login page with the Verana Wallet identity provider, and the broker's
`Waiting for wallet` authorization request were all captured in a real browser.
Screenshots under `docs/evidence/screenshots/`. See §5 for the one browser step
that is proven at the unit layer rather than the browser layer, and why.

---

## 3. Every fail-closed refusal is the design working, not a bug

Getting the live flow green surfaced a chain of misconfigurations. **Every one
was caught by a fail-closed check that refused before doing harm and named the
reason** — none was a crash or a silent pass:

| Symptom | Real cause | The check that caught it |
| --- | --- | --- |
| `ECONNREFUSED :3443` at agent startup | host gateway launched after the agents | Compose health wait |
| host process died at boot | demo app needs Keycloak OIDC discovery first | host-service readiness |
| trust preflight blocked | verify script fell back to the real testnet resolver | controlled-config exact match |
| `no exact DID binding` | issuer binding keyed on origin, not the issuer path | issuer-URL→DID exact bind, before any token request |
| `UNTRUSTED`, 2 queries | only 1 of 3 required Linked-VP fragments served | Linked-VP evidence evaluated as a set |
| `credential schema mismatch` 500 | wrong credential configuration (no `credentialSchema`) | holder gate: stored credential must carry the gated VTJSC |

The last two are worth underlining: the agent refused to mint a gate, refused to
store a credential, and refused to disclose — exactly where a weaker demo would
have shown a green check.

---

## 4. Verification totals

- **Playground `pnpm check` (lint + typecheck + test + build): GREEN.**
  608 passed + 5 `it.fails` documented-defect markers across 31 test files.
- **VS Agent plugin package:** 242/242 tests, compile/format/types/build clean.
- **VS Agent host app:** 50/54 — the 4 failures are the pre-existing
  `trustService.test.ts` JSON-LD context-dereferencing failures, reproduced at
  the pristine branch baseline and unrelated to OpenID4VC (tracked separately).

The typecheck gate was extended to cover `scripts/` (`tsc -p tsconfig.scripts.json`),
which immediately caught a `KeyObject` type error the vitest run had sailed past.

---

## 5. Decisions taken autonomously (per the overnight mandate)

Recorded here rather than parked, per "decide, document, keep moving". None
weakened a security or fail-closed property.

1. **Linked VP as a JWT-secured VP, not a Data-Integrity proof.** The spec review
   flagged that a W3C Data-Integrity proof would need JSON-LD canonicalization or
   a fourth VS Agent. I used a deterministic Ed25519-signed compact-JWS VP over
   the exact served payload. It carries a real signature (a tamper test fails
   verification) and sidesteps the fourth-agent change to the approved design.
   *Delta to note:* the spec does not vendor a Linked-VP proof profile locally, so
   this is a defensible local choice, not a spec-conformant one. Flagged for the
   spec reconciliation phase.
2. **Two resolver URLs.** Containers reach the resolver through the gateway
   (`https://resolver.localhost:3443`); host-side scripts use loopback
   (`http://localhost:3099`), because the per-run private CA is deliberately not
   in any host trust store. Added `hostResolverUrl` rather than weaken the config
   check.
3. **Registry tuple is configured, not assumed.** The broker's receipt policy
   moved off the hardcoded `vna-testnet-1`/184/249 literals (which would have
   rejected every local login) to a configured `network`/`ecosystemId`/
   `credentialSchemaId`, throwing `registry_mismatch` on drift. This was a real
   bug that would have broken every Keycloak login; it is now covered by adversarial
   account-state tests that mutation-check each field.
4. **Offers endpoint selects a credential configuration.** Added an optional
   `credentialConfigurationId` to `POST /oid4vc-demo/offers` so the demo can ask
   for the authorized, schema-bearing configuration. Committed on the VS Agent
   branch with 4 focused tests.
5. **`local:adversarial` defaults to `--expect-count=0`.** The script always
   asserts zero Keycloak users; defaulting keeps `pnpm local:adversarial` runnable
   with no args (this was the only thing blocking the adversarial gate — a usage
   bug, not a trust bug).

---

## 6. Spec deltas — merged v4 conformance (documented, not implemented)

The resolver fixture implements the merged v4 contract at `verana-spec@eaac693`.
A spec-verification pass found it now passes the strict parser AND the normative
schemas for: selector gating (each selector honored, explicit `false` excludes),
`expiresAtTime` as the minimum future boundary (not a synthetic TTL, not null
while a credential carries `validUntil`), `services[]` carrying only
non-LinkedVerifiablePresentation entries, and distinct CredentialSchema ids +
Participant ids per ECS type. Remaining known deltas, deferred:

- `corporation` selector/object not implemented (optional; never requested here).
- Ecosystem VPR service entry uses a bare `https://` endpoint rather than the
  canonical `["vpr:verana:mainnet"]` array form with a `version`.
- The VTJSC-carrying Linked VP is surfaced on the resolved party rather than
  additionally on the ecosystem's own DID document.
- Open `verana-spec` PRs #22/#23 rewrite parts of this contract (expiry gate,
  EcsCredential keying, error contract). The fixture is deliberately built to
  merged `eaac693` only; migrating after those merge is a known scoped task.

---

## 7. Known gaps / NOT_YET

- **Keycloak account-creation + protected-profile completion is PROVEN_UNIT, not
  PROVEN_LIVE end-to-end in the browser.** `local:verify` validates the receipt
  via `authorizeReceipt` directly and asserts zero users; the broker's account +
  session creation is covered by 30 adversarial broker tests asserting on account
  and session STATE (each denial path mutation-checked). The full browser
  round-trip (Keycloak → Verana Wallet IdP → holder present → broker creates
  account → protected profile) is interactive across three origins under a strict
  no-JS CSP; it is set up and reachable but not captured as a single automated
  browser sequence. Next-session item.
- The 4 `trustService.test.ts` JSON-LD failures on the VS Agent host app.
- The `__proto__`-through-`strictObject` and broker-tests-excluded-from-tsconfig
  findings raised by the audit pass (both low impact, spawned as follow-ups).

---

## 8. Next-session pickup

1. Capture the full browser Keycloak completion (or script it) to move §7 item 1
   from PROVEN_UNIT to PROVEN_LIVE.
2. FIDES issuer catalog research + integration plan (Phase G/H) — see the
   companion issuer-catalog doc.
3. Reconcile the §6 spec deltas once PRs #22/#23 land.
4. Fold the JSON-LD `trustService` fix (tracked) so the VS Agent host suite is
   fully green.
