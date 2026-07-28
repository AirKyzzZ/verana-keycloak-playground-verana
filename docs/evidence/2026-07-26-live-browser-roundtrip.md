# Live browser round-trip — Keycloak ← Verana Wallet IdP ← holder (2026-07-26)

Status: **PROVEN_LIVE.** The one open gap from the overnight acceptance report — the full
browser sequence Keycloak → Verana Wallet IdP → holder presents → broker creates the account →
protected profile — was exercised end to end today, twice over two channels, and it closed only
after fixing three real defects that the unit layer structurally could not catch. Evidence mode
throughout: `LOCAL_CONTROLLED` (local stack, controlled local resolver; not testnet evidence).

## The run that passed

Channel A — instrumented HTTP (curl cookie jar, every hop visible), scratchpad `e2e-flow.sh`:

1. `GET /login` → 302 Keycloak `auth?…code_challenge=…` (PKCE)
2. Keycloak login page → broker IdP link `broker/verana-wallet/login`
3. → 302 chain into the broker (`oidc-provider`) → `/interaction/<uid>` with `_interaction`
   cookies set; page carries the `openid4vp://` authorization request
   (`client_id=decentralized_identifier:did:web:verifier.localhost%3A3443`)
4. `POST /wallet/issue` → ACME Playground Employee Badge accepted by the holder VS Agent
5. `POST /wallet/resolve` → holder gates render verdict **TRUSTED_AUTHORIZED** (Q1, Q3 and
   Linked-VP evidence verified against the local v4 resolver fixture)
6. `POST /wallet/share` → presentation submitted to the DID-bound verifier
7. `GET /interaction/<uid>/complete` → 303 `/auth/<uid>` → oidc-provider resume → code →
   Keycloak brokered account created → demo-app `/callback` → **`/profile`**

Final page: `Protected profile · KEYCLOAK VERIFIED · Verana subject
5d0JXqdomp6fZYSvhj6Lj30EhaAH-kJ0WuZznACDpMU · Organization group /organizations/acme · Realm
role employee`.

Channel B — driven browser (in-app browser pane, three origins, real cookies/CSP): same flow;
the holder's resolve/share form submissions were triggered programmatically
(`form.requestSubmit()`) because the pane's synthetic clicks were unreliable — identical POSTs,
cookies, CSRF and Origin as a human click. The broker "waiting" page was left to its **own**
poller: once fronted, it detected the verified presentation, called `/complete`, resumed
through Keycloak and landed on the protected profile with no further driving. Screenshots
captured at every stage (login, IdP button, QR page, verifier review, protected profile).

State assertion after the flow:

```
KEYCLOAK USERS 1
KEYCLOAK ACCOUNT_REF 05b42adb…398c7f
KEYCLOAK SUBJECT_REF 56791533…480a0d
PASS KEYCLOAK GROUP ACME
PASS KEYCLOAK ROLE employee
PASS KEYCLOAK SUBJECT mapped
```

Subject stability held across channels: the browser login matched the **same** federated user
the curl run created (deterministic pairwise subject), rather than minting a second account.

## Three defects found by going live (all fixed today, all now tested)

1. **Broker never granted the `openid` scope** (`apps/broker/src/oidc-provider.ts`). The
   provider removes the `consent` prompt (`loginOnlyPolicy`) but nothing created a
   `provider.Grant`, so every real login resolved `access_denied` ("authorization request
   resolved without requesting interactions but no scope was granted",
   oidc-provider `interactions.js`). This was a *documented known defect* — the suite carried
   an `it.fails("issues an authorization code for a fully authorized login")` marker. Fix:
   `loadExistingGrant` creates/reuses a grant carrying exactly the `openid` scope, only for the
   sole first-party Keycloak client and only with an authenticated session. The `it.fails`
   marker is now a passing test; its adversarial twin (which pinned the buggy `access_denied`
   behavior) is removed.
2. **Keycloak dropped the `verana_subject` attribute and interposed a profile form**
   (`keycloak/realm.template.json`). Keycloak ≥24 declarative user profile silently discards
   writes to undeclared attributes, so the `Verana pairwise subject` IdP mapper (group and role
   mappers worked) never persisted; separately, the default profile requires
   email/firstName/lastName, so first broker login stopped at a VERIFY_PROFILE form asking a
   DID-authenticated user to type an email. Fix: the realm template now declares the user
   profile — email/firstName/lastName optional, `verana_subject` declared admin-writable.
   Brokered users now create cleanly with the attribute and no interstitial.
3. **The user assertion could never pass with a real user**
   (`scripts/keycloak-verification.ts`). `readKeycloakUserStatus` listed users with
   `briefRepresentation=true`, which strips attributes — the very `verana_subject` the check
   requires. Fix: `briefRepresentation=false`. The URL-pinning test updated accordingly.

## Constraints that shaped the flow (documented, unchanged)

- The verifier's trust-gate entry expires **120 s** after the authorization request is minted
  (`GateStore.ts`), and the broker's oidc-provider uses `ttl.Interaction = 300`. The whole
  login must complete inside those windows; expiry produces the observed fail-closed refusals
  (`invalid_request_uri` 404 at the holder, `session expired` at the verifier).
- The demo-app wallet forms are origin-locked to `http://localhost:3000` and rotate the CSRF
  token per render; a stale render's submit is refused (`Invalid wallet request`).

## Verification totals after the fixes

`pnpm check` green: lint, typecheck, **31/31 test files, 609 passed + 4 expected-fail (613)**,
build. Fresh-stack `pnpm local:verify` and `pnpm local:adversarial` re-run green today after
the changes (see session log).

## Re-proof on resurrected stack (2026-07-29, human-driven)

After the 2026-07-28 crash recovery (fresh colima, regenerated TLS/env), the full browser flow
was driven by hand for the first time (no scripts, no driven browser): issue at /wallet, copy
request from the QR page, resolve TRUSTED_AUTHORIZED, share, broker poller resumed Keycloak,
protected profile reached. State assertion: KEYCLOAK USERS 1, PASS GROUP ACME, PASS ROLE
employee, PASS SUBJECT mapped. Automated local:verify + local:adversarial had re-run green on
the same stack earlier the same evening (users 0 precondition, before the manual run).

Operational notes from the retry path: the resolve step fails as a generic "Local VS Agent
unavailable" card when the 120 s verifier gate has expired (the bounded client collapses the
404), and a second GET /login overwrites the single auth transaction, so a straggler tab
completing yields "Invalid login callback". Neither is a defect of the trust path; both are
fail-closed refusals with unhelpful labels. Polish candidates: distinct expiry copy, and
local:verify/local:users self-loading their env (bare runs default to LIVE_VERANA / count 0).
