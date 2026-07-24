# Local verification evidence

## Run boundary

- Date: 2026-07-24, Europe/Paris (CEST, UTC+02:00).
- Playground automated implementation tested: `e4233fa`.
- Browser boundary snapshot: `a736ef5`; the later security fixes were verified
  by focused and full automated checks, not promoted to new browser evidence.
- Runtime: Node.js 24.14.0 and pnpm 10.28.1.
- VS Agent subject/trust integration tested: `ec078f1` (includes the
  subject-capability work at `d778012`).
- Network: Verana testnet resolver at
  `https://resolver.testnet.verana.network/v1/trust`.
- VCT:
  `https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation`.
- VTJSC:
  `https://unfold-org.77.42.86.24.sslip.io/vt/schemas-unfold-attestation-jsc.json`.

The evidence below distinguishes automated controlled-service coverage, live
read-only registry evidence, local component evidence, and the blocked live
acceptance. No fixture result is promoted to live evidence.

## Commands and results

| Command | Exit | Evidence |
| --- | ---: | --- |
| `pnpm vitest run tests/local-flow-verification.test.ts` | 0 | 26 controlled-service tests passed, including topology rejection before all network activity, every Q1/Q2/Q3 condition, strict extra-field rejection, exact DID/VTJSC rejection, capability rejection before issuance, two stable trusted flows, rogue denial, and sanitized bounded output. |
| `pnpm run setup` | 0 | Regenerated local secrets, broker key, and realm import state. |
| `docker compose down` | 0 | Removed the previous local Keycloak container and network. |
| `docker compose up -d keycloak` | 0 | Recreated pinned Keycloak 26.7.0 from the fresh realm state. |
| `docker compose ps` | 0 | `auth-demo-keycloak-1` reported healthy. |
| `docker compose config` | 0 | Rendered one loopback-bound Keycloak 26.7.0 service with the generated realm mounted read-only. |
| `pnpm check` | 0 | Biome checked 50 files; both workspaces typechecked and built; 172 tests passed in 16 files. |
| VS Agent OpenID4VC plugin test and build | 0 | 72 tests passed in 10 files, including exact Q1 DID/production and Q2/Q3 DID/VTJSC response binding for issuer and verifier; the package rebuilt successfully. |
| `pnpm exec tsc --noEmit --target ES2024 --module NodeNext --moduleResolution NodeNext --strict --skipLibCheck scripts/verify-local-flow.ts tests/local-flow-verification.test.ts` | 0 | Standalone script and focused test TypeScript check passed. |
| `pnpm tsx scripts/verify-keycloak.ts` | 0 | Realm, Authorization Code with S256, IdP, broker signature/secret behavior, JIT-only first login, exact mappers, authorization targets, and zero pre-created users passed. |
| `pnpm tsx scripts/verify-local-flow.ts` | 1 | On the fresh repeat, live resolver checks passed, then acceptance stopped with `FAIL BLOCKED_SUBJECT_CONTRACT` before credential issuance. |
| bounded read-only issuer capability probe below | 0 | The currently deployed issuer endpoint returned HTTP `404`. |
| bounded read-only verifier capability probe below | 0 | The currently deployed verifier endpoint returned HTTP `404`. |
| root `pnpm dev` with the safe port overrides below | 0 | Demo returned HTTP 200 and broker discovery returned HTTP 200 with issuer `http://localhost:3301`; both spawned processes were stopped after QA. |
| Chrome boundary run below | blocked as expected | Keycloak and the Verana broker rendered correctly; the final step stopped at the unavailable local VS Agent without creating a user. |
| `git diff --check` | 0 | No patch whitespace errors. |
| `git status --short` | 0 | At the final documentation checkpoint, only `README.md` and `docs/evidence/README.md` were modified. |

The exact reproducible capability probes were:

```bash
curl --max-time 10 --max-filesize 1024 --silent --show-error \
  --output /dev/null --write-out '%{http_code}\n' \
  'https://unfold-org.77.42.86.24.sslip.io/oid4vc-demo/capabilities'
# output: 404
# exit: 0

curl --max-time 10 --max-filesize 1024 --silent --show-error \
  --output /dev/null --write-out '%{http_code}\n' \
  'https://unfold-verifier.77.42.86.24.sslip.io/oid4vc-demo/capabilities'
# output: 404
# exit: 0
```

The HTTP 404 is observed evidence, while curl exits 0 because the probe
intentionally records the HTTP status without `--fail`. The live acceptance
command remains a separate non-zero result.

An immediately preceding acceptance run stopped at
`FAIL BLOCKED_TRUST_PREFLIGHT`. Four bounded direct resolver rechecks then
returned HTTP 200 with the exact expected issuer Q1/Q2 and verifier Q1/Q3
verdicts. The fresh script repeat passed that preflight and reached the subject
contract boundary above. The transient failure is retained here because a
network-dependent demonstration must not silently convert an unavailable
preflight into success.

The default application ports were already published by the unrelated local
container `twitter-bot-vs-agent`. It was not stopped or modified. Application
startup and Chrome QA therefore used:

```bash
set -a
source .env.example
source .data/.env
set +a
DEMO_APP_PORT=3300 \
DEMO_APP_REDIRECT_URI=http://localhost:3300/callback \
BROKER_PORT=3301 \
BROKER_ISSUER=http://localhost:3301 \
pnpm dev
```

The disposable Keycloak realm was temporarily pointed at ports 3300 and 3301
for the browser run. Afterward, Keycloak was recreated from the generated
read-only realm and `pnpm tsx scripts/verify-keycloak.ts` passed again,
including the zero-user assertion.

## Verdicts

- Live issuer Q1/Q2: `TRUSTED_AUTHORIZED`; response DID and VTJSC matched
  exactly and Q1 reported `TRUSTED`, production.
- Live verifier Q1/Q3: `TRUSTED_AUTHORIZED`; response DID and VTJSC matched
  exactly and Q1 reported `TRUSTED`, production.
- Controlled trusted presentation 1: `TRUSTED_AUTHORIZED` for both issuer and
  verifier.
- Controlled trusted presentation 2: `TRUSTED_AUTHORIZED` for both issuer and
  verifier; derived pairwise subject stable.
- Controlled rogue presentation: denied before share.
- Live subject contract: blocked. The reviewed capability code is not present
  on the currently deployed authorized counterparties, whose capability routes
  returned HTTP 404.
- Live positive login: not claimed because the live script exited 1.

## UI and wallet evidence

- Chrome UI was exercised only to the honest blocked boundary. The protected
  app redirected to Keycloak with Authorization Code, S256 PKCE, state, and
  nonce; Keycloak displayed the Verana Wallet IdP; and the broker displayed
  `vs_agent_unavailable` with no browser console warning or error.
- The local-holder page rendered its local/testnet/non-physical-wallet labels
  and server-bound CSRF fields. A real same-origin issuance form POST passed
  the Origin/CSRF gate and reached the bounded `Local VS Agent unavailable`
  result.
- An earlier browser run exposed that `Referrer-Policy: no-referrer` caused
  Chrome to send `Origin: null`. Commit `a736ef5` changes only that policy to
  `same-origin`; exact-Origin validation still rejects null, missing,
  cross-port, and foreign origins.
- Post-review automated checks require `prompt=login` on every fresh Keycloak
  authorization and cap broker-to-verifier JSON responses at 64 KiB before
  parsing. These later controls were not represented as new browser evidence.
- Keycloak JIT account creation and profile claims are not claimed because the
  live subject-contract preflight did not pass. The restored realm still had
  zero users.
- Physical wallet: not exercised.
- Trusted HTTPS wallet-to-counterparty flow: not exercised.
- Screenshots, QR payloads, credentials, presentations, tokens, and private
  keys: not retained.

## Known limitations

- The final ECS-Badge testnet schema and its production semantics remain
  unresolved.
- The binding from the opaque `subject_id` to a DID or wallet-controlled
  identifier remains a specification decision; this playground treats it as an
  issuer-scoped opaque subject.
- The public authorized DIDs cannot be assigned to local role instances without
  control of their published keys.
- A controlled fake-service test proves orchestration and fail-closed behavior,
  not Verana network interoperability or Keycloak browser/JIT behavior.
