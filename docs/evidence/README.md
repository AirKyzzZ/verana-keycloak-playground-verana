# Local verification evidence

## Run boundary

- Date: 2026-07-24, Europe/Paris (CEST, UTC+02:00).
- Playground implementation base: `a516d8a9aa0d1e7a033554e8d6fd66e4e8a9855e`.
- VS Agent subject-capability commit:
  `d778012` (independently reviewed with no findings).
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
| `pnpm vitest run tests/local-flow-verification.test.ts` | 0 | 17 controlled-service tests passed, including every Q1/Q2/Q3 condition, exact DID/VTJSC rejection, capability rejection before issuance, two stable trusted flows, rogue denial, and sanitized bounded output. |
| `pnpm run setup` | 0 | Regenerated local secrets, broker key, and realm import state. |
| `docker compose down` | 0 | Removed the previous local Keycloak container and network. |
| `docker compose up -d keycloak` | 0 | Recreated pinned Keycloak 26.7.0 from the fresh realm state. |
| `docker compose ps` | 0 | `auth-demo-keycloak-1` reported healthy. |
| `docker compose config` | 0 | Rendered one loopback-bound Keycloak 26.7.0 service with the generated realm mounted read-only. |
| `pnpm check` | 0 | Biome checked 49 files; both workspaces typechecked and built; 157 tests passed in 15 files. |
| `pnpm exec tsc --noEmit --target ES2024 --module NodeNext --moduleResolution NodeNext --strict --skipLibCheck scripts/verify-local-flow.ts tests/local-flow-verification.test.ts` | 0 | Standalone script and focused test TypeScript check passed. |
| `pnpm tsx scripts/verify-keycloak.ts` | 0 | Realm, Authorization Code with S256, IdP, broker signature/secret behavior, JIT-only first login, exact mappers, authorization targets, and zero pre-created users passed. |
| `pnpm tsx scripts/verify-local-flow.ts` | 1 | Live resolver checks passed, then acceptance stopped with `FAIL BLOCKED_SUBJECT_CONTRACT` before credential issuance. |
| read-only public capability probes | 0 | Both currently deployed issuer and verifier `/oid4vc-demo/capabilities` endpoints returned HTTP 404. |
| `git diff --check` | 0 | No patch whitespace errors. |
| `git status --short` | 0 | Before commit, only `.env.example`, `README.md`, `docs/evidence/README.md`, `scripts/verify-local-flow.ts`, and `tests/local-flow-verification.test.ts` were changed or untracked. |

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

- Browser UI: not exercised because the live acceptance preflight has not
  passed.
- Keycloak JIT account creation: not claimed.
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
