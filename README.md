# Verana Keycloak playground

This local-only playground brokers a Verana-authorized OpenID4VP presentation
into Keycloak 26.7.0, then lets a confidential demo application authenticate
through Keycloak. The trust boundary fails closed: only receipts whose issuer
and verifier are both `TRUSTED_AUTHORIZED` for the exact VTJSC can reach the
OIDC account boundary.

The repositories are intentionally separate:

- this worktree contains Keycloak, the OIDC broker, the protected app, and the
  live verifier;
- the VS Agent worktree contains the issuer, holder, verifier, and the
  `subjectId` to `subject_id` contract;
- no service is deployed by these instructions.

## Prerequisites

- Node.js and Corepack;
- pnpm 10.28.1 for this repository;
- Docker with Compose;
- a separate VS Agent worktree built from the reviewed subject-contract branch;
- separate state for the issuer/holder and verifier instances;
- two DIDs whose keys the corresponding instances genuinely control and whose
  exact Q1/Q2 or Q1/Q3 checks pass against the configured VTJSC.

The known public issuer and verifier DIDs are useful for read-only registry
preflight. They must not be assigned to a local agent unless that agent controls
their published keys.

## Playground startup

Run the setup and Keycloak import from this worktree:

```bash
pnpm install
pnpm run setup
docker compose up -d keycloak
```

Load the public configuration and generated local secrets into the same shell,
then start the broker and demo app:

```bash
set -a
source .env.example
source .data/.env
set +a
pnpm dev
```

The local endpoints are:

- demo application and local holder UI: `http://localhost:3000`;
- broker: `http://localhost:3001`;
- Keycloak realm:
  `http://localhost:8080/realms/verana-playground`;
- issuer/holder VS Agent: `http://localhost:3101`;
- verifier VS Agent: `http://localhost:3201`.

Generated files under `.data/` contain secrets and must remain local.

## VS Agent role instances

Use the separate VS Agent worktree:

```bash
cd /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim
pnpm install
pnpm build
```

The issuer/holder process requires:

```text
AGENT_PORT=3101
ADMIN_PORT=3100
PUBLIC_API_BASE_URL=http://localhost:3101
AGENT_ENDPOINTS=ws://localhost:3101
OID4VC_ISSUER_ENABLED=true
OID4VC_HOLDER_ENABLED=true
OID4VC_VERIFIER_ENABLED=false
VS_AGENT_PLUGINS=messaging,openid4vc
```

The verifier process requires:

```text
AGENT_PORT=3201
ADMIN_PORT=3200
PUBLIC_API_BASE_URL=http://localhost:3201
AGENT_ENDPOINTS=ws://localhost:3201
OID4VC_ISSUER_ENABLED=false
OID4VC_HOLDER_ENABLED=false
OID4VC_VERIFIER_ENABLED=true
VS_AGENT_PLUGINS=messaging,openid4vc
```

Both processes require:

```text
VERANA_RESOLVER_URL=https://resolver.testnet.verana.network/v1/trust
UNFOLD_VCT=https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation
UNFOLD_VTJSC_ID=https://unfold-org.77.42.86.24.sslip.io/vt/schemas-unfold-attestation-jsc.json
```

Set a distinct `AGENT_PUBLIC_DID`, `AGENT_WALLET_ID`, `AGENT_WALLET_KEY`,
database account/schema, and Redis isolation boundary for each role. If the
current VS Agent configuration cannot assign distinct Redis namespaces, use
separate Redis instances. Set the issuer/holder DID to one that the instance
controls and that passes Q1 plus issuer Q2. Set the verifier DID to a different
controlled DID that passes Q1 plus verifier Q3.

The verifier base URL must also be different from both the issuer and holder
base URLs after URL normalization. The issuer and holder may share one role
instance. The live verifier rejects an aliased role topology before its first
network request.

Start each role in its own configured shell:

```bash
pnpm --filter @verana-labs/vs-agent start
```

Do not substitute the known public authorized DIDs while using locally
generated keys or certificates. A matching DID string without control of its
published keys is not authorization evidence.

## Verification

Recreate generated state and Keycloak before a demonstration:

```bash
pnpm run setup
docker compose down
docker compose up -d keycloak
docker compose ps
docker compose config
pnpm check
pnpm tsx scripts/verify-keycloak.ts
pnpm tsx scripts/verify-local-flow.ts
git diff --check
git status --short
```

`verify-local-flow.ts` first checks the live resolver for exact DID and VTJSC
equality. It then requires the issuer, holder, and verifier capability
contract. Only after those gates pass does it issue a badge or start a
presentation.

The final script output is deliberately limited to stage names, verdict
categories, and `PASS` or a sanitized `FAIL` code. A
`FAIL BLOCKED_SUBJECT_CONTRACT` result is an honest blocked acceptance, not a
passing login. Controlled fake services are used only by automated regression
tests and never satisfy the live acceptance gate.

Live responses are capped at 64 KiB and parsed against explicit field
contracts. Resolver Q1 accepts only `did`, `trustStatus`, and `production`, plus
the documented bounded `evaluatedAt`, `evaluatedAtBlock`, and `expiresAt`
metadata. Q2/Q3 accepts only its authoritative fields plus the documented
bounded `evaluatedAt`, `evaluatedAtBlock`, `fees`, `permission`, and
`permissionChain` metadata. Capability, credential, holder, verifier, and
receipt envelopes reject undocumented fields. OIDC discovery, the protocol
credential-offer object, and SD-JWT `prettyClaims` are intentionally extensible
objects; their keys, key counts, authoritative fields, and full response bodies
remain bounded. Verified receipts are then parsed again by the broker's exact
authorization schema.

Browser verification may start only after the live script prints `PASS`. API
tests do not prove the Keycloak JIT account flow, a physical wallet flow, or a
trusted-HTTPS counterparty.

See [the evidence boundary](docs/evidence/README.md) for the latest local run.
