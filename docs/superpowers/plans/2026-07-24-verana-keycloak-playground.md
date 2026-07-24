# Verana Keycloak Playground Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible local demo where a Verana-authorized OpenID4VP presentation creates and reuses a Keycloak account with a pairwise subject, ACME group, and employee role.

**Architecture:** A TypeScript OIDC broker translates a verified VS Agent proof-of-trust receipt into an Authorization Code response consumed by Keycloak's standard identity-brokering flow. A separate demo application authenticates only through Keycloak, while a local-holder page proxies the existing VS Agent issuer, holder, and verifier endpoints for the reliable call demo.

**Tech Stack:** Node.js 24+, pnpm 10.28.1, TypeScript 7.0.2, Koa 3.2.1, oidc-provider 9.10.0, openid-client 6.8.4, Zod 4.4.3, jose 6.2.4, Vitest 4.1.10, Biome 2.5.5, Docker Compose, Keycloak 26.7.0, and the existing VS Agent OpenID4VC plugin.

## Global Constraints

- Work locally only. Do not push, deploy, submit GitHub reviews, or post comments.
- Do not modify the dirty VS Agent checkout at `/Users/samsepiol/Downloads/GithubRepos/Work/Verana/vs-agent`.
- Create the VS Agent change in an isolated worktree at `/Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim`.
- Treat only `TRUSTED_AUTHORIZED` issuer and verifier verdicts as positive.
- Treat `PARTIAL`, `TRUSTED_NOT_AUTHORIZED`, `UNTRUSTED`, resolver failure, malformed responses, and timeouts as denied login.
- Use the configured playground credential type and schema identifier. Do not call it the final ECS-Badge.
- Never log or commit raw credentials, presentations, authorization requests, tokens, secrets, private keys, or device identifiers.
- Generate development secrets and broker signing keys under ignored `.data/`.
- Use exact allowlists: `organization === "ACME"` and `role === "employee"`.
- The physical-wallet path is not complete without trusted-HTTPS and device evidence.

---

## File Structure

### Playground repository

```text
.data/                                      # generated, ignored
.env.example                                # non-secret variable names
.gitignore
biome.json
compose.yaml
package.json
pnpm-lock.yaml
pnpm-workspace.yaml
tsconfig.base.json
vitest.config.ts
apps/broker/package.json
apps/broker/src/account-store.ts            # OIDC account claims
apps/broker/src/config.ts                   # validated broker configuration
apps/broker/src/html.ts                     # escaped interaction pages
apps/broker/src/index.ts                    # process entrypoint
apps/broker/src/login-service.ts            # VS request and receipt orchestration
apps/broker/src/oidc-provider.ts             # provider configuration
apps/broker/src/pairwise-sub.ts              # HMAC subject derivation
apps/broker/src/policy.ts                    # fail-closed receipt validation
apps/broker/src/server.ts                    # Koa interaction routes
apps/broker/src/transaction-store.ts         # expiring one-time transactions
apps/broker/src/types.ts                     # receipt and transaction contracts
apps/broker/src/vs-agent-client.ts           # bounded VS Agent HTTP client
apps/broker/tests/*.test.ts
apps/demo-app/package.json
apps/demo-app/src/config.ts                  # validated Keycloak/app config
apps/demo-app/src/html.ts                    # signed-in/out and wallet pages
apps/demo-app/src/index.ts                   # process entrypoint
apps/demo-app/src/keycloak-client.ts         # discovery and code exchange
apps/demo-app/src/local-wallet-client.ts     # server-side VS Agent proxy
apps/demo-app/src/server.ts                  # OIDC and holder routes
apps/demo-app/src/session-store.ts           # opaque cookie sessions
apps/demo-app/tests/*.test.ts
keycloak/realm.template.json                 # realm without committed secrets
scripts/setup.ts                             # secrets, JWKS, realm rendering
scripts/verify-keycloak.ts                   # admin API assertions
scripts/verify-local-flow.ts                 # browserless local smoke path
tests/keycloak.integration.test.ts
README.md
docs/evidence/README.md
```

### Isolated VS Agent worktree

```text
packages/plugin-openid4vc/src/services/IssuerService.ts
packages/plugin-openid4vc/src/services/VerifierService.ts
packages/plugin-openid4vc/src/services/receipt.ts
packages/plugin-openid4vc/src/nestjs/IssuerController.ts
packages/plugin-openid4vc/tests/IssuerController.test.ts
packages/plugin-openid4vc/tests/IssuerService.test.ts
packages/plugin-openid4vc/tests/VerifierService.test.ts
packages/plugin-openid4vc/tests/flow.integration.test.ts
```

---

### Task 1: Initialize the strict TypeScript workspace and generated-secret boundary

**Files:**
- Create: `.gitignore`
- Create: `.env.example`
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `tsconfig.base.json`
- Create: `biome.json`
- Create: `vitest.config.ts`
- Create: `apps/broker/package.json`
- Create: `apps/demo-app/package.json`
- Create: `scripts/setup.ts`
- Test: `tests/setup.test.ts`

**Interfaces:**
- Produces: `.data/.env` and `.data/broker-jwks.json`.
- Produces: root commands `pnpm run setup`, `pnpm check`, `pnpm test`, `pnpm build`, and `pnpm dev`.

- [ ] **Step 1: Write the failing setup test**

```ts
// tests/setup.test.ts
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { generateLocalData } from "../scripts/setup.js";

describe("generateLocalData", () => {
  it("generates private secrets and a private ES256 JWK", async () => {
    const output = await mkdtemp(join(tmpdir(), "verana-keycloak-"));
    await generateLocalData(output);

    const env = await readFile(join(output, ".env"), "utf8");
    const jwks = JSON.parse(await readFile(join(output, "broker-jwks.json"), "utf8"));

    expect(env).toContain("PAIRWISE_SUB_SECRET=");
    expect(jwks.keys[0]).toMatchObject({ kty: "EC", crv: "P-256", use: "sig" });
    expect(jwks.keys[0].d).toEqual(expect.any(String));
  });
});
```

- [ ] **Step 2: Run the test and verify the missing module failure**

Run: `pnpm exec vitest run tests/setup.test.ts`

Expected: FAIL because `scripts/setup.ts` does not exist.

- [ ] **Step 3: Add the workspace configuration**

Use these root scripts and exact pinned versions:

```json
{
  "name": "verana-keycloak-playground",
  "private": true,
  "type": "module",
  "packageManager": "pnpm@10.28.1",
  "scripts": {
    "setup": "tsx scripts/setup.ts",
    "dev": "pnpm --parallel --filter @verana-playground/broker --filter @verana-playground/demo-app dev",
    "build": "pnpm -r build",
    "typecheck": "pnpm -r typecheck",
    "lint": "biome check .",
    "test": "vitest run",
    "check": "pnpm lint && pnpm typecheck && pnpm test && pnpm build"
  },
  "devDependencies": {
    "@biomejs/biome": "2.5.5",
    "@types/node": "26.1.1",
    "@types/supertest": "7.2.1",
    "jose": "6.2.4",
    "tsx": "4.23.1",
    "typescript": "7.0.2",
    "vitest": "4.1.10"
  }
}
```

Configure strict TypeScript with `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noImplicitOverride`, and `verbatimModuleSyntax`.
Ignore `.data/`, `node_modules/`, `dist/`, `.env`, and coverage output.

Create the broker package with these exact dependencies and scripts:

```json
{
  "name": "@verana-playground/broker",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dependencies": {
    "@koa/router": "15.7.0",
    "dotenv": "17.4.2",
    "jose": "6.2.4",
    "koa": "3.2.1",
    "koa-bodyparser": "4.4.1",
    "koa-mount": "4.2.0",
    "oidc-provider": "9.10.0",
    "qrcode": "1.5.4",
    "zod": "4.4.3"
  },
  "devDependencies": {
    "@types/koa": "2.15.0",
    "@types/koa-bodyparser": "4.3.12",
    "@types/koa-mount": "4.0.5",
    "@types/oidc-provider": "9.5.0",
    "@types/qrcode": "1.5.6",
    "supertest": "7.2.2"
  }
}
```

Create the demo-app package with the same `dev`, `build`, and `typecheck`
scripts and these dependencies: `@koa/router@15.7.0`, `dotenv@17.4.2`,
`koa@3.2.1`, `koa-bodyparser@4.4.1`, `openid-client@6.8.4`, and
`zod@4.4.3`; add `@types/koa@2.15.0`, `@types/koa-bodyparser@4.3.12`,
and `supertest@7.2.2` as dev dependencies. Add a package-local `tsconfig.json`
to each package that extends the root configuration and writes to `dist/`.

Use this non-secret `.env.example`; `pnpm run setup` writes the four secret values
to ignored `.data/.env`:

```dotenv
BROKER_ISSUER=http://localhost:3001
BROKER_PORT=3001
KEYCLOAK_BROKER_REDIRECT_URI=http://localhost:8080/realms/verana-playground/broker/verana-wallet/endpoint
VS_AGENT_VERIFIER_BASE_URL=http://localhost:3201
EXPECTED_VCT=https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation
EXPECTED_VTJSC_ID=https://unfold-org.77.42.86.24.sslip.io/vt/schemas-unfold-attestation-jsc.json
SECTOR_IDENTIFIER=verana-playground
BROKER_JWKS_PATH=.data/broker-jwks.json

DEMO_APP_PORT=3000
KEYCLOAK_ISSUER=http://localhost:8080/realms/verana-playground
KEYCLOAK_CLIENT_ID=playground-app
DEMO_APP_REDIRECT_URI=http://localhost:3000/callback
VS_AGENT_ISSUER_BASE_URL=http://localhost:3101
VS_AGENT_HOLDER_BASE_URL=http://localhost:3101

VERANA_RESOLVER_URL=https://resolver.testnet.verana.network/v1/trust
EXPECTED_ISSUER_DID=did:webvh:QmPjKbgpLykjtHGTUfVRNoHra94mjitQsFniXYCTgmNYzG:unfold-org.77.42.86.24.sslip.io
EXPECTED_VERIFIER_DID=did:webvh:QmZ9BT7AsWf62ubssns11KfiuauuoVk2v3zL8HYbGSFVTU:unfold-verifier.77.42.86.24.sslip.io
```

- [ ] **Step 4: Implement deterministic-shape secret generation**

```ts
// scripts/setup.ts
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const secret = () => randomBytes(32).toString("base64url");

export async function generateLocalData(
  output = join(root, ".data"),
): Promise<void> {
  await mkdir(output, { recursive: true });
  const appSecret = secret();
  const brokerSecret = secret();
  const pairwiseSecret = secret();
  const sessionSecret = secret();
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = { ...(await exportJWK(privateKey)), alg: "ES256", use: "sig", kid: "playground-es256" };

  const env = [
    `PLAYGROUND_APP_CLIENT_SECRET=${appSecret}`,
    `BROKER_CLIENT_SECRET=${brokerSecret}`,
    `PAIRWISE_SUB_SECRET=${pairwiseSecret}`,
    `SESSION_SECRET=${sessionSecret}`,
    "",
  ].join("\n");

  await writeFile(join(output, ".env"), env, { mode: 0o600 });
  await writeFile(join(output, "broker-jwks.json"), JSON.stringify({ keys: [privateJwk] }, null, 2), { mode: 0o600 });
  await Promise.all([".env", "broker-jwks.json"].map(file => chmod(join(output, file), 0o600)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await generateLocalData();
}
```

- [ ] **Step 5: Install and verify the foundation**

Run: `pnpm install && pnpm exec vitest run tests/setup.test.ts && pnpm lint`

Expected: setup test PASS and Biome exits 0.

- [ ] **Step 6: Commit**

```bash
git add .gitignore .env.example package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json biome.json vitest.config.ts apps scripts tests
git commit -m "chore: initialize Keycloak playground workspace"
```

---

### Task 2: Implement the fail-closed broker policy and pairwise subject

**Files:**
- Create: `apps/broker/src/types.ts`
- Create: `apps/broker/src/pairwise-sub.ts`
- Create: `apps/broker/src/policy.ts`
- Create: `apps/broker/src/transaction-store.ts`
- Test: `apps/broker/tests/pairwise-sub.test.ts`
- Test: `apps/broker/tests/policy.test.ts`
- Test: `apps/broker/tests/transaction-store.test.ts`

**Interfaces:**
- Produces: `derivePairwiseSub(input: PairwiseSubInput): string`.
- Produces: `authorizeReceipt(receipt, expected): AuthorizedIdentity`.
- Produces: `TransactionStore.create/get/complete`.

- [ ] **Step 1: Write failing policy and subject tests**

```ts
const positive = {
  state: "ResponseVerified",
  receipt: {
    exchange: {
      protocol: "OID4VP 1.0",
      vct: "https://demo/vct",
      sessionId: "vs-1",
      tenant: "trusted",
      verifiedAt: "2026-07-24T10:00:00.000Z"
    },
    verifier: { did: "did:web:verifier.example", verdict: "TRUSTED_AUTHORIZED" },
    issuer: { did: "did:web:issuer.example", verdict: "TRUSTED_AUTHORIZED" },
    credential: { vct: "https://demo/vct", disclosedClaims: { subject_id: "user-1", organization: "ACME", role: "employee" } },
    registry: { vtjscId: "https://demo/schema" }
  }
};

expect(authorizeReceipt(positive, {
  sessionId: "vs-1",
  vct: "https://demo/vct",
  vtjscId: "https://demo/schema"
})).toMatchObject({
  subjectId: "user-1",
  organization: "ACME",
  role: "employee"
});

const expected = {
  sessionId: "vs-1",
  vct: "https://demo/vct",
  vtjscId: "https://demo/schema"
};

for (const verdict of ["PARTIAL", "TRUSTED_NOT_AUTHORIZED", "UNTRUSTED", "RESOLVER_UNAVAILABLE"]) {
  expect(() => authorizeReceipt({
    ...positive,
    receipt: { ...positive.receipt, verifier: { ...positive.receipt.verifier, verdict } }
  }, expected)).toThrow("verifier_not_authorized");
}
```

Add a pairwise test proving identical inputs are stable and a different sector
produces a different 43-character base64url value.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `pnpm exec vitest run apps/broker/tests/pairwise-sub.test.ts apps/broker/tests/policy.test.ts apps/broker/tests/transaction-store.test.ts`

Expected: FAIL because the broker modules do not exist.

- [ ] **Step 3: Implement the exact domain contracts**

```ts
export type PositiveVerdict = "TRUSTED_AUTHORIZED";

export interface AuthorizedIdentity {
  subjectId: string;
  organization: "ACME";
  role: "employee";
  issuerDid: string;
  verifierDid: string;
}

export interface PairwiseSubInput {
  secret: Uint8Array;
  issuerDid: string;
  subjectId: string;
  sectorIdentifier: string;
}
```

```ts
export function derivePairwiseSub(input: PairwiseSubInput): string {
  const value = [input.issuerDid, input.subjectId, input.sectorIdentifier].join("\u001f");
  return createHmac("sha256", input.secret).update(value, "utf8").digest("base64url");
}
```

`authorizeReceipt` must parse with a strict Zod schema, compare session, VCT,
and schema identifiers with constant expected strings, enforce both positive
verdicts, require non-empty DIDs, bound `subject_id` to 1–200 characters, and
require exact ACME/employee claims. Include `PARTIAL` in the parsed denied
verdict union even though the current VS Agent receipt type does not emit it,
so a future resolver response cannot accidentally become positive. Return
short machine error codes only.

- [ ] **Step 4: Implement the expiring one-time transaction store**

```ts
export interface LoginTransaction {
  uid: string;
  vsSessionId: string;
  authorizationRequest: string;
  createdAt: number;
  expiresAt: number;
  status: "pending" | "verified" | "denied" | "unavailable" | "used";
  accountId?: string;
  errorCode?: string;
}
```

`complete(uid, accountId)` must atomically reject missing, expired, non-pending,
or already-used transactions. Tests use an injected clock and prove a
five-minute expiry and replay rejection.

- [ ] **Step 5: Run focused and package checks**

Run: `pnpm exec vitest run apps/broker/tests && pnpm --filter @verana-playground/broker typecheck`

Expected: all broker domain tests PASS and TypeScript exits 0.

- [ ] **Step 6: Commit**

```bash
git add apps/broker
git commit -m "feat: add fail-closed broker policy"
```

---

### Task 3: Add the stable subject claim to an isolated VS Agent worktree

**Files:**
- Modify: `packages/plugin-openid4vc/src/services/IssuerService.ts`
- Modify: `packages/plugin-openid4vc/src/services/VerifierService.ts`
- Modify: `packages/plugin-openid4vc/src/services/receipt.ts`
- Modify: `packages/plugin-openid4vc/src/nestjs/IssuerController.ts`
- Modify: `packages/plugin-openid4vc/tests/IssuerController.test.ts`
- Modify: `packages/plugin-openid4vc/tests/IssuerService.test.ts`
- Modify: `packages/plugin-openid4vc/tests/VerifierService.test.ts`
- Modify: `packages/plugin-openid4vc/tests/flow.integration.test.ts`

**Interfaces:**
- Consumes: offer claims `{ subjectId, organization, role }`.
- Produces: SD-JWT claim `subject_id`.
- Produces: `receipt.credential.disclosedClaims.subject_id`.
- Produces: `GET /oid4vc-demo/capabilities` with a non-secret versioned
  contract used by the playground preflight.

- [ ] **Step 1: Create the isolated worktree with the worktree skill**

Use `superpowers:using-git-worktrees`. Base the branch
`codex/keycloak-subject-claim` on `feature/openid4vc-plugin` without switching
or editing the dirty checkout.

- [ ] **Step 2: Add failing issuer tests**

Update the offer parser tests to require:

```ts
expect(parseOfferClaims({
  subjectId: "acme-user-001",
  organization: "ACME",
  role: "employee"
})).toEqual({
  subjectId: "acme-user-001",
  organization: "ACME",
  role: "employee"
});
```

Reject missing, blank, non-string, and over-200-character `subjectId`. Assert
that `buildSdJwtPayload` contains `subject_id` and that `DISCLOSURE_FRAME._sd`
equals `["subject_id", "organization", "role"]`.

- [ ] **Step 3: Run issuer tests and verify the expected failures**

Run from the worktree:

`pnpm --filter @verana-labs/plugin-openid4vc test -- IssuerService.test.ts IssuerController.test.ts`

Expected: FAIL on the missing `subjectId` contract.

- [ ] **Step 4: Implement the issuer claim**

Change the claim type everywhere to:

```ts
export interface DemoBadgeClaims {
  subjectId: string;
  organization: string;
  role: string;
}
```

Emit `subject_id: claims.subjectId`, include it in the disclosure frame, and
retain the existing organization/role bounds. Update remote fixtures with
fixed opaque values such as `remote-demo-trusted`.

- [ ] **Step 5: Add failing verifier and flow tests**

Assert `buildPresentationQuery` includes `{ path: ["subject_id"] }`, a verified
receipt contains `subject_id`, and the in-process issuance-to-presentation
flow returns the same opaque subject supplied at issuance.

- [ ] **Step 6: Implement verified subject propagation**

`VerifierService` must copy `subject_id` only from Credo's verified
`prettyClaims` into `disclosedClaims`. Do not accept request-body claims.
`ProofOfTrustReceipt` remains the only broker input.

Add this exact capability response through `IssuerController` and cover it in
the controller test:

```ts
{
  contractVersion: 1,
  offerClaims: ["subjectId", "organization", "role"],
  disclosedClaims: ["subject_id", "organization", "role"]
}
```

It contains no environment, key, DID, token, or session information.

- [ ] **Step 7: Verify the VS Agent change**

Run:

```bash
pnpm --filter @verana-labs/plugin-openid4vc test
pnpm --filter @verana-labs/plugin-openid4vc build
pnpm check-types
git diff --check
```

Expected: all plugin tests, package build, workspace typecheck, and diff check
PASS.

- [ ] **Step 8: Commit locally in the VS Agent worktree**

```bash
git add packages/plugin-openid4vc
git commit -m "feat(openid4vc): expose stable demo subject"
```

Do not push.

---

### Task 4: Add the bounded VS Agent client and login orchestration

**Files:**
- Create: `apps/broker/src/config.ts`
- Create: `apps/broker/src/vs-agent-client.ts`
- Create: `apps/broker/src/login-service.ts`
- Test: `apps/broker/tests/vs-agent-client.test.ts`
- Test: `apps/broker/tests/login-service.test.ts`

**Interfaces:**
- Produces: `VsAgentClient.createRequest("trusted")`.
- Produces: `VsAgentClient.getSession(id)`.
- Produces: `LoginService.start(uid)` and `LoginService.poll(uid)`.

- [ ] **Step 1: Write failing HTTP and orchestration tests**

Use a local test server. Prove:

- request creation accepts only a non-empty `authorizationRequest` and
  `sessionId`;
- polling has a three-second request timeout;
- non-2xx and malformed JSON become `vs_agent_unavailable`;
- pending sessions remain pending;
- positive receipts call `authorizeReceipt`, derive the pairwise subject, and
  store account claims;
- denied verdicts become `denied` and never create accounts.

- [ ] **Step 2: Run tests and verify missing modules**

Run: `pnpm exec vitest run apps/broker/tests/vs-agent-client.test.ts apps/broker/tests/login-service.test.ts`

Expected: FAIL because the client and service do not exist.

- [ ] **Step 3: Implement validated config**

```ts
import { config as loadDotenv } from "dotenv";
import { z } from "zod";

loadDotenv({ path: ".data/.env", override: false });

export const brokerConfigSchema = z.object({
  BROKER_ISSUER: z.string().url().default("http://localhost:3001"),
  BROKER_PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  BROKER_CLIENT_ID: z.string().default("keycloak-playground"),
  BROKER_CLIENT_SECRET: z.string().min(32),
  KEYCLOAK_BROKER_REDIRECT_URI: z.string().url().default("http://localhost:8080/realms/verana-playground/broker/verana-wallet/endpoint"),
  VS_AGENT_VERIFIER_BASE_URL: z.string().url().default("http://localhost:3201"),
  EXPECTED_VCT: z.string().url(),
  EXPECTED_VTJSC_ID: z.string().min(1),
  SECTOR_IDENTIFIER: z.string().default("verana-playground"),
  PAIRWISE_SUB_SECRET: z.string().min(32),
  BROKER_JWKS_PATH: z.string().default(".data/broker-jwks.json")
});
```

The broker uses port 3001, the issuer/holder VS Agent uses 3101, and the
verifier VS Agent uses 3201. `VS_AGENT_VERIFIER_BASE_URL` is therefore the
only VS Agent endpoint used by the broker.

- [ ] **Step 4: Implement the client and service**

Use `fetch` with `AbortSignal.timeout(3000)`, `cache: "no-store"`, and strict
Zod response parsing. Never log response bodies. `LoginService.poll` is the
only place that translates VS Agent states into transaction states.

- [ ] **Step 5: Verify and commit**

Run: `pnpm exec vitest run apps/broker/tests && pnpm --filter @verana-playground/broker typecheck`

Expected: PASS.

```bash
git add apps/broker
git commit -m "feat: orchestrate Verana login sessions"
```

---

### Task 5: Implement the OIDC provider and wallet interaction page

**Files:**
- Create: `apps/broker/src/account-store.ts`
- Create: `apps/broker/src/html.ts`
- Create: `apps/broker/src/oidc-provider.ts`
- Create: `apps/broker/src/server.ts`
- Create: `apps/broker/src/index.ts`
- Test: `apps/broker/tests/oidc-provider.test.ts`
- Test: `apps/broker/tests/server.test.ts`

**Interfaces:**
- Consumes: `LoginService`, `TransactionStore`, and `AccountStore`.
- Produces: OIDC discovery, `/auth`, `/token`, `/jwks`, and
  `/interaction/:uid`.

- [ ] **Step 1: Write failing discovery and interaction tests**

Tests must prove:

- discovery advertises Authorization Code and `S256`;
- only the exact Keycloak client and redirect URI are registered;
- a new login interaction creates one VS request;
- refreshing the interaction does not create another request;
- status polling returns only `{ status, errorCode? }`;
- `/interaction/:uid/complete` calls `interactionFinished` only after verified;
- denied, unavailable, expired, or used transactions cannot finish login;
- rendered HTML escapes every dynamic value and sets `Cache-Control: no-store`.

- [ ] **Step 2: Run tests and verify failure**

Run: `pnpm exec vitest run apps/broker/tests/oidc-provider.test.ts apps/broker/tests/server.test.ts`

Expected: FAIL because provider/server modules do not exist.

- [ ] **Step 3: Configure the provider**

Create `Provider` with:

```ts
{
  clients: [{
    client_id: config.BROKER_CLIENT_ID,
    client_secret: config.BROKER_CLIENT_SECRET,
    redirect_uris: [config.KEYCLOAK_BROKER_REDIRECT_URI],
    response_types: ["code"],
    grant_types: ["authorization_code"],
    token_endpoint_auth_method: "client_secret_post"
  }],
  jwks: privateJwks,
  claims: {
    openid: ["sub", "preferred_username", "organization", "role", "verana_verifier_did", "verana_issuer_did"]
  },
  features: { devInteractions: { enabled: false } },
  interactions: {
    policy: loginOnlyPolicy,
    url: (_ctx, interaction) => `/interaction/${interaction.uid}`
  },
  findAccount: async (_ctx, accountId) => accountStore.findAccount(accountId),
  ttl: { AuthorizationCode: 60, Interaction: 300, Session: 300 }
}
```

Build `loginOnlyPolicy` from `interactionPolicy.base()` and remove the consent
prompt because Keycloak is the single pre-registered first-party client.

- [ ] **Step 4: Implement the interaction routes**

The page displays:

- "Sign in with a Verana credential";
- the QR generated from the exact authorization request;
- a copy button for local-holder use;
- pending, verified, denied, expired, and unavailable states;
- a visible `LOCAL DEMO` and `TESTNET` label.

JavaScript polls the status endpoint and performs a top-level navigation to
`/interaction/:uid/complete` only when status is `verified`.

- [ ] **Step 5: Verify provider behavior and commit**

Run:

```bash
pnpm exec vitest run apps/broker/tests
pnpm --filter @verana-playground/broker typecheck
pnpm --filter @verana-playground/broker build
```

Expected: PASS.

```bash
git add apps/broker
git commit -m "feat: expose Verana OIDC broker"
```

---

### Task 6: Add the disposable Keycloak realm and verify its security mappings

**Files:**
- Create: `keycloak/realm.template.json`
- Create: `compose.yaml`
- Create: `scripts/verify-keycloak.ts`
- Modify: `scripts/setup.ts`
- Test: `tests/keycloak.integration.test.ts`

**Interfaces:**
- Consumes: generated `.data/realm.json`.
- Produces: Keycloak realm `verana-playground` on `http://localhost:8080`.

- [ ] **Step 1: Write the failing realm contract test**

Parse the template and assert:

- Keycloak client `playground-app` uses Authorization Code only;
- exact redirect URI `http://localhost:3000/callback`;
- IdP `verana-wallet` validates signatures and uses the broker JWKS URL;
- IdP client authentication is `client_secret_post`;
- first login flow contains only `idp-create-user-if-unique`;
- group `/organizations/acme` and realm role `employee` exist;
- advanced group claims config is
  `[{"key":"organization","value":"ACME"}]`;
- role mapper requires claim `role` value `employee`;
- subject mapper maps `sub` to `verana_subject`;
- app protocol mappers emit `verana_subject`, full group paths, and realm
  roles into ID, access, and UserInfo claims;
- no password user is pre-created.

Call `generateLocalData(tempDirectory)`, then assert `realm.json` exists,
contains no `__[A-Z0-9_]+__` placeholder, and uses the generated client
secrets rather than the placeholder strings.

- [ ] **Step 2: Run the test and verify the template is missing**

Run: `pnpm exec vitest run tests/keycloak.integration.test.ts`

Expected: FAIL because the realm template does not exist.

- [ ] **Step 3: Create the exact realm**

Use:

```json
{
  "realm": "verana-playground",
  "enabled": true,
  "sslRequired": "none",
  "registrationAllowed": false,
  "resetPasswordAllowed": false,
  "roles": { "realm": [{ "name": "employee" }] },
  "groups": [{ "name": "organizations", "subGroups": [{ "name": "acme" }] }],
  "clients": [{
    "clientId": "playground-app",
    "secret": "__PLAYGROUND_APP_CLIENT_SECRET__",
    "publicClient": false,
    "standardFlowEnabled": true,
    "implicitFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "redirectUris": ["http://localhost:3000/callback"],
    "webOrigins": ["http://localhost:3000"],
    "protocol": "openid-connect",
    "attributes": { "pkce.code.challenge.method": "S256" }
  }],
  "identityProviders": [{
    "alias": "verana-wallet",
    "displayName": "Verana Wallet",
    "providerId": "oidc",
    "enabled": true,
    "trustEmail": false,
    "storeToken": false,
    "firstBrokerLoginFlowAlias": "verana first broker login",
    "config": {
      "authorizationUrl": "http://localhost:3001/auth",
      "tokenUrl": "http://host.docker.internal:3001/token",
      "jwksUrl": "http://host.docker.internal:3001/jwks",
      "issuer": "http://localhost:3001",
      "clientId": "keycloak-playground",
      "clientSecret": "__BROKER_CLIENT_SECRET__",
      "clientAuthMethod": "client_secret_post",
      "defaultScope": "openid",
      "useJwksUrl": "true",
      "validateSignature": "true",
      "pkceEnabled": "true",
      "pkceMethod": "S256",
      "syncMode": "FORCE"
    }
  }]
}
```

Add this exact first-login flow:

```json
"authenticationFlows": [{
  "alias": "verana first broker login",
  "description": "JIT create verified Verana users",
  "providerId": "basic-flow",
  "topLevel": true,
  "builtIn": false,
  "authenticationExecutions": [{
    "authenticator": "idp-create-user-if-unique",
    "authenticatorFlow": false,
    "requirement": "REQUIRED",
    "priority": 10,
    "userSetupAllowed": false
  }]
}]
```

Add these exact IdP mappers. The group claim configuration is the serialized
JSON array required by Keycloak 26.7.0:

```json
"identityProviderMappers": [
  {
    "name": "ACME organization group",
    "identityProviderAlias": "verana-wallet",
    "identityProviderMapper": "oidc-advanced-group-idp-mapper",
    "config": {
      "syncMode": "FORCE",
      "claims": "[{\"key\":\"organization\",\"value\":\"ACME\"}]",
      "are.claim.values.regex": "false",
      "group": "/organizations/acme"
    }
  },
  {
    "name": "Employee role",
    "identityProviderAlias": "verana-wallet",
    "identityProviderMapper": "oidc-role-idp-mapper",
    "config": {
      "syncMode": "FORCE",
      "claim": "role",
      "claim.value": "employee",
      "role": "employee"
    }
  },
  {
    "name": "Verana pairwise subject",
    "identityProviderAlias": "verana-wallet",
    "identityProviderMapper": "oidc-user-attribute-idp-mapper",
    "config": {
      "syncMode": "FORCE",
      "claim": "sub",
      "user.attribute": "verana_subject",
      "allow.nullable.property": "false"
    }
  }
]
```

Add these exact protocol mappers to the `playground-app` client:

```json
"protocolMappers": [
  {
    "name": "verana subject",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "consentRequired": false,
    "config": {
      "user.attribute": "verana_subject",
      "claim.name": "verana_subject",
      "jsonType.label": "String",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "userinfo.token.claim": "true",
      "multivalued": "false"
    }
  },
  {
    "name": "organization groups",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-group-membership-mapper",
    "consentRequired": false,
    "config": {
      "full.path": "true",
      "claim.name": "groups",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "userinfo.token.claim": "true"
    }
  },
  {
    "name": "realm roles",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-realm-role-mapper",
    "consentRequired": false,
    "config": {
      "claim.name": "realm_access.roles",
      "jsonType.label": "String",
      "multivalued": "true",
      "id.token.claim": "true",
      "access.token.claim": "true",
      "userinfo.token.claim": "true"
    }
  }
]
```

- [ ] **Step 4: Extend setup to render the realm**

After generating the four secrets and broker JWK, read
`keycloak/realm.template.json`, replace exactly
`__PLAYGROUND_APP_CLIENT_SECRET__` and `__BROKER_CLIENT_SECRET__`, reject any
remaining placeholder matching `/__[A-Z0-9_]+__/`, and write
`.data/realm.json` with mode `0600`. Keep this rendering in
`generateLocalData` so `pnpm run setup` remains the single setup command.

- [ ] **Step 5: Add the pinned container**

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.7.0
    command: ["start-dev", "--import-realm"]
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: local-development-only
    volumes:
      - ./.data/realm.json:/opt/keycloak/data/import/verana-playground-realm.json:ro
    extra_hosts:
      - "host.docker.internal:host-gateway"
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/127.0.0.1/8080"]
      interval: 5s
      timeout: 2s
      retries: 30
```

- [ ] **Step 6: Start and inspect the imported realm**

Run:

```bash
pnpm run setup
docker compose up -d keycloak
pnpm tsx scripts/verify-keycloak.ts
```

Expected: the script reports the realm, client, IdP, signature validation,
group mapper, role mapper, and subject mapper as present.

- [ ] **Step 7: Commit**

```bash
git add keycloak compose.yaml scripts/setup.ts scripts/verify-keycloak.ts tests/keycloak.integration.test.ts
git commit -m "feat: configure Keycloak identity broker"
```

---

### Task 7: Implement the protected application and local-holder UI

**Files:**
- Create: `apps/demo-app/src/config.ts`
- Create: `apps/demo-app/src/session-store.ts`
- Create: `apps/demo-app/src/keycloak-client.ts`
- Create: `apps/demo-app/src/local-wallet-client.ts`
- Create: `apps/demo-app/src/html.ts`
- Create: `apps/demo-app/src/server.ts`
- Create: `apps/demo-app/src/index.ts`
- Test: `apps/demo-app/tests/keycloak-client.test.ts`
- Test: `apps/demo-app/tests/local-wallet-client.test.ts`
- Test: `apps/demo-app/tests/server.test.ts`

**Interfaces:**
- Produces: app routes `/`, `/login`, `/callback`, `/profile`, `/logout`.
- Produces: holder routes `/wallet`, `/wallet/issue`, `/wallet/resolve`,
  `/wallet/share`.
- Consumes separate `VS_AGENT_ISSUER_BASE_URL`, `VS_AGENT_HOLDER_BASE_URL`,
  and `VS_AGENT_VERIFIER_BASE_URL` values; never assume one DID is authorized
  for both issuer and verifier roles.

- [ ] **Step 1: Write failing OIDC application tests**

Prove:

- `/login` creates random state, nonce, and PKCE verifier and redirects to
  Keycloak;
- `/callback` rejects missing or mismatched state;
- token exchange requires the stored PKCE verifier and expected nonce;
- only ID tokens with Keycloak issuer and `playground-app` audience create a
  session;
- `/profile` renders the verified `verana_subject`, requires
  `/organizations/acme` in `groups`, and requires `employee` in
  `realm_access.roles`;
- `/profile` requires a server-side opaque session;
- session cookies are `HttpOnly`, `SameSite=Lax`, and not readable by scripts;
- logout deletes the local session.

- [ ] **Step 2: Write failing local-holder tests**

With a fake VS Agent server, prove:

- issue sends `{ subjectId, organization: "ACME", role: "employee" }`;
- issuance goes to the configured issuer, acceptance and request resolution go
  to the holder, and presentation creation/status go to the verifier;
- share requires the returned gate ID;
- non-positive verifier verdicts render a refusal and never call share;
- proxy errors return safe messages without upstream bodies.

- [ ] **Step 3: Run tests and verify missing modules**

Run: `pnpm exec vitest run apps/demo-app/tests`

Expected: FAIL because demo-app modules do not exist.

- [ ] **Step 4: Implement Keycloak Authorization Code + PKCE**

Load ignored secrets from `.data/.env` with `dotenv` before parsing a strict
Zod config that requires `PLAYGROUND_APP_CLIENT_SECRET`, `SESSION_SECRET`,
`KEYCLOAK_ISSUER`, `KEYCLOAK_CLIENT_ID`, `DEMO_APP_REDIRECT_URI`, and the
three role-specific VS Agent base URLs.

Use `openid-client`:

```ts
const verifier = randomPKCECodeVerifier();
const challenge = await calculatePKCECodeChallenge(verifier);
const state = randomState();
const nonce = randomNonce();
const url = buildAuthorizationUrl(configuration, {
  redirect_uri: config.DEMO_APP_REDIRECT_URI,
  scope: "openid",
  code_challenge: challenge,
  code_challenge_method: "S256",
  state,
  nonce
});
```

Exchange with `authorizationCodeGrant` and checks
`{ pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce }`.
Keep token responses only long enough to extract verified claims; store no
refresh token.

- [ ] **Step 5: Implement the local-holder pages**

The wallet page shows this honest sequence:

1. issue "ACME Playground Employee Badge";
2. accept in the local VS Agent holder;
3. copy/open the broker authorization request;
4. review the Q1/Q3 verdict and requested claims;
5. share only when verdict is `TRUSTED_AUTHORIZED`.

Display `LOCAL HOLDER`, `TESTNET`, and "not physical-wallet evidence".

- [ ] **Step 6: Verify and commit**

Run:

```bash
pnpm exec vitest run apps/demo-app/tests
pnpm --filter @verana-playground/demo-app typecheck
pnpm --filter @verana-playground/demo-app build
```

Expected: PASS.

```bash
git add apps/demo-app
git commit -m "feat: add Keycloak demo application"
```

---

### Task 8: Run the complete local flow and retain honest evidence

**Files:**
- Create: `scripts/verify-local-flow.ts`
- Create: `README.md`
- Create: `docs/evidence/README.md`
- Modify: `.env.example`

**Interfaces:**
- Consumes: running VS Agent, broker, demo app, Keycloak, and generated data.
- Produces: reproducible commands and bounded local evidence.

- [ ] **Step 1: Add the failing live-trust preflight**

Before creating a credential or Keycloak user, the script must query the live
resolver with the configured issuer DID, verifier DID, and exact VTJSC. Parse
responses strictly and require:

- exact response DID equality for Q1, Q2, and Q3;
- `trustStatus === "TRUSTED"` and `production === true` for both DIDs;
- exact response VTJSC equality;
- issuer Q2 `authorized === true`;
- verifier Q3 `authorized === true`.

The known testnet fixture on 2026-07-24 is:

```text
issuer DID:
did:webvh:QmPjKbgpLykjtHGTUfVRNoHra94mjitQsFniXYCTgmNYzG:unfold-org.77.42.86.24.sslip.io

verifier DID:
did:webvh:QmZ9BT7AsWf62ubssns11KfiuauuoVk2v3zL8HYbGSFVTU:unfold-verifier.77.42.86.24.sslip.io

VCT:
https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation

VTJSC:
https://unfold-org.77.42.86.24.sslip.io/vt/schemas-unfold-attestation-jsc.json
```

Fresh read-only probes confirmed the issuer is Q2-authorized and the separate
verifier is Q3-authorized for that VTJSC. Do not configure a single local
agent DID for both roles: neither known DID is authorized for both.

The preflight must call `GET /oid4vc-demo/capabilities` on the issuer, holder,
and verifier endpoints and require `contractVersion: 1` plus exact
`subjectId`/`subject_id` claim arrays. The current public deployment does not
expose that capability or claim; until the isolated VS Agent change is running
on counterparties that control the authorized DIDs, the honest result is
`BLOCKED_SUBJECT_CONTRACT`, and no positive Keycloak login may be claimed.

- [ ] **Step 2: Add the failing smoke script**

The script must:

- wait for VS Agent, broker discovery, Keycloak realm, and demo-app health;
- create and accept one badge for `subjectId: "call-demo-user"`;
- start one trusted presentation request;
- resolve and share through the local holder;
- poll until `ResponseVerified`;
- assert both receipt verdicts are `TRUSTED_AUTHORIZED`;
- run a second presentation and assert the derived pairwise subject is stable;
- run a rogue request and assert it is denied.

It must print only stage names, verdict categories, and a final PASS/FAIL line.

- [ ] **Step 3: Run the script before implementation and verify failure**

Run: `pnpm tsx scripts/verify-local-flow.ts`

Expected: FAIL on the first unavailable component or missing script behavior.

- [ ] **Step 4: Implement the smoke checks and documentation**

README startup sequence:

```bash
pnpm install
pnpm run setup
docker compose up -d keycloak
pnpm dev
```

Document the separate VS Agent worktree command and required environment:

```text
issuer/holder instance:
AGENT_PORT=3101
ADMIN_PORT=3100
PUBLIC_API_BASE_URL=http://localhost:3101
AGENT_ENDPOINTS=ws://localhost:3101
OID4VC_ISSUER_ENABLED=true
OID4VC_HOLDER_ENABLED=true
OID4VC_VERIFIER_ENABLED=false
VS_AGENT_PLUGINS=messaging,openid4vc

verifier instance:
AGENT_PORT=3201
ADMIN_PORT=3200
PUBLIC_API_BASE_URL=http://localhost:3201
AGENT_ENDPOINTS=ws://localhost:3201
OID4VC_ISSUER_ENABLED=false
OID4VC_HOLDER_ENABLED=false
OID4VC_VERIFIER_ENABLED=true
VS_AGENT_PLUGINS=messaging,openid4vc

both role instances:
VERANA_RESOLVER_URL=https://resolver.testnet.verana.network/v1/trust
UNFOLD_VCT=https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation
UNFOLD_VTJSC_ID=https://unfold-org.77.42.86.24.sslip.io/vt/schemas-unfold-attestation-jsc.json
```

Each role also needs its own database, Redis namespace, wallet ID/key, and an
`AGENT_PUBLIC_DID` whose keys it genuinely controls and whose exact role
authorization passes the preflight. Do not point a locally generated
self-signed certificate at someone else's authorized DID. Use the actual
branch commit, actual VCT, actual schema identifier, and actual resolver URL
discovered during execution. Do not insert example values into the evidence
record.

- [ ] **Step 5: Execute all non-browser verification**

Run:

```bash
pnpm check
docker compose config
pnpm tsx scripts/verify-keycloak.ts
pnpm tsx scripts/verify-local-flow.ts
git diff --check
git status --short
```

Expected:

- formatting, typecheck, tests, and builds PASS;
- Compose renders successfully;
- Keycloak realm verification PASS;
- only intended documentation/evidence files remain uncommitted.

If the live preflight passes, the trusted login smoke must PASS, the repeated
subject must be stable, and the rogue login must be denied. If it returns
`BLOCKED_SUBJECT_CONTRACT` or another live prerequisite failure, retain the
non-zero result, skip the positive/browser claims, and record the exact
sanitized blocker. Never convert a blocked live acceptance into a passing
fixture result.

- [ ] **Step 6: Exercise the real browser flow**

With all preflights passing:

1. open `http://localhost:3000`;
2. choose login and follow Keycloak to "Verana Wallet";
3. copy the authorization request into the local-holder page;
4. issue and accept the badge, resolve the request, inspect Q1/Q3, and share;
5. return to the broker interaction and complete the Keycloak redirect;
6. assert the profile shows a non-empty `verana_subject`, ACME organization,
   and employee role;
7. log out, repeat with the same credential, and confirm the same external
   subject/account is reused;
8. run the rogue verifier path and confirm it never creates a Keycloak user.

Use the in-app browser or Playwright and retain only sanitized screenshots.
This browser observation is separate from the lower-level smoke script. Do not
claim the browser or JIT account path was exercised based only on API tests.

- [ ] **Step 7: Record evidence**

In `docs/evidence/README.md`, record:

- date and timezone;
- playground and VS Agent commit hashes;
- exact commands and exit results;
- trusted and denied verdict categories;
- whether browser UI was exercised;
- whether any physical wallet or trusted HTTPS was exercised;
- unresolved ECS-Badge and identifier-to-DID limitations.

Never record secrets, raw QR payloads, credentials, presentations, tokens, or
private keys.

- [ ] **Step 8: Commit the runbook and verified evidence boundary**

```bash
git add README.md .env.example scripts/verify-local-flow.ts docs/evidence/README.md
git commit -m "docs: add Keycloak playground runbook"
```

Do not push.
