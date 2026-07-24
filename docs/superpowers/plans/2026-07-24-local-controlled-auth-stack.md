# Local Controlled Authentication Stack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deeply validate the reusable FIDES issuer, holder, verifier, Verana trust, and Keycloak playground foundation defined with Fabrice, using real local OpenID4VC protocol components and an explicitly controlled Q1/Q2/Q3 resolver.

**Architecture:** Three isolated containers run one VS Agent image built from reviewed commit `e2bba78`: issuer, holder, and verifier. A loopback-only TypeScript resolver supplies exact controlled trust responses, while the existing broker, Keycloak realm, and demo application perform real OIDC brokering, JIT provisioning, claim mapping, logout, and stable pairwise-subject reuse. A guarded lifecycle records and restores the unrelated Twitter VS Agent state and removes only disposable playground resources.

**Tech Stack:** Node.js 24+, pnpm 10.28.1, TypeScript 7.0.2, Koa 3.2.1, Zod 4.4.3, Vitest 4.1.10, Supertest 7.2.2, Biome 2.5.5, Docker Compose 5+, Keycloak 26.7.0, VS Agent OpenID4VC target `vs-agent-openid4vc`, OpenID4VCI, OpenID4VP, and OIDC Authorization Code with PKCE.

## Global Constraints

- Every controlled-local page, command result, and evidence record uses the exact label `LOCAL_CONTROLLED`.
- `LOCAL_CONTROLLED` is local integration evidence, not Verana testnet, trusted-HTTPS, physical-wallet, partner-wallet, or production evidence.
- Only the trust resolver may be controlled; issuance, holder acceptance, presentation verification, proof-of-trust receipt, broker, Keycloak, and application remain real components.
- Build one shared VS Agent image from `/Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim` at commit `e2bba78` or a reviewed descendant, target `vs-agent-openid4vc`.
- Run three isolated VS Agent roles with unique wallet IDs, generated wallet keys, and named volumes.
- Use exact DIDs `did:web:issuer.localhost`, `did:web:holder.localhost`, `did:web:verifier.localhost`, and `did:web:rogue.localhost`.
- Use exact claims `subject_id=local-controlled-user`, `organization=ACME`, and `role=employee`.
- Bind every host port to loopback: resolver `3099`, demo `3000`, broker `3001`, Keycloak `8080`, issuer `3100/3101`, holder `3110/3111`, and verifier `3200/3201`.
- Resolver responses must be `application/json`, strict-parser compatible, valid UTF-8, and at most 65,536 bytes.
- A positive login requires exact issuer Q1/Q2 and verifier Q1/Q3 results plus both receipt verdicts equal to `TRUSTED_AUTHORIZED`.
- Start with zero Keycloak users; denied, rogue, malformed, oversized, replayed, or unavailable-resolver paths must create no user or session.
- Before startup, record the state of `twitter-bot-vs-agent`, stop only that exact container when it owns ports `3000` or `3001`, and leave `twitter-bot-redis`, databases, images, and unrelated volumes untouched.
- Do not use Docker prune, delete unrelated state, copy VPS keys, modify `/opt/unfold`, expose the stack publicly, push Git branches, deploy, approve PRs, or post GitHub comments.
- Teardown removes only this Compose project's containers, network, named wallet volumes, local process state, and disposable `.data`, then restores `twitter-bot-vs-agent` only if it was running before startup.
- No raw credential, presentation, authorization request, token, receipt, wallet key, or private key may be written to browser storage, browser logs, evidence documents, or command output.
- Complete automated, adversarial, live API, real Chrome, final review, clean-worktree, and teardown checks before claiming acceptance.

---

## File Map

```text
apps/local-resolver/package.json            # workspace package and focused commands
apps/local-resolver/tsconfig.json            # strict TypeScript build
apps/local-resolver/src/contract.ts          # exact DIDs, VCT, VTJSC, and response builders
apps/local-resolver/src/server.ts            # loopback-only Koa resolver application
apps/local-resolver/src/index.ts             # validated process entry point
apps/local-resolver/tests/server.test.ts     # positive and fail-closed resolver matrix

apps/broker/src/config.ts                    # evidence-mode validation
apps/broker/src/html.ts                      # visible broker boundary
apps/broker/src/server.ts                    # passes mode to renderer
apps/broker/tests/config.test.ts             # evidence-mode config tests
apps/broker/tests/server.test.ts             # boundary rendering tests
apps/demo-app/src/config.ts                  # evidence-mode validation
apps/demo-app/src/html.ts                    # visible home/profile/wallet boundary
apps/demo-app/src/server.ts                  # passes mode to every page
apps/demo-app/tests/server.test.ts           # boundary and no-secret tests

compose.local-controlled.yaml                # Keycloak plus three isolated VS Agent roles
scripts/local-controlled-config.ts           # one canonical set of local identifiers and ports
scripts/setup-local-controlled.ts            # generated secrets and mode-0600 environment
tests/setup-local-controlled.test.ts         # generated-data and secret-mode tests

scripts/local-stack.ts                       # guarded preflight/up/down/status lifecycle
scripts/local-stack-process.ts               # starts resolver, broker, and demo as one host process
tests/local-stack.test.ts                    # command-runner lifecycle safety tests
package.json                                 # local:setup/up/down/status/verify commands

scripts/verify-local-flow.ts                  # evidence mode, repeat flow, and user-count assertions
tests/local-flow-verification.test.ts         # positive and adversarial verifier matrix

README.md                                    # exact operator runbook and proof boundary
docs/evidence/local-controlled-run.md         # sanitized verification evidence
```

### Task 1: Add the strict controlled trust resolver

**Files:**
- Create: `apps/local-resolver/package.json`
- Create: `apps/local-resolver/tsconfig.json`
- Create: `apps/local-resolver/src/contract.ts`
- Create: `apps/local-resolver/src/server.ts`
- Create: `apps/local-resolver/src/index.ts`
- Create: `apps/local-resolver/tests/server.test.ts`
- Modify: `pnpm-lock.yaml`

**Interfaces:**
- Produces: `LOCAL_CONTROLLED_CONTRACT`, `createLocalResolver()`, and `startLocalResolver(app, port)`.
- `LOCAL_CONTROLLED_CONTRACT` contains exact `issuerDid`, `holderDid`, `verifierDid`, `rogueDid`, `vct`, and `vtjscId` strings.
- `createLocalResolver()` returns a Koa application without listening so Supertest can exercise it.
- `startLocalResolver(app, 3099)` binds only to `127.0.0.1`.

- [ ] **Step 1: Write the failing resolver contract tests**

```ts
// apps/local-resolver/tests/server.test.ts
const ISSUER = "did:web:issuer.localhost";
const VERIFIER = "did:web:verifier.localhost";
const ROGUE = "did:web:rogue.localhost";
const VTJSC =
  "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json";

it.each([
  [ISSUER, { did: ISSUER, trustStatus: "TRUSTED", production: true }],
  [VERIFIER, { did: VERIFIER, trustStatus: "TRUSTED", production: true }],
  [ROGUE, { did: ROGUE, trustStatus: "UNTRUSTED", production: false }],
])("returns exact Q1 for %s", async (did, expected) => {
  const response = await request(createLocalResolver().callback())
    .get("/v1/trust/resolve")
    .query({ did });
  expect(response.status).toBe(200);
  expect(response.type).toBe("application/json");
  expect(response.body).toEqual(expected);
});

it.each([
  ["/v1/trust/issuer-authorization", ISSUER, true],
  ["/v1/trust/issuer-authorization", VERIFIER, false],
  ["/v1/trust/verifier-authorization", VERIFIER, true],
  ["/v1/trust/verifier-authorization", ROGUE, false],
])("binds authorization to role, DID, and VTJSC", async (path, did, authorized) => {
  const response = await request(createLocalResolver().callback())
    .get(path)
    .query({ did, vtjscId: VTJSC });
  expect(response.body).toEqual({ did, vtjscId: VTJSC, authorized });
});
```

Add focused cases for missing queries, duplicate `did`, duplicate `vtjscId`, unknown DIDs, wrong VTJSC, method mismatch, exact health response, local VCT, local VTJSC, JSON media type, and serialized bodies below 65,536 bytes.

- [ ] **Step 2: Run the resolver tests and confirm the red state**

Run:

```bash
pnpm exec vitest run apps/local-resolver/tests/server.test.ts
```

Expected: FAIL because `apps/local-resolver/src/server.ts` does not exist.

- [ ] **Step 3: Implement the exact contract and strict routes**

```ts
// apps/local-resolver/src/contract.ts
export const LOCAL_CONTROLLED_CONTRACT = Object.freeze({
  issuerDid: "did:web:issuer.localhost",
  holderDid: "did:web:holder.localhost",
  verifierDid: "did:web:verifier.localhost",
  rogueDid: "did:web:rogue.localhost",
  vct: "http://host.docker.internal:3099/vct/local-controlled-employee",
  vtjscId:
    "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json",
});

export function q1(did: string) {
  if (
    did === LOCAL_CONTROLLED_CONTRACT.issuerDid ||
    did === LOCAL_CONTROLLED_CONTRACT.verifierDid
  ) {
    return { did, trustStatus: "TRUSTED" as const, production: true };
  }
  return { did, trustStatus: "UNTRUSTED" as const, production: false };
}

export function authorization(
  role: "issuer" | "verifier",
  did: string,
  vtjscId: string,
) {
  const expectedDid =
    role === "issuer"
      ? LOCAL_CONTROLLED_CONTRACT.issuerDid
      : LOCAL_CONTROLLED_CONTRACT.verifierDid;
  return {
    did,
    vtjscId,
    authorized:
      did === expectedDid && vtjscId === LOCAL_CONTROLLED_CONTRACT.vtjscId,
  };
}
```

In `server.ts`, accept one and only one non-empty value for each required query, return `400` for malformed queries, `404` for unknown paths, set `Cache-Control: no-store`, and use Koa's JSON response handling. Serve immutable VCT and VTJSC objects whose IDs exactly match `LOCAL_CONTROLLED_CONTRACT`.

In `index.ts`, parse `LOCAL_RESOLVER_PORT` as an integer from `1` to `65535`, default to `3099`, create the application, and listen on `127.0.0.1`.

- [ ] **Step 4: Add the package metadata and build configuration**

```json
{
  "name": "@verana-playground/local-resolver",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dependencies": {
    "@koa/router": "15.7.0",
    "koa": "3.2.1"
  },
  "devDependencies": {
    "@types/koa": "2.15.0",
    "supertest": "7.2.2"
  }
}
```

Use the same `tsconfig.json` structure as the broker and demo packages, then run `pnpm install --lockfile-only` to update the lockfile without changing dependency versions.

- [ ] **Step 5: Run focused and workspace gates**

Run:

```bash
pnpm exec vitest run apps/local-resolver/tests/server.test.ts
pnpm --filter @verana-playground/local-resolver typecheck
pnpm --filter @verana-playground/local-resolver build
pnpm lint
```

Expected: all commands exit `0`.

- [ ] **Step 6: Commit the resolver**

```bash
git add apps/local-resolver pnpm-lock.yaml
git commit -m "feat: add controlled local trust resolver"
```

### Task 2: Make the controlled evidence boundary visible and fail-closed

**Files:**
- Modify: `apps/broker/src/config.ts`
- Modify: `apps/broker/src/html.ts`
- Modify: `apps/broker/src/server.ts`
- Modify: `apps/broker/tests/config.test.ts`
- Modify: `apps/broker/tests/server.test.ts`
- Modify: `apps/demo-app/src/config.ts`
- Modify: `apps/demo-app/src/html.ts`
- Modify: `apps/demo-app/src/server.ts`
- Modify: `apps/demo-app/tests/server.test.ts`

**Interfaces:**
- Produces: `EvidenceMode = "LIVE_VERANA" | "LOCAL_CONTROLLED"`.
- Both `BrokerConfig` and `DemoConfig` expose `EVIDENCE_MODE`.
- Every broker interaction and demo page receives the configured mode.
- `LOCAL_CONTROLLED` copy states that the resolver is controlled and the result is not testnet or physical-wallet evidence.

- [ ] **Step 1: Add failing configuration and rendering tests**

```ts
it("accepts only explicit evidence modes", () => {
  expect(loadBrokerConfig(validBrokerEnv({ EVIDENCE_MODE: "LOCAL_CONTROLLED" }))
    .EVIDENCE_MODE).toBe("LOCAL_CONTROLLED");
  expect(() =>
    loadBrokerConfig(validBrokerEnv({ EVIDENCE_MODE: "local" })),
  ).toThrow();
});

it("labels every local-controlled page without rendering protocol secrets", async () => {
  const response = await request(localControlledDemo()).get("/");
  expect(response.text).toContain("LOCAL_CONTROLLED");
  expect(response.text).toContain("controlled local trust resolver");
  expect(response.text).toContain("not Verana testnet");
  expect(response.text).not.toContain("raw-secret-presentation-token");
});
```

Cover broker initial/pending/denied pages plus demo home, wallet, profile, error, and signed-out pages. Preserve the existing `LIVE_VERANA` rendering with no controlled-local claim.

- [ ] **Step 2: Run the boundary tests and confirm they fail**

Run:

```bash
pnpm exec vitest run \
  apps/broker/tests/config.test.ts \
  apps/broker/tests/server.test.ts \
  apps/demo-app/tests/server.test.ts
```

Expected: FAIL because `EVIDENCE_MODE` is not defined or rendered.

- [ ] **Step 3: Add the shared mode shape to each package without adding a dependency**

```ts
export const evidenceModeSchema = z
  .enum(["LIVE_VERANA", "LOCAL_CONTROLLED"])
  .default("LIVE_VERANA");

export type EvidenceMode = z.infer<typeof evidenceModeSchema>;
```

Add `EVIDENCE_MODE: evidenceModeSchema` to both config schemas. Keep the type local to each package so the existing workspace has no new cross-package runtime dependency.

- [ ] **Step 4: Pass and render the exact boundary**

Use this shared copy on controlled pages:

```html
<aside class="warning" data-evidence-mode="LOCAL_CONTROLLED">
  <strong>LOCAL_CONTROLLED</strong>
  Real local OpenID4VC and Keycloak flow with a controlled local trust resolver.
  This is not Verana testnet, trusted-HTTPS, physical-wallet, or production evidence.
</aside>
```

Escape the mode before rendering, keep `Cache-Control: no-store`, and do not add protocol values to query strings, local storage, session storage, HTML comments, or logs.

- [ ] **Step 5: Run the full package tests and checks**

Run:

```bash
pnpm exec vitest run apps/broker apps/demo-app
pnpm typecheck
pnpm lint
```

Expected: all commands exit `0`.

- [ ] **Step 6: Commit the evidence boundary**

```bash
git add apps/broker apps/demo-app
git commit -m "feat: label controlled authentication evidence"
```

### Task 3: Generate disposable local configuration and compose the three VS Agent roles

**Files:**
- Create: `scripts/local-controlled-config.ts`
- Create: `scripts/setup-local-controlled.ts`
- Create: `tests/setup-local-controlled.test.ts`
- Create: `compose.local-controlled.yaml`
- Modify: `.env.example`
- Modify: `.gitignore`
- Modify: `package.json`

**Interfaces:**
- Produces: `LOCAL_CONTROLLED`, an immutable object containing exact paths, identifiers, ports, and service URLs.
- Produces: `generateLocalControlledData(output, vsAgentSourcePath)` which calls the existing `generateLocalData(output)` and writes `.data/local-controlled.env` plus `.data/local-stack-state.json` only when the lifecycle records state.
- Produces: `pnpm local:setup`.
- Compose project name is exactly `verana-keycloak-local-controlled`.

- [ ] **Step 1: Write failing generated-data tests**

```ts
it("writes unique mode-0600 wallet secrets and exact local identifiers", async () => {
  await generateLocalControlledData(output, VS_SOURCE);
  const env = parseEnv(await readFile(join(output, "local-controlled.env"), "utf8"));

  expect(env.EVIDENCE_MODE).toBe("LOCAL_CONTROLLED");
  expect(env.VS_AGENT_SOURCE_PATH).toBe(VS_SOURCE);
  expect(env.EXPECTED_ISSUER_DID).toBe("did:web:issuer.localhost");
  expect(env.EXPECTED_VERIFIER_DID).toBe("did:web:verifier.localhost");
  expect(new Set([
    env.ISSUER_WALLET_KEY,
    env.HOLDER_WALLET_KEY,
    env.VERIFIER_WALLET_KEY,
  ]).size).toBe(3);
  expect((await stat(join(output, "local-controlled.env")).mode & 0o777).toBe(0o600);
});
```

Also assert the VS source must be an absolute path, the file contains no unresolved `__NAME__` values, the three wallet IDs differ, and `.data/.env` contains local broker/demo URLs plus `EVIDENCE_MODE=LOCAL_CONTROLLED`.

- [ ] **Step 2: Run the setup test and confirm it fails**

Run:

```bash
pnpm exec vitest run tests/setup-local-controlled.test.ts
```

Expected: FAIL because `generateLocalControlledData` does not exist.

- [ ] **Step 3: Implement one canonical controlled configuration**

```ts
export const LOCAL_CONTROLLED = Object.freeze({
  evidenceMode: "LOCAL_CONTROLLED" as const,
  composeProject: "verana-keycloak-local-controlled",
  requiredVsCommit: "e2bba78",
  twitterContainer: "twitter-bot-vs-agent",
  issuerDid: "did:web:issuer.localhost",
  holderDid: "did:web:holder.localhost",
  verifierDid: "did:web:verifier.localhost",
  rogueDid: "did:web:rogue.localhost",
  resolverUrl: "http://host.docker.internal:3099/v1/trust",
  vct: "http://host.docker.internal:3099/vct/local-controlled-employee",
  vtjscId:
    "http://host.docker.internal:3099/vtjsc/local-controlled-employee.json",
  ports: [3000, 3001, 3099, 3100, 3101, 3110, 3111, 3200, 3201] as const,
});
```

`generateLocalControlledData` uses `randomBytes(32).toString("base64url")` independently for each wallet, writes files with `{ mode: 0o600 }`, follows with `chmod(..., 0o600)`, and never prints secret values.

- [ ] **Step 4: Define the exact Compose overlay**

`compose.local-controlled.yaml` must:

- keep the existing Keycloak service from `compose.yaml`;
- set project resources under the lifecycle's exact project name;
- build the issuer image once from `${VS_AGENT_SOURCE_PATH}` with Dockerfile `apps/vs-agent/Dockerfile`, target `vs-agent-openid4vc`, and image `${VS_AGENT_IMAGE}`;
- run holder and verifier from the same `${VS_AGENT_IMAGE}`;
- publish every admin/public port as `127.0.0.1:<host>:<container>`;
- use container ports `3000` admin and `3001` public;
- use `AGENT_PUBLIC_DID`, `PUBLIC_API_BASE_URL`, `AGENT_ENDPOINTS`, `AGENT_WALLET_ID`, and unique `AGENT_WALLET_KEY` values;
- set `VS_AGENT_PLUGINS=messaging,openid4vc`;
- enable only `OID4VC_ISSUER_ENABLED` on issuer, only `OID4VC_HOLDER_ENABLED` on holder, and only `OID4VC_VERIFIER_ENABLED` on verifier;
- set `OID4VC_REQUEST_SIGNER=x5c`, `OID4VC_ISSUER_SIGNER=x5c`, controlled resolver/VCT/VTJSC values, and `ROGUE_VERIFIER_DID`;
- add `extra_hosts: ["host.docker.internal:host-gateway"]`;
- assign separate named volumes mounted at `/root/.afj`;
- use bounded health checks for `/v1/health` on the admin API and `/oid4vc-demo/capabilities` on the public API;
- contain no secret literals.

- [ ] **Step 5: Verify Compose rendering and secret isolation**

Run:

```bash
pnpm local:setup
docker compose \
  --project-name verana-keycloak-local-controlled \
  --env-file .data/local-controlled.env \
  -f compose.yaml \
  -f compose.local-controlled.yaml \
  config > .data/compose.rendered.yaml
if rg -q "0\\.0\\.0\\.0:|\\$\\{[A-Z0-9_]+\\}" .data/compose.rendered.yaml; then
  exit 1
fi
```

Expected: Compose exits `0`; the scan finds no `0.0.0.0` binding or unresolved variable. The pinned Keycloak bootstrap password may remain only in the non-production Compose configuration and must not appear in evidence output.

- [ ] **Step 6: Run focused setup, Compose, lint, and type checks**

Run:

```bash
pnpm exec vitest run tests/setup.test.ts tests/setup-local-controlled.test.ts
pnpm typecheck
pnpm lint
```

Expected: all commands exit `0`.

- [ ] **Step 7: Commit the generated configuration and Compose overlay**

```bash
git add \
  .env.example \
  .gitignore \
  package.json \
  compose.local-controlled.yaml \
  scripts/local-controlled-config.ts \
  scripts/setup-local-controlled.ts \
  tests/setup-local-controlled.test.ts
git commit -m "feat: compose isolated local VS Agent roles"
```

### Task 4: Add the guarded startup, status, and teardown lifecycle

**Files:**
- Create: `scripts/local-stack.ts`
- Create: `scripts/local-stack-process.ts`
- Create: `tests/local-stack.test.ts`
- Modify: `package.json`

**Interfaces:**
- Produces: `preflight(dependencies)`, `up(dependencies)`, `status(dependencies)`, and `down(dependencies)`.
- `CommandRunner.run(command, args, options)` is injectable in tests and uses `spawn`/`execFile`, never a shell-interpolated command.
- State file `.data/local-stack-state.json` contains version `1`, exact Compose project, `twitterWasRunning`, owned host process PID/start token, VS source commit, and start timestamp; it contains no secret.
- Produces: `pnpm local:up`, `pnpm local:status`, and `pnpm local:down`.

- [ ] **Step 1: Write the failing lifecycle safety matrix**

```ts
it("stops only the expected Twitter container and records restoration state", async () => {
  const runner = fakeRunner({
    twitterRunning: true,
    portOwners: { 3000: "twitter-bot-vs-agent", 3001: "twitter-bot-vs-agent" },
  });
  await up(dependencies(runner));
  expect(runner.calls).toContainEqual([
    "docker",
    ["stop", "twitter-bot-vs-agent"],
  ]);
  expect(runner.calls.some(([command, args]) =>
    command === "docker" && args.includes("twitter-bot-redis"),
  )).toBe(false);
});

it.each([
  ["unknown owner", { 3000: "another-project" }],
  ["wrong VS commit", { vsCommit: "deadbeef" }],
  ["Node 23", { nodeMajor: 23 }],
  ["insufficient disk", { freeBytes: 1 }],
])("fails preflight before Compose for %s", async (_name, behavior) => {
  const runner = fakeRunner(behavior);
  await expect(up(dependencies(runner))).rejects.toThrow();
  expect(runner.composeUpCalls()).toHaveLength(0);
});
```

Add cases proving:

- Twitter is not restarted if it was initially stopped;
- Twitter is restarted after teardown if it was initially running;
- only the exact Compose project receives `down --volumes --remove-orphans`;
- `.data` deletion rejects a symlink or path outside the repository;
- stale or mismatched PID metadata is reported and not killed;
- required ports are free after teardown;
- a partial startup invokes scoped teardown and restoration;
- output contains `LOCAL_CONTROLLED` and URLs but no generated secret;
- no call contains `prune`, `system prune`, `volume prune`, `image rm`, or an unrelated container/volume name.

- [ ] **Step 2: Run the lifecycle tests and confirm the red state**

Run:

```bash
pnpm exec vitest run tests/local-stack.test.ts
```

Expected: FAIL because `scripts/local-stack.ts` does not exist.

- [ ] **Step 3: Implement strict preflight**

Preflight must use argv arrays and validate:

```ts
export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CommandRunner {
  run(
    command: string,
    args: readonly string[],
    options?: { cwd?: string; env?: NodeJS.ProcessEnv },
  ): Promise<CommandResult>;
}
```

Checks, in order:

1. repository path and `.data` are not symlinks;
2. Node major is at least `24`;
3. `docker version` and `docker compose version` succeed;
4. playground worktree is the expected Git repository;
5. VS source path is the expected Git repository and `git merge-base --is-ancestor e2bba78 HEAD` succeeds;
6. Docker has enough free capacity to build without deleting anything;
7. each required port is free or owned only by the exact Twitter container on `3000/3001`;
8. no existing Compose resource with the exact project name is in an ambiguous partial state.

Record state before the first mutation. Stop Twitter only with:

```ts
await runner.run("docker", ["stop", "twitter-bot-vs-agent"]);
```

- [ ] **Step 4: Implement the single host process**

`local-stack-process.ts` starts the resolver first on `127.0.0.1:3099`, then creates the broker on `127.0.0.1:3001`, then creates the demo app on `127.0.0.1:3000`. It installs `SIGINT` and `SIGTERM` handlers that close all three servers in reverse order and exit non-zero when any startup fails.

The lifecycle launches it with `process.execPath`, the installed `tsx` loader, detached process-group ownership, a sanitized environment, and logs under `.data/logs/`. Persist PID plus a random start token supplied in the environment; `down` verifies both PID and token before signaling that process group.

- [ ] **Step 5: Implement bounded startup and scoped cleanup**

Startup order:

```text
generate data
record state
stop exact Twitter container when required
docker compose build issuer
docker compose up -d --force-recreate keycloak issuer holder verifier
wait Keycloak realm and all six VS Agent health/capability endpoints
start the single resolver, broker, and demo host process
wait GET http://127.0.0.1:3099/health
verify broker discovery, demo health, capability contracts, and zero Keycloak users
print LOCAL_CONTROLLED plus loopback URLs
```

If any step fails, stop only the verified host process group, run exact-project Compose teardown, remove only verified `.data` children, and restore Twitter according to recorded state.

Teardown Compose arguments are exactly:

```ts
[
  "compose",
  "--project-name",
  "verana-keycloak-local-controlled",
  "--env-file",
  ".data/local-controlled.env",
  "-f",
  "compose.yaml",
  "-f",
  "compose.local-controlled.yaml",
  "down",
  "--volumes",
  "--remove-orphans",
]
```

Do not add `--rmi`, global Docker cleanup, or wildcard deletion.

- [ ] **Step 6: Add exact package commands**

```json
{
  "scripts": {
    "local:setup": "tsx scripts/setup-local-controlled.ts",
    "local:up": "tsx scripts/local-stack.ts up",
    "local:status": "tsx scripts/local-stack.ts status",
    "local:down": "tsx scripts/local-stack.ts down",
    "local:verify": "tsx scripts/verify-local-flow.ts"
  }
}
```

Preserve every existing script.

- [ ] **Step 7: Run lifecycle tests and static gates**

Run:

```bash
pnpm exec vitest run tests/local-stack.test.ts
pnpm typecheck
pnpm lint
pnpm build
```

Expected: all commands exit `0`.

- [ ] **Step 8: Commit the guarded lifecycle**

```bash
git add package.json scripts/local-stack.ts scripts/local-stack-process.ts tests/local-stack.test.ts
git commit -m "feat: add guarded local stack lifecycle"
```

### Task 5: Extend the live verifier for controlled evidence and repeat-presentation safety

**Files:**
- Modify: `scripts/verify-local-flow.ts`
- Modify: `tests/local-flow-verification.test.ts`
- Modify: `scripts/keycloak-verification.ts`
- Modify: `tests/keycloak-verification.test.ts`

**Interfaces:**
- Extends `LocalFlowConfig` with `evidenceMode: "LIVE_VERANA" | "LOCAL_CONTROLLED"`.
- Produces terminal success `PASS LOCAL_CONTROLLED` only in controlled mode.
- Produces failure codes without credential, presentation, token, receipt, or secret bodies.
- Produces `readKeycloakUsers()` and `assertKeycloakUserCount(expectedCount)`.

- [ ] **Step 1: Add failing success, repeat, and denial tests**

```ts
it("prints PASS LOCAL_CONTROLLED only after two stable complete flows", async () => {
  const services = await startFakeServices({ stableSubject: true });
  const lines: string[] = [];
  const result = await runLocalFlow(
    { ...flowConfig(services.baseUrl), evidenceMode: "LOCAL_CONTROLLED" },
    { write: (line) => lines.push(line) },
  );
  expect(result).toBe(0);
  expect(lines.at(-1)).toBe("PASS LOCAL_CONTROLLED");
  expect(services.counters.trustedPresentations).toBe(2);
});

it.each([
  "rogue verifier",
  "resolver unavailable",
  "wrong Q1 DID",
  "production false",
  "wrong Q2 VTJSC",
  "wrong Q3 DID",
  "malformed JSON",
  "invalid UTF-8",
  "oversized resolver body",
  "oversized verifier body",
])("does not cross the broker for %s", async (scenario) => {
  const result = await runScenario(scenario);
  expect(result.brokerCalls).toBe(0);
  expect(result.presentationShared).toBe(false);
});
```

Also cover different second-flow subject, capability drift on any role, wrong VCT, holder claim override attempts, wrong claims, receipt DID mismatch, receipt VTJSC mismatch, receipt verdict mismatch, replay, timeout, and non-JSON media type. Preserve the existing state, nonce, PKCE, callback, CSRF, cookie, and logout tests in the full gate.

- [ ] **Step 2: Run focused tests and confirm they fail**

Run:

```bash
pnpm exec vitest run \
  tests/local-flow-verification.test.ts \
  tests/keycloak-verification.test.ts
```

Expected: FAIL because controlled evidence mode and repeat-presentation assertions are absent.

- [ ] **Step 3: Enforce controlled preflight and two real exchanges**

For `LOCAL_CONTROLLED`, set the issued `subjectId` to exact value `local-controlled-user`, require exact local resolver URL, issuer DID, verifier DID, VCT, VTJSC, all three distinct agent origins, and local loopback Keycloak/demo/broker origins. Keep `LIVE_VERANA` defaults unchanged.

Run the existing offer, acceptance, presentation, share, and receipt path twice. Compare the credential subject, issuer DID, verifier DID, and derived pairwise subject between the two passes. The real Keycloak account reuse is verified through Chrome in Task 6. Do not replay an uncertain share request.

- [ ] **Step 4: Measure Keycloak users around positive and denied paths**

Use the existing admin token helper and return only:

```ts
export interface KeycloakUserSummary {
  id: string;
  username: string;
  veranaSubject: string | null;
  groups: string[];
  roles: string[];
}
```

Never return credentials or tokens. The API verifier does not pretend to create
a Keycloak browser session. Assert:

- initial list length is `0`;
- two direct OpenID4VC presentations leave the count at `0`;
- rogue flow leaves the count at `0`;
- resolver-unavailable direct flow leaves the count at `0`.

Task 6 records the browser-driven transition from `0` to `1`, followed by
stable reuse at `1`.

- [ ] **Step 5: Emit only bounded proof labels**

Success output ends with:

```text
PASS LOCAL_CONTROLLED
```

Failure output remains `FAIL <SAFE_CODE>`. Intermediate lines may name components, DIDs, VCT, VTJSC, verdicts, and user counts, but must not include authorization requests, offers, credentials, presentations, receipts, tokens, cookies, or generated secrets.

- [ ] **Step 6: Run focused and full automated gates**

Run:

```bash
pnpm exec vitest run tests/local-flow-verification.test.ts tests/keycloak-verification.test.ts
pnpm check
```

Expected: all commands exit `0`, with the test count greater than the previous `172`.

- [ ] **Step 7: Commit the controlled verifier**

```bash
git add \
  scripts/verify-local-flow.ts \
  scripts/keycloak-verification.ts \
  tests/local-flow-verification.test.ts \
  tests/keycloak-verification.test.ts
git commit -m "test: verify controlled authentication end to end"
```

### Task 6: Run the real stack, deep-test Chrome, record bounded evidence, and restore local state

**Files:**
- Modify: `README.md`
- Create: `docs/evidence/local-controlled-run.md`

**Interfaces:**
- Consumes: all commands and components from Tasks 1 through 5.
- Produces: a sanitized evidence record separating automated, local-controlled API, real Chrome, teardown, and unproven external claims.
- Leaves both Git worktrees clean and does not push.

- [ ] **Step 1: Verify both worktrees and current commits before runtime mutation**

Run:

```bash
git status --short --branch
git -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  status --short --branch
git -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  merge-base --is-ancestor e2bba78 HEAD
```

Expected: both status commands are clean and the ancestry check exits `0`.

- [ ] **Step 2: Run both repositories' automated gates**

Run:

```bash
pnpm check
pnpm -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  --filter @verana-labs/vs-agent-plugin-openid4vc test
pnpm -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  --filter @verana-labs/vs-agent-plugin-openid4vc build
```

Expected: playground lint/typecheck/tests/build pass; VS Agent OpenID4VC tests remain at least `80/80`; plugin build exits `0`.

- [ ] **Step 3: Start the guarded local stack**

Run:

```bash
pnpm local:up
pnpm local:status
```

Expected: startup prints `LOCAL_CONTROLLED`, all loopback URLs, capability contracts for issuer/holder/verifier, and zero Keycloak users without printing secrets.

- [ ] **Step 4: Run the live API and adversarial matrix**

Run:

```bash
pnpm local:verify
```

Expected: the terminal line is exactly `PASS LOCAL_CONTROLLED`.

Then exercise, one at a time, rogue verifier, resolver unavailable during a fresh login, malformed resolver JSON, oversized resolver body, and oversized broker-to-verifier body using test-only resolver fault controls that bind to the existing loopback process and reset after each case. After each case, run the sanitized user-count command and confirm it remains `1`.

- [ ] **Step 5: Deep-test the real Chrome flow**

Using Maxime's existing Chrome profile:

1. Open `http://localhost:3000`.
2. Confirm the visible `LOCAL_CONTROLLED` boundary.
3. Start Keycloak login and choose `Verana Wallet`.
4. Create and accept the exact local employee credential.
5. Inspect VCT and requested claims, then approve the presentation.
6. Confirm profile values: non-empty `verana_subject`, `ACME`, and `employee`.
7. Log out locally.
8. Repeat the complete wallet interaction and confirm the same Keycloak account and pairwise subject.
9. Exercise the rogue flow and confirm denial with no new user/session.
10. Inspect console and relevant network requests for unexpected errors, third-party destinations, raw secrets, credentials, presentations, tokens, or receipts.

Capture only screenshots that show the proof label, non-sensitive profile mapping, denial state, and sanitized user count. Store them temporarily under `.data/evidence/`; do not commit the image files.

- [ ] **Step 6: Write the operator runbook and sanitized evidence**

`README.md` must include exact `local:up`, `local:status`, `local:verify`, and `local:down` commands, prerequisites, expected ports, proof boundary, failure recovery, and the statement that deployment requires explicit approval.

The runbook must also state that later Verana infrastructure migration changes
only the resolver URL, authorized issuer/verifier DIDs, HTTP-to-HTTPS endpoint
configuration, and secret/storage provider. Broker policy, pairwise-subject
derivation, Keycloak mappings, capability contract, and the verification
sequence remain unchanged.

`docs/evidence/local-controlled-run.md` must record:

- date, macOS, Node, Docker, Keycloak, and Git commit identifiers;
- exact test commands, exit codes, and aggregate test counts;
- `PASS LOCAL_CONTROLLED`;
- Chrome steps that were actually observed;
- positive user-count transition `0 -> 1 -> 1`;
- denied-path user count remaining `1`;
- teardown and Twitter restoration result;
- no raw protocol artifacts or secrets;
- explicit unproven claims: Verana testnet Q2/Q3, public HTTPS, physical wallets, external wallet interoperability, and production readiness.

- [ ] **Step 7: Teardown and verify exact restoration**

Run:

```bash
pnpm local:down
docker ps --format '{{.Names}}'
docker volume ls --format '{{.Name}}'
lsof -nP -iTCP:3000 -iTCP:3001 -iTCP:3099 -iTCP:3100 -iTCP:3101 \
  -iTCP:3110 -iTCP:3111 -iTCP:3200 -iTCP:3201 -sTCP:LISTEN
git status --short --branch
git -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  status --short --branch
```

Expected:

- no `verana-keycloak-local-controlled` container, network, or volume remains;
- no playground process owns the required ports;
- `twitter-bot-vs-agent` is running only if the state file recorded it as initially running;
- unrelated containers and volumes remain;
- disposable `.data` protocol state is gone;
- both worktrees are clean except for the intentional documentation changes awaiting the final evidence commit.

- [ ] **Step 8: Commit only sanitized documentation**

```bash
git add README.md docs/evidence/local-controlled-run.md
git commit -m "docs: record controlled authentication evidence"
```

- [ ] **Step 9: Run the final verification and independent whole-branch review**

Run:

```bash
pnpm check
git status --short --branch
git log --oneline c46ab80..HEAD
```

Dispatch the final reviewer with the complete `c46ab80..HEAD` diff, the approved design, this plan, the subagent ledger, and the evidence record. Acceptance requires:

- specification compliance approved;
- code quality approved;
- no Critical or Important finding;
- no unreviewed fix;
- no push, deployment, PR approval, or external comment;
- clean playground and VS Agent worktrees.
