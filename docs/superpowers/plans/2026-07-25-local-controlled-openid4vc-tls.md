# Local Controlled OpenID4VC TLS Implementation Plan

> **For Codex:** Use `superpowers:subagent-driven-development` to execute this
> plan task by task after Maxime explicitly approves the architecture change.

**Goal:** Complete the real local FIDES issuance and verification path by giving
the issuer, holder, verifier, and controlled Verana resolver valid HTTPS
origins, without weakening OpenID4VC validation or changing system trust.

**Architecture:** A loopback-only Node HTTPS reverse proxy listens on
`127.0.0.1:3443` and accepts four exact SNI/Host names:
`issuer.localhost`, `holder.localhost`, `verifier.localhost`, and
`resolver.localhost`. Each guarded stack run creates an ephemeral private CA and
one leaf certificate with those four SANs. The three VS Agent containers receive
only the CA certificate and trust it through `NODE_EXTRA_CA_CERTS`; the CA key
and server key remain host-only. The existing lifecycle owns, journals, verifies,
and removes all generated TLS material.

**Tech Stack:** Node.js 24 built-in `https`, `http`, `tls`, streams, and
filesystem APIs; OpenSSL 3 CLI through exact `execFile` arguments; Vitest;
Docker Compose. No new runtime or package dependency.

## Binding constraints

- Do not set Credo or OpenID4VC `allowInsecureHttpUrls`.
- Do not modify VS Agent source or its OpenID4VC plugin.
- Do not install a CA in the macOS, Chrome, Docker, or global Node trust stores.
- Do not add Caddy, nginx, Traefik, mkcert, or an npm proxy/certificate package.
- Bind the gateway only to `127.0.0.1:3443`.
- Use only the four fixed `.localhost` names and fixed loopback upstreams.
- Keep Chrome on `http://localhost:3000` and Keycloak on
  `http://localhost:8080`.
- Keep direct host orchestration URLs on loopback HTTP:
  `127.0.0.1:3101`, `127.0.0.1:3111`, `127.0.0.1:3201`, and
  `127.0.0.1:3099`.
- Keep DIDComm `AGENT_ENDPOINTS` unchanged unless a separate reviewed task
  proves DIDComm TLS is required.
- Never mount `ca-key.pem`, `server-key.pem`, or `server.pem` into a container.
  Mount only `ca.pem`, read-only.
- Never log request paths, queries, headers, bodies, credentials, presentations,
  receipts, tokens, cookies, certificate keys, or control tokens.
- Label all resulting evidence `LOCAL_CONTROLLED`. It is not public-PKI,
  browser-trust, testnet Q2/Q3, physical-wallet, external-interoperability, or
  production evidence.
- Do not push, deploy, approve a pull request, or post a GitHub comment.

## Public and internal URL contract

| Role | Public protocol URL | Fixed host upstream |
| --- | --- | --- |
| Issuer | `https://issuer.localhost:3443` | `http://127.0.0.1:3101` |
| Holder | `https://holder.localhost:3443` | `http://127.0.0.1:3111` |
| Verifier | `https://verifier.localhost:3443` | `http://127.0.0.1:3201` |
| Resolver | `https://resolver.localhost:3443` | `http://127.0.0.1:3099` |

The exact controlled metadata values become:

```text
VERANA_RESOLVER_URL=https://resolver.localhost:3443/v1/trust
UNFOLD_VCT=https://resolver.localhost:3443/vct/local-controlled-employee
UNFOLD_VTJSC_ID=https://resolver.localhost:3443/vtjsc/local-controlled-employee.json
```

## Task 1: Generate and verify an ephemeral TLS bundle

**Files:**

- Create: `tsconfig.scripts.json`
- Create: `scripts/local-tls-certificates.ts`
- Create: `tests/local-tls-certificates.test.ts`

### Step 1: Write the failing certificate tests

Define these public types and function:

```ts
export const LOCAL_TLS_HOSTNAMES = [
  "issuer.localhost",
  "holder.localhost",
  "verifier.localhost",
  "resolver.localhost",
] as const;

export interface CertificateCommandRunner {
  run(
    command: string,
    args: readonly string[],
    options: { cwd: string },
  ): Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

export interface SerializedFileIdentity {
  dev: string;
  ino: string;
}

export interface LocalTlsReservation {
  directory: string;
  identity: SerializedFileIdentity;
}

export interface LocalTlsBundle extends LocalTlsReservation {
  caCertificatePath: string;
  caPrivateKeyPath: string;
  serverCertificatePath: string;
  serverPrivateKeyPath: string;
  fileIdentities: {
    caCertificate: SerializedFileIdentity;
    serverCertificate: SerializedFileIdentity;
    serverPrivateKey: SerializedFileIdentity;
  };
}

export async function reserveLocalTlsBundle(options: {
  stagingParent: string;
}): Promise<LocalTlsReservation>;

export async function createLocalTlsBundle(options: {
  reservation: LocalTlsReservation;
  runner?: CertificateCommandRunner;
}): Promise<LocalTlsBundle>;
```

Tests must prove:

- reservation creates a new empty regular directory under the exact regular
  `stagingParent`, with mode `0700`, before any key material is written;
- population accepts only that identity-pinned empty reservation;
- every generated file is regular, non-symlinked, and mode `0600`;
- the CA is `CA:TRUE,pathlen:0` with only certificate-signing usages;
- the leaf is `CA:FALSE`, has `serverAuth`, and has exactly the four SANs;
- `openssl verify -purpose sslserver` succeeds;
- `openssl x509 -checkhost` succeeds for each allowed name and fails for
  `rogue.localhost`;
- the leaf is valid now but no longer than one day and its validity is wholly
  contained by the CA validity;
- command execution uses an injectable runner and never invokes a shell;
- any command failure removes only the identity-verified staging directory;
- a symlinked parent, pre-existing target name, changed file identity, or
  unexpected generated file fails closed.

Run:

```bash
pnpm exec vitest run tests/local-tls-certificates.test.ts
```

Expected: FAIL because `scripts/local-tls-certificates.ts` does not exist.

### Step 2: Implement exact OpenSSL generation

Create the root-script semantic typecheck project:

```json
{
  "extends": "./tsconfig.base.json",
  "compilerOptions": {
    "noEmit": true
  },
  "include": ["scripts/**/*.ts"]
}
```

`reserveLocalTlsBundle` uses `mkdtemp` below `stagingParent` and returns the
empty directory's device/inode identity. `createLocalTlsBundle` rechecks that
same empty directory before using `open`/`lstat` identity checks and `execFile`
without `shell`. Create:

```text
ca-key.pem
ca.pem
server-key.pem
server.csr
server-ext.cnf
server.pem
ca.srl
```

`server-ext.cnf` must contain only:

```ini
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:issuer.localhost,DNS:holder.localhost,DNS:verifier.localhost,DNS:resolver.localhost
```

Run OpenSSL with exact argument arrays equivalent to:

```text
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 2
  -subj /CN=Verana LOCAL_CONTROLLED Ephemeral CA
  -addext basicConstraints=critical,CA:TRUE,pathlen:0
  -addext keyUsage=critical,keyCertSign,cRLSign
  -keyout ca-key.pem -out ca.pem

openssl req -new -newkey rsa:3072 -sha256 -nodes
  -subj /CN=issuer.localhost
  -keyout server-key.pem -out server.csr

openssl x509 -req -sha256 -days 1 -in server.csr
  -CA ca.pem -CAkey ca-key.pem -CAcreateserial
  -extfile server-ext.cnf -out server.pem
```

The CA lasts at most two days solely so the one-day leaf created moments later
is contained by its validity. Both are removed with the same guarded run.

Then run the chain, purpose, expiry, validity-containment, and all hostname
checks before returning. Do not return certificate or key contents. On an
ordinary failure, quarantine and remove only a directory whose device/inode
identity still matches the reservation. A hard exit is handled by the
lifecycle journal in Task 3.

### Step 3: Run focused and static checks

```bash
pnpm exec vitest run tests/local-tls-certificates.test.ts
pnpm exec tsc -p tsconfig.scripts.json
pnpm exec biome check scripts/local-tls-certificates.ts tests/local-tls-certificates.test.ts
```

Expected: all pass.

### Step 4: Commit the certificate slice

```bash
git add \
  tsconfig.scripts.json \
  scripts/local-tls-certificates.ts \
  tests/local-tls-certificates.test.ts
git commit -m "feat: generate controlled local TLS certificates"
```

## Task 2: Add the fixed loopback HTTPS gateway

This task is independent of Task 1 and may run in parallel with it.

**Files:**

- Create: `scripts/local-tls-proxy.ts`
- Create: `tests/local-tls-proxy.test.ts`

### Step 1: Write the failing gateway tests

Define:

```ts
export const LOCAL_TLS_ROUTES = Object.freeze({
  "issuer.localhost": 3101,
  "holder.localhost": 3111,
  "verifier.localhost": 3201,
  "resolver.localhost": 3099,
});

export interface LocalTlsProxyOptions {
  certificate: Buffer;
  privateKey: Buffer;
  requestTimeoutMs?: number;
  maximumBodyBytes?: number;
}

export function createLocalTlsProxy(
  options: LocalTlsProxyOptions,
): import("node:https").Server;
```

Tests use generated test certificates and real loopback HTTP upstreams to
prove:

- TLS minimum version is 1.2;
- exact matching SNI plus Host routes to only the expected fixed port;
- Host may be only the exact hostname or exact hostname with port `3443`;
- absent, duplicate, malformed, non-allowlisted, or mismatched Host/SNI returns
  `421` without reaching an upstream;
- `CONNECT`, `TRACE`, and upgrade attempts return `405` or close the socket;
- request and response headers strip the standard hop-by-hop set and every
  header nominated by `Connection`;
- forwarding preserves method and path but never constructs an upstream from
  caller input;
- request and response streams enforce an `8 MiB` bound; an oversized request
  returns `413`, an oversized declared upstream response returns `502` before
  forwarding headers, and an undeclared streaming overflow aborts both sides
  because an HTTP status can no longer be changed safely;
- upstream connection, response, and idle timeouts are bounded to `15 s`;
- upstream refusal returns sanitized `502`, not an exception, stack trace,
  destination, request data, or protocol artifact;
- server shutdown closes idle connections immediately, allows at most `5 s`
  for active requests, and then force-closes every tracked socket.

Run:

```bash
pnpm exec vitest run tests/local-tls-proxy.test.ts
```

Expected: FAIL because `scripts/local-tls-proxy.ts` does not exist.

### Step 2: Implement the gateway with Node core

Use `https.createServer`, `http.request`, `Transform`, and a fixed route table.
Set `minVersion: "TLSv1.2"`, `maxHeaderSize: 16 * 1024`,
`headersTimeout: 15_000`, `requestTimeout: 15_000`, and
`keepAliveTimeout: 5_000`.

The default `maximumBodyBytes` is `8 * 1024 * 1024`. Count streamed bytes in
both directions; abort both sockets on overflow. Never buffer a complete
credential or presentation.

The sanitized error body is exactly:

```json
{"error":"local_controlled_gateway_failure"}
```

The gateway may log only one of these bounded event labels:

```text
LOCAL_CONTROLLED TLS_GATEWAY_READY
LOCAL_CONTROLLED TLS_GATEWAY_REJECTED
LOCAL_CONTROLLED TLS_GATEWAY_UPSTREAM_FAILED
```

It must not log hostnames, paths, queries, headers, bodies, IP addresses, or
TLS material.

Track accepted sockets in a private `Set`, remove them on `close`, reject all
upgrade events, and expose a bounded close method. Shutdown first stops new
connections, calls `closeIdleConnections()`, then after `5 s` destroys any
remaining tracked socket and calls `closeAllConnections()`. The returned
shutdown promise must always settle within the bound.

### Step 3: Run focused and static checks

```bash
pnpm exec vitest run tests/local-tls-proxy.test.ts
pnpm exec tsc -p tsconfig.scripts.json
pnpm exec biome check scripts/local-tls-proxy.ts tests/local-tls-proxy.test.ts
```

Expected: all pass.

### Step 4: Commit the gateway slice

```bash
git add scripts/local-tls-proxy.ts tests/local-tls-proxy.test.ts
git commit -m "feat: proxy controlled OpenID4VC over TLS"
```

## Task 3: Integrate TLS into the guarded lifecycle

Run this task only after Tasks 1 and 2 are reviewed and committed.

**Files:**

- Modify: `scripts/local-controlled-config.ts`
- Modify: `scripts/setup-local-controlled.ts`
- Modify: `compose.local-controlled.yaml`
- Modify: `scripts/local-stack-process.ts`
- Modify: `scripts/local-stack.ts`
- Modify: `tests/setup-local-controlled.test.ts`
- Modify: `tests/local-stack-process.test.ts`
- Modify: `tests/local-stack.test.ts`

### Step 1: Write failing configuration and process tests

Change `LOCAL_CONTROLLED` to expose:

```ts
tlsPort: 3443,
issuerUrl: "https://issuer.localhost:3443",
holderUrl: "https://holder.localhost:3443",
verifierUrl: "https://verifier.localhost:3443",
resolverUrl: "https://resolver.localhost:3443/v1/trust",
vct: "https://resolver.localhost:3443/vct/local-controlled-employee",
vtjscId:
  "https://resolver.localhost:3443/vtjsc/local-controlled-employee.json",
ports: [3000, 3001, 3099, 3100, 3101, 3110, 3111, 3200, 3201, 3443],
```

Keep `.env` host calls on direct loopback HTTP. Set Compose environment to:

```text
issuer PUBLIC_API_BASE_URL=https://issuer.localhost:3443
holder PUBLIC_API_BASE_URL=https://holder.localhost:3443
verifier PUBLIC_API_BASE_URL=https://verifier.localhost:3443
VERANA_RESOLVER_URL=https://resolver.localhost:3443/v1/trust
UNFOLD_VCT=https://resolver.localhost:3443/vct/local-controlled-employee
UNFOLD_VTJSC_ID=https://resolver.localhost:3443/vtjsc/local-controlled-employee.json
NODE_EXTRA_CA_CERTS=/run/verana-local-ca/ca.pem
```

Each role gets explicit `extra_hosts` entries for all four names mapped to
`host-gateway` and this single mount:

```yaml
- ./.data/tls/ca.pem:/run/verana-local-ca/ca.pem:ro
```

Tests must reject any private-key mount, broad directory mount, non-read-only
CA mount, insecure URL, missing hostname mapping, or public port binding.

Update `HostProcessDependencies` with:

```ts
createTlsProxy: (options: LocalTlsProxyOptions) => {
  listen(port: number, host: string): HostServer;
};
readVerifiedTlsFile: (
  path: string,
  expectedIdentity: SerializedFileIdentity,
) => Promise<Buffer>;
```

The host process must validate that
`LOCAL_TLS_CERTIFICATE_PATH` and `LOCAL_TLS_PRIVATE_KEY_PATH` are absolute,
regular children of the exact identity-pinned `.data/tls` directory. It opens
each with `O_RDONLY | O_NOFOLLOW`, compares `fstat` to the persisted expected
device/inode identity, reads from that same descriptor, repeats `fstat`, and
closes the descriptor. It must never validate by pathname and then reopen the
path separately.

Extend `HostServer` with bounded shutdown support. `closeServers` must stop
accepting connections, close idle connections, allow at most `5 s` for active
requests, then call `closeAllConnections` or destroy tracked sockets. A stuck
client must not prevent host-process exit, Compose cleanup, TLS removal, or
Twitter restoration. Startup and reverse shutdown order becomes:

```text
resolver -> TLS gateway -> broker -> demo
demo -> broker -> TLS gateway -> resolver
```

Run:

```bash
pnpm exec vitest run \
  tests/setup-local-controlled.test.ts \
  tests/local-stack-process.test.ts \
  tests/local-stack.test.ts
```

Expected: FAIL on the new TLS expectations.

### Step 2: Journal TLS ownership before Compose mutation

Bump `LocalStackState.version` from `1` to `2`. Add:

```ts
interface SerializedIdentity {
  dev: string;
  ino: string;
}

interface OwnedTlsState {
  identity: SerializedIdentity;
  stagingName: string;
  phase: "reserved" | "published";
  fileIdentities?: {
    caCertificate: SerializedIdentity;
    serverCertificate: SerializedIdentity;
    serverPrivateKey: SerializedIdentity;
  };
}

ownedLifecycleDirectory?: SerializedIdentity;
ownedTls?: OwnedTlsState;
```

Generation sequence:

1. Publish the existing four generated data files.
2. Create and identity-pin `.data/local-stack`, then persist its serialized
   identity in `ownedLifecycleDirectory` before creating a child entry.
3. Call `reserveLocalTlsBundle` to create an empty staging directory.
4. Before writing any key material, write state with `phase: "reserved"`, its
   exact relative staging name, and its directory identity.
5. Populate only that journaled reservation with `createLocalTlsBundle`.
6. Persist the three returned CA/certificate/key file identities while the
   phase remains `reserved`.
7. Refuse an existing or symlinked `.data/tls`.
8. Atomically rename the identity-matching bundle directory to `.data/tls`.
9. Write state with `phase: "published"`.
10. Immediately before Compose, open `.data/tls/ca.pem` with
    `O_RDONLY | O_NOFOLLOW`, compare its `fstat` to the persisted CA identity,
    and close the same descriptor. Refuse a changed bind source.
11. Inject absolute certificate and private-key paths plus their expected
    identities into the host process environment; forbid all of those names in
    generated environment files.
12. Continue with the existing guarded Twitter, Compose, user-count, and host
    process sequence.

Teardown must handle every crash point between steps 3 and 9:

- if `.data/tls` has the journaled identity, quarantine and remove it;
- otherwise, if the recorded staging path has that identity, quarantine and
  remove it;
- if both exist, either is a symlink, or an identity differs, fail closed and
  preserve the unexpected entry;
- remove the lifecycle directory only after TLS cleanup succeeds.

Tests inject hard-exit-equivalent failures immediately after lifecycle identity
persistence, reservation, journal write, each OpenSSL command, file-identity
persistence, rename, and publication-state write. Every subsequent `down`
removes only the identity-matching lifecycle/reservation/published directory
and never an unexpected replacement.

Never recursively remove `.data`, an unverified directory, or a directory not
recorded in the state journal.

### Step 3: Add readiness and status evidence

Preflight and teardown include port `3443`.

After the host process starts, perform HTTPS readiness using the generated CA
and the hostname `resolver.localhost`, not disabled verification. Confirm:

```text
https://resolver.localhost:3443/health
https://issuer.localhost:3443/oid4vc-demo/capabilities
https://holder.localhost:3443/oid4vc-demo/capabilities
https://verifier.localhost:3443/oid4vc-demo/capabilities
```

Use a bounded Node HTTPS client with `ca`, `servername`, and a resolver that
maps only the four allowed names to `127.0.0.1`. Do not use
`NODE_TLS_REJECT_UNAUTHORIZED=0`, `rejectUnauthorized:false`, curl `-k`, or a
Chrome certificate bypass.

Lifecycle tests also hold an active gateway request open during `down` and
prove bounded forced shutdown, Compose cleanup, exact TLS cleanup, and Twitter
restoration.

Startup adds:

```text
LOCAL_CONTROLLED https://issuer.localhost:3443
LOCAL_CONTROLLED https://holder.localhost:3443
LOCAL_CONTROLLED https://verifier.localhost:3443
LOCAL_CONTROLLED https://resolver.localhost:3443
```

Status prints only:

```text
LOCAL_CONTROLLED TLS gateway active
LOCAL_CONTROLLED TLS certificate valid
```

It must not print certificate subjects, serials, fingerprints, paths, or
contents.

### Step 4: Run lifecycle tests and full gates

```bash
pnpm exec vitest run \
  tests/local-tls-certificates.test.ts \
  tests/local-tls-proxy.test.ts \
  tests/setup-local-controlled.test.ts \
  tests/local-stack-process.test.ts \
  tests/local-stack.test.ts
pnpm exec tsc -p tsconfig.scripts.json
pnpm check
```

Expected: all pass, with the full test count no lower than the current `412`.

### Step 5: Commit the integration

```bash
git add \
  compose.local-controlled.yaml \
  scripts/local-controlled-config.ts \
  scripts/setup-local-controlled.ts \
  scripts/local-stack-process.ts \
  scripts/local-stack.ts \
  tests/setup-local-controlled.test.ts \
  tests/local-stack-process.test.ts \
  tests/local-stack.test.ts
git commit -m "feat: secure controlled OpenID4VC endpoints"
```

## Task 4: Independent correctness and security review

Use separate review agents after implementation:

1. Certificate/lifecycle reviewer: filesystem identity, crash recovery,
   certificate constraints, key exposure, cleanup scope.
2. Gateway reviewer: SNI/Host routing, request smuggling, hop-by-hop headers,
   streaming bounds, timeouts, error disclosure, connection shutdown.
3. Integration reviewer: Compose mounts/hosts, public versus internal URLs,
   OpenID4VC semantics, evidence labels, and regression risk.

No live stack run may begin with an unresolved Critical or Important finding.
Apply accepted fixes with focused red-green tests, rerun `pnpm check`, and
commit each cohesive fix separately.

## Task 5: Deep local proof in real conditions

### Step 1: Verify clean, exact source state

```bash
git status --short --branch
git -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  status --short --branch
git -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  merge-base --is-ancestor e2bba78 HEAD
```

Expected: both worktrees clean and the ancestry check exits `0`.

### Step 2: Run repository gates

```bash
pnpm exec tsc -p tsconfig.scripts.json
pnpm check
pnpm -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  --filter @verana-labs/vs-agent-plugin-openid4vc test
pnpm -C /Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim \
  --filter @verana-labs/vs-agent-plugin-openid4vc build
```

Expected: all pass; VS Agent OpenID4VC remains at least `80/80`.

### Step 3: Start and inspect the disposable stack

```bash
pnpm local:up
pnpm local:status
pnpm local:users --expect-count=0
```

Expected: lifecycle, TLS gateway, certificate, resolver, three VS Agent roles,
Keycloak, broker, and demo are ready; Keycloak has zero users.

### Step 4: Run the real API flow and adversarial matrix

```bash
pnpm local:verify
pnpm local:adversarial
```

Required terminal verdict:

```text
PASS LOCAL_CONTROLLED
```

Capture only bounded stage labels and sanitized user/account hashes. Do not
capture credential, presentation, receipt, token, cookie, or key material.

### Step 5: Run the real Chrome flow

Use Maxime's existing Chrome profile at `http://localhost:3000`:

1. Confirm the visible `LOCAL_CONTROLLED` boundary.
2. Start Keycloak login and choose `Verana Wallet`.
3. Complete issuance, holder acceptance, and verifier presentation.
4. Confirm mapped `verana_subject`, organization `ACME`, and role `employee`.
5. Log out and repeat; confirm one Keycloak account and stable pairwise subject.
6. Run the browser-reachable rogue verifier denial; confirm no new account.
7. Inspect console and relevant network requests for unexpected failures or
   third-party destinations.

Do not navigate Chrome directly to `*.localhost:3443`: the per-run CA is
intentionally not installed in Chrome, so a warning would be expected and
would not be browser-trust evidence. Do not bypass that warning.

### Step 6: Reconcile with current Verana specs

Refresh `verana-labs/verana-spec`, the relevant open pull requests, review
threads, and checks read-only. Record:

- which local calls exercise the legacy controlled resolver adapter;
- which calls match current normative v4;
- unresolved ECS-Badge/testnet authorization dependencies;
- exact integration work still required for FIDES clients and external wallets.

Do not post, approve, merge, push, or deploy.

### Step 7: Record evidence and tear down

Update `docs/evidence/local-controlled-run.md` and `README.md` only with
observed results. Then run:

```bash
pnpm local:down
docker ps --format '{{.Names}}'
docker volume ls --format '{{.Name}}'
lsof -nP \
  -iTCP:3000 -iTCP:3001 -iTCP:3099 -iTCP:3100 -iTCP:3101 \
  -iTCP:3110 -iTCP:3111 -iTCP:3200 -iTCP:3201 -iTCP:3443 \
  -sTCP:LISTEN
find .data -mindepth 1 -maxdepth 2 -print
git status --short --branch
```

Expected:

- no controlled container, network, volume, host process, listener, TLS file,
  lifecycle state, or evidence image remains;
- Twitter is restored only if the lifecycle recorded that it stopped it;
- unrelated Docker resources are unchanged;
- both worktrees contain only the reviewed evidence/runbook update before the
  final evidence commit;
- nothing has been pushed or deployed.

Add the observed teardown result, run `git diff --check`, review the sanitized
diff, and commit:

```bash
git add README.md docs/evidence/local-controlled-run.md
git commit -m "docs: record controlled TLS validation"
git status --short --branch
```

Expected: both worktrees are clean. Nothing is pushed or deployed.
