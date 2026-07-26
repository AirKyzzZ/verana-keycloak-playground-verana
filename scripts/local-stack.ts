import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
} from "node:fs/promises";
import { connect } from "node:net";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sanitizeKeycloakStatus } from "./keycloak-status.js";
import { readKeycloakUserStatus } from "./keycloak-verification.js";
import { LOCAL_CONTROLLED } from "./local-controlled-config.js";
import {
  createLocalTlsBundle,
  type LocalTlsBundle,
  type LocalTlsReservation,
  reserveLocalTlsBundle,
  type SerializedFileIdentity,
} from "./local-tls-certificates.js";
import { LOCAL_TLS_GATEWAY_PORT } from "./local-tls-proxy.js";
import {
  createLocalControlledData,
  type LocalControlledDataFiles,
} from "./setup-local-controlled.js";
import { readResolverFaultStatus } from "./verify-local-adversaries.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDirectoryName = ".data";
const stateFileName = "local-stack-state.json";
const lifecycleDirectoryName = "local-stack";
const tlsDirectoryName = "tls";
const tlsCaCertificateName = "ca.pem";
const tlsServerCertificateName = "server.pem";
const tlsServerPrivateKeyName = "server-key.pem";
const hostTlsEnvironmentNames = [
  "LOCAL_TLS_CERTIFICATE_PATH",
  "LOCAL_TLS_PRIVATE_KEY_PATH",
  "LOCAL_TLS_CERTIFICATE_IDENTITY",
  "LOCAL_TLS_PRIVATE_KEY_IDENTITY",
] as const;
const generatedDataFiles = [
  ".env",
  "local-controlled.env",
  "broker-jwks.json",
  "realm.json",
] as const;
const minimumFreeBytes = 8 * 1024 * 1024 * 1024;
const requiredPorts = [...LOCAL_CONTROLLED.ports];
const expectedVsAgentRepository = "https://github.com/verana-labs/vs-agent";

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

interface HostProcess {
  pid: number;
  startToken: string;
}

interface FileSystemIdentity {
  dev: number | bigint;
  ino: number | bigint;
}

interface TemporaryFile {
  path: string;
  identity: FileSystemIdentity;
}

interface OwnedTlsState {
  identity: SerializedFileIdentity;
  stagingName: string;
  phase: "reserved" | "published";
  fileIdentities?: LocalTlsBundle["fileIdentities"];
}

interface LocalStackState {
  version: 2;
  composeProject: typeof LOCAL_CONTROLLED.composeProject;
  twitterWasRunning: boolean;
  twitterStopped: boolean;
  composeTouched: boolean;
  hostProcess?: HostProcess;
  ownedDataFiles: readonly (typeof generatedDataFiles)[number][];
  ownedLifecycleDirectory?: SerializedFileIdentity;
  ownedTls?: OwnedTlsState;
  vsSourceCommit: string;
  startedAt: string;
}

interface PreflightResult {
  twitterWasRunning: boolean;
  vsSourceCommit: string;
}

export interface LocalStackStatus {
  active: boolean;
  portsClear: boolean;
  twitterWasRunning?: boolean;
}

export interface LifecycleDependencies {
  root?: string;
  dataDirectory?: string;
  vsSourcePath?: string;
  nodeVersion?: string;
  runner?: CommandRunner;
  generateData?: (vsSourcePath: string) => Promise<LocalControlledDataFiles>;
  reserveTls?: (options: {
    stagingParent: string;
  }) => Promise<LocalTlsReservation>;
  createTls?: (options: {
    reservation: LocalTlsReservation;
  }) => Promise<LocalTlsBundle>;
  waitForGateway?: () => Promise<void>;
  afterTempFileOpen?: (opened: {
    path: string;
    label: string;
  }) => Promise<void>;
  afterTempFileRename?: (renamed: {
    path: string;
    label: string;
  }) => Promise<void>;
  launch?: (options: {
    root: string;
    environment: NodeJS.ProcessEnv;
    startToken: string;
  }) => Promise<HostProcess>;
  signalProcessGroup?: (pid: number) => void;
  isProcessRunning?: (pid: number) => Promise<boolean>;
  sleep?: (milliseconds: number) => Promise<void>;
  fetch?: typeof fetch;
  randomToken?: () => string;
  now?: () => Date;
  rename?: (source: string, destination: string) => Promise<void>;
  write?: (line: string) => void;
}

const composeBaseArgs = [
  "compose",
  "--project-name",
  LOCAL_CONTROLLED.composeProject,
  "--env-file",
  ".data/local-controlled.env",
  "-f",
  "compose.yaml",
  "-f",
  "compose.local-controlled.yaml",
] as const;

export async function preflight(
  dependencies: LifecycleDependencies = {},
): Promise<PreflightResult> {
  const context = createContext(dependencies);
  await assertSafePaths(context.root, context.dataDirectory);
  assertNodeVersion(context.nodeVersion);

  await requireSuccess(context.runner, "docker", ["version"]);
  await requireSuccess(context.runner, "docker", ["compose", "version"], {
    cwd: context.root,
  });
  await assertGitWorktree(context.runner, context.root, "playground worktree");
  await assertGitWorktree(
    context.runner,
    context.vsSourcePath,
    "VS Agent source",
  );
  await assertVsAgentRepository(context.runner, context.vsSourcePath);
  await requireSuccess(context.runner, "git", [
    "-C",
    context.vsSourcePath,
    "merge-base",
    "--is-ancestor",
    LOCAL_CONTROLLED.requiredVsCommit,
    "HEAD",
  ]);
  const vsSourceCommit = await readGitHead(
    context.runner,
    context.vsSourcePath,
  );
  await assertCapacity(context);
  const twitterWasRunning = await readTwitterState(context.runner);
  await assertPortsAvailable(context.runner, false);
  await assertNoAmbiguousComposeState(context);

  return { twitterWasRunning, vsSourceCommit };
}

export async function up(
  dependencies: LifecycleDependencies = {},
): Promise<void> {
  const context = createContext(dependencies);
  const checked = await preflight(dependencies);
  const initialState: LocalStackState = {
    version: 2,
    composeProject: LOCAL_CONTROLLED.composeProject,
    twitterWasRunning: checked.twitterWasRunning,
    twitterStopped: false,
    composeTouched: false,
    vsSourceCommit: checked.vsSourceCommit,
    startedAt: context.now().toISOString(),
    ownedDataFiles: [],
  };
  let stateWritten = false;
  let currentState = initialState;

  try {
    await writeState(context, initialState);
    stateWritten = true;
    currentState = await generateAndPublishData(context, currentState);

    if (checked.twitterWasRunning) {
      await requireSuccess(context.runner, "docker", [
        "stop",
        LOCAL_CONTROLLED.twitterContainer,
      ]);
      currentState = { ...currentState, twitterStopped: true };
      await writeState(context, currentState);
    }

    currentState = await establishTlsMaterial(context, currentState);
    await assertPublishedCaCertificate(context, currentState);

    // Startup is three ordered stages because the dependencies run both ways.
    // Keycloak first: the demo app performs OIDC discovery against it while it
    // starts. Then the host process, which owns the controlled resolver and the
    // TLS gateway. Then the agents, which resolve their did:web, VCT and VTJSC
    // documents through that gateway as they start, and would otherwise die
    // with ECONNREFUSED.
    const composeState = { ...currentState, composeTouched: true };
    await writeState(context, composeState);
    currentState = composeState;
    await runCompose(context, ["build", "issuer"]);
    await runCompose(context, [
      "up",
      "--wait",
      "--wait-timeout",
      "180",
      "--force-recreate",
      "keycloak",
    ]);
    await waitForKeycloak(context.fetch);

    const startToken = context.randomToken();
    const environment = await loadSanitizedEnvironment(
      context,
      currentState,
      startToken,
    );
    await ensureLifecycleDirectory(context);
    const hostProcess = await context.launch({
      root: context.root,
      environment,
      startToken,
    });
    currentState = { ...currentState, hostProcess };
    await writeState(context, currentState);
    await waitForHostServices(context.fetch, context.waitForGateway);

    await runCompose(context, [
      "up",
      "--wait",
      "--wait-timeout",
      "180",
      "--force-recreate",
      "issuer",
      "holder",
      "verifier",
    ]);
    await waitForAgentServices(context.fetch);
    await assertZeroKeycloakUsers(context.fetch);
    context.write(
      "LOCAL_CONTROLLED stack active; browser authentication not verified",
    );
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3000");
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3001");
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3099/health");
  } catch (error) {
    if (stateWritten) {
      await cleanupAfterFailedStartup(context, currentState);
    } else {
      try {
        await removeTemporaryFiles(context);
      } catch (cleanupError) {
        context.write(
          `LOCAL_CONTROLLED cleanup incomplete: ${asError(cleanupError).message}`,
        );
      }
    }
    throw error;
  }
}

export async function status(
  dependencies: LifecycleDependencies = {},
): Promise<LocalStackStatus> {
  const context = createContext(dependencies);
  const currentState = await readState(context);
  const portsClear = await portsAreClear(context.runner);
  context.write(
    currentState
      ? "LOCAL_CONTROLLED lifecycle active"
      : "LOCAL_CONTROLLED lifecycle inactive",
  );
  context.write(
    portsClear
      ? "LOCAL_CONTROLLED ports clear"
      : "LOCAL_CONTROLLED ports occupied",
  );
  if (currentState) {
    context.write(
      currentState.ownedTls?.phase === "published"
        ? "LOCAL_CONTROLLED TLS material published"
        : "LOCAL_CONTROLLED TLS material incomplete",
    );
    const keycloakStatus = await readKeycloakUserStatus({
      fetch: context.fetch,
    });
    const sanitized = sanitizeKeycloakStatus(
      { expectedCount: keycloakStatus.count },
      keycloakStatus,
    );
    for (const line of sanitized.lines) context.write(line);

    const controlToken = await readResolverControlToken(context.dataDirectory);
    const faultStatus = await readResolverFaultStatus(
      controlToken,
      context.fetch,
    );
    context.write(
      faultStatus.armed
        ? `LOCAL_CONTROLLED resolver fault armed ${faultStatus.mode ?? "unknown"}`
        : "LOCAL_CONTROLLED resolver fault unarmed",
    );
  }
  return {
    active: currentState !== undefined,
    portsClear,
    ...(currentState
      ? { twitterWasRunning: currentState.twitterWasRunning }
      : {}),
  };
}

async function readResolverControlToken(
  dataDirectory: string,
): Promise<string> {
  const environment = parseEnvironment(
    await readFile(join(dataDirectory, ".env"), "utf8"),
  );
  const token = environment.LOCAL_RESOLVER_CONTROL_TOKEN;
  if (typeof token !== "string" || token.length < 43) {
    throw new Error(
      "LOCAL_CONTROLLED resolver control configuration is invalid",
    );
  }
  return token;
}

export async function down(
  dependencies: LifecycleDependencies = {},
): Promise<void> {
  const context = createContext(dependencies);
  const currentState = await readState(context);
  if (!currentState) {
    context.write("LOCAL_CONTROLLED no stack state found");
    return;
  }

  const errors = await teardown(context, currentState);
  if (errors.length > 0) {
    throw new Error(errors.map((error) => error.message).join("; "));
  }
  if (!(await portsAreClear(context.runner, currentState.twitterWasRunning))) {
    throw new Error("LOCAL_CONTROLLED required ports remain occupied");
  }
  context.write(
    currentState.twitterWasRunning
      ? "LOCAL_CONTROLLED ports released to Twitter"
      : "LOCAL_CONTROLLED ports clear",
  );
}

function createContext(dependencies: LifecycleDependencies) {
  const projectRoot = resolve(dependencies.root ?? root);
  const dataDirectory = resolve(
    dependencies.dataDirectory ?? join(projectRoot, dataDirectoryName),
  );
  const vsSourcePath = resolve(
    dependencies.vsSourcePath ??
      "/Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim",
  );
  return {
    root: projectRoot,
    dataDirectory,
    dataDirectoryIdentity: undefined as FileSystemIdentity | undefined,
    lifecycleDirectory: join(dataDirectory, lifecycleDirectoryName),
    lifecycleDirectoryIdentity: undefined as FileSystemIdentity | undefined,
    tlsDirectory: join(dataDirectory, tlsDirectoryName),
    temporaryFileIdentities: new Map<string, FileSystemIdentity>(),
    publishedDataFiles: new Map<
      (typeof generatedDataFiles)[number],
      FileSystemIdentity
    >(),
    vsSourcePath,
    nodeVersion: dependencies.nodeVersion ?? process.version,
    runner: dependencies.runner ?? systemRunner,
    generateData: dependencies.generateData ?? createLocalControlledData,
    reserveTls: dependencies.reserveTls ?? reserveLocalTlsBundle,
    waitForGateway: dependencies.waitForGateway ?? waitForTlsGateway,
    createTls: dependencies.createTls ?? createLocalTlsBundle,
    afterTempFileOpen:
      dependencies.afterTempFileOpen ?? (async () => undefined),
    afterTempFileRename:
      dependencies.afterTempFileRename ?? (async () => undefined),
    launch: dependencies.launch ?? launchHostProcess,
    signalProcessGroup:
      dependencies.signalProcessGroup ?? defaultSignalProcessGroup,
    isProcessRunning: dependencies.isProcessRunning ?? defaultIsProcessRunning,
    sleep: dependencies.sleep ?? defaultSleep,
    fetch: dependencies.fetch ?? fetch,
    randomToken:
      dependencies.randomToken ?? (() => randomBytes(32).toString("hex")),
    now: dependencies.now ?? (() => new Date()),
    rename: dependencies.rename ?? rename,
    write: dependencies.write ?? console.log,
  };
}

async function assertSafePaths(
  projectRoot: string,
  dataDirectory: string,
): Promise<void> {
  const rootStats = await lstat(projectRoot);
  if (rootStats.isSymbolicLink()) {
    throw new Error("LOCAL_CONTROLLED repository path must not be a symlink");
  }
  if (resolve(dataDirectory) !== join(projectRoot, dataDirectoryName)) {
    throw new Error("LOCAL_CONTROLLED data path is outside the repository");
  }
  try {
    if ((await lstat(dataDirectory)).isSymbolicLink()) {
      throw new Error("LOCAL_CONTROLLED .data must not be a symlink");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function assertDestructivePaths(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await assertSafePaths(context.root, context.dataDirectory);
  const [realRoot, realData] = await Promise.all([
    realpath(context.root),
    realpath(context.dataDirectory),
  ]);
  if (realData !== join(realRoot, dataDirectoryName)) {
    throw new Error(
      "LOCAL_CONTROLLED data path changed outside the repository",
    );
  }
  const dataDetails = await lstat(context.dataDirectory);
  if (!dataDetails.isDirectory() || dataDetails.isSymbolicLink()) {
    throw new Error("LOCAL_CONTROLLED .data must be a regular directory");
  }
  const dataIdentity = { dev: dataDetails.dev, ino: dataDetails.ino };
  if (
    context.dataDirectoryIdentity &&
    !sameFileSystemIdentity(context.dataDirectoryIdentity, dataIdentity)
  ) {
    throw new Error("LOCAL_CONTROLLED .data directory identity changed");
  }
  context.dataDirectoryIdentity ??= dataIdentity;
}

function statePath(context: ReturnType<typeof createContext>): string {
  return join(context.dataDirectory, stateFileName);
}

function ownedDataPath(
  context: ReturnType<typeof createContext>,
  file: (typeof generatedDataFiles)[number],
): string {
  const path = join(context.dataDirectory, file);
  if (dirname(path) !== context.dataDirectory) {
    throw new Error("LOCAL_CONTROLLED invalid owned data path");
  }
  return path;
}

function assertNodeVersion(nodeVersion: string): void {
  const match = /^v?(\d+)\./.exec(nodeVersion);
  if (!match || Number(match[1]) < 24) {
    throw new Error("LOCAL_CONTROLLED requires Node.js 24 or newer");
  }
}

async function assertGitWorktree(
  runner: CommandRunner,
  path: string,
  label: string,
): Promise<void> {
  const result = await requireSuccess(runner, "git", [
    "-C",
    path,
    "rev-parse",
    "--show-toplevel",
  ]);
  if (resolve(result.stdout.trim()) !== resolve(path)) {
    throw new Error(
      `LOCAL_CONTROLLED ${label} is not the expected Git repository`,
    );
  }
}

async function readGitHead(
  runner: CommandRunner,
  path: string,
): Promise<string> {
  const result = await requireSuccess(runner, "git", [
    "-C",
    path,
    "rev-parse",
    "HEAD",
  ]);
  const commit = result.stdout.trim();
  if (!/^[0-9a-f]{7,64}$/i.test(commit)) {
    throw new Error("LOCAL_CONTROLLED VS Agent source has no valid Git commit");
  }
  return commit;
}

async function assertVsAgentRepository(
  runner: CommandRunner,
  path: string,
): Promise<void> {
  const result = await requireSuccess(runner, "git", [
    "-C",
    path,
    "remote",
    "get-url",
    "origin",
  ]);
  const remote = result.stdout
    .trim()
    .replace(/^git@github\.com:/, "https://github.com/")
    .replace(/\.git$/, "");
  if (remote !== expectedVsAgentRepository) {
    throw new Error(
      "LOCAL_CONTROLLED VS Agent source is not the expected Git repository",
    );
  }
}

async function assertCapacity(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  const driverStatus = await requireSuccess(
    context.runner,
    "docker",
    ["info", "--format", "{{json .DriverStatus}}"],
    { cwd: context.root },
  );
  const availableBytes =
    capacityFromDockerDriverStatus(driverStatus.stdout) ??
    (await capacityFromColima(context));
  if (availableBytes === undefined) {
    throw new Error(
      "LOCAL_CONTROLLED Docker runtime capacity cannot be determined",
    );
  }
  if (availableBytes < minimumFreeBytes) {
    throw new Error("LOCAL_CONTROLLED has insufficient free disk capacity");
  }
}

function capacityFromDockerDriverStatus(output: string): number | undefined {
  let status: unknown;
  try {
    status = JSON.parse(output);
  } catch {
    return undefined;
  }
  if (!Array.isArray(status)) return undefined;
  const available = status.find(
    (entry): entry is [string, string] =>
      Array.isArray(entry) &&
      entry[0] === "Data Space Available" &&
      typeof entry[1] === "string",
  );
  return available ? parseDockerSize(available[1]) : undefined;
}

async function capacityFromColima(
  context: ReturnType<typeof createContext>,
): Promise<number | undefined> {
  try {
    const dockerContext = await context.runner.run(
      "docker",
      ["context", "show"],
      { cwd: context.root },
    );
    if (
      dockerContext.exitCode !== 0 ||
      dockerContext.stdout.trim() !== "colima"
    ) {
      return undefined;
    }
    const diskUsage = await context.runner.run(
      "colima",
      ["ssh", "--", "df", "-Pk", "/var/lib/docker"],
      { cwd: context.root },
    );
    if (diskUsage.exitCode !== 0) return undefined;
    return capacityFromPosixDf(diskUsage.stdout);
  } catch {
    return undefined;
  }
}

function capacityFromPosixDf(output: string): number | undefined {
  const lines = output.trim().split(/\r?\n/);
  if (lines.length !== 2) return undefined;
  const header = lines[0]?.trim().split(/\s+/);
  if (
    header?.length !== 7 ||
    header[0] !== "Filesystem" ||
    header[1] !== "1024-blocks" ||
    header[2] !== "Used" ||
    header[3] !== "Available" ||
    header[4] !== "Capacity" ||
    header[5] !== "Mounted" ||
    header[6] !== "on"
  ) {
    return undefined;
  }
  const filesystem = lines[1]?.trim().split(/\s+/);
  if (filesystem?.length !== 6) return undefined;
  const totalBlocks = parseSafeUnsignedInteger(filesystem[1]);
  const usedBlocks = parseSafeUnsignedInteger(filesystem[2]);
  const availableBlocks = parseSafeUnsignedInteger(filesystem[3]);
  const capacity = /^(\d{1,3})%$/.exec(filesystem[4] ?? "");
  if (
    totalBlocks === undefined ||
    usedBlocks === undefined ||
    availableBlocks === undefined ||
    !capacity ||
    Number(capacity[1]) > 100
  ) {
    return undefined;
  }
  const accountedBlocks = usedBlocks + availableBlocks;
  if (
    usedBlocks > totalBlocks ||
    availableBlocks > totalBlocks ||
    !Number.isSafeInteger(accountedBlocks) ||
    accountedBlocks > totalBlocks
  ) {
    return undefined;
  }
  const availableBytes = availableBlocks * 1024;
  return Number.isSafeInteger(availableBytes) ? availableBytes : undefined;
}

function parseSafeUnsignedInteger(value: string | undefined) {
  if (!value || !/^(0|[1-9]\d*)$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function parseDockerSize(value: string): number | undefined {
  const match = /^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)$/i.exec(value.trim());
  if (!match) return undefined;
  const multiplier = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12 }[
    match[2]?.toUpperCase() as "B" | "KB" | "MB" | "GB" | "TB"
  ];
  return multiplier ? Number(match[1]) * multiplier : undefined;
}

async function readTwitterState(runner: CommandRunner): Promise<boolean> {
  const result = await runner.run("docker", [
    "container",
    "inspect",
    "--format",
    "{{.State.Running}}",
    LOCAL_CONTROLLED.twitterContainer,
  ]);
  if (result.exitCode !== 0) return false;
  return result.stdout.trim() === "true";
}

async function assertPortsAvailable(
  runner: CommandRunner,
  afterTeardown: boolean,
  allowRestoredTwitter = false,
): Promise<void> {
  for (const port of requiredPorts) {
    const owner = await dockerPortOwner(runner, port);
    const localListener = await runner.run("lsof", [
      "-nP",
      `-iTCP:${port}`,
      "-sTCP:LISTEN",
      "-t",
    ]);
    const listenerExists =
      localListener.exitCode === 0 && localListener.stdout.trim().length > 0;
    if (!owner && !listenerExists) continue;
    if (
      (port === 3000 || port === 3001) &&
      owner === LOCAL_CONTROLLED.twitterContainer &&
      (!afterTeardown || allowRestoredTwitter)
    ) {
      continue;
    }
    throw new Error(
      `LOCAL_CONTROLLED port ${port} is occupied by ${owner ?? "an unknown process"}`,
    );
  }
}

async function portsAreClear(
  runner: CommandRunner,
  allowRestoredTwitter = false,
): Promise<boolean> {
  try {
    await assertPortsAvailable(runner, true, allowRestoredTwitter);
    return true;
  } catch {
    return false;
  }
}

async function dockerPortOwner(
  runner: CommandRunner,
  port: number,
): Promise<string | undefined> {
  const result = await requireSuccess(runner, "docker", [
    "ps",
    "--filter",
    `publish=${port}`,
    "--format",
    "{{.Names}}",
  ]);
  const owners = result.stdout.trim().split("\n").filter(Boolean);
  if (owners.length > 1) return "multiple containers";
  return owners[0];
}

async function assertNoAmbiguousComposeState(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  const projectLabel = `label=com.docker.compose.project=${LOCAL_CONTROLLED.composeProject}`;
  const containers = await requireSuccess(
    context.runner,
    "docker",
    [
      "container",
      "ls",
      "--all",
      "--filter",
      projectLabel,
      "--format",
      "{{.ID}}",
    ],
    { cwd: context.root },
  );
  if (containers.stdout.trim()) {
    throw new Error(
      "LOCAL_CONTROLLED Compose project is already in a partial state",
    );
  }
  const volumes = await requireSuccess(
    context.runner,
    "docker",
    ["volume", "ls", "--filter", projectLabel, "--format", "{{.Name}}"],
    { cwd: context.root },
  );
  if (volumes.stdout.trim()) {
    throw new Error("LOCAL_CONTROLLED Compose project has a leftover volume");
  }
}

// Keycloak is an ordinary IdP with no dependency on the controlled gateway, so
// it starts first and lets the demo app complete OIDC discovery.
async function waitForKeycloak(fetchImpl: typeof fetch): Promise<void> {
  await waitForUrls(fetchImpl, [
    "http://127.0.0.1:8080/realms/verana-playground/.well-known/openid-configuration",
  ]);
}

async function waitForAgentServices(fetchImpl: typeof fetch): Promise<void> {
  await waitForUrls(fetchImpl, [
    "http://127.0.0.1:3100/v1/health",
    "http://127.0.0.1:3101/oid4vc-demo/capabilities",
    "http://127.0.0.1:3110/v1/health",
    "http://127.0.0.1:3111/oid4vc-demo/capabilities",
    "http://127.0.0.1:3200/v1/health",
    "http://127.0.0.1:3201/oid4vc-demo/capabilities",
  ]);
}

// The gateway terminates TLS with a per-run private CA, so readiness is a TCP
// accept rather than an HTTP probe: a fetch would fail certificate validation
// before proving anything about the listener.
async function waitForTlsGateway(): Promise<void> {
  const deadline = Date.now() + 30_000;
  for (;;) {
    const accepted = await new Promise<boolean>((resolveAccepted) => {
      const socket = connect(LOCAL_TLS_GATEWAY_PORT, "127.0.0.1");
      const settle = (value: boolean) => {
        socket.destroy();
        resolveAccepted(value);
      };
      socket.once("connect", () => settle(true));
      socket.once("error", () => settle(false));
      socket.setTimeout(2_000, () => settle(false));
    });
    if (accepted) return;
    if (Date.now() >= deadline) {
      throw new Error(
        "LOCAL_CONTROLLED TLS gateway did not accept connections before the deadline",
      );
    }
    await new Promise((wait) => setTimeout(wait, 500));
  }
}

async function waitForHostServices(
  fetchImpl: typeof fetch,
  waitForGateway: () => Promise<void>,
): Promise<void> {
  await waitForUrls(fetchImpl, [
    "http://127.0.0.1:3099/health",
    "http://127.0.0.1:3001/.well-known/openid-configuration",
    "http://127.0.0.1:3000/",
  ]);
  await waitForGateway();
}

async function assertZeroKeycloakUsers(fetchImpl: typeof fetch): Promise<void> {
  const tokenResponse = await fetchImpl(
    "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: "admin-cli",
        username: "admin",
        password: "local-development-only",
      }),
      signal: AbortSignal.timeout(2_000),
    },
  );
  if (!tokenResponse.ok) {
    throw new Error("LOCAL_CONTROLLED Keycloak admin token request failed");
  }
  const tokenPayload: unknown = await tokenResponse.json();
  const accessToken =
    tokenPayload &&
    typeof tokenPayload === "object" &&
    typeof (tokenPayload as { access_token?: unknown }).access_token ===
      "string"
      ? (tokenPayload as { access_token: string }).access_token
      : undefined;
  if (!accessToken) {
    throw new Error(
      "LOCAL_CONTROLLED Keycloak admin token response is invalid",
    );
  }
  const usersResponse = await fetchImpl(
    "http://127.0.0.1:8080/admin/realms/verana-playground/users?max=1",
    {
      headers: { authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(2_000),
    },
  );
  if (!usersResponse.ok) {
    throw new Error("LOCAL_CONTROLLED Keycloak user check failed");
  }
  const users: unknown = await usersResponse.json();
  if (!Array.isArray(users) || users.length !== 0) {
    throw new Error("LOCAL_CONTROLLED Keycloak must start with zero users");
  }
}

async function waitForUrls(
  fetchImpl: typeof fetch,
  urls: readonly string[],
): Promise<void> {
  for (const url of urls) {
    let lastError: unknown;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        const response = await fetchImpl(url, {
          signal: AbortSignal.timeout(2_000),
        });
        if (response.ok) {
          lastError = undefined;
          break;
        }
        lastError = new Error(`HTTP ${response.status}`);
      } catch (error) {
        lastError = error;
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
    }
    if (lastError)
      throw new Error(
        `LOCAL_CONTROLLED service health check failed for ${url}`,
      );
  }
}

async function writeState(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<void> {
  const temporaryState = await writePrivateTemporaryFile(
    context,
    `${JSON.stringify(state)}\n`,
    "state file",
  );
  await publishTemporaryFile(
    context,
    temporaryState,
    statePath(context),
    "state file",
    true,
  );
  const persisted = await readState(context);
  if (!persisted || JSON.stringify(persisted) !== JSON.stringify(state)) {
    throw new Error("LOCAL_CONTROLLED state publication cannot be verified");
  }
}

async function readState(
  context: ReturnType<typeof createContext>,
): Promise<LocalStackState | undefined> {
  await assertDestructivePaths(context);
  try {
    const parsed = await readVerifiedState(statePath(context));
    if (!isState(parsed))
      throw new Error("LOCAL_CONTROLLED stack state is invalid");
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function readVerifiedState(path: string): Promise<unknown> {
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink()) {
    throw new Error("LOCAL_CONTROLLED stack state is not a regular file");
  }
  return JSON.parse(await readFile(path, "utf8"));
}

async function ensureDataDirectory(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await assertSafePaths(context.root, context.dataDirectory);
  try {
    await lstat(context.dataDirectory);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await assertSafePaths(context.root, context.dataDirectory);
  try {
    await mkdir(context.dataDirectory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
}

async function ensureLifecycleDirectory(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await ensureDataDirectory(context);
  await assertDestructivePaths(context);
  try {
    await lstat(context.lifecycleDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await assertDestructivePaths(context);
    try {
      await mkdir(context.lifecycleDirectory, { mode: 0o700 });
    } catch (mkdirError) {
      if ((mkdirError as NodeJS.ErrnoException).code !== "EEXIST") {
        throw mkdirError;
      }
    }
  }

  await assertDestructivePaths(context);
  const details = await lstat(context.lifecycleDirectory);
  if (!details.isDirectory() || details.isSymbolicLink()) {
    throw new Error("LOCAL_CONTROLLED lifecycle directory is invalid");
  }
  const identity = { dev: details.dev, ino: details.ino };
  if (
    context.lifecycleDirectoryIdentity &&
    !sameFileSystemIdentity(context.lifecycleDirectoryIdentity, identity)
  ) {
    throw new Error("LOCAL_CONTROLLED lifecycle directory identity changed");
  }
  context.lifecycleDirectoryIdentity ??= identity;
}

async function writePrivateTemporaryFile(
  context: ReturnType<typeof createContext>,
  contents: string,
  label: string,
): Promise<TemporaryFile> {
  await ensureDataDirectory(context);
  await assertDestructivePaths(context);
  const path = join(
    context.dataDirectory,
    `.local-stack-temp-${randomBytes(16).toString("hex")}`,
  );
  if (dirname(path) !== context.dataDirectory) {
    throw new Error("LOCAL_CONTROLLED temporary path is invalid");
  }

  const handle = await open(
    path,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_NOFOLLOW,
    0o600,
  );
  try {
    const openedDetails = await handle.stat();
    if (!openedDetails.isFile()) {
      throw new Error(`LOCAL_CONTROLLED temporary ${label} is invalid`);
    }
    const identity = {
      dev: openedDetails.dev,
      ino: openedDetails.ino,
    };
    context.temporaryFileIdentities.set(path, identity);

    await assertDestructivePaths(context);
    const placedDetails = await lstat(path);
    if (
      !placedDetails.isFile() ||
      placedDetails.isSymbolicLink() ||
      !sameFileSystemIdentity(identity, placedDetails)
    ) {
      throw new Error(`LOCAL_CONTROLLED temporary ${label} placement changed`);
    }

    await context.afterTempFileOpen({ path, label });
    const preWriteDetails = await handle.stat();
    if (
      !preWriteDetails.isFile() ||
      !sameFileSystemIdentity(identity, preWriteDetails)
    ) {
      throw new Error(`LOCAL_CONTROLLED temporary ${label} changed`);
    }
    await assertDestructivePaths(context);
    const preWritePlacement = await lstat(path);
    if (
      !preWritePlacement.isFile() ||
      preWritePlacement.isSymbolicLink() ||
      !sameFileSystemIdentity(identity, preWritePlacement)
    ) {
      throw new Error(`LOCAL_CONTROLLED temporary ${label} placement changed`);
    }

    await handle.chmod(0o600);
    await assertDestructivePaths(context);
    await handle.writeFile(contents, { encoding: "utf8" });
    await handle.sync();

    const writtenDetails = await handle.stat();
    if (
      !writtenDetails.isFile() ||
      !sameFileSystemIdentity(identity, writtenDetails)
    ) {
      throw new Error(`LOCAL_CONTROLLED temporary ${label} changed`);
    }
    await assertDestructivePaths(context);
    const writtenPlacement = await lstat(path);
    if (
      !writtenPlacement.isFile() ||
      writtenPlacement.isSymbolicLink() ||
      !sameFileSystemIdentity(identity, writtenPlacement)
    ) {
      throw new Error(`LOCAL_CONTROLLED temporary ${label} placement changed`);
    }
    return { path, identity };
  } finally {
    await handle.close();
  }
}

async function generateAndPublishData(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<LocalStackState> {
  const generatedData = await context.generateData(context.vsSourcePath);
  assertGeneratedData(generatedData);
  await assertGeneratedDataTargetsAvailable(context);
  const temporaryFiles = new Map<
    (typeof generatedDataFiles)[number],
    TemporaryFile
  >();
  for (const file of generatedDataFiles) {
    temporaryFiles.set(
      file,
      await writePrivateTemporaryFile(
        context,
        generatedData[file],
        `generated data file ${file}`,
      ),
    );
  }

  let publishedState = state;
  for (const file of generatedDataFiles) {
    const temporaryFile = temporaryFiles.get(file);
    if (!temporaryFile) {
      throw new Error(`LOCAL_CONTROLLED generated ${file} is unavailable`);
    }
    await publishTemporaryFile(
      context,
      temporaryFile,
      ownedDataPath(context, file),
      `generated data file ${file}`,
      false,
      () => context.publishedDataFiles.set(file, temporaryFile.identity),
    );
    publishedState = {
      ...publishedState,
      ownedDataFiles: [...publishedState.ownedDataFiles, file],
    };
    await writeState(context, publishedState);
  }
  return publishedState;
}

async function establishTlsMaterial(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<LocalStackState> {
  await ensureLifecycleDirectory(context);
  const lifecycleIdentity = context.lifecycleDirectoryIdentity;
  if (!lifecycleIdentity) {
    throw new Error("LOCAL_CONTROLLED lifecycle directory identity is unknown");
  }
  let currentState: LocalStackState = {
    ...state,
    ownedLifecycleDirectory: serializeIdentity(lifecycleIdentity),
  };
  await writeState(context, currentState);

  await assertTlsTargetAvailable(context);
  const reservation = await context.reserveTls({
    stagingParent: context.lifecycleDirectory,
  });
  const stagingName = basename(reservation.directory);
  if (join(context.lifecycleDirectory, stagingName) !== reservation.directory) {
    throw new Error(
      "LOCAL_CONTROLLED TLS reservation is outside the lifecycle directory",
    );
  }

  const reserved: OwnedTlsState = {
    identity: reservation.identity,
    stagingName,
    phase: "reserved",
  };
  currentState = { ...currentState, ownedTls: reserved };
  await writeState(context, currentState);

  const bundle = await context.createTls({ reservation });
  const populated: OwnedTlsState = {
    ...reserved,
    fileIdentities: bundle.fileIdentities,
  };
  currentState = { ...currentState, ownedTls: populated };
  await writeState(context, currentState);

  await assertTlsTargetAvailable(context);
  await context.rename(reservation.directory, context.tlsDirectory);
  currentState = {
    ...currentState,
    ownedTls: { ...populated, phase: "published" },
  };
  await writeState(context, currentState);
  return currentState;
}

async function assertTlsTargetAvailable(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await assertDestructivePaths(context);
  try {
    await lstat(context.tlsDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("LOCAL_CONTROLLED refuses to replace existing TLS material");
}

async function assertPublishedCaCertificate(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<void> {
  const owned = publishedTlsMaterial(state);
  await assertDestructivePaths(context);
  const directoryDetails = await lstat(context.tlsDirectory);
  if (
    !directoryDetails.isDirectory() ||
    directoryDetails.isSymbolicLink() ||
    !sameSerializedIdentity(serializeIdentity(directoryDetails), owned.identity)
  ) {
    throw new Error("LOCAL_CONTROLLED TLS directory changed before Compose");
  }

  const handle = await open(
    join(context.tlsDirectory, tlsCaCertificateName),
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const details = await handle.stat();
    if (
      !details.isFile() ||
      !sameSerializedIdentity(
        serializeIdentity(details),
        owned.fileIdentities.caCertificate,
      )
    ) {
      throw new Error(
        "LOCAL_CONTROLLED TLS bind source changed before Compose",
      );
    }
  } finally {
    await handle.close();
  }
}

function publishedTlsMaterial(state: LocalStackState): OwnedTlsState & {
  fileIdentities: LocalTlsBundle["fileIdentities"];
} {
  const owned = state.ownedTls;
  if (owned?.phase !== "published" || !owned.fileIdentities) {
    throw new Error("LOCAL_CONTROLLED TLS material is not published");
  }
  return { ...owned, fileIdentities: owned.fileIdentities };
}

async function removeOwnedTls(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<void> {
  const owned = state.ownedTls;
  if (!owned) return;
  if (
    !owned.stagingName ||
    basename(owned.stagingName) !== owned.stagingName ||
    join(context.lifecycleDirectory, owned.stagingName) ===
      context.lifecycleDirectory
  ) {
    throw new Error("LOCAL_CONTROLLED journalled TLS staging name is invalid");
  }

  const stagingPath = join(context.lifecycleDirectory, owned.stagingName);
  const published = await hasJournalledTlsIdentity(
    context,
    context.tlsDirectory,
    owned,
  );
  const staged = await hasJournalledTlsIdentity(context, stagingPath, owned);
  if (published && staged) {
    throw new Error("LOCAL_CONTROLLED TLS material exists in two locations");
  }
  if (published) {
    await removeOwnedEntry(
      context,
      context.tlsDirectory,
      "directory",
      "TLS material",
    );
    return;
  }
  if (staged) {
    await removeOwnedEntry(
      context,
      stagingPath,
      "directory",
      "TLS reservation",
    );
  }
}

async function hasJournalledTlsIdentity(
  context: ReturnType<typeof createContext>,
  path: string,
  owned: OwnedTlsState,
): Promise<boolean> {
  await assertDestructivePaths(context);
  let details: Awaited<ReturnType<typeof lstat>>;
  try {
    details = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  if (
    !details.isDirectory() ||
    details.isSymbolicLink() ||
    !sameSerializedIdentity(serializeIdentity(details), owned.identity)
  ) {
    throw new Error(
      "LOCAL_CONTROLLED refuses to delete unexpected TLS material",
    );
  }
  return true;
}

function serializeIdentity(
  identity: FileSystemIdentity,
): SerializedFileIdentity {
  return { dev: String(identity.dev), ino: String(identity.ino) };
}

function sameSerializedIdentity(
  left: SerializedFileIdentity,
  right: SerializedFileIdentity,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertGeneratedData(generatedData: LocalControlledDataFiles): void {
  const keys = Object.keys(generatedData);
  if (
    keys.length !== generatedDataFiles.length ||
    generatedDataFiles.some((file) => typeof generatedData[file] !== "string")
  ) {
    throw new Error("LOCAL_CONTROLLED generated data is invalid");
  }
}

async function publishTemporaryFile(
  context: ReturnType<typeof createContext>,
  temporaryFile: TemporaryFile,
  destination: string,
  label: string,
  allowVerifiedPriorState: boolean,
  onRenamed?: () => void,
): Promise<void> {
  if (dirname(temporaryFile.path) !== context.dataDirectory) {
    throw new Error("LOCAL_CONTROLLED publication source is invalid");
  }
  const trackedIdentity = context.temporaryFileIdentities.get(
    temporaryFile.path,
  );
  if (
    !trackedIdentity ||
    !sameFileSystemIdentity(trackedIdentity, temporaryFile.identity)
  ) {
    throw new Error(`LOCAL_CONTROLLED temporary ${label} is untracked`);
  }
  await assertPublishTarget(
    context,
    destination,
    label,
    allowVerifiedPriorState,
  );
  await assertDestructivePaths(context);
  const sourceDetails = await lstat(temporaryFile.path);
  if (
    !sourceDetails.isFile() ||
    sourceDetails.isSymbolicLink() ||
    !sameFileSystemIdentity(temporaryFile.identity, sourceDetails)
  ) {
    throw new Error(`LOCAL_CONTROLLED temporary ${label} changed`);
  }
  await assertDestructivePaths(context);
  await context.rename(temporaryFile.path, destination);
  context.temporaryFileIdentities.delete(temporaryFile.path);
  onRenamed?.();
  await context.afterTempFileRename({ path: destination, label });
  await assertDestructivePaths(context);
  const destinationDetails = await lstat(destination);
  if (
    !destinationDetails.isFile() ||
    destinationDetails.isSymbolicLink() ||
    !sameFileSystemIdentity(temporaryFile.identity, destinationDetails)
  ) {
    throw new Error(`LOCAL_CONTROLLED published ${label} is invalid`);
  }
}

async function assertPublishTarget(
  context: ReturnType<typeof createContext>,
  path: string,
  label: string,
  allowVerifiedPriorState: boolean,
): Promise<void> {
  await assertDestructivePaths(context);
  try {
    const details = await lstat(path);
    if (details.isSymbolicLink()) return;
    if (!details.isFile()) {
      throw new Error(`LOCAL_CONTROLLED refuses to replace invalid ${label}`);
    }
    if (!allowVerifiedPriorState) {
      throw new Error(
        `LOCAL_CONTROLLED refuses to replace existing regular ${label}`,
      );
    }
    const existingState = await readVerifiedState(path);
    if (!isState(existingState)) {
      throw new Error(
        "LOCAL_CONTROLLED refuses to replace unverified prior state",
      );
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
}

function isState(value: unknown): value is LocalStackState {
  if (!value || typeof value !== "object") return false;
  const state = value as Partial<LocalStackState>;
  if (
    state.version !== 2 ||
    state.composeProject !== LOCAL_CONTROLLED.composeProject ||
    typeof state.twitterWasRunning !== "boolean" ||
    typeof state.twitterStopped !== "boolean" ||
    typeof state.composeTouched !== "boolean" ||
    typeof state.vsSourceCommit !== "string" ||
    typeof state.startedAt !== "string" ||
    !Array.isArray(state.ownedDataFiles) ||
    state.ownedDataFiles.some(
      (file) =>
        typeof file !== "string" ||
        !generatedDataFiles.includes(
          file as (typeof generatedDataFiles)[number],
        ),
    ) ||
    (state.ownedLifecycleDirectory !== undefined &&
      !isSerializedIdentity(state.ownedLifecycleDirectory)) ||
    (state.ownedTls !== undefined && !isOwnedTlsState(state.ownedTls))
  ) {
    return false;
  }
  return (
    state.hostProcess === undefined ||
    (typeof state.hostProcess.pid === "number" &&
      Number.isInteger(state.hostProcess.pid) &&
      state.hostProcess.pid > 0 &&
      typeof state.hostProcess.startToken === "string" &&
      state.hostProcess.startToken.length >= 16)
  );
}

function isSerializedIdentity(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const identity = value as Partial<SerializedFileIdentity>;
  return typeof identity.dev === "string" && typeof identity.ino === "string";
}

function isOwnedTlsState(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  const owned = value as Partial<OwnedTlsState>;
  if (
    !isSerializedIdentity(owned.identity) ||
    typeof owned.stagingName !== "string" ||
    (owned.phase !== "reserved" && owned.phase !== "published")
  ) {
    return false;
  }
  if (owned.fileIdentities === undefined) return true;
  const files = owned.fileIdentities as Partial<
    LocalTlsBundle["fileIdentities"]
  >;
  return (
    isSerializedIdentity(files.caCertificate) &&
    isSerializedIdentity(files.serverCertificate) &&
    isSerializedIdentity(files.serverPrivateKey)
  );
}

async function stopVerifiedHostProcess(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<boolean> {
  if (!state.hostProcess) return false;
  const processState = await context.runner.run("ps", [
    "eww",
    "-p",
    String(state.hostProcess.pid),
  ]);
  if (
    processState.exitCode !== 0 ||
    !processState.stdout.includes(
      `LOCAL_STACK_START_TOKEN=${state.hostProcess.startToken}`,
    )
  ) {
    context.write(
      "LOCAL_CONTROLLED stale host process metadata; not killing PID",
    );
    return false;
  }
  context.signalProcessGroup(state.hostProcess.pid);
  return true;
}

async function cleanupAfterFailedStartup(
  context: ReturnType<typeof createContext>,
  startupState: LocalStackState,
): Promise<void> {
  let state: LocalStackState | undefined;
  try {
    state = await readState(context);
  } catch (error) {
    await restoreTwitterAfterUnreadableState(context, startupState, error);
    return;
  }
  if (!state) {
    await restoreTwitterAfterUnreadableState(
      context,
      startupState,
      new Error("LOCAL_CONTROLLED stack state disappeared during startup"),
    );
    return;
  }
  const errors = await teardown(context, {
    ...state,
    twitterStopped: state.twitterStopped || startupState.twitterStopped,
    composeTouched: state.composeTouched || startupState.composeTouched,
    ownedDataFiles: generatedDataFiles.filter(
      (file) =>
        state.ownedDataFiles.includes(file) ||
        startupState.ownedDataFiles.includes(file) ||
        context.publishedDataFiles.has(file),
    ),
  });
  if (errors.length > 0) {
    context.write(
      `LOCAL_CONTROLLED cleanup failed: ${errors.map((error) => error.message).join("; ")}`,
    );
  }
}

async function restoreTwitterAfterUnreadableState(
  context: ReturnType<typeof createContext>,
  startupState: LocalStackState,
  stateError: unknown,
): Promise<void> {
  const errors = [asError(stateError)];
  if (startupState.twitterStopped) {
    try {
      await requireSuccess(
        context.runner,
        "docker",
        ["start", LOCAL_CONTROLLED.twitterContainer],
        { cwd: context.root },
      );
    } catch (error) {
      errors.push(asError(error));
    }
  }
  context.write(
    `LOCAL_CONTROLLED cleanup incomplete: ${errors.map((error) => error.message).join("; ")}`,
  );
}

async function teardown(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<Error[]> {
  const errors: Error[] = [];
  let hostExited = true;
  try {
    if (await stopVerifiedHostProcess(context, state)) {
      await waitForHostProcessExit(context, state.hostProcess?.pid ?? 0);
    }
  } catch (error) {
    hostExited = false;
    errors.push(asError(error));
  }

  if (hostExited && state.composeTouched) {
    try {
      await runCompose(context, ["down", "--volumes", "--remove-orphans"]);
    } catch (error) {
      errors.push(asError(error));
    }
  }

  try {
    if (state.twitterStopped) {
      await requireSuccess(
        context.runner,
        "docker",
        ["start", LOCAL_CONTROLLED.twitterContainer],
        { cwd: context.root },
      );
    }
  } catch (error) {
    errors.push(asError(error));
  }

  if (errors.length === 0) {
    try {
      await removeOwnedData(context, state);
      await removeState(context);
    } catch (error) {
      errors.push(asError(error));
    }
  }
  return errors;
}

async function waitForHostProcessExit(
  context: ReturnType<typeof createContext>,
  pid: number,
): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (!(await context.isProcessRunning(pid))) return;
    await context.sleep(250);
  }
  throw new Error("LOCAL_CONTROLLED host process did not exit before teardown");
}

async function assertGeneratedDataTargetsAvailable(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await assertDestructivePaths(context);
  for (const file of generatedDataFiles) {
    try {
      const details = await lstat(ownedDataPath(context, file));
      if (details.isSymbolicLink()) continue;
      if (details.isFile()) {
        throw new Error(
          `LOCAL_CONTROLLED refuses to replace existing regular ${file}`,
        );
      }
      throw new Error(`LOCAL_CONTROLLED refuses to replace invalid ${file}`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

async function removeOwnedData(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
): Promise<void> {
  for (const file of state.ownedDataFiles) {
    const expectedIdentity = context.publishedDataFiles.get(file);
    if (expectedIdentity) {
      await assertDestructivePaths(context);
      const currentIdentity = ownedEntryIdentity(
        await lstat(ownedDataPath(context, file)),
        "file",
        `generated data file ${file}`,
      );
      if (!sameFileSystemIdentity(expectedIdentity, currentIdentity)) {
        throw new Error(
          `LOCAL_CONTROLLED generated data file ${file} changed before cleanup`,
        );
      }
    }
    await removeOwnedEntry(
      context,
      ownedDataPath(context, file),
      "file",
      `generated data file ${file}`,
    );
    context.publishedDataFiles.delete(file);
  }
  await removeOwnedTls(context, state);
  await removeTemporaryFiles(context);
  await removeOwnedEntry(
    context,
    context.lifecycleDirectory,
    "directory",
    "lifecycle directory",
  );
}

async function removeTemporaryFiles(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  for (const [path, expectedIdentity] of context.temporaryFileIdentities) {
    await assertDestructivePaths(context);
    const currentIdentity = ownedEntryIdentity(
      await lstat(path),
      "file",
      "temporary file",
    );
    if (!sameFileSystemIdentity(expectedIdentity, currentIdentity)) {
      throw new Error("LOCAL_CONTROLLED temporary file changed before cleanup");
    }
    await removeOwnedEntry(context, path, "file", "temporary file");
    context.temporaryFileIdentities.delete(path);
  }
}

async function removeState(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await removeOwnedEntry(context, statePath(context), "file", "state file");
}

type OwnedEntryKind = "file" | "directory";

interface OwnedEntryIdentity extends FileSystemIdentity {
  kind: OwnedEntryKind;
}

async function removeOwnedEntry(
  context: ReturnType<typeof createContext>,
  path: string,
  expectedKind: OwnedEntryKind,
  label: string,
): Promise<void> {
  let quarantine: string;
  let identity: OwnedEntryIdentity;
  try {
    ({ quarantine, identity } = await quarantineOwnedEntry(
      context,
      path,
      expectedKind,
      label,
    ));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }

  await deleteQuarantinedEntry(context, quarantine, identity, label);
}

async function quarantineOwnedEntry(
  context: ReturnType<typeof createContext>,
  path: string,
  expectedKind: OwnedEntryKind,
  label: string,
): Promise<{ quarantine: string; identity: OwnedEntryIdentity }> {
  await assertDestructivePaths(context);
  const identity = ownedEntryIdentity(await lstat(path), expectedKind, label);
  const quarantine = join(
    dirname(path),
    `.local-stack-quarantine-${randomBytes(16).toString("hex")}`,
  );
  await assertQuarantinePathAvailable(quarantine);

  await assertDestructivePaths(context);
  await context.rename(path, quarantine);

  try {
    const quarantinedIdentity = ownedEntryIdentity(
      await lstat(quarantine),
      expectedKind,
      label,
    );
    if (sameOwnedEntry(identity, quarantinedIdentity)) {
      return { quarantine, identity };
    }
  } catch (error) {
    await recoverQuarantinedEntry(context, quarantine, path, label);
    throw error;
  }

  await recoverQuarantinedEntry(context, quarantine, path, label);
  throw new Error(`LOCAL_CONTROLLED ${label} changed during quarantine`);
}

async function assertQuarantinePathAvailable(path: string): Promise<void> {
  try {
    await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("LOCAL_CONTROLLED quarantine path already exists");
}

function ownedEntryIdentity(
  details: Awaited<ReturnType<typeof lstat>>,
  expectedKind: OwnedEntryKind,
  label: string,
): OwnedEntryIdentity {
  const isExpectedKind =
    expectedKind === "file" ? details.isFile() : details.isDirectory();
  if (!isExpectedKind || details.isSymbolicLink()) {
    throw new Error(`LOCAL_CONTROLLED refuses to delete invalid ${label}`);
  }
  return { dev: details.dev, ino: details.ino, kind: expectedKind };
}

function sameOwnedEntry(
  left: OwnedEntryIdentity,
  right: OwnedEntryIdentity,
): boolean {
  return sameFileSystemIdentity(left, right) && left.kind === right.kind;
}

function sameFileSystemIdentity(
  left: FileSystemIdentity,
  right: FileSystemIdentity,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function recoverQuarantinedEntry(
  context: ReturnType<typeof createContext>,
  quarantine: string,
  originalPath: string,
  label: string,
): Promise<void> {
  await assertDestructivePaths(context);
  try {
    await lstat(originalPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await assertDestructivePaths(context);
    await context.rename(quarantine, originalPath);
    return;
  }

  const recoveryPath = join(
    dirname(originalPath),
    `.local-stack-recovery-${randomBytes(16).toString("hex")}`,
  );
  await assertQuarantinePathAvailable(recoveryPath);
  await assertDestructivePaths(context);
  await context.rename(quarantine, recoveryPath);
  throw new Error(
    `LOCAL_CONTROLLED ${label} changed during quarantine; recovery preserved at ${recoveryPath}`,
  );
}

async function deleteQuarantinedEntry(
  context: ReturnType<typeof createContext>,
  quarantine: string,
  identity: OwnedEntryIdentity,
  label: string,
): Promise<void> {
  await assertDestructivePaths(context);
  const currentIdentity = ownedEntryIdentity(
    await lstat(quarantine),
    identity.kind,
    label,
  );
  if (!sameOwnedEntry(identity, currentIdentity)) {
    await recoverQuarantinedEntry(context, quarantine, quarantine, label);
    throw new Error(`LOCAL_CONTROLLED ${label} changed before deletion`);
  }
  await assertDestructivePaths(context);
  await rm(quarantine, {
    recursive: identity.kind === "directory",
    force: false,
  });
}

async function loadSanitizedEnvironment(
  context: ReturnType<typeof createContext>,
  state: LocalStackState,
  startToken: string,
): Promise<NodeJS.ProcessEnv> {
  const owned = publishedTlsMaterial(state);
  const [baseEnvironment, controlledEnvironment] = await Promise.all([
    readFile(join(context.dataDirectory, ".env"), "utf8"),
    readFile(join(context.dataDirectory, "local-controlled.env"), "utf8"),
  ]);
  const parsed = {
    ...parseEnvironment(baseEnvironment),
    ...parseEnvironment(controlledEnvironment),
  };
  for (const forbidden of [
    "PATH",
    "NODE_ENV",
    "NODE_OPTIONS",
    "LOCAL_STACK_START_TOKEN",
    ...hostTlsEnvironmentNames,
  ]) {
    if (parsed[forbidden] !== undefined) {
      throw new Error(
        `LOCAL_CONTROLLED host environment override is forbidden: ${forbidden}`,
      );
    }
  }
  return {
    ...parsed,
    PATH: process.env.PATH,
    NODE_ENV: "production",
    LOCAL_STACK_START_TOKEN: startToken,
    LOCAL_TLS_CERTIFICATE_PATH: join(
      context.tlsDirectory,
      tlsServerCertificateName,
    ),
    LOCAL_TLS_PRIVATE_KEY_PATH: join(
      context.tlsDirectory,
      tlsServerPrivateKeyName,
    ),
    LOCAL_TLS_CERTIFICATE_IDENTITY: JSON.stringify(
      owned.fileIdentities.serverCertificate,
    ),
    LOCAL_TLS_PRIVATE_KEY_IDENTITY: JSON.stringify(
      owned.fileIdentities.serverPrivateKey,
    ),
  };
}

function parseEnvironment(contents: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const line of contents.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator < 1)
      throw new Error("LOCAL_CONTROLLED generated environment is invalid");
    const name = line.slice(0, separator);
    const value = line.slice(separator + 1);
    environment[name] = value;
  }
  return environment;
}

async function launchHostProcess({
  root: projectRoot,
  environment,
  startToken,
}: {
  root: string;
  environment: NodeJS.ProcessEnv;
  startToken: string;
}): Promise<HostProcess> {
  const logsDirectory = join(
    projectRoot,
    dataDirectoryName,
    lifecycleDirectoryName,
    "logs",
  );
  await mkdir(logsDirectory, { recursive: true, mode: 0o700 });
  const log = await open(join(logsDirectory, "host-process.log"), "a", 0o600);
  const { spawn } = await import("node:child_process");
  const child = spawn(
    process.execPath,
    ["--import", "tsx", "scripts/local-stack-process.ts"],
    {
      cwd: projectRoot,
      detached: true,
      env: environment,
      stdio: ["ignore", log.fd, log.fd],
    },
  );
  log.close();
  if (!child.pid)
    throw new Error("LOCAL_CONTROLLED could not start host process");
  child.unref();
  return { pid: child.pid, startToken };
}

function defaultSignalProcessGroup(pid: number): void {
  process.kill(-pid, "SIGTERM");
}

async function defaultIsProcessRunning(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function defaultSleep(milliseconds: number): Promise<void> {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

function asError(error: unknown): Error {
  return error instanceof Error
    ? error
    : new Error("LOCAL_CONTROLLED cleanup failed");
}

const systemRunner: CommandRunner = {
  async run(command, args, options) {
    return await new Promise<CommandResult>((resolveResult, reject) => {
      execFile(
        command,
        [...args],
        { cwd: options?.cwd, env: options?.env },
        (error, stdout, stderr) => {
          if (error && typeof error.code !== "number") {
            reject(error);
            return;
          }
          resolveResult({
            exitCode: typeof error?.code === "number" ? error.code : 0,
            stdout,
            stderr,
          });
        },
      );
    });
  },
};

async function requireSuccess(
  runner: CommandRunner,
  command: string,
  args: readonly string[],
  options?: { cwd?: string; env?: NodeJS.ProcessEnv },
): Promise<CommandResult> {
  const result = await runner.run(command, args, options);
  if (result.exitCode !== 0) {
    throw new Error(
      `LOCAL_CONTROLLED command failed: ${command} ${args.join(" ")}`,
    );
  }
  return result;
}

async function runCompose(
  context: ReturnType<typeof createContext>,
  args: readonly string[],
): Promise<CommandResult> {
  return await requireSuccess(
    context.runner,
    "docker",
    [...composeBaseArgs, ...args],
    { cwd: context.root },
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const action = process.argv[2];
  if (action === "up") await up();
  else if (action === "status") await status();
  else if (action === "down") await down();
  else throw new Error("Usage: local-stack.ts <up|status|down>");
}
