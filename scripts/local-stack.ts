import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { LOCAL_CONTROLLED } from "./local-controlled-config.js";
import { generateLocalControlledData } from "./setup-local-controlled.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDirectoryName = ".data";
const stateFileName = "local-stack-state.json";
const lifecycleDirectoryName = "local-stack";
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

interface LocalStackState {
  version: 1;
  composeProject: typeof LOCAL_CONTROLLED.composeProject;
  twitterWasRunning: boolean;
  twitterStopped: boolean;
  hostProcess?: HostProcess;
  ownedDataFiles: readonly (typeof generatedDataFiles)[number][];
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
  generateData?: (output: string, vsSourcePath: string) => Promise<void>;
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
    version: 1,
    composeProject: LOCAL_CONTROLLED.composeProject,
    twitterWasRunning: checked.twitterWasRunning,
    twitterStopped: false,
    vsSourceCommit: checked.vsSourceCommit,
    startedAt: context.now().toISOString(),
    ownedDataFiles: generatedDataFiles,
  };
  let stateWritten = false;
  let currentState = initialState;

  try {
    await writeState(context, initialState);
    stateWritten = true;
    await assertGeneratedDataTargetsAvailable(context);
    await context.generateData(context.dataDirectory, context.vsSourcePath);

    if (checked.twitterWasRunning) {
      await requireSuccess(context.runner, "docker", [
        "stop",
        LOCAL_CONTROLLED.twitterContainer,
      ]);
      currentState = { ...initialState, twitterStopped: true };
      await writeState(context, currentState);
    }

    await runCompose(context, ["build", "issuer"]);
    await runCompose(context, [
      "up",
      "-d",
      "--force-recreate",
      "keycloak",
      "issuer",
      "holder",
      "verifier",
    ]);
    await waitForContainerServices(context.fetch);
    await assertZeroKeycloakUsers(context.fetch);

    const startToken = context.randomToken();
    const environment = await loadSanitizedEnvironment(
      context.dataDirectory,
      startToken,
    );
    const hostProcess = await context.launch({
      root: context.root,
      environment,
      startToken,
    });
    await writeState(context, { ...currentState, hostProcess });

    await waitForHostServices(context.fetch);
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3000");
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3001");
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3099/health");
  } catch (error) {
    if (stateWritten) {
      await cleanupAfterFailedStartup(context, currentState);
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
  if (portsClear) context.write("LOCAL_CONTROLLED ports clear");
  return {
    active: currentState !== undefined,
    portsClear,
    ...(currentState
      ? { twitterWasRunning: currentState.twitterWasRunning }
      : {}),
  };
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
    vsSourcePath,
    nodeVersion: dependencies.nodeVersion ?? process.version,
    runner: dependencies.runner ?? systemRunner,
    generateData: dependencies.generateData ?? generateLocalControlledData,
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
  const availableBytes = capacityFromDockerDriverStatus(driverStatus.stdout);
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
  const result = await runCompose(context, ["ps", "--all", "--format", "json"]);
  const output = result.stdout.trim();
  if (output && output !== "[]") {
    throw new Error(
      "LOCAL_CONTROLLED Compose project is already in a partial state",
    );
  }
  const volumes = await requireSuccess(
    context.runner,
    "docker",
    [
      "volume",
      "ls",
      "--filter",
      `label=com.docker.compose.project=${LOCAL_CONTROLLED.composeProject}`,
      "--format",
      "{{.Name}}",
    ],
    { cwd: context.root },
  );
  if (volumes.stdout.trim()) {
    throw new Error("LOCAL_CONTROLLED Compose project has a leftover volume");
  }
}

async function waitForContainerServices(
  fetchImpl: typeof fetch,
): Promise<void> {
  await waitForUrls(fetchImpl, [
    "http://127.0.0.1:8080/realms/verana-playground/.well-known/openid-configuration",
    "http://127.0.0.1:3100/v1/health",
    "http://127.0.0.1:3101/oid4vc-demo/capabilities",
    "http://127.0.0.1:3110/v1/health",
    "http://127.0.0.1:3111/oid4vc-demo/capabilities",
    "http://127.0.0.1:3200/v1/health",
    "http://127.0.0.1:3201/oid4vc-demo/capabilities",
  ]);
}

async function waitForHostServices(fetchImpl: typeof fetch): Promise<void> {
  await waitForUrls(fetchImpl, [
    "http://127.0.0.1:3099/health",
    "http://127.0.0.1:3001/.well-known/openid-configuration",
    "http://127.0.0.1:3000/",
  ]);
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
  await mkdir(context.dataDirectory, { recursive: true, mode: 0o700 });
  await assertDestructivePaths(context);
  const path = statePath(context);
  await writeFile(path, `${JSON.stringify(state)}\n`, { mode: 0o600 });
  await assertDestructivePaths(context);
  await chmod(path, 0o600);
}

async function readState(
  context: ReturnType<typeof createContext>,
): Promise<LocalStackState | undefined> {
  await assertDestructivePaths(context);
  try {
    const parsed: unknown = JSON.parse(
      await readFile(statePath(context), "utf8"),
    );
    if (!isState(parsed))
      throw new Error("LOCAL_CONTROLLED stack state is invalid");
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

function isState(value: unknown): value is LocalStackState {
  if (!value || typeof value !== "object") return false;
  const state = value as Partial<LocalStackState>;
  if (
    state.version !== 1 ||
    state.composeProject !== LOCAL_CONTROLLED.composeProject ||
    typeof state.twitterWasRunning !== "boolean" ||
    typeof state.twitterStopped !== "boolean" ||
    typeof state.vsSourceCommit !== "string" ||
    typeof state.startedAt !== "string" ||
    !Array.isArray(state.ownedDataFiles) ||
    state.ownedDataFiles.some(
      (file) =>
        typeof file !== "string" ||
        !generatedDataFiles.includes(
          file as (typeof generatedDataFiles)[number],
        ),
    )
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
  const state = await readState(context);
  if (!state) return;
  const errors = await teardown(context, {
    ...state,
    twitterStopped: state.twitterStopped || startupState.twitterStopped,
  });
  if (errors.length > 0) {
    context.write(
      `LOCAL_CONTROLLED cleanup failed: ${errors.map((error) => error.message).join("; ")}`,
    );
  }
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

  if (hostExited) {
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
      await lstat(ownedDataPath(context, file));
      throw new Error(`LOCAL_CONTROLLED refuses to replace existing ${file}`);
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
    await removeOwnedEntry(
      context,
      ownedDataPath(context, file),
      "file",
      `generated data file ${file}`,
    );
  }
  await removeOwnedEntry(
    context,
    context.lifecycleDirectory,
    "directory",
    "lifecycle directory",
  );
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
  dataDirectory: string,
  startToken: string,
): Promise<NodeJS.ProcessEnv> {
  const [baseEnvironment, controlledEnvironment] = await Promise.all([
    readFile(join(dataDirectory, ".env"), "utf8"),
    readFile(join(dataDirectory, "local-controlled.env"), "utf8"),
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
