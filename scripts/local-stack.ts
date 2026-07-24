import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  rm,
  statfs,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { LOCAL_CONTROLLED } from "./local-controlled-config.js";
import { generateLocalControlledData } from "./setup-local-controlled.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataDirectoryName = ".data";
const stateFileName = "local-stack-state.json";
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

interface LocalStackState {
  version: 1;
  composeProject: typeof LOCAL_CONTROLLED.composeProject;
  twitterWasRunning: boolean;
  hostProcess?: HostProcess;
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
  fetch?: typeof fetch;
  randomToken?: () => string;
  now?: () => Date;
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

const composeDownArgs = [
  ...composeBaseArgs,
  "down",
  "--volumes",
  "--remove-orphans",
] as const;

export async function preflight(
  dependencies: LifecycleDependencies = {},
): Promise<PreflightResult> {
  const context = createContext(dependencies);
  await assertSafePaths(context.root, context.dataDirectory);
  assertNodeVersion(context.nodeVersion);

  await requireSuccess(context.runner, "docker", ["version"]);
  await requireSuccess(context.runner, "docker", ["compose", "version"]);
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
  await assertNoAmbiguousComposeState(context.runner);

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
    vsSourceCommit: checked.vsSourceCommit,
    startedAt: context.now().toISOString(),
  };
  let stateWritten = false;

  try {
    await writeState(context, initialState);
    stateWritten = true;
    await context.generateData(context.dataDirectory, context.vsSourcePath);

    if (checked.twitterWasRunning) {
      await requireSuccess(context.runner, "docker", [
        "stop",
        LOCAL_CONTROLLED.twitterContainer,
      ]);
    }

    await requireSuccess(context.runner, "docker", [
      ...composeBaseArgs,
      "build",
      "issuer",
    ]);
    await requireSuccess(context.runner, "docker", [
      ...composeBaseArgs,
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
    await writeState(context, { ...initialState, hostProcess });

    await waitForHostServices(context.fetch);
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3000");
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3001");
    context.write("LOCAL_CONTROLLED http://127.0.0.1:3099/health");
  } catch (error) {
    if (stateWritten) {
      await cleanupAfterFailedStartup(context);
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

  await stopVerifiedHostProcess(context, currentState);
  await requireSuccess(context.runner, "docker", composeDownArgs);
  await removeVerifiedData(context);

  if (currentState.twitterWasRunning) {
    await requireSuccess(context.runner, "docker", [
      "start",
      LOCAL_CONTROLLED.twitterContainer,
    ]);
  }

  if (await portsAreClear(context.runner, currentState.twitterWasRunning)) {
    context.write(
      currentState.twitterWasRunning
        ? "LOCAL_CONTROLLED ports released to Twitter"
        : "LOCAL_CONTROLLED ports clear",
    );
  } else {
    throw new Error("LOCAL_CONTROLLED required ports remain occupied");
  }
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
    vsSourcePath,
    nodeVersion: dependencies.nodeVersion ?? process.version,
    runner: dependencies.runner ?? systemRunner,
    generateData: dependencies.generateData ?? generateLocalControlledData,
    launch: dependencies.launch ?? launchHostProcess,
    signalProcessGroup:
      dependencies.signalProcessGroup ?? defaultSignalProcessGroup,
    fetch: dependencies.fetch ?? fetch,
    randomToken:
      dependencies.randomToken ?? (() => randomBytes(32).toString("hex")),
    now: dependencies.now ?? (() => new Date()),
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
  const dockerUsage = await requireSuccess(context.runner, "docker", [
    "system",
    "df",
    "--format",
    "{{json .}}",
  ]);
  const availableBytes =
    capacityFromDocker(dockerUsage.stdout) ??
    (await availableFilesystemBytes(context.root));
  if (availableBytes < minimumFreeBytes) {
    throw new Error("LOCAL_CONTROLLED has insufficient free disk capacity");
  }
}

function capacityFromDocker(output: string): number | undefined {
  for (const line of output.split("\n")) {
    try {
      const parsed: unknown = JSON.parse(line);
      if (
        parsed &&
        typeof parsed === "object" &&
        typeof (parsed as { freeBytes?: unknown }).freeBytes === "number"
      ) {
        return (parsed as { freeBytes: number }).freeBytes;
      }
    } catch {
      // Docker's normal human-size records do not provide an exact capacity.
    }
  }
  return undefined;
}

async function availableFilesystemBytes(path: string): Promise<number> {
  const filesystem = await statfs(path);
  return Number(filesystem.bavail) * Number(filesystem.bsize);
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
  runner: CommandRunner,
): Promise<void> {
  const result = await requireSuccess(runner, "docker", [
    ...composeBaseArgs,
    "ps",
    "--format",
    "json",
  ]);
  const output = result.stdout.trim();
  if (output && output !== "[]") {
    throw new Error(
      "LOCAL_CONTROLLED Compose project is already in a partial state",
    );
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
  await assertSafePaths(context.root, context.dataDirectory);
  await mkdir(context.dataDirectory, { recursive: true, mode: 0o700 });
  await writeFile(
    join(context.dataDirectory, stateFileName),
    `${JSON.stringify(state)}\n`,
    {
      mode: 0o600,
    },
  );
}

async function readState(
  context: ReturnType<typeof createContext>,
): Promise<LocalStackState | undefined> {
  await assertSafePaths(context.root, context.dataDirectory);
  try {
    const parsed: unknown = JSON.parse(
      await readFile(join(context.dataDirectory, stateFileName), "utf8"),
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
    typeof state.vsSourceCommit !== "string" ||
    typeof state.startedAt !== "string"
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
): Promise<void> {
  if (!state.hostProcess) return;
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
    return;
  }
  context.signalProcessGroup(state.hostProcess.pid);
}

async function cleanupAfterFailedStartup(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  try {
    await down({
      root: context.root,
      vsSourcePath: context.vsSourcePath,
      nodeVersion: context.nodeVersion,
      runner: context.runner,
      generateData: context.generateData,
      launch: context.launch,
      signalProcessGroup: context.signalProcessGroup,
      fetch: context.fetch,
      randomToken: context.randomToken,
      now: context.now,
      write: context.write,
    });
  } catch (cleanupError) {
    context.write(
      `LOCAL_CONTROLLED cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : "unknown error"}`,
    );
  }
}

async function removeVerifiedData(
  context: ReturnType<typeof createContext>,
): Promise<void> {
  await assertSafePaths(context.root, context.dataDirectory);
  const resolvedDataDirectory = resolve(context.dataDirectory);
  if (relative(context.root, resolvedDataDirectory) !== dataDirectoryName) {
    throw new Error(
      "LOCAL_CONTROLLED refusing to delete data outside the repository",
    );
  }
  let children: string[];
  try {
    children = await readdir(resolvedDataDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  await Promise.all(
    children.map(async (child) => {
      const candidate = resolve(resolvedDataDirectory, child);
      if (dirname(candidate) !== resolvedDataDirectory) {
        throw new Error(
          "LOCAL_CONTROLLED refusing to delete an invalid data child",
        );
      }
      if ((await lstat(candidate)).isSymbolicLink()) {
        throw new Error(
          "LOCAL_CONTROLLED refusing to delete a symlinked data child",
        );
      }
    }),
  );
  await Promise.all(
    children.map(async (child) => {
      const candidate = resolve(resolvedDataDirectory, child);
      await rm(candidate, { recursive: true, force: false });
    }),
  );
}

async function loadSanitizedEnvironment(
  dataDirectory: string,
  startToken: string,
): Promise<NodeJS.ProcessEnv> {
  const [baseEnvironment, controlledEnvironment] = await Promise.all([
    readFile(join(dataDirectory, ".env"), "utf8"),
    readFile(join(dataDirectory, "local-controlled.env"), "utf8"),
  ]);
  return {
    PATH: process.env.PATH,
    NODE_ENV: "production",
    LOCAL_STACK_START_TOKEN: startToken,
    ...parseEnvironment(baseEnvironment),
    ...parseEnvironment(controlledEnvironment),
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
  const logsDirectory = join(projectRoot, dataDirectoryName, "logs");
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
): Promise<CommandResult> {
  const result = await runner.run(command, args);
  if (result.exitCode !== 0) {
    throw new Error(
      `LOCAL_CONTROLLED command failed: ${command} ${args.join(" ")}`,
    );
  }
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const action = process.argv[2];
  if (action === "up") await up();
  else if (action === "status") await status();
  else if (action === "down") await down();
  else throw new Error("Usage: local-stack.ts <up|status|down>");
}
