import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename as renamePath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  type CommandResult,
  type CommandRunner,
  down,
  type LifecycleDependencies,
  preflight,
  status,
  up,
} from "../scripts/local-stack.js";

const roots: string[] = [];

interface FakeBehavior {
  colimaDf?: string;
  colimaDfExitCode?: number;
  colimaDfThrows?: boolean;
  dockerContext?: string;
  dockerContextExitCode?: number;
  dockerContextThrows?: boolean;
  driverStatus?: string;
  nodeMajor?: number;
  portOwners?: Partial<Record<number, string>>;
  twitterRunning?: boolean;
  vsCommit?: string;
  vsRemote?: string;
  keycloakUsers?: number;
  hostToken?: string;
  failCommand?: readonly string[];
  failComposeDown?: boolean;
  failTwitterStart?: boolean;
  failTwitterStop?: boolean;
  failComposeBuild?: boolean;
  failComposeWait?: boolean;
  containers?: readonly {
    id: string;
    project: string;
    running: boolean;
  }[];
  volumes?: readonly {
    name: string;
    project: string;
  }[];
}

class FakeRunner implements CommandRunner {
  readonly calls: [string, readonly string[]][] = [];
  readonly sequence: string[] = [];
  onRun?: (command: string, args: readonly string[]) => void;
  readonly options: {
    command: string;
    args: readonly string[];
    options?: { cwd?: string; env?: NodeJS.ProcessEnv };
  }[] = [];
  private readonly behavior: Required<
    Pick<FakeBehavior, "nodeMajor" | "twitterRunning" | "vsCommit">
  > &
    FakeBehavior;
  private stackRunning = false;

  constructor(behavior: FakeBehavior = {}) {
    this.behavior = {
      driverStatus:
        '[["Backing Filesystem","ext4"],["Data Space Available","30GB"]]\n',
      nodeMajor: 24,
      twitterRunning: false,
      vsCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
      vsRemote: "https://github.com/verana-labs/vs-agent",
      keycloakUsers: 0,
      ...behavior,
    };
  }

  async run(
    command: string,
    args: readonly string[],
    options?: { cwd?: string; env?: NodeJS.ProcessEnv },
  ): Promise<CommandResult> {
    this.calls.push([command, args]);
    this.sequence.push(`${command}:${args.join(":")}`);
    this.onRun?.(command, args);
    this.options.push({ command, args, ...(options ? { options } : {}) });
    const envFileIndex = args.indexOf("--env-file");
    if (command === "docker" && args[0] === "compose" && envFileIndex >= 0) {
      const envFile = args[envFileIndex + 1];
      if (!envFile) {
        return {
          exitCode: 1,
          stdout: "",
          stderr: "Compose env file argument is missing",
        };
      }
      try {
        await stat(resolve(options?.cwd ?? process.cwd(), envFile));
      } catch {
        return {
          exitCode: 1,
          stdout: "",
          stderr: `Compose env file does not exist: ${envFile}`,
        };
      }
    }
    if (
      command === "docker" &&
      args.includes("build") &&
      this.behavior.failComposeBuild
    ) {
      return { exitCode: 1, stdout: "", stderr: "compose build failed" };
    }
    if (
      command === "docker" &&
      args.includes("down") &&
      this.behavior.failComposeDown
    ) {
      return { exitCode: 1, stdout: "", stderr: "compose down failed" };
    }
    if (
      command === "docker" &&
      args.includes("up") &&
      args.includes("--wait") &&
      this.behavior.failComposeWait
    ) {
      return { exitCode: 1, stdout: "", stderr: "compose wait failed" };
    }
    if (
      this.behavior.failCommand?.every((value, index) => args[index] === value)
    ) {
      return { exitCode: 1, stdout: "", stderr: "forced failure" };
    }
    if (command === "docker" && args[0] === "stop") {
      if (this.behavior.failTwitterStop) {
        return { exitCode: 1, stdout: "", stderr: "Twitter stop failed" };
      }
      this.behavior.twitterRunning = false;
    }
    if (command === "docker" && args[0] === "start") {
      if (this.behavior.failTwitterStart) {
        return { exitCode: 1, stdout: "", stderr: "Twitter restart failed" };
      }
      this.behavior.twitterRunning = true;
    }
    if (command === "docker" && args.includes("up")) this.stackRunning = true;
    if (command === "docker" && args.includes("down"))
      this.stackRunning = false;
    if (command === "docker" && args[0] === "ps") {
      const port = Number(
        args.find((arg) => arg.startsWith("publish="))?.slice(8),
      );
      const owner = this.ownerFor(port);
      return { exitCode: 0, stdout: owner ? `${owner}\n` : "", stderr: "" };
    }
    if (command === "docker" && args[0] === "container" && args[1] === "ls") {
      const project = this.composeProjectFilter(args);
      const includeStopped = args.includes("--all");
      const containers = (this.behavior.containers ?? []).filter(
        (container) =>
          (project === undefined || container.project === project) &&
          (includeStopped || container.running),
      );
      return {
        exitCode: 0,
        stdout: containers.map((container) => container.id).join("\n"),
        stderr: "",
      };
    }
    if (
      command === "docker" &&
      args[0] === "container" &&
      args[1] === "inspect"
    ) {
      return {
        exitCode: 0,
        stdout: this.behavior.twitterRunning ? "true\n" : "false\n",
        stderr: "",
      };
    }
    if (command === "docker" && args[0] === "info") {
      return {
        exitCode: 0,
        stdout: this.behavior.driverStatus ?? "[]\n",
        stderr: "",
      };
    }
    if (command === "docker" && args[0] === "context") {
      if (!this.hasExactArgs(args, ["context", "show"])) {
        throw new Error(`Unexpected fake command: docker ${args.join(" ")}`);
      }
      if (this.behavior.dockerContextThrows) {
        throw new Error("sensitive Docker context failure details");
      }
      return {
        exitCode: this.behavior.dockerContextExitCode ?? 0,
        stdout: `${this.behavior.dockerContext ?? "default"}\n`,
        stderr: "context command failure details must remain bounded",
      };
    }
    if (command === "colima") {
      if (
        !this.hasExactArgs(args, ["ssh", "--", "df", "-Pk", "/var/lib/docker"])
      ) {
        throw new Error(`Unexpected fake command: colima ${args.join(" ")}`);
      }
      if (this.behavior.colimaDfThrows) {
        throw new Error("sensitive Colima df failure details");
      }
      return {
        exitCode: this.behavior.colimaDfExitCode ?? 0,
        stdout: this.behavior.colimaDf ?? "",
        stderr: "colima command failure details must remain bounded",
      };
    }
    if (command === "docker" && args[0] === "volume") {
      const project = this.composeProjectFilter(args);
      return {
        exitCode: 0,
        stdout: (this.behavior.volumes ?? [])
          .filter(
            (volume) => project === undefined || volume.project === project,
          )
          .map((volume) => volume.name)
          .join("\n"),
        stderr: "",
      };
    }
    if (command === "git" && args.includes("merge-base")) {
      return {
        exitCode:
          this.behavior.vsCommit === "e2bba78746cb2c7ca7f43d28dc9641316f524d24"
            ? 0
            : 1,
        stdout: "",
        stderr: "",
      };
    }
    if (command === "git" && args.includes("remote")) {
      return { exitCode: 0, stdout: `${this.behavior.vsRemote}\n`, stderr: "" };
    }
    if (
      command === "git" &&
      args.includes("rev-parse") &&
      args.includes("HEAD")
    ) {
      return { exitCode: 0, stdout: `${this.behavior.vsCommit}\n`, stderr: "" };
    }
    if (command === "git" && args.includes("rev-parse")) {
      return { exitCode: 0, stdout: `${args[1]}\n`, stderr: "" };
    }
    if (command === "ps") {
      return {
        exitCode: 0,
        stdout: this.behavior.hostToken
          ? `node LOCAL_STACK_START_TOKEN=${this.behavior.hostToken}\n`
          : "node\n",
        stderr: "",
      };
    }
    return { exitCode: 0, stdout: "", stderr: "" };
  }

  composeUpCalls(): [string, readonly string[]][] {
    return this.calls.filter(
      ([command, args]) => command === "docker" && args.includes("up"),
    );
  }

  composeCalls(): [string, readonly string[]][] {
    return this.calls.filter(
      ([command, args]) => command === "docker" && args[0] === "compose",
    );
  }

  setHostToken(token: string): void {
    this.behavior.hostToken = token;
  }

  keycloakUserCount(): number {
    return this.behavior.keycloakUsers ?? 0;
  }

  setKeycloakUserCount(count: number): void {
    this.behavior.keycloakUsers = count;
  }

  private hasExactArgs(
    actual: readonly string[],
    expected: readonly string[],
  ): boolean {
    return (
      actual.length === expected.length &&
      actual.every((value, index) => value === expected[index])
    );
  }

  private composeProjectFilter(args: readonly string[]): string | undefined {
    const filterIndex = args.indexOf("--filter");
    if (filterIndex < 0) return undefined;
    const filter = args[filterIndex + 1];
    return filter?.replace(/^label=com\.docker\.compose\.project=/, "");
  }

  private ownerFor(port: number): string | undefined {
    if (
      this.stackRunning &&
      [3000, 3001, 3100, 3101, 3110, 3111, 3200, 3201].includes(port)
    ) {
      return "verana-keycloak-local-controlled-service";
    }
    if (this.behavior.twitterRunning && (port === 3000 || port === 3001)) {
      return "twitter-bot-vs-agent";
    }
    return this.behavior.portOwners?.[port];
  }
}

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "local-controlled-stack-"));
  roots.push(root);
  await mkdir(join(root, ".data"));
  return root;
}

const bundleFiles = [
  "ca.pem",
  "ca-key.pem",
  "server.pem",
  "server-key.pem",
] as const;

async function serializedIdentity(
  path: string,
): Promise<{ dev: string; ino: string }> {
  const details = await stat(path);
  return { dev: String(details.dev), ino: String(details.ino) };
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

function generatedData(
  environment = [
    "PAIRWISE_SUB_SECRET=test-secret-at-least-32-characters",
    "LOCAL_RESOLVER_CONTROL_TOKEN=test-control-token-with-at-least-thirty-two-bytes",
    "",
  ].join("\n"),
) {
  return {
    ".env": environment,
    "local-controlled.env": "EVIDENCE_MODE=LOCAL_CONTROLLED\n",
    "broker-jwks.json": "{}\n",
    "realm.json": "{}\n",
  };
}

function dependencies(
  runner: FakeRunner,
  root: string,
  options: {
    fetchCalls?: string[];
    launchFails?: boolean;
    signals?: number[];
    output?: string[];
  } = {},
): LifecycleDependencies {
  const signals = options.signals ?? [];
  return {
    root,
    vsSourcePath: "/tmp/reviewed-vs-agent",
    runner,
    nodeVersion: "v24.0.0",
    generateData: async () => generatedData(),
    // The gateway is a real TCP listener in production; the lifecycle tests
    // exercise ordering, not the socket.
    waitForGateway: async () => undefined,
    reserveTls: async ({ stagingParent }) => {
      const directory = await mkdtemp(join(stagingParent, "tls-"));
      await chmod(directory, 0o700);
      return { directory, identity: await serializedIdentity(directory) };
    },
    createTls: async ({ reservation }) => {
      for (const file of bundleFiles) {
        await writeFile(join(reservation.directory, file), `${file}\n`, {
          mode: 0o600,
        });
      }
      return {
        ...reservation,
        caCertificatePath: join(reservation.directory, "ca.pem"),
        caPrivateKeyPath: join(reservation.directory, "ca-key.pem"),
        serverCertificatePath: join(reservation.directory, "server.pem"),
        serverPrivateKeyPath: join(reservation.directory, "server-key.pem"),
        fileIdentities: {
          caCertificate: await serializedIdentity(
            join(reservation.directory, "ca.pem"),
          ),
          serverCertificate: await serializedIdentity(
            join(reservation.directory, "server.pem"),
          ),
          serverPrivateKey: await serializedIdentity(
            join(reservation.directory, "server-key.pem"),
          ),
        },
      };
    },
    launch: async ({ startToken }) => {
      if (options.launchFails) throw new Error("host start failed");
      return { pid: 4242, startToken };
    },
    signalProcessGroup: (pid) => signals.push(pid),
    fetch: async (input) => {
      const url = String(input);
      options.fetchCalls?.push(url);
      if (url.endsWith("/protocol/openid-connect/token")) {
        return Response.json({ access_token: "local-admin-token" });
      }
      if (url.endsWith("/admin/realms/verana-playground/users/count")) {
        return Response.json(runner.keycloakUserCount());
      }
      if (url.includes("/admin/realms/verana-playground/users?")) {
        return Response.json(
          Array.from({ length: runner.keycloakUserCount() }, () => ({
            attributes: {
              verana_subject: ["stable-pairwise-subject"],
            },
            id: "user-1",
            username: "pairwise-user",
          })),
        );
      }
      if (url.endsWith("/groups")) {
        return Response.json([{ path: "/organizations/acme" }]);
      }
      if (url.endsWith("/role-mappings/realm/composite")) {
        return Response.json([{ name: "employee" }]);
      }
      if (url.endsWith("/_local-controlled/resolver-fault")) {
        return Response.json({ armed: false });
      }
      return new Response("{}", { status: 200 });
    },
    randomToken: () => "verified-start-token",
    write: (line) => options.output?.push(line),
  };
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("guarded local controlled stack lifecycle", () => {
  it("restores Twitter but preserves unreadable state after its stopped-state write fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const output: string[] = [];
    const deps = dependencies(runner, root, { launchFails: true, output });
    const statePath = join(root, ".data", "local-stack-state.json");
    let statePublications = 0;
    deps.rename = async (source, destination) => {
      if (destination === statePath && ++statePublications === 6) {
        await rm(destination, { force: true });
        await writeFile(destination, "not valid lifecycle state\n");
        return;
      }
      await renamePath(source, destination);
    };

    await expect(up(deps)).rejects.toThrow();

    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
    await expect(readFile(statePath, "utf8")).resolves.toBe(
      "not valid lifecycle state\n",
    );
    expect(output.join("\n")).toContain("cleanup incomplete");
  });

  it("does not start Twitter when unreadable state was written before any stop", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const output: string[] = [];
    const deps = dependencies(runner, root, { output });
    const statePath = join(root, ".data", "local-stack-state.json");
    let statePublications = 0;
    deps.rename = async (source, destination) => {
      if (destination === statePath && ++statePublications === 2) {
        await rm(destination, { force: true });
        await writeFile(destination, "not valid lifecycle state\n");
        return;
      }
      await renamePath(source, destination);
    };

    await expect(up(deps)).rejects.toThrow();

    expect(runner.calls).not.toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
    expect(output.join("\n")).toContain("cleanup incomplete");
  });

  it("replaces a state symlink without writing through it", async () => {
    const root = await makeRoot();
    const outside = await mkdtemp(join(tmpdir(), "outside-local-controlled-"));
    roots.push(outside);
    const runner = new FakeRunner({
      twitterRunning: true,
      failComposeDown: true,
    });
    const statePath = join(root, ".data", "local-stack-state.json");
    const outsideState = join(outside, "state.json");
    await writeFile(outsideState, "outside state must survive\n");
    await symlink(outsideState, statePath);

    await expect(
      up(dependencies(runner, root, { launchFails: true })),
    ).rejects.toThrow("host start failed");

    await expect(readFile(outsideState, "utf8")).resolves.toBe(
      "outside state must survive\n",
    );
    expect((await lstat(statePath)).isSymbolicLink()).toBe(false);
    await expect(readFile(statePath, "utf8")).resolves.toContain(
      "twitterStopped",
    );
  });

  it("replaces a generated child symlink without writing through it", async () => {
    const root = await makeRoot();
    const outside = await mkdtemp(join(tmpdir(), "outside-local-controlled-"));
    roots.push(outside);
    const runner = new FakeRunner({ failComposeDown: true });
    const deps = dependencies(runner, root, { launchFails: true });
    const generatedEnvironment = join(root, ".data", ".env");
    const outsideEnvironment = join(outside, "outside.env");
    await writeFile(outsideEnvironment, "outside environment must survive\n");
    deps.rename = async (source, destination) => {
      if (destination === generatedEnvironment) {
        await symlink(outsideEnvironment, generatedEnvironment);
      }
      await renamePath(source, destination);
    };

    await expect(up(deps)).rejects.toThrow("host start failed");

    await expect(readFile(outsideEnvironment, "utf8")).resolves.toBe(
      "outside environment must survive\n",
    );
    expect((await lstat(generatedEnvironment)).isSymbolicLink()).toBe(false);
    await expect(readFile(generatedEnvironment, "utf8")).resolves.toContain(
      "PAIRWISE_SUB_SECRET=",
    );
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("ownedDataFiles");
  });

  it("generates controlled data in memory before publication", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    let receivedSourcePath: string | undefined;
    deps.generateData = async (vsSourcePath) => {
      receivedSourcePath = vsSourcePath;
      return generatedData();
    };

    await up(deps);

    expect(receivedSourcePath).toBe("/tmp/reviewed-vs-agent");
    await expect(readFile(join(root, ".data", ".env"), "utf8")).resolves.toBe(
      [
        "PAIRWISE_SUB_SECRET=test-secret-at-least-32-characters",
        "LOCAL_RESOLVER_CONTROL_TOKEN=test-control-token-with-at-least-thirty-two-bytes",
        "",
      ].join("\n"),
    );
  });

  it("writes no secret bytes when the data parent is replaced after temp-file open", async () => {
    const root = await makeRoot();
    const outside = await mkdtemp(join(tmpdir(), "outside-local-controlled-"));
    roots.push(outside);
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const dataDirectory = join(root, ".data");
    const recoveryDirectory = join(root, ".data-before-replacement");
    const outsideEnvironment = join(outside, ".env");
    const outsideState = join(outside, "local-stack-state.json");
    let openedTempFile: string | undefined;
    let parentReplaced = false;
    delete deps.generateData;
    await writeFile(outsideEnvironment, "outside environment sentinel\n");
    await writeFile(outsideState, "outside state sentinel\n");
    deps.afterTempFileOpen = async ({ label, path }) => {
      if (label !== "generated data file .env" || parentReplaced) return;
      openedTempFile = join(recoveryDirectory, basename(path));
      await renamePath(dataDirectory, recoveryDirectory);
      await symlink(outside, dataDirectory);
      parentReplaced = true;
    };

    await expect(up(deps)).rejects.toThrow(/identity changed|symlink/);

    expect(parentReplaced).toBe(true);
    await expect(readFile(outsideEnvironment, "utf8")).resolves.toBe(
      "outside environment sentinel\n",
    );
    await expect(readFile(outsideState, "utf8")).resolves.toBe(
      "outside state sentinel\n",
    );
    expect((await stat(openedTempFile as string)).size).toBe(0);
  });

  it("cleans owned state without Compose when first-file ownership publication fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const statePath = join(root, ".data", "local-stack-state.json");
    let statePublications = 0;
    deps.rename = async (source, destination) => {
      if (destination === statePath && ++statePublications === 2) {
        throw new Error("ownership state publication failed");
      }
      await renamePath(source, destination);
    };

    await expect(up(deps)).rejects.toThrow(
      "ownership state publication failed",
    );

    await expect(lstat(join(root, ".data", ".env"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(lstat(statePath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(
      runner
        .composeCalls()
        .filter(([, args]) => args.includes("build") || args.includes("down")),
    ).toEqual([]);
  });

  it("runs exact scoped teardown when the first Compose build was attempted", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ failComposeBuild: true });
    const deps = dependencies(runner, root);

    await expect(up(deps)).rejects.toThrow("docker compose");

    expect(runner.calls).toContainEqual([
      "docker",
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
      ],
    ]);
  });

  it("launches the host gateway between the Keycloak and agent Compose stages", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const events: string[] = [];
    const deps = dependencies(runner, root);
    const fetchImpl = deps.fetch;
    const launch = deps.launch;
    if (!fetchImpl || !launch) throw new Error("missing test dependency");
    runner.onRun = (command, args) => {
      if (command === "docker" && args.includes("up")) {
        events.push(
          args.includes("keycloak") ? "keycloak-wait" : "agents-wait",
        );
      }
    };
    deps.fetch = async (input, init) => {
      const url = String(input);
      if (
        url ===
        "http://127.0.0.1:8080/realms/verana-playground/.well-known/openid-configuration"
      ) {
        events.push("keycloak-http");
      }
      if (url === "http://127.0.0.1:3100/v1/health") {
        events.push("agents-http");
      }
      if (url.endsWith("/protocol/openid-connect/token")) {
        events.push("zero-user");
      }
      return await fetchImpl(input, init);
    };
    deps.waitForGateway = async () => {
      events.push("gateway-ready");
    };
    deps.launch = async (options) => {
      events.push("host-launch");
      return await launch(options);
    };

    await up(deps);

    const composeArgv = [
      "compose",
      "--project-name",
      "verana-keycloak-local-controlled",
      "--env-file",
      ".data/local-controlled.env",
      "-f",
      "compose.yaml",
      "-f",
      "compose.local-controlled.yaml",
      "up",
      "--wait",
      "--wait-timeout",
      "180",
      "--force-recreate",
    ];
    expect(runner.composeUpCalls()).toEqual([
      ["docker", [...composeArgv, "keycloak"]],
      ["docker", [...composeArgv, "issuer", "holder", "verifier"]],
    ]);
    // The agents resolve did:web, VCT and VTJSC through the host TLS gateway
    // while they start, so the gateway must accept connections before Compose
    // brings them up. Keycloak has no such dependency and starts first.
    expect(events).toEqual([
      "keycloak-wait",
      "keycloak-http",
      "host-launch",
      "gateway-ready",
      "agents-wait",
      "agents-http",
      "zero-user",
    ]);
  });

  it("cleans generated state and restores Twitter when Compose wait fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      failComposeWait: true,
      twitterRunning: true,
    });
    const fetchCalls: string[] = [];
    let hostLaunched = false;
    const deps = dependencies(runner, root, { fetchCalls });
    deps.launch = async () => {
      hostLaunched = true;
      return { pid: 4242, startToken: "unexpected-host-launch" };
    };

    await expect(up(deps)).rejects.toThrow("docker compose");

    expect(runner.composeUpCalls()).toEqual([
      [
        "docker",
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
          "up",
          "--wait",
          "--wait-timeout",
          "180",
          "--force-recreate",
          "keycloak",
        ],
      ],
    ]);
    expect(runner.calls).toContainEqual([
      "docker",
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
      ],
    ]);
    expect(fetchCalls).toEqual([]);
    expect(hostLaunched).toBe(false);
    await expect(readdir(join(root, ".data"))).resolves.toEqual([]);
    expect(runner.calls).toContainEqual([
      "docker",
      ["stop", "twitter-bot-vs-agent"],
    ]);
    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
  });

  it("preserves a replacement inserted after a generated-data rename", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const generatedEnvironment = join(root, ".data", ".env");
    deps.afterTempFileRename = async ({ label, path }) => {
      if (label === "generated data file .env") {
        await rm(path);
        await writeFile(path, "replacement must survive\n");
        throw new Error("post-rename verification failed");
      }
    };

    await expect(up(deps)).rejects.toThrow("post-rename verification failed");

    await expect(readFile(generatedEnvironment, "utf8")).resolves.toBe(
      "replacement must survive\n",
    );
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("ownedDataFiles");
  });

  it("cleans an opened temp file when a pre-write hook fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    deps.afterTempFileOpen = async ({ label }) => {
      if (label === "state file") {
        throw new Error("pre-write hook failed");
      }
    };

    await expect(up(deps)).rejects.toThrow("pre-write hook failed");

    expect(
      (await readdir(join(root, ".data"))).filter((entry) =>
        entry.startsWith(".local-stack-temp-"),
      ),
    ).toEqual([]);
  });

  it("stops only the expected Twitter container and records restoration state", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      twitterRunning: true,
      portOwners: {
        3000: "twitter-bot-vs-agent",
        3001: "twitter-bot-vs-agent",
      },
    });

    await up(dependencies(runner, root));

    expect(runner.calls).toContainEqual([
      "docker",
      ["stop", "twitter-bot-vs-agent"],
    ]);
    expect(
      runner.calls.some(
        ([command, args]) =>
          command === "docker" && args.includes("twitter-bot-redis"),
      ),
    ).toBe(false);
    expect(
      JSON.parse(
        await readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
      ),
    ).toMatchObject({
      version: 2,
      composeProject: "verana-keycloak-local-controlled",
      twitterWasRunning: true,
      hostProcess: { pid: 4242, startToken: "verified-start-token" },
      ownedTls: { phase: "published" },
    });
  });

  it.each<[string, FakeBehavior]>([
    ["unknown owner", { portOwners: { 3000: "another-project" } }],
    ["wrong VS repository", { vsRemote: "https://github.com/other/vs-agent" }],
    ["wrong VS commit", { vsCommit: "deadbeef" }],
    ["Node 23", { nodeMajor: 23 }],
    [
      "insufficient disk",
      { driverStatus: '[["Data Space Available","1B"]]\n' },
    ],
  ])("fails preflight before Compose for %s", async (_name, behavior) => {
    const root = await makeRoot();
    const runner = new FakeRunner(behavior);
    const deps = dependencies(runner, root);
    deps.nodeVersion = `v${behavior.nodeMajor ?? 24}.0.0`;

    await expect(up(deps)).rejects.toThrow(
      _name === "unknown owner"
        ? "port 3000"
        : _name === "wrong VS repository"
          ? "expected Git repository"
          : _name === "wrong VS commit"
            ? "merge-base"
            : _name === "Node 23"
              ? "Node.js 24"
              : "insufficient free disk",
    );
    expect(runner.composeUpCalls()).toHaveLength(0);
  });

  it("does not restart Twitter when it was initially stopped", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: false });

    await up(dependencies(runner, root));
    await down(dependencies(runner, root));

    expect(runner.calls).not.toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
  });

  it("restores Twitter only when the recorded stack found it running", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const deps = dependencies(runner, root);

    await up(deps);
    runner.setHostToken("verified-start-token");
    await down(deps);

    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
  });

  it("uses the exact project teardown argv and no global Docker cleanup", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);

    await up(deps);
    runner.setHostToken("verified-start-token");
    await down(deps);

    expect(runner.calls).toContainEqual([
      "docker",
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
      ],
    ]);
    expect(
      runner.calls
        .flatMap(([command, args]) => [command, ...args].join(" "))
        .join("\n"),
    ).not.toMatch(/\b(prune|image rm|twitter-bot-redis)\b/);
  });

  it("rejects a symlinked data directory before mutating it", async () => {
    const root = await makeRoot();
    await rm(join(root, ".data"), { recursive: true });
    const outside = await mkdtemp(join(tmpdir(), "outside-local-controlled-"));
    roots.push(outside);
    await symlink(outside, join(root, ".data"));
    const runner = new FakeRunner({ driverStatus: "[]\n" });

    await expect(preflight(dependencies(runner, root))).rejects.toThrow(
      "symlink",
    );
    expect(runner.calls).toHaveLength(0);
  });

  it("rejects an external data path before a teardown can delete it", async () => {
    const root = await makeRoot();
    const outside = await mkdtemp(join(tmpdir(), "outside-local-controlled-"));
    roots.push(outside);
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    deps.dataDirectory = outside;

    await expect(down(deps)).rejects.toThrow("outside the repository");
    expect(runner.calls).toHaveLength(0);
  });

  it("preserves unrelated regular data and directories during teardown", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const unrelatedFile = join(root, ".data", "notes.txt");
    const unrelatedDirectory = join(root, ".data", "manual-artifacts");

    await up(deps);
    await writeFile(unrelatedFile, "keep me");
    await mkdir(unrelatedDirectory);
    await writeFile(join(unrelatedDirectory, "record.txt"), "keep me too");
    runner.setHostToken("verified-start-token");
    await down(deps);

    await expect(readFile(unrelatedFile, "utf8")).resolves.toBe("keep me");
    await expect(
      readFile(join(unrelatedDirectory, "record.txt"), "utf8"),
    ).resolves.toBe("keep me too");
  });

  it("does not start Twitter when data generation fails before this run stops it", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const deps = dependencies(runner, root);
    deps.generateData = async () => {
      throw new Error("generated data failed");
    };

    await expect(up(deps)).rejects.toThrow("generated data failed");

    expect(runner.calls).not.toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
  });

  it("does not start Twitter when the exact Twitter stop fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      twitterRunning: true,
      failTwitterStop: true,
    });

    await expect(up(dependencies(runner, root))).rejects.toThrow("docker stop");

    expect(runner.calls).not.toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
  });

  it("restores Twitter after an environment failure that follows a successful stop", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const deps = dependencies(runner, root);
    deps.generateData = async () => generatedData("NODE_OPTIONS=--inspect\n");

    await expect(up(deps)).rejects.toThrow("host environment override");

    expect(runner.calls).toContainEqual([
      "docker",
      ["stop", "twitter-bot-vs-agent"],
    ]);
    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
  });

  it("restores Twitter even when Compose teardown fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      twitterRunning: true,
      failComposeDown: true,
    });
    const deps = dependencies(runner, root, { launchFails: true });

    await expect(up(deps)).rejects.toThrow("host start failed");

    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("twitterWasRunning");
  });

  it("restores Twitter and preserves recovery state when owned data cleanup fails", async () => {
    const root = await makeRoot();
    const outside = await mkdtemp(join(tmpdir(), "outside-local-controlled-"));
    roots.push(outside);
    const runner = new FakeRunner({ twitterRunning: true });
    const deps = dependencies(runner, root);

    await up(deps);
    expect(
      JSON.parse(
        await readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
      ).ownedDataFiles,
    ).toContain(".env");
    await rm(join(root, ".data", ".env"));
    await symlink(outside, join(root, ".data", ".env"));
    runner.setHostToken("verified-start-token");

    await expect(down(deps)).rejects.toThrow();
    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("twitterWasRunning");
  });

  it("preserves recovery state when Twitter restoration fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      twitterRunning: true,
      failTwitterStart: true,
    });
    const deps = dependencies(runner, root);

    await up(deps);
    runner.setHostToken("verified-start-token");

    await expect(down(deps)).rejects.toThrow("docker start");
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("twitterWasRunning");
  });

  it("preserves an owned-file replacement that races lifecycle cleanup", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const ownedFile = join(root, ".data", ".env");

    await up(deps);
    runner.setHostToken("verified-start-token");
    deps.rename = async (source, destination) => {
      if (source === ownedFile) {
        await rm(source);
        await writeFile(source, "replacement");
      }
      await renamePath(source, destination);
    };

    await expect(down(deps)).rejects.toThrow("changed during quarantine");
    await expect(readFile(ownedFile, "utf8")).resolves.toBe("replacement");
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("twitterStopped");
  });

  it("preserves a lifecycle-directory replacement that races cleanup", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const lifecycleDirectory = join(root, ".data", "local-stack");

    await up(deps);
    await writeFile(join(lifecycleDirectory, "host-process.log"), "owned log");
    runner.setHostToken("verified-start-token");
    deps.rename = async (source, destination) => {
      if (source === lifecycleDirectory) {
        await rm(source, { recursive: true });
        await mkdir(source);
        await writeFile(join(source, "replacement.log"), "replacement");
      }
      await renamePath(source, destination);
    };

    await expect(down(deps)).rejects.toThrow("changed during quarantine");
    await expect(
      readFile(join(lifecycleDirectory, "replacement.log"), "utf8"),
    ).resolves.toBe("replacement");
  });

  it("runs every Compose operation from the validated repository root", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);

    await up(deps);
    runner.setHostToken("verified-start-token");
    await down(deps);

    expect(
      runner.options
        .filter(
          ({ command, args }) => command === "docker" && args[0] === "compose",
        )
        .every(({ options }) => options?.cwd === root),
    ).toBe(true);
  });

  it("rejects generated environment attempts to override host invariants", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    deps.generateData = async () =>
      generatedData("PATH=/attacker\nNODE_OPTIONS=--inspect\n");

    await expect(up(deps)).rejects.toThrow("host environment override");
  });

  it("runs fresh preflight without generated Compose config", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();

    await expect(preflight(dependencies(runner, root))).resolves.toEqual({
      twitterWasRunning: false,
      vsSourceCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
    });

    await expect(
      lstat(join(root, ".data", "local-controlled.env")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    expect(runner.calls).toContainEqual([
      "docker",
      [
        "container",
        "ls",
        "--all",
        "--filter",
        "label=com.docker.compose.project=verana-keycloak-local-controlled",
        "--format",
        "{{.ID}}",
      ],
    ]);
    expect(runner.calls).toContainEqual([
      "docker",
      [
        "volume",
        "ls",
        "--filter",
        "label=com.docker.compose.project=verana-keycloak-local-controlled",
        "--format",
        "{{.Name}}",
      ],
    ]);
    expect(runner.composeCalls()).toEqual([["docker", ["compose", "version"]]]);
    expect(runner.calls.flatMap(([, args]) => args)).not.toContain(
      ".data/local-controlled.env",
    );
  });

  it("rejects a stopped exact-project container before build", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      containers: [
        {
          id: "stopped-keycloak-container",
          project: "verana-keycloak-local-controlled",
          running: false,
        },
      ],
    });

    await expect(up(dependencies(runner, root))).rejects.toThrow(
      "partial state",
    );
    expect(runner.composeUpCalls()).toHaveLength(0);
  });

  it("rejects exact-project leftover volumes before build", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      volumes: [
        {
          name: "verana-keycloak-local-controlled_issuer-afj",
          project: "verana-keycloak-local-controlled",
        },
      ],
    });

    await expect(up(dependencies(runner, root))).rejects.toThrow(
      "leftover volume",
    );
    expect(runner.composeUpCalls()).toHaveLength(0);
  });

  it("ignores containers and volumes from another Compose project", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      containers: [
        {
          id: "other-project-container",
          project: "other-project",
          running: false,
        },
      ],
      volumes: [
        {
          name: "other-project-data",
          project: "other-project",
        },
      ],
    });

    await expect(preflight(dependencies(runner, root))).resolves.toEqual({
      twitterWasRunning: false,
      vsSourceCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
    });
  });

  it("fails closed when Docker runtime capacity cannot be determined", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ driverStatus: "[]\n" });

    await expect(up(dependencies(runner, root))).rejects.toThrow(
      "capacity cannot be determined",
    );
    expect(runner.composeUpCalls()).toHaveLength(0);
  });

  it("uses exact Colima df capacity when containerd DriverStatus omits data space", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      driverStatus: '[["driver-type","io.containerd.snapshotter.v1"]]\n',
      dockerContext: "colima",
      colimaDf:
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 62567696 6000000 56558896 10% /\n",
    });

    await expect(preflight(dependencies(runner, root))).resolves.toEqual({
      twitterWasRunning: false,
      vsSourceCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
    });

    expect(runner.calls).toContainEqual(["docker", ["context", "show"]]);
    expect(runner.options).toContainEqual({
      command: "colima",
      args: ["ssh", "--", "df", "-Pk", "/var/lib/docker"],
      options: { cwd: root },
    });
  });

  it("rejects insufficient Colima capacity before mutation", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      driverStatus: '[["driver-type","io.containerd.snapshotter.v1"]]\n',
      dockerContext: "colima",
      colimaDf:
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 10000000 1611393 8388607 17% /\n",
    });

    await expect(preflight(dependencies(runner, root))).rejects.toThrow(
      "LOCAL_CONTROLLED has insufficient free disk capacity",
    );
    expect(runner.composeUpCalls()).toHaveLength(0);
  });

  it.each([
    [
      "missing filesystem row",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n",
    ],
    [
      "ambiguous filesystem rows",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 62567696 6000000 56558896 10% /\n/dev/vda2 62567696 6000000 56558896 10% /var/lib/docker\n",
    ],
    [
      "non-numeric available blocks",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 62567696 6000000 unknown 10% /\n",
    ],
    [
      "unsafe available blocks",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 9007199254740992 0 9007199254740992 0% /\n",
    ],
    [
      "used blocks greater than total blocks",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 10000000 10000001 0 100% /\n",
    ],
    [
      "available blocks greater than total blocks",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1 0 9000000 0% /\n",
    ],
    [
      "used and available blocks greater than total blocks",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 10000000 2000000 9000000 20% /\n",
    ],
    [
      "unsafe used and available block addition",
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 9007199254740991 9007199254740991 8388608 100% /\n",
    ],
  ])("fails closed for %s in Colima df output", async (_name, colimaDf) => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      driverStatus: '[["driver-type","io.containerd.snapshotter.v1"]]\n',
      dockerContext: "colima",
      colimaDf,
    });

    await expect(preflight(dependencies(runner, root))).rejects.toThrow(
      "LOCAL_CONTROLLED Docker runtime capacity cannot be determined",
    );
    expect(runner.composeUpCalls()).toHaveLength(0);
  });

  it("does not inspect Colima for a non-Colima Docker context", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      driverStatus: '[["driver-type","io.containerd.snapshotter.v1"]]\n',
      dockerContext: "desktop-linux",
    });

    await expect(preflight(dependencies(runner, root))).rejects.toThrow(
      "LOCAL_CONTROLLED Docker runtime capacity cannot be determined",
    );
    expect(runner.calls.some(([command]) => command === "colima")).toBe(false);
  });

  it.each([
    ["Docker context command", { dockerContextExitCode: 1 }],
    ["Colima df command", { dockerContext: "colima", colimaDfExitCode: 1 }],
  ] satisfies readonly [string, FakeBehavior][])(
    "fails closed with a static error when the %s fails",
    async (_name, behavior) => {
      const root = await makeRoot();
      const runner = new FakeRunner({
        driverStatus: '[["driver-type","io.containerd.snapshotter.v1"]]\n',
        ...behavior,
      });

      await expect(preflight(dependencies(runner, root))).rejects.toMatchObject(
        {
          message:
            "LOCAL_CONTROLLED Docker runtime capacity cannot be determined",
        },
      );
      expect(runner.composeUpCalls()).toHaveLength(0);
    },
  );

  it.each([
    ["Docker context command", { dockerContextThrows: true }],
    ["Colima df command", { dockerContext: "colima", colimaDfThrows: true }],
  ] satisfies readonly [string, FakeBehavior][])(
    "fails closed with the exact static error when the %s throws",
    async (_name, behavior) => {
      const root = await makeRoot();
      const runner = new FakeRunner({
        driverStatus: '[["driver-type","io.containerd.snapshotter.v1"]]\n',
        ...behavior,
      });

      await expect(preflight(dependencies(runner, root))).rejects.toMatchObject(
        {
          message:
            "LOCAL_CONTROLLED Docker runtime capacity cannot be determined",
        },
      );
      expect(runner.composeUpCalls()).toHaveLength(0);
    },
  );

  it("preserves the legacy DriverStatus capacity fast path without fallback", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      driverStatus:
        '[["Backing Filesystem","ext4"],["Data Space Available","30GB"]]\n',
    });

    await expect(preflight(dependencies(runner, root))).resolves.toEqual({
      twitterWasRunning: false,
      vsSourceCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
    });

    expect(runner.calls).not.toContainEqual(["docker", ["context", "show"]]);
    expect(runner.calls.some(([command]) => command === "colima")).toBe(false);
  });

  it("chmods an existing lifecycle state file to 0600", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const statePath = join(root, ".data", "local-stack-state.json");
    await writeFile(
      statePath,
      JSON.stringify({
        version: 2,
        composeProject: "verana-keycloak-local-controlled",
        twitterWasRunning: false,
        twitterStopped: false,
        composeTouched: false,
        ownedDataFiles: [],
        vsSourceCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
        startedAt: "2026-07-24T00:00:00.000Z",
      }),
    );
    await chmod(statePath, 0o644);

    await up(dependencies(runner, root));

    expect((await stat(statePath)).mode & 0o777).toBe(0o600);
  });

  it("waits for a verified host process to exit before Compose teardown", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const order: string[] = [];
    const deps = dependencies(runner, root, { signals: [] });
    runner.onRun = (command, args) => {
      if (command === "docker" && args.includes("down")) {
        order.push("compose-down");
      }
    };
    let checks = 0;
    deps.isProcessRunning = async () => {
      checks += 1;
      order.push(`check-${checks}`);
      return checks === 1;
    };
    deps.sleep = async () => {
      order.push("sleep");
    };

    await up(deps);
    runner.setHostToken("verified-start-token");
    await down(deps);

    expect(order).toEqual(["check-1", "sleep", "check-2", "compose-down"]);
  });

  it("times out host shutdown without deleting state and still restores Twitter", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const deps = dependencies(runner, root);
    deps.isProcessRunning = async () => true;
    deps.sleep = async () => undefined;

    await up(deps);
    runner.setHostToken("verified-start-token");

    await expect(down(deps)).rejects.toThrow("host process did not exit");
    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
    await expect(
      readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
    ).resolves.toContain("twitterWasRunning");
  });

  it("reports stale host metadata without killing an unrelated process", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const signals: number[] = [];
    const output: string[] = [];
    const deps = dependencies(runner, root, { signals, output });

    await up(deps);
    await down(deps);

    expect(signals).toEqual([]);
    expect(output.join("\n")).toContain("stale host process metadata");
  });

  it("reports ports clear after teardown when Twitter was initially stopped", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const output: string[] = [];
    const deps = dependencies(runner, root, { output });

    await up(deps);
    runner.setHostToken("verified-start-token");
    await down(deps);
    const stackStatus = await status(deps);

    expect(stackStatus.portsClear).toBe(true);
    expect(output.join("\n")).toContain("LOCAL_CONTROLLED ports clear");
  });

  it("reports inactive lifecycle and ports without reading Keycloak or fault state", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const output: string[] = [];
    const fetchCalls: string[] = [];
    const deps = dependencies(runner, root, { fetchCalls, output });

    const stackStatus = await status(deps);

    expect(stackStatus).toEqual({ active: false, portsClear: true });
    expect(output).toEqual([
      "LOCAL_CONTROLLED lifecycle inactive",
      "LOCAL_CONTROLLED ports clear",
    ]);
    expect(fetchCalls).toEqual([]);
  });

  it("reports active lifecycle, occupied ports, sanitized users, and resolver fault state", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const output: string[] = [];
    const deps = dependencies(runner, root, { output });

    await up(deps);
    output.length = 0;
    runner.setKeycloakUserCount(1);

    const stackStatus = await status(deps);

    expect(stackStatus.active).toBe(true);
    expect(stackStatus.portsClear).toBe(false);
    expect(output).toEqual([
      "LOCAL_CONTROLLED lifecycle active",
      "LOCAL_CONTROLLED ports occupied",
      "LOCAL_CONTROLLED TLS material published",
      "KEYCLOAK USERS 1",
      "KEYCLOAK ACCOUNT_REF d35e6a2d30889d691db09e7ddfb36bb8c9caed53280837677f06ff679063b9d5",
      "KEYCLOAK SUBJECT_REF 5761b53b080a93a620e96186f669be72eae400da4619c50f74cc70dab26c6f2e",
      "PASS KEYCLOAK GROUP ACME",
      "PASS KEYCLOAK ROLE employee",
      "PASS KEYCLOAK SUBJECT mapped",
      "LOCAL_CONTROLLED resolver fault unarmed",
    ]);
    expect(output.join("\n")).not.toMatch(
      /user-1|pairwise-user|stable-pairwise-subject|test-control-token|credential|cookie|secret/i,
    );
  });

  it("scopes cleanup and restoration after a partial startup failure", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ twitterRunning: true });
    const deps = dependencies(runner, root, { launchFails: true });

    await expect(up(deps)).rejects.toThrow("host start failed");

    expect(runner.calls).toContainEqual([
      "docker",
      ["stop", "twitter-bot-vs-agent"],
    ]);
    expect(
      runner.calls.some(
        ([command, args]) => command === "docker" && args.includes("down"),
      ),
    ).toBe(true);
    expect(runner.calls).toContainEqual([
      "docker",
      ["start", "twitter-bot-vs-agent"],
    ]);
    await expect(readdir(join(root, ".data"))).resolves.toEqual([]);
  });

  it("fails closed and tears down when Keycloak already has a user", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({ keycloakUsers: 1 });

    await expect(up(dependencies(runner, root))).rejects.toThrow(
      "Keycloak must start with zero users",
    );
    expect(
      runner.calls.some(
        ([command, args]) => command === "docker" && args.includes("down"),
      ),
    ).toBe(true);
  });

  it("prints a local boundary without generated secrets", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const output: string[] = [];

    await up(dependencies(runner, root, { output }));

    expect(output.join("\n")).toContain("LOCAL_CONTROLLED");
    expect(output.join("\n")).toContain("http://127.0.0.1:3000");
    expect(output.join("\n")).toContain(
      "LOCAL_CONTROLLED stack active; browser authentication not verified",
    );
    expect(output.join("\n")).not.toContain("browser authentication verified");
    expect(output.join("\n")).not.toContain(
      "test-secret-at-least-32-characters",
    );
    expect(output.join("\n")).not.toContain(
      "test-control-token-with-at-least-thirty-two-bytes",
    );
  });

  it("journals the TLS reservation before any key material exists", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const createTls = deps.createTls;
    if (!createTls) throw new Error("missing test dependency");
    let journalled: unknown;
    let publishedTooEarly = true;
    deps.createTls = async (options) => {
      journalled = JSON.parse(
        await readFile(join(root, ".data", "local-stack-state.json"), "utf8"),
      );
      publishedTooEarly = await exists(join(root, ".data", "tls"));
      return await createTls(options);
    };

    await up(deps);

    expect(publishedTooEarly).toBe(false);
    expect(journalled).toMatchObject({
      version: 2,
      ownedTls: { phase: "reserved" },
    });
    expect(journalled).not.toMatchObject({ ownedTls: { fileIdentities: {} } });
  });

  it("publishes the bundle and injects only host TLS paths", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    let environment: NodeJS.ProcessEnv | undefined;
    deps.launch = async ({ startToken, environment: launched }) => {
      environment = launched;
      return { pid: 4242, startToken };
    };

    await up(deps);

    const tlsDirectory = join(root, ".data", "tls");
    expect((await readdir(tlsDirectory)).sort()).toEqual(
      [...bundleFiles].sort(),
    );
    expect(environment?.LOCAL_TLS_CERTIFICATE_PATH).toBe(
      join(tlsDirectory, "server.pem"),
    );
    expect(environment?.LOCAL_TLS_PRIVATE_KEY_PATH).toBe(
      join(tlsDirectory, "server-key.pem"),
    );
    expect(
      JSON.parse(environment?.LOCAL_TLS_CERTIFICATE_IDENTITY ?? "null"),
    ).toEqual(await serializedIdentity(join(tlsDirectory, "server.pem")));
    expect(
      JSON.parse(environment?.LOCAL_TLS_PRIVATE_KEY_IDENTITY ?? "null"),
    ).toEqual(await serializedIdentity(join(tlsDirectory, "server-key.pem")));
  });

  it("deletes every generated TLS file without touching the Twitter container", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);

    await up(deps);
    runner.setHostToken("verified-start-token");
    await down(deps);

    expect(await exists(join(root, ".data", "tls"))).toBe(false);
    await expect(readdir(join(root, ".data"))).resolves.toEqual([]);
    expect(
      runner.calls.filter(
        ([command, args]) =>
          command === "docker" && (args[0] === "stop" || args[0] === "start"),
      ),
    ).toEqual([]);
  });

  it("removes a journalled reservation when certificate generation fails", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    deps.createTls = async () => {
      throw new Error("openssl generation failed");
    };

    await expect(up(deps)).rejects.toThrow("openssl generation failed");

    await expect(readdir(join(root, ".data"))).resolves.toEqual([]);
    expect(
      runner
        .composeCalls()
        .filter(([, args]) => args.includes("build") || args.includes("up")),
    ).toEqual([]);
  });

  it("refuses a replaced CA bind source before Compose", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const createTls = deps.createTls;
    if (!createTls) throw new Error("missing test dependency");
    deps.createTls = async (options) => {
      const bundle = await createTls(options);
      await rm(bundle.caCertificatePath);
      await writeFile(bundle.caCertificatePath, "replaced ca\n", {
        mode: 0o600,
      });
      return bundle;
    };

    await expect(up(deps)).rejects.toThrow(
      "TLS bind source changed before Compose",
    );

    await expect(readdir(join(root, ".data"))).resolves.toEqual([]);
    expect(
      runner
        .composeCalls()
        .filter(([, args]) => args.includes("build") || args.includes("up")),
    ).toEqual([]);
  });

  it("refuses to replace existing TLS material", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    const preexisting = join(root, ".data", "tls");
    await mkdir(preexisting);
    await writeFile(join(preexisting, "keep.pem"), "keep me");

    await expect(up(deps)).rejects.toThrow(
      "refuses to replace existing TLS material",
    );

    await expect(readFile(join(preexisting, "keep.pem"), "utf8")).resolves.toBe(
      "keep me",
    );
  });

  it("refuses a generated environment that overrides host TLS material", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner();
    const deps = dependencies(runner, root);
    deps.generateData = async () =>
      generatedData("LOCAL_TLS_PRIVATE_KEY_PATH=/tmp/rogue-key.pem\n");

    await expect(up(deps)).rejects.toThrow(
      "host environment override is forbidden: LOCAL_TLS_PRIVATE_KEY_PATH",
    );
  });

  it("guards the TLS gateway port before startup", async () => {
    const root = await makeRoot();
    const runner = new FakeRunner({
      portOwners: { 3443: "unrelated-gateway" },
    });

    await expect(preflight(dependencies(runner, root))).rejects.toThrow(
      "port 3443 is occupied by unrelated-gateway",
    );
  });
});
