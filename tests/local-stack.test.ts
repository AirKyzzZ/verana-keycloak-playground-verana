import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
  freeBytes?: number;
  nodeMajor?: number;
  portOwners?: Partial<Record<number, string>>;
  twitterRunning?: boolean;
  vsCommit?: string;
  vsRemote?: string;
  keycloakUsers?: number;
  hostToken?: string;
  failCommand?: readonly string[];
}

class FakeRunner implements CommandRunner {
  readonly calls: [string, readonly string[]][] = [];
  private readonly behavior: Required<
    Pick<
      FakeBehavior,
      "freeBytes" | "nodeMajor" | "twitterRunning" | "vsCommit"
    >
  > &
    FakeBehavior;
  private stackRunning = false;

  constructor(behavior: FakeBehavior = {}) {
    this.behavior = {
      freeBytes: 30_000_000_000,
      nodeMajor: 24,
      twitterRunning: false,
      vsCommit: "e2bba78746cb2c7ca7f43d28dc9641316f524d24",
      vsRemote: "https://github.com/verana-labs/vs-agent",
      keycloakUsers: 0,
      ...behavior,
    };
  }

  async run(command: string, args: readonly string[]): Promise<CommandResult> {
    this.calls.push([command, args]);
    if (
      this.behavior.failCommand?.every((value, index) => args[index] === value)
    ) {
      return { exitCode: 1, stdout: "", stderr: "forced failure" };
    }
    if (command === "docker" && args[0] === "stop") {
      this.behavior.twitterRunning = false;
    }
    if (command === "docker" && args[0] === "start") {
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
    if (command === "docker" && args[0] === "system") {
      return {
        exitCode: 0,
        stdout: JSON.stringify({ freeBytes: this.behavior.freeBytes }),
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

  setHostToken(token: string): void {
    this.behavior.hostToken = token;
  }

  keycloakUserCount(): number {
    return this.behavior.keycloakUsers ?? 0;
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

function dependencies(
  runner: FakeRunner,
  root: string,
  options: {
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
    generateData: async (output) => {
      await writeFile(
        join(output, ".env"),
        "PAIRWISE_SUB_SECRET=test-secret-at-least-32-characters\n",
      );
      await writeFile(
        join(output, "local-controlled.env"),
        "EVIDENCE_MODE=LOCAL_CONTROLLED\n",
      );
    },
    launch: async ({ startToken }) => {
      if (options.launchFails) throw new Error("host start failed");
      return { pid: 4242, startToken };
    },
    signalProcessGroup: (pid) => signals.push(pid),
    fetch: async (input) => {
      const url = String(input);
      if (url.endsWith("/protocol/openid-connect/token")) {
        return Response.json({ access_token: "local-admin-token" });
      }
      if (url.includes("/admin/realms/verana-playground/users")) {
        return Response.json(
          Array.from({ length: runner.keycloakUserCount() }, () => ({})),
        );
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
      version: 1,
      composeProject: "verana-keycloak-local-controlled",
      twitterWasRunning: true,
      hostProcess: { pid: 4242, startToken: "verified-start-token" },
    });
  });

  it.each<[string, FakeBehavior]>([
    ["unknown owner", { portOwners: { 3000: "another-project" } }],
    ["wrong VS repository", { vsRemote: "https://github.com/other/vs-agent" }],
    ["wrong VS commit", { vsCommit: "deadbeef" }],
    ["Node 23", { nodeMajor: 23 }],
    ["insufficient disk", { freeBytes: 1 }],
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
    const runner = new FakeRunner();

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
    expect(output.join("\n")).not.toContain(
      "test-secret-at-least-32-characters",
    );
  });
});
