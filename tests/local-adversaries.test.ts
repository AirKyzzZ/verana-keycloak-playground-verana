import { afterEach, describe, expect, it, vi } from "vitest";

import { runLocalAdversaries } from "../scripts/verify-local-adversaries.js";

const CONTROL_TOKEN =
  "host-only-control-token-with-at-least-thirty-two-bytes-of-entropy";
const ACCOUNT_REF =
  "d35e6a2d30889d691db09e7ddfb36bb8c9caed53280837677f06ff679063b9d5";
const SUBJECT_REF =
  "5761b53b080a93a620e96186f669be72eae400da4619c50f74cc70dab26c6f2e";

function stableStatus() {
  return {
    count: 1 as const,
    user: {
      groups: ["/organizations/acme"],
      id: "user-1",
      roles: ["employee"],
      username: "pairwise-user",
      veranaSubject: "stable-pairwise-subject",
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("live controlled resolver adversaries", () => {
  it("passes the expected count to the default Keycloak reader before account details", async () => {
    const requests: string[] = [];
    vi.stubGlobal("fetch", async (input: string | URL | Request) => {
      const url = String(input);
      requests.push(url);
      if (url.endsWith("/protocol/openid-connect/token")) {
        return Response.json({ access_token: "bounded-admin-token" });
      }
      if (url.endsWith("/admin/realms/verana-playground/users/count")) {
        return Response.json(1);
      }
      return Response.json([]);
    });

    await expect(
      runLocalAdversaries(["--expect-count=0"], {
        armFault: async () => undefined,
        loadControlToken: async () => CONTROL_TOKEN,
        readFaultStatus: async () => ({ armed: false }),
        resetFault: async () => undefined,
        runRogueProbe: async () => undefined,
        runTrustedProbe: async () => undefined,
        write: () => undefined,
      }),
    ).rejects.toThrow("Keycloak user count mismatch");

    expect(requests).toEqual([
      "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
      "http://127.0.0.1:8080/admin/realms/verana-playground/users/count",
    ]);
  });

  it("runs each one-shot fault and rogue denial with unchanged sanitized mappings", async () => {
    const events: string[] = [];
    const output: string[] = [];

    await runLocalAdversaries(
      [
        "--expect-count=1",
        `--expect-account-ref=${ACCOUNT_REF}`,
        `--expect-subject-ref=${SUBJECT_REF}`,
      ],
      {
        armFault: async (mode, token) => {
          events.push(`arm:${mode}:${token === CONTROL_TOKEN}`);
        },
        loadControlToken: async () => CONTROL_TOKEN,
        readFaultStatus: async (token) => {
          events.push(`fault-status:${token === CONTROL_TOKEN}`);
          return { armed: false };
        },
        readKeycloakStatus: async () => {
          events.push("keycloak");
          return stableStatus();
        },
        resetFault: async (token) => {
          events.push(`reset:${token === CONTROL_TOKEN}`);
        },
        runRogueProbe: async () => {
          events.push("rogue");
        },
        runTrustedProbe: async (mode) => {
          events.push(`probe:${mode}`);
        },
        write: (line) => output.push(line),
      },
    );

    expect(events).toEqual([
      "keycloak",
      "arm:unavailable:true",
      "probe:unavailable",
      "fault-status:true",
      "reset:true",
      "keycloak",
      "arm:malformed-json:true",
      "probe:malformed-json",
      "fault-status:true",
      "reset:true",
      "keycloak",
      "arm:oversized-body:true",
      "probe:oversized-body",
      "fault-status:true",
      "reset:true",
      "keycloak",
      "rogue",
      "keycloak",
    ]);
    expect(output).toEqual([
      "PASS RESOLVER unavailable DENIED",
      "PASS RESOLVER malformed-json DENIED",
      "PASS RESOLVER oversized-body DENIED",
      "PASS ROGUE DENIED",
      "PASS LOCAL_CONTROLLED ADVERSARIAL",
    ]);
    expect(output.join("\n")).not.toMatch(
      /host-only|user-1|pairwise-user|stable-pairwise-subject|token|credential|cookie|secret/i,
    );
  });

  it("resets the armed fault in finally when the trusted probe fails", async () => {
    const events: string[] = [];

    await expect(
      runLocalAdversaries(["--expect-count=1"], {
        armFault: async (mode) => {
          events.push(`arm:${mode}`);
        },
        loadControlToken: async () => CONTROL_TOKEN,
        readFaultStatus: async () => ({ armed: false }),
        readKeycloakStatus: async () => stableStatus(),
        resetFault: async () => {
          events.push("reset");
        },
        runRogueProbe: async () => undefined,
        runTrustedProbe: async () => {
          events.push("probe");
          throw new Error("sensitive upstream response");
        },
        write: () => undefined,
      }),
    ).rejects.toThrow("LOCAL_CONTROLLED adversarial verification failed");

    expect(events).toEqual(["arm:unavailable", "probe", "reset"]);
  });

  it("attempts reset when arming has an ambiguous failure", async () => {
    let resets = 0;

    await expect(
      runLocalAdversaries(["--expect-count=0"], {
        armFault: async () => {
          throw new Error("ambiguous control response");
        },
        loadControlToken: async () => CONTROL_TOKEN,
        readFaultStatus: async () => ({ armed: false }),
        readKeycloakStatus: async () => ({ count: 0 }),
        resetFault: async () => {
          resets += 1;
        },
        runRogueProbe: async () => undefined,
        runTrustedProbe: async () => undefined,
        write: () => undefined,
      }),
    ).rejects.toThrow("LOCAL_CONTROLLED adversarial verification failed");

    expect(resets).toBe(1);
  });

  it("rejects a fault that remains armed after the probe and still performs reset", async () => {
    let resets = 0;

    await expect(
      runLocalAdversaries(["--expect-count=0"], {
        armFault: async () => undefined,
        loadControlToken: async () => CONTROL_TOKEN,
        readFaultStatus: async () => ({ armed: true }),
        readKeycloakStatus: async () => ({ count: 0 }),
        resetFault: async () => {
          resets += 1;
        },
        runRogueProbe: async () => undefined,
        runTrustedProbe: async () => undefined,
        write: () => undefined,
      }),
    ).rejects.toThrow("LOCAL_CONTROLLED resolver fault did not reset");

    expect(resets).toBe(1);
  });

  it("stops when the Keycloak reference changes after a denied case", async () => {
    let reads = 0;
    const changed = stableStatus();
    changed.user.id = "different-user";

    await expect(
      runLocalAdversaries(
        ["--expect-count=1", `--expect-account-ref=${ACCOUNT_REF}`],
        {
          armFault: async () => undefined,
          loadControlToken: async () => CONTROL_TOKEN,
          readFaultStatus: async () => ({ armed: false }),
          readKeycloakStatus: async () => {
            reads += 1;
            return reads === 1 ? stableStatus() : changed;
          },
          resetFault: async () => undefined,
          runRogueProbe: async () => undefined,
          runTrustedProbe: async () => undefined,
          write: () => undefined,
        },
      ),
    ).rejects.toThrow("LOCAL_CONTROLLED Keycloak mapping mismatch");

    expect(reads).toBe(2);
  });
});
