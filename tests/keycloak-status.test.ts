import { describe, expect, it } from "vitest";

import {
  parseKeycloakStatusArguments,
  runKeycloakStatus,
} from "../scripts/keycloak-status.js";

const ACCOUNT_REF =
  "d35e6a2d30889d691db09e7ddfb36bb8c9caed53280837677f06ff679063b9d5";
const SUBJECT_REF =
  "5761b53b080a93a620e96186f669be72eae400da4619c50f74cc70dab26c6f2e";

describe("sanitized Keycloak status command", () => {
  it.each([
    { args: [] },
    { args: ["--expect-count=2"] },
    { args: ["--expect-count"] },
    { args: ["--expect-count=1", "--expect-count=1"] },
    { args: ["--expect-count=0", "--unknown=value"] },
    { args: ["--expect-count=1", "--expect-account-ref=not-a-hash"] },
    {
      args: [
        "--expect-count=1",
        `--expect-account-ref=${"a".repeat(64)}`,
        "--bad",
      ],
    },
  ])(
    "rejects any argument outside the exact CLI grammar: $args",
    ({ args }) => {
      expect(() => parseKeycloakStatusArguments(args)).toThrow(
        "LOCAL_CONTROLLED keycloak status arguments are invalid",
      );
    },
  );

  it("accepts only count zero or one and optional lowercase references", () => {
    expect(parseKeycloakStatusArguments(["--expect-count=0"])).toEqual({
      expectedCount: 0,
    });
    expect(
      parseKeycloakStatusArguments([
        "--expect-count=1",
        `--expect-account-ref=${ACCOUNT_REF}`,
        `--expect-subject-ref=${SUBJECT_REF}`,
      ]),
    ).toEqual({
      expectedAccountRef: ACCOUNT_REF,
      expectedCount: 1,
      expectedSubjectRef: SUBJECT_REF,
    });
  });

  it("prints only the count, domain-separated references, and passed mappings", async () => {
    const output: string[] = [];

    await runKeycloakStatus(["--expect-count=1"], {
      readStatus: async () => ({
        count: 1,
        user: {
          groups: ["/organizations/acme"],
          id: "user-1",
          roles: ["employee"],
          username: "pairwise-user",
          veranaSubject: "stable-pairwise-subject",
        },
      }),
      write: (line) => output.push(line),
    });

    expect(output).toEqual([
      "KEYCLOAK USERS 1",
      `KEYCLOAK ACCOUNT_REF ${ACCOUNT_REF}`,
      `KEYCLOAK SUBJECT_REF ${SUBJECT_REF}`,
      "PASS KEYCLOAK GROUP ACME",
      "PASS KEYCLOAK ROLE employee",
      "PASS KEYCLOAK SUBJECT mapped",
    ]);
    expect(output.join("\n")).not.toMatch(
      /user-1|pairwise-user|stable-pairwise-subject|token|credential|cookie|secret/i,
    );
  });

  it("prints no account material when the expected count is zero", async () => {
    const output: string[] = [];

    await runKeycloakStatus(["--expect-count=0"], {
      readStatus: async () => ({ count: 0 }),
      write: (line) => output.push(line),
    });

    expect(output).toEqual(["KEYCLOAK USERS 0"]);
  });

  it.each([
    [
      "count",
      ["--expect-count=0"],
      {
        count: 1,
        user: {
          groups: ["/organizations/acme"],
          id: "user-1",
          roles: ["employee"],
          username: "pairwise-user",
          veranaSubject: "stable-pairwise-subject",
        },
      },
    ],
    [
      "account reference",
      ["--expect-count=1", `--expect-account-ref=${"a".repeat(64)}`],
      {
        count: 1,
        user: {
          groups: ["/organizations/acme"],
          id: "user-1",
          roles: ["employee"],
          username: "pairwise-user",
          veranaSubject: "stable-pairwise-subject",
        },
      },
    ],
    [
      "subject reference",
      ["--expect-count=1", `--expect-subject-ref=${"b".repeat(64)}`],
      {
        count: 1,
        user: {
          groups: ["/organizations/acme"],
          id: "user-1",
          roles: ["employee"],
          username: "pairwise-user",
          veranaSubject: "stable-pairwise-subject",
        },
      },
    ],
    [
      "ACME group",
      ["--expect-count=1"],
      {
        count: 1,
        user: {
          groups: [],
          id: "user-1",
          roles: ["employee"],
          username: "pairwise-user",
          veranaSubject: "stable-pairwise-subject",
        },
      },
    ],
    [
      "employee role",
      ["--expect-count=1"],
      {
        count: 1,
        user: {
          groups: ["/organizations/acme"],
          id: "user-1",
          roles: [],
          username: "pairwise-user",
          veranaSubject: "stable-pairwise-subject",
        },
      },
    ],
    [
      "subject mapping",
      ["--expect-count=1"],
      {
        count: 1,
        user: {
          groups: ["/organizations/acme"],
          id: "user-1",
          roles: ["employee"],
          username: "pairwise-user",
          veranaSubject: null,
        },
      },
    ],
  ] as const)(
    "fails closed on a %s mismatch without output",
    async (_name, args, status) => {
      const output: string[] = [];

      await expect(
        runKeycloakStatus([...args], {
          readStatus: async () => ({
            count: 1,
            user: {
              ...status.user,
              groups: [...status.user.groups],
              roles: [...status.user.roles],
            },
          }),
          write: (line) => output.push(line),
        }),
      ).rejects.toThrow("LOCAL_CONTROLLED Keycloak mapping mismatch");
      expect(output).toEqual([]);
    },
  );
});
