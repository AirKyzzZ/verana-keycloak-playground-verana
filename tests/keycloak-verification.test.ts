import { describe, expect, it } from "vitest";
import {
  assertClientSecretPost,
  assertExactNames,
  assertSecretMatch,
  parseLocalSecrets,
} from "../scripts/keycloak-verification.js";

describe("Keycloak verification helpers", () => {
  it("rejects extra configured names with a static error", () => {
    expect(() =>
      assertExactNames(
        [{ name: "expected" }, { name: "unexpected" }],
        ["expected"],
        "Mapper allowlist mismatch",
      ),
    ).toThrowError("Mapper allowlist mismatch");
  });

  it("rejects secret mismatches without including either value", () => {
    const actual = "actual-secret-value";
    const expected = "expected-secret-value";
    let failure: unknown;

    try {
      assertSecretMatch(actual, expected, "Imported secret mismatch");
    } catch (error) {
      failure = error;
    }

    expect(failure instanceof Error).toBe(true);
    expect(
      failure instanceof Error &&
        failure.message === "Imported secret mismatch",
    ).toBe(true);
    expect(failure instanceof Error && failure.message.includes(actual)).toBe(
      false,
    );
    expect(failure instanceof Error && failure.message.includes(expected)).toBe(
      false,
    );
  });

  it("accepts matching secrets", () => {
    expect(() =>
      assertSecretMatch(
        "matching-secret-value",
        "matching-secret-value",
        "Imported secret mismatch",
      ),
    ).not.toThrow();
  });

  it("accepts the exact broker client_secret_post request", () => {
    expect(() =>
      assertClientSecretPost({
        body: new URLSearchParams({
          client_id: "keycloak-playground",
          client_secret: "broker-secret-value",
          grant_type: "authorization_code",
        }).toString(),
        authorizationHeader: undefined,
        expectedSecret: "broker-secret-value",
      }),
    ).not.toThrow();
  });

  it("rejects a stale broker secret without including either value", () => {
    const actual = "stale-broker-secret";
    const expected = "generated-broker-secret";
    let failure: unknown;

    try {
      assertClientSecretPost({
        body: new URLSearchParams({
          client_id: "keycloak-playground",
          client_secret: actual,
          grant_type: "authorization_code",
        }).toString(),
        authorizationHeader: undefined,
        expectedSecret: expected,
      });
    } catch (error) {
      failure = error;
    }

    expect(
      failure instanceof Error &&
        failure.message === "Imported identity-provider secret mismatch",
    ).toBe(true);
    expect(failure instanceof Error && failure.message.includes(actual)).toBe(
      false,
    );
    expect(failure instanceof Error && failure.message.includes(expected)).toBe(
      false,
    );
  });

  it("parses only the generated secrets needed for live verification", () => {
    const secrets = parseLocalSecrets(
      [
        "PLAYGROUND_APP_CLIENT_SECRET=app-secret-value",
        "BROKER_CLIENT_SECRET=broker-secret-value",
        "OTHER_SECRET=ignored-secret-value",
        "",
      ].join("\n"),
    );

    expect(secrets.PLAYGROUND_APP_CLIENT_SECRET === "app-secret-value").toBe(
      true,
    );
    expect(secrets.BROKER_CLIENT_SECRET === "broker-secret-value").toBe(true);
    expect(Object.keys(secrets).sort()).toEqual([
      "BROKER_CLIENT_SECRET",
      "PLAYGROUND_APP_CLIENT_SECRET",
    ]);
  });
});
