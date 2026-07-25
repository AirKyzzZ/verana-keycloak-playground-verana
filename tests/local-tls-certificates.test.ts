import { execFile } from "node:child_process";
import { lstat, mkdir, mkdtemp, readdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  type CertificateCommandRunner,
  createLocalTlsBundle,
  LOCAL_TLS_HOSTNAMES,
  reserveLocalTlsBundle,
  resolveOpenSslBinary,
} from "../scripts/local-tls-certificates.js";

const run = promisify(execFile);

const EXPECTED_FILES = [
  "ca-key.pem",
  "ca.pem",
  "ca.srl",
  "server-ext.cnf",
  "server-key.pem",
  "server.csr",
  "server.pem",
];

// `openssl x509 -checkhost` exits non-zero on a deliberate non-match, so the
// helper reports stdout rather than treating a failed exit code as an error.
async function openssl(args: readonly string[]): Promise<string> {
  const binary = await resolveOpenSslBinary();
  try {
    const { stdout } = await run(binary, [...args]);
    return stdout;
  } catch (error) {
    return (error as { stdout?: string }).stdout ?? "";
  }
}

async function text(path: string): Promise<string> {
  return openssl(["x509", "-in", path, "-noout", "-text"]);
}

describe("local TLS certificate bundle", () => {
  let stagingParent: string;

  beforeEach(async () => {
    stagingParent = await mkdtemp(join(tmpdir(), "verana-tls-test-"));
  });

  afterEach(async () => {
    await rm(stagingParent, { recursive: true, force: true });
  });

  it("reserves an empty directory with mode 0700 under the staging parent", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });

    const stats = await lstat(reservation.directory);
    expect(stats.isDirectory()).toBe(true);
    expect(stats.isSymbolicLink()).toBe(false);
    expect(stats.mode & 0o777).toBe(0o700);
    expect(reservation.directory.startsWith(stagingParent)).toBe(true);
    expect(await readdir(reservation.directory)).toEqual([]);
    expect(reservation.identity.dev).toBe(String(stats.dev));
    expect(reservation.identity.ino).toBe(String(stats.ino));
  });

  it("refuses a symlinked staging parent", async () => {
    const real = await mkdtemp(join(tmpdir(), "verana-tls-real-"));
    const link = join(stagingParent, "link");
    await symlink(real, link);

    await expect(
      reserveLocalTlsBundle({ stagingParent: link }),
    ).rejects.toThrow(/symlink|regular directory/i);

    await rm(real, { recursive: true, force: true });
  });

  it("creates exactly the expected files, each a regular file with mode 0600", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });

    expect((await readdir(bundle.directory)).sort()).toEqual(EXPECTED_FILES);
    for (const name of EXPECTED_FILES) {
      const stats = await lstat(join(bundle.directory, name));
      expect(stats.isFile()).toBe(true);
      expect(stats.isSymbolicLink()).toBe(false);
      expect(stats.mode & 0o777).toBe(0o600);
    }
  });

  it("issues a CA constrained to certificate signing", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });

    const ca = await text(bundle.caCertificatePath);
    expect(ca).toMatch(/CA:TRUE/);
    expect(ca).toMatch(/pathlen:0/);
    expect(ca).toMatch(/Certificate Sign/);
    expect(ca).toMatch(/CRL Sign/);
    expect(ca).not.toMatch(/TLS Web Server Authentication/);
  });

  it("issues a leaf that is not a CA and carries exactly the four allowed SANs", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });

    const leaf = await text(bundle.serverCertificatePath);
    expect(leaf).toMatch(/CA:FALSE/);
    expect(leaf).toMatch(/TLS Web Server Authentication/);

    const sans = leaf
      .split("Subject Alternative Name:")[1]
      ?.split("\n")
      .slice(0, 2)
      .join(" ");
    for (const hostname of LOCAL_TLS_HOSTNAMES) {
      expect(sans).toContain(`DNS:${hostname}`);
    }
    expect(sans).not.toContain("rogue.localhost");
  });

  it("verifies the leaf against the CA for the sslserver purpose", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });

    const output = await openssl([
      "verify",
      "-purpose",
      "sslserver",
      "-CAfile",
      bundle.caCertificatePath,
      bundle.serverCertificatePath,
    ]);
    expect(output).toMatch(/OK/);
  });

  it("matches every allowed hostname and rejects an unlisted one", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });

    for (const hostname of LOCAL_TLS_HOSTNAMES) {
      const output = await openssl([
        "x509",
        "-in",
        bundle.serverCertificatePath,
        "-noout",
        "-checkhost",
        hostname,
      ]);
      expect(output).toMatch(/does match/i);
    }

    const rogue = await openssl([
      "x509",
      "-in",
      bundle.serverCertificatePath,
      "-noout",
      "-checkhost",
      "rogue.localhost",
    ]);
    expect(rogue).toMatch(/does NOT match/i);
  });

  it("keeps the leaf valid for at most a day and wholly inside the CA validity", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });

    const parse = async (path: string) => {
      const stdout = await openssl(["x509", "-in", path, "-noout", "-dates"]);
      const before = stdout.match(/notBefore=(.+)/)?.[1]?.trim() ?? "";
      const after = stdout.match(/notAfter=(.+)/)?.[1]?.trim() ?? "";
      return { before: Date.parse(before), after: Date.parse(after) };
    };

    const ca = await parse(bundle.caCertificatePath);
    const leaf = await parse(bundle.serverCertificatePath);
    const now = Date.now();

    expect(leaf.before).toBeLessThanOrEqual(now);
    expect(leaf.after).toBeGreaterThan(now);
    expect(leaf.after - leaf.before).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
    expect(leaf.before).toBeGreaterThanOrEqual(ca.before);
    expect(leaf.after).toBeLessThanOrEqual(ca.after);
  });

  it("drives generation through an injectable runner without a shell", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const calls: { command: string; args: readonly string[] }[] = [];
    const binary = await resolveOpenSslBinary();
    const runner: CertificateCommandRunner = {
      async run(command, args, options) {
        calls.push({ command, args });
        expect(options).toEqual({ cwd: reservation.directory });
        const { stdout, stderr } = await run(command, [...args], {
          cwd: options.cwd,
        });
        return { exitCode: 0, stdout, stderr };
      },
    };

    await createLocalTlsBundle({ reservation, runner });

    expect(calls.length).toBeGreaterThanOrEqual(3);
    for (const call of calls) {
      expect(call.command).toBe(binary);
      expect(Array.isArray(call.args)).toBe(true);
    }
  });

  it("removes only the reserved directory when a command fails", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    let seen = 0;
    const runner: CertificateCommandRunner = {
      async run() {
        seen += 1;
        return { exitCode: 1, stdout: "", stderr: "forced failure" };
      },
    };

    await expect(
      createLocalTlsBundle({ reservation, runner }),
    ).rejects.toThrow();

    expect(seen).toBe(1);
    await expect(lstat(reservation.directory)).rejects.toThrow();
    await expect(lstat(stagingParent)).resolves.toBeTruthy();
  });

  it("refuses a reservation whose directory identity changed", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    await rm(reservation.directory, { recursive: true, force: true });
    await mkdir(reservation.directory, { mode: 0o700 });

    await expect(createLocalTlsBundle({ reservation })).rejects.toThrow(
      /identity/i,
    );
  });

  it("refuses a reservation that is no longer empty", async () => {
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    await mkdir(join(reservation.directory, "unexpected"));

    await expect(createLocalTlsBundle({ reservation })).rejects.toThrow(
      /empty/i,
    );
  });
});
