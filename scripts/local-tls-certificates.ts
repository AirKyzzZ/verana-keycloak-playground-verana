import { execFile } from "node:child_process";
import {
  chmod,
  lstat,
  mkdtemp,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const LOCAL_TLS_HOSTNAMES = [
  "issuer.localhost",
  "holder.localhost",
  "verifier.localhost",
  "resolver.localhost",
] as const;

const CA_SUBJECT = "/CN=Verana LOCAL_CONTROLLED Ephemeral CA";
const LEAF_SUBJECT = `/CN=${LOCAL_TLS_HOSTNAMES[0]}`;
const CA_DAYS = "2";
const LEAF_DAYS = "1";
const KEY_SPEC = "rsa:3072";

const SERVER_EXTENSIONS = [
  "basicConstraints=critical,CA:FALSE",
  "keyUsage=critical,digitalSignature,keyEncipherment",
  "extendedKeyUsage=serverAuth",
  `subjectAltName=${LOCAL_TLS_HOSTNAMES.map((name) => `DNS:${name}`).join(",")}`,
  "",
].join("\n");

const GENERATED_FILES = [
  "ca-key.pem",
  "ca.pem",
  "ca.srl",
  "server-ext.cnf",
  "server-key.pem",
  "server.csr",
  "server.pem",
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

let cachedOpenSslBinary: string | undefined;

// macOS ships LibreSSL as /usr/bin/openssl, which silently lacks `req -addext`.
// Resolve and verify a genuine OpenSSL 3 binary instead of trusting PATH order.
export async function resolveOpenSslBinary(): Promise<string> {
  if (cachedOpenSslBinary) return cachedOpenSslBinary;

  const candidates = [
    ...(process.env.PATH ?? "")
      .split(delimiter)
      .filter(Boolean)
      .map((entry) => join(entry, "openssl")),
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
  ];

  for (const candidate of candidates) {
    try {
      const { stdout } = await execFileAsync(candidate, ["version"]);
      if (/^OpenSSL 3\./.test(stdout.trim())) {
        cachedOpenSslBinary = candidate;
        return candidate;
      }
    } catch {
      // Try the next candidate.
    }
  }

  throw new Error(
    "no OpenSSL 3 binary found; LibreSSL is not supported for local TLS generation",
  );
}

function serializeIdentity(stats: {
  dev: number;
  ino: number;
}): SerializedFileIdentity {
  return { dev: String(stats.dev), ino: String(stats.ino) };
}

function sameIdentity(
  left: SerializedFileIdentity,
  right: SerializedFileIdentity,
): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function assertRegularDirectory(path: string): Promise<void> {
  const stats = await lstat(path);
  if (stats.isSymbolicLink()) {
    throw new Error(`${path} is a symlink, not a regular directory`);
  }
  if (!stats.isDirectory()) {
    throw new Error(`${path} is not a regular directory`);
  }
}

export async function reserveLocalTlsBundle(options: {
  stagingParent: string;
}): Promise<LocalTlsReservation> {
  await assertRegularDirectory(options.stagingParent);

  const directory = await mkdtemp(join(options.stagingParent, "tls-"));
  await chmod(directory, 0o700);

  const stats = await lstat(directory);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error("reserved path is not a regular directory");
  }
  if ((await readdir(directory)).length > 0) {
    throw new Error("reserved directory is not empty");
  }

  return { directory, identity: serializeIdentity(stats) };
}

async function verifyReservation(
  reservation: LocalTlsReservation,
): Promise<void> {
  await assertRegularDirectory(reservation.directory);

  const stats = await lstat(reservation.directory);
  if (!sameIdentity(serializeIdentity(stats), reservation.identity)) {
    throw new Error("reserved directory identity changed since reservation");
  }
  if ((await readdir(reservation.directory)).length > 0) {
    throw new Error("reserved directory is not empty");
  }
}

async function discardReservation(
  reservation: LocalTlsReservation,
): Promise<void> {
  try {
    const stats = await lstat(reservation.directory);
    if (
      stats.isDirectory() &&
      !stats.isSymbolicLink() &&
      sameIdentity(serializeIdentity(stats), reservation.identity)
    ) {
      await rm(reservation.directory, { recursive: true, force: true });
    }
  } catch {
    // Nothing verifiable to remove.
  }
}

const defaultRunner: CertificateCommandRunner = {
  async run(command, args, options) {
    try {
      const { stdout, stderr } = await execFileAsync(command, [...args], {
        cwd: options.cwd,
      });
      return { exitCode: 0, stdout, stderr };
    } catch (error) {
      const failure = error as {
        code?: number;
        stdout?: string;
        stderr?: string;
      };
      return {
        exitCode: failure.code ?? 1,
        stdout: failure.stdout ?? "",
        stderr: failure.stderr ?? "",
      };
    }
  },
};

async function assertRegularFileWithMode(
  path: string,
  mode: number,
): Promise<SerializedFileIdentity> {
  const stats = await lstat(path);
  if (stats.isSymbolicLink() || !stats.isFile()) {
    throw new Error(`${path} is not a regular file`);
  }
  if ((stats.mode & 0o777) !== mode) {
    throw new Error(`${path} has mode ${(stats.mode & 0o777).toString(8)}`);
  }
  return serializeIdentity(stats);
}

export async function createLocalTlsBundle(options: {
  reservation: LocalTlsReservation;
  runner?: CertificateCommandRunner;
}): Promise<LocalTlsBundle> {
  const { reservation } = options;
  const runner = options.runner ?? defaultRunner;

  await verifyReservation(reservation);

  const binary = await resolveOpenSslBinary();
  const cwd = reservation.directory;

  try {
    await writeFile(join(cwd, "server-ext.cnf"), SERVER_EXTENSIONS, {
      mode: 0o600,
    });

    const steps: readonly (readonly string[])[] = [
      [
        "req",
        "-x509",
        "-newkey",
        KEY_SPEC,
        "-sha256",
        "-nodes",
        "-days",
        CA_DAYS,
        "-subj",
        CA_SUBJECT,
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        "ca-key.pem",
        "-out",
        "ca.pem",
      ],
      [
        "req",
        "-new",
        "-newkey",
        KEY_SPEC,
        "-sha256",
        "-nodes",
        "-subj",
        LEAF_SUBJECT,
        "-keyout",
        "server-key.pem",
        "-out",
        "server.csr",
      ],
      [
        "x509",
        "-req",
        "-sha256",
        "-days",
        LEAF_DAYS,
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca-key.pem",
        "-CAcreateserial",
        "-extfile",
        "server-ext.cnf",
        "-out",
        "server.pem",
      ],
    ];

    for (const args of steps) {
      const result = await runner.run(binary, args, { cwd });
      if (result.exitCode !== 0) {
        throw new Error(`openssl ${args[0]} failed with ${result.exitCode}`);
      }
    }

    const verification = await runner.run(
      binary,
      ["verify", "-purpose", "sslserver", "-CAfile", "ca.pem", "server.pem"],
      { cwd },
    );
    if (verification.exitCode !== 0) {
      throw new Error("generated leaf failed sslserver chain verification");
    }

    for (const hostname of LOCAL_TLS_HOSTNAMES) {
      const check = await runner.run(
        binary,
        ["x509", "-in", "server.pem", "-noout", "-checkhost", hostname],
        { cwd },
      );
      if (check.exitCode !== 0 || !/does match/i.test(check.stdout)) {
        throw new Error(`generated leaf does not match ${hostname}`);
      }
    }

    const present = (await readdir(cwd)).sort();
    const expected = [...GENERATED_FILES].sort();
    if (present.length !== expected.length) {
      throw new Error("unexpected files were generated alongside the bundle");
    }
    for (const [index, name] of expected.entries()) {
      if (present[index] !== name) {
        throw new Error("unexpected files were generated alongside the bundle");
      }
    }

    const fileIdentities = {
      caCertificate: { dev: "", ino: "" },
      serverCertificate: { dev: "", ino: "" },
      serverPrivateKey: { dev: "", ino: "" },
    };
    for (const name of GENERATED_FILES) {
      const path = join(cwd, name);
      // chmod follows symlinks, so refuse anything that is not already a
      // regular file before touching its mode.
      const staged = await lstat(path);
      if (staged.isSymbolicLink() || !staged.isFile()) {
        throw new Error(`${path} is not a regular file`);
      }
      await chmod(path, 0o600);
      const identity = await assertRegularFileWithMode(path, 0o600);
      if (name === "ca.pem") fileIdentities.caCertificate = identity;
      if (name === "server.pem") fileIdentities.serverCertificate = identity;
      if (name === "server-key.pem") fileIdentities.serverPrivateKey = identity;
    }

    return {
      directory: reservation.directory,
      identity: reservation.identity,
      caCertificatePath: join(cwd, "ca.pem"),
      caPrivateKeyPath: join(cwd, "ca-key.pem"),
      serverCertificatePath: join(cwd, "server.pem"),
      serverPrivateKeyPath: join(cwd, "server-key.pem"),
      fileIdentities,
    };
  } catch (error) {
    await discardReservation(reservation);
    throw error;
  }
}
