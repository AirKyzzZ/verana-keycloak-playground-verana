import { randomBytes } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair } from "jose";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const secret = () => randomBytes(32).toString("base64url");

export async function generateLocalData(
  output = join(root, ".data"),
): Promise<void> {
  await mkdir(output, { recursive: true });
  const appSecret = secret();
  const brokerSecret = secret();
  const pairwiseSecret = secret();
  const sessionSecret = secret();
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = {
    ...(await exportJWK(privateKey)),
    alg: "ES256",
    use: "sig",
    kid: "playground-es256",
  };

  const env = [
    `PLAYGROUND_APP_CLIENT_SECRET=${appSecret}`,
    `BROKER_CLIENT_SECRET=${brokerSecret}`,
    `PAIRWISE_SUB_SECRET=${pairwiseSecret}`,
    `SESSION_SECRET=${sessionSecret}`,
    "",
  ].join("\n");

  await writeFile(join(output, ".env"), env, { mode: 0o600 });
  await writeFile(
    join(output, "broker-jwks.json"),
    JSON.stringify({ keys: [privateJwk] }, null, 2),
    { mode: 0o600 },
  );
  await Promise.all(
    [".env", "broker-jwks.json"].map((file) =>
      chmod(join(output, file), 0o600),
    ),
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await generateLocalData();
}
