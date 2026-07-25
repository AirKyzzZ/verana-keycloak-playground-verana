import { randomBytes } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import { LOCAL_CONTROLLED } from "./local-controlled-config.js";
import { createLocalData, type LocalDataFiles } from "./setup.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const placeholderPattern = /__[A-Z0-9_]+__/;
const defaultVsAgentSourcePath =
  "/Users/samsepiol/Downloads/GithubRepos/Work/Verana/worktrees/keycloak-subject-claim";

const secret = () => randomBytes(32).toString("base64url");

function localEnvironment(): string[] {
  return [
    `BROKER_ISSUER=http://localhost:${LOCAL_CONTROLLED.ports[1]}`,
    `BROKER_PORT=${LOCAL_CONTROLLED.ports[1]}`,
    "DEMO_APP_PORT=3000",
    "DEMO_APP_BASE_URL=http://localhost:3000",
    "KEYCLOAK_ISSUER=http://localhost:8080/realms/verana-playground",
    "DEMO_APP_REDIRECT_URI=http://localhost:3000/callback",
    "VS_AGENT_ISSUER_BASE_URL=http://localhost:3101",
    "VS_AGENT_HOLDER_BASE_URL=http://localhost:3111",
    "VS_AGENT_VERIFIER_BASE_URL=http://localhost:3201",
    `EXPECTED_VCT=${LOCAL_CONTROLLED.vct}`,
    `EXPECTED_VTJSC_ID=${LOCAL_CONTROLLED.vtjscId}`,
    `EXPECTED_ISSUER_DID=${LOCAL_CONTROLLED.issuerDid}`,
    `EXPECTED_VERIFIER_DID=${LOCAL_CONTROLLED.verifierDid}`,
    `VERANA_RESOLVER_URL=http://localhost:${LOCAL_CONTROLLED.ports[2]}/v1/trust`,
    `EVIDENCE_MODE=${LOCAL_CONTROLLED.evidenceMode}`,
    `LOCAL_RESOLVER_CONTROL_TOKEN=${secret()}`,
  ];
}

function controlledEnvironment(vsAgentSourcePath: string): string[] {
  return [
    `EVIDENCE_MODE=${LOCAL_CONTROLLED.evidenceMode}`,
    `VS_AGENT_SOURCE_PATH=${vsAgentSourcePath}`,
    "VS_AGENT_IMAGE=verana-keycloak-local-controlled-vs-agent:e2bba78",
    `EXPECTED_ISSUER_DID=${LOCAL_CONTROLLED.issuerDid}`,
    `EXPECTED_HOLDER_DID=${LOCAL_CONTROLLED.holderDid}`,
    `EXPECTED_VERIFIER_DID=${LOCAL_CONTROLLED.verifierDid}`,
    `ROGUE_VERIFIER_DID=${LOCAL_CONTROLLED.rogueDid}`,
    `VERANA_RESOLVER_URL=${LOCAL_CONTROLLED.resolverUrl}`,
    `UNFOLD_VCT=${LOCAL_CONTROLLED.vct}`,
    `UNFOLD_VTJSC_ID=${LOCAL_CONTROLLED.vtjscId}`,
    "ISSUER_WALLET_ID=local-controlled-issuer",
    "HOLDER_WALLET_ID=local-controlled-holder",
    "VERIFIER_WALLET_ID=local-controlled-verifier",
    `ISSUER_WALLET_KEY=${secret()}`,
    `HOLDER_WALLET_KEY=${secret()}`,
    `VERIFIER_WALLET_KEY=${secret()}`,
  ];
}

async function writePrivateFile(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  await chmod(path, 0o600);
}

export interface LocalControlledDataFiles extends LocalDataFiles {
  "local-controlled.env": string;
}

export async function createLocalControlledData(
  vsAgentSourcePath = defaultVsAgentSourcePath,
): Promise<LocalControlledDataFiles> {
  if (!isAbsolute(vsAgentSourcePath)) {
    throw new Error("VS Agent source path must be absolute");
  }

  const localData = await createLocalData();
  const localEnv = `${localData[".env"].trim()}\n${localEnvironment().join("\n")}\n`;
  const controlledEnv = `${controlledEnvironment(vsAgentSourcePath).join("\n")}\n`;

  if (
    placeholderPattern.test(localEnv) ||
    placeholderPattern.test(controlledEnv)
  ) {
    throw new Error(
      "Local controlled configuration contains an unresolved placeholder",
    );
  }

  return {
    ...localData,
    ".env": localEnv,
    "local-controlled.env": controlledEnv,
  };
}

export async function generateLocalControlledData(
  output = join(root, ".data"),
  vsAgentSourcePath = defaultVsAgentSourcePath,
): Promise<void> {
  const files = await createLocalControlledData(vsAgentSourcePath);
  await mkdir(output, { recursive: true });
  await Promise.all(
    Object.entries(files).map(([file, contents]) =>
      writePrivateFile(join(output, file), contents),
    ),
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await generateLocalControlledData(
    join(root, ".data"),
    process.env.VS_AGENT_SOURCE_PATH ?? defaultVsAgentSourcePath,
  );
  console.log(
    "LOCAL_CONTROLLED configuration generated for http://localhost:3000",
  );
}
