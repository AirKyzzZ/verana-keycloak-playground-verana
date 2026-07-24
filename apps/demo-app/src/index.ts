import type { Server } from "node:http";
import { fileURLToPath } from "node:url";

import { loadDemoConfig } from "./config.js";
import { createKeycloakClient } from "./keycloak-client.js";
import { LocalWalletClient } from "./local-wallet-client.js";
import { createDemoServer } from "./server.js";

export async function createDemoApplication() {
  const config = loadDemoConfig();
  const keycloakClient = await createKeycloakClient(config);
  const walletClient = new LocalWalletClient({
    issuerBaseUrl: config.VS_AGENT_ISSUER_BASE_URL,
    holderBaseUrl: config.VS_AGENT_HOLDER_BASE_URL,
    verifierBaseUrl: config.VS_AGENT_VERIFIER_BASE_URL,
  });
  return {
    app: createDemoServer({ config, keycloakClient, walletClient }),
    config,
  };
}

export function startDemoApplication(
  app: ReturnType<typeof createDemoServer>,
  port: number,
): Server {
  return app.listen(port, "127.0.0.1");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { app, config } = await createDemoApplication();
  startDemoApplication(app, config.DEMO_APP_PORT);
}
