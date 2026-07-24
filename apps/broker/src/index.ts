import { readFile } from "node:fs/promises";
import type { Server } from "node:http";
import { fileURLToPath } from "node:url";
import type Provider from "oidc-provider";
import type { JWKS } from "oidc-provider";

import { AccountStore } from "./account-store.js";
import { type BrokerConfig, loadBrokerConfig } from "./config.js";
import { LoginService } from "./login-service.js";
import { createOidcProvider } from "./oidc-provider.js";
import { attachInteractionRoutes } from "./server.js";
import { TransactionStore } from "./transaction-store.js";
import { VsAgentClient } from "./vs-agent-client.js";

export async function createBrokerApplication(
  config: BrokerConfig = loadBrokerConfig(),
) {
  const privateJwks = JSON.parse(
    await readFile(config.BROKER_JWKS_PATH, "utf8"),
  ) as JWKS;
  const accountStore = new AccountStore();
  const transactionStore = new TransactionStore();
  const loginService = new LoginService({
    vsAgentClient: new VsAgentClient(config.VS_AGENT_VERIFIER_BASE_URL),
    transactionStore,
    accountStore,
    expectedVct: config.EXPECTED_VCT,
    expectedVtjscId: config.EXPECTED_VTJSC_ID,
    sectorIdentifier: config.SECTOR_IDENTIFIER,
    pairwiseSubSecret: new TextEncoder().encode(config.PAIRWISE_SUB_SECRET),
  });
  const provider = createOidcProvider({
    accountStore,
    config,
    privateJwks,
  });

  return attachInteractionRoutes(provider, {
    evidenceMode: config.EVIDENCE_MODE,
    loginService,
    transactionStore,
  });
}

export function startBroker(
  provider: Pick<Provider, "listen">,
  port: number,
): Server {
  return provider.listen(port, "127.0.0.1");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const config = loadBrokerConfig();
  const provider = await createBrokerApplication(config);
  startBroker(provider, config.BROKER_PORT);
}
