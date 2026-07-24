import type { Server } from "node:http";

import {
  createBrokerApplication,
  startBroker,
} from "../apps/broker/src/index.js";
import {
  createDemoApplication,
  startDemoApplication,
} from "../apps/demo-app/src/index.js";
import { createLocalResolver } from "../apps/local-resolver/src/server.js";

const servers: Server[] = [];
let shuttingDown = false;

async function closeServers(): Promise<void> {
  await Promise.all(
    [...servers].reverse().map(
      (server) =>
        new Promise<void>((resolveClose, rejectClose) => {
          server.close((error) =>
            error ? rejectClose(error) : resolveClose(),
          );
        }),
    ),
  );
}

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    await closeServers();
    process.exitCode = signal === "startup" ? 1 : 0;
  } catch {
    process.exitCode = 1;
  }
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

try {
  const resolver = createLocalResolver().listen(3099, "127.0.0.1");
  servers.push(resolver);

  const broker = await createBrokerApplication();
  servers.push(startBroker(broker, 3001));

  const { app } = await createDemoApplication();
  servers.push(startDemoApplication(app, 3000));
} catch {
  await shutdown("startup");
}
