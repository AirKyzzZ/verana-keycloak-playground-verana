import {
  createBrokerApplication,
  startBroker,
} from "../apps/broker/src/index.js";
import {
  createDemoApplication,
  startDemoApplication,
} from "../apps/demo-app/src/index.js";
import { createLocalResolver } from "../apps/local-resolver/src/server.js";

interface HostServer {
  close(callback: (error?: Error) => void): void;
}

export interface HostProcessDependencies {
  createResolver: () => {
    listen(port: number, host: string): HostServer;
  };
  createBrokerApplication: () => Promise<unknown>;
  startBroker: (broker: unknown, port: number) => HostServer;
  createDemoApplication: () => Promise<{ app: unknown }>;
  startDemoApplication: (app: unknown, port: number) => HostServer;
}

const defaultDependencies: HostProcessDependencies = {
  createResolver: createLocalResolver,
  createBrokerApplication,
  startBroker: (broker, port) =>
    startBroker(broker as Parameters<typeof startBroker>[0], port),
  createDemoApplication,
  startDemoApplication: (app, port) =>
    startDemoApplication(
      app as Parameters<typeof startDemoApplication>[0],
      port,
    ),
};

export async function startHostProcess(
  dependencies: HostProcessDependencies = defaultDependencies,
): Promise<() => Promise<void>> {
  const servers: HostServer[] = [];
  try {
    servers.push(dependencies.createResolver().listen(3099, "127.0.0.1"));
    const broker = await dependencies.createBrokerApplication();
    servers.push(dependencies.startBroker(broker, 3001));
    const { app } = await dependencies.createDemoApplication();
    servers.push(dependencies.startDemoApplication(app, 3000));
  } catch (error) {
    await closeServers(servers);
    throw error;
  }
  return async () => await closeServers(servers);
}

async function closeServers(servers: readonly HostServer[]): Promise<void> {
  const errors: Error[] = [];
  for (const server of [...servers].reverse()) {
    try {
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => (error ? rejectClose(error) : resolveClose()));
      });
    } catch (error) {
      errors.push(
        error instanceof Error ? error : new Error("server close failed"),
      );
    }
  }
  if (errors.length > 0) {
    throw new Error(errors.map((error) => error.message).join("; "));
  }
}

if (process.argv[1]?.endsWith("local-stack-process.ts")) {
  try {
    const close = await startHostProcess();
    const shutdown = () => {
      void close().then(
        () => {
          process.exitCode = 0;
        },
        () => {
          process.exitCode = 1;
        },
      );
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch {
    process.exitCode = 1;
  }
}
