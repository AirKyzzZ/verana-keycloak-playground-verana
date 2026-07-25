import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";

import {
  createBrokerApplication,
  startBroker,
} from "../apps/broker/src/index.js";
import {
  createDemoApplication,
  startDemoApplication,
} from "../apps/demo-app/src/index.js";
import {
  createLocalResolver,
  type LocalResolverOptions,
} from "../apps/local-resolver/src/server.js";

import {
  closeLocalTlsProxy,
  createLocalTlsProxy,
  LOCAL_TLS_GATEWAY_PORT,
} from "./local-tls-proxy.js";

interface HostServer {
  close(callback: (error?: Error) => void): void;
}

export interface TlsMaterial {
  certificate: Buffer;
  privateKey: Buffer;
}

export interface HostProcessDependencies {
  createResolver: (options: LocalResolverOptions) => {
    listen(port: number, host: string): HostServer;
  };
  startTlsGateway: (
    environment: NodeJS.ProcessEnv,
  ) => HostServer | Promise<HostServer>;
  createBrokerApplication: () => Promise<unknown>;
  startBroker: (broker: unknown, port: number) => HostServer;
  createDemoApplication: () => Promise<{ app: unknown }>;
  startDemoApplication: (app: unknown, port: number) => HostServer;
}

function requiredValue(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} is required to start the controlled TLS gateway`);
  }
  return value;
}

// The lifecycle journals each file's device and inode before publishing it. The
// gateway re-checks that identity on the descriptor it actually reads from, so a
// swapped or symlinked file between publication and startup fails closed.
function readIdentifiedFile(path: string, expectedIdentity: string): Buffer {
  let expected: { dev?: unknown; ino?: unknown };
  try {
    expected = JSON.parse(expectedIdentity) as { dev?: unknown; ino?: unknown };
  } catch {
    throw new Error("controlled TLS material identity is not valid JSON");
  }

  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const details = fstatSync(descriptor);
    if (
      String(details.dev) !== String(expected.dev) ||
      String(details.ino) !== String(expected.ino)
    ) {
      throw new Error(
        "controlled TLS material identity changed before startup",
      );
    }
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

export function loadTlsMaterial(environment: NodeJS.ProcessEnv): TlsMaterial {
  return {
    certificate: readIdentifiedFile(
      requiredValue(environment, "LOCAL_TLS_CERTIFICATE_PATH"),
      requiredValue(environment, "LOCAL_TLS_CERTIFICATE_IDENTITY"),
    ),
    privateKey: readIdentifiedFile(
      requiredValue(environment, "LOCAL_TLS_PRIVATE_KEY_PATH"),
      requiredValue(environment, "LOCAL_TLS_PRIVATE_KEY_IDENTITY"),
    ),
  };
}

// listen() reports failures such as EADDRINUSE asynchronously, so the handler is
// attached before binding and startup only resolves once the socket is live.
async function startControlledTlsGateway(
  environment: NodeJS.ProcessEnv,
): Promise<HostServer> {
  const material = loadTlsMaterial(environment);
  const gateway = createLocalTlsProxy(material);

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      gateway.removeListener("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      gateway.removeListener("error", onError);
      resolve();
    };
    gateway.once("error", onError);
    gateway.once("listening", onListening);
    gateway.listen(LOCAL_TLS_GATEWAY_PORT, "127.0.0.1");
  });

  return {
    close(callback) {
      closeLocalTlsProxy(gateway).then(
        () => callback(),
        (error: Error) => callback(error),
      );
    },
  };
}

const defaultDependencies: HostProcessDependencies = {
  createResolver: createLocalResolver,
  startTlsGateway: startControlledTlsGateway,
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
  environment: NodeJS.ProcessEnv = process.env,
): Promise<() => Promise<void>> {
  const resolverOptions = resolverControlOptions(environment);
  const servers: HostServer[] = [];
  try {
    servers.push(
      dependencies.createResolver(resolverOptions).listen(3099, "127.0.0.1"),
    );
    servers.push(await dependencies.startTlsGateway(environment));
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

function resolverControlOptions(
  environment: NodeJS.ProcessEnv,
): LocalResolverOptions {
  const token = environment.LOCAL_RESOLVER_CONTROL_TOKEN;
  if (
    environment.EVIDENCE_MODE !== "LOCAL_CONTROLLED" ||
    typeof token !== "string" ||
    token.length < 43
  ) {
    throw new Error(
      "LOCAL_CONTROLLED resolver control configuration is invalid",
    );
  }
  return {
    controlToken: token,
    evidenceMode: "LOCAL_CONTROLLED",
  };
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
