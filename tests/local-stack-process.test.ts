import { lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  loadTlsMaterial,
  startHostProcess,
} from "../scripts/local-stack-process.js";
import {
  createLocalTlsBundle,
  reserveLocalTlsBundle,
} from "../scripts/local-tls-certificates.js";

interface FakeServer {
  close(callback: (error?: Error) => void): void;
}

function server(name: string, events: string[]): FakeServer {
  return {
    close(callback) {
      events.push(`close:${name}`);
      callback();
    },
  };
}

describe("local stack host process", () => {
  it("binds every server to loopback and closes them sequentially in reverse startup order", async () => {
    const events: string[] = [];
    const close = await startHostProcess(
      {
        createResolver: () => ({
          listen(port, host) {
            events.push(`start:resolver:${port}:${host}`);
            return server("resolver", events);
          },
        }),
        startTlsGateway: () => {
          events.push("start:tls:3443");
          return server("tls", events);
        },
        createBrokerApplication: async () => ({ name: "broker" }),
        startBroker: (_broker, port) => {
          events.push(`start:broker:${port}`);
          return server("broker", events);
        },
        createDemoApplication: async () => ({ app: { name: "demo" } }),
        startDemoApplication: (_app, port) => {
          events.push(`start:demo:${port}`);
          return server("demo", events);
        },
      },
      {
        EVIDENCE_MODE: "LOCAL_CONTROLLED",
        LOCAL_RESOLVER_CONTROL_TOKEN:
          "test-control-token-with-at-least-thirty-two-bytes-of-entropy",
      },
    );

    await close();

    expect(events).toEqual([
      "start:resolver:3099:127.0.0.1",
      "start:tls:3443",
      "start:broker:3001",
      "start:demo:3000",
      "close:demo",
      "close:broker",
      "close:tls",
      "close:resolver",
    ]);
  });

  it("closes started loopback servers and rejects when startup fails", async () => {
    const events: string[] = [];

    await expect(
      startHostProcess(
        {
          createResolver: () => ({
            listen(port, host) {
              events.push(`start:resolver:${port}:${host}`);
              return server("resolver", events);
            },
          }),
          startTlsGateway: () => {
            events.push("start:tls:3443");
            return server("tls", events);
          },
          createBrokerApplication: async () => {
            throw new Error("broker initialization failed");
          },
          startBroker: () => server("broker", events),
          createDemoApplication: async () => ({ app: {} }),
          startDemoApplication: () => server("demo", events),
        },
        {
          EVIDENCE_MODE: "LOCAL_CONTROLLED",
          LOCAL_RESOLVER_CONTROL_TOKEN:
            "test-control-token-with-at-least-thirty-two-bytes-of-entropy",
        },
      ),
    ).rejects.toThrow("broker initialization failed");

    expect(events).toEqual([
      "start:resolver:3099:127.0.0.1",
      "start:tls:3443",
      "close:tls",
      "close:resolver",
    ]);
  });

  it("passes explicit controlled mode and the host-only token to the resolver", async () => {
    const events: string[] = [];
    const token =
      "host-only-control-token-with-at-least-thirty-two-bytes-of-entropy";

    const close = await startHostProcess(
      {
        createResolver: (options) => ({
          listen: (port, host) => {
            events.push(
              `resolver:${options.evidenceMode}:${options.controlToken === token}:${port}:${host}`,
            );
            return server("resolver", events);
          },
        }),
        startTlsGateway: () => {
          events.push("start:tls:3443");
          return server("tls", events);
        },
        createBrokerApplication: async () => ({}),
        startBroker: () => server("broker", events),
        createDemoApplication: async () => ({ app: {} }),
        startDemoApplication: () => server("demo", events),
      },
      {
        EVIDENCE_MODE: "LOCAL_CONTROLLED",
        LOCAL_RESOLVER_CONTROL_TOKEN: token,
      },
    );
    await close();

    expect(events[0]).toBe("resolver:LOCAL_CONTROLLED:true:3099:127.0.0.1");
    expect(events.join("\n")).not.toContain(token);
  });

  it("fails before binding when the controlled host token is missing", async () => {
    const events: string[] = [];

    await expect(
      startHostProcess(
        {
          createResolver: () => ({
            listen: () => server("resolver", events),
          }),
          startTlsGateway: () => {
            events.push("start:tls:3443");
            return server("tls", events);
          },
          createBrokerApplication: async () => ({}),
          startBroker: () => server("broker", events),
          createDemoApplication: async () => ({ app: {} }),
          startDemoApplication: () => server("demo", events),
        },
        { EVIDENCE_MODE: "LOCAL_CONTROLLED" },
      ),
    ).rejects.toThrow("resolver control configuration");

    expect(events).toEqual([]);
  });
});

describe("controlled TLS material loading", () => {
  let stagingParent: string;
  let certificatePath: string;
  let privateKeyPath: string;
  let certificateIdentity: string;
  let privateKeyIdentity: string;

  beforeAll(async () => {
    stagingParent = await mkdtemp(join(tmpdir(), "verana-host-tls-"));
    const reservation = await reserveLocalTlsBundle({ stagingParent });
    const bundle = await createLocalTlsBundle({ reservation });
    certificatePath = bundle.serverCertificatePath;
    privateKeyPath = bundle.serverPrivateKeyPath;
    const certificateDetails = await lstat(certificatePath);
    const privateKeyDetails = await lstat(privateKeyPath);
    certificateIdentity = JSON.stringify({
      dev: String(certificateDetails.dev),
      ino: String(certificateDetails.ino),
    });
    privateKeyIdentity = JSON.stringify({
      dev: String(privateKeyDetails.dev),
      ino: String(privateKeyDetails.ino),
    });
  }, 60_000);

  afterAll(async () => {
    await rm(stagingParent, { recursive: true, force: true });
  });

  function environment(overrides: Record<string, string> = {}) {
    return {
      LOCAL_TLS_CERTIFICATE_PATH: certificatePath,
      LOCAL_TLS_PRIVATE_KEY_PATH: privateKeyPath,
      LOCAL_TLS_CERTIFICATE_IDENTITY: certificateIdentity,
      LOCAL_TLS_PRIVATE_KEY_IDENTITY: privateKeyIdentity,
      ...overrides,
    };
  }

  it("loads certificate and key material whose identity matches the journal", () => {
    const material = loadTlsMaterial(environment());

    expect(material.certificate.toString("utf8")).toContain(
      "BEGIN CERTIFICATE",
    );
    expect(material.privateKey.toString("utf8")).toContain("PRIVATE KEY");
  });

  it("refuses material whose journaled identity does not match", () => {
    expect(() =>
      loadTlsMaterial(
        environment({
          LOCAL_TLS_CERTIFICATE_IDENTITY: JSON.stringify({
            dev: "1",
            ino: "2",
          }),
        }),
      ),
    ).toThrow(/identity changed/i);
  });

  it.each([
    "LOCAL_TLS_CERTIFICATE_PATH",
    "LOCAL_TLS_PRIVATE_KEY_PATH",
    "LOCAL_TLS_CERTIFICATE_IDENTITY",
    "LOCAL_TLS_PRIVATE_KEY_IDENTITY",
  ])("fails closed when %s is missing", (name) => {
    const values = environment();
    delete (values as Record<string, string>)[name];

    expect(() => loadTlsMaterial(values)).toThrow(new RegExp(name));
  });

  it("rejects a malformed identity journal entry", () => {
    expect(() =>
      loadTlsMaterial(
        environment({ LOCAL_TLS_PRIVATE_KEY_IDENTITY: "not-json" }),
      ),
    ).toThrow(/not valid JSON/i);
  });
});
