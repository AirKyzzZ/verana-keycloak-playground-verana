import { describe, expect, it } from "vitest";

import { startHostProcess } from "../scripts/local-stack-process.js";

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
      "start:broker:3001",
      "start:demo:3000",
      "close:demo",
      "close:broker",
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

    expect(events).toEqual(["start:resolver:3099:127.0.0.1", "close:resolver"]);
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
