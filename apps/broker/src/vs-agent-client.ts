import { z } from "zod";

const REQUEST_TIMEOUT_MS = 3_000;

const createRequestResponseSchema = z.strictObject({
  authorizationRequest: z.string().trim().min(1),
  sessionId: z.string().trim().min(1),
});

const pendingSessionSchema = z.strictObject({
  state: z.string().trim().min(1),
});

const verifiedSessionSchema = z.strictObject({
  state: z.literal("ResponseVerified"),
  receipt: z.unknown(),
});

const sessionResponseSchema = z.union([
  verifiedSessionSchema,
  pendingSessionSchema,
]);

export type VsAgentSession = z.infer<typeof sessionResponseSchema>;

export class VsAgentClient {
  readonly #baseUrl: string;

  constructor(baseUrl: string) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
  }

  async createRequest(
    tenant: "trusted",
  ): Promise<z.infer<typeof createRequestResponseSchema>> {
    return await this.#request(
      "/oid4vc-demo/verifier/requests",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({ tenant }),
      },
      createRequestResponseSchema,
    );
  }

  async getSession(sessionId: string): Promise<VsAgentSession> {
    return await this.#request(
      `/oid4vc-demo/verifier/sessions/${encodeURIComponent(sessionId)}`,
      {
        method: "GET",
      },
      sessionResponseSchema,
    );
  }

  async #request<T>(
    path: string,
    init: RequestInit,
    schema: z.ZodType<T>,
  ): Promise<T> {
    try {
      const response = await fetch(`${this.#baseUrl}${path}`, {
        ...init,
        cache: "no-store",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (!response.ok) throw new Error("vs_agent_unavailable");

      return schema.parse(await response.json());
    } catch {
      throw new Error("vs_agent_unavailable");
    }
  }
}
