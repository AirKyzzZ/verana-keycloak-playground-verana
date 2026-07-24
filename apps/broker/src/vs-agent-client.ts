import { z } from "zod";

const REQUEST_TIMEOUT_MS = 3_000;
const MAX_RESPONSE_BODY_BYTES = 64 * 1_024;

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

      if (!response.ok) {
        await response.body?.cancel();
        throw new Error("response_status_invalid");
      }
      const mediaType = response.headers
        .get("content-type")
        ?.split(";", 1)[0]
        ?.trim()
        .toLowerCase();
      if (mediaType !== "application/json") {
        await response.body?.cancel();
        throw new Error("response_content_type_invalid");
      }

      return schema.parse(await readBoundedJson(response));
    } catch {
      throw new Error("vs_agent_unavailable");
    }
  }
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength)) {
      await response.body?.cancel();
      throw new Error("response_length_invalid");
    }
    if (Number(declaredLength) > MAX_RESPONSE_BODY_BYTES) {
      await response.body?.cancel();
      throw new Error("response_too_large");
    }
  }

  const reader = response.body?.getReader();
  if (!reader) throw new Error("response_body_missing");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BODY_BYTES) {
        await reader.cancel();
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  return JSON.parse(text);
}
