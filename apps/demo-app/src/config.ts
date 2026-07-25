import { config as loadDotenv } from "dotenv";
import { z } from "zod";

loadDotenv({ path: ".data/.env", override: false, quiet: true });

export const evidenceModeSchema = z
  .enum(["LIVE_VERANA", "LOCAL_CONTROLLED"])
  .default("LIVE_VERANA");

export type EvidenceMode = z.infer<typeof evidenceModeSchema>;

export const demoConfigSchema = z
  .object({
    DEMO_APP_PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    PLAYGROUND_APP_CLIENT_SECRET: z.string().min(32),
    SESSION_SECRET: z.string().min(32),
    KEYCLOAK_ISSUER: z
      .string()
      .url()
      .default("http://localhost:8080/realms/verana-playground"),
    KEYCLOAK_CLIENT_ID: z.literal("playground-app").default("playground-app"),
    DEMO_APP_REDIRECT_URI: z
      .string()
      .url()
      .default("http://localhost:3000/callback"),
    VS_AGENT_ISSUER_BASE_URL: z.string().url().default("http://localhost:3101"),
    VS_AGENT_HOLDER_BASE_URL: z.string().url().default("http://localhost:3101"),
    VS_AGENT_VERIFIER_BASE_URL: z
      .string()
      .url()
      .default("http://localhost:3201"),
    EXPECTED_VCT: z.string().url().optional(),
    EXPECTED_VTJSC_ID: z.string().url().optional(),
    ROGUE_VERIFIER_DID: z.string().trim().min(1).max(2_048).optional(),
    VERANA_RESOLVER_URL: z.string().url().optional(),
    EVIDENCE_MODE: evidenceModeSchema,
  })
  .superRefine((config, context) => {
    if (config.EVIDENCE_MODE !== "LOCAL_CONTROLLED") return;
    for (const field of [
      "EXPECTED_VCT",
      "EXPECTED_VTJSC_ID",
      "ROGUE_VERIFIER_DID",
      "VERANA_RESOLVER_URL",
    ] as const) {
      if (config[field] === undefined) {
        context.addIssue({
          code: "custom",
          message: `${field} is required in LOCAL_CONTROLLED`,
          path: [field],
        });
      }
    }
  });

export type DemoConfig = z.infer<typeof demoConfigSchema>;

export function loadDemoConfig(
  environment: Record<string, string | undefined> = process.env,
): DemoConfig {
  return demoConfigSchema.parse(environment);
}
