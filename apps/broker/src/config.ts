import { config as loadDotenv } from "dotenv";
import { z } from "zod";

loadDotenv({ path: ".data/.env", override: false, quiet: true });

export const brokerConfigSchema = z.object({
  BROKER_ISSUER: z.string().url().default("http://localhost:3001"),
  BROKER_PORT: z.coerce.number().int().min(1).max(65535).default(3001),
  BROKER_CLIENT_ID: z.string().default("keycloak-playground"),
  BROKER_CLIENT_SECRET: z.string().min(32),
  BROKER_COOKIE_SECRET: z.string().min(32),
  KEYCLOAK_BROKER_REDIRECT_URI: z
    .string()
    .url()
    .default(
      "http://localhost:8080/realms/verana-playground/broker/verana-wallet/endpoint",
    ),
  VS_AGENT_VERIFIER_BASE_URL: z.string().url().default("http://localhost:3201"),
  EXPECTED_VCT: z.string().url(),
  EXPECTED_VTJSC_ID: z.string().min(1),
  SECTOR_IDENTIFIER: z.string().default("verana-playground"),
  PAIRWISE_SUB_SECRET: z.string().min(32),
  BROKER_JWKS_PATH: z.string().default(".data/broker-jwks.json"),
});

export type BrokerConfig = z.infer<typeof brokerConfigSchema>;

export function loadBrokerConfig(
  environment: Record<string, string | undefined> = process.env,
): BrokerConfig {
  return brokerConfigSchema.parse(environment);
}
