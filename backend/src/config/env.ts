import { config } from 'dotenv';
import { z } from 'zod';

// Load .env file
config();

const envSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(4000),
  HOST: z.string().default('0.0.0.0'),

  // Database
  DATABASE_URL: z.string().optional(),
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.coerce.number().default(5432),
  DB_NAME: z.string().default('codehardener'),
  DB_USER: z.string().default('codehardener'),
  DB_PASSWORD: z.string().default('codehardener_dev'),

  // Redis
  REDIS_URL: z.string().optional(),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().default(6379),

  // JWT
  JWT_SECRET: z.string().default('dev-secret-change-in-production'),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // CORS
  CORS_ORIGIN: z.string().default('http://localhost:3000,http://localhost:3001'),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().default(100),

  // Logging
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  // Scanners
  SCANNER_TIMEOUT_MS: z.coerce.number().default(300000),
  SCANNER_MAX_CONCURRENT: z.coerce.number().default(5),

  // GitHub Integration
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  GITHUB_CALLBACK_URL: z.string().optional(),
  GITHUB_TOKEN_ENCRYPTION_KEY: z.string().optional(), // 64 hex chars (32 bytes)
  GITHUB_WEBHOOK_BASE_URL: z.string().optional(),

  // DefectDojo
  DEFECTDOJO_URL: z.string().default('http://defectdojo:8080'),
  DEFECTDOJO_API_KEY: z.string().optional(),
  DEFECTDOJO_ENABLED: z.coerce.boolean().default(false),

  // n8n
  N8N_URL: z.string().default('http://n8n:5678'),
  N8N_ENABLED: z.coerce.boolean().default(false),
  N8N_WEBHOOK_BASE: z.string().default('http://n8n:5678/webhook'),
  N8N_API_KEY: z.string().optional(),

  // Internal API Key (for n8n -> backend communication)
  INTERNAL_API_KEY: z.string().default('dev-internal-key-change-in-production'),

  // Stripe Billing
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_WEBHOOK_SECRET: z.string().optional(),
  STRIPE_PRICE_PRO_MONTHLY: z.string().optional(),
  STRIPE_PRICE_TEAM_MONTHLY: z.string().optional(),

  // LLM Verification (optional, enables premium exploit verification)
  ANTHROPIC_API_KEY: z.string().optional(),
  LLM_VERIFY_MODEL: z.string().default('claude-haiku-4-5-20251001'),
  LLM_VERIFY_MAX_FINDINGS: z.coerce.number().default(10),

  // LLM Assurance Scanners (defending-code-reference-harness integration)
  // ADV-3: constrain model overrides to Anthropic model ids so a hostile env can't
  // redirect LLM calls to an arbitrary model string (only the two NEW vars).
  LLM_SCAN_MODEL: z
    .string()
    .regex(/^claude-[a-z0-9.-]+$/, 'must be an Anthropic claude-* model id')
    .default('claude-sonnet-4-5-20250929'),
  LLM_THREATMODEL_MODEL: z
    .string()
    .regex(/^claude-[a-z0-9.-]+$/, 'must be an Anthropic claude-* model id')
    .default('claude-haiku-4-5-20251001'),
  LLM_SCAN_MAX_FOCUS_AREAS: z.coerce.number().default(8),
  LLM_SCAN_MAX_TOKENS_PER_AREA: z.coerce.number().default(8000),
  // ADV-2: z.coerce.boolean() treats ANY non-empty string (incl. "false") as true,
  // so the off-switch was unusable. Parse the literal token instead.
  LLM_SCAN_CONFIDENCE_PASS: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),
  LLM_TRIAGE_MAX_FINDINGS: z.coerce.number().default(20),
  LLM_TRIAGE_VOTES: z.coerce.number().default(3),
  LLM_PATCH_MAX_FINDINGS: z.coerce.number().default(5),
  // §11 R2 aggregate cost circuit-breaker. Raised 500k→2M: a realistic repo
  // (e.g. this 630-file codebase) needs headroom for threatmodel + fan-out
  // vuln-scan + triage + patch within a single shared budget.
  LLM_SCAN_MAX_TOTAL_TOKENS: z.coerce.number().default(2000000),
  // §11 R2 refinement: per-stage reservation. Caps the threat-model stage's
  // consumption so it cannot drain the whole shared budget and starve the
  // downstream vuln-scan / triage / patch stages. The shared budget remains the
  // hard aggregate ceiling; this only bounds one stage's slice of it.
  LLM_THREATMODEL_MAX_TOKENS: z.coerce.number().default(150000),
  // Convergence pressure for the threat-model agent: cap its tool-use round trips
  // so it cannot wander the whole tree on large repos. The agent is seeded with
  // CA-001..010 code-analysis output; ~14 iterations is enough for a handful of
  // targeted confirmation reads + synthesis, after which it MUST emit the
  // complete THREAT_MODEL.md. The aggregate token budget remains the backstop.
  LLM_THREATMODEL_MAX_ITERATIONS: z.coerce.number().default(14),
  // Per-request timeout for the threat-model agent. The final synthesis turn emits
  // the full 8-section THREAT_MODEL.md, which on large repos exceeds the default
  // 30s request timeout (inherited from llm-verifier) and aborts. 120s lets the
  // document generation complete.
  LLM_THREATMODEL_REQUEST_TIMEOUT_MS: z.coerce.number().default(120000),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('Invalid environment variables:', parsed.error.format());
  process.exit(1);
}

export const env = parsed.data;

// Computed values
export const databaseUrl = env.DATABASE_URL ||
  `postgresql://${env.DB_USER}:${env.DB_PASSWORD}@${env.DB_HOST}:${env.DB_PORT}/${env.DB_NAME}`;

export const redisUrl = env.REDIS_URL ||
  `redis://${env.REDIS_HOST}:${env.REDIS_PORT}`;

export const corsOrigins = env.CORS_ORIGIN.split(',').map(o => o.trim());

export const isDev = env.NODE_ENV === 'development';
export const isProd = env.NODE_ENV === 'production';

// Refuse to run in production with the development placeholder credentials.
// Both defaults are published in this repository, so a deployment that forgot
// to set them accepts tokens anyone can forge and an internal API key anyone
// can read. Fail at startup rather than serve with a known secret.
const DEV_PLACEHOLDER_SECRETS: Array<[string, string]> = [
  ['JWT_SECRET', 'dev-secret-change-in-production'],
  ['INTERNAL_API_KEY', 'dev-internal-key-change-in-production'],
];

if (isProd) {
  const unset = DEV_PLACEHOLDER_SECRETS
    .filter(([name, placeholder]) => (env as Record<string, unknown>)[name] === placeholder)
    .map(([name]) => name);
  if (unset.length > 0) {
    console.error(
      `[FATAL] ${unset.join(', ')} still set to the development placeholder. ` +
      'These values are published in the repository; set real secrets before running in production.'
    );
    process.exit(1);
  }
}
export const isTest = env.NODE_ENV === 'test';

export const stripeEnabled = !!env.STRIPE_SECRET_KEY;
export const llmVerifyEnabled = !!env.ANTHROPIC_API_KEY;
