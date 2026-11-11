import { randomBytes } from "node:crypto";

export interface AppConfig {
  port: number; jwtSecret: string; scoreThreshold: number;
  maxEvalAgeMs: number; spendWindowHours: number;
  serv: { baseUrl: string; apiKey: string; model: string; timeoutMs: number };
  reppo: { baseUrl: string; apiKey: string; settlementMinutes: number; timeoutMs: number; mode: "evals" | "legacy"; taskType: string; dailyBudget: number };
}

const INSECURE = new Set(["", "dev-only-change-me-agentshield-secret", "change-me-to-a-long-random-string", "secret", "changeme"]);

/** Fails closed: in production a missing/weak JWT_SECRET aborts startup.
 *  In development an ephemeral per-boot secret is generated (tokens do not
 *  survive restarts) - never a hard-coded known value. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const secret = env.JWT_SECRET ?? "";
  const isProd = env.NODE_ENV === "production";
  if (isProd && (INSECURE.has(secret) || secret.length < 32)) {
    throw new Error("JWT_SECRET is required in production and must be at least 32 characters (generate: openssl rand -hex 32). Refusing to start.");
  }
  return {
    port: Number(env.PORT ?? 4000),
    jwtSecret: secret && !INSECURE.has(secret) ? secret : randomBytes(32).toString("hex"),
    scoreThreshold: Number(env.SCORE_THRESHOLD ?? 80),
    maxEvalAgeMs: Number(env.REPPO_MAX_EVAL_AGE_MS ?? 24 * 3600 * 1000),
    // Cumulative-spend limits apply to spend inside this rolling window.
    spendWindowHours: Number(env.SPEND_WINDOW_HOURS ?? 24),
    serv: {
      baseUrl: env.SERV_BASE_URL ?? "https://inference-api.openserv.ai",
      apiKey: env.SERV_API_KEY ?? "",
      model: env.SERV_MODEL ?? "gpt-5.4-mini",
      timeoutMs: Number(env.SERV_TIMEOUT_MS ?? 60000),
    },
    reppo: {
      baseUrl: env.REPPO_BASE_URL ?? "https://eval.reppo.xyz/api/v1",
      apiKey: env.REPPO_API_KEY ?? "",
      settlementMinutes: Number(env.REPPO_SETTLEMENT_MINUTES ?? 10),
      timeoutMs: Number(env.REPPO_TIMEOUT_MS ?? 20000),
      // "evals" = current API (POST /agents/evals, ~30-90s); "legacy" = old /agents/eval-requests/* (10+ min).
      mode: (env.REPPO_API_MODE === "legacy" ? "legacy" : "evals") as "evals" | "legacy",
      taskType: env.REPPO_TASK_TYPE ?? "response",
      // Each evaluation costs Reppo credits (~440). Cap submissions per rolling 24h so open sign-up cannot drain them.
      dailyBudget: Number(env.REPPO_DAILY_BUDGET ?? 30),
    },
  };
}

export const config = loadConfig();
export const servConfigured = () => config.serv.apiKey.trim().length > 0;
export const reppoConfigured = () => config.reppo.apiKey.trim().length > 0;
