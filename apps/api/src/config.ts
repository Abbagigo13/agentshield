export const config = {
  port: Number(process.env.PORT ?? 4000),
  jwtSecret: process.env.JWT_SECRET ?? "dev-only-change-me-agentshield-secret",
  scoreThreshold: Number(process.env.SCORE_THRESHOLD ?? 80),
  serv: {
    baseUrl: process.env.SERV_BASE_URL ?? "https://inference-api.openserv.ai",
    apiKey: process.env.SERV_API_KEY ?? "",
    model: process.env.SERV_MODEL ?? "gpt-5.4-mini",
    timeoutMs: Number(process.env.SERV_TIMEOUT_MS ?? 20000),
  },
  reppo: {
    baseUrl: process.env.REPPO_BASE_URL ?? "https://eval.reppo.xyz/api/v1",
    apiKey: process.env.REPPO_API_KEY ?? "",
    settlementMinutes: Number(process.env.REPPO_SETTLEMENT_MINUTES ?? 10),
    timeoutMs: Number(process.env.REPPO_TIMEOUT_MS ?? 20000),
  },
};
export const servConfigured = () => config.serv.apiKey.trim().length > 0;
export const reppoConfigured = () => config.reppo.apiKey.trim().length > 0;
