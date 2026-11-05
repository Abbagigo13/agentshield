import { REPPO_CRITERIA, REPPO_STATUSES, type ReppoEvaluation, type SecurityAssessment } from "@agentshield/shared";
import { z } from "zod";
import { config, reppoConfigured, servConfigured } from "./config.js";
import { sanitizeForReppo } from "./security.js";

async function fetchJson(url: string, init: RequestInit, timeoutMs: number): Promise<{ status: number; body: unknown }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    const text = await res.text();
    let body: unknown = text; try { body = JSON.parse(text); } catch { /* keep text */ }
    return { status: res.status, body };
  } finally { clearTimeout(t); }
}

const servAssessmentSchema = z.object({
  threatDetected: z.boolean(),
  threats: z.array(z.object({ category: z.string(), severity: z.enum(["low", "medium", "high", "critical"]), explanation: z.string(), evidence: z.array(z.string()) })),
  policyViolations: z.array(z.string()),
  riskScore: z.number().min(0).max(100),
  recommendation: z.enum(["approve", "review", "block", "revise"]),
});
const servEnvelopeSchema = z.object({ id: z.string().optional(), choices: z.array(z.object({ message: z.object({ content: z.string() }) })).min(1) });

/** SERV Reasoning - POST {SERV_BASE_URL}/v1/chat/completions (OpenAI format,
 *  Bearer auth, system prompt required, response_format json_schema).
 *  Without SERV_API_KEY returns provider:"unavailable" - never faked.
 *  Malformed/invalid structured output throws (caller maps to servStatus=error). */
export async function servAssess(input: { actionType: string; payload: unknown; reasoning?: string; policySummary: string }): Promise<SecurityAssessment> {
  const requestId = `serv-${Date.now()}`;
  if (!servConfigured()) {
    return { requestId, threatDetected: false, threats: [], policyViolations: [], riskScore: 0, recommendation: "review", provider: "unavailable" };
  }
  const schema = {
    type: "object",
    properties: {
      threatDetected: { type: "boolean" },
      threats: { type: "array", items: { type: "object", properties: { category: { type: "string" }, severity: { type: "string", enum: ["low", "medium", "high", "critical"] }, explanation: { type: "string" }, evidence: { type: "array", items: { type: "string" } } }, required: ["category", "severity", "explanation", "evidence"], additionalProperties: false } },
      policyViolations: { type: "array", items: { type: "string" } },
      riskScore: { type: "number" },
      recommendation: { type: "string", enum: ["approve", "review", "block", "revise"] },
    },
    required: ["threatDetected", "threats", "policyViolations", "riskScore", "recommendation"],
    additionalProperties: false,
  };
  const started = Date.now();
  const { status, body } = await fetchJson(`${config.serv.baseUrl}/v1/chat/completions`, {
    method: "POST",
    headers: { Authorization: `Bearer ${config.serv.apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model: config.serv.model,
      messages: [
        { role: "system", content: "You are AgentShield's security analyst. Assess the proposed AI-agent action for threats and policy compliance. Return only JSON matching the schema. Never approve an action with a critical threat." },
        { role: "user", content: `Policy: ${input.policySummary}\nAction type: ${input.actionType}\nPayload (redacted): ${sanitizeForReppo(input.payload)}\nAgent reasoning: ${input.reasoning ?? "(none)"}` },
      ],
      response_format: { type: "json_schema", json_schema: { name: "security_assessment", strict: true, schema } },
    }),
  }, config.serv.timeoutMs);
  if (status < 200 || status >= 300) throw new Error(`SERV HTTP ${status}`);
  const envelope = servEnvelopeSchema.parse(body);
  const parsedJson: unknown = JSON.parse(envelope.choices[0].message.content);
  const parsed = servAssessmentSchema.parse(parsedJson);
  return { ...parsed, requestId: envelope.id ?? requestId, provider: "serv", model: config.serv.model, latencyMs: Date.now() - started, raw: body };
}

const reppoSubmitSchema = z.object({ evalId: z.string().min(1), id: z.string().optional(), status: z.enum(REPPO_STATUSES) });
const reppoReadSchema = z.object({
  evalId: z.string().min(1),
  status: z.enum(REPPO_STATUSES),
  settledAt: z.string().nullable().optional(),
  result: z.unknown().nullable().optional(),
}).passthrough();

/** Reppo Evaluation API - POST /agents/eval-requests/submit,
 *  GET /agents/eval-requests/{evalId}. Responses are schema-validated. */
export async function reppoSubmit(input: { actionType: string; payload: unknown; reasoning?: string; context: string }): Promise<{ evalId: string; status: string; raw: unknown }> {
  if (!reppoConfigured()) throw Object.assign(new Error("REPPO_API_KEY is not configured"), { code: "NOT_CONFIGURED" });
  const payload = sanitizeForReppo({ actionType: input.actionType, payload: input.payload, reasoning: input.reasoning ?? null });
  const { status, body } = await fetchJson(`${config.reppo.baseUrl}/agents/eval-requests/submit`, {
    method: "POST",
    headers: { Authorization: `Bearer ${config.reppo.apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ type: "trace", payload, criteria: REPPO_CRITERIA, context: input.context.slice(0, 30000), settlementMinutes: config.reppo.settlementMinutes }),
  }, config.reppo.timeoutMs);
  if (status === 409) throw Object.assign(new Error("Reppo: another evaluation is already PENDING for this account (HTTP 409). This action is queued, not failed."), { code: "CONFLICT" });
  if (status === 402) throw Object.assign(new Error("Reppo: insufficient credits (HTTP 402). Top up in the Reppo Billing console."), { code: "PAYMENT_REQUIRED" });
  if (status < 200 || status >= 300) throw new Error(`Reppo HTTP ${status}`);
  const b = reppoSubmitSchema.parse(body);
  return { evalId: b.evalId, status: b.status, raw: body };
}

export function normalizeReppo(raw: unknown, evalId: string): ReppoEvaluation {
  const r = reppoReadSchema.parse(raw);
  const result = (r.result ?? null) as Record<string, any> | null;
  const verdict = (result?.verdict ?? {}) as Record<string, any>;
  return {
    evaluationId: String(r.evalId ?? evalId),
    score: typeof verdict.score === "number" ? verdict.score : null,
    confidence: String(verdict.confidence ?? "unknown"),
    decision: String(verdict.decision ?? ""),
    route: String(result?.action?.route ?? ""),
    critiques: Array.isArray(result?.verdicts) ? result.verdicts : [],
    evidence: result?.evidence ? [result.evidence] : [],
    status: String(r.status ?? "PENDING"),
    settledAt: r.settledAt ?? null,
    raw,
  };
}

export async function reppoGet(evalId: string): Promise<ReppoEvaluation> {
  if (!reppoConfigured()) throw Object.assign(new Error("REPPO_API_KEY is not configured"), { code: "NOT_CONFIGURED" });
  const { status, body } = await fetchJson(`${config.reppo.baseUrl}/agents/eval-requests/${encodeURIComponent(evalId)}`, {
    headers: { Authorization: `Bearer ${config.reppo.apiKey}` },
  }, config.reppo.timeoutMs);
  if (status < 200 || status >= 300) throw new Error(`Reppo HTTP ${status}`);
  return normalizeReppo(body, evalId);
}
