import bcrypt from "bcryptjs";
import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";
import { config, reppoConfigured, servConfigured } from "./config.js";
import { decide } from "./decision.js";
import { reppoGet, reppoSubmit, servAssess } from "./providers.js";
import { analyzeAction, redact } from "./security.js";
import { all, audit, filter, find, insert, remove, update, type Row } from "./store.js";

export const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(",") ?? true }));
app.use(express.json({ limit: "256kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true }));

const hashKey = (k: string) => createHash("sha256").update(k).digest("hex");
type Authed = Request & { user?: { id: string; email: string; role: string } };

function auth(req: Authed, res: Response, next: NextFunction) {
  const h = req.headers.authorization ?? "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Missing bearer token" });
  try { req.user = jwt.verify(h.slice(7), config.jwtSecret) as Authed["user"]; next(); }
  catch { return res.status(401).json({ error: "Invalid or expired token" }); }
}
const ok = (res: Response, data: unknown, status = 200) => res.status(status).json({ data });
const fail = (res: Response, status: number, error: string) => res.status(status).json({ error });
function parse<T>(schema: z.ZodType<T>, req: Request, res: Response): T | null {
  const r = schema.safeParse(req.body);
  if (!r.success) { fail(res, 400, r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")); return null; }
  return r.data;
}

// ---------- Auth ----------
app.post("/api/v1/auth/register", async (req, res) => {
  const b = parse(z.object({ email: z.string().email(), password: z.string().min(8), name: z.string().optional() }), req, res); if (!b) return;
  if (find("users", (u) => u.email === b.email)) return fail(res, 409, "Email already registered");
  const user = insert("users", { email: b.email, name: b.name ?? null, role: "OWNER", passwordHash: await bcrypt.hash(b.password, 10) });
  audit("auth.register", { userId: user.id });
  ok(res, { token: sign(user), user: pub(user) }, 201);
});
app.post("/api/v1/auth/login", async (req, res) => {
  const b = parse(z.object({ email: z.string().email(), password: z.string().min(1) }), req, res); if (!b) return;
  const user = find("users", (u) => u.email === b.email);
  if (!user || !(await bcrypt.compare(b.password, String(user.passwordHash)))) return fail(res, 401, "Invalid credentials");
  ok(res, { token: sign(user), user: pub(user) });
});
const sign = (u: Row) => jwt.sign({ id: u.id, email: u.email, role: u.role }, config.jwtSecret, { expiresIn: "7d" });
const pub = (u: Row) => ({ id: u.id, email: u.email, name: u.name, role: u.role });
app.get("/api/v1/auth/me", auth, (req: Authed, res) => { const u = find("users", (x) => x.id === req.user!.id); u ? ok(res, pub(u)) : fail(res, 404, "User not found"); });

// ---------- Agents ----------
const agentSchema = z.object({ name: z.string().min(1).max(120), description: z.string().max(1000).optional(), permissions: z.array(z.string()).default([]), spendingLimitUsd: z.number().min(0).default(100), allowedDestinations: z.array(z.string()).default([]) });
app.post("/api/v1/agents", auth, (req: Authed, res) => {
  const b = parse(agentSchema, req, res); if (!b) return;
  const agent = insert("agents", { ...b, ownerId: req.user!.id, status: "ACTIVE" });
  const rawKey = `as_agent_${randomBytes(24).toString("hex")}`;
  insert("agentKeys", { agentId: agent.id, keyPrefix: rawKey.slice(0, 16), keyHash: hashKey(rawKey), revokedAt: null });
  audit("agent.created", { userId: req.user!.id, agentId: agent.id });
  // Raw key shown once, mirroring Reppo's key handling. Only the hash is stored.
  ok(res, { ...agent, apiKey: rawKey, apiKeyNote: "Store this now — only its SHA-256 hash is kept." }, 201);
});
app.get("/api/v1/agents", auth, (req: Authed, res) => ok(res, filter("agents", (a) => a.ownerId === req.user!.id)));
app.get("/api/v1/agents/:id", auth, (req: Authed, res) => {
  const a = find("agents", (x) => x.id === req.params.id && x.ownerId === req.user!.id);
  a ? ok(res, a) : fail(res, 404, "Agent not found");
});

// ---------- Actions ----------
const actionSchema = z.object({
  agentId: z.string().min(1), actionType: z.string().min(1).max(120),
  payload: z.record(z.unknown()).default({}), reasoning: z.string().max(20000).optional(),
  authorized: z.boolean().optional(), authorizationEvidence: z.string().max(4000).optional(),
  parentActionId: z.string().optional(), idempotencyKey: z.string().max(200).optional(),
});

async function processAction(req: Authed, res: Response) {
  const b = parse(actionSchema, req, res); if (!b) return;
  const agent = find("agents", (a) => a.id === b.agentId);
  if (!agent) return fail(res, 404, "Agent not found");
  if (b.idempotencyKey) {
    const dup = find("actions", (a) => a.idempotencyKey === b.idempotencyKey);
    if (dup) return ok(res, { action: dup, duplicate: true });
  }
  const action = insert("actions", { agentId: b.agentId, actionType: b.actionType, payload: b.payload, reasoning: b.reasoning ?? null, parentActionId: b.parentActionId ?? null, idempotencyKey: b.idempotencyKey ?? null, status: "ANALYZING" });
  audit("action.received", { agentId: b.agentId, actionId: action.id });

  const policy = { spendingLimitUsd: Number(agent.spendingLimitUsd ?? 100), allowedDestinations: (agent.allowedDestinations as string[]) ?? [], permissions: (agent.permissions as string[]) ?? [] };
  const { findings, hardViolations } = analyzeAction({ actionType: b.actionType, payload: b.payload ?? {}, reasoning: b.reasoning, authorized: b.authorized, authorizationEvidence: b.authorizationEvidence }, policy);
  for (const f of findings) insert("threats", { ...f, agentId: b.agentId, actionId: action.id, evidence: f.evidence });
  const critical = findings.some((f) => f.severity === "CRITICAL");

  // SERV (real call when configured; explicit unavailable otherwise)
  let serv = null as Awaited<ReturnType<typeof servAssess>> | null;
  let servError: string | null = null;
  try { serv = await servAssess({ actionType: b.actionType, payload: b.payload, reasoning: b.reasoning, policySummary: JSON.stringify(policy) }); }
  catch (e) { servError = e instanceof Error ? e.message : String(e); }
  insert("assessments", { actionId: action.id, provider: serv?.provider ?? "unavailable", requestId: serv?.requestId ?? null, threatDetected: Boolean(serv?.threatDetected || critical), riskScore: serv?.riskScore ?? (critical ? 95 : findings.length ? 60 : 10), recommendation: serv?.recommendation ?? null, policyViolations: hardViolations, latencyMs: serv?.latencyMs ?? null, rawResponse: servError ? { error: servError } : (serv?.raw ?? null) });

  // Reppo (sanitized trace; skipped only when hard-blocked to save credits, still recorded)
  let evaluation: Row | null = null;
  let reppoStatus = "NOT_SUBMITTED";
  if (critical || hardViolations.length > 0) {
    evaluation = insert("evaluations", { actionId: action.id, externalEvalId: null, status: "NOT_SUBMITTED", score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], note: "Not submitted: deterministic policy already blocks this action; Reppo credits are not spent on hard-blocked actions." });
    reppoStatus = "NOT_SUBMITTED";
  } else if (!reppoConfigured()) {
    evaluation = insert("evaluations", { actionId: action.id, externalEvalId: null, status: "NOT_SUBMITTED", score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], note: "REPPO_API_KEY not configured — no evaluation submitted. This is not an approval." });
    reppoStatus = "UNAVAILABLE";
  } else {
    try {
      const sub = await reppoSubmit({ actionType: b.actionType, payload: b.payload, reasoning: b.reasoning, context: `AgentShield security evaluation. Agent: ${String(agent.name)}. Action type: ${b.actionType}. Policy: spending limit ${policy.spendingLimitUsd} USD; allowed destinations: ${policy.allowedDestinations.join(", ") || "(any)"}. Synthetic/demo data only — no real credentials or customer data.` });
      evaluation = insert("evaluations", { actionId: action.id, externalEvalId: sub.evalId, status: sub.status, score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], rawResponse: sub.raw });
      reppoStatus = sub.status;
      audit("evaluation.submitted", { agentId: b.agentId, actionId: action.id });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      evaluation = insert("evaluations", { actionId: action.id, externalEvalId: null, status: "FAILED", score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], note: msg });
      reppoStatus = "FAILED";
    }
  }

  const reppoNorm = evaluation && evaluation.externalEvalId ? null : null;
  const result = decide({ hardViolations, criticalThreat: critical, serv, reppo: reppoNorm, reppoStatus });
  const decision = insert("decisions", { actionId: action.id, outcome: result.outcome, reasons: result.reasons, threshold: result.threshold, humanRequired: result.outcome === "REVIEW" });
  if (result.outcome === "REVIEW") insert("approvals", { decisionId: decision.id, status: "PENDING", note: null });
  update("actions", action.id, { status: result.outcome === "BLOCK" ? "BLOCKED" : result.outcome === "APPROVE" ? "DECIDED" : "PENDING_EVALUATION" });
  audit("decision.made", { agentId: b.agentId, actionId: action.id });

  // Improvement tracking: link revision to its parent evaluation
  if (b.parentActionId) {
    const origEval = filter("evaluations", (e) => e.actionId === b.parentActionId).at(-1);
    if (origEval) insert("improvements", { agentId: b.agentId, originalActionId: b.parentActionId, revisedActionId: action.id, originalScore: origEval.score ?? null, revisedScore: evaluation?.score ?? null, improvement: null, note: "Revised score fills in after the revised Reppo evaluation settles; poll GET /evaluations/:id." });
  }

  ok(res, {
    action: find("actions", (a) => a.id === action.id), findings,
    serv: serv ? { provider: serv.provider, recommendation: serv.recommendation, riskScore: serv.riskScore, requestId: serv.requestId } : { provider: "unavailable", error: servError },
    evaluation: evaluation ? { id: evaluation.id, externalEvalId: evaluation.externalEvalId, status: evaluation.status, note: evaluation.note ?? null } : null,
    decision: { outcome: result.outcome, reasons: result.reasons, threshold: result.threshold },
    feedback: result.outcome === "APPROVE" ? ["Action approved. No changes required."] : [...hardViolations, ...findings.map((f) => f.mitigation)],
  }, 201);
}
app.post("/api/v1/actions/analyze", auth, processAction);
app.get("/api/v1/actions", auth, (_req, res) => ok(res, all("actions").slice().reverse()));
app.get("/api/v1/actions/:id", auth, (req, res) => { const a = find("actions", (x) => x.id === req.params.id); a ? ok(res, a) : fail(res, 404, "Action not found"); });
app.get("/api/v1/actions/:id/trace", auth, (req, res) => {
  const a = find("actions", (x) => x.id === req.params.id); if (!a) return fail(res, 404, "Action not found");
  ok(res, { action: a, assessment: find("assessments", (s) => s.actionId === a.id) ?? null, threats: filter("threats", (t) => t.actionId === a.id), evaluations: filter("evaluations", (e) => e.actionId === a.id), decision: find("decisions", (d) => d.actionId === a.id) ?? null });
});

// ---------- Evaluations ----------
app.get("/api/v1/evaluations", auth, (_req, res) => ok(res, all("evaluations").slice().reverse()));
app.get("/api/v1/evaluations/:id", auth, async (req, res) => {
  const ev = find("evaluations", (e) => e.id === req.params.id || e.externalEvalId === req.params.id);
  if (!ev) return fail(res, 404, "Evaluation not found");
  if (ev.externalEvalId && ev.status === "PENDING" && reppoConfigured()) {
    try {
      const fresh = await reppoGet(String(ev.externalEvalId));
      const updated = update("evaluations", ev.id, { status: fresh.status, score: fresh.score, confidence: fresh.confidence, decision: fresh.decision, route: fresh.route, critiques: fresh.critiques, evidence: fresh.evidence, rawResponse: fresh.raw });
      return ok(res, updated);
    } catch (e) { return ok(res, { ...ev, pollError: e instanceof Error ? e.message : String(e) }); }
  }
  ok(res, ev);
});
app.post("/api/v1/evaluations/:id/retry", auth, async (req, res) => {
  const ev = find("evaluations", (e) => e.id === req.params.id);
  if (!ev) return fail(res, 404, "Evaluation not found");
  if (!ev.externalEvalId) return fail(res, 400, "Evaluation was never submitted (no evalId); submit a new action instead.");
  try { const fresh = await reppoGet(String(ev.externalEvalId)); ok(res, update("evaluations", ev.id, { status: fresh.status, score: fresh.score, confidence: fresh.confidence, decision: fresh.decision, route: fresh.route, critiques: fresh.critiques, evidence: fresh.evidence, rawResponse: fresh.raw })); }
  catch (e) { fail(res, 502, e instanceof Error ? e.message : String(e)); }
});

// ---------- Decisions / approvals ----------
app.get("/api/v1/decisions", auth, (_req, res) => ok(res, all("decisions").slice().reverse().map((d) => ({ ...d, approval: find("approvals", (a) => a.decisionId === d.id) ?? null }))));
app.post("/api/v1/decisions/:id/approve", auth, (req: Authed, res) => humanDecision(req, res, "APPROVED", "APPROVE"));
app.post("/api/v1/decisions/:id/reject", auth, (req: Authed, res) => humanDecision(req, res, "REJECTED", "BLOCK"));
function humanDecision(req: Authed, res: Response, status: string, outcome: string) {
  const d = find("decisions", (x) => x.id === req.params.id); if (!d) return fail(res, 404, "Decision not found");
  const ap = find("approvals", (a) => a.decisionId === d.id);
  if (ap) update("approvals", ap.id, { status, decidedBy: req.user!.id, decidedAt: new Date().toISOString() });
  update("decisions", d.id, { outcome, reasons: [...(d.reasons as string[]), `Human ${status.toLowerCase()} by ${req.user!.email}.`] });
  update("actions", String(d.actionId), { status: outcome === "APPROVE" ? "DECIDED" : "BLOCKED" });
  audit("decision.human", { userId: req.user!.id, actionId: d.actionId });
  ok(res, find("decisions", (x) => x.id === d.id));
}

// ---------- Policies ----------
app.get("/api/v1/policies", auth, (req: Authed, res) => ok(res, filter("policies", (p) => p.ownerId === req.user!.id)));
app.post("/api/v1/policies", auth, (req: Authed, res) => {
  const b = parse(z.object({ name: z.string().min(1), kind: z.string().min(1), config: z.record(z.unknown()).default({}) }), req, res); if (!b) return;
  const p = insert("policies", { ...b, ownerId: req.user!.id, enabled: true, version: 1 });
  insert("policyVersions", { policyId: p.id, version: 1, config: b.config });
  ok(res, p, 201);
});
app.patch("/api/v1/policies/:id", auth, (req: Authed, res) => {
  const p = find("policies", (x) => x.id === req.params.id && x.ownerId === req.user!.id); if (!p) return fail(res, 404, "Policy not found");
  const b = parse(z.object({ name: z.string().optional(), config: z.record(z.unknown()).optional(), enabled: z.boolean().optional() }), req, res); if (!b) return;
  const v = Number(p.version ?? 1) + 1;
  insert("policyVersions", { policyId: p.id, version: v, config: b.config ?? p.config });
  ok(res, update("policies", p.id, { ...b, version: v }));
});
app.delete("/api/v1/policies/:id", auth, (req: Authed, res) => {
  const p = find("policies", (x) => x.id === req.params.id && x.ownerId === req.user!.id); if (!p) return fail(res, 404, "Policy not found");
  remove("policies", p.id); ok(res, { deleted: true });
});

// ---------- Analytics / audit / integrations ----------
app.get("/api/v1/analytics/overview", auth, (_req, res) => {
  const acts = all("actions"), th = all("threats"), evs = all("evaluations"), decs = all("decisions");
  const settled = evs.filter((e) => typeof e.score === "number");
  ok(res, {
    agents: all("agents").length, actionsAnalyzed: acts.length, threatsDetected: th.length,
    actionsBlocked: decs.filter((d) => d.outcome === "BLOCK").length,
    avgReppoScore: settled.length ? Math.round(settled.reduce((s, e) => s + Number(e.score), 0) / settled.length) : null,
    settledEvaluations: settled.length, pendingEvaluations: evs.filter((e) => e.status === "PENDING").length,
    recentActivity: all("audit").slice(-10).reverse(),
  });
});
app.get("/api/v1/analytics/threats", auth, (_req, res) => {
  const th = all("threats"); const by: Record<string, number> = {};
  for (const t of th) by[String(t.severity)] = (by[String(t.severity)] ?? 0) + 1;
  ok(res, { total: th.length, bySeverity: by, findings: th.slice().reverse() });
});
app.get("/api/v1/analytics/improvements", auth, (_req, res) => {
  // Recompute from settled evaluations so revised scores appear after polling.
  const rows = all("improvements").map((m) => {
    const rev = filter("evaluations", (e) => e.actionId === m.revisedActionId).at(-1);
    const revisedScore = typeof rev?.score === "number" ? rev.score : m.revisedScore;
    return { ...m, revisedScore, improvement: typeof m.originalScore === "number" && typeof revisedScore === "number" ? revisedScore - m.originalScore : null };
  });
  const done = rows.filter((r) => typeof r.improvement === "number");
  ok(res, { items: rows.slice().reverse(), revisionSuccessRate: done.length ? Math.round(done.filter((r) => Number(r.improvement) > 0).length / done.length * 100) : null, avgImprovement: done.length ? Math.round(done.reduce((s, r) => s + Number(r.improvement), 0) / done.length) : null });
});
app.get("/api/v1/audit-logs", auth, (_req, res) => ok(res, all("audit").slice().reverse()));
app.get("/api/v1/integrations/status", auth, (_req, res) => ok(res, {
  serv: { configured: servConfigured(), baseUrl: config.serv.baseUrl, model: config.serv.model, status: servConfigured() ? "configured_unverified" : "not_configured", note: servConfigured() ? "Key present. Use Test connection to verify against the live API." : "Set SERV_API_KEY (from console.openserv.ai) to enable live SERV Reasoning." },
  reppo: { configured: reppoConfigured(), baseUrl: config.reppo.baseUrl, status: reppoConfigured() ? "configured_unverified" : "not_configured", note: reppoConfigured() ? "Key present. Use Test connection to verify against the live API." : "Set REPPO_API_KEY (from eval.reppo.xyz → API Key) to enable live evaluations." },
}));
app.post("/api/v1/integrations/test", auth, async (req, res) => {
  const b = parse(z.object({ provider: z.enum(["serv", "reppo"]) }), req, res); if (!b) return;
  try {
    if (b.provider === "serv") {
      if (!servConfigured()) return ok(res, { provider: "serv", ok: false, status: "not_configured", detail: "SERV_API_KEY missing" });
      const r = await servAssess({ actionType: "healthcheck", payload: { ping: true }, policySummary: "healthcheck only" });
      return ok(res, { provider: "serv", ok: r.provider === "serv", status: r.provider, detail: `model=${config.serv.model} requestId=${r.requestId}` });
    }
    if (!reppoConfigured()) return ok(res, { provider: "reppo", ok: false, status: "not_configured", detail: "REPPO_API_KEY missing" });
    // Read-only probe: listing pending evaluations verifies auth without spending credits.
    const r = await fetch(`${config.reppo.baseUrl}/agents/eval-requests/pending?page=1&pageSize=1`, { headers: { Authorization: `Bearer ${config.reppo.apiKey}` } });
    return ok(res, { provider: "reppo", ok: r.ok, status: r.ok ? "connected" : `http_${r.status}`, detail: r.ok ? "Authenticated against Reppo Evaluation API." : `Reppo returned HTTP ${r.status} (check key/credits).` });
  } catch (e) { return ok(res, { provider: b.provider, ok: false, status: "error", detail: e instanceof Error ? e.message : String(e) }); }
});

app.get("/health", (_req, res) => ok(res, { status: "ok", serv: servConfigured() ? "configured" : "not_configured", reppo: reppoConfigured() ? "configured" : "not_configured" }));
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => fail(res, 500, err.message || "Internal error"));
export { redact };
