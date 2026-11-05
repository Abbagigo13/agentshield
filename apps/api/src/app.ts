import bcrypt from "bcryptjs";
import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { config, reppoConfigured, servConfigured } from "./config.js";
import { decide } from "./decision.js";
import { reppoGet, reppoSubmit, servAssess } from "./providers.js";
import { analyzeAction, deepFinancials, redact } from "./security.js";
import { all, audit, claimApproval, filter, find, insert, prismaEnabled, remove, update, type Row } from "./db.js";
import type { SecurityAssessment } from "@agentshield/shared";

export const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(",") ?? true }));
app.use(express.json({ limit: "256kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true }));

export const hashKey = (k: string) => createHash("sha256").update(k).digest("hex");
function keysEqual(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

type Actor = { type: "user"; id: string; email: string; role: string } | { type: "agent"; agentId: string; ownerId: string };
type Authed = Request & { actor?: Actor };

/** Accepts a user JWT, or an agent API key (`x-agent-api-key` header or
 *  `Bearer as_agent_...`). Agent keys are hash-compared, and revoked,
 *  expired, or non-ACTIVE agents are rejected. */
async function auth(req: Authed, res: Response, next: NextFunction) {
  const agentKey = (req.headers["x-agent-api-key"] as string) || ((req.headers.authorization ?? "").startsWith("Bearer as_agent_") ? (req.headers.authorization ?? "").slice(7) : "");
  if (agentKey) {
    const rec = (await filter("agentKeys", (k) => keysEqual(String(k.keyHash), hashKey(agentKey))))[0];
    if (!rec) return res.status(401).json({ error: "Invalid agent API key" });
    if (rec.revokedAt) return res.status(401).json({ error: "Agent API key has been revoked" });
    if (rec.expiresAt && Date.parse(String(rec.expiresAt)) < Date.now()) return res.status(401).json({ error: "Agent API key has expired" });
    const agent = await find("agents", (a) => a.id === rec.agentId);
    if (!agent || agent.status !== "ACTIVE") return res.status(403).json({ error: "Agent is not ACTIVE" });
    await update("agentKeys", rec.id, { lastUsedAt: new Date().toISOString() });
    req.actor = { type: "agent", agentId: String(agent.id), ownerId: String(agent.ownerId) };
    return next();
  }
  const h = req.headers.authorization ?? "";
  if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Missing bearer token" });
  try {
    const u = jwt.verify(h.slice(7), config.jwtSecret) as { id: string; email: string; role: string };
    req.actor = { type: "user", id: u.id, email: u.email, role: u.role };
    next();
  } catch { return res.status(401).json({ error: "Invalid or expired token" }); }
}
function requireUser(req: Authed, res: Response, next: NextFunction) {
  if (req.actor?.type !== "user") return res.status(403).json({ error: "User authentication required" });
  next();
}
const ownerOf = (req: Authed) => (req.actor!.type === "user" ? req.actor!.id : req.actor!.ownerId);
const ok = (res: Response, data: unknown, status = 200) => res.status(status).json({ data });
const fail = (res: Response, status: number, error: string) => res.status(status).json({ error });
function parse<T>(schema: z.ZodType<T>, req: Request, res: Response): T | null {
  const r = schema.safeParse(req.body);
  if (!r.success) { fail(res, 400, r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")); return null; }
  return r.data;
}
const owns = (req: Authed, row?: Row) => Boolean(row) && String(row!.ownerId ?? "") === ownerOf(req);

// ---------- Auth ----------
app.post("/api/v1/auth/register", async (req, res) => {
  const b = parse(z.object({ email: z.string().email(), password: z.string().min(8), name: z.string().optional() }), req, res); if (!b) return;
  if (await find("users", (u) => u.email === b.email)) return fail(res, 409, "Email already registered");
  const user = await insert("users", { email: b.email, name: b.name ?? null, role: "OWNER", passwordHash: await bcrypt.hash(b.password, 10) });
  await audit("auth.register", { userId: user.id, ownerId: user.id });
  ok(res, { token: sign(user), user: pub(user) }, 201);
});
app.post("/api/v1/auth/login", async (req, res) => {
  const b = parse(z.object({ email: z.string().email(), password: z.string().min(1) }), req, res); if (!b) return;
  const user = await find("users", (u) => u.email === b.email);
  if (!user || !(await bcrypt.compare(b.password, String(user.passwordHash)))) return fail(res, 401, "Invalid credentials");
  ok(res, { token: sign(user), user: pub(user) });
});
const sign = (u: Row) => jwt.sign({ id: u.id, email: u.email, role: u.role }, config.jwtSecret, { expiresIn: "7d" });
const pub = (u: Row) => ({ id: u.id, email: u.email, name: u.name, role: u.role });
app.get("/api/v1/auth/me", auth, requireUser, async (req: Authed, res) => { const u = await find("users", (x) => x.id === (req.actor as { id: string }).id); u ? ok(res, pub(u)) : fail(res, 404, "User not found"); });

// ---------- Agents + keys ----------
const agentSchema = z.object({ name: z.string().min(1).max(120), description: z.string().max(1000).optional(), permissions: z.array(z.string()).default([]), spendingLimitUsd: z.number().min(0).default(100), allowedDestinations: z.array(z.string()).default([]) });
async function issueKey(agentId: string): Promise<string> {
  const rawKey = `as_agent_${randomBytes(24).toString("hex")}`;
  await insert("agentKeys", { agentId, keyPrefix: rawKey.slice(0, 16), keyHash: hashKey(rawKey), revokedAt: null, expiresAt: null });
  return rawKey;
}
app.post("/api/v1/agents", auth, requireUser, async (req: Authed, res) => {
  const b = parse(agentSchema, req, res); if (!b) return;
  const agent = await insert("agents", { ...b, ownerId: ownerOf(req), status: "ACTIVE" });
  const rawKey = await issueKey(agent.id);
  await audit("agent.created", { userId: ownerOf(req), ownerId: ownerOf(req), agentId: agent.id });
  ok(res, { ...agent, apiKey: rawKey, apiKeyNote: "Store this now - only its SHA-256 hash is kept." }, 201);
});
app.get("/api/v1/agents", auth, requireUser, async (req: Authed, res) => ok(res, await filter("agents", (a) => a.ownerId === ownerOf(req))));
app.get("/api/v1/agents/:id", auth, requireUser, async (req: Authed, res) => {
  const a = await find("agents", (x) => x.id === req.params.id && x.ownerId === ownerOf(req));
  a ? ok(res, a) : fail(res, 404, "Agent not found");
});
/** Rotate: revoke all live keys for the agent and issue a fresh one. */
app.post("/api/v1/agents/:id/keys/rotate", auth, requireUser, async (req: Authed, res) => {
  const a = await find("agents", (x) => x.id === req.params.id && x.ownerId === ownerOf(req));
  if (!a) return fail(res, 404, "Agent not found");
  for (const k of await filter("agentKeys", (k) => k.agentId === a.id && !k.revokedAt)) await update("agentKeys", k.id, { revokedAt: new Date().toISOString() });
  const rawKey = await issueKey(a.id);
  await audit("agent.key_rotated", { userId: ownerOf(req), ownerId: ownerOf(req), agentId: a.id });
  ok(res, { apiKey: rawKey, apiKeyNote: "Previous keys revoked. Store this now - only its hash is kept." }, 201);
});
app.post("/api/v1/agents/:id/keys/:keyId/revoke", auth, requireUser, async (req: Authed, res) => {
  const a = await find("agents", (x) => x.id === req.params.id && x.ownerId === ownerOf(req));
  if (!a) return fail(res, 404, "Agent not found");
  const k = await find("agentKeys", (x) => x.id === req.params.keyId && x.agentId === a.id);
  if (!k) return fail(res, 404, "Key not found");
  await update("agentKeys", k.id, { revokedAt: new Date().toISOString() });
  await audit("agent.key_revoked", { userId: ownerOf(req), ownerId: ownerOf(req), agentId: a.id });
  ok(res, { revoked: true });
});
app.get("/api/v1/agents/:id/keys", auth, requireUser, async (req: Authed, res) => {
  const a = await find("agents", (x) => x.id === req.params.id && x.ownerId === ownerOf(req));
  if (!a) return fail(res, 404, "Agent not found");
  ok(res, (await filter("agentKeys", (k) => k.agentId === a.id)).map((k) => ({ id: k.id, keyPrefix: k.keyPrefix, revokedAt: k.revokedAt, expiresAt: k.expiresAt, lastUsedAt: k.lastUsedAt ?? null, createdAt: k.createdAt })));
});

// ---------- Actions ----------
const actionSchema = z.object({
  agentId: z.string().min(1), actionType: z.string().min(1).max(120),
  payload: z.record(z.unknown()).default({}), reasoning: z.string().max(20000).optional(),
  authorized: z.boolean().optional(), authorizationEvidence: z.string().max(4000).optional(),
  parentActionId: z.string().optional(), idempotencyKey: z.string().max(200).optional(),
});

async function priorSpentUsd(agentId: string): Promise<number> {
  return (await filter("actions", (a) => a.agentId === agentId && a.status !== "BLOCKED"))
    .reduce((s, a) => s + deepFinancials(a.payload ?? {}).amounts.reduce((x, y) => x + y, 0), 0);
}
function servFromAssessment(a?: Row): { serv: SecurityAssessment | null; servStatus: "ok" | "unavailable" | "error" } {
  if (!a) return { serv: null, servStatus: "error" };
  if (a.provider === "serv") return { serv: { requestId: String(a.requestId ?? ""), threatDetected: Boolean(a.threatDetected), threats: [], policyViolations: (a.policyViolations as string[]) ?? [], riskScore: Number(a.riskScore ?? 0), recommendation: (a.recommendation as SecurityAssessment["recommendation"]) ?? "review", provider: "serv" }, servStatus: "ok" };
  if (a.provider === "unavailable") return { serv: { requestId: String(a.requestId ?? ""), threatDetected: false, threats: [], policyViolations: [], riskScore: 0, recommendation: "review", provider: "unavailable" }, servStatus: "unavailable" };
  return { serv: null, servStatus: "error" };
}

/** Re-run the decision engine for an action (used on submission and whenever
 *  its Reppo evaluation settles). Updates decision, approval, action status,
 *  feedback and audit. Synchronous store writes make each transition atomic. */
export async function reevaluate(actionId: string) {
  const action = await find("actions", (a) => a.id === actionId); if (!action) return null;
  const threats = await filter("threats", (t) => t.actionId === actionId);
  const hardViolations = threats.filter((t) => t.hard).map((t) => String(t.description));
  const critical = threats.some((t) => t.severity === "CRITICAL");
  const { serv, servStatus } = servFromAssessment(await find("assessments", (s) => s.actionId === actionId));
  const ev = (await filter("evaluations", (e) => e.actionId === actionId)).at(-1);
  const reppo = ev && ev.status === "SETTLED" ? { evaluationId: String(ev.externalEvalId ?? ev.id), score: typeof ev.score === "number" ? ev.score : null, confidence: String(ev.confidence ?? "unknown"), decision: String(ev.decision ?? ""), route: String(ev.route ?? ""), critiques: (ev.critiques as unknown[]) ?? [], evidence: (ev.evidence as unknown[]) ?? [], status: "SETTLED", settledAt: (ev.settledAt as string) ?? null } : null;
  const result = decide({ hardViolations, criticalThreat: critical, serv, servStatus, reppo, reppoStatus: String(ev?.status ?? "NOT_SUBMITTED"), threshold: config.scoreThreshold, maxEvalAgeMs: config.maxEvalAgeMs });
  let decision = await find("decisions", (d) => d.actionId === actionId);
  if (decision) await update("decisions", decision.id, { outcome: result.outcome, reasons: result.reasons, threshold: result.threshold, humanRequired: result.outcome === "REVIEW" });
  else decision = await insert("decisions", { actionId, ownerId: action.ownerId, outcome: result.outcome, reasons: result.reasons, threshold: result.threshold, humanRequired: result.outcome === "REVIEW" });
  const approval = await find("approvals", (a) => a.decisionId === decision!.id);
  if (result.outcome === "REVIEW" && !approval) await insert("approvals", { decisionId: decision.id, ownerId: action.ownerId, status: "PENDING", note: null });
  if (result.outcome !== "REVIEW" && approval && approval.status === "PENDING") await update("approvals", approval.id, { status: "SUPERSEDED" });
  await update("actions", actionId, { status: result.outcome === "BLOCK" ? "BLOCKED" : result.outcome === "APPROVE" ? "DECIDED" : result.outcome === "HOLD" ? "PENDING_EVALUATION" : "DECIDED" });
  return { decision: await find("decisions", (d) => d.actionId === actionId), result };
}

/** Poll Reppo for one evaluation; on settlement, re-evaluate the decision. */
export async function pollAndReevaluate(evaluationId: string) {
  const ev = await find("evaluations", (e) => e.id === evaluationId || e.externalEvalId === evaluationId);
  if (!ev) return null;
  if (!ev.externalEvalId || !reppoConfigured()) return { evaluation: ev, decision: await find("decisions", (d) => d.actionId === ev.actionId) ?? null };
  const fresh = await reppoGet(String(ev.externalEvalId));
  const updated = await update("evaluations", ev.id, { status: fresh.status, score: fresh.score, confidence: fresh.confidence, decision: fresh.decision, route: fresh.route, critiques: fresh.critiques, evidence: fresh.evidence, settledAt: fresh.settledAt ?? null, rawResponse: redact(fresh.raw) });
  if (fresh.status === "SETTLED") {
    await audit("evaluation.settled", { ownerId: ev.ownerId, agentId: ev.agentId, actionId: ev.actionId });
    await insert("feedback", { evaluationId: ev.id, ownerId: ev.ownerId, actionId: ev.actionId, message: fresh.critiques.length ? "Reppo critiques available for agent revision." : "Reppo evaluation settled.", critiques: fresh.critiques });
    const r = await reevaluate(String(ev.actionId));
    await audit("decision.reevaluated", { ownerId: ev.ownerId, agentId: ev.agentId, actionId: ev.actionId });
    return { evaluation: updated, decision: r?.decision ?? null };
  }
  return { evaluation: updated, decision: await find("decisions", (d) => d.actionId === ev.actionId) ?? null };
}
export async function pollPendingEvaluations(): Promise<number> {
  let n = 0;
  for (const ev of await filter("evaluations", (e) => e.status === "PENDING" && Boolean(e.externalEvalId))) { try { await pollAndReevaluate(ev.id); n++; } catch { /* keep polling others */ } }
  return n;
}

async function processAction(req: Authed, res: Response) {
  const b = parse(actionSchema, req, res); if (!b) return;
  const agent = await find("agents", (a) => a.id === b.agentId);
  if (!agent) return fail(res, 404, "Agent not found");
  // Tenant + actor enforcement: users act only on their own agents; agent
  // credentials act only for themselves.
  if (req.actor!.type === "user" && String(agent.ownerId) !== req.actor!.id) return fail(res, 404, "Agent not found");
  if (req.actor!.type === "agent" && req.actor!.agentId !== String(agent.id)) return fail(res, 403, "Agent key does not match agentId");
  if (agent.status !== "ACTIVE") return fail(res, 403, "Agent is not ACTIVE");
  if (b.idempotencyKey) {
    const dup = await find("actions", (a) => a.idempotencyKey === b.idempotencyKey && a.ownerId === agent.ownerId);
    if (dup) return ok(res, { action: dup, duplicate: true });
  }
  // Prior spend must be measured before this action is stored, otherwise
  // the current action is counted twice by the cumulative-limit check.
  const spentBefore = await priorSpentUsd(b.agentId);
  // Raw secrets never persist: the stored payload/reasoning are redacted.
  const action = await insert("actions", { agentId: b.agentId, ownerId: agent.ownerId, actionType: b.actionType, payload: redact(b.payload ?? {}), reasoning: b.reasoning ? String(redact(b.reasoning)) : null, parentActionId: b.parentActionId ?? null, idempotencyKey: b.idempotencyKey ?? null, status: "ANALYZING" });
  await audit("action.received", { ownerId: agent.ownerId, agentId: b.agentId, actionId: action.id });

  const policy = { spendingLimitUsd: Number(agent.spendingLimitUsd ?? 100), allowedDestinations: (agent.allowedDestinations as string[]) ?? [], permissions: (agent.permissions as string[]) ?? [], priorSpentUsd: spentBefore };
  const { findings, hardViolations } = analyzeAction({ actionType: b.actionType, payload: b.payload ?? {}, reasoning: b.reasoning, authorized: b.authorized, authorizationEvidence: b.authorizationEvidence }, policy);
  for (const f of findings) await insert("threats", { ...f, ownerId: agent.ownerId, agentId: b.agentId, actionId: action.id, evidence: f.evidence });
  const critical = findings.some((f) => f.severity === "CRITICAL");

  let serv = null as Awaited<ReturnType<typeof servAssess>> | null;
  let servError: string | null = null;
  try { serv = await servAssess({ actionType: b.actionType, payload: b.payload, reasoning: b.reasoning, policySummary: JSON.stringify(policy) }); }
  catch (e) { servError = e instanceof Error ? e.message.slice(0, 200) : "SERV error"; }
  const servStatus = servError ? "error" : serv?.provider === "serv" ? "ok" : "unavailable";
  // SERV-detected threats become first-class findings (they can block).
  if (serv?.provider === "serv") for (const t of serv.threats) await insert("threats", { threatId: "serv-threat", category: t.category, severity: t.severity.toUpperCase(), description: t.explanation, evidence: ["[evidence withheld]"], mitigation: "Address the SERV-identified threat before resubmission.", hard: t.severity === "critical", ownerId: agent.ownerId, agentId: b.agentId, actionId: action.id });
  const allThreats = await filter("threats", (t) => t.actionId === action.id);
  await insert("assessments", { actionId: action.id, ownerId: agent.ownerId, provider: serv?.provider ?? "unavailable", servStatus, requestId: serv?.requestId ?? null, threatDetected: Boolean(serv?.threatDetected || critical), riskScore: serv?.riskScore ?? (critical ? 95 : findings.length ? 60 : 10), recommendation: serv?.recommendation ?? null, policyViolations: hardViolations, latencyMs: serv?.latencyMs ?? null, rawResponse: servError ? { error: servError } : redact(serv?.raw ?? null) });

  let evaluation: Row | null = null;
  const blocked = critical || hardViolations.length > 0 || allThreats.some((t) => t.severity === "CRITICAL");
  if (blocked) {
    evaluation = await insert("evaluations", { actionId: action.id, ownerId: agent.ownerId, agentId: b.agentId, externalEvalId: null, status: "NOT_SUBMITTED", score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], settledAt: null, note: "Not submitted: deterministic policy already blocks this action; Reppo credits are not spent on hard-blocked actions." });
  } else if (!reppoConfigured()) {
    evaluation = await insert("evaluations", { actionId: action.id, ownerId: agent.ownerId, agentId: b.agentId, externalEvalId: null, status: "NOT_SUBMITTED", score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], settledAt: null, note: "REPPO_API_KEY not configured - no evaluation submitted. This is not an approval." });
  } else {
    try {
      const sub = await reppoSubmit({ actionType: b.actionType, payload: b.payload, reasoning: b.reasoning, context: `AgentShield security evaluation. Agent: ${String(agent.name)}. Action type: ${b.actionType}. Policy: spending limit ${policy.spendingLimitUsd} USD; allowed destinations: ${policy.allowedDestinations.join(", ") || "(any)"}. Synthetic/demo data only - no real credentials or customer data.` });
      evaluation = await insert("evaluations", { actionId: action.id, ownerId: agent.ownerId, agentId: b.agentId, externalEvalId: sub.evalId, status: sub.status, score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], settledAt: null, rawResponse: redact(sub.raw) });
      await audit("evaluation.submitted", { ownerId: agent.ownerId, agentId: b.agentId, actionId: action.id });
    } catch (e) {
      const code = (e as { code?: string }).code;
      const msg = e instanceof Error ? e.message : String(e);
      // 409 = another evaluation pending on the account: QUEUED (retryable),
      // not a permanent failure.
      evaluation = await insert("evaluations", { actionId: action.id, ownerId: agent.ownerId, agentId: b.agentId, externalEvalId: null, status: code === "CONFLICT" ? "QUEUED" : "FAILED", score: null, confidence: null, decision: null, route: null, critiques: [], evidence: [], settledAt: null, note: msg });
    }
  }

  const r = await reevaluate(action.id);
  await audit("decision.made", { ownerId: agent.ownerId, agentId: b.agentId, actionId: action.id });
  if (b.parentActionId) {
    const origEval = (await filter("evaluations", (e) => e.actionId === b.parentActionId)).at(-1);
    if (origEval) await insert("improvements", { agentId: b.agentId, ownerId: agent.ownerId, originalActionId: b.parentActionId, revisedActionId: action.id, originalScore: origEval.score ?? null, revisedScore: evaluation?.score ?? null, improvement: null, note: "Revised score fills in after the revised Reppo evaluation settles." });
  }
  ok(res, {
    action: await find("actions", (a) => a.id === action.id), findings,
    serv: serv ? { provider: serv.provider, recommendation: serv.recommendation, riskScore: serv.riskScore, requestId: serv.requestId } : { provider: "unavailable", error: servError },
    evaluation: evaluation ? { id: evaluation.id, externalEvalId: evaluation.externalEvalId, status: evaluation.status, note: evaluation.note ?? null } : null,
    decision: { outcome: r?.result.outcome, reasons: r?.result.reasons, threshold: r?.result.threshold },
    feedback: r?.result.outcome === "APPROVE" ? ["Action approved. No changes required."] : [...hardViolations, ...findings.map((f) => f.mitigation)],
  }, 201);
}
app.post("/api/v1/actions/analyze", auth, processAction);
app.get("/api/v1/actions", auth, async (req: Authed, res) => ok(res, (await filter("actions", (a) => owns(req, a))).slice().reverse()));
app.get("/api/v1/actions/:id", auth, async (req: Authed, res) => { const a = await find("actions", (x) => x.id === req.params.id); owns(req, a) ? ok(res, a) : fail(res, 404, "Action not found"); });
app.get("/api/v1/actions/:id/trace", auth, async (req: Authed, res) => {
  const a = await find("actions", (x) => x.id === req.params.id); if (!owns(req, a)) return fail(res, 404, "Action not found");
  // Stored payloads are redacted at write time, so traces cannot leak secrets.
  ok(res, { action: a, assessment: await find("assessments", (s) => s.actionId === a!.id) ?? null, threats: await filter("threats", (t) => t.actionId === a!.id), evaluations: await filter("evaluations", (e) => e.actionId === a!.id), decision: await find("decisions", (d) => d.actionId === a!.id) ?? null, feedback: await filter("feedback", (f) => f.actionId === a!.id) });
});

// ---------- Evaluations ----------
app.get("/api/v1/evaluations", auth, async (req: Authed, res) => ok(res, (await filter("evaluations", (e) => owns(req, e))).slice().reverse()));
app.get("/api/v1/evaluations/:id", auth, async (req: Authed, res) => {
  const ev = await find("evaluations", (e) => e.id === req.params.id || e.externalEvalId === req.params.id);
  if (!owns(req, ev)) return fail(res, 404, "Evaluation not found");
  if (ev!.externalEvalId && (ev!.status === "PENDING") && reppoConfigured()) {
    try { return ok(res, await pollAndReevaluate(ev!.id)); }
    catch (e) { return ok(res, { evaluation: ev, pollError: e instanceof Error ? e.message : String(e) }); }
  }
  ok(res, { evaluation: ev, decision: await find("decisions", (d) => d.actionId === ev!.actionId) ?? null });
});
app.post("/api/v1/evaluations/:id/retry", auth, async (req: Authed, res) => {
  const ev = await find("evaluations", (e) => e.id === req.params.id);
  if (!owns(req, ev)) return fail(res, 404, "Evaluation not found");
  if (ev!.externalEvalId) {
    try { return ok(res, await pollAndReevaluate(ev!.id)); } catch (e) { return fail(res, 502, e instanceof Error ? e.message : String(e)); }
  }
  if (ev!.status === "QUEUED") return fail(res, 409, "Still queued: another Reppo evaluation is pending for this account. Retry after it settles.");
  return fail(res, 400, "Evaluation was never submitted (no evalId); submit a new action instead.");
});

// ---------- Decisions / approvals ----------
app.get("/api/v1/decisions", auth, async (req: Authed, res) => {
  const decisions = await filter("decisions", (d) => owns(req, d));
  const approvals = await all("approvals");
  ok(res, decisions.slice().reverse().map((d) => ({ ...d, approval: approvals.find((a) => a.decisionId === d.id) ?? null })));
});
app.post("/api/v1/decisions/:id/approve", auth, requireUser, async (req: Authed, res) => humanDecision(req, res, "APPROVED", "APPROVE"));
app.post("/api/v1/decisions/:id/reject", auth, requireUser, async (req: Authed, res) => humanDecision(req, res, "REJECTED", "BLOCK"));
/** Only a PENDING approval on a REVIEW decision owned by the caller can be
 *  decided, exactly once. No `await` occurs between the status check and the
 *  claim update, so concurrent requests cannot both succeed (single-threaded
 *  store writes). BLOCK/HOLD/other outcomes can never be approved here. */
async function humanDecision(req: Authed, res: Response, status: string, outcome: string) {
  const d = await find("decisions", (x) => x.id === req.params.id);
  if (!owns(req, d)) return fail(res, 404, "Decision not found");
  if (d!.outcome !== "REVIEW") return fail(res, 409, `Only REVIEW decisions can enter human approval (current: ${d!.outcome}). ${d!.outcome === "BLOCK" ? "Blocked actions can never be approved through this endpoint." : ""}`);
  const ap = await find("approvals", (a) => a.decisionId === d!.id);
  if (!ap || ap.status !== "PENDING") return fail(res, 409, "Approval request is not pending (already decided or superseded).");
  // Atomic claim: exactly one concurrent request can transition PENDING.
  if (!(await claimApproval(ap.id, status, (req.actor as { id: string }).id))) return fail(res, 409, "Approval request was already decided concurrently.");
  await update("decisions", d!.id, { outcome, humanRequired: false, reasons: [...(d!.reasons as string[]), `Human ${status.toLowerCase()} by ${(req.actor as { email: string }).email}.`] });
  await update("actions", String(d!.actionId), { status: outcome === "APPROVE" ? "DECIDED" : "BLOCKED" });
  await audit(`decision.human_${status.toLowerCase()}`, { userId: (req.actor as { id: string }).id, ownerId: ownerOf(req), actionId: d!.actionId });
  ok(res, await find("decisions", (x) => x.id === d!.id));
}

// ---------- Policies ----------
app.get("/api/v1/policies", auth, requireUser, async (req: Authed, res) => ok(res, await filter("policies", (p) => p.ownerId === ownerOf(req))));
app.post("/api/v1/policies", auth, requireUser, async (req: Authed, res) => {
  const b = parse(z.object({ name: z.string().min(1), kind: z.string().min(1), config: z.record(z.unknown()).default({}) }), req, res); if (!b) return;
  const p = await insert("policies", { ...b, ownerId: ownerOf(req), enabled: true, version: 1 });
  await insert("policyVersions", { policyId: p.id, version: 1, config: b.config });
  ok(res, p, 201);
});
app.patch("/api/v1/policies/:id", auth, requireUser, async (req: Authed, res) => {
  const p = await find("policies", (x) => x.id === req.params.id && x.ownerId === ownerOf(req)); if (!p) return fail(res, 404, "Policy not found");
  const b = parse(z.object({ name: z.string().optional(), config: z.record(z.unknown()).optional(), enabled: z.boolean().optional() }), req, res); if (!b) return;
  const v = Number(p.version ?? 1) + 1;
  await insert("policyVersions", { policyId: p.id, version: v, config: b.config ?? p.config });
  ok(res, await update("policies", p.id, { ...b, version: v }));
});
app.delete("/api/v1/policies/:id", auth, requireUser, async (req: Authed, res) => {
  const p = await find("policies", (x) => x.id === req.params.id && x.ownerId === ownerOf(req)); if (!p) return fail(res, 404, "Policy not found");
  await remove("policies", p.id); ok(res, { deleted: true });
});

// ---------- Analytics / audit / integrations ----------
app.get("/api/v1/analytics/overview", auth, requireUser, async (req: Authed, res) => {
  const me = ownerOf(req);
  const acts = await filter("actions", (a) => a.ownerId === me), th = await filter("threats", (t) => t.ownerId === me), evs = await filter("evaluations", (e) => e.ownerId === me), decs = await filter("decisions", (d) => d.ownerId === me);
  const settled = evs.filter((e) => typeof e.score === "number");
  ok(res, {
    agents: (await filter("agents", (a) => a.ownerId === me)).length, actionsAnalyzed: acts.length, threatsDetected: th.length,
    actionsBlocked: decs.filter((d) => d.outcome === "BLOCK").length,
    avgReppoScore: settled.length ? Math.round(settled.reduce((s, e) => s + Number(e.score), 0) / settled.length) : null,
    settledEvaluations: settled.length, pendingEvaluations: evs.filter((e) => e.status === "PENDING" || e.status === "QUEUED").length,
    recentActivity: (await filter("audit", (a) => a.ownerId === me)).slice(-10).reverse(),
  });
});
app.get("/api/v1/analytics/threats", auth, requireUser, async (req: Authed, res) => {
  const th = await filter("threats", (t) => t.ownerId === ownerOf(req)); const by: Record<string, number> = {};
  for (const t of th) by[String(t.severity)] = (by[String(t.severity)] ?? 0) + 1;
  ok(res, { total: th.length, bySeverity: by, findings: th.slice().reverse() });
});
app.get("/api/v1/analytics/improvements", auth, requireUser, async (req: Authed, res) => {
  const rows = await Promise.all((await filter("improvements", (m) => m.ownerId === ownerOf(req))).map(async (m) => {
    const rev = (await filter("evaluations", (e) => e.actionId === m.revisedActionId)).at(-1);
    const revisedScore = typeof rev?.score === "number" ? rev.score : m.revisedScore;
    return { ...m, revisedScore, improvement: typeof m.originalScore === "number" && typeof revisedScore === "number" ? revisedScore - m.originalScore : null };
  }));
  const done = rows.filter((r) => typeof r.improvement === "number");
  ok(res, { items: rows.slice().reverse(), revisionSuccessRate: done.length ? Math.round(done.filter((r) => Number(r.improvement) > 0).length / done.length * 100) : null, avgImprovement: done.length ? Math.round(done.reduce((s, r) => s + Number(r.improvement), 0) / done.length) : null });
});
app.get("/api/v1/audit-logs", auth, requireUser, async (req: Authed, res) => ok(res, (await filter("audit", (a) => a.ownerId === ownerOf(req))).slice().reverse()));
app.get("/api/v1/integrations/status", auth, requireUser, async (_req, res) => ok(res, {
  serv: { configured: servConfigured(), baseUrl: config.serv.baseUrl, model: config.serv.model, status: servConfigured() ? "configured_unverified" : "not_configured", note: servConfigured() ? "Key present. Use Test connection to verify against the live API." : "Set SERV_API_KEY (from console.openserv.ai) to enable live SERV Reasoning." },
  reppo: { configured: reppoConfigured(), baseUrl: config.reppo.baseUrl, status: reppoConfigured() ? "configured_unverified" : "not_configured", note: reppoConfigured() ? "Key present. Use Test connection to verify against the live API." : "Set REPPO_API_KEY (from eval.reppo.xyz → API Key) to enable live evaluations." },
}));
app.post("/api/v1/integrations/test", auth, requireUser, async (req, res) => {
  const b = parse(z.object({ provider: z.enum(["serv", "reppo"]) }), req, res); if (!b) return;
  try {
    if (b.provider === "serv") {
      if (!servConfigured()) return ok(res, { provider: "serv", ok: false, status: "not_configured", detail: "SERV_API_KEY missing" });
      const r = await servAssess({ actionType: "healthcheck", payload: { ping: true }, policySummary: "healthcheck only" });
      return ok(res, { provider: "serv", ok: r.provider === "serv", status: r.provider, detail: `model=${config.serv.model} requestId=${r.requestId}` });
    }
    if (!reppoConfigured()) return ok(res, { provider: "reppo", ok: false, status: "not_configured", detail: "REPPO_API_KEY missing" });
    const r = await fetch(`${config.reppo.baseUrl}/agents/eval-requests/pending?page=1&pageSize=1`, { headers: { Authorization: `Bearer ${config.reppo.apiKey}` } });
    return ok(res, { provider: "reppo", ok: r.ok, status: r.ok ? "connected" : `http_${r.status}`, detail: r.ok ? "Authenticated against Reppo Evaluation API." : `Reppo returned HTTP ${r.status} (check key/credits).` });
  } catch (e) { return ok(res, { provider: b.provider, ok: false, status: "error", detail: e instanceof Error ? e.message.slice(0, 200) : String(e) }); }
});

app.get("/health", async (_req, res) => ok(res, { status: "ok", serv: servConfigured() ? "configured" : "not_configured", reppo: reppoConfigured() ? "configured" : "not_configured", database: prismaEnabled() ? "postgresql" : "json-fallback" }));
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => fail(res, 500, "Internal error"));
export { redact };
