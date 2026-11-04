import { prisma, prismaEnabled } from "./repositories.js";
import * as json from "./store.js";

/** Async data layer. When DATABASE_URL is set, rows live in PostgreSQL via
 *  Prisma; otherwise the JSON file store is used (temporary fallback, kept
 *  until PostgreSQL verification succeeds in the target environment).
 *  Row shape is identical either way (dates as ISO strings). Filtering is
 *  applied in-process over the delegate result so semantics never diverge
 *  between backends; tenant scoping is enforced by callers' predicates. */
export type Row = json.Row;
export { prismaEnabled };

const DELEGATE: Record<string, string> = {
  users: "user", agents: "agent", agentKeys: "agentApiKey", actions: "agentAction",
  assessments: "securityAssessment", threats: "threatFinding", policies: "policyRule",
  policyVersions: "policyVersion", evaluations: "evaluation", feedback: "evaluationFeedback",
  decisions: "decision", approvals: "approvalRequest", audit: "auditLog",
  improvements: "improvementMetric", integrations: "integrationConfiguration",
};
const FIELDS: Record<string, string[]> = {
  users: ["id", "email", "passwordHash", "name", "role", "createdAt", "updatedAt"],
  agents: ["id", "ownerId", "name", "description", "status", "permissions", "spendingLimitUsd", "allowedDestinations", "createdAt", "updatedAt"],
  agentKeys: ["id", "agentId", "keyPrefix", "keyHash", "lastUsedAt", "revokedAt", "expiresAt", "createdAt"],
  actions: ["id", "ownerId", "agentId", "externalId", "actionType", "payload", "reasoning", "status", "parentActionId", "idempotencyKey", "createdAt", "updatedAt"],
  assessments: ["id", "actionId", "provider", "servStatus", "ownerId", "requestId", "threatDetected", "riskScore", "recommendation", "policyViolations", "rawResponse", "latencyMs", "createdAt"],
  threats: ["id", "actionId", "ownerId", "hard", "assessmentId", "agentId", "threatId", "category", "severity", "description", "evidence", "mitigation", "createdAt"],
  policies: ["id", "ownerId", "name", "kind", "config", "enabled", "version", "createdAt", "updatedAt"],
  policyVersions: ["id", "policyId", "version", "config", "createdAt"],
  evaluations: ["id", "actionId", "ownerId", "agentId", "provider", "externalEvalId", "status", "score", "confidence", "decision", "route", "critiques", "evidence", "rawResponse", "sanitizedPayload", "settledAt", "note", "createdAt", "updatedAt"],
  feedback: ["id", "evaluationId", "actionId", "ownerId", "message", "critiques", "createdAt"],
  decisions: ["id", "ownerId", "actionId", "outcome", "reasons", "threshold", "humanRequired", "createdAt"],
  approvals: ["id", "ownerId", "decisionId", "status", "decidedBy", "note", "decidedAt", "createdAt"],
  audit: ["id", "ownerId", "userId", "agentId", "actionId", "event", "detail", "createdAt"],
  improvements: ["id", "ownerId", "agentId", "originalActionId", "revisedActionId", "originalScore", "revisedScore", "improvement", "createdAt"],
  integrations: ["id", "provider", "status", "lastCheckedAt", "detail", "updatedAt"],
};
const DATES = new Set(["createdAt", "updatedAt", "lastUsedAt", "revokedAt", "expiresAt", "settledAt", "decidedAt", "lastCheckedAt"]);

function toDb(table: string, row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of FIELDS[table] ?? []) {
    if (row[f] === undefined) continue;
    out[f] = DATES.has(f) && typeof row[f] === "string" ? new Date(row[f] as string) : row[f];
  }
  if (table === "threats" && !out.assessmentId) delete out.assessmentId;
  return out;
}
function fromDb(row: Record<string, unknown>): Row {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) out[k] = v instanceof Date ? v.toISOString() : v;
  return out as Row;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const delegate = (table: string): any => (prisma() as any)[DELEGATE[table]];

export async function insert(table: string, row: Omit<Row, "id" | "createdAt"> & Partial<Row>): Promise<Row> {
  if (!prismaEnabled()) return json.insert(table, row);
  const full: Row = { id: (row.id as string) ?? json.uid(), createdAt: (row.createdAt as string) ?? json.now(), ...row };
  const created = await delegate(table).create({ data: toDb(table, full) });
  return fromDb(created);
}
export async function all(table: string): Promise<Row[]> {
  if (!prismaEnabled()) return json.all(table);
  return (await delegate(table).findMany({ orderBy: { createdAt: "asc" } })).map(fromDb);
}
export async function find(table: string, pred: (r: Row) => boolean): Promise<Row | undefined> { return (await all(table)).find(pred); }
export async function filter(table: string, pred: (r: Row) => boolean): Promise<Row[]> { return (await all(table)).filter(pred); }
export async function update(table: string, id: string, patch: Record<string, unknown>): Promise<Row | undefined> {
  if (!prismaEnabled()) return json.update(table, id, patch);
  try { return fromDb(await delegate(table).update({ where: { id }, data: toDb(table, patch) })); } catch { return undefined; }
}
export async function remove(table: string, id: string): Promise<boolean> {
  if (!prismaEnabled()) return json.remove(table, id);
  try { await delegate(table).delete({ where: { id } }); return true; } catch { return false; }
}
export async function audit(event: string, detail: Record<string, unknown> = {}): Promise<void> {
  if (!prismaEnabled()) { json.audit(event, detail); return; }
  await insert("audit", { event, detail: detail as object, ownerId: detail.ownerId ?? detail.userId ?? null, userId: detail.userId ?? null, agentId: detail.agentId ?? null, actionId: detail.actionId ?? null });
}
/** Atomic approval claim: exactly one concurrent caller wins.
 *  PostgreSQL: single UPDATE ... WHERE status='PENDING'. JSON: the
 *  check-and-set runs synchronously inside this call, so it cannot interleave. */
export async function claimApproval(approvalId: string, status: string, decidedBy: string): Promise<boolean> {
  if (!prismaEnabled()) {
    const ap = json.find("approvals", (a) => a.id === approvalId);
    if (!ap || ap.status !== "PENDING") return false;
    json.update("approvals", approvalId, { status, decidedBy, decidedAt: json.now() });
    return true;
  }
  const r = await prisma().approvalRequest.updateMany({ where: { id: approvalId, status: "PENDING" }, data: { status, decidedBy, decidedAt: new Date() } });
  return r.count === 1;
}
