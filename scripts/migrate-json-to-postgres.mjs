// One-way migration: JSON fallback store -> PostgreSQL via Prisma.
// Usage: DATABASE_URL=postgresql://... node scripts/migrate-json-to-postgres.mjs [.data/store.json]
// Safety: refuses without DATABASE_URL; every insert uses skipDuplicates, so a
// failed run can simply be re-run (recovery = fix the cause, run again).
// FK order: users -> agents -> keys/actions -> assessments -> threats ->
// policies -> versions -> evaluations -> feedback -> decisions -> approvals
// -> audit -> improvements. Agent keys migrate as hashes only (raw keys are
// unrecoverable by design - issue fresh keys after cutover if needed).
// The JSON file is never modified or deleted by this script.
import fs from "node:fs";
import { PrismaClient } from "@prisma/client";

if (!process.env.DATABASE_URL) { console.error("DATABASE_URL is required"); process.exit(1); }
const file = process.argv[2] ?? ".data/store.json";
const db = JSON.parse(fs.readFileSync(file, "utf8"));
const prisma = new PrismaClient();

const FIELDS = {
  users: ["id", "email", "passwordHash", "name", "role", "createdAt"],
  agents: ["id", "ownerId", "name", "description", "status", "permissions", "spendingLimitUsd", "allowedDestinations", "createdAt"],
  agentKeys: ["id", "agentId", "keyPrefix", "keyHash", "lastUsedAt", "revokedAt", "expiresAt", "createdAt"],
  actions: ["id", "ownerId", "agentId", "externalId", "actionType", "payload", "reasoning", "status", "parentActionId", "idempotencyKey", "createdAt"],
  assessments: ["id", "actionId", "provider", "servStatus", "ownerId", "requestId", "threatDetected", "riskScore", "recommendation", "policyViolations", "rawResponse", "latencyMs", "createdAt"],
  threats: ["id", "actionId", "ownerId", "hard", "agentId", "threatId", "category", "severity", "description", "evidence", "mitigation", "createdAt"],
  policies: ["id", "ownerId", "name", "kind", "config", "enabled", "version", "createdAt"],
  policyVersions: ["id", "policyId", "version", "config", "createdAt"],
  evaluations: ["id", "actionId", "ownerId", "agentId", "provider", "externalEvalId", "status", "score", "confidence", "decision", "route", "critiques", "evidence", "rawResponse", "sanitizedPayload", "settledAt", "note", "createdAt"],
  feedback: ["id", "evaluationId", "actionId", "ownerId", "message", "critiques", "createdAt"],
  decisions: ["id", "ownerId", "actionId", "outcome", "reasons", "threshold", "humanRequired", "createdAt"],
  approvals: ["id", "ownerId", "decisionId", "status", "decidedBy", "note", "decidedAt", "createdAt"],
  audit: ["id", "ownerId", "userId", "agentId", "actionId", "event", "detail", "createdAt"],
  improvements: ["id", "ownerId", "agentId", "originalActionId", "revisedActionId", "originalScore", "revisedScore", "improvement", "createdAt"],
};
const DATES = new Set(["createdAt", "lastUsedAt", "revokedAt", "expiresAt", "settledAt", "decidedAt"]);
const MODEL = { users: "user", agents: "agent", agentKeys: "agentApiKey", actions: "agentAction", assessments: "securityAssessment", threats: "threatFinding", policies: "policyRule", policyVersions: "policyVersion", evaluations: "evaluation", feedback: "evaluationFeedback", decisions: "decision", approvals: "approvalRequest", audit: "auditLog", improvements: "improvementMetric" };
const ORDER = ["users", "agents", "agentKeys", "actions", "assessments", "threats", "policies", "policyVersions", "evaluations", "feedback", "decisions", "approvals", "audit", "improvements"];

function mapRow(table, row) {
  const out = {};
  for (const f of FIELDS[table]) {
    if (row[f] === undefined) continue;
    out[f] = DATES.has(f) && row[f] ? new Date(row[f]) : row[f];
  }
  return out;
}

// Referential guard: rows whose required parent is absent from the source
// (orphans) are skipped and reported, never silently inserted or fatal.
const FK = { agents: ["ownerId", "users"], agentKeys: ["agentId", "agents"], actions: ["agentId", "agents"], assessments: ["actionId", "actions"], evaluations: ["actionId", "actions"], feedback: ["evaluationId", "evaluations"], decisions: ["actionId", "actions"], approvals: ["decisionId", "decisions"], policyVersions: ["policyId", "policies"] };
const included = {};
try {
  for (const table of ORDER) {
    let rows = db[table] ?? [];
    if (FK[table]) {
      const [field, parent] = FK[table];
      const parentIds = included[parent] ?? new Set();
      const before = rows.length;
      rows = rows.filter((r) => parentIds.has(r[field]));
      if (rows.length < before) console.log(`${table}: skipped ${before - rows.length} orphan row(s) (missing ${parent})`);
    }
    included[table] = new Set(rows.map((r) => r.id));
    if (!rows.length) { console.log(`${table}: 0`); continue; }
    const res = await prisma[MODEL[table]].createMany({ data: rows.map((r) => mapRow(table, r)), skipDuplicates: true });
    const total = await prisma[MODEL[table]].count();
    console.log(`${table}: migrated ${res.count}/${rows.length} new (table total ${total})`);
  }
  console.log("MIGRATION_OK - verify counts above, then run the API against PostgreSQL in staging before retiring the JSON store.");
} catch (e) {
  console.error("MIGRATION_FAILED:", e.message);
  console.error("Recovery: fix the cause and re-run - completed tables keep their rows, duplicates are skipped.");
  process.exitCode = 1;
} finally { await prisma.$disconnect(); }
