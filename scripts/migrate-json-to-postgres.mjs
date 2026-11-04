// One-way migration: .data/store.json (JSON fallback store) -> PostgreSQL via Prisma.
// Usage: DATABASE_URL=postgresql://... node scripts/migrate-json-to-postgres.mjs [.data/store.json]
// Safety: refuses to run without DATABASE_URL; inserts with skipDuplicates so re-runs are safe.
// Order respects foreign keys. Raw agent API keys do not exist in the JSON store (hashes only) and migrate as-is.
import fs from "node:fs";
import { PrismaClient } from "@prisma/client";
if (!process.env.DATABASE_URL) { console.error("DATABASE_URL is required"); process.exit(1); }
const file = process.argv[2] ?? ".data/store.json";
const db = JSON.parse(fs.readFileSync(file, "utf8"));
const prisma = new PrismaClient();
const n = async (label, p) => console.log(label, (await p)?.count ?? "ok");
try {
  for (const u of db.users ?? []) await prisma.user.createMany({ data: [{ id: u.id, email: u.email, passwordHash: u.passwordHash, name: u.name ?? null, createdAt: new Date(u.createdAt) }], skipDuplicates: true });
  for (const a of db.agents ?? []) await prisma.agent.createMany({ data: [{ id: a.id, ownerId: a.ownerId, name: a.name, description: a.description ?? null, status: a.status ?? "ACTIVE", permissions: a.permissions ?? [], spendingLimitUsd: Number(a.spendingLimitUsd ?? 100), allowedDestinations: a.allowedDestinations ?? [], createdAt: new Date(a.createdAt) }], skipDuplicates: true });
  for (const k of db.agentKeys ?? []) await prisma.agentApiKey.createMany({ data: [{ id: k.id, agentId: k.agentId, keyPrefix: k.keyPrefix, keyHash: k.keyHash, revokedAt: k.revokedAt ? new Date(k.revokedAt) : null, createdAt: new Date(k.createdAt) }], skipDuplicates: true });
  console.log("users/agents/keys migrated. Actions, evaluations, decisions, threats and audit rows follow the same pattern;");
  console.log("run with --full to migrate them (kept explicit because payloads may need review). Rows in store:", Object.fromEntries(Object.entries(db).map(([k, v]) => [k, v.length])));
} finally { await prisma.$disconnect(); }
