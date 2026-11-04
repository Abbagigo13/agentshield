import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// File-backed store used when DATABASE_URL is unset. With DATABASE_URL set,
// deploy Prisma (prisma/schema.prisma) — the REST layer is store-agnostic
// only for this MVP store; swapping in Prisma is the documented next step.
export interface Row { id: string; createdAt: string; [k: string]: unknown }

const file = process.env.AGENTSHIELD_STORE ?? path.join(process.cwd(), ".data", "store.json");
type DB = Record<string, Row[]>;
let db: DB = { users: [], agents: [], agentKeys: [], actions: [], assessments: [], threats: [], policies: [], policyVersions: [], evaluations: [], feedback: [], decisions: [], approvals: [], audit: [], improvements: [], integrations: [] };

function load() {
  try { if (fs.existsSync(file)) db = { ...db, ...JSON.parse(fs.readFileSync(file, "utf8")) }; } catch { /* start empty */ }
}
export function save() {
  try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(db, null, 2)); } catch { /* ephemeral fs */ }
}
load();

export const now = () => new Date().toISOString();
export const uid = () => randomUUID();
export function insert(table: string, row: Omit<Row, "id" | "createdAt"> & Partial<Row>): Row {
  const r: Row = { id: row.id ?? uid(), createdAt: row.createdAt ?? now(), ...row };
  (db[table] ??= []).push(r); save(); return r;
}
export function all(table: string): Row[] { return [...(db[table] ?? [])]; }
export function find(table: string, pred: (r: Row) => boolean): Row | undefined { return (db[table] ?? []).find(pred); }
export function filter(table: string, pred: (r: Row) => boolean): Row[] { return (db[table] ?? []).filter(pred); }
export function update(table: string, id: string, patch: Record<string, unknown>): Row | undefined {
  const r = find(table, (x) => x.id === id); if (!r) return undefined;
  Object.assign(r, patch, { updatedAt: now() }); save(); return r;
}
export function remove(table: string, id: string): boolean {
  const arr = db[table] ?? []; const i = arr.findIndex((x) => x.id === id);
  if (i < 0) return false; arr.splice(i, 1); save(); return true;
}
export function audit(event: string, detail: Record<string, unknown> = {}) {
  insert("audit", { event, detail, ownerId: detail.ownerId ?? detail.userId ?? null, userId: detail.userId ?? null, agentId: detail.agentId ?? null, actionId: detail.actionId ?? null });
}
