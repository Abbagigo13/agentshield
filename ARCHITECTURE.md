# Architecture (V2)
Monorepo: apps/api (Express), apps/web (React), packages/shared (normalized types + status enums), prisma/ (PostgreSQL schema + generated migrations), scripts/ (JSON->PG migration).
## Flow
Agent (agent API key) or owner (JWT) -> POST /actions/analyze -> Zod + idempotency -> tenant/agent checks -> deterministic engine (recursive financial scan, exact destinations, cumulative limits, deny-by-default permissions) -> SERV adapter (schema-validated JSON) -> Reppo adapter (redacted trace; 409 -> QUEUED not FAILED) -> decide() -> approval queue (REVIEW only) -> audit. On Reppo settlement (GET poll or 60s background worker in index.ts): validation -> normalization -> reevaluate() re-runs decide() -> decision/action/approval updates -> feedback + audit (evaluation.settled, decision.reevaluated).
## Authority rule
Deterministic policy > AI. See SECURITY.md for the full approval invariant list. decide() is pure and deterministic; freshness uses settledAt vs REPPO_MAX_EVAL_AGE_MS (default 24h).
## Persistence
Prisma/PostgreSQL is the production target (repositories in apps/api/src/repositories.ts, tenant-scoped, atomic approval claim via updateMany-on-PENDING, idempotent upsert). The JSON file store remains the no-database fallback with identical API contracts; it is NOT removed until a deployment has migrated (scripts/migrate-json-to-postgres.mjs).
