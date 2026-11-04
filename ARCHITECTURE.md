# Architecture
Monorepo: `apps/api` (Express), `apps/web` (React), `packages/shared` (normalized SecurityAssessment / ReppoEvaluation / decision types), `prisma/schema.prisma` (PostgreSQL).
## Flow
Agent → POST /api/v1/actions/analyze → Zod validation + idempotency → deterministic security engine (`security.ts`: injection, leakage, spending, destination, permission, authorization) → SERV adapter (`providers.ts`, POST inference-api.openserv.ai/v1/chat/completions, json_schema response_format; system prompt required) → Reppo adapter (POST eval.reppo.xyz/api/v1/agents/eval-requests/submit type=trace after redaction; GET poll by evalId) → decision engine (`decision.ts`) → approvals/audit.
## Authority rule
Deterministic policy > AI. Critical/hard findings BLOCK regardless of SERV/Reppo. PENDING → HOLD. FAILED/UNAVAILABLE/missing → REVIEW. SERV↔Reppo disagreement or low confidence → REVIEW. APPROVE needs Reppo accept, score ≥ threshold (default 80, env SCORE_THRESHOLD), and no violations.
## Trade-offs
Hard-blocked actions are not sent to Reppo (saves credits; recorded as NOT_SUBMITTED with the reason). Reppo allows one PENDING evaluation per account — a 409 is surfaced, not hidden. Local demo uses a file store when DATABASE_URL is unset; Prisma/PostgreSQL is the production path.
