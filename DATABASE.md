# Database
Prisma + PostgreSQL (`prisma/schema.prisma`): User, Agent, AgentApiKey (SHA-256 hash only), AgentAction, SecurityAssessment, ThreatFinding, PolicyRule, PolicyVersion, Evaluation (raw response preserved), EvaluationFeedback, Decision, ApprovalRequest, AuditLog, ImprovementMetric, IntegrationConfiguration. UUID keys, FKs, unique constraints (idempotencyKey, externalEvalId), indexes on owner/time/status.
Apply: `npx prisma migrate deploy` with DATABASE_URL set. Without DATABASE_URL the API uses `.data/store.json` (gitignored) so the MVP runs anywhere; data shape mirrors the Prisma models.
Retention: keep audit/evaluation records for the life of the deployment; delete agent keys on revocation (revokedAt), never store plaintext secrets.
