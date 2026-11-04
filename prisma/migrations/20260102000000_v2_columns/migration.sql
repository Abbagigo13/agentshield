-- V2 denormalized tenant/lifecycle columns (hand-written; verified with
-- `prisma migrate deploy` against the staging database).
ALTER TABLE "AgentApiKey" ADD COLUMN "expiresAt" TIMESTAMP(3);
ALTER TABLE "AgentAction" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "SecurityAssessment" ADD COLUMN "servStatus" TEXT;
ALTER TABLE "SecurityAssessment" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "ThreatFinding" ADD COLUMN "actionId" TEXT;
ALTER TABLE "ThreatFinding" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "ThreatFinding" ADD COLUMN "hard" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "ThreatFinding" ALTER COLUMN "assessmentId" DROP NOT NULL;
ALTER TABLE "Evaluation" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "Evaluation" ADD COLUMN "agentId" TEXT;
ALTER TABLE "Evaluation" ADD COLUMN "settledAt" TIMESTAMP(3);
ALTER TABLE "Evaluation" ADD COLUMN "note" TEXT;
ALTER TABLE "Decision" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "ApprovalRequest" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "EvaluationFeedback" ADD COLUMN "actionId" TEXT;
ALTER TABLE "EvaluationFeedback" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "AuditLog" ADD COLUMN "ownerId" TEXT;
ALTER TABLE "ImprovementMetric" ADD COLUMN "ownerId" TEXT;
CREATE INDEX "ThreatFinding_actionId_idx" ON "ThreatFinding"("actionId");
CREATE INDEX "AgentAction_ownerId_idx" ON "AgentAction"("ownerId");
CREATE INDEX "Evaluation_ownerId_idx" ON "Evaluation"("ownerId");
CREATE INDEX "Decision_ownerId_idx" ON "Decision"("ownerId");
