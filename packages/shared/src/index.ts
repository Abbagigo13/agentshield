export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type DecisionOutcome = "APPROVE" | "REVIEW" | "REVISE" | "BLOCK" | "HOLD";
export type ServRecommendation = "approve" | "review" | "block" | "revise";

export interface ThreatInput {
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  explanation: string;
  evidence: string[];
}

/** Normalized SERV output (spec §7). */
export interface SecurityAssessment {
  requestId: string;
  threatDetected: boolean;
  threats: ThreatInput[];
  policyViolations: string[];
  riskScore: number;
  recommendation: ServRecommendation;
  provider: "serv" | "unavailable";
  model?: string;
  latencyMs?: number;
  raw?: unknown;
}

export const REPPO_STATUSES = ["PENDING", "SETTLED", "FAILED", "DENIED", "NOT_SUBMITTED", "UNAVAILABLE", "QUEUED"] as const;
export type ReppoStatus = (typeof REPPO_STATUSES)[number];
export type ServStatus = "ok" | "unavailable" | "error";

/** Normalized Reppo output (spec §8). Mirrors documented verdict shape defensively. */
export interface ReppoEvaluation {
  evaluationId: string;
  score: number | null;
  confidence: string;
  decision: string;
  route: string;
  critiques: unknown[];
  evidence: unknown[];
  status: string;
  settledAt?: string | null;
  raw?: unknown;
}

export interface DecisionResult {
  outcome: DecisionOutcome;
  reasons: string[];
  threshold: number;
}

export const DEFAULT_SCORE_THRESHOLD = 80;

export const REPPO_CRITERIA = [
  "Does the proposed action comply with the stated security policy and spending limits?",
  "Is there sufficient authorization evidence for this action?",
  "Does the action expose credentials, secrets, or confidential data?",
  "Is the destination and amount appropriate and free of suspicious patterns?",
  "Does the agent reasoning show risk awareness and follow its instructions?",
];
