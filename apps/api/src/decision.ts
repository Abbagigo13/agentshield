import { DEFAULT_SCORE_THRESHOLD, type DecisionResult, type ReppoEvaluation, type SecurityAssessment } from "@agentshield/shared";

/** Deterministic decision engine (spec §9). Policy always wins over AI:
 *  a positive evaluation never overrides a critical/hard violation. */
export function decide(input: {
  hardViolations: string[];
  criticalThreat: boolean;
  serv?: SecurityAssessment | null;
  reppo?: ReppoEvaluation | null;
  reppoStatus: string; // NOT_SUBMITTED | PENDING | SETTLED | FAILED | UNAVAILABLE
  threshold?: number;
}): DecisionResult {
  const threshold = input.threshold ?? DEFAULT_SCORE_THRESHOLD;
  const reasons: string[] = [];
  const done = (outcome: DecisionResult["outcome"]): DecisionResult => ({ outcome, reasons, threshold });

  if (input.criticalThreat) { reasons.push("Critical threat detected by the deterministic security engine."); return done("BLOCK"); }
  if (input.hardViolations.length > 0) { reasons.push(`Hard policy violation: ${input.hardViolations[0]}`); return done("BLOCK"); }
  if (input.serv?.recommendation === "block") { reasons.push("SERV Reasoning recommended block."); return done("BLOCK"); }

  if (input.reppoStatus === "PENDING") { reasons.push("Reppo evaluation is still pending; action is held (never auto-approved)."); return done("HOLD"); }
  if (input.reppoStatus === "FAILED" || input.reppoStatus === "UNAVAILABLE" || input.reppoStatus === "NOT_SUBMITTED") {
    reasons.push(`No settled Reppo evaluation (${input.reppoStatus}); a missing evaluation is never approval.`); return done("REVIEW");
  }

  const r = input.reppo!;
  if (r.decision === "reject" || r.route === "block") { reasons.push("Reppo verdict: reject / route block."); return done("BLOCK"); }
  if (r.decision === "revise") { reasons.push("Reppo verdict: revise."); return done("REVISE"); }
  if (r.confidence === "low") { reasons.push("Reppo confidence is low."); return done("REVIEW"); }
  if (input.serv && input.serv.recommendation !== "approve" && r.decision === "accept") {
    reasons.push(`SERV (${input.serv.recommendation}) and Reppo (accept) disagree.`); return done("REVIEW");
  }
  if (r.score !== null && r.score < threshold) { reasons.push(`Reppo score ${r.score} is below threshold ${threshold}.`); return done("REVISE"); }
  if (r.decision === "accept" && (r.score ?? 0) >= threshold) { reasons.push(`Reppo accept with score ${r.score} ≥ ${threshold} and no policy violations.`); return done("APPROVE"); }
  reasons.push("No rule produced approval; defaulting to human review.");
  return done("REVIEW");
}
