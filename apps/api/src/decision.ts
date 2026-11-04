import { DEFAULT_SCORE_THRESHOLD, REPPO_STATUSES, type DecisionResult, type ReppoEvaluation, type ReppoStatus, type SecurityAssessment, type ServStatus } from "@agentshield/shared";

export interface DecideInput {
  hardViolations: string[];
  criticalThreat: boolean;
  serv?: SecurityAssessment | null;
  servStatus: ServStatus;
  reppo?: ReppoEvaluation | null;
  reppoStatus: string;
  threshold?: number;
  maxEvalAgeMs?: number;
  nowMs?: number;
}

/** Deterministic, fail-closed decision engine.
 *  Invariants: hard policy > AI; only a validated SETTLED Reppo verdict with
 *  decision=accept, route=auto-ship, confidence high|medium, a fresh settledAt,
 *  score >= threshold, working SERV, and no SERV/Reppo disagreement can APPROVE.
 *  Every unknown state resolves to REVIEW/BLOCK/HOLD — never APPROVE. */
export function decide(input: DecideInput): DecisionResult {
  const threshold = input.threshold ?? DEFAULT_SCORE_THRESHOLD;
  const reasons: string[] = [];
  const done = (outcome: DecisionResult["outcome"]): DecisionResult => ({ outcome, reasons, threshold });

  if (input.criticalThreat) { reasons.push("Critical threat detected by the deterministic security engine."); return done("BLOCK"); }
  if (input.hardViolations.length > 0) { reasons.push(`Hard policy violation: ${input.hardViolations[0]}`); return done("BLOCK"); }

  // SERV is a required signal: its threats and failures are never ignored.
  const serv = input.serv;
  if (serv?.threatDetected && serv.threats.some((t) => t.severity === "critical")) { reasons.push("SERV Reasoning reported a critical threat."); return done("BLOCK"); }
  if (serv?.recommendation === "block") { reasons.push("SERV Reasoning recommended block."); return done("BLOCK"); }
  if (serv?.threatDetected && serv.recommendation === "approve") { reasons.push("SERV detected threats but recommended approve; treating as disagreement."); return done("REVIEW"); }

  if (!(REPPO_STATUSES as readonly string[]).includes(input.reppoStatus)) {
    reasons.push(`Unknown evaluation status "${input.reppoStatus}"; failing closed to review.`);
    return done("REVIEW");
  }
  const status = input.reppoStatus as ReppoStatus;
  if (status === "PENDING" || status === "QUEUED") { reasons.push(`Reppo evaluation is ${status.toLowerCase()}; action is held (never auto-approved).`); return done("HOLD"); }
  if (status !== "SETTLED") { reasons.push(`No settled Reppo evaluation (${status}); a missing evaluation is never approval.`); return done("REVIEW"); }

  const r = input.reppo;
  if (!r || r.status !== "SETTLED") { reasons.push("Settled status claimed without a validated settled evaluation."); return done("REVIEW"); }
  if (input.servStatus !== "ok") { reasons.push(`SERV Reasoning ${input.servStatus}; its failure is never silently ignored.`); return done("REVIEW"); }

  // Freshness: a stale verdict cannot approve current behaviour.
  const maxAge = input.maxEvalAgeMs ?? 24 * 3600 * 1000;
  const settledMs = r.settledAt ? Date.parse(r.settledAt) : NaN;
  if (!Number.isFinite(settledMs)) { reasons.push("Settled evaluation has no settledAt timestamp; cannot verify freshness."); return done("REVIEW"); }
  if ((input.nowMs ?? Date.now()) - settledMs > maxAge) { reasons.push("Reppo evaluation is stale (settled too long ago)."); return done("REVIEW"); }
  if (settledMs - (input.nowMs ?? Date.now()) > 5 * 60 * 1000) { reasons.push("Evaluation settledAt is in the future; untrusted timestamp."); return done("REVIEW"); }

  if (r.decision === "reject" || r.route === "block") { reasons.push("Reppo verdict: reject / route block."); return done("BLOCK"); }
  if (r.decision === "revise") { reasons.push("Reppo verdict: revise."); return done("REVISE"); }
  if (r.route === "review") { reasons.push("Reppo route is review (includes held/manipulation-suspect accepts)."); return done("REVIEW"); }
  if (r.route !== "auto-ship") { reasons.push(`Unknown Reppo route "${r.route}"; failing closed to review.`); return done("REVIEW"); }
  if (r.decision !== "accept") { reasons.push(`Unknown Reppo decision "${r.decision}"; failing closed to review.`); return done("REVIEW"); }
  if (r.confidence !== "high" && r.confidence !== "medium") { reasons.push(`Reppo confidence "${r.confidence}" is not sufficient for approval.`); return done("REVIEW"); }
  if (serv && serv.recommendation !== "approve") { reasons.push(`SERV (${serv.recommendation}) and Reppo (accept) disagree.`); return done("REVIEW"); }
  if (typeof r.score !== "number" || !Number.isFinite(r.score)) { reasons.push("Settled evaluation has no numeric score."); return done("REVIEW"); }
  if (r.score < threshold) { reasons.push(`Reppo score ${r.score} is below threshold ${threshold}.`); return done("REVISE"); }
  reasons.push(`Reppo accept, route auto-ship, score ${r.score} ≥ ${threshold}, SERV in agreement, no policy violations.`);
  return done("APPROVE");
}
