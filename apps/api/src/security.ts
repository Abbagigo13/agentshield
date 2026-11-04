import type { Severity } from "@agentshield/shared";

export interface Finding {
  threatId: string; category: string; severity: Severity;
  description: string; evidence: string[]; mitigation: string;
}

const INJECTION = [/ignore (all )?(previous|prior|above) instructions/i, /disregard (the )?system/i, /you are now/i, /reveal (the )?(system prompt|instructions)/i, /override.*polic/i, /jailbreak/i, /developer mode/i];
const SECRET = [/(api[_-]?key|password|secret|private[_-]?key|seed phrase|access[_-]?token)\s*[:=]/i, /sk-[A-Za-z0-9]{16,}/, /AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];

export interface PolicyContext {
  spendingLimitUsd: number;
  allowedDestinations: string[];
  permissions: string[];
  requireApprovalAboveUsd?: number;
}

/** Deterministic heuristic engine (spec §6). Heuristics are not perfect —
 *  see SECURITY.md for stated limits. Hard findings here can BLOCK. */
export function analyzeAction(input: {
  actionType: string; payload: Record<string, unknown>; reasoning?: string;
  authorized?: boolean; authorizationEvidence?: string;
}, policy: PolicyContext): { findings: Finding[]; hardViolations: string[] } {
  const findings: Finding[] = [];
  const hard: string[] = [];
  const text = `${input.actionType} ${JSON.stringify(input.payload)} ${input.reasoning ?? ""}`;
  const push = (f: Finding, isHard = false) => { findings.push(f); if (isHard) hard.push(f.description); };

  for (const re of INJECTION) {
    const m = text.match(re);
    if (m) push({ threatId: "prompt-injection", category: "Prompt injection", severity: "CRITICAL", description: "Possible prompt injection: instruction-override pattern detected in action content.", evidence: [m[0]], mitigation: "Reject embedded instructions from untrusted content; re-run with sanitized input." }, true);
  }
  for (const re of SECRET) {
    const m = text.match(re);
    if (m) push({ threatId: "credential-disclosure", category: "Data leakage", severity: "CRITICAL", description: "Action appears to contain or request credential material.", evidence: ["[redacted pattern match]"], mitigation: "Strip secrets, rotate any exposed credential, and block exfiltration." }, true);
  }

  const amount = num(input.payload.amountUsd ?? input.payload.amount);
  const dest = str(input.payload.destination ?? input.payload.to ?? input.payload.recipient);
  if (amount !== null && amount > policy.spendingLimitUsd) {
    push({ threatId: "spending-limit", category: "Financial policy violation", severity: "HIGH", description: `Amount ${amount} exceeds configured spending limit ${policy.spendingLimitUsd}.`, evidence: [`amount=${amount}`, `limit=${policy.spendingLimitUsd}`], mitigation: "Reduce amount to within limit or obtain human approval." }, true);
  }
  if (dest && policy.allowedDestinations.length > 0 && !policy.allowedDestinations.some((d) => dest.toLowerCase().includes(d.toLowerCase()))) {
    push({ threatId: "unauthorized-destination", category: "Financial policy violation", severity: "HIGH", description: `Destination "${dest}" is not in the allowed destinations list.`, evidence: [dest], mitigation: "Use an allow-listed destination or request a policy change." }, true);
  }
  if (policy.permissions.length > 0 && !policy.permissions.includes(input.actionType)) {
    push({ threatId: "unauthorized-action", category: "Unauthorized action", severity: "HIGH", description: `Action type "${input.actionType}" is outside the agent's configured permissions.`, evidence: [input.actionType], mitigation: "Grant the permission explicitly or choose a permitted action type." }, true);
  }
  if (input.authorized === false || (requiresAuth(input) && !input.authorizationEvidence)) {
    push({ threatId: "missing-authorization", category: "Unauthorized action", severity: amount !== null && amount > 0 ? "HIGH" : "MEDIUM", description: "No verified authorization evidence supplied for this action.", evidence: ["authorizationEvidence missing"], mitigation: "Attach verifiable authorization evidence before execution." }, input.authorized === false);
  }
  if (/transfer|payment|send|withdraw/i.test(input.actionType) && amount !== null && amount >= policy.spendingLimitUsd * 0.9 && amount <= policy.spendingLimitUsd) {
    findings.push({ threatId: "near-limit-transfer", category: "Suspicious behavior", severity: "MEDIUM", description: "Transfer amount is close to the spending limit (possible limit probing).", evidence: [`amount=${amount}`], mitigation: "Review pattern of near-limit transfers." });
  }
  return { findings, hardViolations: hard };
}

function requiresAuth(i: { actionType: string; payload: Record<string, unknown> }) {
  return /transfer|payment|send|withdraw|delete|export/i.test(i.actionType) || num(i.payload.amountUsd ?? i.payload.amount) !== null;
}
export function num(v: unknown): number | null { const n = typeof v === "string" ? Number(v) : typeof v === "number" ? v : NaN; return Number.isFinite(n) ? n : null; }
export function str(v: unknown): string { return typeof v === "string" ? v : ""; }

/** Redaction layer (spec §8 privacy rule). Fail-closed: unknown secret-like
 *  fields are dropped, never passed through. */
const SECRET_KEY = /(api[_-]?key|password|passwd|secret|token|private[_-]?key|seed|credential|authorization)/i;
export function redact(value: unknown, key = ""): unknown {
  if (SECRET_KEY.test(key)) return "[REDACTED]";
  if (typeof value === "string") {
    return value
      .replace(/sk-[A-Za-z0-9_-]{8,}/g, "[REDACTED]")
      .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, "Bearer [REDACTED]")
      .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED-EMAIL]")
      .replace(/\b\d{12,19}\b/g, "[REDACTED-NUMBER]");
  }
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = redact(v, k);
    return out;
  }
  return value;
}
export function sanitizeForReppo(payload: unknown): string {
  const s = JSON.stringify(redact(payload), null, 2);
  return s.slice(0, 48000);
}
