import type { Severity } from "@agentshield/shared";

export interface Finding {
  threatId: string; category: string; severity: Severity;
  description: string; evidence: string[]; mitigation: string; hard?: boolean;
}

const INJECTION = [/ignore (all )?(previous|prior|above) instructions/i, /disregard (the )?system/i, /you are now/i, /reveal (the )?(system prompt|instructions)/i, /override.*polic/i, /jailbreak/i, /developer mode/i];
const SECRET = [/(api[_-]?key|password|secret|private[_-]?key|seed phrase|access[_-]?token)\s*[:=]/i, /sk-[A-Za-z0-9]{16,}/, /AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];

export interface PolicyContext {
  spendingLimitUsd: number;
  allowedDestinations: string[];
  permissions: string[];
  /** Sum of amounts already spent by this agent (for cumulative limits). */
  priorSpentUsd?: number;
}

/** Authorization evidence must be a structured signed-approval reference:
 *  `sig:<at least 24 url-safe chars>`. Arbitrary strings are rejected.
 *  This verifies format/provenance shape only - cryptographic verification
 *  against an issuer key is future work and is not claimed here. */
export function validAuthorizationEvidence(v?: string): boolean {
  return typeof v === "string" && /^sig:[A-Za-z0-9_-]{24,}$/.test(v);
}

const AMOUNT_KEY = /^(amount|amountusd|value|total|price|cost|sum)$/i;
const DEST_KEY = /^(destination|to|recipient|payee|address|account|wallet)$/i;

/** Recursively collect amounts/destinations from nested payloads. */
export function deepFinancials(value: unknown, amounts: number[] = [], destinations: string[] = [], key = ""): { amounts: number[]; destinations: string[] } {
  if (AMOUNT_KEY.test(key)) { const n = num(value); if (n !== null) amounts.push(n); }
  if (DEST_KEY.test(key) && typeof value === "string" && value) destinations.push(value);
  if (Array.isArray(value)) value.forEach((v) => deepFinancials(v, amounts, destinations));
  else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) deepFinancials(v, amounts, destinations, k);
  return { amounts, destinations };
}

/** Deterministic heuristic engine. Heuristics are NOT perfect protection -
 *  see SECURITY.md for stated limits. Hard findings can BLOCK. */
export function analyzeAction(input: {
  actionType: string; payload: Record<string, unknown>; reasoning?: string;
  authorized?: boolean; authorizationEvidence?: string;
}, policy: PolicyContext): { findings: Finding[]; hardViolations: string[] } {
  const findings: Finding[] = [];
  const hard: string[] = [];
  const text = `${input.actionType} ${JSON.stringify(input.payload)} ${input.reasoning ?? ""}`;
  const push = (f: Finding, isHard = false) => { findings.push({ ...f, hard: isHard }); if (isHard) hard.push(f.description); };

  for (const re of INJECTION) {
    const m = text.match(re);
    if (m) push({ threatId: "prompt-injection", category: "Prompt injection", severity: "CRITICAL", description: "Possible prompt injection: instruction-override pattern detected in action content.", evidence: [m[0]], mitigation: "Reject embedded instructions from untrusted content; re-run with sanitized input." }, true);
  }
  for (const re of SECRET) {
    if (re.test(text)) push({ threatId: "credential-disclosure", category: "Data leakage", severity: "CRITICAL", description: "Action appears to contain or request credential material.", evidence: ["[redacted pattern match]"], mitigation: "Strip secrets, rotate any exposed credential, and block exfiltration." }, true);
  }

  const { amounts, destinations } = deepFinancials(input.payload);
  const amount = amounts.length ? Math.max(...amounts) : null;
  const prior = policy.priorSpentUsd ?? 0;
  for (const a of amounts) {
    if (a > policy.spendingLimitUsd) push({ threatId: "spending-limit", category: "Financial policy violation", severity: "HIGH", description: `Amount ${a} exceeds configured spending limit ${policy.spendingLimitUsd}.`, evidence: [`amount=${a}`, `limit=${policy.spendingLimitUsd}`], mitigation: "Reduce amount to within limit or obtain human approval." }, true);
    if (a + prior > policy.spendingLimitUsd && a <= policy.spendingLimitUsd) push({ threatId: "cumulative-spending-limit", category: "Financial policy violation", severity: "HIGH", description: `Cumulative spend ${prior} + ${a} exceeds configured spending limit ${policy.spendingLimitUsd}.`, evidence: [`prior=${prior}`, `amount=${a}`, `limit=${policy.spendingLimitUsd}`], mitigation: "Wait for the limit window to reset or obtain human approval for the total." }, true);
  }
  if (policy.allowedDestinations.length > 0) {
    const allowed = new Set(policy.allowedDestinations.map((d) => d.trim().toLowerCase()));
    for (const dest of destinations) {
      // Exact match only - substring/lookalike destinations must not pass.
      if (!allowed.has(dest.trim().toLowerCase())) push({ threatId: "unauthorized-destination", category: "Financial policy violation", severity: "HIGH", description: `Destination "${dest}" is not exactly in the allowed destinations list.`, evidence: ["[destination withheld]"], mitigation: "Use an allow-listed destination or request a policy change." }, true);
    }
  }
  if (policy.permissions.length === 0) {
    push({ threatId: "no-permissions-configured", category: "Unauthorized action", severity: "HIGH", description: "Agent has no configured permissions; deny-by-default applies to every action type.", evidence: [input.actionType], mitigation: "Configure explicit permissions for this agent before it acts." }, true);
  } else if (!policy.permissions.includes(input.actionType)) {
    push({ threatId: "unauthorized-action", category: "Unauthorized action", severity: "HIGH", description: `Action type "${input.actionType}" is outside the agent's configured permissions.`, evidence: [input.actionType], mitigation: "Grant the permission explicitly or choose a permitted action type." }, true);
  }
  const needsAuth = requiresAuth(input) || amounts.length > 0;
  if (needsAuth && !validAuthorizationEvidence(input.authorizationEvidence)) {
    const claimed = input.authorized === true || Boolean(input.authorizationEvidence);
    push({ threatId: "missing-authorization", category: "Unauthorized action", severity: "HIGH", description: claimed ? "Authorization evidence is not a valid signed-approval reference (expected sig:<24+ chars>)." : "No verified authorization evidence supplied for this action.", evidence: ["authorizationEvidence missing or malformed"], mitigation: "Attach a valid signed authorization reference (sig:...) before execution." }, true);
  }
  if (/transfer|payment|send|withdraw/i.test(input.actionType) && amount !== null && amount >= policy.spendingLimitUsd * 0.9 && amount <= policy.spendingLimitUsd) {
    findings.push({ threatId: "near-limit-transfer", category: "Suspicious behavior", severity: "MEDIUM", description: "Transfer amount is close to the spending limit (possible limit probing).", evidence: [`amount=${amount}`], mitigation: "Review pattern of near-limit transfers.", hard: false });
  }
  return { findings, hardViolations: hard };
}

function requiresAuth(i: { actionType: string; payload: Record<string, unknown> }) {
  return /transfer|payment|send|withdraw|delete|export/i.test(i.actionType);
}
export function num(v: unknown): number | null { const n = typeof v === "string" ? Number(v) : typeof v === "number" ? v : NaN; return Number.isFinite(n) ? n : null; }
export function str(v: unknown): string { return typeof v === "string" ? v : ""; }

/** Redaction layer. Fail-closed for secret-named fields; value patterns are
 *  masked wherever they appear. Applied before provider submission AND
 *  before persistence, so stored traces never hold raw secrets. */
const SECRET_KEY = /(api[_-]?key|password|passwd|secret|token|private[_-]?key|seed|credential|authorization)/i;
export function redact(value: unknown, key = ""): unknown {
  if (SECRET_KEY.test(key)) return "[REDACTED]";
  if (typeof value === "string") {
    return value
      .replace(/sk-[A-Za-z0-9_-]{8,}/g, "[REDACTED]")
      .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, "Bearer [REDACTED]")
      .replace(/(api[_-]?key|password|passwd|secret|access[_-]?token)\s*[:=]\s*\S+/gi, "$1:[REDACTED]")
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
