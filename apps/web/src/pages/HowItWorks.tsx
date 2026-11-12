import { Link } from "react-router-dom";
import { Eyebrow, PublicLayout, Table, usePageTitle } from "../components/Site";

const STEPS: [string, string][] = [
  ["Submit", "An agent (or your orchestrator) sends a proposed action to POST /api/v1/actions/analyze with its API key: the action type, a payload, and the agent's reasoning. A request with an idempotency key that was seen before returns the original result instead of running twice."],
  ["Redact", "Secrets (API keys, tokens, passwords) are stripped from the payload with pattern matching before anything is stored or sent to a provider."],
  ["Enforce", "Deterministic rules run first: is the action type in the agent's permissions, is the amount within the per-action limit and the rolling spend window, is the destination on the allow-list, is the amount a valid number, and is there authorization evidence for money. Prompt-injection and credential-leak patterns are checked too. Any hard violation is an immediate BLOCK, and no provider credits are spent on it."],
  ["Reason", "OpenServ SERV Reasoning returns a structured security assessment (JSON-schema enforced). It can add findings and recommend a block, but it can never override a hard policy violation. If SERV is unavailable, the action cannot be approved."],
  ["Evaluate", "A redacted trace goes to the Reppo Evaluation API. A panel of independent evaluators scores it, usually within 30 to 90 seconds. Reppo takes one evaluation at a time per account, so a busy account queues the action and the worker resubmits it automatically."],
  ["Decide", "A fail-closed decision engine combines everything. Only a fresh, settled Reppo verdict that says accept, routes to auto-ship, has enough confidence and clears the score threshold, with SERV in agreement and no policy violations, can APPROVE. Every unknown state resolves to HOLD, REVIEW or BLOCK."],
  ["Review", "REVIEW decisions wait for a person, who can approve or reject exactly once. A BLOCK can never be approved through that path."],
  ["Record", "Every step lands in the audit trail (exportable as CSV), and the dashboard updates live."],
  ["Revise", "Blocked, revised or reviewed actions can be fixed and resubmitted with a link to the original. Improvement Lab compares the two Reppo scores once both have settled."],
];

export default function HowItWorks() {
  usePageTitle("How it works");
  return <PublicLayout>
    <section className="pt-14 pb-10 max-w-3xl">
      <Eyebrow>HOW IT WORKS</Eyebrow>
      <h1 className="text-[38px] md:text-[48px] font-bold mt-4 leading-[1.08] tracking-tight">One gate between an agent and what it acts on.</h1>
      <p className="mt-5 text-[17px] leading-relaxed" style={{ color: "var(--text2)" }}>AgentShield does not execute anything. It answers one question before your agent acts: should this action proceed? Three systems keep strict lanes: code enforces policy, SERV Reasoning analyzes, and Reppo independently evaluates. Nothing pending or unknown is ever treated as approval.</p>
    </section>

    <section className="pb-12"><h2 className="text-2xl font-bold mb-5">Every action runs these steps in order</h2>
      <ol className="space-y-3">{STEPS.map(([t, d], i) => <li key={t} className="card flex gap-4" style={{ padding: 18 }}>
        <span className="mono text-sm font-bold shrink-0 w-8" style={{ color: "#34D399" }}>{String(i + 1).padStart(2, "0")}</span>
        <div><h3 className="font-bold">{t}</h3><p className="text-sm mt-1 leading-relaxed" style={{ color: "var(--text2)" }}>{d}</p></div>
      </li>)}</ol>
      <p className="text-sm mt-4" style={{ color: "var(--muted)" }}>Steps 1 to 3 can stop an action before any provider is called.</p>
    </section>

    <section className="pb-12"><h2 className="text-2xl font-bold mb-5">The five outcomes</h2>
      <Table head={["Outcome", "When", "What happens next"]} rows={[
        ["APPROVE", "No violations, SERV agrees, and a fresh settled Reppo verdict says accept with route auto-ship, high or medium confidence and a score at or above the threshold (default 80).", "Your agent may proceed."],
        ["HOLD", "The Reppo evaluation is pending or queued.", "Wait. The decision re-runs automatically when it settles."],
        ["REVIEW", "Anything uncertain: low confidence, evaluators disagree, Reppo or SERV failed or is stale, or SERV and Reppo disagree.", "A person approves or rejects once."],
        ["REVISE", "Reppo says revise, or the score is below the threshold.", "Fix the action using the critiques and resubmit."],
        ["BLOCK", "A hard policy violation, a critical threat, a SERV block, or Reppo reject.", "Not approvable. Revise and resubmit as a new action."],
      ]} />
    </section>

    <section className="pb-4"><h2 className="text-2xl font-bold mb-5">What never happens</h2>
      <ul className="space-y-2.5 text-[15px] leading-relaxed" style={{ color: "var(--text2)" }}>
        <li>A pending, failed, missing or stale evaluation is never counted as approval.</li>
        <li>An AI verdict never overrides a hard policy violation.</li>
        <li>A missing provider key is never hidden. The dashboard says so and routes the action to a person.</li>
        <li>Scores are never invented. They appear only after Reppo settles an evaluation.</li>
        <li>One agent's key never reads another agent's records.</li>
      </ul>
      <div className="flex flex-wrap gap-3 mt-8"><Link to="/docs" className="btn">Read the docs</Link><Link to="/faq" className="btn btn-ghost">FAQ</Link><Link to="/register" className="btn btn-ghost">Try it</Link></div>
    </section>
  </PublicLayout>;
}
