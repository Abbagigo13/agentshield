import { Link } from "react-router-dom";
import { Eyebrow, GITHUB, PublicLayout, usePageTitle } from "../components/Site";

const QA: [string, string][] = [
  ["What is AgentShield?", "A security gateway for autonomous AI agents. Before an agent acts, it sends the proposed action to AgentShield and gets back a decision: approve, hold, review, revise or block. Every step is recorded in an audit trail."],
  ["Does it move money or run the action?", "No. AgentShield only decides. Your agent or orchestrator must proceed only when the outcome is APPROVE."],
  ["What do SERV and Reppo each do?", "OpenServ SERV Reasoning analyzes the action and returns a structured security assessment. The Reppo Evaluation API has a panel of independent evaluators score it. Deterministic code makes the final decision and neither AI system can override a hard policy violation."],
  ["Why is my action on HOLD?", "The Reppo evaluation is still running, which usually takes 30 to 90 seconds. Reppo handles one evaluation at a time per account, so if another is running yours is queued and submitted automatically as soon as it is free. The decision updates on its own."],
  ["Why did I get REVIEW even with a score of 99?", "Reppo's verdict also carries a confidence and a route. When its evaluators disagree, confidence drops and the route becomes review, even when the score is high. AgentShield fails closed: a person approves or rejects. This is the system working as designed."],
  ["Can a blocked action be approved by a human?", "No. Only REVIEW decisions can be approved or rejected, and only once. A blocked action must be revised and resubmitted as a new action."],
  ["Why was my blocked action not sent to Reppo?", "Hard policy violations and critical threats are decided by code first. Sending them to Reppo would only spend credits on an action that cannot be approved."],
  ["What happens if SERV or Reppo is down, or no key is configured?", "The dashboard says so, and the action goes to REVIEW or HOLD. A missing, failed, pending or stale result is never approval."],
  ["What data leaves AgentShield?", "A redacted version of the action and the agent's reasoning, plus the agent's policy summary, is sent to SERV and Reppo. Secrets such as API keys, tokens and passwords are stripped first using pattern matching. Do not put real credentials in payloads."],
  ["How do spending limits work?", "Each action must be within the agent's limit, and total spend by that agent inside a rolling window (24 hours by default) must also stay within it. Blocked actions do not count toward the total. Negative or unreadable amounts are blocked."],
  ["How do I improve an action that was not approved?", "Open it in Decision Center and choose Revise and resubmit. You see what to fix, edit the payload and reasoning, and resubmit. The new action is linked to the original, and Improvement Lab compares the two Reppo scores once both have settled."],
  ["Can one agent see another agent's data?", "No. An agent API key only reads its own agent's actions, evaluations and decisions. Signed-in account owners see everything for their account."],
  ["Does it cost anything to run?", "Each evaluation Reppo runs costs credits on the server's Reppo account. A daily budget caps how many evaluations are sent, and anything beyond it goes to a person."],
  ["Is the demo data real?", "No. Demo actions are synthetic, and traces are redacted before submission. This project was built for SERV Hackathon Edition 02 on the Reppo track."],
  ["What are the known limits?", "Amount and destination detection works by field name, authorization evidence is only format-checked, and named policies are recorded but not yet enforced. The full list is in the Security and limits section of the docs."],
];

export default function Faq() {
  usePageTitle("FAQ");
  return <PublicLayout>
    <section className="pt-14 pb-8 max-w-3xl"><Eyebrow>FAQ</Eyebrow>
      <h1 className="text-[38px] md:text-[46px] font-bold mt-4 leading-[1.08] tracking-tight">Questions, answered plainly.</h1>
      <p className="mt-5 text-[17px] leading-relaxed" style={{ color: "var(--text2)" }}>Short answers about what AgentShield does, what it leaves to you, and why it behaves the way it does.</p></section>
    <section className="max-w-3xl space-y-2.5">{QA.map(([q, a]) => <details key={q} className="card group" style={{ padding: "14px 18px" }}>
      <summary className="cursor-pointer font-semibold text-[15px] leading-snug">{q}</summary>
      <p className="text-[15px] leading-relaxed mt-3" style={{ color: "var(--text2)" }}>{a}</p></details>)}</section>
    <section className="max-w-3xl mt-10 text-[15px]" style={{ color: "var(--text2)" }}>Still stuck? Read the <Link to="/docs" style={{ color: "#34D399" }}>docs</Link>, see <Link to="/how-it-works" style={{ color: "#34D399" }}>how it works</Link>, or open an issue on <a href={GITHUB} target="_blank" rel="noreferrer" style={{ color: "#34D399" }}>GitHub</a>.</section>
  </PublicLayout>;
}
