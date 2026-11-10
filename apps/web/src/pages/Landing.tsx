import { ArrowRight, BrainCircuit, FileClock, Scale, Shield, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

const STEPS = [
  ["Submit", "An agent sends a proposed action to the AgentShield gateway with its API key."],
  ["Enforce", "Deterministic rules check spending limits, destinations, permissions, injection and leakage. Hard violations block immediately."],
  ["Reason", "SERV Reasoning returns a structured security assessment (JSON-schema enforced)."],
  ["Evaluate", "A sanitized trace goes to Reppo; the settled verdict (score, confidence, critiques) drives routing."],
  ["Decide", "APPROVE, REVISE, REVIEW (human), BLOCK or HOLD. Nothing pending is ever auto-approved."],
] as const;

export default function Landing() {
  return <div style={{ background: "var(--bg)" }}>
    <div className="max-w-6xl mx-auto px-6">
      <header className="flex justify-between items-center h-[72px]" style={{ borderBottom: "1px solid var(--border)" }}>
        <span className="flex items-center gap-2.5 font-bold text-lg"><span style={{ background: "linear-gradient(135deg,#0B8A5F,#15C17B)", borderRadius: 9, padding: 7, display: "grid", placeItems: "center" }}><Shield size={18} color="#fff" /></span>AgentShield</span>
        <nav className="flex items-center gap-3"><Link to="/login" className="text-sm font-medium px-3 py-2" style={{ color: "var(--text2)" }}>Sign in</Link><Link to="/register" className="btn btn-sm" style={{ padding: "8px 14px" }}>Start free</Link></nav>
      </header>
      <section className="py-20 md:py-24 max-w-3xl">
        <span className="badge" style={{ background: "rgba(21,193,123,.1)", color: "#6EE7B7" }}><ShieldCheck size={12} /> AI agent security gateway</span>
        <h1 className="text-[42px] md:text-[56px] font-bold mt-6 leading-[1.06] tracking-tight">Trust every action.<br /><span style={{ color: "#34D399" }}>Verify every decision.</span></h1>
        <p className="mt-6 text-[17px] leading-relaxed max-w-2xl" style={{ color: "var(--text2)" }}>AgentShield sits between autonomous AI agents and the systems they act on. Every proposed action is checked by a deterministic policy engine, analyzed with OpenServ SERV Reasoning, and independently evaluated by Reppo before it can run - with a full audit trail.</p>
        <div className="flex flex-wrap gap-3 mt-9"><Link to="/register" className="btn" style={{ height: 44, padding: "0 22px" }}>Start free <ArrowRight size={16} /></Link><Link to="/login" className="btn btn-ghost" style={{ height: 44, padding: "0 22px" }}>Open dashboard</Link></div>
        <p className="text-xs mt-4" style={{ color: "var(--muted)" }}>No credit card required · Provider keys stay server-side</p>
      </section>
      <section className="pb-16"><h2 className="text-xl font-bold mb-6">How it works</h2>
        <div className="grid md:grid-cols-5 gap-3">{STEPS.map(([t, d], i) => <article key={t} className="card card-hover" style={{ padding: 16 }}><span className="mono text-xs font-bold" style={{ color: "#34D399" }}>0{i + 1}</span><h3 className="font-bold mt-2.5">{t}</h3><p className="text-[13px] mt-1.5 leading-relaxed" style={{ color: "var(--text2)" }}>{d}</p></article>)}</div></section>
      <section className="grid md:grid-cols-3 gap-4 pb-20">
        <article className="card card-hover"><BrainCircuit color="#22D3EE" size={22} /><h3 className="font-bold mt-3">Independent evaluation</h3><p className="text-sm mt-1.5 leading-relaxed" style={{ color: "var(--text2)" }}>OpenServ SERV Reasoning for structured analysis. Reppo Evaluation API for independent, evidence-backed verdicts. Neither can override a critical policy violation.</p></article>
        <article className="card card-hover"><Scale color="#34D399" size={22} /><h3 className="font-bold mt-3">Human in the loop</h3><p className="text-sm mt-1.5 leading-relaxed" style={{ color: "var(--text2)" }}>Uncertain actions route to REVIEW. A person approves or rejects exactly once - blocked actions can never be approved through that path.</p></article>
        <article className="card card-hover"><FileClock color="#34D399" size={22} /><h3 className="font-bold mt-3">Honest by design</h3><p className="text-sm mt-1.5 leading-relaxed" style={{ color: "var(--text2)" }}>If a provider key is missing, the dashboard says so. Pending evaluations hold actions instead of approving them. Every event lands in the audit trail.</p></article>
      </section>
      <footer className="py-8 flex flex-wrap gap-3 justify-between text-xs" style={{ borderTop: "1px solid var(--border)", color: "var(--muted)" }}><span>AgentShield - SERV Hackathon Edition 02, Reppo Track.</span><span>Synthetic data only in demos; traces are redacted before submission.</span></footer>
    </div>
  </div>;
}
