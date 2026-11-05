import { Shield } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { post, setToken } from "../api";

export default function AuthPage({ mode }: { mode: "login" | "register" }) {
  const nav = useNavigate(); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) { e.preventDefault(); setBusy(true); const f = new FormData(e.currentTarget);
    try { const r = await post<{ token: string }>(`/api/v1/auth/${mode}`, { email: f.get("email"), password: f.get("password"), name: f.get("name") || undefined }); setToken(r.token); nav("/app"); }
    catch (x) { setErr(x instanceof Error ? x.message : "Failed"); } setBusy(false); }
  return <div className="min-h-screen grid lg:grid-cols-2">
    <div className="hidden lg:flex flex-col justify-between p-12" style={{ background: "linear-gradient(160deg,#0D1626,#080B12 65%)", borderRight: "1px solid var(--border)" }}>
      <Link to="/" className="flex items-center gap-2.5 font-bold text-lg"><span style={{ background: "linear-gradient(135deg,#0B8A5F,#15C17B)", borderRadius: 9, padding: 7, display: "grid", placeItems: "center" }}><Shield size={18} color="#fff" /></span>RecallGuard</Link>
      <div><h2 className="text-4xl font-bold leading-tight tracking-tight">Trust every action.<br />Verify every decision.</h2><p className="mt-4 max-w-md leading-relaxed" style={{ color: "var(--text2)" }}>Deterministic policy enforcement, SERV reasoning and independent Reppo evaluation - before an agent action can run.</p>
      <div className="grid grid-cols-3 gap-3 mt-8 max-w-md">{[["Policy", "Hard blocks first"], ["SERV", "Risk reasoning"], ["Reppo", "Settled verdicts"]].map(([a, b]) => <div key={a} style={{ border: "1px solid var(--border)", borderRadius: 10, padding: 12, background: "rgba(148,163,184,.04)" }}><span className="block font-bold text-sm">{a}</span><span className="text-xs" style={{ color: "var(--muted)" }}>{b}</span></div>)}</div></div>
      <p className="text-xs" style={{ color: "var(--muted)" }}>Synthetic data only in demos. Traces are redacted before evaluation.</p>
    </div>
    <div className="flex items-center justify-center p-6"><div className="w-full max-w-sm"><Link to="/" className="lg:hidden flex items-center gap-2 font-bold mb-8"><Shield color="#15C17B" />RecallGuard</Link>
    <h1 className="text-2xl font-bold tracking-tight">{mode === "login" ? "Welcome back" : "Create your workspace"}</h1><p className="text-sm mt-1.5 mb-6" style={{ color: "var(--text2)" }}>{mode === "login" ? "Sign in to monitor and verify agent actions." : "Start verifying agent actions in minutes."}</p>
    <form onSubmit={submit} className="space-y-3.5">{mode === "register" && <div><label className="text-xs font-semibold block mb-1.5" style={{ color: "var(--text2)" }}>Name</label><input name="name" placeholder="Your name" className="input" autoComplete="name" /></div>}<div><label className="text-xs font-semibold block mb-1.5" style={{ color: "var(--text2)" }}>Email</label><input name="email" type="email" required placeholder="you@company.com" className="input" autoComplete="email" /></div><div><label className="text-xs font-semibold block mb-1.5" style={{ color: "var(--text2)" }}>Password</label><input name="password" type="password" required placeholder="Min. 8 characters" className="input" autoComplete={mode === "login" ? "current-password" : "new-password"} /></div>{err && <p className="text-sm rounded-lg p-3" role="alert" style={{ color: "#FCA5A5", background: "rgba(248,113,113,.07)", border: "1px solid rgba(248,113,113,.22)" }}>{err}</p>}<button className="btn w-full" style={{ height: 42 }} disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}</button></form>
    <p className="text-sm mt-5" style={{ color: "var(--text2)" }}>{mode === "login" ? <>No account? <Link to="/register" className="font-semibold" style={{ color: "#34D399" }}>Sign up</Link></> : <>Have an account? <Link to="/login" className="font-semibold" style={{ color: "#34D399" }}>Sign in</Link></>}</p></div></div>
  </div>;
}
