import { ArrowRight, Github, Menu, Shield, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";

export const GITHUB = "https://github.com/Abbagigo13/agentshield";
const NAV = [["How it works", "/how-it-works"], ["Docs", "/docs"], ["FAQ", "/faq"]] as const;

export function usePageTitle(title: string) { useEffect(() => { document.title = `${title} - AgentShield`; }, [title]); }

export function Brand() {
  return <Link to="/" className="flex items-center gap-2.5 font-bold text-lg"><span style={{ background: "linear-gradient(135deg,#0B8A5F,#15C17B)", borderRadius: 9, padding: 7, display: "grid", placeItems: "center" }}><Shield size={18} color="#fff" /></span>AgentShield</Link>;
}

export function SiteHeader() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => setOpen(false), [pathname]);
  const link = ({ isActive }: { isActive: boolean }) => ({ color: isActive ? "var(--text)" : "var(--text2)" });
  return <header className="relative" style={{ borderBottom: "1px solid var(--border)" }}>
    <div className="flex justify-between items-center h-[72px]">
      <Brand />
      <nav className="hidden md:flex items-center gap-1 text-sm font-medium">
        {NAV.map(([t, to]) => <NavLink key={to} to={to} style={link} className="px-3 py-2">{t}</NavLink>)}
        <a href={GITHUB} target="_blank" rel="noreferrer" className="px-3 py-2 flex items-center gap-1.5" style={{ color: "var(--text2)" }}><Github size={15} />GitHub</a>
        <Link to="/login" className="px-3 py-2" style={{ color: "var(--text2)" }}>Sign in</Link>
        <Link to="/register" className="btn btn-sm ml-1" style={{ padding: "8px 14px" }}>Start free</Link>
      </nav>
      <button className="md:hidden btn btn-ghost btn-sm" aria-label="Menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>{open ? <X size={18} /> : <Menu size={18} />}</button>
    </div>
    {open && <nav className="md:hidden pb-4 flex flex-col text-[15px] font-medium">
      {NAV.map(([t, to]) => <NavLink key={to} to={to} style={link} className="py-2.5">{t}</NavLink>)}
      <a href={GITHUB} target="_blank" rel="noreferrer" className="py-2.5" style={{ color: "var(--text2)" }}>GitHub</a>
      <Link to="/login" className="py-2.5" style={{ color: "var(--text2)" }}>Sign in</Link>
      <Link to="/register" className="btn mt-2">Start free <ArrowRight size={15} /></Link>
    </nav>}
  </header>;
}

const col = (title: string, items: ReactNode[]) => <div><h4 className="mono text-[11px] font-bold tracking-[.14em] uppercase mb-3" style={{ color: "var(--muted)" }}>{title}</h4><ul className="space-y-2.5 text-sm">{items.map((x, i) => <li key={i}>{x}</li>)}</ul></div>;
const L = (to: string, t: string) => <Link to={to} style={{ color: "var(--text2)" }}>{t}</Link>;

export function SiteFooter() {
  return <footer className="mt-20 py-10" style={{ borderTop: "1px solid var(--border)", color: "var(--muted)" }}>
    <div className="grid gap-8 md:grid-cols-[1.4fr_1fr_1fr_1fr]">
      <div><Brand /><p className="text-sm mt-3 max-w-xs leading-relaxed" style={{ color: "var(--text2)" }}>Deterministic rules decide. SERV Reasoning analyzes. Reppo evaluates. People approve what is uncertain.</p></div>
      {col("Product", [L("/how-it-works", "How it works"), L("/register", "Create an account"), L("/login", "Sign in"), L("/faq", "FAQ")])}
      {col("Build", [L("/docs", "Docs"), L("/docs#api", "API reference"), L("/docs#limits", "Security and limits"), <a href={GITHUB} target="_blank" rel="noreferrer" style={{ color: "var(--text2)" }}>GitHub</a>])}
      {col("Learn", [L("/docs#quickstart", "Quick start"), L("/docs#outcomes", "Decision outcomes"), L("/faq", "Why is my action on hold?")])}
    </div>
    <div className="flex flex-wrap gap-3 justify-between text-xs mt-10 pt-5" style={{ borderTop: "1px solid var(--border)" }}>
      <span>AgentShield - SERV Hackathon Edition 02, Reppo Track.</span>
      <span>Synthetic data only in demos; traces are redacted before submission.</span>
    </div>
  </footer>;
}

/** Shared frame for the public (signed-out) pages. */
export function PublicLayout({ children }: { children: ReactNode }) {
  const { pathname, hash } = useLocation();
  useEffect(() => { if (!hash) window.scrollTo(0, 0); }, [pathname, hash]);
  return <div style={{ background: "var(--bg)", minHeight: "100vh" }}><div className="max-w-6xl mx-auto px-6"><SiteHeader />{children}<SiteFooter /></div></div>;
}

export function Eyebrow({ children }: { children: ReactNode }) { return <p className="mono text-xs font-bold tracking-[.14em] uppercase" style={{ color: "#34D399" }}>[ {children} ]</p>; }
export function Code({ children }: { children: string }) { return <pre className="card mono text-xs leading-relaxed overflow-x-auto" style={{ padding: 16 }}>{children}</pre>; }
export function Table({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return <div className="overflow-x-auto card" style={{ padding: 0 }}><table className="w-full text-sm" style={{ borderCollapse: "collapse" }}>
    <thead><tr>{head.map((h) => <th key={h} className="text-left mono text-[11px] uppercase tracking-wider px-4 py-3" style={{ color: "var(--muted)", borderBottom: "1px solid var(--border)" }}>{h}</th>)}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j} className="px-4 py-3 align-top leading-relaxed" style={{ borderTop: i ? "1px solid var(--border)" : undefined, color: j ? "var(--text2)" : "var(--text)" }}>{c}</td>)}</tr>)}</tbody>
  </table></div>;
}
