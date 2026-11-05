import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowDownRight, ArrowUpRight, Inbox, Minus, X, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { api } from "../api";
import { PageSkeleton } from "./skeletons";

export type Row = Record<string, any>;
export const SEV: Record<string, string> = { CRITICAL: "#F87171", HIGH: "#FB923C", MEDIUM: "#FBBF24", LOW: "#38BDF8" };
export const OUT: Record<string, string> = { APPROVE: "#34D399", APPROVED: "#34D399", BLOCK: "#F87171", BLOCKED: "#F87171", REVIEW: "#FBBF24", REVISE: "#FB923C", HOLD: "#94A3B8", ACTIVE: "#34D399", SETTLED: "#34D399", PENDING: "#FBBF24", QUEUED: "#FBBF24", FAILED: "#F87171", NOT_SUBMITTED: "#94A3B8", UNAVAILABLE: "#94A3B8", DECIDED: "#38BDF8", ANALYZING: "#38BDF8", PENDING_EVALUATION: "#FBBF24", configured_unverified: "#FBBF24", connected: "#34D399", not_configured: "#94A3B8", ok: "#34D399", error: "#F87171" };
export const CHART = { blue: "#15C17B", cyan: "#22D3EE", emerald: "#34D399", amber: "#FBBF24", red: "#F87171", orange: "#FB923C", slate: "#64748B", grid: "rgba(148,163,184,.09)", tooltip: { background: "#0F172A", border: "1px solid rgba(148,163,184,.2)", borderRadius: 10, color: "#F1F5F9", fontSize: 12, boxShadow: "0 10px 30px rgba(0,0,0,.5)" } as React.CSSProperties };

export const badge = (v: string) => { const c = SEV[v] ?? OUT[v] ?? "#6EE7B7"; return <span className="badge" style={{ background: `${c}14`, color: c }}><span style={{ width: 6, height: 6, borderRadius: 99, background: c }} />{String(v || "-").replaceAll("_", " ")}</span>; };
export function StatusBadge({ value }: { value: string }) { return badge(value); }
export function useApi<T>(key: string, path: string, opts?: { refetchInterval?: number | false }) { return useQuery({ queryKey: [key, path], queryFn: () => api<T>(path), refetchInterval: opts?.refetchInterval }); }

export function EmptyState({ title, body, icon: Icon = Inbox }: { title: string; body?: string; icon?: LucideIcon }) {
  return <div className="flex flex-col items-center text-center py-10 px-4"><div style={{ background: "rgba(21,193,123,.09)", border: "1px solid rgba(21,193,123,.18)", borderRadius: 12, padding: 12 }}><Icon size={22} color="#34D399" /></div><p className="font-semibold mt-4">{title}</p>{body && <p className="text-sm mt-1 max-w-md" style={{ color: "var(--text2)" }}>{body}</p>}</div>;
}
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return <div className="card" role="alert" style={{ borderColor: "rgba(248,113,113,.3)" }}><div className="flex gap-3"><AlertTriangle size={20} color="#F87171" className="shrink-0 mt-0.5" /><div><p className="font-semibold" style={{ color: "#FCA5A5" }}>Could not load data</p><p className="text-sm mt-1" style={{ color: "var(--text2)" }}>{error instanceof Error ? error.message : "Request failed"}. Check that the API is running and reachable.</p>{onRetry && <button className="btn btn-ghost btn-sm mt-3" onClick={onRetry}>Retry</button>}</div></div></div>;
}
export function State({ q, children, skeleton }: { q: { isLoading: boolean; isError: boolean; error: unknown; refetch?: () => void }; children: ReactNode; skeleton?: ReactNode }) {
  if (q.isLoading) return <>{skeleton ?? <PageSkeleton />}</>;
  if (q.isError) return <ErrorState error={q.error} onRetry={q.refetch} />;
  return <>{children}</>;
}
export const H = ({ t, s, children }: { t: string; s?: string; children?: ReactNode }) => (
  <div className="mb-6 flex flex-wrap items-end justify-between gap-4"><div><h1 className="text-[26px] leading-tight font-bold tracking-tight">{t}</h1>{s && <p className="text-sm mt-1.5 max-w-2xl" style={{ color: "var(--text2)" }}>{s}</p>}</div>{children}</div>
);
export function PageHeader(props: { t: string; s?: string; children?: ReactNode }) { return <H {...props} />; }

export function Sparkline({ data, color = "#15C17B", height = 34 }: { data: number[]; color?: string; height?: number }) {
  if (data.length < 2 || data.every((v) => v === data[0])) return null;
  const max = Math.max(...data), min = Math.min(...data), range = max - min || 1, w = 120;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${height - 3 - ((v - min) / range) * (height - 8)}`).join(" ");
  return <svg width="100%" height={height} viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" aria-hidden="true"><polyline points={pts} fill="none" stroke={color} strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" opacity=".9" /></svg>;
}
export function Metric({ label, value, icon: Icon, sub, trend, spark, accent = "#15C17B" }: { label: string; value: ReactNode; icon?: LucideIcon; sub?: string; trend?: number | null; spark?: number[]; accent?: string }) {
  return <div className="card card-hover" style={{ padding: 18 }}>
    <div className="flex items-start justify-between gap-3"><span className="text-xs font-medium" style={{ color: "var(--text2)" }}>{label}</span>{Icon && <span style={{ background: `${accent}14`, border: `1px solid ${accent}26`, borderRadius: 8, padding: 7 }}><Icon size={16} color={accent} /></span>}</div>
    <div className="text-[30px] leading-none font-bold mt-3 num">{value ?? "-"}</div>
    <div className="flex items-end justify-between gap-3 mt-2.5 min-h-[18px]"><span className="text-xs" style={{ color: "var(--muted)" }}>{sub ?? ""}</span>
      {typeof trend === "number" && <span className="inline-flex items-center gap-1 text-xs font-semibold" style={{ color: trend > 0 ? "#34D399" : trend < 0 ? "#F87171" : "#94A3B8" }}>{trend > 0 ? <ArrowUpRight size={13} /> : trend < 0 ? <ArrowDownRight size={13} /> : <Minus size={13} />}{Math.abs(trend)}%</span>}</div>
    {spark && <div className="mt-1"><Sparkline data={spark} color={accent} /></div>}
  </div>;
}
export function ChartCard({ title, sub, children, action }: { title: string; sub?: string; children: ReactNode; action?: ReactNode }) {
  return <section className="card"><div className="flex flex-wrap justify-between gap-3 mb-4"><div><h3 className="font-semibold text-[15px]">{title}</h3>{sub && <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>{sub}</p>}</div>{action}</div>{children}</section>;
}
export function SearchInput({ value, onChange, placeholder = "Search…" }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return <div className="relative w-full sm:w-72"><input className="input" style={{ paddingLeft: 36 }} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} aria-label={placeholder} /><span className="absolute left-3 top-1/2 -translate-y-1/2 text-sm" style={{ color: "var(--muted)" }}>⌕</span></div>;
}
export function FilterSelect({ value, onChange, options, label }: { value: string; onChange: (v: string) => void; options: string[]; label: string }) {
  return <select className="input" style={{ width: "auto", minWidth: 150 }} value={value} onChange={(e) => onChange(e.target.value)} aria-label={label}><option value="ALL">{label}: All</option>{options.map((o) => <option key={o} value={o}>{o.replaceAll("_", " ")}</option>)}</select>;
}
export function DetailDrawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label={title}><div className="absolute inset-0" style={{ background: "rgba(3,6,12,.66)" }} onClick={onClose} /><aside className="drawer-enter absolute right-0 top-0 h-full w-full max-w-md overflow-y-auto p-6" style={{ background: "var(--elev)", borderLeft: "1px solid var(--border)" }}><div className="flex items-center justify-between mb-5"><h2 className="font-bold text-lg">{title}</h2><button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close details"><X size={16} /></button></div>{children}</aside></div>;
}
export function ConfirmDialog({ title, body, confirmLabel = "Confirm", tone = "danger", icon: Icon, onCancel, onConfirm }: { title: string; body: string; confirmLabel?: string; tone?: "danger" | "amber" | "emerald"; icon?: LucideIcon; onCancel: () => void; onConfirm: () => void }) {
  return <div className="fixed inset-0 z-50 grid place-items-center p-4" role="alertdialog" aria-modal="true"><div className="absolute inset-0" style={{ background: "rgba(3,6,12,.66)" }} onClick={onCancel} /><div className="pop-enter card relative w-full max-w-sm" style={{ borderRadius: 18, padding: 26 }}>{Icon && <span className="inline-grid place-items-center mb-4" style={{ background: tone === "amber" ? "rgba(245,181,68,.14)" : tone === "emerald" ? "rgba(21,193,123,.13)" : "rgba(248,113,113,.12)", borderRadius: 11, padding: 10 }}><Icon size={19} color={tone === "amber" ? "#F5B544" : tone === "emerald" ? "#34D399" : "#F87171"} /></span>}<h2 className="font-bold text-lg">{title}</h2><p className="text-sm mt-2" style={{ color: "var(--text2)" }}>{body}</p><div className="flex gap-2 mt-5 justify-end"><button className="btn btn-ghost" onClick={onCancel}>Cancel</button><button className={tone === "amber" ? "btn btn-amber" : tone === "emerald" ? "btn" : "btn btn-danger"} onClick={onConfirm}>{confirmLabel}</button></div></div></div>;
}
export function Toast({ msg, tone = "info" }: { msg: string; tone?: "info" | "error" | "success" }) {
  if (!msg) return null; const c = tone === "error" ? "#F87171" : tone === "success" ? "#34D399" : "#34D399";
  return <div className="pop-enter card text-sm mb-4 flex gap-2.5 items-start" role="status" style={{ borderColor: `${c}44`, padding: "13px 16px" }}><span style={{ width: 8, height: 8, borderRadius: 99, background: c, marginTop: 5, flexShrink: 0 }} />{msg}</div>;
}
export function DetailRow({ k, v }: { k: string; v: ReactNode }) { return <div className="flex justify-between gap-4 py-2.5 text-sm" style={{ borderBottom: "1px solid rgba(148,163,184,.07)" }}><span style={{ color: "var(--muted)" }}>{k}</span><span className="text-right break-all">{v ?? "-"}</span></div>; }
export const fmtDate = (v: unknown) => { const d = new Date(String(v ?? "")); return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); };
export const fmtTime = (v: unknown) => { const d = new Date(String(v ?? "")); return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }); };
/** Group dated rows into per-day counts (oldest→newest) from real data only. */
export function dailySeries(rows: Row[], days = 14): { label: string; count: number; date: string }[] {
  const out: { label: string; count: number; date: string }[] = []; const now = new Date(); now.setHours(0, 0, 0, 0);
  for (let i = days - 1; i >= 0; i--) { const d = new Date(now); d.setDate(d.getDate() - i); const key = d.toDateString(); out.push({ label: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }), date: key, count: rows.filter((r) => new Date(String(r.createdAt ?? "")).toDateString() === key).length }); }
  return out;
}
export function trendPct(series: number[]): number | null {
  if (series.length < 4) return null; const half = Math.floor(series.length / 2); const a = series.slice(0, half).reduce((s, v) => s + v, 0), b = series.slice(half).reduce((s, v) => s + v, 0);
  if (a === 0) return b > 0 ? 100 : null; return Math.round(((b - a) / a) * 100);
}
export { PageSkeleton };
