import { Activity, Bot, CheckCircle2, ChevronDown, Clock3, Gauge, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CHART, EmptyState, Metric, State, dailySeries, fmtDate, trendPct, useApi, type Row } from "../components/ui";
import { DashboardSkeleton } from "../components/skeletons";

export default function Overview() {
  const q = useApi<Row>("ov", "/api/v1/analytics/overview");
  const t = useApi<Row>("th", "/api/v1/analytics/threats");
  const acts = useApi<Row[]>("ov-acts", "/api/v1/actions");
  const decs = useApi<Row[]>("ov-decs", "/api/v1/decisions");
  const evals = useApi<Row[]>("ov-evals", "/api/v1/evaluations");
  const agents = useApi<Row[]>("ov-agents", "/api/v1/agents");
  const [days, setDays] = useState(14); const [open, setOpen] = useState<string | null>(null);
  const series = useMemo(() => dailySeries(acts.data ?? [], days), [acts.data, days]);
  const outcomeData = useMemo(() => { const m: Record<string, number> = {}; (decs.data ?? []).forEach((d) => { m[d.outcome] = (m[d.outcome] ?? 0) + 1; }); return Object.entries(m).map(([name, value]) => ({ name, value })); }, [decs.data]);
  const sev = Object.entries(t.data?.bySeverity ?? {}).map(([name, value]) => ({ name, value: Number(value) }));
  const agentPerf = useMemo(() => { const names = new Map((agents.data ?? []).map((a) => [a.id, a.name])); const m: Record<string, number> = {}; (acts.data ?? []).forEach((a) => { const n = names.get(a.agentId) ?? "Agent"; m[n] = (m[n] ?? 0) + 1; }); return Object.entries(m).map(([name, actions]) => ({ name: String(name).slice(0, 14), actions })).slice(0, 6); }, [acts.data, agents.data]);
  const totalDecisions = decs.data?.length ?? 0;
  const verified = (evals.data ?? []).filter((e) => e.status === "SETTLED").length;
  const successRate = totalDecisions ? Math.round(((decs.data ?? []).filter((d) => d.outcome === "APPROVE").length / totalDecisions) * 100) : null;
  const spark = series.map((s) => s.count);
  const recent = q.data?.recentActivity ?? [];
  const settledShare = evals.data?.length ? Math.round((verified / evals.data.length) * 100) : null;
  const activeShare = agents.data?.length ? Math.round(((agents.data ?? []).filter((a) => a.status === "ACTIVE").length / agents.data.length) * 100) : null;
  const criticals = Number(t.data?.bySeverity?.CRITICAL ?? 0);
  const score = typeof q.data?.avgReppoScore === "number" ? q.data.avgReppoScore : null;
  const riskFactors: Array<[string, number | null, string]> = [
    ["Threat control", criticals > 0 ? 25 : (q.data?.threatsDetected ?? 0) > 0 ? 70 : 100, criticals > 0 ? `${criticals} critical flagged` : (q.data?.threatsDetected ?? 0) > 0 ? "Watch" : "Clean"],
    ["Evaluation coverage", settledShare, settledShare === null ? "No evaluations" : `${verified} settled`],
    ["Agent posture", activeShare, activeShare === null ? "No agents" : `${activeShare}% active`],
    ["Approval rate", successRate, successRate === null ? "No decisions" : `${successRate}% approved`],
    ["Evaluation score", score, score === null ? "Not settled yet" : `${score} / 100`],
  ];
  const riskLevel = riskFactors.some(([, v]) => v !== null && v < 40) ? "High" : riskFactors.some(([, v]) => v !== null && v < 75) ? "Watch" : "Low";
  const segColor = (v: number | null) => v === null ? "rgba(148,163,184,.25)" : v >= 75 ? "#15C17B" : v >= 40 ? "#F5B544" : "#F87171";
  return <>
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div><h1 className="text-[26px] font-bold tracking-tight">Security overview</h1><p className="text-sm mt-1.5" style={{ color: "var(--text2)" }}>Live posture across agents, decisions and evaluations.</p><p className="text-xs mt-1" style={{ color: "var(--muted)" }}><span className="live-dot inline-block mr-1.5" style={{ width: 7, height: 7, borderRadius: 99, background: "#34D399", verticalAlign: "middle" }} />Synced from the AgentShield API{q.data ? "" : "…"} · auto-refreshes</p></div>
      <label className="text-xs font-medium" style={{ color: "var(--text2)" }}>Range <select className="input ml-2" style={{ width: "auto", height: 36, padding: "6px 10px" }} value={days} onChange={(e) => setDays(Number(e.target.value))}><option value={7}>Last 7 days</option><option value={14}>Last 14 days</option><option value={30}>Last 30 days</option></select></label>
    </div>
    <State q={q} skeleton={<DashboardSkeleton />}>
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <Metric label="Total decisions" value={totalDecisions || q.data?.actionsAnalyzed} icon={Gauge} accent="#15C17B" sub="All recorded outcomes" trend={trendPct(spark)} spark={spark} />
        <Metric label="Verified decisions" value={verified} icon={ShieldCheck} accent="#34D399" sub="Settled Reppo evaluations" />
        <Metric label="Blocked threats" value={q.data?.actionsBlocked} icon={XCircle} accent="#F87171" sub={`${q.data?.threatsDetected ?? 0} threats detected`} />
        <Metric label="Active agents" value={(agents.data ?? []).filter((a) => a.status === "ACTIVE").length || q.data?.agents} icon={Bot} accent="#22D3EE" sub={`${q.data?.agents ?? 0} registered`} />
        <Metric label="Approval rate" value={successRate === null ? "-" : `${successRate}%`} icon={CheckCircle2} accent="#34D399" sub="APPROVE share of decisions" />
        <Metric label="Avg Reppo score" value={q.data?.avgReppoScore ?? "-"} icon={Activity} accent="#FBBF24" sub={q.data?.pendingEvaluations ? `${q.data.pendingEvaluations} pending evaluations` : "Settled evaluations only"} />
      </div>
      <div className="grid lg:grid-cols-5 gap-4 mt-4">
        <section className="card lg:col-span-3"><div className="flex justify-between mb-4"><div><h3 className="font-semibold text-[15px]">Decision activity</h3><p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>Actions analyzed per day · real submission timestamps</p></div><Clock3 size={16} color="#64748B" /></div>
          {acts.data?.length ? <ResponsiveContainer width="100%" height={248}><AreaChart data={series}><defs><linearGradient id="actFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#15C17B" stopOpacity={.32} /><stop offset="100%" stopColor="#15C17B" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke={CHART.grid} vertical={false} /><XAxis dataKey="label" tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} width={30} /><Tooltip contentStyle={CHART.tooltip} /><Area type="monotone" dataKey="count" name="Actions" stroke="#15C17B" strokeWidth={2} fill="url(#actFill)" /></AreaChart></ResponsiveContainer> : <EmptyState title="No activity yet" body="Submit an action from Live Monitoring to see activity here." />}</section>
        <section className="card lg:col-span-2"><div className="flex items-center justify-between"><h3 className="font-semibold text-[15px]">Risk</h3><span className="badge" style={{ background: riskLevel === "Low" ? "rgba(21,193,123,.12)" : riskLevel === "Watch" ? "rgba(245,181,68,.12)" : "rgba(248,113,113,.12)", color: riskLevel === "Low" ? "#34D399" : riskLevel === "Watch" ? "#F5B544" : "#F87171" }}><span style={{ width: 6, height: 6, borderRadius: 99, background: "currentColor" }} />{riskLevel}</span></div>
          <div className="flex gap-1.5 mt-4" aria-hidden="true">{riskFactors.map(([n, v]) => <span key={n} title={n} style={{ flex: 1, height: 5, borderRadius: 99, background: segColor(v) }} />)}</div>
          <p className="text-xs mt-2.5" style={{ color: "var(--muted)" }}>{riskFactors.filter(([, v]) => v !== null && v < 75).length} of {riskFactors.length} factors need attention.</p>
          <div className="mt-2">{riskFactors.map(([n, v, note]) => <div key={n} className="flex items-center justify-between py-2.5 text-sm" style={{ borderBottom: "1px solid rgba(148,163,184,.06)" }}><span style={{ color: "var(--text2)" }}>{n}</span><span className="inline-flex items-center gap-1.5 text-xs font-semibold" style={{ color: segColor(v) }}><span style={{ width: 6, height: 6, borderRadius: 99, background: "currentColor" }} />{note}</span></div>)}</div>
          {score !== null && <div className="mt-4 rounded-xl p-3.5" style={{ background: "rgba(148,163,184,.04)", border: "1px solid var(--border)" }}><div className="flex justify-between text-xs"><span style={{ color: "var(--muted)" }}>Last evaluation average</span><b className="num">{score} / 100</b></div><div className="flex gap-[3px] mt-2.5" aria-hidden="true">{Array.from({ length: 28 }).map((_, i) => <span key={i} style={{ flex: 1, height: 14, borderRadius: 2, background: i < Math.round((score / 100) * 28) ? "#15C17B" : "rgba(148,163,184,.18)" }} />)}</div></div>}</section>
      </div>
      <div className="grid lg:grid-cols-3 gap-4 mt-4">
        <section className="card"><h3 className="font-semibold text-[15px]">Threat distribution</h3><p className="text-xs mt-0.5 mb-2" style={{ color: "var(--muted)" }}>Findings by severity</p>
          {sev.length ? <ResponsiveContainer width="100%" height={210}><BarChart data={sev} layout="vertical"><CartesianGrid stroke={CHART.grid} horizontal={false} /><XAxis type="number" allowDecimals={false} tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis type="category" dataKey="name" tick={{ fill: "#94A3B8", fontSize: 11 }} axisLine={false} tickLine={false} width={72} /><Tooltip contentStyle={CHART.tooltip} /><Bar dataKey="value" name="Threats" radius={[0, 6, 6, 0]}>{sev.map((s) => <Cell key={s.name} fill={{ CRITICAL: "#F87171", HIGH: "#FB923C", MEDIUM: "#FBBF24", LOW: "#38BDF8" }[s.name] ?? "#38BDF8"} />)}</Bar></BarChart></ResponsiveContainer> : <EmptyState title="No threats recorded" body="Deterministic findings will appear here." icon={ShieldAlert} />}</section>
        <section className="card"><h3 className="font-semibold text-[15px]">Verification outcomes</h3><p className="text-xs mt-0.5 mb-2" style={{ color: "var(--muted)" }}>Decision outcome distribution</p>
          {outcomeData.length ? <ResponsiveContainer width="100%" height={210}><PieChart><Pie data={outcomeData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={74} paddingAngle={3} stroke="none">{outcomeData.map((x) => <Cell key={x.name} fill={{ APPROVE: "#34D399", BLOCK: "#F87171", REVIEW: "#FBBF24", REVISE: "#FB923C", HOLD: "#94A3B8" }[x.name] ?? "#38BDF8"} />)}</Pie><Tooltip contentStyle={CHART.tooltip} /></PieChart></ResponsiveContainer> : <EmptyState title="No decisions yet" body="Outcomes appear after actions are analyzed." />}</section>
        <section className="card"><h3 className="font-semibold text-[15px]">Agent performance</h3><p className="text-xs mt-0.5 mb-2" style={{ color: "var(--muted)" }}>Actions analyzed per agent</p>
          {agentPerf.length ? <ResponsiveContainer width="100%" height={210}><BarChart data={agentPerf}><CartesianGrid stroke={CHART.grid} vertical={false} /><XAxis dataKey="name" tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#64748B", fontSize: 11 }} axisLine={false} tickLine={false} width={30} /><Tooltip contentStyle={CHART.tooltip} /><Bar dataKey="actions" name="Actions" fill="#22D3EE" radius={[6, 6, 0, 0]} fillOpacity={.85} /></BarChart></ResponsiveContainer> : <EmptyState title="No agent activity" body="Register an agent and submit an action to compare performance." icon={Bot} />}</section>
      </div>
      <section className="card mt-4"><h3 className="font-semibold text-[15px] mb-1">Recent activity</h3><p className="text-xs mb-3" style={{ color: "var(--muted)" }}>Latest audit events for your account</p>
        {recent.length ? recent.map((a: Row) => <div key={a.id} style={{ borderTop: "1px solid rgba(148,163,184,.07)" }}><button className="w-full flex items-center gap-3 py-3 text-left" onClick={() => setOpen(open === a.id ? null : a.id)} aria-expanded={open === a.id}><span style={{ background: "rgba(21,193,123,.1)", border: "1px solid rgba(21,193,123,.18)", borderRadius: 8, padding: 7 }}><Activity size={14} color="#34D399" /></span><span className="flex-1 min-w-0"><span className="block text-sm font-medium truncate">{a.event}</span><span className="block text-xs" style={{ color: "var(--muted)" }}>{fmtDate(a.createdAt)}{a.actionId ? ` · action ${String(a.actionId).slice(0, 8)}…` : ""}</span></span><ChevronDown size={15} color="#64748B" style={{ transform: open === a.id ? "rotate(180deg)" : undefined, transition: "transform .2s" }} /></button>{open === a.id && <div className="pb-3 pl-12 text-[13px]" style={{ color: "var(--text2)" }}><p>Event <span className="mono">{a.event}</span>{a.agentId ? <> · Agent <span className="mono">{String(a.agentId).slice(0, 12)}…</span></> : null}</p><p className="mt-1">Recorded {fmtDate(a.createdAt)}. Full details are available in the Audit Trail.</p></div>}</div>) : <EmptyState title="No activity yet" body="Authentication, agent and decision events will appear here." />}</section>
    </State></>;
}
