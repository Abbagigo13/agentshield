const B = ({ className = "", style }: { className?: string; style?: React.CSSProperties }) => <div className={`skel ${className}`} style={style} aria-hidden="true" />;

export function Skeleton({ className = "", style }: { className?: string; style?: React.CSSProperties }) { return <B className={className} style={style} />; }

export function MetricCardSkeleton() {
  return <div className="card" role="status" aria-label="Loading metric"><div className="flex justify-between"><B className="h-3 w-24" /><B className="h-8 w-8" style={{ borderRadius: 8 }} /></div><B className="h-9 w-20 mt-4" /><B className="h-3 w-32 mt-3" /><B className="h-8 w-full mt-4" /></div>;
}
export function ChartSkeleton({ height = 240 }: { height?: number }) {
  return <div className="card" role="status" aria-label="Loading chart"><B className="h-4 w-44" /><B className="h-3 w-28 mt-2" /><B className="w-full mt-5" style={{ height }} /></div>;
}
export function TableSkeleton({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) {
  return <div className="card" role="status" aria-label="Loading table"><B className="h-4 w-40 mb-4" />{Array.from({ length: rows }).map((_, r) => <div key={r} className="flex gap-3 py-2.5" style={{ borderBottom: "1px solid rgba(148,163,184,.07)" }}>{Array.from({ length: cols }).map((_, c) => <B key={c} className="h-3.5" style={{ flex: c === 0 ? 1.4 : 1 }} />)}</div>)}</div>;
}
export function ActivityFeedSkeleton({ rows = 5 }: { rows?: number }) {
  return <div className="card" role="status" aria-label="Loading activity">{Array.from({ length: rows }).map((_, i) => <div key={i} className="flex gap-3 py-3" style={{ borderBottom: i < rows - 1 ? "1px solid rgba(148,163,184,.07)" : undefined }}><B className="h-9 w-9 shrink-0" style={{ borderRadius: 9 }} /><div className="flex-1"><B className="h-3.5 w-3/5" /><B className="h-3 w-2/5 mt-2" /></div><B className="h-5 w-16" style={{ borderRadius: 99 }} /></div>)}</div>;
}
export function AgentCardSkeleton() {
  return <div className="card" role="status" aria-label="Loading agent"><div className="flex gap-3 items-center"><B className="h-11 w-11" style={{ borderRadius: 10 }} /><div className="flex-1"><B className="h-4 w-32" /><B className="h-3 w-20 mt-2" /></div><B className="h-5 w-16" style={{ borderRadius: 99 }} /></div><B className="h-3 w-full mt-5" /><B className="h-3 w-2/3 mt-2" /><div className="flex gap-2 mt-4"><B className="h-8 w-24" /><B className="h-8 w-24" /></div></div>;
}
export function DashboardSkeleton() {
  return <div role="status" aria-label="Loading dashboard"><B className="h-8 w-72" /><B className="h-4 w-96 max-w-full mt-3" /><div className="grid grid-cols-2 lg:grid-cols-3 gap-4 mt-7">{Array.from({ length: 6 }).map((_, i) => <MetricCardSkeleton key={i} />)}</div><div className="grid lg:grid-cols-5 gap-4 mt-4"><div className="lg:col-span-3"><ChartSkeleton /></div><div className="lg:col-span-2"><ActivityFeedSkeleton /></div></div></div>;
}
export function PageSkeleton({ variant = "table" }: { variant?: "table" | "cards" | "dashboard" }) {
  if (variant === "dashboard") return <DashboardSkeleton />;
  return <div role="status" aria-label="Loading page"><B className="h-8 w-64" /><B className="h-4 w-80 max-w-full mt-3" /><div className="mt-7">{variant === "cards" ? <div className="grid md:grid-cols-2 gap-4">{Array.from({ length: 4 }).map((_, i) => <AgentCardSkeleton key={i} />)}</div> : <TableSkeleton />}</div></div>;
}
