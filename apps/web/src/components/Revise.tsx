import { FlaskConical, Send } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, post } from "../api";
import { DetailDrawer, Toast, badge, type Row } from "./ui";

/** Revise & resubmit: loads the original action's trace (what to fix + Reppo critiques),
 *  lets the user edit payload/reasoning, and submits a child action (parentActionId) so the
 *  Improvement Lab can compare original vs revised Reppo scores once both settle. */
export function ReviseDrawer({ actionId, onClose, onDone }: { actionId: string; onClose: () => void; onDone?: () => void }) {
  const [trace, setTrace] = useState<Row | null>(null); const [loadErr, setLoadErr] = useState("");
  const [payload, setPayload] = useState(""); const [reasoning, setReasoning] = useState(""); const [evidence, setEvidence] = useState("");
  const [busy, setBusy] = useState(false); const [err, setErr] = useState(""); const [res, setRes] = useState<Row | null>(null);
  useEffect(() => {
    api<Row>(`/api/v1/actions/${actionId}/trace`).then((t) => { setTrace(t); setPayload(JSON.stringify(t.action?.payload ?? {}, null, 2)); setReasoning(String(t.action?.reasoning ?? "")); })
      .catch((e) => setLoadErr(e instanceof Error ? e.message : "Could not load the action"));
  }, [actionId]);

  const fixes = [...new Map<string, string>(((trace?.threats ?? []) as Row[]).filter((t) => t.mitigation).map((t) => [String(t.mitigation), String(t.description)])).entries()];
  const critiques = ((trace?.feedback ?? []) as Row[]).flatMap((f) => (f.critiques ?? []) as Row[]);

  async function submit() {
    setErr(""); let parsed: Record<string, unknown>;
    try { parsed = JSON.parse(payload); if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(); } catch { setErr("Payload must be a valid JSON object."); return; }
    setBusy(true);
    try {
      const r = await post<Row>("/api/v1/actions/analyze", { agentId: trace!.action.agentId, actionType: trace!.action.actionType, payload: parsed, reasoning: reasoning.trim() || undefined, authorized: Boolean(evidence.trim()), authorizationEvidence: evidence.trim() || undefined, parentActionId: actionId });
      setRes(r); onDone?.();
    } catch (e) { setErr(e instanceof Error ? e.message : "Submit failed"); }
    setBusy(false);
  }

  return <DetailDrawer title="Revise & resubmit" onClose={onClose}>
    {loadErr && <Toast msg={loadErr} tone="error" />}
    {!trace && !loadErr && <p className="text-sm" style={{ color: "var(--muted)" }}>Loading original action…</p>}
    {trace && !res && <>
      <p className="text-sm mb-3" style={{ color: "var(--text2)" }}>Fix what was flagged and resubmit. The new action is linked to the original, so <b>Improvement Lab</b> can compare Reppo scores once both evaluations settle.</p>
      {(fixes.length > 0 || critiques.length > 0) && <section className="mb-4"><h3 className="font-semibold text-sm mb-1.5">What to fix</h3>
        <ul className="space-y-1.5 text-[13px]" style={{ color: "var(--text2)" }}>
          {fixes.map(([m, d]) => <li key={m}><span style={{ color: "#FB923C" }}>●</span> {d} <span style={{ color: "var(--muted)" }}>→ {m}</span></li>)}
          {critiques.slice(0, 6).map((c, i) => <li key={i}><span style={{ color: "#22D3EE" }}>●</span> <b style={{ color: "var(--text)" }}>{c.criterion ?? "Reppo"}</b>{c.score != null ? ` · ${c.score}` : ""}{c.critique === "" ? "" : ` - ${c.critique ?? JSON.stringify(c).slice(0, 200)}`}</li>)}
        </ul></section>}
      <label className="text-xs font-semibold block mb-1.5" style={{ color: "var(--text2)" }}>Payload (JSON)</label>
      <textarea className="input mono text-xs" style={{ minHeight: 150, height: "auto" }} value={payload} onChange={(e) => setPayload(e.target.value)} spellCheck={false} />
      <p className="text-[11px] mt-1" style={{ color: "var(--muted)" }}>Secrets were redacted when the original was stored; keep them out of the revision.</p>
      <label className="text-xs font-semibold block mt-3 mb-1.5" style={{ color: "var(--text2)" }}>Reasoning</label>
      <textarea className="input text-sm" style={{ minHeight: 90, height: "auto" }} value={reasoning} onChange={(e) => setReasoning(e.target.value)} placeholder="Explain why this action is safe and within policy. Clear reasoning is what Reppo scores." />
      <label className="text-xs font-semibold block mt-3 mb-1.5" style={{ color: "var(--text2)" }}>Signed approval reference</label>
      <input className="input mono text-xs" value={evidence} onChange={(e) => setEvidence(e.target.value)} placeholder="sig:… (required for payments; format-checked only)" />
      {err && <div className="mt-3"><Toast msg={err} tone="error" /></div>}
      <button className="btn w-full mt-4" disabled={busy} onClick={submit}><Send size={15} />{busy ? "Submitting…" : "Resubmit revised action"}</button>
    </>}
    {res && <div className="space-y-3">
      <div className="flex items-center gap-2">{badge(res.decision?.outcome ?? "-")}<span className="text-sm" style={{ color: "var(--text2)" }}>Evaluation: {res.evaluation?.status ?? "n/a"}</span></div>
      <p className="text-sm leading-relaxed" style={{ color: "var(--text2)" }}>{(res.decision?.reasons ?? []).join(" ")}</p>
      <p className="text-xs" style={{ color: "var(--muted)" }}>If the evaluation is pending or queued, check back in Evaluation Center. The comparison appears in Improvement Lab after both scores settle.</p>
      <Link to="/app/improvement" className="btn btn-ghost w-full" onClick={onClose}><FlaskConical size={15} />Open Improvement Lab</Link>
    </div>}
  </DetailDrawer>;
}