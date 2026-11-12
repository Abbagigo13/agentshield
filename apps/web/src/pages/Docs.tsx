import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { Code, Eyebrow, GITHUB, PublicLayout, Table, usePageTitle } from "../components/Site";

const SECTIONS = [
  ["overview", "Overview"], ["quickstart", "Quick start"], ["concepts", "Agents and policy"], ["outcomes", "Decision outcomes"],
  ["response", "Reading a response"], ["api", "API reference"], ["config", "Configuration"], ["limits", "Security and limits"],
] as const;

const CURL = `curl -X POST $API/api/v1/actions/analyze \\
  -H "x-agent-api-key: <agent-api-key>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "agentId": "<agent-id>",
    "actionType": "payment.transfer",
    "payload": { "amountUsd": 10, "destination": "vendor-payroll" },
    "reasoning": "Scheduled vendor payment within policy.",
    "authorized": true,
    "authorizationEvidence": "sig:<at least 24 characters>"
  }'`;

const RESPONSE = `{
  "data": {
    "action":     { "id": "...", "status": "DECIDED", "actionType": "payment.transfer", ... },
    "decision":   { "outcome": "HOLD", "reasons": ["Reppo evaluation is pending; action is held (never auto-approved)."], "threshold": 80 },
    "evaluation": { "id": "...", "status": "PENDING", "score": null, ... }
  }
}`;

const H = ({ id, children }: { id: string; children: string }) => <h2 id={id} className="text-2xl font-bold mt-14 mb-4 scroll-mt-24">{children}</h2>;
const P = ({ children }: { children: React.ReactNode }) => <p className="text-[15px] leading-relaxed mb-4" style={{ color: "var(--text2)" }}>{children}</p>;
const C = ({ children }: { children: string }) => <code className="mono text-[13px] px-1.5 py-0.5 rounded" style={{ background: "rgba(148,163,184,.12)", color: "var(--text)" }}>{children}</code>;

export default function Docs() {
  usePageTitle("Docs");
  const { hash } = useLocation();
  useEffect(() => { if (hash) setTimeout(() => document.getElementById(hash.slice(1))?.scrollIntoView(), 60); }, [hash]);
  return <PublicLayout>
    <div className="lg:grid lg:grid-cols-[210px_1fr] lg:gap-12 pt-14">
      <aside className="hidden lg:block"><nav className="sticky top-8 text-sm space-y-1">
        <p className="mono text-[11px] uppercase tracking-[.14em] mb-3" style={{ color: "var(--muted)" }}>On this page</p>
        {SECTIONS.map(([id, t]) => <a key={id} href={`#${id}`} className="block py-1.5" style={{ color: "var(--text2)" }}>{t}</a>)}
        <a href={GITHUB} target="_blank" rel="noreferrer" className="block py-1.5 mt-3" style={{ color: "var(--text2)" }}>GitHub repository</a>
      </nav></aside>

      <article className="max-w-3xl min-w-0">
        <Eyebrow>DOCS</Eyebrow>
        <h1 className="text-[38px] md:text-[46px] font-bold mt-4 leading-[1.08] tracking-tight">AgentShield, end to end.</h1>
        <p className="mt-5 text-[17px] leading-relaxed" style={{ color: "var(--text2)" }}>How a decision is made, what every field means, and how to call the gateway from your own agent.</p>
        <details className="lg:hidden card mt-6" style={{ padding: 14 }}><summary className="cursor-pointer text-sm font-semibold">On this page</summary>
          <div className="mt-3 flex flex-col gap-2 text-sm">{SECTIONS.map(([id, t]) => <a key={id} href={`#${id}`} style={{ color: "var(--text2)" }}>{t}</a>)}</div></details>

        <H id="overview">Overview</H>
        <P>AgentShield is a gateway that sits between an autonomous AI agent and the systems it acts on. The agent proposes an action; AgentShield returns a decision. It does not execute the action itself, so your agent or orchestrator must only proceed on <C>APPROVE</C>.</P>
        <P><b style={{ color: "var(--text)" }}>Three systems, strict lanes.</b> Deterministic code enforces policy and decides. OpenServ SERV Reasoning returns a structured security assessment. The Reppo Evaluation API independently scores the action. Neither AI system can override a hard policy violation, and a missing, pending or failed result is never treated as approval.</P>
        <P><b style={{ color: "var(--text)" }}>Not a replacement for spending controls.</b> A wallet cap limits what an agent can pay. AgentShield checks whether a specific proposed action should proceed at all, and keeps the evidence. Use both. See <Link to="/how-it-works" style={{ color: "#34D399" }}>How it works</Link> for the step-by-step flow.</P>

        <H id="quickstart">Quick start</H>
        <ol className="list-decimal pl-5 space-y-2 text-[15px] leading-relaxed mb-5" style={{ color: "var(--text2)" }}>
          <li><Link to="/register" style={{ color: "#34D399" }}>Create an account</Link> and sign in.</li>
          <li>Open <b style={{ color: "var(--text)" }}>Agent Management</b> and register an agent with a spending limit, its permissions (for example <C>payment.transfer</C>) and allowed destinations. The API key is shown once, and only its hash is stored.</li>
          <li>Open <b style={{ color: "var(--text)" }}>Integrations</b> and press Test connection to confirm the SERV and Reppo keys on the server.</li>
          <li>Send an action from your agent:</li>
        </ol>
        <Code>{CURL}</Code>
        <P>You can also authenticate as a signed-in user with <C>Authorization: Bearer &lt;jwt&gt;</C>. Optional fields: <C>parentActionId</C> to link a revision to its original, and <C>idempotencyKey</C> so a retried request returns the original result instead of running twice.</P>
        <P>If the outcome is <C>HOLD</C>, the Reppo evaluation is still running. It usually settles in 30 to 90 seconds, and a background worker re-runs the decision automatically. You can also read <C>GET /api/v1/evaluations/:id</C> or watch Live Monitoring.</P>

        <H id="concepts">Agents and policy</H>
        <Table head={["Setting", "What it does"]} rows={[
          ["Permissions", "Action types the agent may propose. Matching ignores case and treats spaces, dashes and underscores as dots, so \"payment transfer\" matches payment.transfer. Anything else is a hard block."],
          ["Spending limit (USD)", "Per-action ceiling, and the cap on cumulative spend inside a rolling window (24 hours by default, set with SPEND_WINDOW_HOURS). Blocked actions do not count."],
          ["Allowed destinations", "If set, the destination must match one exactly. If an amount is present but no destination field can be found, the action is blocked (deny by default)."],
          ["Authorization evidence", "Money actions need authorized: true plus evidence in the form sig: followed by at least 24 characters. This is format-checked, not cryptographically verified."],
          ["Score threshold", "The Reppo score needed to approve. Default 80 out of 100 (SCORE_THRESHOLD)."],
        ]} />

        <H id="outcomes">Decision outcomes</H>
        <Table head={["Outcome", "Meaning"]} rows={[
          ["APPROVE", "No violations, SERV in agreement, and a fresh settled Reppo verdict: accept, route auto-ship, high or medium confidence, score at or above the threshold. Verdicts older than 24 hours are stale."],
          ["HOLD", "The Reppo evaluation is pending or queued. The decision re-runs on its own."],
          ["REVIEW", "Uncertain: Reppo confidence is low or its evaluators disagree, route is review, SERV or Reppo failed, or the two disagree. A person approves or rejects once."],
          ["REVISE", "Reppo said revise, or the score is under the threshold. Fix it and resubmit with parentActionId."],
          ["BLOCK", "Hard policy violation, critical threat (prompt injection, credential disclosure), SERV block, or Reppo reject. Blocked actions never spend Reppo credits and cannot be approved."],
        ]} />

        <H id="response">Reading a response</H>
        <Code>{RESPONSE}</Code>
        <P><C>decision.reasons</C> always explains the outcome in words. <C>evaluation.status</C> is <C>PENDING</C>, <C>QUEUED</C> (Reppo was busy), <C>SETTLED</C>, <C>FAILED</C> or <C>NOT_SUBMITTED</C> (blocked before submission, no key configured, or the daily budget was reached). Scores, confidence, route and critiques appear only after an evaluation settles. Full detail for any action, including findings, critiques and the audit events, is at <C>GET /api/v1/actions/:id/trace</C>.</P>

        <H id="api">API reference</H>
        <P>Base path <C>/api/v1</C>. Responses are wrapped as <C>{"{ \"data\": ... }"}</C>. Agent keys can only see their own agent's records.</P>
        <Table head={["Method and path", "Auth", "Purpose"]} rows={[
          [<C key="a">POST /auth/register</C>, "none", "Create an account; returns a session token."],
          [<C key="b">POST /auth/login</C>, "none", "Sign in; returns a session token."],
          [<C key="c">POST /agents</C>, "user", "Register an agent. The API key is returned once."],
          [<C key="d">GET /agents, /agents/:id, /agents/:id/keys</C>, "user", "List agents and their key records."],
          [<C key="e">POST /agents/:id/keys/rotate, /keys/:keyId/revoke</C>, "user", "Rotate or revoke an agent key."],
          [<C key="f">POST /actions/analyze</C>, "user or agent key", "Submit a proposed action and get a decision."],
          [<C key="g">GET /actions, /actions/:id, /actions/:id/trace</C>, "user or agent key", "List actions and read one with its full trace."],
          [<C key="h">GET /decisions</C>, "user or agent key", "Decisions and any human approvals."],
          [<C key="i">POST /decisions/:id/approve, /reject</C>, "user", "Human decision on a REVIEW item, allowed once."],
          [<C key="j">GET /evaluations, /evaluations/:id</C>, "user or agent key", "Reppo evaluations; reading a pending one polls Reppo."],
          [<C key="k">POST /evaluations/:id/retry</C>, "user or agent key", "Resubmit a queued evaluation or poll a pending one."],
          [<C key="l">GET /analytics/overview, /threats, /improvements</C>, "user", "Dashboard data."],
          [<C key="m">GET /audit-logs</C>, "user", "Every event for your account."],
          [<C key="n">GET, POST, PATCH, DELETE /policies</C>, "user", "Named policies, recorded and versioned for audit. Not enforced yet."],
          [<C key="o">GET /integrations/status, POST /integrations/test</C>, "user", "Provider status and a live connection check (spends no credits)."],
          [<C key="p">POST /events/ticket, GET /events?token=</C>, "user", "Live updates over server-sent events. The stream accepts only a 60-second ticket."],
          [<C key="q">GET /health</C>, "none", "Service and database status (at the API root, not under /api/v1)."],
        ]} />

        <H id="config">Configuration</H>
        <P>Set these on the API server. Provider keys never reach the browser.</P>
        <Table head={["Variable", "Purpose"]} rows={[
          [<C key="1">SERV_API_KEY, REPPO_API_KEY</C>, "Provider credentials. Without them the dashboard says so and actions go to review."],
          [<C key="2">SCORE_THRESHOLD</C>, "Score needed to approve (default 80)."],
          [<C key="3">SPEND_WINDOW_HOURS</C>, "Rolling window for cumulative spend (default 24)."],
          [<C key="4">REPPO_DAILY_BUDGET</C>, "Maximum evaluations sent to Reppo per 24 hours (default 30). Each costs credits."],
          [<C key="5">ALLOW_SIGNUP, AUTH_RATE_LIMIT, ACTION_RATE_LIMIT, DAILY_ACTION_CAP</C>, "Abuse and credit protection."],
          [<C key="6">JWT_SECRET, DATABASE_URL, TRUST_PROXY</C>, "Required secret, Postgres connection, and proxy hops."],
          [<C key="7">VITE_API_URL</C>, "Frontend setting: the API's public URL."],
        ]} />

        <H id="limits">Security and limits</H>
        <ul className="space-y-2.5 text-[15px] leading-relaxed list-disc pl-5" style={{ color: "var(--text2)" }}>
          <li>Secrets are redacted with pattern matching before storage and before anything is sent to SERV or Reppo. Pattern matching is not perfect, so keep real credentials out of payloads.</li>
          <li>Amount and destination detection works by field name (for example <C>amountUsd</C>, <C>usd_amount</C>, <C>beneficiary</C>, <C>recipient_address</C>). Unrecognized field names are not inspected. For production, validate payloads against a strict schema per action type.</li>
          <li>Authorization evidence is format-checked only. It proves nothing cryptographically.</li>
          <li>Named policies are recorded and versioned. Enforcement today comes from each agent's own limit, permissions and destinations.</li>
          <li>Reppo evaluates one action at a time per account and charges credits per evaluation. A busy account queues the action; a spent budget routes it to a person.</li>
          <li>Agent keys are stored as hashes. A key rotates or revokes from Agent Management.</li>
          <li>The demo uses synthetic data only. Source and tests: <a href={GITHUB} target="_blank" rel="noreferrer" style={{ color: "#34D399" }}>GitHub</a>.</li>
        </ul>
        <div className="flex flex-wrap gap-3 mt-10"><Link to="/register" className="btn">Create an account</Link><Link to="/faq" className="btn btn-ghost">FAQ</Link></div>
      </article>
    </div>
  </PublicLayout>;
}
