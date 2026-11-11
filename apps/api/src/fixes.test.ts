import request from "supertest";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { app, pollPendingEvaluations } from "./app.js";
import { config } from "./config.js";
import { analyzeAction, deepFinancials, parseAmount } from "./security.js";
import { insert, update, find } from "./store.js";

// Regression tests for the audit fixes: detector bypasses, spend window,
// QUEUED resubmission, terminal Reppo states, agent scoping, abuse limits.
const SIG = "sig:" + "a".repeat(24);
const policy = { spendingLimitUsd: 100, allowedDestinations: ["vendor-payroll"], permissions: ["payment.transfer"] };
const run = (payload: Record<string, unknown>, prior = 0) => analyzeAction({ actionType: "payment.transfer", payload, authorizationEvidence: SIG }, { ...policy, priorSpentUsd: prior });
const hard = (payload: Record<string, unknown>, prior = 0) => run(payload, prior).hardViolations.join(" | ");

describe("detector bypasses are closed", () => {
  it("alternate amount key names are inspected (usd_amount, AmountUSD, amount-usd)", () => {
    for (const k of ["usd_amount", "AmountUSD", "amount-usd", "paymentAmount"]) expect(hard({ [k]: 5000, destination: "vendor-payroll" })).toMatch(/exceeds/);
  });
  it("cents fields are converted (50000 cents = 500 USD)", () => { expect(hard({ amountCents: 50000, destination: "vendor-payroll" })).toMatch(/exceeds/); });
  it("amounts inside arrays are inspected", () => { expect(hard({ amounts: [5, 9999], destination: "vendor-payroll" })).toMatch(/exceeds/); });
  it("unparseable / non-finite strong amounts are a hard violation", () => {
    for (const v of ["1e999", "NaN", "Infinity", "lots", "1e3"]) expect(hard({ amountUsd: v, destination: "vendor-payroll" })).toMatch(/not a valid finite/);
  });
  it("formatted amounts still parse ($1,000.50 / 12 USDC)", () => {
    expect(parseAmount("$1,000.50")).toEqual({ ok: true, n: 1000.5 });
    expect(parseAmount("12 USDC")).toEqual({ ok: true, n: 12 });
    expect(hard({ amountUsd: "$1,000.50", destination: "vendor-payroll" })).toMatch(/exceeds/);
  });
  it("negative amounts are rejected", () => { expect(hard({ amountUsd: -10000, destination: "vendor-payroll" })).toMatch(/Negative amount/); });
  it("alternate destination keys are checked against the allow-list", () => {
    for (const k of ["beneficiary", "recipient_address", "payee", "wallet", "to", "receiver"]) expect(hard({ amountUsd: 10, [k]: "evil-wallet" })).toMatch(/not exactly/);
  });
  it("allow-list + amount but no recognisable destination -> deny by default", () => { expect(hard({ amountUsd: 10, memo: "x" })).toMatch(/no recognisable destination/); });
  it("a clean payment still passes", () => { expect(run({ amountUsd: 10, destination: "vendor-payroll" }).hardViolations).toHaveLength(0); });
  it("non-financial 'value'/'summary' fields do not cause false positives", () => {
    expect(deepFinancials({ value: "hello", summary: "text", weight: 900 }).invalid).toEqual([]);
    expect(analyzeAction({ actionType: "note", payload: { value: "hello", summary: "text" } }, { ...policy, permissions: ["note"] }).hardViolations).toHaveLength(0);
  });
  it("prior spend can never be negative", () => { expect(hard({ amountUsd: 60, destination: "vendor-payroll" }, -10000)).toBe(""); expect(hard({ amountUsd: 60, destination: "vendor-payroll" }, 50)).toMatch(/Cumulative/); });
});

let token = "", agentA = "", keyA = "", agentB = "", keyB = "";
const U = () => ({ Authorization: `Bearer ${token}` });
const good = (agentId: string, amountUsd = 10) => ({ agentId, actionType: "payment.transfer", payload: { amountUsd, destination: "vendor-payroll" }, authorizationEvidence: SIG });
beforeAll(async () => {
  const r = await request(app).post("/api/v1/auth/register").send({ email: `fx${Date.now()}@example.com`, password: "password123" });
  token = r.body.data.token;
  const mk = async (name: string) => (await request(app).post("/api/v1/agents").set(U()).send({ name, spendingLimitUsd: 100, permissions: ["payment.transfer"], allowedDestinations: ["vendor-payroll"] })).body.data;
  const a = await mk("A"), b = await mk("B");
  agentA = a.id; keyA = a.apiKey; agentB = b.id; keyB = b.apiKey;
});

describe("spend window", () => {
  it("compliant demo can be run repeatedly (10 x 10 USDC stays within 100)", async () => {
    const outs: string[] = [];
    for (let i = 0; i < 5; i++) outs.push((await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 10))).body.data.decision.reasons.join(" "));
    expect(outs.some((o) => /Cumulative/.test(o))).toBe(false);
  });
  it("spend older than the window no longer counts", async () => {
    const old = new Date(Date.now() - (config.spendWindowHours + 1) * 3600 * 1000).toISOString();
    const a = insert("agents", { name: "W", ownerId: "owner-w", status: "ACTIVE", spendingLimitUsd: 100, permissions: ["payment.transfer"], allowedDestinations: ["vendor-payroll"] });
    insert("actions", { agentId: a.id, ownerId: "owner-w", actionType: "payment.transfer", payload: { amountUsd: 95, destination: "vendor-payroll" }, status: "DECIDED", createdAt: old });
    const reg = await request(app).post("/api/v1/agents").set(U()).send({ name: "W2", spendingLimitUsd: 100, permissions: ["payment.transfer"], allowedDestinations: ["vendor-payroll"] });
    const mine = reg.body.data.id;
    insert("actions", { agentId: mine, ownerId: "x", actionType: "payment.transfer", payload: { amountUsd: 95, destination: "vendor-payroll" }, status: "DECIDED", createdAt: old });
    const r = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(mine, 40));
    expect(r.body.data.decision.reasons.join(" ")).not.toMatch(/Cumulative/);
    insert("actions", { agentId: mine, ownerId: "x", actionType: "payment.transfer", payload: { amountUsd: 95, destination: "vendor-payroll" }, status: "DECIDED" }); // fresh -> counts
    const r2 = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(mine, 40));
    expect(r2.body.data.decision.outcome).toBe("BLOCK");
    expect(r2.body.data.decision.reasons.join(" ")).toMatch(/Cumulative/);
  });
});

describe("agent credentials are scoped to their own agent", () => {
  it("agent B cannot read agent A's actions, evaluations, traces or decisions", async () => {
    const act = await request(app).post("/api/v1/actions/analyze").set({ "x-agent-api-key": keyA }).send(good(agentA));
    const actionId = act.body.data.action.id, evalId = act.body.data.evaluation.id;
    const H = { "x-agent-api-key": keyB };
    expect((await request(app).get("/api/v1/actions").set(H)).body.data.some((x: any) => x.agentId === agentA)).toBe(false);
    expect((await request(app).get(`/api/v1/actions/${actionId}`).set(H)).status).toBe(404);
    expect((await request(app).get(`/api/v1/actions/${actionId}/trace`).set(H)).status).toBe(404);
    expect((await request(app).get(`/api/v1/evaluations/${evalId}`).set(H)).status).toBe(404);
    expect((await request(app).post(`/api/v1/evaluations/${evalId}/retry`).set(H)).status).toBe(404);
    expect((await request(app).get("/api/v1/evaluations").set(H)).body.data.some((x: any) => x.agentId === agentA)).toBe(false);
    expect((await request(app).get("/api/v1/decisions").set(H)).body.data.some((d: any) => d.actionId === actionId)).toBe(false);
  });
  it("agent A still sees its own records; the owner user sees all", async () => {
    const H = { "x-agent-api-key": keyA };
    expect((await request(app).get("/api/v1/actions").set(H)).body.data.length).toBeGreaterThan(0);
    expect((await request(app).get("/api/v1/decisions").set(H)).body.data.length).toBeGreaterThan(0);
    const all = (await request(app).get("/api/v1/actions").set(U())).body.data;
    expect(new Set(all.map((x: any) => x.agentId)).size).toBeGreaterThanOrEqual(1);
  });
});

describe("Reppo queue + terminal states (mocked Reppo)", () => {
  let mode: "conflict" | "accept" | "failed" = "conflict";
  beforeAll(() => {
    config.reppo.apiKey = "test-reppo-key";
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: { method?: string }) => {
      if (init?.method === "POST") {
        if (mode === "conflict") return { status: 409, text: async () => "{}" };
        return { status: 201, text: async () => JSON.stringify({ id: `ev-${Math.random().toString(36).slice(2)}`, status: "QUEUED" }) };
      }
      return { status: 200, text: async () => JSON.stringify({ id: "x", status: mode === "failed" ? "FAILED" : "PROCESSING", result: mode === "failed" ? { reason: "judging failed" } : null }) };
    }) as never);
  });
  afterAll(() => { vi.unstubAllGlobals(); config.reppo.apiKey = ""; });

  it("409 -> QUEUED/HOLD; retry stays 409 while Reppo is busy; worker resubmits when free", async () => {
    mode = "conflict";
    const sub = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 5));
    expect(sub.body.data.evaluation.status).toBe("QUEUED");
    expect(sub.body.data.decision.outcome).toBe("HOLD");
    const evId = sub.body.data.evaluation.id;
    expect((await request(app).post(`/api/v1/evaluations/${evId}/retry`).set(U())).status).toBe(409);
    await pollPendingEvaluations();
    expect((await find("evaluations", (e) => e.id === evId))!.status).toBe("QUEUED"); // still busy

    mode = "accept";
    await pollPendingEvaluations();
    const after = (await find("evaluations", (e) => e.id === evId))!;
    expect(after.status).toBe("PENDING");
    expect(String(after.externalEvalId)).toMatch(/^ev-/);
  });
  it("manual retry resubmits a queued evaluation once Reppo is free", async () => {
    mode = "conflict";
    // drain anything pending so the account looks idle, then queue a new one
    for (const e of (await request(app).get("/api/v1/evaluations").set(U())).body.data) if (e.status === "PENDING") await update("evaluations", e.id, { status: "SETTLED" });
    const sub = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 5));
    expect(sub.body.data.evaluation.status).toBe("QUEUED");
    mode = "accept";
    const r = await request(app).post(`/api/v1/evaluations/${sub.body.data.evaluation.id}/retry`).set(U());
    expect(r.status).toBe(200);
    expect(r.body.data.evaluation.status).toBe("PENDING");
  });
  it("a FAILED Reppo result leaves HOLD and routes to REVIEW (never approve)", async () => {
    mode = "accept";
    for (const e of (await request(app).get("/api/v1/evaluations").set(U())).body.data) if (e.status === "PENDING" || e.status === "QUEUED") await update("evaluations", e.id, { status: "SETTLED" });
    const sub = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 5));
    expect(sub.body.data.decision.outcome).toBe("HOLD");
    mode = "failed";
    const polled = await request(app).get(`/api/v1/evaluations/${sub.body.data.evaluation.id}`).set(U());
    expect(polled.body.data.evaluation.status).toBe("FAILED");
    expect(polled.body.data.decision.outcome).toBe("REVIEW");
  });
});

describe("abuse limits", () => {
  it("login/register are rate limited (when enabled)", async () => {
    process.env.RATE_LIMIT_TEST = "1"; process.env.AUTH_RATE_LIMIT = "3";
    try {
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) codes.push((await request(app).post("/api/v1/auth/login").send({ email: "nobody@example.com", password: "wrong-password" })).status);
      expect(codes.slice(0, 3).every((c) => c === 401)).toBe(true);
      expect(codes[4]).toBe(429);
    } finally { delete process.env.RATE_LIMIT_TEST; delete process.env.AUTH_RATE_LIMIT; }
  });
  it("per-account daily action cap returns 429", async () => {
    process.env.RATE_LIMIT_TEST = "1"; process.env.DAILY_ACTION_CAP = "1";
    try {
      const r = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 1));
      expect(r.status).toBe(429);
    } finally { delete process.env.RATE_LIMIT_TEST; delete process.env.DAILY_ACTION_CAP; }
  });
  it("sign-up can be closed with ALLOW_SIGNUP=false", async () => {
    process.env.ALLOW_SIGNUP = "false";
    try { expect((await request(app).post("/api/v1/auth/register").send({ email: `c${Date.now()}@example.com`, password: "password123" })).status).toBe(403); }
    finally { delete process.env.ALLOW_SIGNUP; }
  });
});

describe("permission matching is forgiving about separators", () => {
  const act = (permissions: string[]) => analyzeAction({ actionType: "payment.transfer", payload: { amountUsd: 10, destination: "vendor-payroll" }, authorizationEvidence: SIG }, { ...policy, permissions }).hardViolations.join(" ");
  it("'payment transfer', 'Payment_Transfer' and 'payment-transfer' all grant payment.transfer", () => {
    for (const p of ["payment transfer", "Payment_Transfer", "payment-transfer", " PAYMENT.TRANSFER "]) expect(act([p])).toBe("");
  });
  it("an unrelated permission still denies", () => { expect(act(["file.read"])).toMatch(/outside the agent/); });
  it("new agents store normalised permissions", async () => {
    const r = await request(app).post("/api/v1/agents").set(U()).send({ name: "Norm", permissions: ["Payment Transfer", "payment.transfer"] });
    expect(r.body.data.permissions).toEqual(["payment.transfer"]);
  });
});

describe("revise & resubmit (parentActionId)", () => {
  it("links a revision to its own original and rejects a foreign/unknown parent", async () => {
    const orig = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 3));
    const ok = await request(app).post("/api/v1/actions/analyze").set(U()).send({ ...good(agentA, 3), parentActionId: orig.body.data.action.id });
    expect(ok.status).toBe(201);
    expect(ok.body.data.action.parentActionId).toBe(orig.body.data.action.id);
    // another tenant's action cannot be used as a parent
    const other = await request(app).post("/api/v1/auth/register").send({ email: `par${Date.now()}@example.com`, password: "password123" });
    const H2 = { Authorization: `Bearer ${other.body.data.token}` };
    const ag2 = (await request(app).post("/api/v1/agents").set(H2).send({ name: "X", permissions: ["payment.transfer"], allowedDestinations: ["vendor-payroll"] })).body.data;
    const bad = await request(app).post("/api/v1/actions/analyze").set(H2).send({ ...good(ag2.id, 3), parentActionId: orig.body.data.action.id });
    expect(bad.status).toBe(404);
    // same tenant but a different agent's action is also refused
    const cross = await request(app).post("/api/v1/actions/analyze").set(U()).send({ ...good(agentB, 3), parentActionId: orig.body.data.action.id });
    expect(cross.status).toBe(404);
    // the improvement row is created for the legitimate revision
    const imp = await request(app).get("/api/v1/analytics/improvements").set(U());
    expect(imp.body.data.items.some((i: any) => i.revisedActionId === ok.body.data.action.id)).toBe(true);
  });
});

describe("Reppo connection test + daily budget (current API, mocked)", () => {
  afterAll(() => { vi.unstubAllGlobals(); config.reppo.apiKey = ""; config.reppo.dailyBudget = 30; config.reppo.mode = "evals"; });
  it("connection test: 404 on the probe id = key accepted; 401 = key rejected", async () => {
    config.reppo.apiKey = "test-reppo-key"; config.reppo.mode = "evals";
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 404, text: async () => "{}" })) as never);
    const okRes = await request(app).post("/api/v1/integrations/test").set(U()).send({ provider: "reppo" });
    expect(okRes.body.data).toMatchObject({ ok: true, status: "connected" });
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 401, text: async () => "{}" })) as never);
    const bad = await request(app).post("/api/v1/integrations/test").set(U()).send({ provider: "reppo" });
    expect(bad.body.data.ok).toBe(false); expect(bad.body.data.detail).toMatch(/rejected the API key/);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 500, text: async () => "{}" })) as never);
    const down = await request(app).post("/api/v1/integrations/test").set(U()).send({ provider: "reppo" });
    expect(down.body.data.ok).toBe(false); expect(down.body.data.status).toBe("http_500");
  });
  it("daily budget: once reached, actions are not sent to Reppo and route to REVIEW", async () => {
    config.reppo.apiKey = "test-reppo-key";
    let posts = 0;
    vi.stubGlobal("fetch", vi.fn(async (_u: string, init?: { method?: string }) => { if (init?.method === "POST") { posts++; return { status: 201, text: async () => JSON.stringify({ id: `b${posts}`, status: "QUEUED" }) }; } return { status: 200, text: async () => JSON.stringify({ id: "b", status: "PROCESSING", result: null }) }; }) as never);
    const used = (await request(app).get("/api/v1/evaluations").set(U())).body.data.filter((e: any) => e.externalEvalId).length;
    config.reppo.dailyBudget = used + 1; // exactly one more submission allowed
    for (const e of (await request(app).get("/api/v1/evaluations").set(U())).body.data) if (e.status === "PENDING" || e.status === "QUEUED") await update("evaluations", e.id, { status: "SETTLED" });
    const first = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 1));
    expect(first.body.data.evaluation.status).toBe("PENDING");
    const second = await request(app).post("/api/v1/actions/analyze").set(U()).send(good(agentA, 1));
    expect(second.body.data.evaluation.status).toBe("NOT_SUBMITTED");
    expect(second.body.data.evaluation.note).toMatch(/daily budget/);
    expect(second.body.data.decision.outcome).toBe("REVIEW");
    expect(posts).toBe(1);
  });
});
