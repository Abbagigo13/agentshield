import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "./app.js";
import { loadConfig } from "./config.js";
import { decide } from "./decision.js";
import { analyzeAction } from "./security.js";
import { insert } from "./store.js";
import type { ReppoEvaluation } from "@agentshield/shared";

// Phase 5 security regression suite (audit C1-C6 + Phase 1/2 hardening).
const SIG = "sig:" + "a".repeat(24);
const policy = { spendingLimitUsd: 100, allowedDestinations: ["vendor-payroll"], permissions: ["payment.transfer"] };
const settled = (p: Partial<ReppoEvaluation>): ReppoEvaluation => ({ evaluationId: "e1", score: 95, confidence: "high", decision: "accept", route: "auto-ship", critiques: [], evidence: [], status: "SETTLED", settledAt: new Date().toISOString(), ...p });
const servOk = { requestId: "s", threatDetected: false, threats: [], policyViolations: [], riskScore: 5, recommendation: "approve" as const, provider: "serv" as const };
const base = { hardViolations: [] as string[], criticalThreat: false, serv: servOk, servStatus: "ok" as const, reppoStatus: "SETTLED" };

describe("decision hardening", () => {
  it("unknown Reppo confidence -> REVIEW", () => { expect(decide({ ...base, reppo: settled({ confidence: "unknown" }) }).outcome).toBe("REVIEW"); });
  it("Reppo route=review never auto-approves", () => { expect(decide({ ...base, reppo: settled({ route: "review" }) }).outcome).toBe("REVIEW"); });
  it("SERV critical threat blocks despite perfect Reppo", () => {
    const serv = { ...servOk, threatDetected: true, threats: [{ category: "injection", severity: "critical" as const, explanation: "x", evidence: [] }] };
    expect(decide({ ...base, serv, reppo: settled({ score: 100 }) }).outcome).toBe("BLOCK");
  });
  it("SERV threatDetected with approve recommendation -> REVIEW (disagreement)", () => {
    const serv = { ...servOk, threatDetected: true, threats: [{ category: "x", severity: "low" as const, explanation: "x", evidence: [] }] };
    expect(decide({ ...base, serv, reppo: settled({}) }).outcome).toBe("REVIEW");
  });
  it("SERV outage (servStatus=error) -> REVIEW, never approve", () => { expect(decide({ ...base, serv: null, servStatus: "error", reppo: settled({}) }).outcome).toBe("REVIEW"); });
  it("SERV unavailable -> REVIEW, never approve", () => { expect(decide({ ...base, serv: null, servStatus: "unavailable", reppo: settled({}) }).outcome).toBe("REVIEW"); });
  it("stale Reppo evaluation (48h old) -> REVIEW", () => { expect(decide({ ...base, reppo: settled({ settledAt: new Date(Date.now() - 48 * 3600 * 1000).toISOString() }) }).outcome).toBe("REVIEW"); });
  it("unknown evaluation status fails closed -> REVIEW (no crash)", () => { expect(decide({ ...base, reppo: null, reppoStatus: "SOME_FUTURE_STATUS" }).outcome).toBe("REVIEW"); });
  it("QUEUED -> HOLD", () => { expect(decide({ ...base, reppo: null, reppoStatus: "QUEUED" }).outcome).toBe("HOLD"); });
});

describe("detector hardening", () => {
  it("nested transaction amount is inspected", () => {
    const r = analyzeAction({ actionType: "payment.transfer", payload: { transfer: { amount: 500, destination: "vendor-payroll" } }, authorizationEvidence: SIG }, policy);
    expect(r.hardViolations.join(" ")).toMatch(/exceeds/);
  });
  it("lookalike destination vendor-payroll.evil.example is rejected", () => {
    const r = analyzeAction({ actionType: "payment.transfer", payload: { amountUsd: 10, destination: "vendor-payroll.evil.example" }, authorizationEvidence: SIG }, policy);
    expect(r.hardViolations.join(" ")).toMatch(/not exactly/);
  });
  it("exact destination passes", () => {
    const r = analyzeAction({ actionType: "payment.transfer", payload: { amountUsd: 10, destination: "Vendor-Payroll" }, authorizationEvidence: SIG }, policy);
    expect(r.hardViolations).toHaveLength(0);
  });
  it("arbitrary authorization string is rejected", () => {
    const r = analyzeAction({ actionType: "payment.transfer", payload: { amountUsd: 10, destination: "vendor-payroll" }, authorized: true, authorizationEvidence: "yes-trust-me" }, policy);
    expect(r.hardViolations.join(" ")).toMatch(/signed-approval/);
  });
  it("empty permissions deny by default", () => {
    const r = analyzeAction({ actionType: "payment.transfer", payload: { amountUsd: 10, destination: "vendor-payroll" }, authorizationEvidence: SIG }, { ...policy, permissions: [] });
    expect(r.hardViolations.join(" ")).toMatch(/no configured permissions/i);
  });
  it("cumulative spending: prior 80 + 30 over limit 100 is hard", () => {
    const r = analyzeAction({ actionType: "payment.transfer", payload: { amountUsd: 30, destination: "vendor-payroll" }, authorizationEvidence: SIG }, { ...policy, priorSpentUsd: 80 });
    expect(r.hardViolations.join(" ")).toMatch(/Cumulative/);
  });
});

describe("JWT configuration", () => {
  it("production without JWT_SECRET refuses to start", () => { expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/JWT_SECRET/); });
  it("production with weak JWT_SECRET refuses to start", () => { expect(() => loadConfig({ NODE_ENV: "production", JWT_SECRET: "short" })).toThrow(/JWT_SECRET/); });
  it("production with a strong secret loads", () => { expect(loadConfig({ NODE_ENV: "production", JWT_SECRET: "x".repeat(40) }).jwtSecret).toHaveLength(40); });
  it("development without secret generates an ephemeral one (not hard-coded)", () => {
    const a = loadConfig({}), b = loadConfig({});
    expect(a.jwtSecret.length).toBeGreaterThanOrEqual(32); expect(a.jwtSecret).not.toBe(b.jwtSecret);
  });
});

// ---------- HTTP-level regressions ----------
let tokenA = "", tokenB = "", agentA = "", keyA = "", blockDecision = "", reviewDecision = "";
const A = () => ({ Authorization: `Bearer ${tokenA}` });
const B = () => ({ Authorization: `Bearer ${tokenB}` });
async function mkUser(email: string) {
  const r = await request(app).post("/api/v1/auth/register").send({ email, password: "password123" });
  return r.body.data.token as string;
}
beforeAll(async () => {
  const stamp = Date.now();
  tokenA = await mkUser(`a${stamp}@example.com`); tokenB = await mkUser(`b${stamp}@example.com`);
  const a = await request(app).post("/api/v1/agents").set(A()).send({ name: "PayBot", spendingLimitUsd: 100, permissions: ["payment.transfer"], allowedDestinations: ["vendor-payroll"] });
  agentA = a.body.data.id; keyA = a.body.data.apiKey;
  const atk = await request(app).post("/api/v1/actions/analyze").set(A()).send({ agentId: agentA, actionType: "payment.transfer", payload: { amountUsd: 500, destination: "ext" } });
  expect(atk.body.data.decision.outcome).toBe("BLOCK");
  const good = await request(app).post("/api/v1/actions/analyze").set(A()).send({ agentId: agentA, actionType: "payment.transfer", payload: { amountUsd: 40, destination: "vendor-payroll" }, authorizationEvidence: SIG });
  expect(good.body.data.decision.outcome).toBe("REVIEW");
  const decs = await request(app).get("/api/v1/decisions").set(A());
  blockDecision = decs.body.data.find((d: any) => d.outcome === "BLOCK").id;
  reviewDecision = decs.body.data.find((d: any) => d.outcome === "REVIEW").id;
});

describe("approval + tenant + agent-key regressions", () => {
  it("BLOCK decision cannot be approved (409)", async () => {
    const r = await request(app).post(`/api/v1/decisions/${blockDecision}/approve`).set(A()).send({});
    expect(r.status).toBe(409);
    const decs = await request(app).get("/api/v1/decisions").set(A());
    expect(decs.body.data.find((d: any) => d.id === blockDecision).outcome).toBe("BLOCK");
  });
  it("HOLD decision cannot be approved (409)", async () => {
    const hold = insert("decisions", { actionId: "n/a", ownerId: "seed", outcome: "HOLD", reasons: [], threshold: 80, humanRequired: false });
    // owner is seeded as another tenant on purpose: caller must also not see it
    const r = await request(app).post(`/api/v1/decisions/${hold.id}/approve`).set(A()).send({});
    expect([404, 409]).toContain(r.status);
  });
  it("concurrent approvals: exactly one succeeds", async () => {
    const [r1, r2] = await Promise.all([
      request(app).post(`/api/v1/decisions/${reviewDecision}/approve`).set(A()).send({}),
      request(app).post(`/api/v1/decisions/${reviewDecision}/approve`).set(A()).send({}),
    ]);
    expect([r1.status, r2.status].sort()).toEqual([200, 409]);
  });
  it("cross-tenant: user B sees none of A's records", async () => {
    expect((await request(app).get("/api/v1/actions").set(B())).body.data).toHaveLength(0);
    expect((await request(app).get("/api/v1/decisions").set(B())).body.data).toHaveLength(0);
    expect((await request(app).get(`/api/v1/agents/${agentA}`).set(B())).status).toBe(404);
    expect((await request(app).post(`/api/v1/decisions/${blockDecision}/reject`).set(B()).send({})).status).toBe(404);
  });
  it("cross-tenant: user B cannot submit actions for A's agent", async () => {
    const r = await request(app).post("/api/v1/actions/analyze").set(B()).send({ agentId: agentA, actionType: "payment.transfer", payload: { amountUsd: 1, destination: "vendor-payroll" }, authorizationEvidence: SIG });
    expect(r.status).toBe(404);
  });
  it("agent API key authenticates its own agent", async () => {
    const r = await request(app).post("/api/v1/actions/analyze").set({ "x-agent-api-key": keyA }).send({ agentId: agentA, actionType: "payment.transfer", payload: { amountUsd: 500, destination: "ext" } });
    expect(r.status).toBe(201); expect(r.body.data.decision.outcome).toBe("BLOCK");
  });
  it("invalid agent API key is rejected (401)", async () => {
    const r = await request(app).post("/api/v1/actions/analyze").set({ "x-agent-api-key": "as_agent_deadbeef" }).send({ agentId: agentA, actionType: "payment.transfer", payload: {} });
    expect(r.status).toBe(401);
  });
  it("agent key cannot act for a different agent (403)", async () => {
    const other = await request(app).post("/api/v1/agents").set(A()).send({ name: "Other", permissions: ["payment.transfer"] });
    const r = await request(app).post("/api/v1/actions/analyze").set({ "x-agent-api-key": keyA }).send({ agentId: other.body.data.id, actionType: "payment.transfer", payload: {} });
    expect(r.status).toBe(403);
  });
  it("rotation revokes the old key; revoked key is rejected", async () => {
    const rot = await request(app).post(`/api/v1/agents/${agentA}/keys/rotate`).set(A()).send({});
    expect(rot.status).toBe(201);
    const oldUse = await request(app).post("/api/v1/actions/analyze").set({ "x-agent-api-key": keyA }).send({ agentId: agentA, actionType: "payment.transfer", payload: {} });
    expect(oldUse.status).toBe(401);
    const newUse = await request(app).post("/api/v1/actions/analyze").set({ "x-agent-api-key": rot.body.data.apiKey }).send({ agentId: agentA, actionType: "payment.transfer", payload: { amountUsd: 500, destination: "ext" } });
    expect(newUse.status).toBe(201); keyA = rot.body.data.apiKey;
  });
  it("sensitive trace disclosure: stored payload never contains the raw secret", async () => {
    const secret = "sk-" + "z".repeat(24);
    const sub = await request(app).post("/api/v1/actions/analyze").set(A()).send({ agentId: agentA, actionType: "payment.transfer", payload: { amountUsd: 500, destination: "ext", api_key: secret } });
    const trace = await request(app).get(`/api/v1/actions/${sub.body.data.action.id}/trace`).set(A());
    expect(JSON.stringify(trace.body.data)).not.toContain(secret);
  });
});
