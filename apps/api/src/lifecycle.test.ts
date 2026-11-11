import request from "supertest";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { app } from "./app.js";
import { config } from "./config.js";

// Phase 2 lifecycle test with MOCKED Reppo HTTP (not a live API test):
// submit -> PENDING/HOLD -> poll settles -> decision is re-evaluated.
const SIG = "sig:" + "a".repeat(24);
let token = "", agentId = "", evalId = "";
const auth = () => ({ Authorization: `Bearer ${token}` });

beforeAll(async () => {
  config.reppo.apiKey = "test-reppo-key";
  vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: { method?: string }) => {
    // current Reppo contract: POST /agents/evals -> {id,status:QUEUED}; GET /agents/evals/{id} -> {status:COMPLETED,result:{...flat}}
    if (init?.method === "POST") return { status: 201, text: async () => JSON.stringify({ id: "ev-life-1", status: "QUEUED" }) };
    return { status: 200, text: async () => JSON.stringify({ id: "ev-life-1", status: "COMPLETED", result: { score: 95, decision: "accept", confidence: "high", route: "auto-ship", reason: "compliant", rubric_scores: { safety: 100, completeness: 90 } } }) };
  }) as never);
  const r = await request(app).post("/api/v1/auth/register").send({ email: `life${Date.now()}@example.com`, password: "password123" });
  token = r.body.data.token;
  const a = await request(app).post("/api/v1/agents").set(auth()).send({ name: "LifeBot", spendingLimitUsd: 100, permissions: ["payment.transfer"], allowedDestinations: ["vendor-payroll"] });
  agentId = a.body.data.id;
});
afterAll(() => { vi.unstubAllGlobals(); config.reppo.apiKey = ""; });

describe("evaluation lifecycle (mocked Reppo)", () => {
  it("submit -> HOLD while pending; poll settles -> decision re-evaluated", async () => {
    const sub = await request(app).post("/api/v1/actions/analyze").set(auth()).send({ agentId, actionType: "payment.transfer", payload: { amountUsd: 40, destination: "vendor-payroll" }, authorizationEvidence: SIG });
    expect(sub.status).toBe(201);
    expect(sub.body.data.evaluation.status).toBe("PENDING");
    expect(sub.body.data.decision.outcome).toBe("HOLD");
    evalId = sub.body.data.evaluation.id;

    const polled = await request(app).get(`/api/v1/evaluations/${evalId}`).set(auth());
    expect(polled.body.data.evaluation.status).toBe("SETTLED");
    expect(polled.body.data.evaluation.score).toBe(95);
    // SERV is unconfigured in tests, so the re-evaluated decision must be
    // REVIEW (SERV unavailable can never approve) - proving re-decision ran.
    expect(polled.body.data.decision.outcome).toBe("REVIEW");

    const audit = await request(app).get("/api/v1/audit-logs").set(auth());
    const events = audit.body.data.map((a: any) => a.event);
    expect(events).toContain("evaluation.settled");
    expect(events).toContain("decision.reevaluated");
  });
});
