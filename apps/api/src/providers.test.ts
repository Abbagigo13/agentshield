import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { config } from "./config.js";
import { normalizeReppo, reppoGet, reppoSubmit, servAssess } from "./providers.js";

// HTTP-MOCKED provider tests. These stub global fetch - they are NOT live
// API tests and prove nothing about real SERV/Reppo availability.
const resp = (status: number, body: unknown) => ({ status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
function mockFetch(impl: (url: string, init?: unknown) => Promise<unknown>) { vi.stubGlobal("fetch", vi.fn(impl as never)); }
const servBody = (content: unknown) => ({ id: "chatcmpl-1", choices: [{ message: { content: typeof content === "string" ? content : JSON.stringify(content) } }] });
const validAssessment = { threatDetected: false, threats: [], policyViolations: [], riskScore: 5, recommendation: "approve" };
const settledRaw = (verdict: object) => ({ evalId: "ev1", status: "SETTLED", settledAt: new Date().toISOString(), result: { verdict: { scale: "0-100", ...verdict }, verdicts: [{ criterion: "c", score: 9, critique: "ok" }], action: { route: "auto-ship" }, evidence: { evidenceBasis: "model-judgment", pods: [] } } });

beforeEach(() => { config.serv.apiKey = "test-serv-key"; config.reppo.apiKey = "test-reppo-key"; });
afterEach(() => { vi.unstubAllGlobals(); config.serv.apiKey = ""; config.reppo.apiKey = ""; });

describe("SERV adapter (mocked HTTP)", () => {
  it("successful structured response is validated and normalized", async () => {
    mockFetch(async () => resp(200, servBody(validAssessment)));
    const r = await servAssess({ actionType: "payment.transfer", payload: {}, policySummary: "{}" });
    expect(r.provider).toBe("serv"); expect(r.recommendation).toBe("approve"); expect(r.riskScore).toBe(5);
  });
  it("401 throws", async () => { mockFetch(async () => resp(401, { error: "unauthorized" })); await expect(servAssess({ actionType: "x", payload: {}, policySummary: "{}" })).rejects.toThrow(/SERV HTTP 401/); });
  it("429 rate limit throws", async () => { mockFetch(async () => resp(429, {})); await expect(servAssess({ actionType: "x", payload: {}, policySummary: "{}" })).rejects.toThrow(/SERV HTTP 429/); });
  it("timeout/abort throws", async () => { mockFetch(async () => { throw new DOMException("aborted", "AbortError"); }); await expect(servAssess({ actionType: "x", payload: {}, policySummary: "{}" })).rejects.toThrow(); });
  it("malformed JSON content throws", async () => { mockFetch(async () => resp(200, servBody("not-json{"))); await expect(servAssess({ actionType: "x", payload: {}, policySummary: "{}" })).rejects.toThrow(); });
  it("invalid structured output (missing fields) throws", async () => { mockFetch(async () => resp(200, servBody({ threatDetected: true }))); await expect(servAssess({ actionType: "x", payload: {}, policySummary: "{}" })).rejects.toThrow(); });
  it("no key -> explicit unavailable, no HTTP call", async () => {
    config.serv.apiKey = ""; const f = vi.fn(); vi.stubGlobal("fetch", f);
    const r = await servAssess({ actionType: "x", payload: {}, policySummary: "{}" });
    expect(r.provider).toBe("unavailable"); expect(f).not.toHaveBeenCalled();
  });
});

describe("Reppo adapter - legacy API mode (mocked HTTP)", () => {
  beforeEach(() => { config.reppo.mode = "legacy"; });
  afterEach(() => { config.reppo.mode = "evals"; });
  it("successful submission returns evalId + PENDING", async () => {
    mockFetch(async () => resp(201, { id: "i1", evalId: "ev1", status: "PENDING" }));
    const r = await reppoSubmit({ actionType: "payment.transfer", payload: {}, context: "ctx" });
    expect(r).toMatchObject({ evalId: "ev1", status: "PENDING" });
  });
  it("pending read: score null, status PENDING", async () => {
    mockFetch(async () => resp(200, { evalId: "ev1", status: "PENDING", settledAt: null, result: null }));
    const r = await reppoGet("ev1"); expect(r.status).toBe("PENDING"); expect(r.score).toBeNull();
  });
  it("settled read is normalized", async () => {
    mockFetch(async () => resp(200, settledRaw({ score: 94, decision: "accept", confidence: "high" })));
    const r = await reppoGet("ev1"); expect(r).toMatchObject({ score: 94, decision: "accept", confidence: "high", route: "auto-ship", status: "SETTLED" });
    expect(r.settledAt).toBeTruthy();
  });
  it("rejected verdict is normalized", async () => {
    mockFetch(async () => resp(200, { ...settledRaw({ score: 5, decision: "reject", confidence: "high" }), result: { verdict: { score: 5, decision: "reject", confidence: "high" }, verdicts: [], action: { route: "block" } } }));
    const r = await reppoGet("ev1"); expect(r.decision).toBe("reject"); expect(r.route).toBe("block");
  });
  it("normalizeReppo tolerates missing verdict fields", () => {
    const r = normalizeReppo({ evalId: "e", status: "SETTLED", settledAt: null, result: {} }, "e");
    expect(r.score).toBeNull(); expect(r.confidence).toBe("unknown");
  });
  it("invalid submit response (no evalId) throws", async () => { mockFetch(async () => resp(201, { status: "PENDING" })); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow(); });
  it("401 throws", async () => { mockFetch(async () => resp(401, { error: "bad key" })); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow(/HTTP 401/); });
  it("402 insufficient credits is coded", async () => { mockFetch(async () => resp(402, {})); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toMatchObject({ code: "PAYMENT_REQUIRED" }); });
  it("409 pending conflict is coded CONFLICT (queued, not failed)", async () => { mockFetch(async () => resp(409, {})); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toMatchObject({ code: "CONFLICT" }); });
  it("timeout/abort throws on submit and on poll", async () => {
    mockFetch(async () => { throw new DOMException("aborted", "AbortError"); });
    await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow();
    await expect(reppoGet("ev1")).rejects.toThrow();
  });
  it("polling HTTP 500 throws", async () => { mockFetch(async () => resp(500, {})); await expect(reppoGet("ev1")).rejects.toThrow(/Reppo HTTP 500/); });
});


describe("Reppo adapter - current evals API (mocked HTTP)", () => {
  beforeEach(() => { config.reppo.mode = "evals"; });
  const done = (result: object) => ({ id: "ev9", status: "COMPLETED", result });
  it("POSTs {taskType,input} to /agents/evals; the id is the eval id; QUEUED maps to PENDING", async () => {
    let seen: { url: string; body: any } | null = null;
    mockFetch(async (url, init) => { seen = { url, body: JSON.parse((init as { body: string }).body) }; return resp(201, { id: "ev9", status: "QUEUED" }); });
    const r = await reppoSubmit({ actionType: "payment.transfer", payload: { amountUsd: 10, destination: "vendor-payroll" }, reasoning: "scheduled payment", context: "Policy: limit 100" });
    expect(r).toMatchObject({ evalId: "ev9", status: "PENDING" });
    expect(seen!.url).toMatch(/\/agents\/evals$/);
    expect(seen!.body.taskType).toBe("response");
    expect(seen!.body.input).toMatch(/Proposed action type: payment\.transfer/);
    expect(seen!.body.input).toMatch(/Policy: limit 100/);
    expect(seen!.body.input).toMatch(/scheduled payment/);
    expect(seen!.body.criteria).toBeUndefined();
  });
  it("secrets are redacted from what Reppo sees", async () => {
    let body = ""; mockFetch(async (_u, init) => { body = (init as { body: string }).body; return resp(201, { id: "e", status: "QUEUED" }); });
    await reppoSubmit({ actionType: "x", payload: { note: "key sk-abcdefghijklmnopqrstuvwxyz123456", password: "hunter2hunter2" }, context: "" });
    expect(body).not.toMatch(/hunter2|sk-abcdefghijklmnop/);
  });
  it("PROCESSING reads as PENDING with no score", async () => {
    mockFetch(async () => resp(200, { id: "ev9", status: "PROCESSING", result: null }));
    const r = await reppoGet("ev9"); expect(r.status).toBe("PENDING"); expect(r.score).toBeNull();
  });
  it("COMPLETED flat result is normalized (score, decision, confidence, route, rubric critiques)", async () => {
    mockFetch(async () => resp(200, done({ score: 94, decision: "Accept", confidence: "High", route: "auto-ship", reason: "Looks compliant.", rubric_scores: { safety: 100, factual_accuracy: 88 } })));
    const r = await reppoGet("ev9");
    expect(r).toMatchObject({ status: "SETTLED", score: 94, decision: "accept", confidence: "high", route: "auto-ship" });
    expect(r.settledAt).toBeTruthy();
    expect(r.critiques).toEqual(expect.arrayContaining([expect.objectContaining({ criterion: "Overall", critique: "Looks compliant." }), expect.objectContaining({ criterion: "factual accuracy", score: 88 })]));
  });
  it("a missing route stays empty (decision logic then fails closed to review)", async () => {
    mockFetch(async () => resp(200, done({ score: 90, decision: "accept", confidence: "high" })));
    expect((await reppoGet("ev9")).route).toBe("");
  });
  it("FAILED carries the reason and no score", async () => {
    mockFetch(async () => resp(200, { id: "ev9", status: "FAILED", result: { reason: "no evaluators" } }));
    const r = await reppoGet("ev9"); expect(r.status).toBe("FAILED"); expect(r.score).toBeNull(); expect(JSON.stringify(r.critiques)).toMatch(/no evaluators/);
  });
  it("scores are clamped to 0-100 and non-numeric scores become null", async () => {
    mockFetch(async () => resp(200, done({ score: 250, decision: "accept", confidence: "high", route: "auto-ship" })));
    expect((await reppoGet("ev9")).score).toBe(100);
    mockFetch(async () => resp(200, done({ score: "high", decision: "accept", confidence: "high", route: "auto-ship" })));
    expect((await reppoGet("ev9")).score).toBeNull();
  });
  it("unknown status throws instead of guessing", async () => { mockFetch(async () => resp(200, { id: "e", status: "WEIRD", result: null })); await expect(reppoGet("e")).rejects.toThrow(/Unknown Reppo status/); });
  it("401 is coded UNAUTHORIZED; 402 PAYMENT_REQUIRED; 409 CONFLICT; 404 is a plain error", async () => {
    for (const [code, expected] of [[401, "UNAUTHORIZED"], [402, "PAYMENT_REQUIRED"], [409, "CONFLICT"]] as const) {
      mockFetch(async () => resp(code, {})); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toMatchObject({ code: expected });
    }
    mockFetch(async () => resp(404, "not found")); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow(/Reppo HTTP 404/);
  });
  it("a submit response with no id throws", async () => { mockFetch(async () => resp(201, { status: "QUEUED" })); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow(); });
});
