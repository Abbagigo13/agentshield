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

describe("Reppo adapter (mocked HTTP)", () => {
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
  it("401 throws", async () => { mockFetch(async () => resp(401, { error: "bad key" })); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow(/Reppo HTTP 401/); });
  it("402 insufficient credits is coded", async () => { mockFetch(async () => resp(402, {})); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toMatchObject({ code: "PAYMENT_REQUIRED" }); });
  it("409 pending conflict is coded CONFLICT (queued, not failed)", async () => { mockFetch(async () => resp(409, {})); await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toMatchObject({ code: "CONFLICT" }); });
  it("timeout/abort throws on submit and on poll", async () => {
    mockFetch(async () => { throw new DOMException("aborted", "AbortError"); });
    await expect(reppoSubmit({ actionType: "x", payload: {}, context: "" })).rejects.toThrow();
    await expect(reppoGet("ev1")).rejects.toThrow();
  });
  it("polling HTTP 500 throws", async () => { mockFetch(async () => resp(500, {})); await expect(reppoGet("ev1")).rejects.toThrow(/Reppo HTTP 500/); });
});
