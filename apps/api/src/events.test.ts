import { get } from "node:http";
import type { Server } from "node:http";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "./app.js";

let server: Server;
let base = "";
let token = "";

beforeAll(async () => {
  await new Promise<void>((r) => { server = app.listen(0, () => r()); });
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const reg = await request(app).post("/api/v1/auth/register").send({ email: `sse${Date.now()}@example.com`, password: "password123" });
  token = reg.body.data.token;
});
afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });

describe("live events (SSE)", () => {
  it("rejects requests without a valid token", async () => {
    const r = await request(app).get("/api/v1/events");
    expect(r.status).toBe(401);
  });
  it("streams a connected event to an authenticated user", async () => {
    const text = await new Promise<string>((resolve, reject) => {
      const req = get(`${base}/api/v1/events?token=${encodeURIComponent(token)}`, (res) => {
        expect(res.headers["content-type"]).toContain("text/event-stream");
        res.once("data", (chunk) => { req.destroy(); resolve(String(chunk)); });
      });
      req.on("error", reject);
      setTimeout(() => reject(new Error("no SSE chunk within 4s")), 4000);
    });
    expect(text).toContain('"type":"connected"');
  });
});
