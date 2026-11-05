import request from "supertest";
import { describe, expect, it } from "vitest";

// Regression: DATABASE_URL points at an unavailable PostgreSQL instance
// (127.0.0.1:1 refuses instantly). Registration must not 500/crash - the API
// must fall back to the JSON store and genuinely persist the account.
process.env.DATABASE_URL = "postgresql://user:pass@127.0.0.1:1/agentshield_unavailable";
process.env.AGENTSHIELD_STORE = `/tmp/agentshield-fallback-test-${Date.now()}.json`;

const { app } = await import("./app.js");
const { initializeDatabase, prismaEnabled } = await import("./repositories.js");

describe("unavailable PostgreSQL falls back to JSON persistence", () => {
  it("detects the unreachable database and disables Prisma mode", async () => {
    await expect(initializeDatabase()).resolves.toBe(false);
    expect(prismaEnabled()).toBe(false);
  });

  it("registers and logs in a real persisted account (no 500, no fake success)", async () => {
    const email = `fallback${Date.now()}@example.com`;
    const reg = await request(app).post("/api/v1/auth/register").send({ email, password: "password123" });
    expect(reg.status).toBe(201);
    expect(reg.body.data.token).toBeTruthy();
    expect(reg.body.data.user.email).toBe(email);

    const login = await request(app).post("/api/v1/auth/login").send({ email, password: "password123" });
    expect(login.status).toBe(200);
    expect(login.body.data.token).toBeTruthy();

    const bad = await request(app).post("/api/v1/auth/login").send({ email, password: "wrong-password" });
    expect(bad.status).toBe(401);

    const me = await request(app).get("/api/v1/auth/me").set("Authorization", `Bearer ${login.body.data.token}`);
    expect(me.status).toBe(200);
    expect(me.body.data.email).toBe(email);
  });
});
