import { PrismaClient } from "@prisma/client";

/** PostgreSQL persistence via Prisma. Used when DATABASE_URL is set.
 *  The JSON store (store.ts) remains the fallback for local demos without a
 *  database - see DATABASE.md for the migration path. API contracts are
 *  unchanged; these repositories mirror the Prisma models in
 *  prisma/schema.prisma, all queries are tenant-scoped by ownerId. */
let client: PrismaClient | null = null;
export function prisma(): PrismaClient {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set; Prisma persistence is unavailable.");
  client ??= new PrismaClient();
  return client;
}

let postgresReady = false;
let initPromise: Promise<boolean> | null = null;
/** True only after PostgreSQL has been probed and answered. DATABASE_URL
 *  merely being present (e.g. a placeholder in .env) is not enough. */
export const prismaEnabled = () => postgresReady;

/** One-time connectivity probe, cached for the process lifetime. If
 *  DATABASE_URL is set but the server cannot be reached, the API falls back
 *  to the JSON file store instead of crashing on the first query, and logs
 *  a loud warning. Point DATABASE_URL at a running database (or unset it)
 *  to use PostgreSQL. */
export function initializeDatabase(): Promise<boolean> {
  if (!process.env.DATABASE_URL) { postgresReady = false; return Promise.resolve(false); }
  initPromise ??= (async () => {
    try {
      const c = prisma();
      await Promise.race([
        (async () => { await c.$connect(); await c.$queryRaw`SELECT 1`; })(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("connection timed out after 5000ms")), 5000)),
      ]);
      postgresReady = true;
      console.log("[agentshield] PostgreSQL connected; using database persistence.");
    } catch (e) {
      postgresReady = false;
      console.error(`[agentshield] WARNING: DATABASE_URL is set but PostgreSQL is unreachable (${e instanceof Error ? e.message.split("\n")[0] : String(e)}). Falling back to the JSON file store so the API stays available. Fix DATABASE_URL or start PostgreSQL to use database persistence.`);
      try { await client?.$disconnect(); } catch { /* already disconnected */ }
      client = null;
    }
    return postgresReady;
  })();
  return initPromise;
}

export const repositories = {
  users: {
    byEmail: (email: string) => prisma().user.findUnique({ where: { email } }),
    byId: (id: string) => prisma().user.findUnique({ where: { id } }),
    create: (data: { email: string; passwordHash: string; name?: string }) => prisma().user.create({ data }),
  },
  agents: {
    listForOwner: (ownerId: string) => prisma().agent.findMany({ where: { ownerId }, orderBy: { createdAt: "desc" } }),
    byIdForOwner: (id: string, ownerId: string) => prisma().agent.findFirst({ where: { id, ownerId } }),
    create: (data: { ownerId: string; name: string; description?: string; permissions: string[]; spendingLimitUsd: number; allowedDestinations: string[] }) =>
      prisma().agent.create({ data: { ...data, permissions: data.permissions, allowedDestinations: data.allowedDestinations } }),
  },
  agentKeys: {
    byHash: (keyHash: string) => prisma().agentApiKey.findUnique({ where: { keyHash }, include: { agent: true } }),
    revokeAllForAgent: (agentId: string) => prisma().agentApiKey.updateMany({ where: { agentId, revokedAt: null }, data: { revokedAt: new Date() } }),
  },
  actions: {
    listForOwner: (ownerId: string) => prisma().agentAction.findMany({ where: { agent: { ownerId } }, orderBy: { createdAt: "desc" } }),
    byIdForOwner: (id: string, ownerId: string) => prisma().agentAction.findFirst({ where: { id, agent: { ownerId } } }),
    /** Idempotent create: the unique idempotencyKey makes retries safe. */
    createIdempotent: (data: Parameters<PrismaClient["agentAction"]["create"]>[0]["data"]) =>
      prisma().agentAction.upsert({ where: { idempotencyKey: (data as { idempotencyKey: string }).idempotencyKey }, update: {}, create: data }),
  },
  evaluations: {
    pending: () => prisma().evaluation.findMany({ where: { status: "PENDING" } }),
    byId: (id: string) => prisma().evaluation.findUnique({ where: { id } }),
  },
  decisions: {
    byAction: (actionId: string) => prisma().decision.findUnique({ where: { actionId }, include: { approval: true } }),
  },
  approvals: {
    /** Atomic claim: succeeds only while PENDING (optimistic concurrency). */
    claim: (id: string, status: string, decidedBy: string) =>
      prisma().approvalRequest.updateMany({ where: { id, status: "PENDING" }, data: { status, decidedBy, decidedAt: new Date() } }),
  },
  audit: {
    append: (data: { event: string; userId?: string; agentId?: string; actionId?: string; detail: object }) => prisma().auditLog.create({ data }),
    listForUser: (userId: string) => prisma().auditLog.findMany({ where: { userId }, orderBy: { createdAt: "desc" }, take: 500 }),
  },
};

/** Transaction helper for multi-row writes (e.g. decision + approval). */
export function withTransaction<T>(fn: (tx: PrismaClient) => Promise<T>): Promise<T> {
  return prisma().$transaction((tx) => fn(tx as unknown as PrismaClient));
}
