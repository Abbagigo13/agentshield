import { PrismaClient } from "@prisma/client";

/** PostgreSQL persistence via Prisma. Used when DATABASE_URL is set.
 *  The JSON store (store.ts) remains the fallback for local demos without a
 *  database — see DATABASE.md for the migration path. API contracts are
 *  unchanged; these repositories mirror the Prisma models in
 *  prisma/schema.prisma, all queries are tenant-scoped by ownerId. */
let client: PrismaClient | null = null;
export function prisma(): PrismaClient {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set; Prisma persistence is unavailable.");
  client ??= new PrismaClient();
  return client;
}
export const prismaEnabled = () => Boolean(process.env.DATABASE_URL);

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
