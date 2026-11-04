import { Prisma, type PrismaClient } from "@aasp/database";
import { hasPermission, type Permission } from "@aasp/security-core";

export interface TenantActor {
  workspaceId: string;
  userId: string;
}
export class GovernanceError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message = code,
  ) {
    super(message);
  }
}
export type DatabaseTransaction = Prisma.TransactionClient;

export async function requirePermission(
  db: DatabaseTransaction,
  ctx: TenantActor,
  permission: Permission,
) {
  const member = await db.workspaceMember.findFirst({
    where: {
      workspaceId: ctx.workspaceId,
      userId: ctx.userId,
      user: { isActive: true },
      workspace: { organization: { members: { some: { userId: ctx.userId } } } },
    },
    include: { role: true },
  });
  if (!member || !hasPermission(member.role.name, permission))
    throw new GovernanceError(403, "PERMISSION_DENIED");
  return member.role.name;
}

export function audit(
  db: DatabaseTransaction,
  ctx: TenantActor,
  action: string,
  resourceType: string,
  resourceId: string,
  metadata?: Prisma.InputJsonValue,
) {
  return db.auditEvent.create({
    data: {
      workspaceId: ctx.workspaceId,
      actorId: ctx.userId,
      action,
      resourceType,
      resourceId,
      ...(metadata === undefined ? {} : { metadata }),
    },
  });
}

export async function atomic<T>(
  db: PrismaClient,
  fn: (tx: DatabaseTransaction) => Promise<T>,
): Promise<T> {
  try {
    return await db.$transaction(fn, {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
      timeout: 15000,
    });
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      ["P2034", "P2002"].includes(error.code)
    )
      throw new GovernanceError(
        409,
        "CONCURRENT_CHANGE",
        "The record changed. Reload it before retrying.",
      );
    throw error;
  }
}

export async function lockEngagement(
  db: DatabaseTransaction,
  ctx: TenantActor,
  id: string,
  expectedVersion?: number,
) {
  await db.$queryRaw`SELECT id FROM "Engagement" WHERE id = ${id} AND "workspaceId" = ${ctx.workspaceId} FOR UPDATE`;
  const engagement = await db.engagement.findFirst({ where: { id, workspaceId: ctx.workspaceId } });
  if (!engagement) throw new GovernanceError(404, "ENGAGEMENT_NOT_FOUND");
  if (expectedVersion !== undefined && engagement.version !== expectedVersion)
    throw new GovernanceError(409, "STALE_VERSION");
  return engagement;
}
