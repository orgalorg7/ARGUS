import { Injectable } from "@nestjs/common";
import type { Prisma } from "@aasp/database";
import { PrismaService } from "../database/prisma.service.js";

export interface AuditInput {
  workspaceId?: string;
  actorId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  requestId?: string;
  metadata?: Prisma.InputJsonValue;
}

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async record(input: AuditInput): Promise<void> {
    await this.prisma.auditEvent.create({
      data: {
        action: input.action,
        resourceType: input.resourceType,
        ...(input.workspaceId ? { workspaceId: input.workspaceId } : {}),
        ...(input.actorId ? { actorId: input.actorId } : {}),
        ...(input.resourceId ? { resourceId: input.resourceId } : {}),
        ...(input.requestId ? { requestId: input.requestId } : {}),
        ...(input.metadata !== undefined ? { metadata: input.metadata } : {}),
      },
    });
  }

  list(workspaceId: string) {
    return this.prisma.auditEvent.findMany({
      where: { workspaceId },
      include: { actor: { select: { id: true, email: true, displayName: true } } },
      orderBy: { createdAt: "desc" },
      take: 250,
    });
  }
}
