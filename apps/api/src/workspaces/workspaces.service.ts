import { ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { WorkspaceRole } from "@aasp/database";
import { AuditService } from "../audit/audit.service.js";
import { PrismaService } from "../database/prisma.service.js";

function slugify(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
}

@Injectable()
export class WorkspacesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async listForUser(userId: string) {
    return this.prisma.workspace.findMany({
      where: { members: { some: { userId } } },
      include: { members: { where: { userId }, include: { role: true } } },
      orderBy: { createdAt: "asc" },
    });
  }

  async create(userId: string, name: string) {
    const base = slugify(name);
    if (!base) throw new ConflictException("Workspace name must contain letters or numbers.");
    const ownerRole = await this.prisma.role.findUnique({ where: { name: WorkspaceRole.OWNER } });
    if (!ownerRole) throw new NotFoundException("OWNER role is not seeded.");
    const suffix = randomUUID().slice(0, 8);
    const workspace = await this.prisma.workspace.create({
      data: {
        name: name.trim(),
        slug: `${base}-${suffix}`,
        members: { create: { userId, roleId: ownerRole.id } },
      },
    });
    await this.audit.record({
      workspaceId: workspace.id,
      actorId: userId,
      action: "workspace.created",
      resourceType: "Workspace",
      resourceId: workspace.id,
    });
    return workspace;
  }
}
