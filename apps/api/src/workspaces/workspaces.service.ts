import { atomic, audit, GovernanceError } from "@aasp/engagement-engine";
import { ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { randomUUID } from "node:crypto";
import { WorkspaceRole } from "@aasp/database";
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
  constructor(private readonly prisma: PrismaService) {}

  async listForUser(userId: string) {
    return this.prisma.workspace.findMany({
      where: { members: { some: { userId } }, organization: { members: { some: { userId } } } },
      include: {
        organization: { select: { id: true, name: true } },
        members: { where: { userId }, include: { role: true } },
      },
      orderBy: { createdAt: "asc" },
    });
  }

  async create(userId: string, name: string, organizationId?: string) {
    const base = slugify(name);
    if (!base) throw new ConflictException("Workspace name must contain letters or numbers.");
    const ownerRole = await this.prisma.role.findUnique({ where: { name: WorkspaceRole.OWNER } });
    if (!ownerRole) throw new NotFoundException("OWNER role is not seeded.");
    const suffix = randomUUID().slice(0, 8);
    return atomic(this.prisma, async (tx) => {
      let organization;
      if (organizationId) {
        const membership = await tx.organizationMember.findUnique({
          where: { organizationId_userId: { organizationId, userId } },
        });
        if (
          !membership ||
          !["OWNER", "ADMIN", "ORG_OWNER", "SECURITY_DIRECTOR"].includes(membership.role)
        )
          throw new GovernanceError(403, "ORGANIZATION_ADMIN_REQUIRED");
        organization = { id: organizationId };
      } else {
        organization = await tx.organization.create({
          data: { name: name.trim(), members: { create: { userId, role: "OWNER" } } },
        });
      }
      const workspace = await tx.workspace.create({
        data: {
          name: name.trim(),
          slug: `${base}-${suffix}`,
          organizationId: organization.id,
          members: { create: { userId, roleId: ownerRole.id } },
        },
      });
      await audit(
        tx,
        { workspaceId: workspace.id, userId },
        "workspace.created",
        "Workspace",
        workspace.id,
        { organizationId: organization.id },
      );
      return workspace;
    });
  }
}
