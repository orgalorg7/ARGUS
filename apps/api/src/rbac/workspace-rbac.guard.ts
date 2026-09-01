import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { WorkspaceRole } from "@aasp/database";
import type { Request } from "express";
import { PrismaService } from "../database/prisma.service.js";
import { WORKSPACE_ROLES_KEY } from "./roles.decorator.js";

@Injectable()
export class WorkspaceRbacGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const workspaceIdParameter = request.params["workspaceId"];
    const workspaceId = Array.isArray(workspaceIdParameter)
      ? workspaceIdParameter[0]
      : workspaceIdParameter;
    const user = request.user;
    if (!workspaceId || !user) throw new ForbiddenException("Workspace context is required.");
    const role = await this.prisma.role.findFirst({
      where: { members: { some: { workspaceId, userId: user.id } } },
    });
    if (!role) throw new ForbiddenException("Workspace access denied.");
    const allowed = this.reflector.getAllAndOverride<WorkspaceRole[]>(WORKSPACE_ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (allowed && !allowed.includes(role.name))
      throw new ForbiddenException("Workspace role is insufficient.");
    return true;
  }
}
