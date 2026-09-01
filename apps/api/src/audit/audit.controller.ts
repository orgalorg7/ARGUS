import { Controller, Get, Param, UseGuards } from "@nestjs/common";
import { WorkspaceRole } from "@aasp/database";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { WorkspaceRoles } from "../rbac/roles.decorator.js";
import { WorkspaceRbacGuard } from "../rbac/workspace-rbac.guard.js";
import { AuditService } from "./audit.service.js";

@Controller("workspaces/:workspaceId/audit")
@UseGuards(JwtAuthGuard, WorkspaceRbacGuard)
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  @Get()
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  list(@Param("workspaceId") workspaceId: string) {
    return this.audit.list(workspaceId);
  }
}
