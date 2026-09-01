import { Body, Controller, Get, Param, Post, UseGuards } from "@nestjs/common";
import { VerificationMethod, WorkspaceRole } from "@aasp/database";
import { IsEnum, IsOptional, IsString, IsUrl, Length } from "class-validator";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { WorkspaceRoles } from "../rbac/roles.decorator.js";
import { WorkspaceRbacGuard } from "../rbac/workspace-rbac.guard.js";
import { TargetsService } from "./targets.service.js";

class CreateTargetDto {
  @IsString()
  @Length(2, 120)
  name!: string;

  @IsUrl({ require_protocol: true, protocols: ["http", "https"] })
  url!: string;

  @IsEnum(VerificationMethod)
  method!: VerificationMethod;
}

class VerifyTargetDto {
  @IsOptional()
  @IsString()
  token?: string;
}

@Controller("workspaces/:workspaceId/targets")
@UseGuards(JwtAuthGuard, WorkspaceRbacGuard)
export class TargetsController {
  constructor(private readonly targets: TargetsService) {}

  @Get()
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  list(@Param("workspaceId") workspaceId: string) {
    return this.targets.list(workspaceId);
  }

  @Post()
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  create(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: CreateTargetDto,
  ) {
    return this.targets.create(workspaceId, user.id, input);
  }

  @Post(":targetId/verify")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  verify(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: VerifyTargetDto,
  ) {
    return this.targets.verify(workspaceId, targetId, user, input.token);
  }
}
