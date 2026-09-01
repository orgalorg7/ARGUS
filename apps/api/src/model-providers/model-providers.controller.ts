import { Body, Controller, Get, Param, Post, UseGuards } from "@nestjs/common";
import { WorkspaceRole } from "@aasp/database";
import { Equals, IsOptional, IsString, IsUrl, Length, MinLength } from "class-validator";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { WorkspaceRoles } from "../rbac/roles.decorator.js";
import { WorkspaceRbacGuard } from "../rbac/workspace-rbac.guard.js";
import { ModelProvidersService } from "./model-providers.service.js";

class ConfigureModelProviderDto {
  @IsString()
  @Length(2, 120)
  name!: string;

  @IsUrl({ require_protocol: true, protocols: ["http", "https"] })
  baseUrl!: string;

  @IsString()
  @Equals("Qwen/Qwen3.8-27B")
  modelName!: string;

  @IsOptional()
  @IsString()
  @MinLength(16)
  apiKey?: string;
}

@Controller("workspaces/:workspaceId/model-providers")
@UseGuards(JwtAuthGuard, WorkspaceRbacGuard)
export class ModelProvidersController {
  constructor(private readonly providers: ModelProvidersService) {}

  @Get()
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  list(@Param("workspaceId") workspaceId: string) {
    return this.providers.list(workspaceId);
  }

  @Post()
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN)
  configure(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() actor: AuthenticatedUser,
    @Body() input: ConfigureModelProviderDto,
  ) {
    return this.providers.configure(workspaceId, actor, input);
  }

  @Post(":providerId/health")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN)
  health(
    @Param("workspaceId") workspaceId: string,
    @Param("providerId") providerId: string,
    @CurrentUser() actor: AuthenticatedUser,
  ) {
    return this.providers.health(workspaceId, providerId, actor);
  }
}
