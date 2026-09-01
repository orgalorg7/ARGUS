import { Body, Controller, Get, Param, Post, Put, UseGuards } from "@nestjs/common";
import { WorkspaceRole } from "@aasp/database";
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  IsUrl,
  Length,
  Max,
  Min,
  ValidateNested,
} from "class-validator";
import { Type } from "class-transformer";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { WorkspaceRoles } from "../rbac/roles.decorator.js";
import { WorkspaceRbacGuard } from "../rbac/workspace-rbac.guard.js";
import { TargetsService } from "./targets.service.js";

class TargetScopeDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(50)
  @IsString({ each: true })
  allowedDomains!: string[];

  @IsBoolean()
  includeSubdomains!: boolean;

  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(32)
  @IsInt({ each: true })
  @Min(1, { each: true })
  @Max(65_535, { each: true })
  allowedPorts!: number[];

  @IsArray()
  @ArrayMaxSize(200)
  @IsString({ each: true })
  excludedPaths!: string[];

  @IsOptional()
  @IsBoolean()
  allowPrivateNetwork?: boolean;
}

class CreateTargetDto {
  @IsString()
  @Length(2, 120)
  name!: string;

  @IsUrl({ require_protocol: true, protocols: ["http", "https"] })
  url!: string;

  @IsOptional()
  @ValidateNested()
  @Type(() => TargetScopeDto)
  scope?: TargetScopeDto;
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
    return this.targets.create(workspaceId, user.id, {
      name: input.name,
      url: input.url,
      ...(input.scope
        ? {
            scope: {
              allowedDomains: input.scope.allowedDomains,
              includeSubdomains: input.scope.includeSubdomains,
              allowedPorts: input.scope.allowedPorts,
              excludedPaths: input.scope.excludedPaths,
              allowPrivateNetwork: input.scope.allowPrivateNetwork ?? false,
            },
          }
        : {}),
    });
  }

  @Put(":targetId/scope")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  configureScope(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: TargetScopeDto,
  ) {
    return this.targets.configureScope(workspaceId, targetId, user.id, {
      ...input,
      allowPrivateNetwork: input.allowPrivateNetwork ?? false,
    });
  }

  @Post(":targetId/disable")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN)
  disable(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    return this.targets.disable(workspaceId, targetId, user.id);
  }
}
