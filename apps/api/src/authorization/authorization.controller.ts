import { Body, Controller, Get, Param, Post, UseGuards } from "@nestjs/common";
import {
  AuthorizationCleanupStrategy,
  AuthorizationMutationRisk,
  IdentityAuthenticationType,
  ResourceProvenance,
  ResourceRelationshipType,
  WorkspaceRole,
} from "@aasp/database";
import { Type } from "class-transformer";
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsBoolean,
  IsEnum,
  IsIn,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  Length,
  Max,
  MaxLength,
  Min,
  ValidateNested,
} from "class-validator";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { WorkspaceRoles } from "../rbac/roles.decorator.js";
import { WorkspaceRbacGuard } from "../rbac/workspace-rbac.guard.js";
import { AuthorizationService } from "./authorization.service.js";

class CreateIdentityDto {
  @IsString()
  @Length(1, 120)
  label!: string;

  @IsString()
  @Length(1, 80)
  role!: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  tenant?: string;

  @IsEnum(IdentityAuthenticationType)
  authenticationType!: IdentityAuthenticationType;

  @IsObject()
  credential!: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;
}

class ResourceRelationshipDto {
  @IsString()
  identityId!: string;

  @IsEnum(ResourceRelationshipType)
  relationship!: ResourceRelationshipType;
}

class CreateResourceDto {
  @IsString()
  @Length(1, 120)
  resourceType!: string;

  @IsString()
  @Length(1, 500)
  externalId!: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  tenant?: string;

  @IsOptional()
  @IsString()
  ownerIdentityId?: string;

  @IsEnum(ResourceProvenance)
  provenance!: ResourceProvenance;

  @IsOptional()
  @IsObject()
  endpointVariables?: Record<string, string>;

  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(50)
  @ValidateNested({ each: true })
  @Type(() => ResourceRelationshipDto)
  relationships?: ResourceRelationshipDto[];
}

class CreateAuthorizationTestCaseDto {
  @IsString()
  @Length(2, 160)
  name!: string;

  @IsString()
  resourceId!: string;

  @IsString()
  @Length(1, 120)
  action!: string;

  @IsString()
  @MaxLength(2_048)
  endpointTemplate!: string;

  @IsIn(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
  method!: "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";

  @IsArray()
  @ArrayMinSize(2)
  @ArrayMaxSize(20)
  @IsString({ each: true })
  identityIds!: string[];

  @IsObject()
  expectedPolicy!: Record<string, "ALLOW" | "DENY" | "UNKNOWN">;

  @IsEnum(AuthorizationMutationRisk)
  mutationRisk!: AuthorizationMutationRisk;

  @IsBoolean()
  mutationExplicitlyAuthorized!: boolean;

  @IsEnum(AuthorizationCleanupStrategy)
  cleanupStrategy!: AuthorizationCleanupStrategy;

  @IsOptional()
  @IsObject()
  requestHeaders?: Record<string, string>;

  @IsOptional()
  @IsString()
  @MaxLength(262_144)
  requestBody?: string;

  @IsOptional()
  @IsString()
  @MaxLength(160)
  contentType?: string;

  @IsBoolean()
  followRedirects!: boolean;

  @IsInt()
  @Min(1)
  @Max(5)
  timingSamples!: number;
}

@Controller("workspaces/:workspaceId/targets/:targetId/authorization")
@UseGuards(JwtAuthGuard, WorkspaceRbacGuard)
export class AuthorizationController {
  constructor(private readonly authorization: AuthorizationService) {}

  @Get("identities")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  identities(@Param("workspaceId") workspaceId: string, @Param("targetId") targetId: string) {
    return this.authorization.listIdentities(workspaceId, targetId);
  }

  @Post("identities")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  createIdentity(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: CreateIdentityDto,
  ) {
    return this.authorization.createIdentity(workspaceId, targetId, user.id, input);
  }

  @Post("identities/:identityId/disable")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN)
  disableIdentity(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @Param("identityId") identityId: string,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    return this.authorization.disableIdentity(workspaceId, targetId, identityId, user.id);
  }

  @Get("resources")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  resources(@Param("workspaceId") workspaceId: string, @Param("targetId") targetId: string) {
    return this.authorization.listResources(workspaceId, targetId);
  }

  @Post("resources")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  createResource(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: CreateResourceDto,
  ) {
    return this.authorization.createResource(workspaceId, targetId, user.id, input);
  }

  @Get("test-cases")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  testCases(@Param("workspaceId") workspaceId: string, @Param("targetId") targetId: string) {
    return this.authorization.listTestCases(workspaceId, targetId);
  }

  @Post("test-cases")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  createTestCase(
    @Param("workspaceId") workspaceId: string,
    @Param("targetId") targetId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: CreateAuthorizationTestCaseDto,
  ) {
    return this.authorization.createTestCase(workspaceId, targetId, user.id, input);
  }
}

@Controller("workspaces/:workspaceId/scans/:scanId/authorization-matrix")
@UseGuards(JwtAuthGuard, WorkspaceRbacGuard)
export class AuthorizationMatrixController {
  constructor(private readonly authorization: AuthorizationService) {}

  @Get()
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  matrix(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.authorization.matrix(workspaceId, scanId);
  }
}
