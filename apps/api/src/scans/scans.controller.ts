import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Res,
  StreamableFile,
  UseGuards,
} from "@nestjs/common";
import { ScanProfile, WorkspaceRole } from "@aasp/database";
import { IsEnum, IsObject, IsOptional, IsString, Length } from "class-validator";
import type { ScanConfigInput } from "@aasp/schemas";
import type { Response } from "express";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { WorkspaceRoles } from "../rbac/roles.decorator.js";
import { WorkspaceRbacGuard } from "../rbac/workspace-rbac.guard.js";
import { ScansService } from "./scans.service.js";

class CreateScanDto {
  @IsString()
  targetId!: string;

  @IsString()
  @Length(2, 160)
  name!: string;

  @IsEnum(ScanProfile)
  profile!: ScanProfile;

  @IsOptional()
  @IsObject()
  config?: Partial<ScanConfigInput>;
}

@Controller("workspaces/:workspaceId/scans")
@UseGuards(JwtAuthGuard, WorkspaceRbacGuard)
export class ScansController {
  constructor(private readonly scans: ScansService) {}

  @Get()
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  list(@Param("workspaceId") workspaceId: string) {
    return this.scans.list(workspaceId);
  }

  @Get(":scanId")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  get(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.get(workspaceId, scanId);
  }

  @Get(":scanId/assets")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  assets(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.assets(workspaceId, scanId);
  }

  @Get(":scanId/urls")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  urls(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.urls(workspaceId, scanId);
  }

  @Get(":scanId/endpoints")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  endpoints(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.endpoints(workspaceId, scanId);
  }

  @Get(":scanId/technologies")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  technologies(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.technologies(workspaceId, scanId);
  }

  @Get(":scanId/evidence")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  evidence(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.evidence(workspaceId, scanId);
  }

  @Get(":scanId/findings")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  findings(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.findings(workspaceId, scanId);
  }

  @Get(":scanId/findings/:findingId")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  finding(
    @Param("workspaceId") workspaceId: string,
    @Param("scanId") scanId: string,
    @Param("findingId") findingId: string,
  ) {
    return this.scans.finding(workspaceId, scanId, findingId);
  }

  @Get(":scanId/reports")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  reports(@Param("workspaceId") workspaceId: string, @Param("scanId") scanId: string) {
    return this.scans.reports(workspaceId, scanId);
  }

  @Get(":scanId/reports/:reportId/content")
  @WorkspaceRoles(
    WorkspaceRole.OWNER,
    WorkspaceRole.ADMIN,
    WorkspaceRole.ANALYST,
    WorkspaceRole.VIEWER,
  )
  async reportContent(
    @Param("workspaceId") workspaceId: string,
    @Param("scanId") scanId: string,
    @Param("reportId") reportId: string,
    @Query("format") format: "html" | "json" | "pdf-ready" | undefined,
    @Res({ passthrough: true }) response: Response,
  ) {
    const file = await this.scans.reportFile(workspaceId, scanId, reportId, format);
    response.setHeader("Content-Type", file.contentType);
    response.setHeader("Content-Disposition", `inline; filename="${file.filename}"`);
    response.setHeader("X-Content-Type-Options", "nosniff");
    return new StreamableFile(file.stream);
  }

  @Post()
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  create(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: CreateScanDto,
  ) {
    return this.scans.create(workspaceId, user.id, input);
  }

  @Post(":scanId/start")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  start(
    @Param("workspaceId") workspaceId: string,
    @Param("scanId") scanId: string,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    return this.scans.start(workspaceId, scanId, user.id);
  }

  @Post(":scanId/cancel")
  @WorkspaceRoles(WorkspaceRole.OWNER, WorkspaceRole.ADMIN, WorkspaceRole.ANALYST)
  cancel(
    @Param("workspaceId") workspaceId: string,
    @Param("scanId") scanId: string,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    return this.scans.cancel(workspaceId, scanId, user.id);
  }
}
