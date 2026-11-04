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
import { EngagementService } from "@aasp/engagement-engine";
import type { Response } from "express";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import { CurrentUser } from "../auth/current-user.decorator.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";

@Controller("workspaces/:workspaceId/clients")
@UseGuards(JwtAuthGuard)
export class ClientsController {
  constructor(private readonly engagements: EngagementService) {}
  @Get()
  list(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Query("after") after?: string,
  ) {
    return this.engagements.listClients({ workspaceId, userId: user.id }, after);
  }
  @Post()
  create(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: unknown,
  ) {
    return this.engagements.createClient({ workspaceId, userId: user.id }, body);
  }
}

@Controller("workspaces/:workspaceId/engagements")
@UseGuards(JwtAuthGuard)
export class EngagementsController {
  constructor(private readonly engagements: EngagementService) {}
  @Get()
  list(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Query("after") after?: string,
  ) {
    return this.engagements.list({ workspaceId, userId: user.id }, after);
  }
  @Post()
  create(
    @Param("workspaceId") workspaceId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: unknown,
  ) {
    return this.engagements.create({ workspaceId, userId: user.id }, body);
  }
  @Get(":id")
  get(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    return this.engagements.get({ workspaceId, userId: user.id }, id);
  }
  @Post(":id/policies")
  policy(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: unknown,
  ) {
    return this.engagements.configurePolicy({ workspaceId, userId: user.id }, id, body);
  }
  @Post(":id/transitions")
  transition(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: unknown,
  ) {
    return this.engagements.transition({ workspaceId, userId: user.id }, id, body);
  }
  @Post(":id/documents")
  upload(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: unknown,
  ) {
    return this.engagements.uploadDocument({ workspaceId, userId: user.id }, id, body);
  }
  @Get(":id/documents/:documentId/content")
  async download(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @Param("documentId") documentId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Res({ passthrough: true }) response: Response,
  ) {
    const file = await this.engagements.downloadDocument(
      { workspaceId, userId: user.id },
      id,
      documentId,
    );
    response.setHeader("Content-Type", file.contentType);
    response.setHeader(
      "Content-Disposition",
      `attachment; filename*=UTF-8''${encodeURIComponent(file.filename)}`,
    );
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("X-Content-Type-Options", "nosniff");
    return new StreamableFile(file.content);
  }
  @Post(":id/authorizations")
  authorize(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: unknown,
  ) {
    return this.engagements.authorize({ workspaceId, userId: user.id }, id, body);
  }
  @Post(":id/authorizations/:grantId/revocations")
  revoke(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @Param("grantId") grantId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body("reason") reason: unknown,
  ) {
    return this.engagements.revoke({ workspaceId, userId: user.id }, id, grantId, reason);
  }
  @Get(":id/decisions")
  decisions(
    @Param("workspaceId") workspaceId: string,
    @Param("id") id: string,
    @CurrentUser() user: AuthenticatedUser,
    @Query("after") after?: string,
  ) {
    return this.engagements.decisions({ workspaceId, userId: user.id }, id, after);
  }
}
