import { Body, Controller, Get, Post, UseGuards } from "@nestjs/common";
import { IsString, IsOptional, Length } from "class-validator";
import { CurrentUser } from "../auth/current-user.decorator.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";
import type { AuthenticatedUser } from "../auth/auth.types.js";
import { WorkspacesService } from "./workspaces.service.js";

class CreateWorkspaceDto {
  @IsOptional()
  @IsString()
  organizationId?: string;
  @IsString()
  @Length(2, 120)
  name!: string;
}

@Controller("workspaces")
@UseGuards(JwtAuthGuard)
export class WorkspacesController {
  constructor(private readonly workspaces: WorkspacesService) {}

  @Get()
  list(@CurrentUser() user: AuthenticatedUser) {
    return this.workspaces.listForUser(user.id);
  }

  @Post()
  create(@CurrentUser() user: AuthenticatedUser, @Body() input: CreateWorkspaceDto) {
    return this.workspaces.create(user.id, input.name, input.organizationId);
  }
}
