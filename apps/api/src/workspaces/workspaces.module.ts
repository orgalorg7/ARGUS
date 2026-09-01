import { Module } from "@nestjs/common";
import { WorkspacesController } from "./workspaces.controller.js";
import { WorkspacesService } from "./workspaces.service.js";

@Module({ controllers: [WorkspacesController], providers: [WorkspacesService] })
export class WorkspacesModule {}
