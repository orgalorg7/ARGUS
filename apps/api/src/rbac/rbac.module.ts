import { Global, Module } from "@nestjs/common";
import { WorkspaceRbacGuard } from "./workspace-rbac.guard.js";

@Global()
@Module({ providers: [WorkspaceRbacGuard], exports: [WorkspaceRbacGuard] })
export class RbacModule {}
