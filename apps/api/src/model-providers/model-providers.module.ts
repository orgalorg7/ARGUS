import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module.js";
import { DatabaseModule } from "../database/database.module.js";
import { RbacModule } from "../rbac/rbac.module.js";
import { ModelProvidersController } from "./model-providers.controller.js";
import { ModelProvidersService } from "./model-providers.service.js";

@Module({
  imports: [DatabaseModule, AuditModule, RbacModule],
  controllers: [ModelProvidersController],
  providers: [ModelProvidersService],
})
export class ModelProvidersModule {}
