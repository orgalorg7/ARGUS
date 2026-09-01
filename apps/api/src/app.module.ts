import { Module } from "@nestjs/common";
import { APP_PIPE } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { AuditModule } from "./audit/audit.module.js";
import { AuthModule } from "./auth/auth.module.js";
import { DatabaseModule } from "./database/database.module.js";
import { HealthController } from "./health/health.controller.js";
import { QueueModule } from "./queue/queue.module.js";
import { ModelProvidersModule } from "./model-providers/model-providers.module.js";
import { RbacModule } from "./rbac/rbac.module.js";
import { ScansModule } from "./scans/scans.module.js";
import { TargetsModule } from "./targets/targets.module.js";
import { WorkspacesModule } from "./workspaces/workspaces.module.js";

@Module({
  imports: [
    DatabaseModule,
    AuditModule,
    AuthModule,
    RbacModule,
    QueueModule,
    ModelProvidersModule,
    WorkspacesModule,
    TargetsModule,
    ScansModule,
  ],
  controllers: [HealthController],
  providers: [
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    },
  ],
})
export class AppModule {}
