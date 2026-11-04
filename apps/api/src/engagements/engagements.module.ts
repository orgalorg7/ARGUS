import { Module } from "@nestjs/common";
import { APP_FILTER } from "@nestjs/core";
import { EngagementService } from "@aasp/engagement-engine";
import { PrismaService } from "../database/prisma.service.js";
import { ClientsController, EngagementsController } from "./engagements.controller.js";
import { GovernanceFilter } from "./governance.filter.js";

@Module({
  controllers: [ClientsController, EngagementsController],
  providers: [
    {
      provide: EngagementService,
      inject: [PrismaService],
      useFactory: (prisma: PrismaService) => new EngagementService(prisma),
    },
    { provide: APP_FILTER, useClass: GovernanceFilter },
  ],
})
export class EngagementsModule {}
