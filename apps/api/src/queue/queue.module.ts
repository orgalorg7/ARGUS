import { Global, Module } from "@nestjs/common";
import { QueuePublisherService } from "./queue-publisher.service.js";

@Global()
@Module({ providers: [QueuePublisherService], exports: [QueuePublisherService] })
export class QueueModule {}
