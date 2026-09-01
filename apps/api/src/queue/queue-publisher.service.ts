import { Injectable, type OnModuleDestroy } from "@nestjs/common";
import { Queue } from "bullmq";
import { Redis } from "ioredis";
import { loadEnvironment } from "../config/environment.js";

export const orchestrationQueueName = "scan.orchestration";

@Injectable()
export class QueuePublisherService implements OnModuleDestroy {
  private readonly connection: Redis;
  private readonly queue: Queue;

  constructor() {
    this.connection = new Redis(loadEnvironment().redisUrl, {
      maxRetriesPerRequest: null,
      enableReadyCheck: true,
      lazyConnect: true,
    });
    this.connection.on("error", () => undefined);
    this.queue = new Queue(orchestrationQueueName, { connection: this.connection });
  }

  async publish(jobId: string, payload: { workspaceId: string; scanId: string }): Promise<boolean> {
    try {
      await this.queue.add("orchestrate", payload, {
        jobId,
        attempts: 5,
        backoff: { type: "exponential", delay: 2_000 },
        removeOnComplete: 1_000,
        removeOnFail: 5_000,
      });
      return true;
    } catch {
      return false;
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.queue.close();
    await this.connection.quit();
  }
}
