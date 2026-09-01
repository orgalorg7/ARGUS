import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import { JobStatus, PrismaClient, ScanState, StageStatus, WorkerStatus } from "@aasp/database";
import { logger } from "@aasp/logger";
import { ScopeEngine } from "@aasp/scope-engine";
import { assertCurrentTargetAuthorization } from "@aasp/security-core";
import { Queue, Worker } from "bullmq";
import type { Job } from "bullmq";
import { Redis } from "ioredis";
import { startDay2Workers } from "./day2-workers.js";
import { startDay3Workers } from "./day3-workers.js";
import { startDay4Workers } from "./day4-workers.js";
import { startDay5Workers } from "./day5-workers.js";

interface OrchestrationPayload {
  workspaceId: string;
  scanId: string;
}

const redisUrl = process.env["REDIS_URL"];
const databaseUrl = process.env["DATABASE_URL"];
if (!redisUrl || !databaseUrl) throw new Error("REDIS_URL and DATABASE_URL are required.");

const orchestrationQueueName = "scan.orchestration";
const discoveryQueueName = "scan.discovery";
const workerId = `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
const prisma = new PrismaClient({ datasourceUrl: databaseUrl });
const connection = new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true });
const publisherConnection = new Redis(redisUrl, {
  maxRetriesPerRequest: null,
  enableReadyCheck: true,
});
const orchestrationQueue = new Queue<OrchestrationPayload>(orchestrationQueueName, {
  connection: publisherConnection,
});
const discoveryQueue = new Queue<OrchestrationPayload>(discoveryQueueName, {
  connection: publisherConnection,
});

async function registerWorker(): Promise<void> {
  await prisma.worker.upsert({
    where: { id: workerId },
    create: {
      id: workerId,
      name: hostname(),
      queues: [
        orchestrationQueueName,
        "scan.discovery",
        "scan.crawl",
        "scan.api_discovery",
        "scan.fingerprint",
        "scan.http",
        "scan.tls",
        "scan.headers",
        "scan.cookies",
        "scan.cors",
        "scan.normalize",
        "scan.correlate",
        "scan.ai",
        "scan.report",
      ],
      status: WorkerStatus.ONLINE,
      metadata: { pid: process.pid, node: process.version },
    },
    update: { status: WorkerStatus.ONLINE, lastHeartbeat: new Date() },
  });
}

async function heartbeat(): Promise<void> {
  const now = new Date();
  await prisma.$transaction([
    prisma.worker.update({
      where: { id: workerId },
      data: { lastHeartbeat: now, status: WorkerStatus.ONLINE },
    }),
    prisma.workerHeartbeat.create({
      data: {
        workerId,
        timestamp: now,
        status: WorkerStatus.ONLINE,
        metrics: { pid: process.pid },
      },
    }),
  ]);
}

async function processOrchestration(
  job: Job<OrchestrationPayload>,
): Promise<{ discoveryJobId: string }> {
  const { workspaceId, scanId } = job.data;
  const persistedJobId = String(job.id ?? "");
  const context = { workspaceId, scanId, jobId: persistedJobId, workerId };
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, workspaceId },
    include: { target: true, config: true },
  });
  if (!scan || !scan.config)
    throw new Error("Persisted scan/config was not found in its workspace.");
  if (scan.state === ScanState.DISCOVERY) {
    logger.info("Orchestration already completed; returning idempotently.", context);
    return { discoveryJobId: `discover:${scanId}:v1` };
  }
  if (scan.state !== ScanState.QUEUED)
    throw new Error(`Expected QUEUED scan, observed ${scan.state}.`);
  try {
    assertCurrentTargetAuthorization(scan.target);
  } catch {
    throw new Error("Target authorization is not valid at worker execution time.");
  }

  await prisma.$transaction([
    prisma.scan.update({
      where: { id: scanId },
      data: { state: ScanState.VALIDATING_SCOPE, startedAt: scan.startedAt ?? new Date() },
    }),
    prisma.scanStage.update({
      where: { scanId_name: { scanId, name: ScanState.VALIDATING_SCOPE } },
      data: { status: StageStatus.RUNNING, startedAt: new Date() },
    }),
    prisma.scanJob.update({
      where: { id: persistedJobId },
      data: {
        status: JobStatus.RUNNING,
        attempt: { increment: 1 },
        startedAt: new Date(),
        lockedBy: workerId,
      },
    }),
  ]);

  const allowedPorts = [
    scan.target.normalizedPort ?? (scan.target.origin.startsWith("https:") ? 443 : 80),
  ];
  const engine = new ScopeEngine();
  const decision = await engine.assertAllowed(scan.target.origin, {
    targetOrigin: scan.target.origin,
    includeSubdomains: scan.config.includeSubdomains,
    allowPrivateNetwork: scan.target.allowPrivateNetwork,
    allowedPorts,
  });
  const discoveryIdempotencyKey = `discover:${scanId}:v1`;
  const discoveryJob = await prisma.$transaction(async (transaction) => {
    await transaction.scanStage.update({
      where: { scanId_name: { scanId, name: ScanState.VALIDATING_SCOPE } },
      data: {
        status: StageStatus.COMPLETED,
        completedAt: new Date(),
        completedUnits: 1,
        totalUnits: 1,
        metadata: {
          hostname: decision.url.hostname,
          addressFamilies: decision.addresses.map(({ family }) => family),
        },
      },
    });
    await transaction.scan.update({ where: { id: scanId }, data: { state: ScanState.DISCOVERY } });
    return transaction.scanJob.upsert({
      where: { idempotencyKey: discoveryIdempotencyKey },
      create: {
        workspaceId,
        scanId,
        queue: discoveryQueueName,
        idempotencyKey: discoveryIdempotencyKey,
        status: JobStatus.CREATED,
        payload: { workspaceId, scanId },
      },
      update: {},
    });
  });
  await discoveryQueue.add(
    "discover",
    { workspaceId, scanId },
    {
      jobId: discoveryJob.id,
      attempts: 5,
      backoff: { type: "exponential", delay: 2_000 },
    },
  );
  await prisma.$transaction([
    prisma.scanJob.update({
      where: { id: discoveryJob.id },
      data: { status: JobStatus.QUEUED, bullJobId: discoveryJob.id },
    }),
    prisma.scanJob.update({
      where: { id: persistedJobId },
      data: {
        status: JobStatus.SUCCEEDED,
        completedAt: new Date(),
        result: { discoveryJobId: discoveryJob.id },
      },
    }),
  ]);
  logger.info("Authorization and scope validation completed; discovery job queued.", context);
  return { discoveryJobId: discoveryJob.id };
}

async function recoverOutbox(): Promise<void> {
  const jobs = await prisma.scanJob.findMany({
    where: { queue: orchestrationQueueName, status: JobStatus.CREATED },
    take: 100,
    orderBy: { createdAt: "asc" },
  });
  for (const persisted of jobs) {
    const payload = persisted.payload as unknown as OrchestrationPayload;
    await orchestrationQueue.add("orchestrate", payload, {
      jobId: persisted.id,
      attempts: persisted.maxAttempts,
      backoff: { type: "exponential", delay: 2_000 },
    });
    await prisma.scanJob.update({
      where: { id: persisted.id },
      data: { status: JobStatus.QUEUED, bullJobId: persisted.id },
    });
  }
}

await prisma.$connect();
await registerWorker();
await recoverOutbox();
const day2Workers = startDay2Workers({ prisma, redisUrl, workerId });
const day3Workers = startDay3Workers({ prisma, redisUrl, workerId });
const day4Workers = startDay4Workers({ prisma, redisUrl, workerId });
const day5Workers = startDay5Workers({ prisma, redisUrl, workerId });

const worker = new Worker<OrchestrationPayload>(orchestrationQueueName, processOrchestration, {
  connection,
  concurrency: Number(process.env["WORKER_CONCURRENCY"] ?? "2"),
  lockDuration: 60_000,
});

worker.on("failed", (job, error) => {
  if (!job) return;
  const { workspaceId, scanId } = job.data;
  void prisma
    .$transaction([
      prisma.scan.updateMany({
        where: {
          id: scanId,
          workspaceId,
          state: { notIn: [ScanState.COMPLETED, ScanState.CANCELLED] },
        },
        data: { state: ScanState.FAILED, failureReason: error.message.slice(0, 1_000) },
      }),
      prisma.scanJob.updateMany({
        where: { id: String(job.id) },
        data: {
          status: JobStatus.FAILED,
          lastError: error.message.slice(0, 1_000),
          completedAt: new Date(),
        },
      }),
    ])
    .catch((persistenceError: unknown) => {
      logger.error("Failed to persist worker failure.", {
        workspaceId,
        scanId,
        workerId,
        error:
          persistenceError instanceof Error ? persistenceError.message : String(persistenceError),
      });
    });
  logger.error("Orchestration job failed.", {
    workspaceId,
    scanId,
    jobId: String(job.id ?? ""),
    workerId,
    error: error.message,
  });
});

const heartbeatTimer = setInterval(() => {
  void heartbeat().catch((error: unknown) => {
    logger.error("Worker heartbeat failed.", {
      workerId,
      error: error instanceof Error ? error.message : String(error),
    });
  });
}, 15_000);
heartbeatTimer.unref();

const outboxTimer = setInterval(() => {
  void recoverOutbox().catch((error: unknown) => {
    logger.error("Outbox recovery failed.", {
      workerId,
      error: error instanceof Error ? error.message : String(error),
    });
  });
}, 10_000);
outboxTimer.unref();

async function shutdown(signal: string): Promise<void> {
  clearInterval(heartbeatTimer);
  clearInterval(outboxTimer);
  logger.info("Worker is draining.", { workerId, signal });
  await prisma.worker
    .update({ where: { id: workerId }, data: { status: WorkerStatus.DRAINING } })
    .catch(() => undefined);
  await worker.close();
  await Promise.all([
    day2Workers.close(),
    day3Workers.close(),
    day4Workers.close(),
    day5Workers.close(),
  ]);
  await orchestrationQueue.close();
  await discoveryQueue.close();
  await connection.quit();
  await publisherConnection.quit();
  await prisma.worker
    .update({ where: { id: workerId }, data: { status: WorkerStatus.OFFLINE } })
    .catch(() => undefined);
  await prisma.$disconnect();
}

process.once("SIGTERM", () => void shutdown("SIGTERM"));
process.once("SIGINT", () => void shutdown("SIGINT"));
logger.info("Worker started.", { workerId, queues: [orchestrationQueueName] });
