import type { Prisma, PrismaClient, ScanState as ScanStateType } from "@aasp/database";
import { JobStatus, ScanState, StageStatus } from "@aasp/database";
import { EvidenceEngine } from "@aasp/evidence-engine";
import { logger } from "@aasp/logger";
import { AuthenticationSurfaceScanner } from "@aasp/scanner-auth-surface";
import { CookieSecurityScanner } from "@aasp/scanner-cookies";
import { analyzeCors } from "@aasp/scanner-cors";
import { HeaderSecurityScanner } from "@aasp/scanner-headers";
import { HttpSecurityScanner } from "@aasp/scanner-http";
import { runPassiveAdapters, type HttpExchange } from "@aasp/scanner-integrations";
import { MisconfigurationScanner } from "@aasp/scanner-misconfiguration";
import { analyzeTls } from "@aasp/scanner-tls";
import { ScopeEngine, ScopedHttpClient } from "@aasp/scope-engine";
import type { ScannerObservationInput } from "@aasp/schemas";
import { assertCurrentTargetAuthorization } from "@aasp/security-core";
import { Queue, Worker, type Job } from "bullmq";
import { Redis } from "ioredis";

interface StagePayload {
  workspaceId: string;
  scanId: string;
}

interface WorkerContext {
  prisma: PrismaClient;
  redisUrl: string;
  workerId: string;
}

export interface Day3WorkerRuntime {
  close(): Promise<void>;
}

const queues = {
  http: "scan.http",
  tls: "scan.tls",
  headers: "scan.headers",
  cookies: "scan.cookies",
  cors: "scan.cors",
  normalize: "scan.normalize",
} as const;

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

async function loadScan(prisma: PrismaClient, payload: StagePayload) {
  const scan = await prisma.scan.findFirst({
    where: { id: payload.scanId, workspaceId: payload.workspaceId },
    include: { target: true, config: true },
  });
  if (!scan?.config) throw new Error("Persisted scan configuration was not found.");
  assertCurrentTargetAuthorization(scan.target);
  return { ...scan, config: scan.config };
}

function scopePolicy(scan: Awaited<ReturnType<typeof loadScan>>) {
  return {
    targetOrigin: scan.target.origin,
    includeSubdomains: scan.config.includeSubdomains,
    allowPrivateNetwork: scan.target.allowPrivateNetwork,
    allowedPorts: [
      scan.target.normalizedPort ?? (scan.target.origin.startsWith("https:") ? 443 : 80),
    ],
  };
}

function recordValue(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function headersValue(value: unknown): Record<string, string | string[]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const headers: Record<string, string | string[]> = {};
  for (const [name, item] of Object.entries(value)) {
    if (typeof item === "string") headers[name] = item;
    if (Array.isArray(item))
      headers[name] = item.filter((part): part is string => typeof part === "string");
  }
  return headers;
}

async function loadExchanges(prisma: PrismaClient, payload: StagePayload): Promise<HttpExchange[]> {
  const evidence = await prisma.evidence.findMany({
    where: {
      workspaceId: payload.workspaceId,
      scanId: payload.scanId,
      source: "scope-guarded-crawler",
    },
    orderBy: { timestamp: "asc" },
  });
  const exchanges = new Map<string, HttpExchange>();
  for (const item of evidence) {
    const request = recordValue(item.requestMetadata);
    const response = recordValue(item.responseMetadata);
    const finalUrl = typeof response["finalUrl"] === "string" ? response["finalUrl"] : item.asset;
    const method = typeof request["method"] === "string" ? request["method"] : "GET";
    const statusCode = typeof response["statusCode"] === "number" ? response["statusCode"] : 0;
    exchanges.set(`${method}|${finalUrl}`, {
      requestedUrl:
        typeof request["requestedUrl"] === "string" ? request["requestedUrl"] : item.asset,
      finalUrl,
      method,
      statusCode,
      headers: headersValue(response["headers"]),
      body: item.redactedExcerpt,
      redirects: stringArray(response["redirects"]),
    });
  }
  return [...exchanges.values()];
}

async function loadEndpointExchanges(
  prisma: PrismaClient,
  payload: StagePayload,
): Promise<HttpExchange[]> {
  const endpoints = await prisma.discoveredEndpoint.findMany({
    where: { workspaceId: payload.workspaceId, scanId: payload.scanId },
    orderBy: { createdAt: "asc" },
  });
  return endpoints.map((endpoint) => {
    const url = new URL(endpoint.path, endpoint.asset).toString();
    return {
      requestedUrl: url,
      finalUrl: url,
      method: endpoint.method,
      statusCode: 0,
      headers: {},
      body: `Endpoint observed by discovery source: ${endpoint.source}.`,
      redirects: [],
    };
  });
}

async function persistObservations(
  engine: EvidenceEngine,
  payload: StagePayload,
  observations: readonly ScannerObservationInput[],
): Promise<number> {
  for (const observation of observations) {
    await engine.record(payload.workspaceId, payload.scanId, observation);
  }
  return observations.length;
}

async function startJob(
  prisma: PrismaClient,
  job: Job<StagePayload>,
  workerId: string,
  stage?: ScanStateType,
): Promise<void> {
  const operations: Prisma.PrismaPromise<unknown>[] = [
    prisma.scanJob.update({
      where: { id: String(job.id ?? "") },
      data: {
        status: JobStatus.RUNNING,
        attempt: { increment: 1 },
        startedAt: new Date(),
        lockedBy: workerId,
      },
    }),
  ];
  if (stage) {
    operations.push(
      prisma.scanStage.update({
        where: { scanId_name: { scanId: job.data.scanId, name: stage } },
        data: { status: StageStatus.RUNNING, startedAt: new Date(), errorMessage: null },
      }),
    );
  }
  await prisma.$transaction(operations);
}

async function finishJob(
  prisma: PrismaClient,
  job: Job<StagePayload>,
  result: Record<string, unknown>,
): Promise<void> {
  await prisma.scanJob.update({
    where: { id: String(job.id ?? "") },
    data: { status: JobStatus.SUCCEEDED, completedAt: new Date(), result: jsonValue(result) },
  });
}

async function enqueue(
  prisma: PrismaClient,
  queue: Queue<StagePayload>,
  queueName: string,
  payload: StagePayload,
): Promise<string> {
  const persisted = await prisma.scanJob.upsert({
    where: { idempotencyKey: `${queueName}:${payload.scanId}:v1` },
    create: {
      workspaceId: payload.workspaceId,
      scanId: payload.scanId,
      queue: queueName,
      idempotencyKey: `${queueName}:${payload.scanId}:v1`,
      status: JobStatus.CREATED,
      maxAttempts: 4,
      payload: jsonValue(payload),
    },
    update: { payload: jsonValue(payload) },
  });
  try {
    await queue.add(queueName, payload, {
      jobId: persisted.id,
      attempts: persisted.maxAttempts,
      backoff: { type: "exponential", delay: 2_000 },
      removeOnComplete: 1_000,
      removeOnFail: 5_000,
    });
    await prisma.scanJob.update({
      where: { id: persisted.id },
      data: { status: JobStatus.QUEUED, bullJobId: persisted.id },
    });
  } catch (error: unknown) {
    logger.warn("Day 3 queue publication deferred to persisted outbox recovery.", {
      queueName,
      scanId: payload.scanId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
  return persisted.id;
}

async function isCancelled(prisma: PrismaClient, scanId: string): Promise<boolean> {
  return Boolean(
    (await prisma.scan.findUnique({ where: { id: scanId }, select: { cancelRequestedAt: true } }))
      ?.cancelRequestedAt,
  );
}

async function cancel(
  prisma: PrismaClient,
  job: Job<StagePayload>,
  stage: ScanStateType,
): Promise<void> {
  await prisma.$transaction([
    prisma.scan.update({
      where: { id: job.data.scanId },
      data: { state: ScanState.CANCELLED, completedAt: new Date() },
    }),
    prisma.scanStage.update({
      where: { scanId_name: { scanId: job.data.scanId, name: stage } },
      data: { status: StageStatus.CANCELLED, completedAt: new Date() },
    }),
    prisma.scanJob.update({
      where: { id: String(job.id ?? "") },
      data: { status: JobStatus.CANCELLED, completedAt: new Date() },
    }),
  ]);
}

function attachFailure(
  worker: Worker<StagePayload>,
  prisma: PrismaClient,
  stage: ScanStateType,
): void {
  worker.on("failed", (job, error) => {
    if (!job || job.attemptsMade < (job.opts.attempts ?? 1)) return;
    void prisma
      .$transaction([
        prisma.scan.updateMany({
          where: {
            id: job.data.scanId,
            workspaceId: job.data.workspaceId,
            state: { notIn: [ScanState.COMPLETED, ScanState.CANCELLED] },
          },
          data: { state: ScanState.FAILED, failureReason: error.message.slice(0, 1_000) },
        }),
        prisma.scanStage.updateMany({
          where: { scanId: job.data.scanId, workspaceId: job.data.workspaceId, name: stage },
          data: {
            status: StageStatus.FAILED,
            completedAt: new Date(),
            errorMessage: error.message.slice(0, 1_000),
          },
        }),
        prisma.scanJob.updateMany({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.FAILED,
            completedAt: new Date(),
            lastError: error.message.slice(0, 1_000),
          },
        }),
      ])
      .catch((persistenceError: unknown) =>
        logger.error("Failed to persist Day 3 worker failure.", {
          scanId: job.data.scanId,
          error:
            persistenceError instanceof Error ? persistenceError.message : String(persistenceError),
        }),
      );
  });
}

export function startDay3Workers(context: WorkerContext): Day3WorkerRuntime {
  const { prisma, redisUrl, workerId } = context;
  const publisher = new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true });
  const queueMap = Object.fromEntries(
    Object.entries(queues).map(([key, name]) => [
      key,
      new Queue<StagePayload>(name, { connection: publisher }),
    ]),
  ) as Record<keyof typeof queues, Queue<StagePayload>>;
  const connections = Array.from(
    { length: 5 },
    () => new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true }),
  );
  const evidenceEngine = new EvidenceEngine(prisma);

  const httpWorker = new Worker<StagePayload>(
    queues.http,
    async (job) => {
      const scan = await loadScan(prisma, job.data);
      if (scan.state !== ScanState.PASSIVE_ANALYSIS)
        throw new Error(`HTTP analysis expected PASSIVE_ANALYSIS, observed ${scan.state}.`);
      await startJob(prisma, job, workerId, ScanState.PASSIVE_ANALYSIS);
      const exchanges = await loadExchanges(prisma, job.data);
      const endpointExchanges = await loadEndpointExchanges(prisma, job.data);
      const observations = [
        ...runPassiveAdapters(
          [new HttpSecurityScanner(), new MisconfigurationScanner()],
          exchanges,
        ),
        ...new AuthenticationSurfaceScanner().analyze([...exchanges, ...endpointExchanges]),
      ];
      const count = await persistObservations(evidenceEngine, job.data, observations);
      await finishJob(prisma, job, { exchanges: exchanges.length, observations: count });
      const nextJobId = await enqueue(prisma, queueMap.tls, queues.tls, job.data);
      return { observations: count, nextJobId };
    },
    { connection: connections[0] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  const tlsWorker = new Worker<StagePayload>(
    queues.tls,
    async (job) => {
      const scan = await loadScan(prisma, job.data);
      if (scan.state !== ScanState.PASSIVE_ANALYSIS)
        throw new Error(`TLS analysis expected PASSIVE_ANALYSIS, observed ${scan.state}.`);
      await startJob(prisma, job, workerId);
      if (await isCancelled(prisma, scan.id)) {
        await cancel(prisma, job, ScanState.PASSIVE_ANALYSIS);
        return { status: "CANCELLED" };
      }
      const client = new ScopedHttpClient(new ScopeEngine(), scopePolicy(scan));
      const observations = await analyzeTls(client, scan.target.origin, scan.config.timeoutMs);
      const count = await persistObservations(evidenceEngine, job.data, observations);
      await finishJob(prisma, job, {
        observations: count,
        applicable: scan.target.origin.startsWith("https:"),
      });
      const nextJobId = await enqueue(prisma, queueMap.headers, queues.headers, job.data);
      return { observations: count, nextJobId };
    },
    { connection: connections[1] as Redis, concurrency: 2, lockDuration: 120_000 },
  );

  const headersWorker = new Worker<StagePayload>(
    queues.headers,
    async (job) => {
      const scan = await loadScan(prisma, job.data);
      if (scan.state !== ScanState.PASSIVE_ANALYSIS)
        throw new Error(`Header analysis expected PASSIVE_ANALYSIS, observed ${scan.state}.`);
      await startJob(prisma, job, workerId);
      const exchanges = await loadExchanges(prisma, job.data);
      const count = await persistObservations(
        evidenceEngine,
        job.data,
        new HeaderSecurityScanner().analyze(exchanges),
      );
      await finishJob(prisma, job, { exchanges: exchanges.length, observations: count });
      const nextJobId = await enqueue(prisma, queueMap.cookies, queues.cookies, job.data);
      return { observations: count, nextJobId };
    },
    { connection: connections[2] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  const cookiesWorker = new Worker<StagePayload>(
    queues.cookies,
    async (job) => {
      const scan = await loadScan(prisma, job.data);
      if (scan.state !== ScanState.PASSIVE_ANALYSIS)
        throw new Error(`Cookie analysis expected PASSIVE_ANALYSIS, observed ${scan.state}.`);
      await startJob(prisma, job, workerId);
      const exchanges = await loadExchanges(prisma, job.data);
      const count = await persistObservations(
        evidenceEngine,
        job.data,
        new CookieSecurityScanner().analyze(exchanges),
      );
      const observationCount = await prisma.scannerObservation.count({
        where: { workspaceId: scan.workspaceId, scanId: scan.id, scanner: { startsWith: "aasp-" } },
      });
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.SUCCEEDED,
            completedAt: new Date(),
            result: { observations: count },
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.PASSIVE_ANALYSIS } },
          data: {
            status: StageStatus.COMPLETED,
            completedAt: new Date(),
            completedUnits: observationCount,
            totalUnits: observationCount,
            metadata: { deterministicObservations: observationCount },
          },
        }),
        prisma.scan.update({
          where: { id: scan.id },
          data: { state: ScanState.SAFE_ACTIVE_ANALYSIS },
        }),
      ]);
      const nextJobId = await enqueue(prisma, queueMap.cors, queues.cors, job.data);
      return { observations: count, nextJobId };
    },
    { connection: connections[3] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  const corsWorker = new Worker<StagePayload>(
    queues.cors,
    async (job) => {
      const scan = await loadScan(prisma, job.data);
      if (scan.state !== ScanState.SAFE_ACTIVE_ANALYSIS)
        throw new Error(`CORS analysis expected SAFE_ACTIVE_ANALYSIS, observed ${scan.state}.`);
      await startJob(prisma, job, workerId, ScanState.SAFE_ACTIVE_ANALYSIS);
      const stages = await prisma.scanStage.findMany({
        where: { scanId: scan.id, name: { in: [ScanState.DISCOVERY, ScanState.CRAWLING] } },
        select: { metadata: true },
      });
      const consumed = stages.reduce(
        (sum, stage) => {
          const metadata = stage.metadata ? recordValue(stage.metadata) : {};
          return (
            sum + (typeof metadata["requestsMade"] === "number" ? metadata["requestsMade"] : 0)
          );
        },
        scan.target.origin.startsWith("https:") ? 1 : 0,
      );
      const remaining = Math.max(0, scan.config.maxRequests - consumed);
      const urls = (
        await prisma.discoveredURL.findMany({
          where: {
            workspaceId: scan.workspaceId,
            scanId: scan.id,
            statusCode: { gte: 200, lt: 500 },
          },
          select: { canonicalUrl: true },
          orderBy: { createdAt: "asc" },
        })
      )
        .map((item) => item.canonicalUrl)
        .sort(
          (left, right) =>
            Number(new URL(right).pathname.includes("cors")) -
            Number(new URL(left).pathname.includes("cors")),
        );
      const client = new ScopedHttpClient(new ScopeEngine(), scopePolicy(scan));
      const result = await analyzeCors(client, urls, {
        timeoutMs: scan.config.timeoutMs,
        maxRequests: Math.min(remaining, 20),
        requestsPerSecond: scan.config.requestsPerSecond,
        isCancelled: () => isCancelled(prisma, scan.id),
      });
      if (await isCancelled(prisma, scan.id)) {
        await cancel(prisma, job, ScanState.SAFE_ACTIVE_ANALYSIS);
        return { status: "CANCELLED" };
      }
      const count = await persistObservations(evidenceEngine, job.data, result.observations);
      const metadata = {
        observations: count,
        requestsMade: result.requestsMade,
        requestBudgetRemainingBeforeStage: remaining,
        failures: result.failures.slice(0, 20),
      };
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.SUCCEEDED,
            completedAt: new Date(),
            result: jsonValue(metadata),
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.SAFE_ACTIVE_ANALYSIS } },
          data: {
            status: result.failures.length > 0 ? StageStatus.DEGRADED : StageStatus.COMPLETED,
            completedAt: new Date(),
            completedUnits: result.requestsMade,
            totalUnits: Math.min(remaining, 20),
            metadata: jsonValue(metadata),
          },
        }),
        prisma.scan.update({
          where: { id: scan.id },
          data: {
            state: ScanState.NORMALIZING,
            warningCount: { increment: result.failures.length > 0 ? 1 : 0 },
          },
        }),
      ]);
      const nextJobId = await enqueue(prisma, queueMap.normalize, queues.normalize, job.data);
      return { ...metadata, nextJobId };
    },
    { connection: connections[4] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  for (const [worker, stage] of [
    [httpWorker, ScanState.PASSIVE_ANALYSIS],
    [tlsWorker, ScanState.PASSIVE_ANALYSIS],
    [headersWorker, ScanState.PASSIVE_ANALYSIS],
    [cookiesWorker, ScanState.PASSIVE_ANALYSIS],
    [corsWorker, ScanState.SAFE_ACTIVE_ANALYSIS],
  ] as const)
    attachFailure(worker, prisma, stage);

  const allQueues = new Map<string, Queue<StagePayload>>(
    Object.values(queues).map((name) => [
      name,
      Object.values(queueMap).find((queue) => queue.name === name) as Queue<StagePayload>,
    ]),
  );
  const recoveryTimer = setInterval(() => {
    void (async () => {
      const jobs = await prisma.scanJob.findMany({
        where: { queue: { in: [...allQueues.keys()] }, status: JobStatus.CREATED },
        orderBy: { createdAt: "asc" },
        take: 100,
      });
      for (const persisted of jobs) {
        const queue = allQueues.get(persisted.queue);
        if (!queue) continue;
        const payload = persisted.payload as unknown as StagePayload;
        await queue.add(persisted.queue, payload, {
          jobId: persisted.id,
          attempts: persisted.maxAttempts,
          backoff: { type: "exponential", delay: 2_000 },
        });
        await prisma.scanJob.update({
          where: { id: persisted.id },
          data: { status: JobStatus.QUEUED, bullJobId: persisted.id },
        });
      }
    })().catch((error: unknown) =>
      logger.error("Day 3 outbox recovery failed.", {
        workerId,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
  }, 10_000);
  recoveryTimer.unref();

  return {
    async close(): Promise<void> {
      clearInterval(recoveryTimer);
      await Promise.all([
        httpWorker.close(),
        tlsWorker.close(),
        headersWorker.close(),
        cookiesWorker.close(),
        corsWorker.close(),
      ]);
      await Promise.all(Object.values(queueMap).map((queue) => queue.close()));
      await Promise.all(connections.map((connection) => connection.quit()));
      await publisher.quit();
    },
  };
}
