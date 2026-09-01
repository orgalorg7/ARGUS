import type { Prisma, PrismaClient, ScanState as ScanStateType } from "@aasp/database";
import { JobStatus, ScanState, StageStatus } from "@aasp/database";
import { discoverApiEndpoints } from "@aasp/api-discovery";
import {
  AsynchronousCrawler,
  canonicalizeUrl,
  type CrawledPage,
  type CrawlResult,
  type EndpointCandidate,
} from "@aasp/crawler";
import { EvidenceEngine } from "@aasp/evidence-engine";
import { logger } from "@aasp/logger";
import { ScopeEngine, ScopedHttpClient, ScopeViolationError } from "@aasp/scope-engine";
import { assertCurrentTargetAuthorization } from "@aasp/security-core";
import { fingerprintTechnologies, type TechnologyCandidate } from "@aasp/technology-fingerprinter";
import { Queue, Worker, type Job } from "bullmq";
import { Redis } from "ioredis";

interface StagePayload {
  workspaceId: string;
  scanId: string;
}

interface ApiDiscoveryPayload extends StagePayload {
  endpoints: EndpointCandidate[];
  technologies: TechnologyCandidate[];
  pageEvidence: Record<string, string[]>;
}

interface CrawlPayload extends StagePayload {
  seedEndpoints: EndpointCandidate[];
  seedTechnologies: TechnologyCandidate[];
  pageEvidence: Record<string, string[]>;
}

interface FingerprintPayload extends StagePayload {
  technologies: TechnologyCandidate[];
  pageEvidence: Record<string, string[]>;
}

interface WorkerContext {
  prisma: PrismaClient;
  redisUrl: string;
  workerId: string;
}

export interface Day2WorkerRuntime {
  close(): Promise<void>;
}

const queueNames = {
  discovery: "scan.discovery",
  crawl: "scan.crawl",
  apiDiscovery: "scan.api_discovery",
  fingerprint: "scan.fingerprint",
  passive: "scan.http",
} as const;

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function failureSummary(result: CrawlResult): Prisma.InputJsonValue {
  return jsonValue({
    requestsMade: result.requestsMade,
    requestsBlockedByScope: result.requestsBlockedByScope,
    trapBlockedUrls: result.trapBlockedUrls,
    failures: result.failures.slice(0, 100).map((failure) => ({
      ...failure,
      message: failure.message.slice(0, 500),
    })),
    omittedFailures: Math.max(0, result.failures.length - 100),
  });
}

async function loadScan(prisma: PrismaClient, workspaceId: string, scanId: string) {
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, workspaceId },
    include: { target: true, config: true },
  });
  if (!scan?.config)
    throw new Error("Persisted scan configuration was not found in its workspace.");
  assertCurrentTargetAuthorization(scan.target);
  return { ...scan, config: scan.config };
}

function policyFor(scan: Awaited<ReturnType<typeof loadScan>>) {
  return {
    targetOrigin: scan.target.origin,
    includeSubdomains: scan.config.includeSubdomains,
    allowPrivateNetwork: scan.target.allowPrivateNetwork,
    allowedPorts: [
      scan.target.normalizedPort ?? (scan.target.origin.startsWith("https:") ? 443 : 80),
    ],
  };
}

async function markJobRunning<T extends StagePayload>(
  prisma: PrismaClient,
  job: Job<T>,
  stage: ScanStateType,
  workerId: string,
): Promise<void> {
  const persistedJobId = String(job.id ?? "");
  await prisma.$transaction([
    prisma.scanJob.update({
      where: { id: persistedJobId },
      data: {
        status: JobStatus.RUNNING,
        attempt: { increment: 1 },
        startedAt: new Date(),
        lockedBy: workerId,
      },
    }),
    prisma.scanStage.update({
      where: { scanId_name: { scanId: job.data.scanId, name: stage } },
      data: { status: StageStatus.RUNNING, startedAt: new Date(), errorMessage: null },
    }),
  ]);
}

async function persistPage(
  prisma: PrismaClient,
  evidenceEngine: EvidenceEngine,
  workspaceId: string,
  scanId: string,
  page: CrawledPage,
): Promise<string[]> {
  const recorded = await evidenceEngine.record(workspaceId, scanId, {
    scanner: "aasp-crawler",
    scannerVersion: "0.1.0",
    observationType: "HTTP_RESPONSE_OBSERVATION",
    asset: new URL(page.finalUrl).origin,
    endpoint: new URL(page.finalUrl).pathname,
    method: "GET",
    evidence: [
      {
        source: "scope-guarded-crawler",
        asset: page.finalUrl,
        requestMetadata: {
          method: "GET",
          requestedUrl: page.url,
          depth: page.depth,
          discoveredBy: page.discoveredBy,
        },
        responseMetadata: {
          statusCode: page.statusCode,
          contentType: page.contentType,
          headers: page.headers,
          finalUrl: page.finalUrl,
          redirects: page.redirects,
        },
        excerpt: page.bodyText.slice(0, 32_768),
      },
    ],
    metadata: {
      statusCode: page.statusCode,
      contentType: page.contentType,
      depth: page.depth,
      linkCount: page.links.length,
      scriptCount: page.scripts.length,
    },
  });
  const parsed = new URL(page.finalUrl);
  await prisma.$transaction([
    prisma.discoveredAsset.upsert({
      where: { scanId_assetType_value: { scanId, assetType: "ORIGIN", value: parsed.origin } },
      create: {
        workspaceId,
        scanId,
        assetType: "ORIGIN",
        value: parsed.origin,
        metadata: { hostname: parsed.hostname, protocol: parsed.protocol },
      },
      update: { lastSeenAt: new Date() },
    }),
    prisma.discoveredURL.upsert({
      where: { scanId_canonicalUrl: { scanId, canonicalUrl: page.canonicalUrl } },
      create: {
        workspaceId,
        scanId,
        url: page.finalUrl,
        canonicalUrl: page.canonicalUrl,
        depth: page.depth,
        statusCode: page.statusCode,
        contentType: page.contentType,
        discoveredBy: page.discoveredBy,
        scannedAt: new Date(),
      },
      update: {
        url: page.finalUrl,
        statusCode: page.statusCode,
        contentType: page.contentType,
        scannedAt: new Date(),
      },
    }),
  ]);
  return recorded.evidenceIds;
}

async function persistDiscoveredUrls(
  prisma: PrismaClient,
  workspaceId: string,
  scanId: string,
  result: CrawlResult,
): Promise<void> {
  for (const discovered of result.discoveredUrls) {
    await prisma.discoveredURL.upsert({
      where: { scanId_canonicalUrl: { scanId, canonicalUrl: discovered.canonicalUrl } },
      create: {
        workspaceId,
        scanId,
        url: discovered.url,
        canonicalUrl: discovered.canonicalUrl,
        depth: discovered.depth,
        discoveredBy: discovered.discoveredBy,
      },
      update: {},
    });
  }
}

async function createPersistedJob(
  prisma: PrismaClient,
  queue: Queue,
  queueName: string,
  name: string,
  payload: StagePayload,
  idempotencyKey: string,
): Promise<{ id: string; published: boolean }> {
  const persisted = await prisma.scanJob.upsert({
    where: { idempotencyKey },
    create: {
      workspaceId: payload.workspaceId,
      scanId: payload.scanId,
      queue: queueName,
      idempotencyKey,
      status: JobStatus.CREATED,
      payload: jsonValue(payload),
    },
    update: { payload: jsonValue(payload) },
  });
  try {
    await queue.add(name, payload, {
      jobId: persisted.id,
      attempts: 4,
      backoff: { type: "exponential", delay: 2_000 },
      removeOnComplete: 1_000,
      removeOnFail: 5_000,
    });
    await prisma.scanJob.update({
      where: { id: persisted.id },
      data: { status: JobStatus.QUEUED, bullJobId: persisted.id },
    });
    return { id: persisted.id, published: true };
  } catch {
    return { id: persisted.id, published: false };
  }
}

async function completeAndAdvance<T extends StagePayload>(
  prisma: PrismaClient,
  job: Job<T>,
  currentStage: ScanStateType,
  nextStage: ScanStateType,
  completedUnits: number,
  totalUnits: number,
  metadata: Prisma.InputJsonValue,
): Promise<void> {
  await prisma.$transaction([
    prisma.scanStage.update({
      where: { scanId_name: { scanId: job.data.scanId, name: currentStage } },
      data: {
        status: StageStatus.COMPLETED,
        completedAt: new Date(),
        completedUnits,
        totalUnits,
        metadata,
      },
    }),
    prisma.scan.update({ where: { id: job.data.scanId }, data: { state: nextStage } }),
    prisma.scanJob.update({
      where: { id: String(job.id ?? "") },
      data: { status: JobStatus.SUCCEEDED, completedAt: new Date(), result: metadata },
    }),
  ]);
}

async function cancelStage<T extends StagePayload>(
  prisma: PrismaClient,
  job: Job<T>,
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

function attachFailurePersistence<T extends StagePayload>(
  worker: Worker<T>,
  prisma: PrismaClient,
  workerId: string,
  stage: ScanStateType,
): void {
  worker.on("failed", (job, error) => {
    if (!job || job.attemptsMade < (job.opts.attempts ?? 1)) return;
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
        prisma.scanStage.updateMany({
          where: { scanId, workspaceId, name: stage },
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
      .catch((persistenceError: unknown) => {
        logger.error("Failed to persist Day 2 worker failure.", {
          workspaceId,
          scanId,
          workerId,
          error:
            persistenceError instanceof Error ? persistenceError.message : String(persistenceError),
        });
      });
  });
}

function mergeEndpoints(groups: readonly EndpointCandidate[][]): EndpointCandidate[] {
  const merged = new Map<string, EndpointCandidate>();
  for (const candidate of groups.flat()) {
    const key = `${candidate.asset}|${candidate.path}|${candidate.method}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...candidate, parameters: [...candidate.parameters] });
      continue;
    }
    existing.parameters = [
      ...new Map(
        [...existing.parameters, ...candidate.parameters].map((parameter) => [
          `${parameter.location}|${parameter.name}`,
          parameter,
        ]),
      ).values(),
    ];
    if (!existing.source.includes(candidate.source))
      existing.source = `${existing.source},${candidate.source}`;
  }
  return [...merged.values()];
}

function mergeTechnologies(groups: readonly TechnologyCandidate[][]): TechnologyCandidate[] {
  const merged = new Map<string, TechnologyCandidate>();
  for (const candidate of groups.flat()) {
    const key = `${candidate.technology.toLowerCase()}|${candidate.possibleVersion ?? ""}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, {
        ...candidate,
        sourceUrls: [...candidate.sourceUrls],
        evidence: [...candidate.evidence],
      });
      continue;
    }
    existing.confidence = Math.max(existing.confidence, candidate.confidence);
    existing.sourceUrls = [...new Set([...existing.sourceUrls, ...candidate.sourceUrls])];
    existing.evidence = [...new Set([...existing.evidence, ...candidate.evidence])];
  }
  return [...merged.values()];
}

export function startDay2Workers(context: WorkerContext): Day2WorkerRuntime {
  const { prisma, redisUrl, workerId } = context;
  const publisherConnection = new Redis(redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
  });
  const queues = {
    discovery: new Queue(queueNames.discovery, { connection: publisherConnection }),
    crawl: new Queue(queueNames.crawl, { connection: publisherConnection }),
    apiDiscovery: new Queue(queueNames.apiDiscovery, { connection: publisherConnection }),
    fingerprint: new Queue(queueNames.fingerprint, { connection: publisherConnection }),
    passive: new Queue(queueNames.passive, { connection: publisherConnection }),
  };
  const workerConnections = [
    queueNames.discovery,
    queueNames.crawl,
    queueNames.apiDiscovery,
    queueNames.fingerprint,
  ].map(() => new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true }));
  const evidenceEngine = new EvidenceEngine(prisma);

  const discoveryWorker = new Worker<StagePayload>(
    queueNames.discovery,
    async (job) => {
      const scan = await loadScan(prisma, job.data.workspaceId, job.data.scanId);
      if (scan.state !== ScanState.DISCOVERY) {
        if (scan.state === ScanState.CRAWLING) return { status: "ALREADY_COMPLETED" };
        throw new Error(`Discovery expected DISCOVERY state, observed ${scan.state}.`);
      }
      await markJobRunning(prisma, job, ScanState.DISCOVERY, workerId);
      const pageEvidence: Record<string, string[]> = {};
      const crawler = new AsynchronousCrawler(
        new ScopedHttpClient(new ScopeEngine(), policyFor(scan)),
        {
          maxDepth: 0,
          maxUrls: Math.min(scan.config.maxUrls, 10),
          maxRequests: Math.min(scan.config.maxRequests, 10),
          requestsPerSecond: scan.config.requestsPerSecond,
          concurrency: Math.min(scan.config.concurrency, 4),
          timeoutMs: scan.config.timeoutMs,
          followRedirects: scan.config.followRedirects,
          retries: 1,
        },
        {
          isCancelled: async () =>
            Boolean(
              (
                await prisma.scan.findUnique({
                  where: { id: scan.id },
                  select: { cancelRequestedAt: true },
                })
              )?.cancelRequestedAt,
            ),
          onPage: async (page, progress) => {
            const evidenceIds = await persistPage(
              prisma,
              evidenceEngine,
              scan.workspaceId,
              scan.id,
              page,
            );
            pageEvidence[page.canonicalUrl] = evidenceIds;
            pageEvidence[page.finalUrl] = evidenceIds;
            await prisma.scanStage.update({
              where: { scanId_name: { scanId: scan.id, name: ScanState.DISCOVERY } },
              data: {
                completedUnits: progress.requestsMade,
                totalUnits: progress.discoveredUrls,
              },
            });
          },
        },
      );
      const result = await crawler.crawl(scan.target.origin, true);
      await persistDiscoveredUrls(prisma, scan.workspaceId, scan.id, result);
      if (result.cancelled) {
        await cancelStage(prisma, job, ScanState.DISCOVERY);
        return { status: "CANCELLED" };
      }
      await completeAndAdvance(
        prisma,
        job,
        ScanState.DISCOVERY,
        ScanState.CRAWLING,
        result.pages.length,
        result.discoveredUrls.length,
        failureSummary(result),
      );
      const crawlPayload: CrawlPayload = {
        ...job.data,
        seedEndpoints: discoverApiEndpoints(result.pages),
        seedTechnologies: fingerprintTechnologies(result.pages),
        pageEvidence,
      };
      const next = await createPersistedJob(
        prisma,
        queues.crawl,
        queueNames.crawl,
        "crawl",
        crawlPayload,
        `crawl:${scan.id}:v1`,
      );
      return {
        status: "COMPLETED",
        nextJobId: next.id,
        queueDispatch: next.published ? "PUBLISHED" : "DEFERRED",
      };
    },
    { connection: workerConnections[0] as Redis, concurrency: 2, lockDuration: 120_000 },
  );

  const crawlWorker = new Worker<CrawlPayload>(
    queueNames.crawl,
    async (job) => {
      const scan = await loadScan(prisma, job.data.workspaceId, job.data.scanId);
      if (scan.state !== ScanState.CRAWLING) {
        if (scan.state === ScanState.API_DISCOVERY) return { status: "ALREADY_COMPLETED" };
        throw new Error(`Crawler expected CRAWLING state, observed ${scan.state}.`);
      }
      await markJobRunning(prisma, job, ScanState.CRAWLING, workerId);
      const pageEvidence: Record<string, string[]> = { ...job.data.pageEvidence };
      const crawler = new AsynchronousCrawler(
        new ScopedHttpClient(new ScopeEngine(), policyFor(scan)),
        {
          maxDepth: scan.config.crawlDepth,
          maxUrls: scan.config.maxUrls,
          maxRequests: scan.config.maxRequests,
          requestsPerSecond: scan.config.requestsPerSecond,
          concurrency: scan.config.concurrency,
          timeoutMs: scan.config.timeoutMs,
          followRedirects: scan.config.followRedirects,
          retries: 1,
        },
        {
          isCancelled: async () =>
            Boolean(
              (
                await prisma.scan.findUnique({
                  where: { id: scan.id },
                  select: { cancelRequestedAt: true },
                })
              )?.cancelRequestedAt,
            ),
          onPage: async (page, progress) => {
            const evidenceIds = await persistPage(
              prisma,
              evidenceEngine,
              scan.workspaceId,
              scan.id,
              page,
            );
            pageEvidence[page.canonicalUrl] = evidenceIds;
            pageEvidence[page.finalUrl] = evidenceIds;
            await prisma.scanStage.update({
              where: { scanId_name: { scanId: scan.id, name: ScanState.CRAWLING } },
              data: {
                completedUnits: progress.requestsMade,
                totalUnits: progress.discoveredUrls,
              },
            });
          },
        },
      );
      const result = await crawler.crawl(scan.target.origin);
      await persistDiscoveredUrls(prisma, scan.workspaceId, scan.id, result);
      if (result.cancelled) {
        await cancelStage(prisma, job, ScanState.CRAWLING);
        return { status: "CANCELLED" };
      }
      const payload: ApiDiscoveryPayload = {
        ...job.data,
        endpoints: mergeEndpoints([job.data.seedEndpoints, discoverApiEndpoints(result.pages)]),
        technologies: mergeTechnologies([
          job.data.seedTechnologies,
          fingerprintTechnologies(result.pages),
        ]),
        pageEvidence,
      };
      await completeAndAdvance(
        prisma,
        job,
        ScanState.CRAWLING,
        ScanState.API_DISCOVERY,
        result.pages.length,
        result.discoveredUrls.length,
        failureSummary(result),
      );
      const next = await createPersistedJob(
        prisma,
        queues.apiDiscovery,
        queueNames.apiDiscovery,
        "api-discovery",
        payload,
        `api-discovery:${scan.id}:v1`,
      );
      return {
        status: "COMPLETED",
        nextJobId: next.id,
        queueDispatch: next.published ? "PUBLISHED" : "DEFERRED",
      };
    },
    { connection: workerConnections[1] as Redis, concurrency: 2, lockDuration: 300_000 },
  );

  const apiDiscoveryWorker = new Worker<ApiDiscoveryPayload>(
    queueNames.apiDiscovery,
    async (job) => {
      const scan = await loadScan(prisma, job.data.workspaceId, job.data.scanId);
      if (scan.state !== ScanState.API_DISCOVERY) {
        if (scan.state === ScanState.FINGERPRINTING) return { status: "ALREADY_COMPLETED" };
        throw new Error(`API discovery expected API_DISCOVERY state, observed ${scan.state}.`);
      }
      await markJobRunning(prisma, job, ScanState.API_DISCOVERY, workerId);
      const scopeEngine = new ScopeEngine();
      const policy = policyFor(scan);
      let persistedCount = 0;
      let outOfScopeCount = 0;
      for (const candidate of job.data.endpoints) {
        const candidateUrl = new URL(candidate.path, candidate.asset).toString();
        try {
          await scopeEngine.assertAllowed(candidateUrl, policy);
        } catch (error: unknown) {
          if (error instanceof ScopeViolationError) {
            outOfScopeCount += 1;
            continue;
          }
          throw error;
        }
        const endpoint = await prisma.discoveredEndpoint.upsert({
          where: {
            scanId_asset_path_method: {
              scanId: scan.id,
              asset: candidate.asset,
              path: candidate.path,
              method: candidate.method,
            },
          },
          create: {
            workspaceId: scan.workspaceId,
            scanId: scan.id,
            asset: candidate.asset,
            path: candidate.path,
            method: candidate.method,
            source: candidate.source,
          },
          update: { source: candidate.source },
        });
        for (const parameter of candidate.parameters) {
          await prisma.discoveredParameter.upsert({
            where: {
              endpointId_name_location: {
                endpointId: endpoint.id,
                name: parameter.name,
                location: parameter.location,
              },
            },
            create: {
              workspaceId: scan.workspaceId,
              scanId: scan.id,
              endpointId: endpoint.id,
              name: parameter.name,
              location: parameter.location,
              ...(parameter.observedType ? { observedType: parameter.observedType } : {}),
            },
            update: parameter.observedType ? { observedType: parameter.observedType } : {},
          });
        }
        persistedCount += 1;
        await prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.API_DISCOVERY } },
          data: { completedUnits: persistedCount, totalUnits: job.data.endpoints.length },
        });
      }
      const metadata = jsonValue({
        persistedEndpoints: persistedCount,
        outOfScopeCandidates: outOfScopeCount,
      });
      await completeAndAdvance(
        prisma,
        job,
        ScanState.API_DISCOVERY,
        ScanState.FINGERPRINTING,
        persistedCount,
        job.data.endpoints.length,
        metadata,
      );
      const payload: FingerprintPayload = {
        workspaceId: scan.workspaceId,
        scanId: scan.id,
        technologies: job.data.technologies,
        pageEvidence: job.data.pageEvidence,
      };
      const next = await createPersistedJob(
        prisma,
        queues.fingerprint,
        queueNames.fingerprint,
        "fingerprint",
        payload,
        `fingerprint:${scan.id}:v1`,
      );
      return {
        status: "COMPLETED",
        nextJobId: next.id,
        queueDispatch: next.published ? "PUBLISHED" : "DEFERRED",
      };
    },
    { connection: workerConnections[2] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  const fingerprintWorker = new Worker<FingerprintPayload>(
    queueNames.fingerprint,
    async (job) => {
      const scan = await loadScan(prisma, job.data.workspaceId, job.data.scanId);
      if (scan.state !== ScanState.FINGERPRINTING) {
        if (scan.state === ScanState.PASSIVE_ANALYSIS) return { status: "ALREADY_COMPLETED" };
        throw new Error(`Fingerprinting expected FINGERPRINTING state, observed ${scan.state}.`);
      }
      await markJobRunning(prisma, job, ScanState.FINGERPRINTING, workerId);
      let persistedCount = 0;
      for (const candidate of job.data.technologies) {
        const evidenceIds = [
          ...new Set(
            candidate.sourceUrls.flatMap((url) => {
              const canonical = canonicalizeUrl(url);
              return job.data.pageEvidence[url] ?? job.data.pageEvidence[canonical] ?? [];
            }),
          ),
        ];
        if (evidenceIds.length === 0) continue;
        const existing = await prisma.technology.findFirst({
          where: {
            scanId: scan.id,
            technology: candidate.technology,
            possibleVersion: candidate.possibleVersion ?? null,
          },
        });
        if (existing) {
          await prisma.technology.update({
            where: { id: existing.id },
            data: {
              confidence: Math.max(existing.confidence, candidate.confidence),
              evidenceIds: [...new Set([...existing.evidenceIds, ...evidenceIds])],
            },
          });
        } else {
          await prisma.technology.create({
            data: {
              workspaceId: scan.workspaceId,
              scanId: scan.id,
              technology: candidate.technology,
              ...(candidate.possibleVersion ? { possibleVersion: candidate.possibleVersion } : {}),
              confidence: candidate.confidence,
              evidenceIds,
            },
          });
        }
        persistedCount += 1;
      }
      const metadata = jsonValue({ persistedTechnologies: persistedCount });
      await completeAndAdvance(
        prisma,
        job,
        ScanState.FINGERPRINTING,
        ScanState.PASSIVE_ANALYSIS,
        persistedCount,
        job.data.technologies.length,
        metadata,
      );
      const next = await createPersistedJob(
        prisma,
        queues.passive,
        queueNames.passive,
        "passive-analysis",
        { workspaceId: scan.workspaceId, scanId: scan.id },
        `passive:${scan.id}:v1`,
      );
      return {
        status: "COMPLETED",
        nextJobId: next.id,
        queueDispatch: next.published ? "PUBLISHED" : "DEFERRED",
      };
    },
    { connection: workerConnections[3] as Redis, concurrency: 2, lockDuration: 120_000 },
  );

  attachFailurePersistence(discoveryWorker, prisma, workerId, ScanState.DISCOVERY);
  attachFailurePersistence(crawlWorker, prisma, workerId, ScanState.CRAWLING);
  attachFailurePersistence(apiDiscoveryWorker, prisma, workerId, ScanState.API_DISCOVERY);
  attachFailurePersistence(fingerprintWorker, prisma, workerId, ScanState.FINGERPRINTING);

  const queueByName = new Map<string, Queue>([
    [queueNames.discovery, queues.discovery],
    [queueNames.crawl, queues.crawl],
    [queueNames.apiDiscovery, queues.apiDiscovery],
    [queueNames.fingerprint, queues.fingerprint],
    [queueNames.passive, queues.passive],
  ]);
  const recoveryTimer = setInterval(() => {
    void (async () => {
      const jobs = await prisma.scanJob.findMany({
        where: { queue: { in: [...queueByName.keys()] }, status: JobStatus.CREATED },
        orderBy: { createdAt: "asc" },
        take: 100,
      });
      for (const persisted of jobs) {
        const queue = queueByName.get(persisted.queue);
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
    })().catch((error: unknown) => {
      logger.error("Day 2 outbox recovery failed.", {
        workerId,
        error: error instanceof Error ? error.message : String(error),
      });
    });
  }, 10_000);
  recoveryTimer.unref();

  return {
    async close(): Promise<void> {
      clearInterval(recoveryTimer);
      await Promise.all([
        discoveryWorker.close(),
        crawlWorker.close(),
        apiDiscoveryWorker.close(),
        fingerprintWorker.close(),
      ]);
      await Promise.all(Object.values(queues).map((queue) => queue.close()));
      await Promise.all(workerConnections.map((connection) => connection.quit()));
      await publisherConnection.quit();
    },
  };
}
