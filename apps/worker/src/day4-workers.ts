import type { PrismaClient, ScanState as ScanStateType } from "@aasp/database";
import {
  AIAnalysisStatus,
  FindingStatus,
  JobStatus,
  ModelProviderStatus,
  Prisma,
  ScanState,
  StageStatus,
} from "@aasp/database";
import {
  buildQwenAnalysisInput,
  decryptProviderSecret,
  QwenClient,
  type QwenProviderConfig,
} from "@aasp/ai-engine";
import { correlateFindings, type CorrelatedFinding } from "@aasp/correlation-engine";
import { normalizeObservations, type FindingObservationRecord } from "@aasp/finding-engine";
import { logger } from "@aasp/logger";
import type { QwenAnalysisInput, QwenAnalysisOutput, Severity } from "@aasp/schemas";
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

export interface Day4WorkerRuntime {
  close(): Promise<void>;
}

const queueNames = {
  normalize: "scan.normalize",
  correlate: "scan.correlate",
  ai: "scan.ai",
  report: "scan.report",
} as const;

const promptVersion = "aasp-qwen-finding-v1";

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

async function loadObservations(
  prisma: PrismaClient,
  payload: StagePayload,
): Promise<FindingObservationRecord[]> {
  const observations = await prisma.scannerObservation.findMany({
    where: { workspaceId: payload.workspaceId, scanId: payload.scanId },
    include: { evidence: { orderBy: { timestamp: "asc" } } },
    orderBy: { createdAt: "asc" },
  });
  return observations.map((observation) => ({
    id: observation.id,
    scanner: observation.scanner,
    scannerVersion: observation.scannerVersion,
    observationType: observation.observationType,
    asset: observation.asset,
    endpoint: observation.endpoint,
    method: observation.method,
    parameter: observation.parameter,
    rawSeverity: observation.rawSeverity,
    metadata: observation.metadata,
    createdAt: observation.createdAt,
    evidence: observation.evidence.map((item) => ({
      id: item.id,
      timestamp: item.timestamp,
      source: item.source,
      asset: item.asset,
      hash: item.hash,
      requestMetadata: item.requestMetadata,
      responseMetadata: item.responseMetadata,
      redactedExcerpt: item.redactedExcerpt,
    })),
  }));
}

async function markRunning(
  prisma: PrismaClient,
  job: Job<StagePayload>,
  workerId: string,
  stage: ScanStateType,
): Promise<void> {
  await prisma.$transaction([
    prisma.scanJob.update({
      where: { id: String(job.id ?? "") },
      data: {
        status: JobStatus.RUNNING,
        attempt: { increment: 1 },
        startedAt: new Date(),
        completedAt: null,
        lockedBy: workerId,
        lastError: null,
      },
    }),
    prisma.scanStage.update({
      where: { scanId_name: { scanId: job.data.scanId, name: stage } },
      data: { status: StageStatus.RUNNING, startedAt: new Date(), errorMessage: null },
    }),
  ]);
}

async function cancelRequested(prisma: PrismaClient, scanId: string): Promise<boolean> {
  return Boolean(
    (await prisma.scan.findUnique({ where: { id: scanId }, select: { cancelRequestedAt: true } }))
      ?.cancelRequestedAt,
  );
}

async function cancelStage(
  prisma: PrismaClient,
  job: Job<StagePayload>,
  stage: ScanStateType,
): Promise<void> {
  const now = new Date();
  await prisma.$transaction([
    prisma.scan.update({
      where: { id: job.data.scanId },
      data: { state: ScanState.CANCELLED, completedAt: now },
    }),
    prisma.scanStage.update({
      where: { scanId_name: { scanId: job.data.scanId, name: stage } },
      data: { status: StageStatus.CANCELLED, completedAt: now },
    }),
    prisma.scanJob.update({
      where: { id: String(job.id ?? "") },
      data: { status: JobStatus.CANCELLED, completedAt: now },
    }),
  ]);
}

async function enqueue(
  prisma: PrismaClient,
  queue: Queue<StagePayload>,
  queueName: string,
  payload: StagePayload,
): Promise<string> {
  const idempotencyKey = `${queueName}:${payload.scanId}:v1`;
  const persisted = await prisma.scanJob.upsert({
    where: { idempotencyKey },
    create: {
      workspaceId: payload.workspaceId,
      scanId: payload.scanId,
      queue: queueName,
      idempotencyKey,
      status: JobStatus.CREATED,
      maxAttempts: queueName === queueNames.ai ? 2 : 4,
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
    logger.warn("Day 4 queue publication deferred to persisted outbox recovery.", {
      queueName,
      scanId: payload.scanId,
      error: error instanceof Error ? error.message : String(error),
    });
  }
  return persisted.id;
}

async function persistCorrelatedFindings(
  prisma: PrismaClient,
  payload: StagePayload,
  findings: readonly CorrelatedFinding[],
): Promise<number> {
  const existing = await prisma.finding.findMany({
    where: { workspaceId: payload.workspaceId, scanId: payload.scanId },
    select: { id: true, publicId: true, correlationKey: true },
  });
  const byCorrelationKey = new Map(existing.map((finding) => [finding.correlationKey, finding]));
  let nextSequence = existing.reduce((maximum, finding) => {
    const matched = /^FIND-(\d+)$/.exec(finding.publicId);
    return Math.max(maximum, matched ? Number(matched[1]) : 0);
  }, 0);

  for (const candidate of findings) {
    const previous = byCorrelationKey.get(candidate.correlationKey);
    const publicId = previous?.publicId ?? `FIND-${String(++nextSequence).padStart(4, "0")}`;
    const finding = await prisma.finding.upsert({
      where: {
        scanId_correlationKey: {
          scanId: payload.scanId,
          correlationKey: candidate.correlationKey,
        },
      },
      create: {
        workspaceId: payload.workspaceId,
        scanId: payload.scanId,
        publicId,
        title: candidate.title,
        category: candidate.category,
        severity: candidate.severity,
        confidence: candidate.confidence,
        status: candidate.status,
        cwe: candidate.cwe,
        owasp: candidate.owasp,
        asset: candidate.asset,
        endpoint: candidate.endpoint,
        method: candidate.method,
        parameter: candidate.parameter,
        description: candidate.description,
        technicalImpact: candidate.technicalImpact,
        businessImpact: candidate.businessImpact,
        scannerSources: candidate.scannerSources,
        remediation: candidate.remediation,
        manualVerificationRequired: candidate.manualVerificationRequired,
        correlationKey: candidate.correlationKey,
        firstSeen: candidate.firstSeen,
        lastSeen: candidate.lastSeen,
      },
      update: {
        title: candidate.title,
        severity: candidate.severity,
        confidence: candidate.confidence,
        status: candidate.status,
        cwe: candidate.cwe,
        owasp: candidate.owasp,
        scannerSources: candidate.scannerSources,
        remediation: candidate.remediation,
        manualVerificationRequired: candidate.manualVerificationRequired,
        firstSeen: candidate.firstSeen,
        lastSeen: candidate.lastSeen,
      },
    });
    await prisma.$transaction([
      prisma.findingEvidence.createMany({
        data: candidate.evidenceIds.map((evidenceId) => ({ findingId: finding.id, evidenceId })),
        skipDuplicates: true,
      }),
      prisma.findingOccurrence.createMany({
        data: candidate.observationIds.map((observationId) => ({
          findingId: finding.id,
          observationId,
        })),
        skipDuplicates: true,
      }),
      ...(previous
        ? []
        : [
            prisma.findingHistory.create({
              data: {
                findingId: finding.id,
                action: "CORRELATED_FROM_OBSERVATIONS",
                after: jsonValue({
                  publicId,
                  evidenceCount: candidate.evidenceIds.length,
                  observationCount: candidate.observationIds.length,
                  severity: candidate.severity,
                  confidence: candidate.confidence,
                }),
              },
            }),
          ]),
    ]);
  }
  return findings.length;
}

async function providerConfiguration(
  prisma: PrismaClient,
  workspaceId: string,
): Promise<{ id: string | null; config: QwenProviderConfig } | null> {
  const provider =
    (await prisma.modelProvider.findFirst({
      where: { workspaceId },
      orderBy: { updatedAt: "desc" },
    })) ??
    (await prisma.modelProvider.findFirst({
      where: { workspaceId: null },
      orderBy: { updatedAt: "desc" },
    }));
  if (provider) {
    let apiKey: string | undefined;
    if (provider.encryptedApiKey && provider.apiKeyInitializationVector) {
      const encryptionKey = process.env["MODEL_PROVIDER_ENCRYPTION_KEY"];
      if (!encryptionKey) {
        throw new Error("MODEL_PROVIDER_ENCRYPTION_KEY is required to decrypt the provider key.");
      }
      apiKey = decryptProviderSecret(
        provider.encryptedApiKey,
        provider.apiKeyInitializationVector,
        encryptionKey,
      );
    }
    return {
      id: provider.id,
      config: {
        baseUrl: provider.baseUrl,
        modelName: provider.modelName,
        ...(apiKey ? { apiKey } : {}),
      },
    };
  }
  const baseUrl = process.env["QWEN_BASE_URL"];
  if (!baseUrl) return null;
  const apiKey = process.env["QWEN_API_KEY"];
  return {
    id: null,
    config: {
      baseUrl,
      modelName: process.env["QWEN_MODEL"] ?? "Qwen/Qwen3.8-27B",
      ...(apiKey ? { apiKey } : {}),
    },
  };
}

async function upsertAnalysis(
  prisma: PrismaClient,
  input: {
    workspaceId: string;
    scanId: string;
    findingId: string;
    providerId: string | null;
    modelName: string;
    analysisInput: QwenAnalysisInput;
  },
): Promise<{
  analysis: Awaited<ReturnType<PrismaClient["aIAnalysis"]["create"]>>;
  alreadyCompleted: boolean;
}> {
  const existing = await prisma.aIAnalysis.findFirst({
    where: { findingId: input.findingId, promptVersion },
  });
  if (
    existing?.status === AIAnalysisStatus.COMPLETED &&
    existing.schemaValid === true &&
    existing.evidenceValid === true
  ) {
    return { analysis: existing, alreadyCompleted: true };
  }
  if (existing) {
    const analysis = await prisma.aIAnalysis.update({
      where: { id: existing.id },
      data: {
        providerId: input.providerId,
        modelName: input.modelName,
        input: jsonValue(input.analysisInput),
        status: AIAnalysisStatus.RUNNING,
        output: Prisma.JsonNull,
        schemaValid: null,
        evidenceValid: null,
        failureReason: null,
      },
    });
    return { analysis, alreadyCompleted: false };
  }
  const analysis = await prisma.aIAnalysis.create({
    data: {
      workspaceId: input.workspaceId,
      scanId: input.scanId,
      findingId: input.findingId,
      providerId: input.providerId,
      modelName: input.modelName,
      promptVersion,
      input: jsonValue(input.analysisInput),
      status: AIAnalysisStatus.RUNNING,
    },
  });
  return { analysis, alreadyCompleted: false };
}

const severityOrder: Severity[] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function boundedSeverity(deterministic: Severity, proposed: Severity): Severity {
  const current = severityOrder.indexOf(deterministic);
  const next = severityOrder.indexOf(proposed);
  if (Math.abs(next - current) <= 1) return proposed;
  return severityOrder[current + Math.sign(next - current)] ?? deterministic;
}

async function applyAnalysis(
  prisma: PrismaClient,
  finding: {
    id: string;
    severity: Severity;
    confidence: number;
    manualVerificationRequired: boolean;
  },
  output: QwenAnalysisOutput,
): Promise<void> {
  const manualVerificationRequired =
    finding.manualVerificationRequired || output.manualVerificationRequired;
  await prisma.$transaction([
    prisma.finding.update({
      where: { id: finding.id },
      data: {
        title: output.title,
        severity: boundedSeverity(finding.severity, output.severity),
        confidence: Math.min(0.99, output.confidence),
        cwe: output.cwe,
        owasp: output.owasp,
        description: output.description,
        technicalImpact: output.technicalImpact,
        businessImpact: output.businessImpact,
        remediation: output.remediation,
        manualVerificationRequired,
        status: manualVerificationRequired
          ? FindingStatus.MANUAL_VERIFICATION_REQUIRED
          : FindingStatus.OPEN,
      },
    }),
    prisma.findingHistory.create({
      data: {
        findingId: finding.id,
        action: "QWEN_ANALYSIS_APPLIED",
        before: jsonValue({ severity: finding.severity, confidence: finding.confidence }),
        after: jsonValue({
          severity: boundedSeverity(finding.severity, output.severity),
          confidence: output.confidence,
          likelyFalsePositive: output.likelyFalsePositive,
          evidenceIds: output.evidenceIds,
        }),
      },
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
        logger.error("Failed to persist Day 4 worker failure.", {
          scanId: job.data.scanId,
          error:
            persistenceError instanceof Error ? persistenceError.message : String(persistenceError),
        }),
      );
  });
}

function attachAiFailure(
  worker: Worker<StagePayload>,
  prisma: PrismaClient,
  reportQueue: Queue<StagePayload>,
): void {
  worker.on("failed", (job, error) => {
    if (!job || job.attemptsMade < (job.opts.attempts ?? 1)) return;
    void (async () => {
      await prisma.$transaction([
        prisma.scan.updateMany({
          where: {
            id: job.data.scanId,
            workspaceId: job.data.workspaceId,
            state: { notIn: [ScanState.COMPLETED, ScanState.CANCELLED] },
          },
          data: {
            state: ScanState.GENERATING_SCAN_REPORT,
            warningCount: { increment: 1 },
          },
        }),
        prisma.scanStage.updateMany({
          where: {
            scanId: job.data.scanId,
            workspaceId: job.data.workspaceId,
            name: ScanState.AI_ANALYSIS,
          },
          data: {
            status: StageStatus.DEGRADED,
            completedAt: new Date(),
            errorMessage: error.message.slice(0, 1_000),
            metadata: { deterministicFindingsPreserved: true },
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
      ]);
      await enqueue(prisma, reportQueue, queueNames.report, job.data);
    })().catch((persistenceError: unknown) =>
      logger.error("Failed to degrade AI analysis and preserve deterministic findings.", {
        scanId: job.data.scanId,
        error:
          persistenceError instanceof Error ? persistenceError.message : String(persistenceError),
      }),
    );
  });
}

export function startDay4Workers(context: WorkerContext): Day4WorkerRuntime {
  const { prisma, redisUrl, workerId } = context;
  const publisher = new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true });
  const queues = Object.fromEntries(
    Object.entries(queueNames).map(([key, name]) => [
      key,
      new Queue<StagePayload>(name, { connection: publisher }),
    ]),
  ) as Record<keyof typeof queueNames, Queue<StagePayload>>;
  const connections = Array.from(
    { length: 3 },
    () => new Redis(redisUrl, { maxRetriesPerRequest: null, enableReadyCheck: true }),
  );

  const normalizeWorker = new Worker<StagePayload>(
    queueNames.normalize,
    async (job) => {
      const scan = await prisma.scan.findFirst({
        where: { id: job.data.scanId, workspaceId: job.data.workspaceId },
      });
      if (!scan) throw new Error("Scan was not found in its workspace.");
      if (scan.state !== ScanState.NORMALIZING) {
        if (scan.state === ScanState.CORRELATING) return { status: "ALREADY_COMPLETED" };
        throw new Error(`Normalization expected NORMALIZING, observed ${scan.state}.`);
      }
      await markRunning(prisma, job, workerId, ScanState.NORMALIZING);
      if (await cancelRequested(prisma, scan.id)) {
        await cancelStage(prisma, job, ScanState.NORMALIZING);
        return { status: "CANCELLED" };
      }
      const observations = await loadObservations(prisma, job.data);
      const candidates = normalizeObservations(observations);
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.SUCCEEDED,
            completedAt: new Date(),
            result: { observations: observations.length, normalizedCandidates: candidates.length },
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.NORMALIZING } },
          data: {
            status: StageStatus.COMPLETED,
            completedAt: new Date(),
            completedUnits: observations.length,
            totalUnits: observations.length,
            metadata: {
              normalizedCandidates: candidates.length,
              ignoredObservations: observations.length - candidates.length,
            },
          },
        }),
        prisma.scan.update({ where: { id: scan.id }, data: { state: ScanState.CORRELATING } }),
      ]);
      const nextJobId = await enqueue(prisma, queues.correlate, queueNames.correlate, job.data);
      return { observations: observations.length, candidates: candidates.length, nextJobId };
    },
    { connection: connections[0] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  const correlateWorker = new Worker<StagePayload>(
    queueNames.correlate,
    async (job) => {
      const scan = await prisma.scan.findFirst({
        where: { id: job.data.scanId, workspaceId: job.data.workspaceId },
      });
      if (!scan) throw new Error("Scan was not found in its workspace.");
      if (scan.state !== ScanState.CORRELATING) {
        if (scan.state === ScanState.AI_ANALYSIS) return { status: "ALREADY_COMPLETED" };
        throw new Error(`Correlation expected CORRELATING, observed ${scan.state}.`);
      }
      await markRunning(prisma, job, workerId, ScanState.CORRELATING);
      if (await cancelRequested(prisma, scan.id)) {
        await cancelStage(prisma, job, ScanState.CORRELATING);
        return { status: "CANCELLED" };
      }
      const candidates = normalizeObservations(await loadObservations(prisma, job.data));
      const findings = correlateFindings(candidates);
      const persisted = await persistCorrelatedFindings(prisma, job.data, findings);
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.SUCCEEDED,
            completedAt: new Date(),
            result: { candidates: candidates.length, findings: persisted },
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.CORRELATING } },
          data: {
            status: StageStatus.COMPLETED,
            completedAt: new Date(),
            completedUnits: persisted,
            totalUnits: candidates.length,
            metadata: { deduplicatedCandidates: candidates.length - persisted },
          },
        }),
        prisma.scan.update({ where: { id: scan.id }, data: { state: ScanState.AI_ANALYSIS } }),
      ]);
      const nextJobId = await enqueue(prisma, queues.ai, queueNames.ai, job.data);
      return { candidates: candidates.length, findings: persisted, nextJobId };
    },
    { connection: connections[1] as Redis, concurrency: 2, lockDuration: 180_000 },
  );

  const aiWorker = new Worker<StagePayload>(
    queueNames.ai,
    async (job) => {
      const scan = await prisma.scan.findFirst({
        where: { id: job.data.scanId, workspaceId: job.data.workspaceId },
        include: { target: true },
      });
      if (!scan) throw new Error("Scan was not found in its workspace.");
      if (
        scan.state !== ScanState.AI_ANALYSIS &&
        scan.state !== ScanState.AI_ANALYSIS_WAITING_FOR_PROVIDER
      ) {
        if (scan.state === ScanState.GENERATING_SCAN_REPORT) return { status: "ALREADY_COMPLETED" };
        throw new Error(`AI analysis expected AI_ANALYSIS, observed ${scan.state}.`);
      }
      await markRunning(prisma, job, workerId, ScanState.AI_ANALYSIS);
      if (await cancelRequested(prisma, scan.id)) {
        await cancelStage(prisma, job, ScanState.AI_ANALYSIS);
        return { status: "CANCELLED" };
      }
      if (scan.state === ScanState.AI_ANALYSIS_WAITING_FOR_PROVIDER) {
        await prisma.scan.update({
          where: { id: scan.id },
          data: { state: ScanState.AI_ANALYSIS },
        });
      }
      const findings = await prisma.finding.findMany({
        where: { workspaceId: scan.workspaceId, scanId: scan.id },
        include: { evidenceLinks: { include: { evidence: true } } },
        orderBy: { publicId: "asc" },
      });
      if (findings.length === 0) {
        await prisma.$transaction([
          prisma.scanJob.update({
            where: { id: String(job.id ?? "") },
            data: {
              status: JobStatus.SUCCEEDED,
              completedAt: new Date(),
              result: { completed: 0, failed: 0, deterministicFindings: 0 },
            },
          }),
          prisma.scanStage.update({
            where: { scanId_name: { scanId: scan.id, name: ScanState.AI_ANALYSIS } },
            data: {
              status: StageStatus.COMPLETED,
              completedAt: new Date(),
              completedUnits: 0,
              totalUnits: 0,
              metadata: { reason: "No evidence-backed findings required model analysis." },
            },
          }),
          prisma.scan.update({
            where: { id: scan.id },
            data: { state: ScanState.GENERATING_SCAN_REPORT },
          }),
        ]);
        const nextJobId = await enqueue(prisma, queues.report, queueNames.report, job.data);
        return { completed: 0, failed: 0, deterministicFindings: 0, nextJobId };
      }
      const selectedProvider = await providerConfiguration(prisma, scan.workspaceId);
      if (!selectedProvider) {
        await prisma.$transaction([
          prisma.scan.update({
            where: { id: scan.id },
            data: {
              state: ScanState.GENERATING_SCAN_REPORT,
              warningCount: { increment: 1 },
            },
          }),
          prisma.scanStage.update({
            where: { scanId_name: { scanId: scan.id, name: ScanState.AI_ANALYSIS } },
            data: {
              status: StageStatus.DEGRADED,
              completedAt: new Date(),
              completedUnits: 0,
              totalUnits: findings.length,
              errorMessage: "No Qwen provider is configured.",
              metadata: {
                deterministicFindingsPreserved: findings.length,
                modelAnalysisPerformed: false,
              },
            },
          }),
          prisma.scanJob.update({
            where: { id: String(job.id ?? "") },
            data: {
              status: JobStatus.SUCCEEDED,
              completedAt: new Date(),
              lastError: null,
              result: {
                completed: 0,
                failed: 0,
                deterministicFindings: findings.length,
                degraded: true,
              },
            },
          }),
        ]);
        const nextJobId = await enqueue(prisma, queues.report, queueNames.report, job.data);
        return {
          status: "AI_ANALYSIS_DEGRADED",
          deterministicFindings: findings.length,
          nextJobId,
        };
      }
      const client = new QwenClient(selectedProvider.config);
      let completed = 0;
      let failed = 0;
      for (const finding of findings) {
        const analysisInput = buildQwenAnalysisInput({
          targetOrigin: scan.target.origin,
          finding: {
            publicId: finding.publicId,
            title: finding.title,
            category: finding.category,
            severity: finding.severity,
            confidence: finding.confidence,
            cwe: finding.cwe,
            owasp: finding.owasp,
            asset: finding.asset,
            endpoint: finding.endpoint,
            method: finding.method,
            parameter: finding.parameter,
            manualVerificationRequired: finding.manualVerificationRequired,
            scannerSources: finding.scannerSources,
          },
          evidence: finding.evidenceLinks.map(({ evidence }) => evidence),
        });
        const prepared = await upsertAnalysis(prisma, {
          workspaceId: scan.workspaceId,
          scanId: scan.id,
          findingId: finding.id,
          providerId: selectedProvider.id,
          modelName: selectedProvider.config.modelName,
          analysisInput,
        });
        if (prepared.alreadyCompleted) {
          completed += 1;
          await prisma.scanStage.update({
            where: { scanId_name: { scanId: scan.id, name: ScanState.AI_ANALYSIS } },
            data: { completedUnits: completed + failed, totalUnits: findings.length },
          });
          continue;
        }
        const analysis = prepared.analysis;
        const result = await client.analyze(analysisInput);
        if (result.status === "WAITING_FOR_PROVIDER") {
          await prisma.$transaction([
            prisma.aIAnalysis.update({
              where: { id: analysis.id },
              data: {
                status: AIAnalysisStatus.WAITING_FOR_PROVIDER,
                failureReason: result.failureReason,
                latencyMs: result.latencyMs,
                retryCount: result.retryCount,
              },
            }),
            ...(selectedProvider.id
              ? [
                  prisma.modelProvider.update({
                    where: { id: selectedProvider.id },
                    data: { status: ModelProviderStatus.OFFLINE, lastError: result.failureReason },
                  }),
                ]
              : []),
            prisma.scan.update({
              where: { id: scan.id },
              data: { state: ScanState.AI_ANALYSIS_WAITING_FOR_PROVIDER },
            }),
            prisma.scanStage.update({
              where: { scanId_name: { scanId: scan.id, name: ScanState.AI_ANALYSIS } },
              data: {
                status: StageStatus.WAITING,
                completedUnits: completed,
                totalUnits: findings.length,
                errorMessage: result.failureReason.slice(0, 1_000),
              },
            }),
            prisma.scanJob.update({
              where: { id: String(job.id ?? "") },
              data: {
                status: JobStatus.CREATED,
                lastError: result.failureReason.slice(0, 1_000),
                lockedBy: null,
              },
            }),
          ]);
          return {
            status: "WAITING_FOR_PROVIDER",
            deterministicFindings: findings.length,
            analyzed: completed,
          };
        }
        if (result.status === "FAILED") {
          failed += 1;
          await prisma.aIAnalysis.update({
            where: { id: analysis.id },
            data: {
              status: AIAnalysisStatus.FAILED,
              ...(result.rawOutput
                ? { output: { untrustedRawOutput: result.rawOutput } }
                : { output: Prisma.JsonNull }),
              schemaValid: false,
              evidenceValid: false,
              retryCount: result.retryCount,
              failureReason: result.failureReason.slice(0, 4_000),
              latencyMs: result.latencyMs,
            },
          });
        } else {
          completed += 1;
          await applyAnalysis(prisma, finding, result.output);
          await prisma.aIAnalysis.update({
            where: { id: analysis.id },
            data: {
              status: AIAnalysisStatus.COMPLETED,
              output: jsonValue(result.output),
              schemaValid: true,
              evidenceValid: true,
              retryCount: result.retryCount,
              latencyMs: result.latencyMs,
            },
          });
        }
        await prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.AI_ANALYSIS } },
          data: { completedUnits: completed + failed, totalUnits: findings.length },
        });
      }
      await prisma.$transaction([
        prisma.scanJob.update({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.SUCCEEDED,
            completedAt: new Date(),
            result: { completed, failed, deterministicFindings: findings.length },
          },
        }),
        prisma.scanStage.update({
          where: { scanId_name: { scanId: scan.id, name: ScanState.AI_ANALYSIS } },
          data: {
            status: failed > 0 ? StageStatus.DEGRADED : StageStatus.COMPLETED,
            completedAt: new Date(),
            completedUnits: completed + failed,
            totalUnits: findings.length,
            metadata: { completed, failed, deterministicFindingsPreserved: findings.length },
          },
        }),
        prisma.scan.update({
          where: { id: scan.id },
          data: {
            state: ScanState.GENERATING_SCAN_REPORT,
            warningCount: { increment: failed > 0 ? 1 : 0 },
          },
        }),
      ]);
      const nextJobId = await enqueue(prisma, queues.report, queueNames.report, job.data);
      return { completed, failed, deterministicFindings: findings.length, nextJobId };
    },
    { connection: connections[2] as Redis, concurrency: 1, lockDuration: 900_000 },
  );

  attachFailure(normalizeWorker, prisma, ScanState.NORMALIZING);
  attachFailure(correlateWorker, prisma, ScanState.CORRELATING);
  attachAiFailure(aiWorker, prisma, queues.report);

  const queueByName = new Map<string, Queue<StagePayload>>(
    Object.values(queueNames).map((name) => [
      name,
      Object.values(queues).find((queue) => queue.name === name) as Queue<StagePayload>,
    ]),
  );
  const recoveryTimer = setInterval(() => {
    void (async () => {
      const jobs = await prisma.scanJob.findMany({
        where: {
          queue: { in: [...queueByName.keys()] },
          status: { in: [JobStatus.CREATED, JobStatus.QUEUED] },
          updatedAt: { lt: new Date(Date.now() - 30_000) },
        },
        orderBy: { createdAt: "asc" },
        take: 100,
      });
      for (const persisted of jobs) {
        const queue = queueByName.get(persisted.queue);
        if (!queue) continue;
        const existingJob = await queue.getJob(persisted.id);
        if (existingJob) {
          const state = await existingJob.getState();
          if (state === "completed" || state === "failed") {
            await existingJob.remove();
          } else {
            continue;
          }
        }
        const payload = persisted.payload as unknown as StagePayload;
        await queue.add(persisted.queue, payload, {
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
      }
    })().catch((error: unknown) =>
      logger.error("Day 4 outbox recovery failed.", {
        workerId,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
  }, 30_000);
  recoveryTimer.unref();

  return {
    async close(): Promise<void> {
      clearInterval(recoveryTimer);
      await Promise.all([normalizeWorker.close(), correlateWorker.close(), aiWorker.close()]);
      await Promise.all(Object.values(queues).map((queue) => queue.close()));
      await Promise.all(connections.map((connection) => connection.quit()));
      await publisher.quit();
    },
  };
}
