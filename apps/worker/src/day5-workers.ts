import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { Prisma, PrismaClient } from "@aasp/database";
import {
  AIAnalysisStatus,
  JobStatus,
  ReportStatus,
  ReportType,
  ScanState,
  StageStatus,
} from "@aasp/database";
import { logger } from "@aasp/logger";
import {
  generateCompleteScanReport,
  generateVulnerabilityReport,
  type ReportFinding,
  type ScanReportInput,
} from "@aasp/report-engine";
import { Queue, Worker, type Job } from "bullmq";
import { Redis } from "ioredis";

interface ReportPayload {
  workspaceId: string;
  scanId: string;
}

interface WorkerContext {
  prisma: PrismaClient;
  redisUrl: string;
  workerId: string;
}

export interface Day5WorkerRuntime {
  close(): Promise<void>;
}

const reportQueueName = "scan.report";

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function iso(value: Date | null): string | null {
  return value?.toISOString() ?? null;
}

function analysisContext(output: Prisma.JsonValue | null): {
  likelyFalsePositive: boolean | null;
  reasoningSummary: string | null;
} {
  if (!output || Array.isArray(output) || typeof output !== "object") {
    return { likelyFalsePositive: null, reasoningSummary: null };
  }
  const record = output as Record<string, Prisma.JsonValue>;
  return {
    likelyFalsePositive:
      typeof record["likely_false_positive"] === "boolean" ? record["likely_false_positive"] : null,
    reasoningSummary:
      typeof record["reasoning_summary"] === "string" ? record["reasoning_summary"] : null,
  };
}

async function atomicWrite(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, value, { encoding: "utf8", mode: 0o640 });
  await rename(temporary, path);
}

async function persistReport(
  prisma: PrismaClient,
  input: {
    workspaceId: string;
    scanId: string;
    findingId?: string;
    type: ReportType;
    path: string;
    sha256: string;
  },
): Promise<string> {
  const existing = await prisma.report.findFirst({
    where: {
      workspaceId: input.workspaceId,
      scanId: input.scanId,
      type: input.type,
      findingId: input.findingId ?? null,
    },
  });
  const data = {
    path: input.path,
    sha256: input.sha256,
    status: ReportStatus.GENERATED,
    generatedAt: new Date(),
    errorMessage: null,
  } as const;
  if (existing) {
    const updated = await prisma.report.update({ where: { id: existing.id }, data });
    return updated.id;
  }
  const created = await prisma.report.create({
    data: {
      workspaceId: input.workspaceId,
      scanId: input.scanId,
      findingId: input.findingId ?? null,
      type: input.type,
      ...data,
    },
  });
  return created.id;
}

async function buildInput(prisma: PrismaClient, payload: ReportPayload): Promise<ScanReportInput> {
  const scan = await prisma.scan.findFirst({
    where: { id: payload.scanId, workspaceId: payload.workspaceId },
    include: {
      workspace: true,
      target: { include: { scopeRules: true } },
      config: true,
      stages: { orderBy: { createdAt: "asc" } },
      assets: { orderBy: { value: "asc" } },
      urls: { orderBy: { canonicalUrl: "asc" } },
      endpoints: { include: { parameters: true }, orderBy: [{ asset: "asc" }, { path: "asc" }] },
      technologies: { orderBy: { technology: "asc" } },
      observations: { select: { scanner: true } },
      findings: {
        orderBy: { publicId: "asc" },
        include: {
          evidenceLinks: { include: { evidence: true } },
          aiAnalyses: {
            where: {
              status: AIAnalysisStatus.COMPLETED,
              schemaValid: true,
              evidenceValid: true,
            },
            orderBy: { updatedAt: "desc" },
            take: 1,
          },
        },
      },
    },
  });
  if (!scan || !scan.config) throw new Error("Scan report input was not found in its workspace.");

  const evidence = await prisma.evidence.findMany({
    where: { workspaceId: payload.workspaceId, scanId: payload.scanId },
    select: { requestMetadata: true },
  });
  const findings: ReportFinding[] = scan.findings.map((finding) => {
    const context = analysisContext(finding.aiAnalyses[0]?.output ?? null);
    return {
      id: finding.publicId,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      status: finding.status,
      cwe: finding.cwe,
      owasp: finding.owasp,
      asset: finding.asset,
      endpoint: finding.endpoint,
      method: finding.method,
      parameter: finding.parameter,
      description: finding.description,
      technicalImpact: finding.technicalImpact,
      businessImpact: finding.businessImpact,
      scannerSources: finding.scannerSources,
      remediation: finding.remediation,
      manualVerificationRequired: finding.manualVerificationRequired,
      ...context,
      firstSeen: finding.firstSeen.toISOString(),
      lastSeen: finding.lastSeen.toISOString(),
      evidence: finding.evidenceLinks.map(({ evidence: item }) => ({
        id: item.id,
        timestamp: item.timestamp.toISOString(),
        source: item.source,
        asset: item.asset,
        requestMetadata: item.requestMetadata,
        responseMetadata: item.responseMetadata,
        redactedExcerpt: item.redactedExcerpt,
        hash: item.hash,
      })),
    };
  });
  const configuration = {
    profile: scan.config.profile,
    crawlDepth: scan.config.crawlDepth,
    maxUrls: scan.config.maxUrls,
    maxRequests: scan.config.maxRequests,
    requestsPerSecond: scan.config.requestsPerSecond,
    concurrency: scan.config.concurrency,
    timeoutMs: scan.config.timeoutMs,
    followRedirects: scan.config.followRedirects,
    includeSubdomains: scan.config.includeSubdomains,
  };
  return {
    scan: {
      id: scan.id,
      name: scan.name,
      state: scan.state,
      createdAt: scan.createdAt.toISOString(),
      startedAt: iso(scan.startedAt),
      completedAt: iso(scan.completedAt),
      warningCount: scan.warningCount,
    },
    workspace: { id: scan.workspace.id, name: scan.workspace.name },
    target: {
      name: scan.target.name,
      origin: scan.target.origin,
      status: scan.target.status,
      scopeConfiguredAt: scan.target.updatedAt.toISOString(),
    },
    scopeRules: [
      ...scan.target.scopeRules.map((rule) => ({
        type: rule.type,
        value: rule.value,
        enabled: rule.enabled,
      })),
      {
        type: "INCLUDE_SUBDOMAINS",
        value: scan.target.includeSubdomains ? "true" : "false",
        enabled: true,
      },
      {
        type: "ALLOW_PRIVATE_NETWORK",
        value: scan.target.allowPrivateNetwork ? "true" : "false",
        enabled: true,
      },
    ],
    config: configuration,
    stages: scan.stages.map((stage) => ({
      name: stage.name,
      status: stage.status,
      startedAt: iso(stage.startedAt),
      completedAt: iso(stage.completedAt),
      completedUnits: stage.completedUnits,
      totalUnits: stage.totalUnits,
      errorMessage: stage.errorMessage,
    })),
    assets: scan.assets.map((asset) => ({
      assetType: asset.assetType,
      value: asset.value,
      firstSeenAt: asset.firstSeenAt.toISOString(),
      lastSeenAt: asset.lastSeenAt.toISOString(),
    })),
    urls: scan.urls.map((url) => ({
      canonicalUrl: url.canonicalUrl,
      depth: url.depth,
      statusCode: url.statusCode,
      contentType: url.contentType,
    })),
    endpoints: scan.endpoints.map((endpoint) => ({
      asset: endpoint.asset,
      path: endpoint.path,
      method: endpoint.method,
      source: endpoint.source,
      parameters: endpoint.parameters.map((parameter) => ({
        name: parameter.name,
        location: parameter.location,
        observedType: parameter.observedType,
      })),
    })),
    technologies: scan.technologies.map((technology) => ({
      technology: technology.technology,
      possibleVersion: technology.possibleVersion,
      confidence: technology.confidence,
      evidenceIds: technology.evidenceIds,
    })),
    findings,
    scannerSources: [...new Set(scan.observations.map(({ scanner }) => scanner))].sort(),
    requestsPerformed: evidence.filter(({ requestMetadata }) => {
      return (
        requestMetadata !== null &&
        typeof requestMetadata === "object" &&
        !Array.isArray(requestMetadata) &&
        typeof (requestMetadata as Record<string, Prisma.JsonValue>)["method"] === "string"
      );
    }).length,
    failedOrDegradedStages: scan.stages
      .filter(({ status }) => status === StageStatus.FAILED || status === StageStatus.DEGRADED)
      .map((stage) => ({
        name: stage.name,
        status: stage.status,
        errorMessage: stage.errorMessage,
      })),
    generatedAt: new Date().toISOString(),
  };
}

async function processReport(
  prisma: PrismaClient,
  workerId: string,
  job: Job<ReportPayload>,
): Promise<{ reports: number; reportDirectory: string }> {
  const { workspaceId, scanId } = job.data;
  const scan = await prisma.scan.findFirst({ where: { id: scanId, workspaceId } });
  if (!scan) throw new Error("Scan was not found in its workspace.");
  if (scan.state === ScanState.COMPLETED || scan.state === ScanState.COMPLETED_WITH_WARNINGS) {
    return {
      reports: await prisma.report.count({ where: { workspaceId, scanId } }),
      reportDirectory: scanId,
    };
  }
  if (
    scan.state !== ScanState.GENERATING_SCAN_REPORT &&
    scan.state !== ScanState.GENERATING_VULNERABILITY_REPORTS
  ) {
    throw new Error(`Report generation expected a report state, observed ${scan.state}.`);
  }
  const jobId = String(job.id ?? "");
  await prisma.$transaction([
    prisma.scanJob.update({
      where: { id: jobId },
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
      where: { scanId_name: { scanId, name: ScanState.GENERATING_SCAN_REPORT } },
      data: { status: StageStatus.RUNNING, startedAt: new Date(), errorMessage: null },
    }),
  ]);

  const cancellation = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { cancelRequestedAt: true },
  });
  if (cancellation?.cancelRequestedAt) {
    const completedAt = new Date();
    await prisma.$transaction([
      prisma.scan.update({
        where: { id: scanId },
        data: { state: ScanState.CANCELLED, completedAt },
      }),
      prisma.scanStage.update({
        where: { scanId_name: { scanId, name: ScanState.GENERATING_SCAN_REPORT } },
        data: { status: StageStatus.CANCELLED, completedAt },
      }),
      prisma.scanJob.update({
        where: { id: jobId },
        data: { status: JobStatus.CANCELLED, completedAt },
      }),
    ]);
    return { reports: 0, reportDirectory: "CANCELLED" };
  }

  const input = await buildInput(prisma, job.data);
  if (input.findings.some(({ evidence }) => evidence.length === 0)) {
    throw new Error("Report generation refused a finding without persisted evidence.");
  }
  const reportsRoot = resolve(process.env["REPORTS_ROOT"] ?? "../../reports");
  const scanDirectory = resolve(reportsRoot, scanId);
  const complete = generateCompleteScanReport(input);
  const completePath = resolve(scanDirectory, "scan-report.html");
  const completeJsonPath = resolve(scanDirectory, "scan-report.json");
  const pdfReadyPath = resolve(scanDirectory, "scan-report.pdf-ready.html");
  await Promise.all([
    atomicWrite(completePath, complete.html),
    atomicWrite(completeJsonPath, `${JSON.stringify(complete.document, null, 2)}\n`),
    atomicWrite(pdfReadyPath, complete.pdfReadyHtml),
  ]);
  await Promise.all([
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.COMPLETE_SCAN,
      path: completePath,
      sha256: complete.sha256,
    }),
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.COMPLETE_SCAN_PDF_READY,
      path: pdfReadyPath,
      sha256: complete.pdfReadySha256,
    }),
  ]);
  await prisma.$transaction([
    prisma.scanStage.update({
      where: { scanId_name: { scanId, name: ScanState.GENERATING_SCAN_REPORT } },
      data: {
        status: StageStatus.COMPLETED,
        completedAt: new Date(),
        completedUnits: 1,
        totalUnits: 1,
      },
    }),
    prisma.scan.update({
      where: { id: scanId },
      data: { state: ScanState.GENERATING_VULNERABILITY_REPORTS },
    }),
    prisma.scanStage.update({
      where: { scanId_name: { scanId, name: ScanState.GENERATING_VULNERABILITY_REPORTS } },
      data: {
        status: StageStatus.RUNNING,
        startedAt: new Date(),
        totalUnits: input.findings.length,
        completedUnits: 0,
      },
    }),
  ]);

  let generated = 2;
  for (const [index, finding] of input.findings.entries()) {
    const cancelRequestedAt = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { cancelRequestedAt: true },
    });
    if (cancelRequestedAt?.cancelRequestedAt) {
      const completedAt = new Date();
      await prisma.$transaction([
        prisma.scan.update({
          where: { id: scanId },
          data: { state: ScanState.CANCELLED, completedAt },
        }),
        prisma.scanStage.update({
          where: {
            scanId_name: { scanId, name: ScanState.GENERATING_VULNERABILITY_REPORTS },
          },
          data: { status: StageStatus.CANCELLED, completedAt },
        }),
        prisma.scanJob.update({
          where: { id: jobId },
          data: { status: JobStatus.CANCELLED, completedAt },
        }),
      ]);
      return { reports: generated, reportDirectory: scanDirectory };
    }
    const vulnerability = generateVulnerabilityReport({
      scan: input.scan,
      workspace: input.workspace,
      target: input.target,
      generatedAt: input.generatedAt,
      finding,
    });
    const base = resolve(scanDirectory, "findings", finding.id);
    const htmlPath = `${base}.html`;
    await Promise.all([
      atomicWrite(htmlPath, vulnerability.html),
      atomicWrite(`${base}.json`, `${JSON.stringify(vulnerability.document, null, 2)}\n`),
    ]);
    const persistedFinding = await prisma.finding.findFirst({
      where: { workspaceId, scanId, publicId: finding.id },
      select: { id: true },
    });
    if (!persistedFinding) throw new Error(`Finding ${finding.id} was removed during reporting.`);
    await persistReport(prisma, {
      workspaceId,
      scanId,
      findingId: persistedFinding.id,
      type: ReportType.VULNERABILITY,
      path: htmlPath,
      sha256: vulnerability.sha256,
    });
    generated += 1;
    await prisma.scanStage.update({
      where: { scanId_name: { scanId, name: ScanState.GENERATING_VULNERABILITY_REPORTS } },
      data: { completedUnits: index + 1 },
    });
  }

  const completedAt = new Date();
  const finalState =
    scan.warningCount > 0 || input.failedOrDegradedStages.length > 0
      ? ScanState.COMPLETED_WITH_WARNINGS
      : ScanState.COMPLETED;

  // Refresh the documents only after every report has been written once. The
  // published snapshot can then carry the actual terminal state and completed
  // report-stage units without exposing synthetic progress during execution.
  const latestInput = await buildInput(prisma, job.data);
  const finalizedInput: ScanReportInput = {
    ...latestInput,
    generatedAt: completedAt.toISOString(),
    scan: {
      ...latestInput.scan,
      state: finalState,
      completedAt: completedAt.toISOString(),
    },
    stages: latestInput.stages.map((stage) =>
      stage.name === ScanState.GENERATING_VULNERABILITY_REPORTS
        ? {
            ...stage,
            status: StageStatus.COMPLETED,
            completedAt: completedAt.toISOString(),
            completedUnits: latestInput.findings.length,
            totalUnits: latestInput.findings.length,
          }
        : stage,
    ),
  };
  const finalizedComplete = generateCompleteScanReport(finalizedInput);
  await Promise.all([
    atomicWrite(completePath, finalizedComplete.html),
    atomicWrite(completeJsonPath, `${JSON.stringify(finalizedComplete.document, null, 2)}\n`),
    atomicWrite(pdfReadyPath, finalizedComplete.pdfReadyHtml),
  ]);
  await Promise.all([
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.COMPLETE_SCAN,
      path: completePath,
      sha256: finalizedComplete.sha256,
    }),
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.COMPLETE_SCAN_PDF_READY,
      path: pdfReadyPath,
      sha256: finalizedComplete.pdfReadySha256,
    }),
  ]);
  for (const finding of finalizedInput.findings) {
    const vulnerability = generateVulnerabilityReport({
      scan: finalizedInput.scan,
      workspace: finalizedInput.workspace,
      target: finalizedInput.target,
      generatedAt: finalizedInput.generatedAt,
      finding,
    });
    const base = resolve(scanDirectory, "findings", finding.id);
    const htmlPath = `${base}.html`;
    await Promise.all([
      atomicWrite(htmlPath, vulnerability.html),
      atomicWrite(`${base}.json`, `${JSON.stringify(vulnerability.document, null, 2)}\n`),
    ]);
    const persistedFinding = await prisma.finding.findFirst({
      where: { workspaceId, scanId, publicId: finding.id },
      select: { id: true },
    });
    if (!persistedFinding) throw new Error(`Finding ${finding.id} was removed during reporting.`);
    await persistReport(prisma, {
      workspaceId,
      scanId,
      findingId: persistedFinding.id,
      type: ReportType.VULNERABILITY,
      path: htmlPath,
      sha256: vulnerability.sha256,
    });
  }
  await prisma.$transaction([
    prisma.scanStage.update({
      where: { scanId_name: { scanId, name: ScanState.GENERATING_VULNERABILITY_REPORTS } },
      data: {
        status: StageStatus.COMPLETED,
        completedAt,
        completedUnits: input.findings.length,
        totalUnits: input.findings.length,
      },
    }),
    prisma.scan.update({
      where: { id: scanId },
      data: { state: finalState, completedAt, failureReason: null },
    }),
    prisma.scanJob.update({
      where: { id: jobId },
      data: {
        status: JobStatus.SUCCEEDED,
        completedAt,
        result: jsonValue({ reports: generated, reportDirectory: scanDirectory }),
      },
    }),
    prisma.auditEvent.create({
      data: {
        workspaceId,
        action: "scan.reports.generated",
        resourceType: "Scan",
        resourceId: scanId,
        metadata: jsonValue({ reports: generated, finalState }),
      },
    }),
    prisma.auditEvent.create({
      data: {
        workspaceId,
        action: "scan.completed",
        resourceType: "Scan",
        resourceId: scanId,
        metadata: jsonValue({ state: finalState, warningCount: scan.warningCount }),
      },
    }),
  ]);
  logger.info("Evidence-backed reports generated.", {
    workspaceId,
    scanId,
    jobId,
    workerId,
    reports: generated,
  });
  return { reports: generated, reportDirectory: scanDirectory };
}

export function startDay5Workers(context: WorkerContext): Day5WorkerRuntime {
  const connection = new Redis(context.redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
  });
  const worker = new Worker<ReportPayload>(
    reportQueueName,
    (job) => processReport(context.prisma, context.workerId, job),
    { connection, concurrency: 1, lockDuration: 300_000 },
  );
  const publisher = new Redis(context.redisUrl, {
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
  });
  const reportQueue = new Queue<ReportPayload>(reportQueueName, { connection: publisher });
  worker.on("failed", (job, error) => {
    if (!job || job.attemptsMade < (job.opts.attempts ?? 1)) return;
    void context.prisma
      .$transaction([
        context.prisma.scan.updateMany({
          where: {
            id: job.data.scanId,
            workspaceId: job.data.workspaceId,
            state: {
              notIn: [ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS, ScanState.CANCELLED],
            },
          },
          data: { state: ScanState.FAILED, failureReason: error.message.slice(0, 1_000) },
        }),
        context.prisma.scanStage.updateMany({
          where: {
            scanId: job.data.scanId,
            workspaceId: job.data.workspaceId,
            name: {
              in: [ScanState.GENERATING_SCAN_REPORT, ScanState.GENERATING_VULNERABILITY_REPORTS],
            },
            status: { in: [StageStatus.QUEUED, StageStatus.RUNNING] },
          },
          data: {
            status: StageStatus.FAILED,
            completedAt: new Date(),
            errorMessage: error.message.slice(0, 1_000),
          },
        }),
        context.prisma.scanJob.updateMany({
          where: { id: String(job.id ?? "") },
          data: {
            status: JobStatus.FAILED,
            completedAt: new Date(),
            lastError: error.message.slice(0, 1_000),
          },
        }),
      ])
      .catch((persistenceError: unknown) => {
        logger.error("Failed to persist report worker failure.", {
          scanId: job.data.scanId,
          error:
            persistenceError instanceof Error ? persistenceError.message : String(persistenceError),
        });
      });
  });

  const recoveryTimer = setInterval(() => {
    void (async () => {
      const jobs = await context.prisma.scanJob.findMany({
        where: {
          queue: reportQueueName,
          status: JobStatus.CREATED,
          updatedAt: { lt: new Date(Date.now() - 30_000) },
        },
        take: 100,
        orderBy: { createdAt: "asc" },
      });
      for (const persisted of jobs) {
        const payload = persisted.payload as unknown as ReportPayload;
        await reportQueue.add(reportQueueName, payload, {
          jobId: persisted.id,
          attempts: persisted.maxAttempts,
          backoff: { type: "exponential", delay: 2_000 },
        });
        await context.prisma.scanJob.update({
          where: { id: persisted.id },
          data: { status: JobStatus.QUEUED, bullJobId: persisted.id },
        });
      }
    })().catch((error: unknown) => {
      logger.error("Report outbox recovery failed.", {
        error: error instanceof Error ? error.message : String(error),
      });
    });
  }, 10_000);
  recoveryTimer.unref();

  return {
    async close(): Promise<void> {
      clearInterval(recoveryTimer);
      await worker.close();
      await reportQueue.close();
      await connection.quit();
      await publisher.quit();
    },
  };
}
