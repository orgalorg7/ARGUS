import { Readable } from "node:stream";
import { readVerifiedReport } from "./report-store.js";
import { authorizeScanQueue, requirePermission, GovernanceError } from "@aasp/engagement-engine";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import {
  JobStatus,
  Prisma,
  ScanState as DatabaseScanState,
  StageStatus,
  type ScanProfile,
} from "@aasp/database";
import {
  scanConfigSchema,
  scanProfileDefaults,
  type ScanConfigInput,
  type ScanState,
} from "@aasp/schemas";
import { scopePolicyFromTarget } from "@aasp/scope-engine";
import { assertScanTransition, assertTargetReadyForScan } from "@aasp/security-core";
import { AuditService } from "../audit/audit.service.js";
import { PrismaService } from "../database/prisma.service.js";
import { QueuePublisherService, orchestrationQueueName } from "../queue/queue-publisher.service.js";

const pipelineStages: ScanState[] = [
  "VALIDATING_SCOPE",
  "DISCOVERY",
  "CRAWLING",
  "API_DISCOVERY",
  "FINGERPRINTING",
  "PASSIVE_ANALYSIS",
  "SAFE_ACTIVE_ANALYSIS",
  "AUTHORIZATION_ANALYSIS",
  "NORMALIZING",
  "CORRELATING",
  "AI_ANALYSIS",
  "GENERATING_SCAN_REPORT",
  "GENERATING_VULNERABILITY_REPORTS",
];

export function resolveStoredReportPath(
  reportsRootInput: string,
  storedPath: string,
  format: "html" | "json" | "pdf-ready",
  reportType:
    | "EXECUTIVE"
    | "EXECUTIVE_PDF_READY"
    | "COMPLETE_SCAN"
    | "COMPLETE_SCAN_PDF_READY"
    | "VULNERABILITY",
): string {
  if (!["html", "json", "pdf-ready"].includes(format)) {
    throw new BadRequestException("Unsupported report format.");
  }
  let requestedPath = storedPath;
  if (format === "json") {
    requestedPath = storedPath.replace(/(?:\.pdf-ready)?\.html$/u, ".json");
  } else if (format === "pdf-ready") {
    if (reportType === "VULNERABILITY") {
      throw new BadRequestException("PDF-ready output is available for complete scan reports.");
    }
    requestedPath = resolve(
      dirname(storedPath),
      reportType.startsWith("EXECUTIVE")
        ? "executive-report.pdf-ready.html"
        : "scan-report.pdf-ready.html",
    );
  }
  const reportsRoot = resolve(reportsRootInput);
  const absolutePath = resolve(requestedPath);
  const relativePath = relative(reportsRoot, absolutePath);
  if (relativePath.startsWith("..") || isAbsolute(relativePath)) {
    throw new NotFoundException("Report path is outside the configured report store.");
  }
  return absolutePath;
}

@Injectable()
export class ScansService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly publisher: QueuePublisherService,
  ) {}

  list(workspaceId: string) {
    return this.prisma.scan.findMany({
      where: { workspaceId },
      include: { target: true, config: true },
      orderBy: { createdAt: "desc" },
    });
  }

  async get(workspaceId: string, scanId: string) {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, workspaceId },
      include: { target: true, config: true, stages: { orderBy: { createdAt: "asc" } } },
    });
    if (!scan) throw new NotFoundException("Scan does not exist in this workspace.");
    return scan;
  }

  async assets(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    return this.prisma.discoveredAsset.findMany({
      where: { workspaceId, scanId },
      orderBy: [{ assetType: "asc" }, { value: "asc" }],
    });
  }

  async urls(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    return this.prisma.discoveredURL.findMany({
      where: { workspaceId, scanId },
      orderBy: [{ depth: "asc" }, { canonicalUrl: "asc" }],
    });
  }

  async endpoints(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    return this.prisma.discoveredEndpoint.findMany({
      where: { workspaceId, scanId },
      include: { parameters: { orderBy: [{ location: "asc" }, { name: "asc" }] } },
      orderBy: [{ asset: "asc" }, { path: "asc" }, { method: "asc" }],
    });
  }

  async technologies(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    return this.prisma.technology.findMany({
      where: { workspaceId, scanId },
      orderBy: [{ technology: "asc" }, { confidence: "desc" }],
    });
  }

  async evidence(workspaceId: string, scanId: string, actorId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    await this.audit.record({
      workspaceId,
      actorId,
      action: "evidence.read",
      resourceType: "Scan",
      resourceId: scanId,
    });
    return this.prisma.evidence.findMany({
      where: { workspaceId, scanId },
      orderBy: { timestamp: "asc" },
    });
  }

  async findings(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId, scanId },
      include: {
        evidenceLinks: { select: { evidenceId: true } },
        _count: { select: { occurrences: true, aiAnalyses: true } },
      },
      orderBy: { publicId: "asc" },
    });
    const rank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;
    return findings.sort(
      (left, right) =>
        rank[right.severity] - rank[left.severity] || left.publicId.localeCompare(right.publicId),
    );
  }

  async assessmentSummary(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    const [findings, comparison, analyses, provider, urls, endpoints, evidence] = await Promise.all(
      [
        this.prisma.finding.findMany({
          where: { workspaceId, scanId },
          select: {
            severity: true,
            trendStatus: true,
            remediationPriority: true,
            asset: true,
          },
        }),
        this.prisma.scanComparison.findUnique({
          where: { scanId },
          include: {
            findings: {
              where: { trendStatus: { in: ["RESOLVED", "UNVERIFIED"] } },
              include: {
                previousFinding: { select: { publicId: true, title: true, severity: true } },
              },
            },
          },
        }),
        this.prisma.aIAnalysis.findMany({
          where: { workspaceId, scanId },
          select: { findingId: true, status: true, schemaValid: true, evidenceValid: true },
        }),
        this.prisma.modelProvider.findFirst({
          where: { OR: [{ workspaceId }, { workspaceId: null }] },
          select: { id: true },
        }),
        this.prisma.discoveredURL.count({ where: { workspaceId, scanId } }),
        this.prisma.discoveredEndpoint.count({ where: { workspaceId, scanId } }),
        this.prisma.evidence.count({ where: { workspaceId, scanId } }),
      ],
    );
    const validatedAnalyses = new Set(
      analyses
        .filter(
          ({ findingId, status, schemaValid, evidenceValid }) =>
            findingId && status === "COMPLETED" && schemaValid === true && evidenceValid === true,
        )
        .map(({ findingId }) => findingId),
    ).size;
    const qwenStatus = !provider
      ? "NOT_CONFIGURED"
      : findings.length === 0 || analyses.length === 0
        ? "NOT_RUN"
        : validatedAnalyses === findings.length
          ? "COMPLETED"
          : validatedAnalyses > 0
            ? "PARTIAL"
            : "FAILED_OR_WAITING";
    return {
      severityCounts: Object.fromEntries(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((severity) => [
          severity,
          findings.filter((finding) => finding.severity === severity).length,
        ]),
      ),
      trendCounts: Object.fromEntries(
        ["NEW", "RECURRING", "RESOLVED", "REGRESSED", "CHANGED", "UNVERIFIED"].map((trend) => [
          trend,
          trend === "RESOLVED" || trend === "UNVERIFIED"
            ? (comparison?.findings.filter((finding) => finding.trendStatus === trend).length ?? 0)
            : findings.filter((finding) => finding.trendStatus === trend).length,
        ]),
      ),
      priorityCounts: Object.fromEntries(
        ["FIX_NOW", "FIX_NEXT", "PLANNED", "HARDENING"].map((priority) => [
          priority,
          findings.filter((finding) => finding.remediationPriority === priority).length,
        ]),
      ),
      comparison: comparison
        ? {
            previousScanId: comparison.previousScanId,
            coverageSufficient: comparison.coverageSufficient,
            coverageRatio: comparison.coverageRatio,
            summary: comparison.summary,
            unresolvedPriorFindings: comparison.findings.map((finding) => ({
              trendStatus: finding.trendStatus,
              reason: finding.reason,
              finding: finding.previousFinding,
            })),
          }
        : null,
      coverage: { urls, endpoints, evidence },
      qwenAnalysis: {
        status: qwenStatus,
        totalFindings: findings.length,
        validatedAnalyses,
        failedOrWaitingAnalyses: Math.max(0, findings.length - validatedAnalyses),
      },
    };
  }

  async finding(workspaceId: string, scanId: string, findingId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    const finding = await this.prisma.finding.findFirst({
      where: {
        workspaceId,
        scanId,
        OR: [{ id: findingId }, { publicId: findingId }],
      },
      include: {
        evidenceLinks: { include: { evidence: true } },
        occurrences: { include: { observation: true } },
        aiAnalyses: { orderBy: { createdAt: "desc" } },
        history: { orderBy: { createdAt: "asc" } },
      },
    });
    if (!finding) throw new NotFoundException("Finding does not exist in this workspace scan.");
    return finding;
  }

  async reports(workspaceId: string, scanId: string) {
    await this.assertWorkspaceScan(workspaceId, scanId);
    return this.prisma.report.findMany({
      where: { workspaceId, scanId },
      include: { finding: { select: { publicId: true, title: true, severity: true } } },
      orderBy: [{ type: "asc" }, { createdAt: "asc" }],
    });
  }

  async reportFile(
    workspaceId: string,
    scanId: string,
    reportId: string,
    actorId: string,
    format: "html" | "json" | "pdf-ready" = "html",
  ) {
    const report = await this.prisma.report.findFirst({
      where: { id: reportId, workspaceId, scanId, status: "GENERATED" },
    });
    if (!report?.path) throw new NotFoundException("Generated report file was not found.");
    const reportsRoot = resolve(process.env["REPORTS_ROOT"] ?? "../../reports");
    const absolutePath = resolveStoredReportPath(reportsRoot, report.path, format, report.type);
    const artifact =
      format === "pdf-ready"
        ? await this.prisma.report.findFirst({
            where: { workspaceId, scanId, path: absolutePath, status: "GENERATED" },
          })
        : report;
    const content = await readVerifiedReport(
      reportsRoot,
      absolutePath,
      format === "json" ? report.jsonSha256 : (artifact?.sha256 ?? null),
    );
    await this.audit.record({
      workspaceId,
      actorId,
      action: "report.downloaded",
      resourceType: "Report",
      resourceId: report.id,
      metadata: { format },
    });
    return {
      stream: Readable.from(content),
      contentType:
        format === "json" ? "application/json; charset=utf-8" : "text/html; charset=utf-8",
      filename: basename(absolutePath),
    };
  }

  private async assertWorkspaceScan(workspaceId: string, scanId: string): Promise<void> {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, workspaceId },
      select: { id: true },
    });
    if (!scan) throw new NotFoundException("Scan does not exist in this workspace.");
  }

  async create(
    workspaceId: string,
    actorId: string,
    input: {
      targetId: string;
      engagementId: string;
      name: string;
      config?: Partial<ScanConfigInput>;
      profile: ScanProfile;
    },
  ) {
    await requirePermission(this.prisma, { workspaceId, userId: actorId }, "test.execute.safe");
    const engagement = await this.prisma.engagement.findFirst({
      where: { id: input.engagementId, workspaceId },
    });
    if (!engagement) throw new NotFoundException("Engagement does not exist in this workspace.");
    const assigned = await this.prisma.engagementTarget.findFirst({
      where: {
        workspaceId,
        engagementId: engagement.id,
        policyRevision: engagement.policyRevision,
        targetId: input.targetId,
      },
    });
    if (!assigned)
      throw new ConflictException("Target is not assigned to the current engagement scope.");
    const target = await this.prisma.target.findFirst({
      where: { id: input.targetId, workspaceId },
      include: { scopeRules: { where: { enabled: true } } },
    });
    if (!target) throw new NotFoundException("Target does not exist in this workspace.");
    try {
      assertTargetReadyForScan(target);
      scopePolicyFromTarget(target);
    } catch {
      throw new ConflictException("The target must be enabled with a valid saved scope.");
    }

    const defaults = scanProfileDefaults[input.profile];
    const config = scanConfigSchema.parse({
      ...defaults,
      ...input.config,
      scanProfile: input.profile,
    });
    const scan = await this.prisma.scan.create({
      data: {
        workspaceId,
        targetId: target.id,
        engagementId: engagement.id,
        createdById: actorId,
        name: input.name.trim(),
        state: DatabaseScanState.CREATED,
        config: {
          create: {
            profile: input.profile,
            crawlDepth: config.crawlDepth,
            maxUrls: config.maxUrls,
            maxRequests: config.maxRequests,
            requestsPerSecond: config.requestsPerSecond,
            concurrency: config.concurrency,
            timeoutMs: config.timeoutMs,
            followRedirects: config.followRedirects,
            includeSubdomains: target.includeSubdomains,
          },
        },
        stages: {
          create: pipelineStages.map((name) => ({
            name: name as DatabaseScanState,
            status: StageStatus.QUEUED,
          })),
        },
      },
      include: { config: true, stages: true },
    });
    await this.audit.record({
      workspaceId,
      actorId,
      action: "scan.created",
      resourceType: "Scan",
      resourceId: scan.id,
      metadata: { targetId: target.id, profile: input.profile },
    });
    return scan;
  }

  async start(workspaceId: string, scanId: string, actorId: string) {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, workspaceId },
      include: { target: { include: { scopeRules: { where: { enabled: true } } } } },
    });
    if (!scan) throw new NotFoundException("Scan does not exist in this workspace.");
    try {
      assertTargetReadyForScan(scan.target);
      scopePolicyFromTarget(scan.target);
    } catch {
      throw new ConflictException("Target is disabled, busy, or has an invalid saved scope.");
    }
    assertScanTransition(scan.state as ScanState, "QUEUED");
    const idempotencyKey = `orchestrate:${scan.id}:v1`;
    const queued = await this.prisma.$transaction(async (transaction) => {
      const authorization = await authorizeScanQueue(
        transaction,
        { workspaceId, userId: actorId },
        scan.id,
        scan.target.origin,
      );
      if (!authorization.decision.permitted) return { denial: authorization.decision.code };
      const reservedTarget = await transaction.target.updateMany({
        where: {
          id: scan.targetId,
          workspaceId,
          status: { in: ["READY", "COMPLETED", "FAILED", "CANCELLED"] },
        },
        data: { status: "SCANNING" },
      });
      if (reservedTarget.count !== 1) {
        throw new ConflictException("Target is no longer available to start this assessment.");
      }
      const updated = await transaction.scan.updateMany({
        where: { id: scan.id, workspaceId, state: DatabaseScanState.CREATED },
        data: { state: DatabaseScanState.QUEUED, queuedAt: new Date() },
      });
      if (updated.count !== 1)
        throw new ConflictException("Scan has already been started or changed state.");
      const job = await transaction.scanJob.upsert({
        where: { idempotencyKey },
        create: {
          workspaceId,
          scanId: scan.id,
          queue: orchestrationQueueName,
          idempotencyKey,
          status: JobStatus.CREATED,
          payload: { workspaceId, scanId: scan.id },
        },
        update: {},
      });
      await transaction.auditEvent.create({
        data: {
          workspaceId,
          actorId,
          action: "scan.queued",
          resourceType: "Scan",
          resourceId: scan.id,
          metadata: { persistedJobId: job.id },
        },
      });
      return { job, scanId: scan.id };
    });

    if ("denial" in queued) throw new GovernanceError(403, queued.denial ?? "EXECUTION_DENIED");
    const published = await this.publisher.publish(queued.job.id, { workspaceId, scanId: scan.id });
    if (published) {
      await this.prisma.scanJob.updateMany({
        where: { id: queued.job.id, workspaceId, status: JobStatus.CREATED },
        data: { status: JobStatus.QUEUED, bullJobId: queued.job.id },
      });
    } else {
      await this.audit.record({
        workspaceId,
        actorId,
        action: "scan.queue_dispatch_deferred",
        resourceType: "ScanJob",
        resourceId: queued.job.id,
        metadata: { reason: "Redis publish unavailable; persisted outbox remains CREATED." },
      });
    }
    return {
      scanId: scan.id,
      state: DatabaseScanState.QUEUED,
      queueDispatch: published ? "PUBLISHED" : "DEFERRED",
    };
  }

  async cancel(workspaceId: string, scanId: string, actorId: string) {
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId } });
    if (!scan) throw new NotFoundException("Scan does not exist in this workspace.");
    if (
      scan.state === DatabaseScanState.COMPLETED ||
      scan.state === DatabaseScanState.COMPLETED_WITH_WARNINGS ||
      scan.state === DatabaseScanState.FAILED ||
      scan.state === DatabaseScanState.CANCELLED
    ) {
      throw new ConflictException(`A ${scan.state} scan cannot be cancelled.`);
    }
    const now = new Date();
    const immediate =
      scan.state === DatabaseScanState.CREATED ||
      scan.state === DatabaseScanState.AUTHORIZED ||
      scan.state === DatabaseScanState.QUEUED;
    const updated = await this.prisma.$transaction(async (transaction) => {
      const result = await transaction.scan.update({
        where: { id: scan.id },
        data: {
          cancelRequestedAt: now,
          ...(immediate ? { state: DatabaseScanState.CANCELLED, completedAt: now } : {}),
        },
      });
      if (immediate) {
        await transaction.target.updateMany({
          where: { id: scan.targetId, workspaceId, status: "SCANNING" },
          data: { status: "CANCELLED" },
        });
        await transaction.scanJob.updateMany({
          where: {
            workspaceId,
            scanId,
            status: { in: [JobStatus.CREATED, JobStatus.QUEUED] },
          },
          data: { status: JobStatus.CANCELLED, completedAt: now },
        });
      }
      await transaction.auditEvent.create({
        data: {
          workspaceId,
          actorId,
          action: "scan.cancellation_requested",
          resourceType: "Scan",
          resourceId: scan.id,
          metadata: { stateAtRequest: scan.state, immediate },
        },
      });
      return result;
    });
    return {
      scanId: updated.id,
      state: updated.state,
      cancellation: immediate ? "COMPLETED" : "REQUESTED",
    };
  }

  async transition(
    workspaceId: string,
    scanId: string,
    to: ScanState,
    metadata?: Prisma.InputJsonValue,
  ) {
    return this.prisma.$transaction(async (transaction) => {
      const scan = await transaction.scan.findFirst({ where: { id: scanId, workspaceId } });
      if (!scan) throw new NotFoundException("Scan does not exist in this workspace.");
      assertScanTransition(scan.state as ScanState, to);
      const now = new Date();
      await transaction.scanStage.updateMany({
        where: { scanId, workspaceId, name: to as DatabaseScanState },
        data: {
          status: StageStatus.RUNNING,
          startedAt: now,
          ...(metadata !== undefined ? { metadata } : {}),
        },
      });
      return transaction.scan.update({
        where: { id: scanId },
        data: { state: to as DatabaseScanState, startedAt: scan.startedAt ?? now },
      });
    });
  }
}
