import { createHash } from "node:crypto";
import { mkdir, rename, writeFile, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { Prisma, PrismaClient } from "@aasp/database";
import {
  AIAnalysisStatus,
  type FindingTrendStatus,
  JobStatus,
  type RemediationPriority,
  ReportStatus,
  ReportType,
  ScanState,
  StageStatus,
} from "@aasp/database";
import { logger } from "@aasp/logger";
import {
  compareAssessments,
  type AssessmentSnapshot,
  type ComparableFinding,
} from "@aasp/longitudinal-engine";
import {
  generateCompleteScanReport,
  generateExecutiveReport,
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
const comparisonRelevantStages = new Set<ScanState>([
  ScanState.VALIDATING_SCOPE,
  ScanState.DISCOVERY,
  ScanState.CRAWLING,
  ScanState.API_DISCOVERY,
  ScanState.FINGERPRINTING,
  ScanState.PASSIVE_ANALYSIS,
  ScanState.SAFE_ACTIVE_ANALYSIS,
  ScanState.AUTHORIZATION_ANALYSIS,
  ScanState.NORMALIZING,
  ScanState.CORRELATING,
]);

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
  const likelyFalsePositive = record["likelyFalsePositive"] ?? record["likely_false_positive"];
  const reasoningSummary = record["reasoningSummary"] ?? record["reasoning_summary"];
  return {
    likelyFalsePositive: typeof likelyFalsePositive === "boolean" ? likelyFalsePositive : null,
    reasoningSummary: typeof reasoningSummary === "string" ? reasoningSummary : null,
  };
}

function requestEvidenceCount(evidence: readonly { requestMetadata: Prisma.JsonValue }[]): number {
  return evidence.filter(({ requestMetadata }) => {
    return (
      requestMetadata !== null &&
      typeof requestMetadata === "object" &&
      !Array.isArray(requestMetadata) &&
      typeof (requestMetadata as Record<string, Prisma.JsonValue>)["method"] === "string"
    );
  }).length;
}

function jsonRecord(value: Prisma.JsonValue | null): Record<string, Prisma.JsonValue> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, Prisma.JsonValue>)
    : {};
}

function jsonStrings(value: Prisma.JsonValue | undefined): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

async function assessmentSnapshot(
  prisma: PrismaClient,
  workspaceId: string,
  scanId: string,
): Promise<AssessmentSnapshot> {
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, workspaceId },
    include: {
      config: true,
      findings: {
        include: {
          occurrences: {
            include: {
              observation: { select: { asset: true, endpoint: true, method: true } },
            },
          },
        },
      },
      assets: true,
      technologies: true,
      stages: true,
      evidence: { select: { requestMetadata: true } },
    },
  });
  if (!scan?.config)
    throw new Error("Assessment snapshot requires a persisted scan configuration.");
  const findings: ComparableFinding[] = scan.findings.map((finding) => ({
    id: finding.id,
    correlationKey: finding.correlationKey,
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    asset: finding.asset,
    endpoint: finding.endpoint,
    recurrenceCount: finding.recurrenceCount,
    affectedEndpointCount: new Set(
      finding.occurrences.map(
        ({ observation }) =>
          `${observation.asset}|${observation.method ?? ""}|${observation.endpoint ?? ""}`,
      ),
    ).size,
  }));
  return {
    scanId: scan.id,
    findings,
    coverage: {
      profile: scan.config.profile,
      urls: await prisma.discoveredURL.count({ where: { workspaceId, scanId } }),
      endpoints: await prisma.discoveredEndpoint.count({ where: { workspaceId, scanId } }),
      requests: requestEvidenceCount(scan.evidence),
      completedModules: scan.stages
        .filter(
          ({ name, status }) =>
            comparisonRelevantStages.has(name) && status === StageStatus.COMPLETED,
        )
        .map(({ name }) => name),
      failedOrDegradedModules: scan.stages
        .filter(
          ({ name, status }) =>
            comparisonRelevantStages.has(name) &&
            (status === StageStatus.FAILED || status === StageStatus.DEGRADED),
        )
        .map(({ name }) => name),
    },
    inventory: {
      assets: scan.assets.map(({ assetType, value }) => `${assetType}|${value}`),
      technologies: scan.technologies.map(
        ({ technology, possibleVersion }) =>
          `${technology}|${possibleVersion ?? "UNKNOWN_VERSION"}`,
      ),
    },
  };
}

async function persistMonthlyComparison(
  prisma: PrismaClient,
  payload: ReportPayload,
): Promise<void> {
  const current = await prisma.scan.findFirst({
    where: { id: payload.scanId, workspaceId: payload.workspaceId },
    select: { id: true, targetId: true, createdAt: true },
  });
  if (!current) throw new Error("Current scan was not found for monthly comparison.");
  const previous = await prisma.scan.findFirst({
    where: {
      workspaceId: payload.workspaceId,
      targetId: current.targetId,
      id: { not: current.id },
      createdAt: { lt: current.createdAt },
      state: { in: [ScanState.COMPLETED, ScanState.COMPLETED_WITH_WARNINGS] },
    },
    select: { id: true },
    orderBy: [{ completedAt: "desc" }, { createdAt: "desc" }],
  });
  const currentSnapshot = await assessmentSnapshot(prisma, payload.workspaceId, payload.scanId);
  const previousSnapshot = previous
    ? await assessmentSnapshot(prisma, payload.workspaceId, previous.id)
    : null;
  const result = compareAssessments(currentSnapshot, previousSnapshot);
  const comparison = await prisma.scanComparison.upsert({
    where: { scanId: payload.scanId },
    create: {
      workspaceId: payload.workspaceId,
      scanId: payload.scanId,
      previousScanId: result.previousScanId,
      coverageSufficient: result.coverageSufficient,
      coverageRatio: result.coverageRatio,
      summary: jsonValue({
        counts: result.counts,
        coverageReasons: result.coverageReasons,
        newAssets: result.newAssets,
        removedAssets: result.removedAssets,
        technologyChanges: result.technologyChanges,
      }),
    },
    update: {
      previousScanId: result.previousScanId,
      coverageSufficient: result.coverageSufficient,
      coverageRatio: result.coverageRatio,
      summary: jsonValue({
        counts: result.counts,
        coverageReasons: result.coverageReasons,
        newAssets: result.newAssets,
        removedAssets: result.removedAssets,
        technologyChanges: result.technologyChanges,
      }),
    },
  });
  await prisma.findingComparison.deleteMany({ where: { scanComparisonId: comparison.id } });
  if (result.findings.length > 0) {
    await prisma.findingComparison.createMany({
      data: result.findings.map((finding) => ({
        scanComparisonId: comparison.id,
        currentFindingId: finding.currentFindingId,
        previousFindingId: finding.previousFindingId,
        correlationKey: finding.correlationKey,
        trendStatus: finding.trendStatus as FindingTrendStatus,
        severityBefore: finding.severityBefore,
        severityAfter: finding.severityAfter,
        reason: finding.reason,
      })),
    });
  }
  for (const finding of result.findings) {
    if (!finding.currentFindingId || !finding.remediationPriority) continue;
    const previousFinding = finding.previousFindingId
      ? await prisma.finding.findUnique({
          where: { id: finding.previousFindingId },
          select: { firstSeen: true },
        })
      : null;
    await prisma.finding.update({
      where: { id: finding.currentFindingId },
      data: {
        trendStatus: finding.trendStatus as FindingTrendStatus,
        remediationPriority: finding.remediationPriority as RemediationPriority,
        recurrenceCount: finding.recurrenceCount,
        previousFindingId: finding.previousFindingId,
        ...(previousFinding ? { firstSeen: previousFinding.firstSeen } : {}),
      },
    });
  }
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
    jsonSha256: createHash("sha256")
      .update(await readFile(input.path.replace(/(?:\.pdf-ready)?\.html$/u, ".json")))
      .digest("hex"),
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
      aiAnalyses: {
        select: { findingId: true, status: true, schemaValid: true, evidenceValid: true },
      },
      currentComparison: {
        include: {
          findings: {
            include: {
              previousFinding: { select: { publicId: true, title: true, severity: true } },
            },
          },
        },
      },
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
      authorizationTestResults: {
        include: { testCase: true },
        orderBy: { createdAt: "asc" },
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
      trendStatus: finding.trendStatus,
      remediationPriority: finding.remediationPriority,
      recurrenceCount: finding.recurrenceCount,
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
  const summary = jsonRecord(scan.currentComparison?.summary ?? null);
  const rawCounts = jsonRecord(summary["counts"] ?? null);
  const comparisonCounts = {
    NEW: typeof rawCounts["NEW"] === "number" ? rawCounts["NEW"] : 0,
    RECURRING: typeof rawCounts["RECURRING"] === "number" ? rawCounts["RECURRING"] : 0,
    RESOLVED: typeof rawCounts["RESOLVED"] === "number" ? rawCounts["RESOLVED"] : 0,
    REGRESSED: typeof rawCounts["REGRESSED"] === "number" ? rawCounts["REGRESSED"] : 0,
    CHANGED: typeof rawCounts["CHANGED"] === "number" ? rawCounts["CHANGED"] : 0,
    UNVERIFIED: typeof rawCounts["UNVERIFIED"] === "number" ? rawCounts["UNVERIFIED"] : 0,
  };
  const technologyChanges = jsonRecord(summary["technologyChanges"] ?? null);
  const comparisonFindings = scan.currentComparison?.findings ?? [];
  const toPriorFinding = (trendStatus: "RESOLVED" | "UNVERIFIED") =>
    comparisonFindings
      .filter((item) => item.trendStatus === trendStatus && item.previousFinding)
      .map((item) => ({
        id: item.previousFinding!.publicId,
        title: item.previousFinding!.title,
        severity: item.previousFinding!.severity,
        reason: item.reason,
      }));
  const provider = await prisma.modelProvider.findFirst({
    where: { OR: [{ workspaceId: payload.workspaceId }, { workspaceId: null }] },
    select: { id: true },
  });
  const validatedAnalyses = new Set(
    scan.aiAnalyses
      .filter(
        ({ findingId, status, schemaValid, evidenceValid }) =>
          findingId &&
          status === AIAnalysisStatus.COMPLETED &&
          schemaValid === true &&
          evidenceValid === true,
      )
      .map(({ findingId }) => findingId),
  ).size;
  const failedOrWaitingAnalyses = Math.max(0, findings.length - validatedAnalyses);
  const qwenStatus = !provider
    ? "NOT_CONFIGURED"
    : findings.length === 0 || scan.aiAnalyses.length === 0
      ? "NOT_RUN"
      : validatedAnalyses === findings.length
        ? "COMPLETED"
        : validatedAnalyses > 0
          ? "PARTIAL"
          : "FAILED_OR_WAITING";
  const authorizationMatrices = scan.authorizationTestResults.map((result) => {
    const matrix = jsonRecord(result.matrix);
    const observations = Array.isArray(matrix["observations"])
      ? matrix["observations"].filter(
          (item): item is Record<string, Prisma.JsonValue> =>
            Boolean(item) && typeof item === "object" && !Array.isArray(item),
        )
      : [];
    const differences = Array.isArray(matrix["differences"])
      ? matrix["differences"].filter(
          (item): item is Record<string, Prisma.JsonValue> =>
            Boolean(item) && typeof item === "object" && !Array.isArray(item),
        )
      : [];
    return {
      testCaseId: result.testCaseId,
      name: result.testCase.name,
      method: result.testCase.method,
      endpointTemplate: result.testCase.endpointTemplate,
      degraded: result.degraded,
      incompleteIdentityCount: result.incompleteIdentityIds.length,
      cells: observations.map((observation) => {
        const identityId =
          typeof observation["identityId"] === "string" ? observation["identityId"] : "unknown";
        const response = jsonRecord(observation["response"] ?? null);
        const difference = differences.find((item) => item["comparisonIdentityId"] === identityId);
        return {
          identityLabel:
            typeof observation["identityLabel"] === "string"
              ? observation["identityLabel"]
              : identityId,
          expected:
            typeof observation["expected"] === "string" ? observation["expected"] : "UNKNOWN",
          statusCode: typeof response["statusCode"] === "number" ? response["statusCode"] : 0,
          classification:
            difference && typeof difference["classification"] === "string"
              ? difference["classification"]
              : "BASELINE",
          severity:
            difference && typeof difference["severity"] === "string"
              ? difference["severity"]
              : "INFO",
          confidence:
            difference && typeof difference["confidence"] === "number"
              ? difference["confidence"]
              : 1,
        };
      }),
    };
  });
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
    authorizationMatrices,
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
    comparison: {
      previousScanId: scan.currentComparison?.previousScanId ?? null,
      coverageSufficient: scan.currentComparison?.coverageSufficient ?? false,
      coverageRatio: scan.currentComparison?.coverageRatio ?? 0,
      coverageReasons: jsonStrings(summary["coverageReasons"]),
      counts: comparisonCounts,
      newAssets: jsonStrings(summary["newAssets"]),
      removedAssets: jsonStrings(summary["removedAssets"]),
      technologyChanges: {
        added: jsonStrings(technologyChanges["added"]),
        removed: jsonStrings(technologyChanges["removed"]),
      },
      resolvedFindings: toPriorFinding("RESOLVED"),
      unverifiedFindings: toPriorFinding("UNVERIFIED"),
    },
    qwenAnalysis: {
      status: qwenStatus,
      totalFindings: findings.length,
      validatedAnalyses,
      failedOrWaitingAnalyses,
    },
    scannerSources: [...new Set(scan.observations.map(({ scanner }) => scanner))].sort(),
    requestsPerformed: requestEvidenceCount(evidence),
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

  await persistMonthlyComparison(prisma, job.data);
  const input = await buildInput(prisma, job.data);
  if (input.findings.some(({ evidence }) => evidence.length === 0)) {
    throw new Error("Report generation refused a finding without persisted evidence.");
  }
  const reportsRoot = resolve(process.env["REPORTS_ROOT"] ?? "../../reports");
  const scanDirectory = resolve(reportsRoot, scanId);
  const complete = generateCompleteScanReport(input);
  const executive = generateExecutiveReport(input);
  const completePath = resolve(scanDirectory, "scan-report.html");
  const completeJsonPath = resolve(scanDirectory, "scan-report.json");
  const pdfReadyPath = resolve(scanDirectory, "scan-report.pdf-ready.html");
  const executivePath = resolve(scanDirectory, "executive-report.html");
  const executiveJsonPath = resolve(scanDirectory, "executive-report.json");
  const executivePdfReadyPath = resolve(scanDirectory, "executive-report.pdf-ready.html");
  await Promise.all([
    atomicWrite(completePath, complete.html),
    atomicWrite(completeJsonPath, `${JSON.stringify(complete.document, null, 2)}\n`),
    atomicWrite(pdfReadyPath, complete.pdfReadyHtml),
    atomicWrite(executivePath, executive.html),
    atomicWrite(executiveJsonPath, `${JSON.stringify(executive.document, null, 2)}\n`),
    atomicWrite(executivePdfReadyPath, executive.pdfReadyHtml),
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
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.EXECUTIVE,
      path: executivePath,
      sha256: executive.sha256,
    }),
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.EXECUTIVE_PDF_READY,
      path: executivePdfReadyPath,
      sha256: executive.pdfReadySha256,
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

  let generated = 4;
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
  const finalizedExecutive = generateExecutiveReport(finalizedInput);
  await Promise.all([
    atomicWrite(completePath, finalizedComplete.html),
    atomicWrite(completeJsonPath, `${JSON.stringify(finalizedComplete.document, null, 2)}\n`),
    atomicWrite(pdfReadyPath, finalizedComplete.pdfReadyHtml),
    atomicWrite(executivePath, finalizedExecutive.html),
    atomicWrite(executiveJsonPath, `${JSON.stringify(finalizedExecutive.document, null, 2)}\n`),
    atomicWrite(executivePdfReadyPath, finalizedExecutive.pdfReadyHtml),
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
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.EXECUTIVE,
      path: executivePath,
      sha256: finalizedExecutive.sha256,
    }),
    persistReport(prisma, {
      workspaceId,
      scanId,
      type: ReportType.EXECUTIVE_PDF_READY,
      path: executivePdfReadyPath,
      sha256: finalizedExecutive.pdfReadySha256,
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
