import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { correlateFindings } from "@aasp/correlation-engine";
import { normalizeObservations, type FindingObservationRecord } from "@aasp/finding-engine";
import {
  generateCompleteScanReport,
  generateVulnerabilityReport,
  type ReportFinding,
  type ScanReportInput,
} from "@aasp/report-engine";
import {
  qwenAnalysisOutputSchema,
  scannerObservationInputSchema,
  type QwenAnalysisOutput,
  type ScannerEvidenceInput,
  type ScannerObservationInput,
} from "@aasp/schemas";

const inputPath = resolve(
  process.env["DAY5_OBSERVATIONS_PATH"] ?? "../../artifacts/day3-scanner-observations.json",
);
const reportsRoot = resolve(process.env["REPORTS_ROOT"] ?? "../../reports");
const decoded = JSON.parse(await readFile(inputPath, "utf8")) as {
  target: string;
  generatedAt: string;
  crawl: { requestsMade: number };
  safeActive: { requestsMade: number };
  observations: unknown[];
};
if (!decoded.target || !decoded.generatedAt || !Array.isArray(decoded.observations))
  throw new Error("Day 3 artifact is incomplete.");
const timestamp = new Date(decoded.generatedAt);
function evidenceRecord(
  item: ScannerEvidenceInput,
  observationIndex: number,
  evidenceIndex: number,
) {
  return {
    id: `EVID-LOCAL-${String(observationIndex + 1).padStart(4, "0")}-${String(evidenceIndex + 1).padStart(2, "0")}`,
    timestamp,
    source: item.source,
    asset: item.asset,
    hash: createHash("sha256").update(JSON.stringify(item)).digest("hex"),
    requestMetadata: item.requestMetadata,
    responseMetadata: item.responseMetadata,
    redactedExcerpt: item.excerpt,
  };
}
function observationRecord(item: ScannerObservationInput, index: number): FindingObservationRecord {
  return {
    id: `OBS-LOCAL-${String(index + 1).padStart(4, "0")}`,
    scanner: item.scanner,
    scannerVersion: item.scannerVersion,
    observationType: item.observationType,
    asset: item.asset,
    endpoint: item.endpoint ?? null,
    method: item.method ?? null,
    parameter: item.parameter ?? null,
    rawSeverity: item.rawSeverity ?? null,
    metadata: item.metadata,
    createdAt: timestamp,
    evidence: item.evidence.map((evidence, evidenceIndex) =>
      evidenceRecord(evidence, index, evidenceIndex),
    ),
  };
}
const observations = decoded.observations.map((item) => scannerObservationInputSchema.parse(item));
const records = observations.map(observationRecord);
const evidenceById = new Map(
  records.flatMap(({ evidence }) => evidence.map((item) => [item.id, item] as const)),
);
const correlated = correlateFindings(normalizeObservations(records));
const aiPath = process.env["DAY5_AI_FINDINGS_PATH"]
  ? resolve(process.env["DAY5_AI_FINDINGS_PATH"])
  : null;
const aiByFinding = new Map<string, QwenAnalysisOutput>();
if (aiPath) {
  const artifact = JSON.parse(await readFile(aiPath, "utf8")) as {
    analyses?: Array<{ findingId?: unknown; output?: unknown }>;
  };
  if (!Array.isArray(artifact.analyses)) throw new Error("AI artifact has no analyses array.");
  for (const analysis of artifact.analyses) {
    if (typeof analysis.findingId !== "string") throw new Error("AI analysis has no findingId.");
    aiByFinding.set(analysis.findingId, qwenAnalysisOutputSchema.parse(analysis.output));
  }
}
const severityOrder = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
function boundedSeverity(
  deterministic: (typeof severityOrder)[number],
  proposed: (typeof severityOrder)[number],
) {
  const current = severityOrder.indexOf(deterministic);
  const next = severityOrder.indexOf(proposed);
  if (Math.abs(next - current) <= 1) return proposed;
  return severityOrder[current + Math.sign(next - current)] ?? deterministic;
}
const findings: ReportFinding[] = correlated.map((finding, index) => ({
  ...(() => {
    const id = `FIND-${String(index + 1).padStart(4, "0")}`;
    const analysis = aiByFinding.get(id);
    if (aiPath && !analysis) throw new Error(`AI artifact is missing ${id}.`);
    if (
      analysis &&
      !analysis.evidenceIds.every((evidenceId) => finding.evidenceIds.includes(evidenceId))
    ) {
      throw new Error(
        `AI analysis for ${id} referenced evidence outside the deterministic finding.`,
      );
    }
    const manualVerificationRequired =
      finding.manualVerificationRequired || analysis?.manualVerificationRequired === true;
    return {
      id,
      title: analysis?.title ?? finding.title,
      category: analysis?.classification ?? finding.category,
      severity: analysis ? boundedSeverity(finding.severity, analysis.severity) : finding.severity,
      confidence: analysis ? Math.min(0.99, analysis.confidence) : finding.confidence,
      status: manualVerificationRequired ? "MANUAL_VERIFICATION_REQUIRED" : finding.status,
      cwe: analysis?.cwe ?? finding.cwe,
      owasp: analysis?.owasp ?? finding.owasp,
      asset: finding.asset,
      endpoint: finding.endpoint,
      method: finding.method,
      parameter: finding.parameter,
      description: analysis?.description ?? finding.description,
      technicalImpact: analysis?.technicalImpact ?? finding.technicalImpact,
      businessImpact: analysis?.businessImpact ?? finding.businessImpact,
      scannerSources: finding.scannerSources,
      remediation: analysis?.remediation ?? finding.remediation,
      manualVerificationRequired,
      likelyFalsePositive: analysis?.likelyFalsePositive ?? null,
      reasoningSummary: analysis?.reasoningSummary ?? null,
      firstSeen: finding.firstSeen.toISOString(),
      lastSeen: finding.lastSeen.toISOString(),
      evidence: finding.evidenceIds.map((evidenceId) => {
        const item = evidenceById.get(evidenceId);
        if (!item) throw new Error(`Missing evidence ${evidenceId}`);
        return { ...item, timestamp: item.timestamp.toISOString() };
      }),
    };
  })(),
}));
const endpoints = [
  ...new Map(
    observations.map((item) => [
      `${item.asset}|${item.endpoint ?? "/"}|${item.method ?? "GET"}`,
      {
        asset: item.asset,
        path: item.endpoint ?? "/",
        method: item.method ?? "GET",
        source: item.scanner,
        parameters: [],
      },
    ]),
  ).values(),
];
const input: ScanReportInput = {
  scan: {
    id: aiPath ? "local-day6-qwen-demo" : "local-day5-demo",
    name: "Authorized local fixture assessment",
    state: aiPath ? "COMPLETED" : "COMPLETED_WITH_WARNINGS",
    createdAt: decoded.generatedAt,
    startedAt: decoded.generatedAt,
    completedAt: new Date().toISOString(),
    warningCount: aiPath ? 0 : 1,
  },
  workspace: { id: "local-demo", name: "Local authorized fixtures" },
  target: {
    name: "Intentionally vulnerable local fixture",
    origin: decoded.target,
    status: "COMPLETED",
    scopeConfiguredAt: decoded.generatedAt,
  },
  scopeRules: [
    { type: "HOST", value: new URL(decoded.target).hostname, enabled: true },
    { type: "PORT", value: String(new URL(decoded.target).port || "80"), enabled: true },
    { type: "INCLUDE_SUBDOMAINS", value: "false", enabled: true },
    { type: "ALLOW_PRIVATE_NETWORK", value: "true", enabled: true },
  ],
  config: { profile: "STANDARD", source: "day3 real local scanner artifact" },
  stages: [
    {
      name: "DISCOVERY",
      status: "COMPLETED",
      startedAt: decoded.generatedAt,
      completedAt: decoded.generatedAt,
      completedUnits: 1,
      totalUnits: 1,
      errorMessage: null,
    },
    {
      name: "AI_ANALYSIS",
      status: aiPath ? "COMPLETED" : "DEGRADED",
      startedAt: null,
      completedAt: null,
      completedUnits: aiPath ? findings.length : 0,
      totalUnits: findings.length,
      errorMessage: aiPath
        ? null
        : "Qwen was not invoked for this CPU-only local artifact; deterministic findings were preserved.",
    },
  ],
  assets: [
    {
      assetType: "ORIGIN",
      value: decoded.target,
      firstSeenAt: decoded.generatedAt,
      lastSeenAt: decoded.generatedAt,
    },
  ],
  urls: endpoints.map(({ asset, path }) => ({
    canonicalUrl: new URL(path, asset).toString(),
    depth: 0,
    statusCode: null,
    contentType: null,
  })),
  endpoints,
  technologies: [],
  findings,
  scannerSources: [...new Set(observations.map(({ scanner }) => scanner))].sort(),
  requestsPerformed: decoded.crawl.requestsMade + decoded.safeActive.requestsMade,
  failedOrDegradedStages: aiPath
    ? []
    : [
        {
          name: "AI_ANALYSIS",
          status: "DEGRADED",
          errorMessage: "No Qwen provider used for this local report-generation demonstration.",
        },
      ],
  generatedAt: new Date().toISOString(),
};
const directory = resolve(reportsRoot, input.scan.id);
await mkdir(resolve(directory, "findings"), { recursive: true });
const report = generateCompleteScanReport(input);
await Promise.all([
  writeFile(resolve(directory, "scan-report.html"), report.html),
  writeFile(resolve(directory, "scan-report.pdf-ready.html"), report.pdfReadyHtml),
  writeFile(
    resolve(directory, "scan-report.json"),
    JSON.stringify(report.document, null, 2) + "\n",
  ),
  ...findings.flatMap((finding) => {
    const item = generateVulnerabilityReport({
      scan: input.scan,
      workspace: input.workspace,
      target: input.target,
      generatedAt: input.generatedAt,
      finding,
    });
    return [
      writeFile(resolve(directory, "findings", `${finding.id}.html`), item.html),
      writeFile(
        resolve(directory, "findings", `${finding.id}.json`),
        JSON.stringify(item.document, null, 2) + "\n",
      ),
    ];
  }),
]);
process.stdout.write(
  JSON.stringify({
    reportDirectory: directory,
    findings: findings.length,
    everyFindingHasEvidence: findings.every(({ evidence }) => evidence.length > 0),
    aiAnalysisPerformed: Boolean(aiPath),
  }) + "\n",
);
