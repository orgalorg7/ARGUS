import type { Severity } from "@aasp/schemas";

export type FindingTrendStatus =
  | "NEW"
  | "RECURRING"
  | "RESOLVED"
  | "REGRESSED"
  | "CHANGED"
  | "UNVERIFIED";

export type RemediationPriority = "FIX_NOW" | "FIX_NEXT" | "PLANNED" | "HARDENING";

export interface ComparableFinding {
  id: string;
  correlationKey: string;
  severity: Severity;
  confidence: number;
  category: string;
  asset: string;
  endpoint: string | null;
  recurrenceCount: number;
  affectedEndpointCount?: number;
}

export interface CoverageSnapshot {
  profile: "LIGHT" | "STANDARD" | "DEEP_SAFE";
  urls: number;
  endpoints: number;
  requests: number;
  completedModules: string[];
  failedOrDegradedModules: string[];
}

export interface InventorySnapshot {
  assets: string[];
  technologies: string[];
}

export interface AssessmentSnapshot {
  scanId: string;
  findings: ComparableFinding[];
  coverage: CoverageSnapshot;
  inventory: InventorySnapshot;
}

export interface FindingComparisonResult {
  correlationKey: string;
  currentFindingId: string | null;
  previousFindingId: string | null;
  trendStatus: FindingTrendStatus;
  severityBefore: Severity | null;
  severityAfter: Severity | null;
  reason: string;
  recurrenceCount: number;
  remediationPriority: RemediationPriority | null;
  priorityScore: number | null;
}

export interface MonthlyComparisonResult {
  currentScanId: string;
  previousScanId: string | null;
  coverageSufficient: boolean;
  coverageRatio: number;
  coverageReasons: string[];
  findings: FindingComparisonResult[];
  counts: Record<FindingTrendStatus, number>;
  newAssets: string[];
  removedAssets: string[];
  technologyChanges: { added: string[]; removed: string[] };
}

const severityRank: Readonly<Record<Severity, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const profileRank: Readonly<Record<CoverageSnapshot["profile"], number>> = {
  LIGHT: 0,
  STANDARD: 1,
  DEEP_SAFE: 2,
};

function ratio(current: number, previous: number): number {
  if (previous <= 0) return 1;
  return Math.min(1, current / previous);
}

function coverageComparison(
  current: CoverageSnapshot,
  previous: CoverageSnapshot,
): { sufficient: boolean; ratio: number; reasons: string[] } {
  const previousModules = new Set(previous.completedModules);
  const currentModules = new Set(current.completedModules);
  const moduleRatio =
    previousModules.size === 0
      ? 1
      : [...previousModules].filter((module) => currentModules.has(module)).length /
        previousModules.size;
  const ratios = [
    ratio(current.urls, previous.urls),
    ratio(current.endpoints, previous.endpoints),
    ratio(current.requests, previous.requests),
    moduleRatio,
  ];
  const profileComparable = profileRank[current.profile] >= profileRank[previous.profile];
  const coverageRatio = Math.min(...ratios, profileComparable ? 1 : 0.75);
  const reasons: string[] = [];
  if (!profileComparable) reasons.push("Current scan profile is weaker than the previous scan.");
  if (ratio(current.urls, previous.urls) < 0.8)
    reasons.push("Current URL coverage is below 80% of the previous scan.");
  if (ratio(current.endpoints, previous.endpoints) < 0.8)
    reasons.push("Current endpoint coverage is below 80% of the previous scan.");
  if (ratio(current.requests, previous.requests) < 0.8)
    reasons.push("Current recorded-request coverage is below 80% of the previous scan.");
  if (moduleRatio < 1) reasons.push("Not every previously completed module completed this time.");
  if (current.failedOrDegradedModules.length > 0)
    reasons.push("The current scan contains failed or degraded modules.");
  return {
    sufficient: coverageRatio >= 0.8 && current.failedOrDegradedModules.length === 0,
    ratio: Number(coverageRatio.toFixed(4)),
    reasons,
  };
}

export function prioritizeFinding(input: {
  severity: Severity;
  confidence: number;
  trendStatus: FindingTrendStatus;
  recurrenceCount: number;
  affectedEndpointCount?: number;
}): { priority: RemediationPriority; score: number; factors: string[] } {
  const base = [0, 25, 50, 75, 100][severityRank[input.severity]] ?? 0;
  const confidence = Math.max(0, Math.min(1, input.confidence));
  let score = base * (0.7 + confidence * 0.3);
  const factors = [`${input.severity} severity`, `${Math.round(confidence * 100)}% confidence`];
  if (input.trendStatus === "REGRESSED") {
    score += 15;
    factors.push("regressed since previous scan");
  } else if (input.trendStatus === "RECURRING" && input.recurrenceCount > 1) {
    score += Math.min(12, input.recurrenceCount * 2);
    factors.push(`recurring across ${input.recurrenceCount} scans`);
  } else if (input.trendStatus === "NEW") {
    score += 4;
    factors.push("new finding");
  }
  const endpointCount = Math.max(1, input.affectedEndpointCount ?? 1);
  if (endpointCount > 1) {
    score += Math.min(10, Math.log2(endpointCount) * 3);
    factors.push(`${endpointCount} affected endpoints`);
  }
  const normalizedScore = Number(Math.min(100, score).toFixed(2));
  const priority: RemediationPriority =
    input.severity === "CRITICAL" || normalizedScore >= 75
      ? "FIX_NOW"
      : normalizedScore >= 45
        ? "FIX_NEXT"
        : normalizedScore >= 20
          ? "PLANNED"
          : "HARDENING";
  return { priority, score: normalizedScore, factors };
}

function setDifference(left: readonly string[], right: readonly string[]): string[] {
  const rightSet = new Set(right);
  return [...new Set(left)].filter((value) => !rightSet.has(value)).sort();
}

function emptyCounts(): Record<FindingTrendStatus, number> {
  return {
    NEW: 0,
    RECURRING: 0,
    RESOLVED: 0,
    REGRESSED: 0,
    CHANGED: 0,
    UNVERIFIED: 0,
  };
}

export function compareAssessments(
  current: AssessmentSnapshot,
  previous: AssessmentSnapshot | null,
): MonthlyComparisonResult {
  const counts = emptyCounts();
  if (!previous) {
    const findings = current.findings.map((finding) => {
      const priority = prioritizeFinding({
        severity: finding.severity,
        confidence: finding.confidence,
        trendStatus: "NEW",
        recurrenceCount: 1,
        ...(finding.affectedEndpointCount === undefined
          ? {}
          : { affectedEndpointCount: finding.affectedEndpointCount }),
      });
      counts.NEW += 1;
      return {
        correlationKey: finding.correlationKey,
        currentFindingId: finding.id,
        previousFindingId: null,
        trendStatus: "NEW" as const,
        severityBefore: null,
        severityAfter: finding.severity,
        reason: "No comparable previous completed assessment exists for this target.",
        recurrenceCount: 1,
        remediationPriority: priority.priority,
        priorityScore: priority.score,
      };
    });
    return {
      currentScanId: current.scanId,
      previousScanId: null,
      coverageSufficient: false,
      coverageRatio: 0,
      coverageReasons: ["No previous completed assessment is available."],
      findings,
      counts,
      newAssets: [...new Set(current.inventory.assets)].sort(),
      removedAssets: [],
      technologyChanges: {
        added: [...new Set(current.inventory.technologies)].sort(),
        removed: [],
      },
    };
  }

  const coverage = coverageComparison(current.coverage, previous.coverage);
  const currentByKey = new Map(
    current.findings.map((finding) => [finding.correlationKey, finding]),
  );
  const previousByKey = new Map(
    previous.findings.map((finding) => [finding.correlationKey, finding]),
  );
  const findings: FindingComparisonResult[] = [];

  for (const finding of current.findings) {
    const prior = previousByKey.get(finding.correlationKey);
    let trendStatus: FindingTrendStatus;
    let reason: string;
    let recurrenceCount = 1;
    if (!prior) {
      trendStatus = "NEW";
      reason = "The correlation key was not present in the previous assessment.";
    } else {
      recurrenceCount = Math.max(1, prior.recurrenceCount) + 1;
      if (severityRank[finding.severity] > severityRank[prior.severity]) {
        trendStatus = "REGRESSED";
        reason = `Severity increased from ${prior.severity} to ${finding.severity}.`;
      } else if (
        finding.severity !== prior.severity ||
        finding.asset !== prior.asset ||
        finding.endpoint !== prior.endpoint
      ) {
        trendStatus = "CHANGED";
        reason = "Severity or affected location changed while the correlation key remained stable.";
      } else {
        trendStatus = "RECURRING";
        reason = "The same correlation key was observed again with a comparable classification.";
      }
    }
    counts[trendStatus] += 1;
    const priority = prioritizeFinding({
      severity: finding.severity,
      confidence: finding.confidence,
      trendStatus,
      recurrenceCount,
      ...(finding.affectedEndpointCount === undefined
        ? {}
        : { affectedEndpointCount: finding.affectedEndpointCount }),
    });
    findings.push({
      correlationKey: finding.correlationKey,
      currentFindingId: finding.id,
      previousFindingId: prior?.id ?? null,
      trendStatus,
      severityBefore: prior?.severity ?? null,
      severityAfter: finding.severity,
      reason,
      recurrenceCount,
      remediationPriority: priority.priority,
      priorityScore: priority.score,
    });
  }

  for (const prior of previous.findings) {
    if (currentByKey.has(prior.correlationKey)) continue;
    const trendStatus: FindingTrendStatus = coverage.sufficient ? "RESOLVED" : "UNVERIFIED";
    counts[trendStatus] += 1;
    findings.push({
      correlationKey: prior.correlationKey,
      currentFindingId: null,
      previousFindingId: prior.id,
      trendStatus,
      severityBefore: prior.severity,
      severityAfter: null,
      reason: coverage.sufficient
        ? "The prior finding was not observed under comparable current coverage."
        : "The prior finding was not rediscovered, but current coverage is insufficient to claim resolution.",
      recurrenceCount: prior.recurrenceCount,
      remediationPriority: null,
      priorityScore: null,
    });
  }

  return {
    currentScanId: current.scanId,
    previousScanId: previous.scanId,
    coverageSufficient: coverage.sufficient,
    coverageRatio: coverage.ratio,
    coverageReasons: coverage.reasons,
    findings,
    counts,
    newAssets: setDifference(current.inventory.assets, previous.inventory.assets),
    removedAssets: setDifference(previous.inventory.assets, current.inventory.assets),
    technologyChanges: {
      added: setDifference(current.inventory.technologies, previous.inventory.technologies),
      removed: setDifference(previous.inventory.technologies, current.inventory.technologies),
    },
  };
}
