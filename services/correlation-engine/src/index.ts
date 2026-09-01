import { createHash } from "node:crypto";
import type { NormalizedFindingCandidate } from "@aasp/finding-engine";
import type { Severity } from "@aasp/schemas";

export interface CorrelatedFinding extends NormalizedFindingCandidate {
  correlationKey: string;
}

const severityRank: Readonly<Record<Severity, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const siteWideCategories = new Set([
  "INFORMATION_DISCLOSURE",
  "CONTENT_SECURITY_POLICY",
  "MIME_SNIFFING_PROTECTION",
  "CLICKJACKING_PROTECTION",
  "REFERRER_INFORMATION_CONTROL",
  "BROWSER_CAPABILITY_CONTROL",
  "TRANSPORT_SECURITY_POLICY",
]);

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function identity(candidate: NormalizedFindingCandidate): string {
  const endpoint = siteWideCategories.has(candidate.category) ? "*" : (candidate.endpoint ?? "");
  return [
    candidate.asset.toLowerCase(),
    endpoint,
    candidate.method ?? "",
    candidate.parameter ?? "",
    candidate.category,
    candidate.correlationDiscriminator ?? "",
    uniqueSorted(candidate.cwe).join(","),
  ].join("|");
}

function hashIdentity(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function moreSevere(left: Severity, right: Severity): Severity {
  return severityRank[left] >= severityRank[right] ? left : right;
}

function merge(
  current: CorrelatedFinding,
  candidate: NormalizedFindingCandidate,
): CorrelatedFinding {
  const evidenceIds = uniqueSorted([...current.evidenceIds, ...candidate.evidenceIds]);
  const scannerSources = uniqueSorted([...current.scannerSources, ...candidate.scannerSources]);
  const confidenceBonus = Math.min(0.05, Math.log2(Math.max(1, evidenceIds.length)) * 0.01);
  const manualVerificationRequired =
    current.manualVerificationRequired || candidate.manualVerificationRequired;
  return {
    ...current,
    severity: moreSevere(current.severity, candidate.severity),
    confidence: Math.min(
      0.99,
      Math.max(current.confidence, candidate.confidence) + confidenceBonus,
    ),
    status: manualVerificationRequired ? "MANUAL_VERIFICATION_REQUIRED" : current.status,
    cwe: uniqueSorted([...current.cwe, ...candidate.cwe]),
    owasp: uniqueSorted([...current.owasp, ...candidate.owasp]),
    evidenceIds,
    scannerSources,
    manualVerificationRequired,
    observationIds: uniqueSorted([...current.observationIds, ...candidate.observationIds]),
    firstSeen: current.firstSeen < candidate.firstSeen ? current.firstSeen : candidate.firstSeen,
    lastSeen: current.lastSeen > candidate.lastSeen ? current.lastSeen : candidate.lastSeen,
  };
}

export function correlateFindings(
  candidates: readonly NormalizedFindingCandidate[],
): CorrelatedFinding[] {
  const grouped = new Map<string, CorrelatedFinding>();
  for (const candidate of candidates) {
    if (candidate.evidenceIds.length === 0) continue;
    const key = hashIdentity(identity(candidate));
    const current = grouped.get(key);
    grouped.set(key, current ? merge(current, candidate) : { ...candidate, correlationKey: key });
  }
  return [...grouped.values()].sort((left, right) => {
    const severityDifference = severityRank[right.severity] - severityRank[left.severity];
    return severityDifference || left.correlationKey.localeCompare(right.correlationKey);
  });
}
