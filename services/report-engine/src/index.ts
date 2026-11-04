import { createHash } from "node:crypto";

export type ReportSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type FindingTrendStatus =
  | "NEW"
  | "RECURRING"
  | "RESOLVED"
  | "REGRESSED"
  | "CHANGED"
  | "UNVERIFIED";
export type ReportRemediationPriority = "FIX_NOW" | "FIX_NEXT" | "PLANNED" | "HARDENING";
export type ReportConfidenceLevel = "CONFIRMED" | "HIGH_CONFIDENCE" | "POSSIBLE" | "FALSE_POSITIVE";

export interface ReportEvidence {
  id: string;
  timestamp: string;
  source: string;
  asset: string;
  requestMetadata: unknown;
  responseMetadata: unknown;
  redactedExcerpt: string;
  hash: string;
}

export interface ReportFinding {
  id: string;
  title: string;
  category: string;
  severity: ReportSeverity;
  confidence: number;
  status: string;
  cwe: string[];
  owasp: string[];
  asset: string;
  endpoint: string | null;
  method: string | null;
  parameter: string | null;
  description: string;
  technicalImpact: string;
  businessImpact: string;
  evidence: ReportEvidence[];
  scannerSources: string[];
  remediation: string;
  manualVerificationRequired: boolean;
  trendStatus: FindingTrendStatus;
  remediationPriority: ReportRemediationPriority;
  recurrenceCount: number;
  likelyFalsePositive: boolean | null;
  reasoningSummary: string | null;
  firstSeen: string;
  lastSeen: string;
}

export interface ReportMonthlyComparison {
  previousScanId: string | null;
  coverageSufficient: boolean;
  coverageRatio: number;
  coverageReasons: string[];
  counts: Record<FindingTrendStatus, number>;
  newAssets: string[];
  removedAssets: string[];
  technologyChanges: { added: string[]; removed: string[] };
  resolvedFindings: Array<{ id: string; title: string; severity: ReportSeverity; reason: string }>;
  unverifiedFindings: Array<{
    id: string;
    title: string;
    severity: ReportSeverity;
    reason: string;
  }>;
}

export interface ScanReportInput {
  scan: {
    id: string;
    name: string;
    state: string;
    createdAt: string;
    startedAt: string | null;
    completedAt: string | null;
    warningCount: number;
  };
  workspace: { id: string; name: string };
  target: { name: string; origin: string; status: string; scopeConfiguredAt: string };
  scopeRules: Array<{ type: string; value: string; enabled: boolean }>;
  config: Record<string, unknown>;
  stages: Array<{
    name: string;
    status: string;
    startedAt: string | null;
    completedAt: string | null;
    completedUnits: number | null;
    totalUnits: number | null;
    errorMessage: string | null;
  }>;
  assets: Array<{ assetType: string; value: string; firstSeenAt: string; lastSeenAt: string }>;
  urls: Array<{
    canonicalUrl: string;
    depth: number;
    statusCode: number | null;
    contentType: string | null;
  }>;
  endpoints: Array<{
    asset: string;
    path: string;
    method: string;
    source: string;
    parameters: Array<{ name: string; location: string; observedType: string | null }>;
  }>;
  technologies: Array<{
    technology: string;
    possibleVersion: string | null;
    confidence: number;
    evidenceIds: string[];
  }>;
  findings: ReportFinding[];
  authorizationMatrices?: Array<{
    testCaseId: string;
    name: string;
    method: string;
    endpointTemplate: string;
    degraded: boolean;
    incompleteIdentityCount: number;
    cells: Array<{
      identityLabel: string;
      expected: string;
      statusCode: number;
      classification: string;
      severity: string;
      confidence: number;
    }>;
  }>;
  comparison: ReportMonthlyComparison;
  qwenAnalysis: {
    status: "NOT_CONFIGURED" | "NOT_RUN" | "COMPLETED" | "PARTIAL" | "FAILED_OR_WAITING";
    totalFindings: number;
    validatedAnalyses: number;
    failedOrWaitingAnalyses: number;
  };
  scannerSources: string[];
  requestsPerformed: number;
  failedOrDegradedStages: Array<{ name: string; status: string; errorMessage: string | null }>;
  generatedAt: string;
}

export interface GeneratedReport<T> {
  document: T;
  html: string;
  pdfReadyHtml: string;
  sha256: string;
  pdfReadySha256: string;
}

export interface WeaknessSummary {
  category: string;
  riskLevel: ReportSeverity;
  riskScore: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  mostImportantEvidenceIds: string[];
  affectedAreas: string[];
  recommendedPriority: string;
  summary: string;
}

export interface ExposedAssetSummary {
  asset: string;
  findingCount: number;
  highestSeverity: ReportSeverity;
}

export interface ChainedRisk {
  title: string;
  findingIds: string[];
  riskLevel: ReportSeverity;
  rationale: string;
  manualVerificationRequired: true;
}

export interface SecurityDomainScore {
  domain: string;
  score: number | null;
  assessment: "FINDINGS_OBSERVED" | "NO_FINDINGS_OBSERVED" | "NOT_ASSESSED";
  findingCount: number;
  scannerSources: string[];
}

export interface SecurityScorecard {
  finalScore: number | null;
  methodology: string;
  domains: SecurityDomainScore[];
}

const severityOrder: ReportSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const severityRank: Readonly<Record<ReportSeverity, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};
const priorityRank: Readonly<Record<ReportRemediationPriority, number>> = {
  HARDENING: 0,
  PLANNED: 1,
  FIX_NEXT: 2,
  FIX_NOW: 3,
};

const severityPenalty: Readonly<Record<ReportSeverity, number>> = {
  INFO: 1,
  LOW: 6,
  MEDIUM: 14,
  HIGH: 26,
  CRITICAL: 40,
};

const securityDomains = [
  {
    domain: "Authentication",
    category: /(?:AUTHENTICATION|PASSWORD|MFA|LOGIN|TOKEN)/u,
    scanner: /(?:auth|cookie|application)/u,
  },
  {
    domain: "Authorization",
    category: /(?:AUTHORIZATION|ACCESS|OBJECT_LEVEL|FUNCTION_LEVEL|IDOR|BOLA|RBAC)/u,
    scanner: /(?:auth|application)/u,
  },
  {
    domain: "Input validation",
    category: /(?:INPUT|INJECTION|REFLECTION|VALIDATION|XSS|TRAVERSAL|REDIRECT|SSRF)/u,
    scanner: /application/u,
  },
  {
    domain: "API security",
    category: /(?:API|GRAPHQL|MASS_ASSIGNMENT|CORS)/u,
    scanner: /(?:application|cors|misconfiguration)/u,
  },
  {
    domain: "Data protection",
    category: /(?:TLS|TRANSPORT|COOKIE|SESSION|CACHE|SECRET|CRYPTO|DISCLOSURE)/u,
    scanner: /(?:tls|cookie|http)/u,
  },
  {
    domain: "Infrastructure",
    category: /(?:CONFIGURATION|HEADER|TLS|TRANSPORT|SERVER|DEBUG|DIRECTORY|BACKUP)/u,
    scanner: /(?:headers|tls|http|misconfiguration)/u,
  },
  {
    domain: "Multi-tenancy",
    category: /(?:TENANT|WORKSPACE|ORGANIZATION|OWNERSHIP_TRANSFER)/u,
    scanner: /tenant/u,
  },
  {
    domain: "Monitoring",
    category: /(?:MONITORING|LOGGING|AUDIT|ALERT)/u,
    scanner: /monitor/u,
  },
  {
    domain: "Dependency security",
    category: /(?:DEPENDENCY|CVE|SUPPLY_CHAIN|LIBRARY|PACKAGE)/u,
    scanner: /(?:application|misconfiguration|dependency)/u,
  },
] as const;

function escapeHtml(value: string | number | boolean | null | undefined): string {
  return (value ?? "")
    .toString()
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatDate(value: string | null): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : `${date.toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

function duration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt || !completedAt) return "—";
  const milliseconds = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  return milliseconds < 1_000 ? `${milliseconds} ms` : `${(milliseconds / 1_000).toFixed(1)} s`;
}

function percent(value: number): string {
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

function severityCounts(findings: readonly ReportFinding[]): Record<ReportSeverity, number> {
  return Object.fromEntries(
    severityOrder.map((severity) => [
      severity,
      findings.filter((finding) => finding.severity === severity).length,
    ]),
  ) as Record<ReportSeverity, number>;
}

function overallPosture(counts: Record<ReportSeverity, number>): string {
  if (counts.CRITICAL > 0) return "Critical risk requires immediate action";
  if (counts.HIGH > 0) return "High-priority security weaknesses require prompt remediation";
  if (counts.MEDIUM > 0) return "Material hardening opportunities were identified";
  if (counts.LOW > 0) return "Generally stable with defense-in-depth improvements recommended";
  if (counts.INFO > 0) return "Informational observations only within assessed coverage";
  return "NO FINDINGS OBSERVED within assessed coverage — this does not prove the target secure";
}

function mainWeaknessCategory(category: string): string {
  if (/(?:ACCESS|CORS|CSRF|AUTHORIZATION|OBJECT_LEVEL|FUNCTION_LEVEL)/u.test(category))
    return "Access-control weaknesses";
  if (/(?:AUTHENTICATION|SESSION|COOKIE|PASSWORD|MFA|TOKEN)/u.test(category))
    return "Authentication/session weaknesses";
  if (/(?:INPUT|INJECTION|REFLECTION|VALIDATION|XSS|REDIRECT)/u.test(category))
    return "Input-validation weaknesses";
  if (/(?:API|GRAPHQL)/u.test(category)) return "API-security weaknesses";
  if (/(?:TLS|TRANSPORT|MIXED_CONTENT|CRYPTO)/u.test(category)) return "Transport/TLS weaknesses";
  if (/(?:CLIENT|DOM|SOURCE_CODE|SOURCE_MAP|DEPENDENCY)/u.test(category))
    return "Client-side weaknesses";
  if (/(?:DISCLOSURE|VERBOSE|INFORMATION)/u.test(category)) return "Information disclosure";
  if (/(?:BUSINESS|WORKFLOW)/u.test(category)) return "Business-logic weaknesses";
  if (/(?:FILE|UPLOAD|PATH|RESOURCE)/u.test(category)) return "File-handling weaknesses";
  return "Security configuration weaknesses";
}

export function classifyFindingConfidence(finding: ReportFinding): ReportConfidenceLevel {
  if (finding.status === "FALSE_POSITIVE") return "FALSE_POSITIVE";
  if (finding.confidence >= 0.9 && !finding.manualVerificationRequired) return "HIGH_CONFIDENCE";
  if (finding.confidence >= 0.7) return "HIGH_CONFIDENCE";
  return "POSSIBLE";
}

export function buildSecurityScorecard(input: ScanReportInput): SecurityScorecard {
  const normalizedSources = input.scannerSources.map((source) => source.toLowerCase());
  const domains = securityDomains.map((definition): SecurityDomainScore => {
    const findings = input.findings.filter((finding) => definition.category.test(finding.category));
    const scannerSources = normalizedSources.filter((source) => definition.scanner.test(source));
    if (findings.length === 0 && scannerSources.length === 0) {
      return {
        domain: definition.domain,
        score: null,
        assessment: "NOT_ASSESSED",
        findingCount: 0,
        scannerSources: [],
      };
    }
    const penalty = findings.reduce((total, finding) => {
      if (classifyFindingConfidence(finding) === "FALSE_POSITIVE") return total;
      const manualVerificationFactor = finding.manualVerificationRequired ? 0.75 : 1;
      return (
        total + severityPenalty[finding.severity] * finding.confidence * manualVerificationFactor
      );
    }, 0);
    return {
      domain: definition.domain,
      score: Math.max(0, Math.round(100 - penalty)),
      assessment: findings.length > 0 ? "FINDINGS_OBSERVED" : "NO_FINDINGS_OBSERVED",
      findingCount: findings.length,
      scannerSources,
    };
  });
  const scored = domains.filter(
    (domain): domain is SecurityDomainScore & { score: number } => domain.score !== null,
  );
  return {
    finalScore:
      scored.length > 0
        ? Math.round(scored.reduce((total, domain) => total + domain.score, 0) / scored.length)
        : null,
    methodology:
      "Coverage-aware observed-control score. Severity, confidence, and manual-verification status reduce scored domains; unassessed domains remain unscored. This is not proof of security.",
    domains,
  };
}

function highestSeverity(findings: readonly ReportFinding[]): ReportSeverity {
  return (
    severityOrder.find((severity) => findings.some((finding) => finding.severity === severity)) ??
    "INFO"
  );
}

export function analyzeChainedRisks(findings: readonly ReportFinding[]): ChainedRisk[] {
  const eligible = findings.filter(
    (finding) =>
      finding.confidence >= 0.5 && classifyFindingConfidence(finding) !== "FALSE_POSITIVE",
  );
  const chainDefinitions = [
    {
      title: "Identity and access-control compound risk",
      left: /(?:AUTHENTICATION|SESSION|COOKIE|PASSWORD|TOKEN)/u,
      right: /(?:AUTHORIZATION|ACCESS|OBJECT_LEVEL|FUNCTION_LEVEL|IDOR|BOLA|RBAC)/u,
      rationale:
        "Authentication or session weaknesses combined with access-control weaknesses may amplify unauthorized access. The combined exploit path was not executed and requires authorized manual validation.",
    },
    {
      title: "Input handling and browser-control compound risk",
      left: /(?:INPUT|INJECTION|REFLECTION|XSS|VALIDATION)/u,
      right: /(?:CONTENT_SECURITY_POLICY|SECURITY_HEADER|CLIENT|DOM|COOKIE|SESSION)/u,
      rationale:
        "Unsafe input handling combined with weak browser defenses may increase client-side impact. The chained behavior was not executed and requires authorized manual validation.",
    },
    {
      title: "Disclosure and exposed-component compound risk",
      left: /(?:DISCLOSURE|VERBOSE|INFORMATION|DEBUG)/u,
      right: /(?:DEPENDENCY|CVE|CONFIGURATION|SERVER|ADMIN)/u,
      rationale:
        "Information disclosure combined with exposed or weakly configured components may reduce attacker uncertainty. Exploitability is not established by this correlation alone.",
    },
  ] as const;
  return chainDefinitions.flatMap((definition): ChainedRisk[] => {
    const left = eligible.filter((finding) => definition.left.test(finding.category));
    const right = eligible.filter(
      (finding) => definition.right.test(finding.category) && !left.includes(finding),
    );
    if (left.length === 0 || right.length === 0) return [];
    const related = [...left, ...right];
    return [
      {
        title: definition.title,
        findingIds: [...new Set(related.map((finding) => finding.id))],
        riskLevel: highestSeverity(related),
        rationale: definition.rationale,
        manualVerificationRequired: true,
      },
    ];
  });
}

export function summarizeWeaknesses(findings: readonly ReportFinding[]): WeaknessSummary[] {
  const groups = new Map<string, ReportFinding[]>();
  for (const finding of findings) {
    const category = mainWeaknessCategory(finding.category);
    groups.set(category, [...(groups.get(category) ?? []), finding]);
  }
  return [...groups.entries()]
    .map(([category, items]) => {
      const ordered = [...items].sort(
        (left, right) =>
          severityRank[right.severity] - severityRank[left.severity] ||
          right.confidence - left.confidence,
      );
      const riskLevel = ordered[0]?.severity ?? "INFO";
      const riskScoreBase: Record<ReportSeverity, number> = {
        INFO: 5,
        LOW: 25,
        MEDIUM: 50,
        HIGH: 75,
        CRITICAL: 95,
      };
      const highestPriority = [...items].sort(
        (left, right) =>
          priorityRank[right.remediationPriority] - priorityRank[left.remediationPriority],
      )[0]?.remediationPriority;
      const affectedAssets = new Set(items.map(({ asset }) => asset));
      return {
        category,
        riskLevel,
        riskScore: Math.min(100, riskScoreBase[riskLevel] + Math.min(10, (items.length - 1) * 2)),
        findingCount: items.length,
        criticalCount: items.filter(({ severity }) => severity === "CRITICAL").length,
        highCount: items.filter(({ severity }) => severity === "HIGH").length,
        mostImportantEvidenceIds: [
          ...new Set(ordered.flatMap((finding) => finding.evidence.map(({ id }) => id))),
        ].slice(0, 5),
        affectedAreas: [
          ...new Set(ordered.map((finding) => `${finding.asset}${finding.endpoint ?? ""}`)),
        ].slice(0, 10),
        recommendedPriority: highestPriority ?? "HARDENING",
        summary: `${items.length} evidence-backed finding${items.length === 1 ? "" : "s"} affected ${affectedAssets.size} observed asset${affectedAssets.size === 1 ? "" : "s"}.`,
      };
    })
    .sort(
      (left, right) =>
        severityRank[right.riskLevel] - severityRank[left.riskLevel] ||
        right.findingCount - left.findingCount ||
        left.category.localeCompare(right.category),
    );
}

function summarizeExposedAssets(findings: readonly ReportFinding[]): ExposedAssetSummary[] {
  const groups = new Map<string, ReportFinding[]>();
  for (const finding of findings)
    groups.set(finding.asset, [...(groups.get(finding.asset) ?? []), finding]);
  return [...groups.entries()]
    .map(([asset, items]) => ({
      asset,
      findingCount: items.length,
      highestSeverity:
        [...items].sort(
          (left, right) => severityRank[right.severity] - severityRank[left.severity],
        )[0]?.severity ?? "INFO",
    }))
    .sort(
      (left, right) =>
        severityRank[right.highestSeverity] - severityRank[left.highestSeverity] ||
        right.findingCount - left.findingCount,
    )
    .slice(0, 10);
}

const styles = `
:root{--ink:#20231f;--muted:#686c66;--line:#dedfd9;--paper:#fff;--wash:#f4f3ef;--critical:#8f2525;--high:#a3472e;--medium:#8a6516;--low:#2d6175;--info:#53655a;font-family:"Helvetica Neue",Arial,sans-serif;color:var(--ink)}
*{box-sizing:border-box}body{margin:0;background:#efeee9;color:var(--ink);line-height:1.55}.report{width:min(1120px,calc(100% - 40px));margin:28px auto;background:var(--paper);border:1px solid var(--line)}.cover{padding:72px 64px 56px;border-bottom:1px solid var(--line);min-height:360px;display:flex;flex-direction:column;justify-content:space-between}.mark,.label{font:700 10px/1.2 ui-monospace,monospace;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}h1{font:500 clamp(40px,6vw,76px)/.98 Georgia,serif;letter-spacing:-.045em;max-width:850px;margin:30px 0}h2{font:500 31px/1.1 Georgia,serif;margin:0 0 20px}h3{font-size:15px;text-transform:uppercase;letter-spacing:.08em;margin:30px 0 10px}.cover-grid,.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line)}.cover-grid>div,.metric{background:#fff;padding:18px}.label{display:block;margin-bottom:7px}.section{padding:48px 64px;border-bottom:1px solid var(--line)}.lede{font:400 21px/1.5 Georgia,serif}.note{background:var(--wash);border-left:3px solid #9a9d94;padding:16px 18px}.facts,.split{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.fact{border:1px solid var(--line);padding:18px}.metric strong{font:500 34px/1 Georgia,serif}.severity{display:inline-block;border-radius:999px;padding:5px 9px;font:700 10px/1 ui-monospace,monospace}.severity.CRITICAL{background:#fdebec;color:var(--critical)}.severity.HIGH{background:#f8e9e2;color:var(--high)}.severity.MEDIUM{background:#fbf3db;color:var(--medium)}.severity.LOW{background:#e1f3fe;color:var(--low)}.severity.INFO{background:#edf3ec;color:var(--info)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:12px 8px}th{color:var(--muted);font:700 10px/1.2 ui-monospace,monospace}.finding{border:1px solid var(--line);padding:26px;margin:18px 0}.finding-head{display:flex;justify-content:space-between;gap:24px}.meta{color:var(--muted);font:12px/1.5 ui-monospace,monospace}.evidence{background:#191b19;color:#f1f1ec;padding:18px;overflow-wrap:anywhere;white-space:pre-wrap;font:12px/1.55 ui-monospace,monospace}.footer{padding:26px 64px;color:var(--muted);font-size:12px}@media(max-width:760px){.cover,.section{padding:36px 24px}.cover-grid,.metrics,.facts,.split{grid-template-columns:1fr}.report{width:100%;margin:0}}@media print{body{background:#fff}.report{border:0;width:100%;margin:0}.section,.finding{break-inside:avoid}.cover{min-height:90vh}}
`;

function documentShell(title: string, body: string, pdfReady: boolean): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'"><title>${escapeHtml(title)}</title><style>${styles}${pdfReady ? "@page{size:A4;margin:14mm}.report{max-width:none}" : ""}</style></head><body><main class="report"><p class="note">Internal working report. Human review and client-safe publication approval are required before delivery.</p>${body}</main></body></html>`;
}

function finish<T>(title: string, body: string, document: T): GeneratedReport<T> {
  if (containsUnredactedSecret(document))
    throw new Error("Report export blocked: unredacted secret detected.");
  const html = documentShell(title, body, false);
  const pdfReadyHtml = documentShell(title, body, true);
  return {
    document,
    html,
    pdfReadyHtml,
    sha256: createHash("sha256").update(html).digest("hex"),
    pdfReadySha256: createHash("sha256").update(pdfReadyHtml).digest("hex"),
  };
}

function evidenceHtml(evidence: readonly ReportEvidence[]): string {
  if (evidence.length === 0)
    return '<p class="note">No evidence object was linked. This finding must not be treated as confirmed.</p>';
  return evidence
    .map(
      (item) =>
        `<pre class="evidence">${escapeHtml(item.id)} · ${escapeHtml(item.source)} · ${escapeHtml(formatDate(item.timestamp))}\n${escapeHtml(item.asset)} · SHA-256 ${escapeHtml(item.hash)}\n\n${escapeHtml(item.redactedExcerpt || "No response excerpt retained.")}</pre>`,
    )
    .join("");
}

function orderedFindings(findings: readonly ReportFinding[]): ReportFinding[] {
  return [...findings].sort(
    (left, right) =>
      priorityRank[right.remediationPriority] - priorityRank[left.remediationPriority] ||
      severityRank[right.severity] - severityRank[left.severity] ||
      right.confidence - left.confidence,
  );
}

function findingDetails(finding: ReportFinding): string {
  return `<article class="finding"><div class="finding-head"><div><span class="meta">${escapeHtml(finding.id)} · ${escapeHtml(finding.trendStatus)} · ${escapeHtml(finding.remediationPriority)}</span><h3>${escapeHtml(finding.title)}</h3></div><span class="severity ${finding.severity}">${finding.severity}</span></div><div class="facts"><div class="fact"><span class="label">Confidence</span>${escapeHtml(classifyFindingConfidence(finding))} · ${escapeHtml(percent(finding.confidence))}</div><div class="fact"><span class="label">Affected URL</span>${escapeHtml(`${finding.asset}${finding.endpoint ?? ""}`)}</div></div><h3>Detailed description</h3><p>${escapeHtml(finding.description)}</p><div class="split"><div><h3>Technical impact</h3><p>${escapeHtml(finding.technicalImpact)}</p></div><div><h3>Business impact</h3><p>${escapeHtml(finding.businessImpact)}</p></div></div><h3>Evidence</h3>${evidenceHtml(finding.evidence)}<h3>Remediation</h3><p>${escapeHtml(finding.remediation)}</p></article>`;
}

export function generateCompleteScanReport(input: ScanReportInput): GeneratedReport<
  ScanReportInput & {
    posture: string;
    overallRisk: ReportSeverity | "NONE";
    severityCounts: Record<ReportSeverity, number>;
    topWeaknesses: WeaknessSummary[];
    mostExposedAssets: ExposedAssetSummary[];
    highestPriorityFixes: Array<{
      findingId: string;
      title: string;
      priority: ReportRemediationPriority;
      remediation: string;
    }>;
    chainedRisks: ChainedRisk[];
    securityScorecard: SecurityScorecard;
  }
> {
  const counts = severityCounts(input.findings);
  const posture = overallPosture(counts);
  const overallRisk: ReportSeverity | "NONE" =
    severityOrder.find((severity) => counts[severity] > 0) ?? "NONE";
  const topWeaknesses = summarizeWeaknesses(input.findings);
  const mostExposedAssets = summarizeExposedAssets(input.findings);
  const priorityFindings = orderedFindings(input.findings)
    .filter(({ severity }) => severity !== "INFO")
    .slice(0, 10);
  const highestPriorityFixes = priorityFindings.map((finding) => ({
    findingId: finding.id,
    title: finding.title,
    priority: finding.remediationPriority,
    remediation: finding.remediation,
  }));
  const chainedRisks = analyzeChainedRisks(input.findings);
  const securityScorecard = buildSecurityScorecard(input);
  const document = {
    ...input,
    posture,
    overallRisk,
    severityCounts: counts,
    topWeaknesses,
    mostExposedAssets,
    highestPriorityFixes,
    chainedRisks,
    securityScorecard,
  };
  const weaknessRows = topWeaknesses
    .map(
      (item, index) =>
        `<tr><td>${index + 1}</td><td>${escapeHtml(item.category)}</td><td><span class="severity ${item.riskLevel}">${item.riskLevel}</span></td><td>${item.riskScore}</td><td>${item.findingCount}</td><td>${escapeHtml(item.affectedAreas.join(", "))}</td><td>${escapeHtml(item.recommendedPriority)}</td></tr>`,
    )
    .join("");
  const stageRows = input.stages
    .map(
      (stage) =>
        `<tr><td>${escapeHtml(stage.name)}</td><td>${escapeHtml(stage.status)}</td><td>${escapeHtml(duration(stage.startedAt, stage.completedAt))}</td><td>${escapeHtml(stage.completedUnits ?? "—")} / ${escapeHtml(stage.totalUnits ?? "—")}</td><td>${escapeHtml(stage.errorMessage ?? "")}</td></tr>`,
    )
    .join("");
  const findingRows = input.findings
    .map(
      (finding) =>
        `<tr><td>${escapeHtml(finding.id)}</td><td>${escapeHtml(finding.title)}</td><td><span class="severity ${finding.severity}">${finding.severity}</span></td><td>${escapeHtml(percent(finding.confidence))}</td><td>${escapeHtml(finding.trendStatus)}</td><td>${escapeHtml(finding.remediationPriority)}</td></tr>`,
    )
    .join("");
  const authorizationMatrices = input.authorizationMatrices ?? [];
  const authorizationMatrixHtml = authorizationMatrices
    .map(
      (matrix) =>
        `<article class="finding"><h3>${escapeHtml(matrix.name)}</h3><p class="meta">${escapeHtml(matrix.method)} ${escapeHtml(matrix.endpointTemplate)} · ${matrix.degraded ? `DEGRADED (${matrix.incompleteIdentityCount} unavailable)` : "COMPLETE"}</p><table><thead><tr><th>Identity</th><th>Expected</th><th>Observed</th><th>Analysis</th><th>Confidence</th></tr></thead><tbody>${matrix.cells.map((cell) => `<tr><td>${escapeHtml(cell.identityLabel)}</td><td>${escapeHtml(cell.expected)}</td><td>HTTP ${cell.statusCode}</td><td>${escapeHtml(cell.classification)}</td><td>${escapeHtml(percent(cell.confidence))}</td></tr>`).join("")}</tbody></table></article>`,
    )
    .join("");
  const body = `<section class="cover"><div><div class="mark">Authorized security assessment · Complete technical report</div><h1>${escapeHtml(input.scan.name)}</h1><p class="lede">Evidence-backed assessment of ${escapeHtml(input.target.origin)}</p></div><div class="cover-grid"><div><span class="label">Scan ID</span>${escapeHtml(input.scan.id)}</div><div><span class="label">Workspace</span>${escapeHtml(input.workspace.name)}</div><div><span class="label">Generated</span>${escapeHtml(formatDate(input.generatedAt))}</div><div><span class="label">State</span>${escapeHtml(input.scan.state)}</div></div></section>
  <section class="section"><span class="label">Executive summary</span><h2>${escapeHtml(posture)}</h2><p class="lede">${input.findings.length} evidence-backed finding${input.findings.length === 1 ? "" : "s"} across ${input.urls.length} discovered URL${input.urls.length === 1 ? "" : "s"}. Risk reflects observed behavior and measured non-destructive coverage only.</p><div class="metrics">${severityOrder.map((severity) => `<div class="metric"><span class="label">${severity}</span><strong>${counts[severity]}</strong></div>`).join("")}</div></section>
  <section class="section"><span class="label">Engagement authorization &amp; scope</span><h2>Configured technical boundary</h2><p>Authorization is established through the organization's engagement process. Every outbound target request is checked against the saved scope; redirects outside it are blocked.</p><table><thead><tr><th>Rule</th><th>Value</th><th>Enabled</th></tr></thead><tbody>${input.scopeRules.map((rule) => `<tr><td>${escapeHtml(rule.type)}</td><td>${escapeHtml(rule.value)}</td><td>${rule.enabled ? "Yes" : "No"}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">Methodology & coverage</span><h2>Controlled non-destructive analysis</h2><p>Bounded discovery, crawling, API/client-side discovery, fingerprinting, passive analysis, controlled safe validation, evidence validation, correlation, false-positive review, and reporting were performed where their stages completed. No destructive exploitation, brute force, denial-of-service, persistence, data extraction, or out-of-scope pivoting was performed.</p><div class="metrics"><div class="metric"><span class="label">URLs</span><strong>${input.urls.length}</strong></div><div class="metric"><span class="label">Endpoints</span><strong>${input.endpoints.length}</strong></div><div class="metric"><span class="label">Technologies</span><strong>${input.technologies.length}</strong></div><div class="metric"><span class="label">Requests</span><strong>${input.requestsPerformed}</strong></div></div><table><thead><tr><th>Stage</th><th>Status</th><th>Duration</th><th>Units</th><th>Error</th></tr></thead><tbody>${stageRows}</tbody></table></section>
  <section class="section"><span class="label">Attack surface</span><h2>Observed inventory</h2><p>${input.assets.length} assets, ${input.urls.length} URLs, ${input.endpoints.length} endpoints, and ${input.technologies.length} evidence-backed technology fingerprints were persisted.</p><table><thead><tr><th>Technology</th><th>Version evidence</th><th>Confidence</th></tr></thead><tbody>${input.technologies.map((item) => `<tr><td>${escapeHtml(item.technology)}</td><td>${escapeHtml(item.possibleVersion ?? "UNKNOWN_VERSION")}</td><td>${escapeHtml(percent(item.confidence))}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">Authorization matrix</span><h2>Expected versus observed identity behavior</h2>${authorizationMatrixHtml || "<p>No multi-identity authorization test case was configured for this assessment.</p>"}</section>
  <section class="section"><span class="label">Site weakness model</span><h2>What are this website's main weaknesses?</h2>${weaknessRows ? `<table><thead><tr><th>Rank</th><th>Area</th><th>Risk</th><th>Score</th><th>Findings</th><th>Affected areas</th><th>Priority</th></tr></thead><tbody>${weaknessRows}</tbody></table>` : '<p class="note"><strong>NO FINDINGS OBSERVED.</strong> This does not prove the website secure.</p>'}</section>
  <section class="section"><span class="label">Monthly comparison</span><h2>${input.comparison.previousScanId ? "Compared with previous completed assessment" : "Initial assessment baseline"}</h2><div class="metrics"><div class="metric"><span class="label">New</span><strong>${input.comparison.counts.NEW}</strong></div><div class="metric"><span class="label">Recurring</span><strong>${input.comparison.counts.RECURRING}</strong></div><div class="metric"><span class="label">Resolved</span><strong>${input.comparison.counts.RESOLVED}</strong></div><div class="metric"><span class="label">Unverified</span><strong>${input.comparison.counts.UNVERIFIED}</strong></div></div><p>Comparable coverage: <strong>${input.comparison.coverageSufficient ? "YES" : "NO"}</strong> (${escapeHtml(percent(input.comparison.coverageRatio))}). ${escapeHtml(input.comparison.coverageReasons.join(" ") || "No comparison caveat recorded.")}</p>${input.comparison.unverifiedFindings.length ? `<p class="note">${input.comparison.unverifiedFindings.length} prior finding(s) were not rediscovered but remain UNVERIFIED because coverage was insufficient.</p>` : ""}</section>
  <section class="section"><span class="label">Qwen analysis</span><h2>${escapeHtml(input.qwenAnalysis.status.replaceAll("_", " "))}</h2><p>${input.qwenAnalysis.validatedAnalyses} of ${input.qwenAnalysis.totalFindings} finding analyses passed schema and evidence validation; ${input.qwenAnalysis.failedOrWaitingAnalyses} failed or remain incomplete. Deterministic findings remain available when model analysis is unavailable. No model output is invented.</p></section>
  <section class="section"><span class="label">Finding register</span><h2>All findings</h2><table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Confidence</th><th>Trend</th><th>Priority</th></tr></thead><tbody>${findingRows}</tbody></table>${input.findings.map(findingDetails).join("") || '<p class="note">No evidence-backed findings were created.</p>'}</section>
  <section class="section"><span class="label">Chained-risk analysis</span><h2>Potential compound weaknesses</h2>${chainedRisks.length ? `<table><thead><tr><th>Chain</th><th>Risk</th><th>Findings</th><th>Assessment</th></tr></thead><tbody>${chainedRisks.map((risk) => `<tr><td>${escapeHtml(risk.title)}</td><td><span class="severity ${risk.riskLevel}">${risk.riskLevel}</span></td><td>${escapeHtml(risk.findingIds.join(", "))}</td><td>${escapeHtml(risk.rationale)}</td></tr>`).join("")}</tbody></table>` : "<p>No evidence-backed compound-risk candidate was identified. This does not prove that no chained attack path exists.</p>"}</section>
  <section class="section"><span class="label">Security score</span><h2>${securityScorecard.finalScore === null ? "Insufficient evidence for a score" : `${securityScorecard.finalScore}/100 observed-control score`}</h2><p class="note">${escapeHtml(securityScorecard.methodology)}</p><table><thead><tr><th>Domain</th><th>Score</th><th>Assessment</th><th>Findings</th><th>Coverage evidence</th></tr></thead><tbody>${securityScorecard.domains.map((domain) => `<tr><td>${escapeHtml(domain.domain)}</td><td>${domain.score ?? "—"}</td><td>${escapeHtml(domain.assessment)}</td><td>${domain.findingCount}</td><td>${escapeHtml(domain.scannerSources.join(", ") || "No domain-specific analyzer evidence")}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">Remediation roadmap</span><h2>Risk-led action plan</h2>${priorityFindings.length ? `<ol>${priorityFindings.map((finding) => `<li><strong>${escapeHtml(finding.remediationPriority)} · ${escapeHtml(finding.id)} — ${escapeHtml(finding.title)}</strong>: ${escapeHtml(finding.remediation)}</li>`).join("")}</ol>` : "<p>No material remediation priority was generated.</p>"}</section>
  <section class="section"><span class="label">Limitations & execution quality</span><h2>Coverage is not proof of security</h2><p>Testing was bounded by the configured profile, authentication context, request budget, depth, rate, timeout, and safe-validation policy. A missing finding is not evidence of absence outside executed coverage.</p>${input.failedOrDegradedStages.length ? `<p class="note">${input.failedOrDegradedStages.length} stage(s) failed or degraded and are disclosed in the stage table.</p>` : "<p>No failed or degraded stage was recorded.</p>"}</section>
  <section class="section"><span class="label">Appendix</span><pre class="evidence">${escapeHtml(JSON.stringify({ scanConfig: input.config, scannerSources: input.scannerSources, comparison: input.comparison, qwenAnalysis: input.qwenAnalysis }, null, 2))}</pre></section><footer class="footer">Generated ${escapeHtml(formatDate(input.generatedAt))} · Authorized assessment · Evidence excerpts are redacted</footer>`;
  return finish(`${input.scan.name} — Complete scan report`, body, document);
}

export function generateExecutiveReport(input: ScanReportInput): GeneratedReport<{
  scan: ScanReportInput["scan"];
  target: ScanReportInput["target"];
  generatedAt: string;
  overallRisk: ReportSeverity | "NONE";
  posture: string;
  severityCounts: Record<ReportSeverity, number>;
  topRisks: ReportFinding[];
  weaknessAreas: WeaknessSummary[];
  remediationPriorities: Record<ReportRemediationPriority, number>;
  comparison: ReportMonthlyComparison;
  qwenAnalysis: ScanReportInput["qwenAnalysis"];
  chainedRisks: ChainedRisk[];
  securityScorecard: SecurityScorecard;
}> {
  const counts = severityCounts(input.findings);
  const overallRisk: ReportSeverity | "NONE" =
    severityOrder.find((severity) => counts[severity] > 0) ?? "NONE";
  const posture = overallPosture(counts);
  const topRisks = orderedFindings(input.findings).slice(0, 5);
  const weaknessAreas = summarizeWeaknesses(input.findings);
  const remediationPriorities = Object.fromEntries(
    (["FIX_NOW", "FIX_NEXT", "PLANNED", "HARDENING"] as const).map((priority) => [
      priority,
      input.findings.filter(({ remediationPriority }) => remediationPriority === priority).length,
    ]),
  ) as Record<ReportRemediationPriority, number>;
  const chainedRisks = analyzeChainedRisks(input.findings);
  const securityScorecard = buildSecurityScorecard(input);
  const document = {
    scan: input.scan,
    target: input.target,
    generatedAt: input.generatedAt,
    overallRisk,
    posture,
    severityCounts: counts,
    topRisks,
    weaknessAreas,
    remediationPriorities,
    comparison: input.comparison,
    qwenAnalysis: input.qwenAnalysis,
    chainedRisks,
    securityScorecard,
  };
  const body = `<section class="cover"><div><div class="mark">Executive security report</div><h1>${escapeHtml(input.target.name)}</h1><p class="lede">${escapeHtml(posture)}</p></div><div class="cover-grid"><div><span class="label">Overall risk</span>${escapeHtml(overallRisk)}</div><div><span class="label">Findings</span>${input.findings.length}</div><div><span class="label">Coverage</span>${input.urls.length} URLs</div><div><span class="label">Generated</span>${escapeHtml(formatDate(input.generatedAt))}</div></div></section>
  <section class="section"><span class="label">Leadership summary</span><h2>Observed security posture</h2><p class="lede">This report summarizes evidence-backed, non-destructive testing within the configured authorization boundary. It does not claim the application is secure when no finding is observed.</p><div class="metrics">${severityOrder.map((severity) => `<div class="metric"><span class="label">${severity}</span><strong>${counts[severity]}</strong></div>`).join("")}</div></section>
  <section class="section"><span class="label">Top five risks</span><h2>What leadership should address first</h2>${topRisks.length ? `<ol>${topRisks.map((finding) => `<li><strong>${escapeHtml(finding.remediationPriority)} · ${escapeHtml(finding.title)}</strong><br>${escapeHtml(finding.businessImpact)} <span class="meta">Confidence ${escapeHtml(percent(finding.confidence))}</span></li>`).join("")}</ol>` : '<p class="note">NO FINDINGS OBSERVED within executed coverage; this does not prove the target secure.</p>'}</section>
  <section class="section"><span class="label">Most affected areas</span><h2>Weakness concentration</h2><table><thead><tr><th>Area</th><th>Risk</th><th>Findings</th><th>Priority</th></tr></thead><tbody>${weaknessAreas.map((area) => `<tr><td>${escapeHtml(area.category)}</td><td>${escapeHtml(area.riskLevel)}</td><td>${area.findingCount}</td><td>${escapeHtml(area.recommendedPriority)}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">Security score</span><h2>${securityScorecard.finalScore === null ? "Not scored" : `${securityScorecard.finalScore}/100`}</h2><p>${escapeHtml(securityScorecard.methodology)}</p><p>Potential compound risks requiring manual review: ${chainedRisks.length}.</p></section>
  <section class="section"><span class="label">Change since previous assessment</span><h2>Monthly security movement</h2><p>New: ${input.comparison.counts.NEW}. Recurring: ${input.comparison.counts.RECURRING}. Regressed: ${input.comparison.counts.REGRESSED}. Resolved: ${input.comparison.counts.RESOLVED}. Unverified: ${input.comparison.counts.UNVERIFIED}.</p><p>Resolution claims are permitted only when coverage is comparable. Current comparison coverage: <strong>${input.comparison.coverageSufficient ? "SUFFICIENT" : "INSUFFICIENT"}</strong>.</p></section>
  <section class="section"><span class="label">30-day action plan</span><h2>Recommended priorities</h2><ol><li>Fix all FIX_NOW items and verify each control with retained retest evidence.</li><li>Schedule FIX_NEXT items, prioritizing recurring or regressed weaknesses.</li><li>Complete authorized manual validation for findings marked manual verification required.</li><li>Restore any failed/degraded coverage before claiming prior findings resolved.</li><li>Retest remediated endpoints in the next monthly assessment.</li></ol></section><footer class="footer">Generated ${escapeHtml(formatDate(input.generatedAt))} · Executive report · Evidence-backed results only</footer>`;
  return finish(`${input.scan.name} — Executive report`, body, document);
}

function confidenceLanguage(finding: ReportFinding): string {
  const basis = `Confidence is ${classifyFindingConfidence(finding)} (${percent(finding.confidence)}) based on ${finding.evidence.length} persisted evidence object${finding.evidence.length === 1 ? "" : "s"} from ${finding.scannerSources.join(", ")}.`;
  return finding.manualVerificationRequired
    ? `${basis} Safe automated evidence is insufficient for full impact confirmation; authorized manual verification is required.`
    : `${basis} Classification is limited to directly observed behavior.`;
}

function cvssEstimateLanguage(finding: ReportFinding): string {
  if (finding.severity === "INFO") return "Not applicable to an informational observation.";
  return `Not numerically calculated: the retained non-destructive evidence supports a qualitative ${finding.severity} rating but does not establish every CVSS vector metric. Authentication, privileges, user interaction, and CIA impact must be confirmed before assigning a numeric vector.`;
}

function safeReproductionLanguage(finding: ReportFinding): string {
  const location = `${finding.asset}${finding.endpoint ?? ""}`;
  return `Within the saved authorization boundary, repeat the original ${finding.method ?? "observed"} request to ${location} using the same non-sensitive test context. Compare the resulting behavior with evidence ${finding.evidence.map(({ id }) => id).join(", ")}. Stop after confirming whether the observable condition remains; do not retrieve unrelated data or perform a state-changing action.`;
}

function rootCauseLanguage(finding: ReportFinding): string {
  return `The observable control gap is in ${finding.category} handling at ${finding.endpoint ?? finding.asset}. Black-box evidence establishes the reported behavior, not the exact source-code defect. Review the component responsible for this response and related endpoints to determine whether the cause is missing enforcement, inconsistent configuration, or an upstream control that did not apply.`;
}

function secureImplementationLanguage(finding: ReportFinding): string {
  return `${finding.remediation} Enforce the control on the server-side trust boundary, centralize it where related routes share behavior, fail closed, and preserve an automated test proving unauthorized or malformed requests receive the expected safe response. Framework-specific code is intentionally omitted when the implementation technology is not confirmed by evidence.`;
}

function regressionTestLanguage(finding: ReportFinding): string {
  return `Create an automated test for ${finding.method ?? "the observed method"} ${finding.endpoint ?? finding.asset} that reproduces the sanitized pre-fix condition, asserts the corrected secure behavior, and exercises at least one related route or parameter. Run it in CI and retain the post-fix response as retest evidence.`;
}

function falsePositiveLanguage(finding: ReportFinding): string {
  if (finding.likelyFalsePositive === true)
    return "Evidence review identified a possible false positive. Confirm manually before closure.";
  if (finding.likelyFalsePositive === false)
    return "Available evidence is consistent with the stated weakness; compensating controls may still affect impact.";
  return "No validated model false-positive determination was available; deterministic evidence was retained.";
}

function referenceLinks(finding: ReportFinding): string {
  return `<ul>${finding.cwe.map((item) => `<li>${escapeHtml(item)} — MITRE CWE</li>`).join("")}${finding.owasp.map((item) => `<li>${escapeHtml(item)} — OWASP</li>`).join("")}</ul>`;
}

export function generateVulnerabilityReport(
  input: Pick<ScanReportInput, "scan" | "workspace" | "target" | "generatedAt"> & {
    finding: ReportFinding;
  },
): GeneratedReport<typeof input> {
  const { finding } = input;
  if (finding.evidence.length === 0)
    throw new Error("A vulnerability report requires linked evidence.");
  const body = `<section class="cover"><div><div class="mark">Detailed vulnerability report</div><h1>${escapeHtml(finding.title)}</h1><p><span class="severity ${finding.severity}">${finding.severity}</span></p></div><div class="cover-grid"><div><span class="label">Finding ID</span>${escapeHtml(finding.id)}</div><div><span class="label">Confidence</span>${escapeHtml(classifyFindingConfidence(finding))} · ${escapeHtml(percent(finding.confidence))}</div><div><span class="label">Trend</span>${escapeHtml(finding.trendStatus)}</div><div><span class="label">Priority</span>${escapeHtml(finding.remediationPriority)}</div></div></section>
  <section class="section"><span class="label">Affected surface</span><h2>Location and classification</h2><div class="facts"><div class="fact"><span class="label">Host</span>${escapeHtml(finding.asset)}</div><div class="fact"><span class="label">Endpoint</span>${escapeHtml(finding.endpoint ?? "Not endpoint-specific")}</div><div class="fact"><span class="label">Method</span>${escapeHtml(finding.method ?? "Not method-specific")}</div><div class="fact"><span class="label">Parameter</span>${escapeHtml(finding.parameter ?? "Not parameter-specific")}</div><div class="fact"><span class="label">CWE / OWASP</span>${escapeHtml([...finding.cwe, ...finding.owasp].join(" · "))}</div><div class="fact"><span class="label">Scanner sources</span>${escapeHtml(finding.scannerSources.join(", "))}</div></div></section>
  <section class="section"><span class="label">Detailed description</span><h2>What was observed and why it matters</h2><p class="lede">${escapeHtml(finding.description)}</p><h3>Root-cause analysis</h3><p>${escapeHtml(rootCauseLanguage(finding))}</p><div class="split"><div><h3>Technical impact</h3><p>${escapeHtml(finding.technicalImpact)}</p></div><div><h3>Business impact</h3><p>${escapeHtml(finding.businessImpact)}</p></div></div><h3>CVSS estimate</h3><p>${escapeHtml(cvssEstimateLanguage(finding))}</p></section>
  <section class="section"><span class="label">Evidence</span><h2>Redacted reproducible observations</h2>${evidenceHtml(finding.evidence)}<h3>Safe reproduction</h3><p>${escapeHtml(safeReproductionLanguage(finding))}</p><h3>Expected secure behavior</h3><p>${escapeHtml(finding.remediation)}</p></section>
  <section class="section"><span class="label">Confidence & false-positive analysis</span><p>${escapeHtml(confidenceLanguage(finding))}</p><p>${escapeHtml(falsePositiveLanguage(finding))}</p>${finding.reasoningSummary ? `<p class="note">${escapeHtml(finding.reasoningSummary)}</p>` : ""}</section>
  <section class="section"><span class="label">Remediation</span><h2>Corrective action</h2><p class="lede">${escapeHtml(finding.remediation)}</p><h3>Secure implementation example</h3><p>${escapeHtml(secureImplementationLanguage(finding))}</p><h3>Regression test</h3><p>${escapeHtml(regressionTestLanguage(finding))}</p><h3>Retest guidance</h3><p>Repeat the original safe request, confirm expected secure behavior, test related endpoints, and preserve new evidence.</p></section>
  <section class="section"><span class="label">Lineage</span><div class="facts"><div class="fact"><span class="label">First seen</span>${escapeHtml(formatDate(finding.firstSeen))}</div><div class="fact"><span class="label">Last seen</span>${escapeHtml(formatDate(finding.lastSeen))}</div><div class="fact"><span class="label">Recurrence</span>${finding.recurrenceCount} assessment(s)</div><div class="fact"><span class="label">Manual verification</span>${finding.manualVerificationRequired ? "Required" : "Not required"}</div></div></section>
  <section class="section"><span class="label">References</span>${referenceLinks(finding)}</section><footer class="footer">Workspace ${escapeHtml(input.workspace.name)} · Generated ${escapeHtml(formatDate(input.generatedAt))} · Evidence excerpts are redacted</footer>`;
  return finish(`${finding.id} — ${finding.title}`, body, input);
}
import { containsUnredactedSecret } from "@aasp/security-core";
