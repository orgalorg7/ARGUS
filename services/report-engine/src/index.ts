import { createHash } from "node:crypto";

export type ReportSeverity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

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
  likelyFalsePositive: boolean | null;
  reasoningSummary: string | null;
  firstSeen: string;
  lastSeen: string;
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
  target: {
    name: string;
    origin: string;
    status: string;
    scopeConfiguredAt: string;
  };
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

const severityOrder: ReportSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

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
    : date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
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
  return "No confirmed material weakness was identified within the assessed coverage";
}

function confidenceLanguage(finding: ReportFinding): string {
  const basis = `Confidence is ${percent(finding.confidence)} based on ${finding.evidence.length} persisted evidence object${finding.evidence.length === 1 ? "" : "s"} from ${finding.scannerSources.join(", ")}.`;
  return finding.manualVerificationRequired
    ? `${basis} Safe automated evidence is insufficient for full impact confirmation; authorized manual verification is required.`
    : `${basis} The classification is limited to the behavior directly observed during this assessment.`;
}

function falsePositiveLanguage(finding: ReportFinding): string {
  if (finding.likelyFalsePositive === true) {
    return "Automated evidence review identified characteristics consistent with a possible false positive. Retain the observation and confirm the affected behavior manually before closure.";
  }
  if (finding.likelyFalsePositive === false) {
    return "The available evidence is consistent with the stated configuration weakness. Environmental compensating controls may still affect practical impact.";
  }
  return "No validated model false-positive determination was available. The deterministic evidence and contextual classification were retained.";
}

function referenceLinks(finding: ReportFinding): string {
  const cwe = finding.cwe
    .map((item) => {
      const number = /^CWE-(\d+)$/.exec(item)?.[1];
      return number
        ? `<li><a href="https://cwe.mitre.org/data/definitions/${number}.html">${escapeHtml(item)} — MITRE CWE</a></li>`
        : `<li>${escapeHtml(item)}</li>`;
    })
    .join("");
  const owasp = finding.owasp.map((item) => `<li>${escapeHtml(item)} — OWASP Top 10</li>`).join("");
  return `<ul>${cwe}${owasp}</ul>`;
}

const styles = `
:root{--ink:#20231f;--muted:#686c66;--line:#dedfd9;--paper:#fff;--wash:#f4f3ef;--critical:#8f2525;--high:#a3472e;--medium:#8a6516;--low:#2d6175;--info:#53655a;font-family:"Helvetica Neue",Arial,sans-serif;color:var(--ink)}
*{box-sizing:border-box}body{margin:0;background:#efeee9;color:var(--ink);line-height:1.55}.report{width:min(1120px,calc(100% - 40px));margin:28px auto;background:var(--paper);border:1px solid var(--line)}
.cover{padding:72px 64px 56px;border-bottom:1px solid var(--line);min-height:420px;display:flex;flex-direction:column;justify-content:space-between}.mark{font:700 12px/1.2 ui-monospace,monospace;letter-spacing:.13em;text-transform:uppercase;color:var(--muted)}h1{font:500 clamp(40px,6vw,76px)/.98 Georgia,serif;letter-spacing:-.045em;max-width:850px;margin:30px 0}h2{font:500 31px/1.1 Georgia,serif;letter-spacing:-.025em;margin:0 0 20px}h3{font-size:15px;text-transform:uppercase;letter-spacing:.08em;margin:30px 0 10px}.cover-grid,.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line)}.cover-grid>div,.metric{background:#fff;padding:18px}.label{display:block;color:var(--muted);font:700 10px/1.2 ui-monospace,monospace;letter-spacing:.09em;text-transform:uppercase;margin-bottom:7px}.section{padding:48px 64px;border-bottom:1px solid var(--line)}.lede{font:400 21px/1.5 Georgia,serif;max-width:850px}.note{background:var(--wash);border-left:3px solid #9a9d94;padding:16px 18px}.facts{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.fact{border:1px solid var(--line);padding:18px}.metric strong{font:500 34px/1 Georgia,serif}.severity{display:inline-block;border-radius:999px;padding:5px 9px;font:700 10px/1 ui-monospace,monospace;letter-spacing:.07em}.severity.CRITICAL{background:#fdebec;color:var(--critical)}.severity.HIGH{background:#f8e9e2;color:var(--high)}.severity.MEDIUM{background:#fbf3db;color:var(--medium)}.severity.LOW{background:#e1f3fe;color:var(--low)}.severity.INFO{background:#edf3ec;color:var(--info)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:12px 8px}th{color:var(--muted);font:700 10px/1.2 ui-monospace,monospace;letter-spacing:.06em;text-transform:uppercase}.finding{border:1px solid var(--line);padding:26px;margin:18px 0}.finding-head{display:flex;justify-content:space-between;gap:24px}.finding h3{margin:0;text-transform:none;letter-spacing:-.01em;font-size:20px}.meta{color:var(--muted);font:12px/1.5 ui-monospace,monospace}.evidence{background:#191b19;color:#f1f1ec;padding:18px;overflow-wrap:anywhere;white-space:pre-wrap;font:12px/1.55 ui-monospace,monospace;border-radius:4px}.evidence-meta{color:#aeb4ac;margin-bottom:10px}.split{display:grid;grid-template-columns:1fr 1fr;gap:24px}a{color:#285f76}.footer{padding:26px 64px;color:var(--muted);font-size:12px}@media(max-width:760px){.cover,.section{padding:36px 24px}.cover-grid,.metrics,.facts,.split{grid-template-columns:1fr}.finding-head{display:block}.report{width:100%;margin:0}}@media print{body{background:#fff}.report{border:0;width:100%;margin:0}.section,.finding{break-inside:avoid}.cover{min-height:90vh}.no-print{display:none}}
`;

function documentShell(title: string, body: string, pdfReady: boolean): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'"><title>${escapeHtml(title)}</title><style>${styles}${pdfReady ? "@page{size:A4;margin:14mm}.report{max-width:none}" : ""}</style></head><body><main class="report">${body}</main></body></html>`;
}

function evidenceHtml(evidence: readonly ReportEvidence[]): string {
  if (evidence.length === 0)
    return `<p class="note">No evidence object was linked. This finding must not be treated as confirmed.</p>`;
  return evidence
    .map(
      (item) =>
        `<div class="evidence"><div class="evidence-meta">${escapeHtml(item.id)} · ${escapeHtml(item.source)} · ${escapeHtml(formatDate(item.timestamp))}<br>${escapeHtml(item.asset)} · SHA-256 ${escapeHtml(item.hash)}</div>${escapeHtml(item.redactedExcerpt || "No response excerpt retained.")}</div>`,
    )
    .join("<br>");
}

function findingDetails(finding: ReportFinding): string {
  const affectedUrl = `${finding.asset}${finding.endpoint ?? ""}`;
  return `<article class="finding"><div class="finding-head"><div><span class="meta">${escapeHtml(finding.id)}</span><h3>${escapeHtml(finding.title)}</h3></div><span class="severity ${finding.severity}">${finding.severity}</span></div><div class="facts"><div class="fact"><span class="label">Confidence</span>${escapeHtml(percent(finding.confidence))}</div><div class="fact"><span class="label">Status</span>${escapeHtml(finding.status)}</div><div class="fact"><span class="label">Affected URL</span>${escapeHtml(affectedUrl)}</div><div class="fact"><span class="label">Method / Parameter</span>${escapeHtml(finding.method ?? "Not method-specific")} / ${escapeHtml(finding.parameter ?? "Not parameter-specific")}</div></div><h3>Detailed description</h3><p>${escapeHtml(finding.description)}</p><div class="split"><div><h3>Technical impact</h3><p>${escapeHtml(finding.technicalImpact)}</p></div><div><h3>Business impact</h3><p>${escapeHtml(finding.businessImpact)}</p></div></div><h3>Evidence</h3>${evidenceHtml(finding.evidence)}<h3>Remediation</h3><p>${escapeHtml(finding.remediation)}</p></article>`;
}

export function generateCompleteScanReport(
  input: ScanReportInput,
): GeneratedReport<
  ScanReportInput & { posture: string; severityCounts: Record<ReportSeverity, number> }
> {
  const counts = severityCounts(input.findings);
  const posture = overallPosture(counts);
  const document = { ...input, posture, severityCounts: counts };
  const priorities = input.findings
    .filter((finding) => finding.severity !== "INFO")
    .slice(0, 10)
    .map(
      (finding) =>
        `<li><strong>${escapeHtml(finding.id)} — ${escapeHtml(finding.title)}</strong>: ${escapeHtml(finding.remediation)}</li>`,
    )
    .join("");
  const body = `<section class="cover"><div><div class="mark">Authorized security assessment · Complete scan report</div><h1>${escapeHtml(input.scan.name)}</h1><p class="lede">Evidence-backed assessment of ${escapeHtml(input.target.origin)}</p></div><div class="cover-grid"><div><span class="label">Scan ID</span>${escapeHtml(input.scan.id)}</div><div><span class="label">Workspace</span>${escapeHtml(input.workspace.name)}</div><div><span class="label">Assessment date</span>${escapeHtml(formatDate(input.generatedAt))}</div><div><span class="label">Target status</span>${escapeHtml(input.target.status)}</div></div></section>
  <section class="section"><span class="label">1. Executive summary</span><h2>${escapeHtml(posture)}</h2><p class="lede">The assessment identified ${input.findings.length} evidence-backed finding${input.findings.length === 1 ? "" : "s"} across ${input.urls.length} discovered URL${input.urls.length === 1 ? "" : "s"}. Risk estimates reflect only observed behavior and the configured non-destructive coverage.</p><div class="metrics">${severityOrder.map((severity) => `<div class="metric"><span class="label">${severity}</span><strong>${counts[severity]}</strong></div>`).join("")}</div></section>
  <section class="section"><span class="label">2. Engagement authorization &amp; scope</span><h2>Configured assessment boundary</h2><p>Authorization was established through the organization's engagement process before target entry. This platform records and enforces the configured technical scope; it does not independently prove domain ownership.</p><div class="facts"><div class="fact"><span class="label">Configured origin</span>${escapeHtml(input.target.origin)}</div><div class="fact"><span class="label">Target status</span>${escapeHtml(input.target.status)}</div><div class="fact"><span class="label">Scope saved</span>${escapeHtml(formatDate(input.target.scopeConfiguredAt))}</div></div><h3>Scope rules</h3><table><thead><tr><th>Type</th><th>Value</th><th>Enabled</th></tr></thead><tbody>${input.scopeRules.map((rule) => `<tr><td>${escapeHtml(rule.type)}</td><td>${escapeHtml(rule.value)}</td><td>${rule.enabled ? "Yes" : "No"}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">3. Assessment methodology</span><h2>Controlled, non-destructive analysis</h2><p>Scope validation preceded every target request. The platform performed bounded discovery, crawling, API and technology discovery, deterministic HTTP/TLS/header/cookie/authentication and misconfiguration checks, controlled CORS validation, evidence normalization, correlation, and structured reasoning where available. No destructive exploitation, password attack, persistence, denial-of-service, or data modification was performed.</p></section>
  <section class="section"><span class="label">4. Scan coverage</span><h2>Measured coverage</h2><div class="metrics"><div class="metric"><span class="label">URLs discovered</span><strong>${input.urls.length}</strong></div><div class="metric"><span class="label">Endpoints</span><strong>${input.endpoints.length}</strong></div><div class="metric"><span class="label">Technologies</span><strong>${input.technologies.length}</strong></div><div class="metric"><span class="label">Requests recorded</span><strong>${input.requestsPerformed}</strong></div></div><p class="meta">Scanner sources: ${escapeHtml(input.scannerSources.join(", ") || "No scanner observations")}</p></section>
  <section class="section"><span class="label">5. Scan timeline</span><h2>Persisted stage history</h2><table><thead><tr><th>Stage</th><th>Status</th><th>Started</th><th>Completed</th><th>Duration</th><th>Units</th></tr></thead><tbody>${input.stages.map((stage) => `<tr><td>${escapeHtml(stage.name)}</td><td>${escapeHtml(stage.status)}</td><td>${escapeHtml(formatDate(stage.startedAt))}</td><td>${escapeHtml(formatDate(stage.completedAt))}</td><td>${escapeHtml(duration(stage.startedAt, stage.completedAt))}</td><td>${escapeHtml(stage.completedUnits ?? "—")} / ${escapeHtml(stage.totalUnits ?? "—")}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">6. Asset inventory</span><h2>Observed assets</h2><table><thead><tr><th>Type</th><th>Asset</th><th>First observed</th><th>Last observed</th></tr></thead><tbody>${input.assets.map((asset) => `<tr><td>${escapeHtml(asset.assetType)}</td><td>${escapeHtml(asset.value)}</td><td>${escapeHtml(formatDate(asset.firstSeenAt))}</td><td>${escapeHtml(formatDate(asset.lastSeenAt))}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">7. Technology inventory</span><h2>Evidence-backed fingerprints</h2><table><thead><tr><th>Technology</th><th>Version</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>${input.technologies.map((technology) => `<tr><td>${escapeHtml(technology.technology)}</td><td>${escapeHtml(technology.possibleVersion ?? "Not asserted")}</td><td>${escapeHtml(percent(technology.confidence))}</td><td>${technology.evidenceIds.length}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">8–9. Security posture &amp; findings summary</span><h2>Finding register</h2><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Asset</th><th>Status</th></tr></thead><tbody>${input.findings.map((finding) => `<tr><td>${escapeHtml(finding.id)}</td><td>${escapeHtml(finding.title)}</td><td><span class="severity ${finding.severity}">${finding.severity}</span></td><td>${escapeHtml(percent(finding.confidence))}</td><td>${escapeHtml(finding.asset)}</td><td>${escapeHtml(finding.status)}</td></tr>`).join("")}</tbody></table></section>
  <section class="section"><span class="label">10. Detailed findings</span><h2>Evidence and remediation</h2>${input.findings.map(findingDetails).join("") || '<p class="note">No evidence-backed findings were created.</p>'}</section>
  <section class="section"><span class="label">11. Coverage limitations</span><h2>What this assessment does not claim</h2><ul><li>Testing was limited to observable behavior within the configured URL, request, depth, rate, timeout, and concurrency budgets.</li><li>No credentials were supplied unless explicitly configured outside this report; authenticated role coverage may therefore be incomplete.</li><li>Potential weaknesses requiring risky or destructive confirmation remain marked for authorized manual verification.</li><li>Absence of a finding does not prove absence of a vulnerability outside assessed coverage.</li></ul></section>
  <section class="section"><span class="label">12. Failed or degraded scanners</span><h2>Execution quality</h2>${input.failedOrDegradedStages.length ? `<table><thead><tr><th>Stage</th><th>Status</th><th>Detail</th></tr></thead><tbody>${input.failedOrDegradedStages.map((stage) => `<tr><td>${escapeHtml(stage.name)}</td><td>${escapeHtml(stage.status)}</td><td>${escapeHtml(stage.errorMessage ?? "No error detail retained")}</td></tr>`).join("")}</tbody></table>` : '<p class="note">No failed or degraded stage was recorded in the supplied scan data.</p>'}</section>
  <section class="section"><span class="label">13. Recommended remediation priority</span><h2>Risk-led action plan</h2>${priorities ? `<ol>${priorities}</ol>` : "<p>No material remediation priority was generated from the available evidence.</p>"}</section>
  <section class="section"><span class="label">14. Appendix</span><h2>Assessment metadata</h2><pre class="evidence">${escapeHtml(JSON.stringify({ scanConfig: input.config, scannerSources: input.scannerSources, warningCount: input.scan.warningCount }, null, 2))}</pre></section><footer class="footer">Generated ${escapeHtml(formatDate(input.generatedAt))} · Authorized assessment · Evidence excerpts are redacted</footer>`;
  const html = documentShell(`${input.scan.name} — Complete scan report`, body, false);
  const pdfReadyHtml = documentShell(`${input.scan.name} — Print report`, body, true);
  return {
    document,
    html,
    pdfReadyHtml,
    sha256: createHash("sha256").update(html).digest("hex"),
    pdfReadySha256: createHash("sha256").update(pdfReadyHtml).digest("hex"),
  };
}

export function generateVulnerabilityReport(
  input: Pick<ScanReportInput, "scan" | "workspace" | "target" | "generatedAt"> & {
    finding: ReportFinding;
  },
): GeneratedReport<typeof input> {
  const { finding } = input;
  if (finding.evidence.length === 0)
    throw new Error("A vulnerability report requires linked evidence.");
  const affectedUrl = `${finding.asset}${finding.endpoint ?? ""}`;
  const body = `<section class="cover"><div><div class="mark">Authorized security assessment · Detailed vulnerability report</div><h1>${escapeHtml(finding.title)}</h1><p><span class="severity ${finding.severity}">${finding.severity}</span></p></div><div class="cover-grid"><div><span class="label">Vulnerability ID</span>${escapeHtml(finding.id)}</div><div><span class="label">Confidence</span>${escapeHtml(percent(finding.confidence))}</div><div><span class="label">Status</span>${escapeHtml(finding.status)}</div><div><span class="label">Scan ID</span>${escapeHtml(input.scan.id)}</div></div></section>
  <section class="section"><span class="label">Affected surface</span><h2>Location and classification</h2><div class="facts"><div class="fact"><span class="label">Affected host</span>${escapeHtml(finding.asset)}</div><div class="fact"><span class="label">Affected URL</span>${escapeHtml(affectedUrl)}</div><div class="fact"><span class="label">Endpoint</span>${escapeHtml(finding.endpoint ?? "Not endpoint-specific")}</div><div class="fact"><span class="label">Method</span>${escapeHtml(finding.method ?? "Not method-specific")}</div><div class="fact"><span class="label">Parameter</span>${escapeHtml(finding.parameter ?? "Not parameter-specific")}</div><div class="fact"><span class="label">CWE / OWASP</span>${escapeHtml([...finding.cwe, ...finding.owasp].join(" · "))}</div><div class="fact"><span class="label">Discovery source</span>${escapeHtml([...new Set(finding.evidence.map(({ source }) => source))].join(", "))}</div><div class="fact"><span class="label">Scanner sources</span>${escapeHtml(finding.scannerSources.join(", "))}</div></div></section>
  <section class="section"><span class="label">Detailed description</span><h2>Observed security condition</h2><p class="lede">${escapeHtml(finding.description)}</p><h3>Why this matters</h3><p>${escapeHtml(finding.businessImpact)}</p><div class="split"><div><h3>Technical impact</h3><p>${escapeHtml(finding.technicalImpact)}</p></div><div><h3>Business impact</h3><p>${escapeHtml(finding.businessImpact)}</p></div></div></section>
  <section class="section"><span class="label">Evidence</span><h2>Redacted reproducible observations</h2>${evidenceHtml(finding.evidence)}<h3>Observed behavior</h3><p>${escapeHtml(
    finding.evidence
      .map(({ redactedExcerpt }) => redactedExcerpt)
      .filter(Boolean)
      .join(" | ")
      .slice(0, 4_000),
  )}</p><h3>Expected secure behavior</h3><p>${escapeHtml(finding.remediation)}</p></section>
  <section class="section"><span class="label">Confidence and false-positive analysis</span><h2>Classification basis</h2><p>${escapeHtml(confidenceLanguage(finding))}</p><p>${escapeHtml(falsePositiveLanguage(finding))}</p>${finding.reasoningSummary ? `<p class="note">${escapeHtml(finding.reasoningSummary)}</p>` : ""}</section>
  <section class="section"><span class="label">Remediation</span><h2>Recommended corrective action</h2><p class="lede">${escapeHtml(finding.remediation)}</p><h3>Implementation guidance</h3><p>Apply the recommended control at the application or edge layer responsible for the affected response. Test in a non-production environment, review compatibility, and deploy through the normal change-control process.</p><h3>Validation / retest guidance</h3><p>Repeat the original non-destructive request and confirm the expected secure behavior is present. Verify related endpoints and preserve the new response as retest evidence.</p></section>
  <section class="section"><span class="label">References</span><h2>Standards mapping</h2>${referenceLinks(finding)}</section>
  <section class="section"><span class="label">Observation record</span><div class="facts"><div class="fact"><span class="label">Discovery timestamp</span>${escapeHtml(formatDate(finding.firstSeen))}</div><div class="fact"><span class="label">Last observed</span>${escapeHtml(formatDate(finding.lastSeen))}</div><div class="fact"><span class="label">Manual verification required</span>${finding.manualVerificationRequired ? "Yes" : "No"}</div><div class="fact"><span class="label">Authorization boundary</span>${escapeHtml(input.target.origin)}</div></div></section><footer class="footer">Workspace ${escapeHtml(input.workspace.name)} · Generated ${escapeHtml(formatDate(input.generatedAt))} · Evidence excerpts are redacted</footer>`;
  const html = documentShell(`${finding.id} — ${finding.title}`, body, false);
  const pdfReadyHtml = documentShell(`${finding.id} — ${finding.title}`, body, true);
  return {
    document: input,
    html,
    pdfReadyHtml,
    sha256: createHash("sha256").update(html).digest("hex"),
    pdfReadySha256: createHash("sha256").update(pdfReadyHtml).digest("hex"),
  };
}
