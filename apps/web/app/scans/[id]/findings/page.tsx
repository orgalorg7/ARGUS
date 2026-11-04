import Link from "next/link";
import { AppShell } from "../../../../components/app-shell";
import { platformGet } from "../../../../lib/platform";
interface Finding {
  id: string;
  publicId: string;
  title: string;
  severity: string;
  category: string;
  confidence: number;
  asset: string;
  status: string;
  remediation: string;
  trendStatus: string;
  remediationPriority: string;
  recurrenceCount: number;
  evidenceLinks: unknown[];
}
interface AssessmentSummary {
  trendCounts: Record<string, number>;
  priorityCounts: Record<string, number>;
  comparison: null | {
    coverageSufficient: boolean;
    coverageRatio: number;
    unresolvedPriorFindings: Array<{
      trendStatus: string;
      reason: string;
      finding: null | { publicId: string; title: string; severity: string };
    }>;
  };
  coverage: { urls: number; endpoints: number; evidence: number };
  qwenAnalysis: {
    status: string;
    totalFindings: number;
    validatedAnalyses: number;
    failedOrWaitingAnalyses: number;
  };
}
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const priorityRank: Record<string, number> = {
  FIX_NOW: 3,
  FIX_NEXT: 2,
  PLANNED: 1,
  HARDENING: 0,
};
export default async function Findings({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId!;
  const [items, summary] = await Promise.all([
    platformGet<Finding[]>(`workspaces/${workspaceId}/scans/${id}/findings`),
    platformGet<AssessmentSummary>(`workspaces/${workspaceId}/scans/${id}/assessment-summary`),
  ]);
  const counts = Object.fromEntries(
    severities.map((severity) => [
      severity,
      items.filter((item) => item.severity === severity).length,
    ]),
  ) as Record<(typeof severities)[number], number>;
  const overallRisk = severities.find((severity) => counts[severity] > 0) ?? null;
  const categoryCounts = [...new Set(items.map(({ category }) => category))]
    .map((category) => ({
      category,
      count: items.filter((item) => item.category === category).length,
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 5);
  const exposedAssets = [...new Set(items.map(({ asset }) => asset))]
    .map((asset) => ({ asset, count: items.filter((item) => item.asset === asset).length }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 5);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Correlated observations</p>
          <h1>Findings</h1>
        </div>
      </div>
      <section className="dashboard-summary" aria-label="Assessment finding summary">
        <div className="summary-risk">
          <span className="label">Overall risk</span>
          {overallRisk ? (
            <span className={`badge severity-${overallRisk}`}>{overallRisk}</span>
          ) : (
            <strong>NO FINDINGS OBSERVED</strong>
          )}
          {!overallRisk && <small>This does not prove the assessed application secure.</small>}
        </div>
        <div className="summary-counts">
          {severities.map((severity) => (
            <div key={severity}>
              <span className="label">{severity}</span>
              <strong>{counts[severity]}</strong>
            </div>
          ))}
        </div>
        <div className="summary-counts summary-operational">
          {(["NEW", "RECURRING", "REGRESSED", "RESOLVED", "UNVERIFIED"] as const).map((trend) => (
            <div key={trend}>
              <span className="label">{trend.replaceAll("_", " ")}</span>
              <strong>{summary.trendCounts[trend] ?? 0}</strong>
            </div>
          ))}
        </div>
        <div className="summary-columns assessment-health">
          <div>
            <h2>Remediation queue</h2>
            <p>
              <strong>{summary.priorityCounts["FIX_NOW"] ?? 0}</strong> fix now ·{" "}
              <strong>{summary.priorityCounts["FIX_NEXT"] ?? 0}</strong> fix next
            </p>
          </div>
          <div>
            <h2>Scan coverage</h2>
            <p>
              {summary.coverage.urls} URLs · {summary.coverage.endpoints} endpoints ·{" "}
              {summary.coverage.evidence} evidence objects
            </p>
            {summary.comparison && (
              <small>
                Monthly comparison{" "}
                {summary.comparison.coverageSufficient ? "sufficient" : "insufficient"} ·{" "}
                {Math.round(summary.comparison.coverageRatio * 100)}%
              </small>
            )}
          </div>
          <div>
            <h2>Qwen analysis</h2>
            <p>{summary.qwenAnalysis.status.replaceAll("_", " ")}</p>
            <small>
              {summary.qwenAnalysis.validatedAnalyses}/{summary.qwenAnalysis.totalFindings}{" "}
              validated
            </small>
          </div>
        </div>
        <div className="summary-columns">
          <div>
            <h2>Top weaknesses</h2>
            {categoryCounts.length ? (
              <ol>
                {categoryCounts.map(({ category, count }) => (
                  <li key={category}>
                    {category.replaceAll("_", " ")} <small>{count} finding(s)</small>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted">No evidence-backed weakness category was created.</p>
            )}
          </div>
          <div>
            <h2>Most exposed assets</h2>
            {exposedAssets.length ? (
              <ol>
                {exposedAssets.map(({ asset, count }) => (
                  <li key={asset}>
                    <span className="mono">{asset}</span> <small>{count} finding(s)</small>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted">No affected asset was identified.</p>
            )}
          </div>
          <div>
            <h2>Highest-priority fixes</h2>
            {items.some(({ severity }) => severity !== "INFO") ? (
              <ol>
                {items
                  .filter(({ severity }) => severity !== "INFO")
                  .sort(
                    (left, right) =>
                      (priorityRank[right.remediationPriority] ?? 0) -
                      (priorityRank[left.remediationPriority] ?? 0),
                  )
                  .slice(0, 5)
                  .map((item) => (
                    <li key={item.id}>
                      <strong>{item.remediationPriority.replaceAll("_", " ")}</strong> ·{" "}
                      {item.title}
                      <small>{item.remediation}</small>
                    </li>
                  ))}
              </ol>
            ) : (
              <p className="muted">No material remediation priority was generated.</p>
            )}
          </div>
        </div>
      </section>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Trend</th>
            <th>Priority</th>
            <th>Evidence</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>
                <Link href={`/scans/${id}/findings/${item.publicId}?workspaceId=${workspaceId}`}>
                  {item.publicId}
                </Link>
              </td>
              <td>
                {item.title}
                <small>{item.asset}</small>
              </td>
              <td>
                <span className={`badge severity-${item.severity}`}>{item.severity}</span>
              </td>
              <td>{Math.round(item.confidence * 100)}%</td>
              <td>{item.trendStatus.replaceAll("_", " ")}</td>
              <td>{item.remediationPriority.replaceAll("_", " ")}</td>
              <td>{item.evidenceLinks.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </AppShell>
  );
}
