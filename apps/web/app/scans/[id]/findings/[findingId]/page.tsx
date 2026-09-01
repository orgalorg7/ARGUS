import { AppShell } from "../../../../../components/app-shell";
import { platformGet } from "../../../../../lib/platform";
interface Finding {
  publicId: string;
  title: string;
  severity: string;
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
  remediation: string;
  manualVerificationRequired: boolean;
  evidenceLinks: Array<{
    evidence: {
      id: string;
      source: string;
      timestamp: string;
      hash: string;
      redactedExcerpt: string;
    };
  }>;
}
export default async function FindingPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string; findingId: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id, findingId } = await params;
  const workspaceId = (await searchParams).workspaceId!;
  const finding = await platformGet<Finding>(
    `workspaces/${workspaceId}/scans/${id}/findings/${findingId}`,
  );
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">{finding.publicId}</p>
          <h1>{finding.title}</h1>
          <p>
            <span className={`badge severity-${finding.severity}`}>{finding.severity}</span> ·{" "}
            {Math.round(finding.confidence * 100)}% confidence · {finding.status}
          </p>
        </div>
      </div>
      <div className="detail-grid">
        <section>
          <h2>Observed condition</h2>
          <p>{finding.description}</p>
          <h2>Technical impact</h2>
          <p>{finding.technicalImpact}</p>
          <h2>Business impact</h2>
          <p>{finding.businessImpact}</p>
          <h2>Remediation</h2>
          <p>{finding.remediation}</p>
        </section>
        <aside className="fact-panel">
          <span className="label">Affected surface</span>
          <p className="mono">
            {finding.asset}
            {finding.endpoint}
          </p>
          <p>
            {finding.method ?? "Any observed method"} · {finding.parameter ?? "No parameter"}
          </p>
          <p>{[...finding.cwe, ...finding.owasp].join(" · ")}</p>
          <p>
            Manual verification: {finding.manualVerificationRequired ? "Required" : "Not required"}
          </p>
        </aside>
      </div>
      <section>
        <h2>Persisted evidence</h2>
        {finding.evidenceLinks.map(({ evidence }) => (
          <article className="evidence-block" key={evidence.id}>
            <strong>{evidence.id}</strong>
            <br />
            {evidence.source} · {new Date(evidence.timestamp).toLocaleString()}
            <br />
            SHA-256 {evidence.hash}
            <pre>{evidence.redactedExcerpt}</pre>
          </article>
        ))}
      </section>
    </AppShell>
  );
}
