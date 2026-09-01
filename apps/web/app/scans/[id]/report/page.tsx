import { AppShell } from "../../../../components/app-shell";
import { platformGet } from "../../../../lib/platform";
interface Report {
  id: string;
  type: string;
  status: string;
  generatedAt: string | null;
  sha256: string | null;
  finding: { publicId: string; title: string } | null;
}
export default async function Reports({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId!;
  const items = await platformGet<Report[]>(`workspaces/${workspaceId}/scans/${id}/reports`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Consulting deliverables</p>
          <h1>Reports</h1>
          <p className="lede">
            Files appear only after the report worker has persisted and hashed them.
          </p>
        </div>
      </div>
      <div className="data-list">
        {items.map((item) => (
          <article className="data-row" key={item.id}>
            <div>
              <h2>
                {item.finding
                  ? `${item.finding.publicId} — ${item.finding.title}`
                  : item.type.replaceAll("_", " ")}
              </h2>
              <p className="mono">SHA-256 {item.sha256 ?? "Pending"}</p>
            </div>
            <div className="actions">
              <a
                className="button secondary"
                target="_blank"
                href={`/api/platform/workspaces/${workspaceId}/scans/${id}/reports/${item.id}/content`}
              >
                Open HTML
              </a>
              {item.type !== "COMPLETE_SCAN_PDF_READY" && (
                <a
                  className="text-button"
                  target="_blank"
                  href={`/api/platform/workspaces/${workspaceId}/scans/${id}/reports/${item.id}/content?format=json`}
                >
                  JSON
                </a>
              )}
            </div>
          </article>
        ))}
      </div>
      {items.length === 0 && (
        <p className="empty">
          No generated report is available. Current scan state is retained by the scan view.
        </p>
      )}
    </AppShell>
  );
}
