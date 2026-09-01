import Link from "next/link";
import { AppShell } from "../../components/app-shell";
import { platformGet, workspaceHref } from "../../lib/platform";
interface Scan {
  id: string;
  name: string;
  state: string;
  createdAt: string;
  target: { origin: string };
}
export default async function ScansPage({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return null;
  const scans = await platformGet<Scan[]>(`workspaces/${workspaceId}/scans`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Assessment operations</p>
          <h1>Scans</h1>
        </div>
        <Link className="button" href={workspaceHref("/scans/new", workspaceId)}>
          New assessment
        </Link>
      </div>
      <div className="data-list">
        {scans.map((scan) => (
          <Link
            className="data-row linked-row"
            key={scan.id}
            href={`/scans/${scan.id}?workspaceId=${workspaceId}`}
          >
            <div>
              <h2>{scan.name}</h2>
              <p className="mono">{scan.target.origin}</p>
            </div>
            <div>
              <span className={`badge status-${scan.state}`}>
                {scan.state.replaceAll("_", " ")}
              </span>
              <p className="muted">{new Date(scan.createdAt).toLocaleString()}</p>
            </div>
          </Link>
        ))}
      </div>
    </AppShell>
  );
}
