import Link from "next/link";
import { AppShell } from "../../../components/app-shell";
import { LiveScan } from "../../../components/live-scan";
import { platformGet } from "../../../lib/platform";
interface Scan {
  id: string;
  name: string;
  state: string;
  warningCount: number;
  target: { origin: string };
  stages: Array<{
    name: string;
    status: string;
    completedUnits: number | null;
    totalUnits: number | null;
    errorMessage: string | null;
  }>;
}
export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return null;
  const scan = await platformGet<Scan>(`workspaces/${workspaceId}/scans/${id}`);
  const tabs = [
    ["Assets", "assets"],
    ["Endpoints", "endpoints"],
    ["Findings", "findings"],
    ["Report", "report"],
  ];
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Live assessment</p>
          <h1>{scan.name}</h1>
          <p className="mono">
            {scan.target.origin} · {scan.id}
          </p>
        </div>
      </div>
      <nav className="tabs">
        {tabs.map(([label, path]) => (
          <Link key={path} href={`/scans/${id}/${path}?workspaceId=${workspaceId}`}>
            {label}
          </Link>
        ))}
      </nav>
      <LiveScan initial={scan} workspaceId={workspaceId} scanId={id} />
    </AppShell>
  );
}
