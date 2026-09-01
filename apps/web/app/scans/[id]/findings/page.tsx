import Link from "next/link";
import { AppShell } from "../../../../components/app-shell";
import { platformGet } from "../../../../lib/platform";
interface Finding {
  id: string;
  publicId: string;
  title: string;
  severity: string;
  confidence: number;
  asset: string;
  status: string;
  evidenceLinks: unknown[];
}
export default async function Findings({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId!;
  const items = await platformGet<Finding[]>(`workspaces/${workspaceId}/scans/${id}/findings`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Correlated observations</p>
          <h1>Findings</h1>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Finding</th>
            <th>Severity</th>
            <th>Confidence</th>
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
              <td>{item.evidenceLinks.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </AppShell>
  );
}
