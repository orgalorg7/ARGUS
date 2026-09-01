import { AppShell } from "../../../../components/app-shell";
import { platformGet } from "../../../../lib/platform";
interface Asset {
  id: string;
  assetType: string;
  value: string;
  firstSeenAt: string;
  lastSeenAt: string;
}
export default async function Assets({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId!;
  const items = await platformGet<Asset[]>(`workspaces/${workspaceId}/scans/${id}/assets`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Observed inventory</p>
          <h1>Assets</h1>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>First observed</th>
            <th>Last observed</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>{item.assetType}</td>
              <td className="mono">{item.value}</td>
              <td>{new Date(item.firstSeenAt).toLocaleString()}</td>
              <td>{new Date(item.lastSeenAt).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </AppShell>
  );
}
