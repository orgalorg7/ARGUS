import { AppShell } from "../../../../components/app-shell";
import { platformGet } from "../../../../lib/platform";
interface Endpoint {
  id: string;
  asset: string;
  path: string;
  method: string;
  source: string;
  parameters: Array<{ name: string; location: string }>;
}
export default async function Endpoints({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId!;
  const items = await platformGet<Endpoint[]>(`workspaces/${workspaceId}/scans/${id}/endpoints`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Discovered surface</p>
          <h1>Endpoints</h1>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Endpoint</th>
            <th>Source</th>
            <th>Parameters</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>{item.method}</td>
              <td className="mono">
                {item.asset}
                {item.path}
              </td>
              <td>{item.source}</td>
              <td>{item.parameters.map((p) => `${p.location}:${p.name}`).join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </AppShell>
  );
}
