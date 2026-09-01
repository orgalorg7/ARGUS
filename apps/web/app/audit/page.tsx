import { AppShell } from "../../components/app-shell";
import { platformGet } from "../../lib/platform";
interface Event {
  id: string;
  action: string;
  resourceType: string;
  resourceId: string | null;
  createdAt: string;
  actor: { email: string } | null;
}
export default async function Audit({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const workspaceId = (await searchParams).workspaceId!;
  const items = await platformGet<Event[]>(`workspaces/${workspaceId}/audit`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Immutable activity trail</p>
          <h1>Audit events</h1>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Actor</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id}>
              <td>{new Date(item.createdAt).toLocaleString()}</td>
              <td>{item.action}</td>
              <td className="mono">
                {item.resourceType} / {item.resourceId ?? "—"}
              </td>
              <td>{item.actor?.email ?? "System worker"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </AppShell>
  );
}
