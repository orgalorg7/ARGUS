import Link from "next/link";
import { AppShell } from "../../components/app-shell";
import { CreateClient, CreateEngagement } from "../../components/engagement-forms";
import { platformGet, workspaceHref } from "../../lib/platform";
import type { ClientRecord, EngagementRecord, PageResult } from "../../lib/engagements";

export default async function EngagementsPage({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string; after?: string }>;
}) {
  const { workspaceId, after } = await searchParams;
  if (!workspaceId)
    return (
      <main className="auth-shell">
        <Link href="/workspaces">Select a workspace</Link>
      </main>
    );
  const [engagements, clients, workspaces] = await Promise.all([
    platformGet<PageResult<EngagementRecord>>(
      `workspaces/${workspaceId}/engagements${after ? `?after=${encodeURIComponent(after)}` : ""}`,
    ),
    platformGet<PageResult<ClientRecord>>(`workspaces/${workspaceId}/clients`),
    platformGet<Array<{ id: string; members: Array<{ role: { name: string } }> }>>("workspaces"),
  ]);
  const role =
    workspaces.find((workspace) => workspace.id === workspaceId)?.members[0]?.role.name ?? "";
  const canManage = [
    "OWNER",
    "ADMIN",
    "ORG_OWNER",
    "SECURITY_DIRECTOR",
    "PENTEST_MANAGER",
    "LEAD_PENTESTER",
  ].includes(role);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head engagement-head">
        <div>
          <p className="eyebrow">Delivery workspace</p>
          <h1>Engagements</h1>
          <p className="muted">Client context, permission and testing history in one place.</p>
        </div>
        <Link href={workspaceHref("/targets", workspaceId)}>Manage target scope</Link>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Engagement / client</th>
              <th>Environment</th>
              <th>Lifecycle</th>
              <th>Policy</th>
            </tr>
          </thead>
          <tbody>
            {engagements.items.map((item) => (
              <tr key={item.id}>
                <td>
                  <Link href={workspaceHref(`/engagements/${item.id}`, workspaceId)}>
                    {item.name}
                  </Link>
                  <small>{item.client.name}</small>
                </td>
                <td>{item.environment}</td>
                <td>
                  <span className="badge">{item.state.replaceAll("_", " ")}</span>
                </td>
                <td>
                  {item.policyRevision ? `Revision ${item.policyRevision}` : "Scope required"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!engagements.items.length && (
        <p className="empty">
          Create a client and engagement to establish the authorization boundary for testing.
        </p>
      )}
      {engagements.nextCursor && (
        <Link
          href={`${workspaceHref("/engagements", workspaceId)}&after=${engagements.nextCursor}`}
        >
          Next engagements →
        </Link>
      )}
      {canManage && (
        <section className="engagement-grid">
          <details className="engagement-panel">
            <summary>Create a client</summary>
            <CreateClient workspaceId={workspaceId} />
          </details>
          <details className="engagement-panel">
            <summary>Create an engagement</summary>
            {clients.items.length ? (
              <CreateEngagement workspaceId={workspaceId} clients={clients.items} />
            ) : (
              <p className="muted">Create the client first.</p>
            )}
          </details>
        </section>
      )}
    </AppShell>
  );
}
