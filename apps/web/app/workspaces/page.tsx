import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { CreateWorkspace } from "./create-workspace";
import Link from "next/link";

interface WorkspaceRecord {
  id: string;
  name: string;
  slug: string;
  members: Array<{ role: { name: string } }>;
}

const apiBaseUrl = process.env["API_BASE_URL"] ?? "http://localhost:3001";

export default async function WorkspacesPage() {
  const token = (await cookies()).get("aasp_access")?.value;
  if (!token) redirect("/login");
  const response = await fetch(`${apiBaseUrl}/api/workspaces`, {
    headers: { authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (response.status === 401) redirect("/login");
  if (!response.ok) throw new Error(`Workspace request failed with status ${response.status}.`);
  const workspaces = (await response.json()) as WorkspaceRecord[];

  return (
    <>
      <header className="topbar">
        <div className="shell">
          <span className="brand">
            AASP<span>.</span>
          </span>
        </div>
      </header>
      <main className="shell">
        <div className="page-head">
          <div>
            <p className="eyebrow">Tenant boundary</p>
            <h1>Workspaces</h1>
          </div>
          <CreateWorkspace />
        </div>
        {workspaces.length === 0 ? (
          <div className="empty">
            Create a workspace to establish an isolated target and assessment boundary.
          </div>
        ) : (
          <section className="workspace-grid" aria-label="Available workspaces">
            {workspaces.map((workspace) => (
              <Link
                className="workspace-row linked-row"
                href={`/scans?workspaceId=${workspace.id}`}
                key={workspace.id}
              >
                <div>
                  <h2>{workspace.name}</h2>
                  <span className="muted">{workspace.slug}</span>
                </div>
                <span className="badge">{workspace.members[0]?.role.name ?? "MEMBER"}</span>
              </Link>
            ))}
          </section>
        )}
      </main>
    </>
  );
}
