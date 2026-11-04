import Link from "next/link";
import { AppShell } from "../../components/app-shell";
import { platformGet } from "../../lib/platform";

interface Target {
  id: string;
  name: string;
  origin: string;
  status: string;
}

export default async function AuthorizationTargetsPage({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return <main className="auth-shell">Select a workspace first.</main>;
  const targets = await platformGet<Target[]>(`workspaces/${workspaceId}/targets`);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Identity boundaries</p>
          <h1>Authorization testing</h1>
          <p>
            Configure isolated test identities, approved resources, and explicit policy matrices.
          </p>
        </div>
      </div>
      <div className="data-list">
        {targets.map((target) => (
          <article className="data-row" key={target.id}>
            <div>
              <h2>{target.name}</h2>
              <p className="mono">{target.origin}</p>
              <span className={`badge status-${target.status}`}>{target.status}</span>
            </div>
            <Link
              className="button secondary"
              href={`/authorization/${target.id}?workspaceId=${encodeURIComponent(workspaceId)}`}
            >
              Configure identities
            </Link>
          </article>
        ))}
      </div>
    </AppShell>
  );
}
