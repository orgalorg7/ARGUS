import Link from "next/link";
import { AppShell } from "../../components/app-shell";
import { ConfigureScope } from "../../components/configure-scope";
import { platformGet, workspaceHref } from "../../lib/platform";

interface Target {
  id: string;
  name: string;
  origin: string;
  status: string;
  includeSubdomains: boolean;
  scopeRules: Array<{ type: string; value: string }>;
}
export default async function TargetsPage({
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
          <p className="eyebrow">Authorization boundary</p>
          <h1>Targets</h1>
        </div>
        <Link className="button" href={workspaceHref("/targets/new", workspaceId)}>
          Register target
        </Link>
      </div>
      <div className="data-list">
        {targets.map((target) => (
          <article className="data-row" key={target.id}>
            <div>
              <h2>{target.name}</h2>
              <p className="mono">{target.origin}</p>
              <span className={`badge status-${target.status}`}>
                {target.status.replaceAll("_", " ")}
              </span>
              {target.scopeRules.length > 0 && (
                <p className="mono">
                  {target.scopeRules.map(({ type, value }) => `${type}:${value}`).join(" · ")}
                  {target.includeSubdomains ? " · SUBDOMAINS:INCLUDED" : ""}
                </p>
              )}
            </div>
            {target.status === "DRAFT" && (
              <ConfigureScope
                workspaceId={workspaceId}
                targetId={target.id}
                origin={target.origin}
              />
            )}
          </article>
        ))}
      </div>
    </AppShell>
  );
}
