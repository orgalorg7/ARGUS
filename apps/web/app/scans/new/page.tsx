import Link from "next/link";
import { AppShell } from "../../../components/app-shell";
import { ScanForm } from "../../../components/scan-form";
import { platformGet, workspaceHref } from "../../../lib/platform";
import type { EngagementDetail, EngagementRecord, PageResult } from "../../../lib/engagements";

export default async function NewScan({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string; engagementId?: string }>;
}) {
  const { workspaceId, engagementId } = await searchParams;
  if (!workspaceId)
    return (
      <main className="auth-shell">
        <Link href="/workspaces">Select a workspace</Link>
      </main>
    );
  if (!engagementId) {
    const engagements = await platformGet<PageResult<EngagementRecord>>(
      `workspaces/${workspaceId}/engagements`,
    );
    const ready = engagements.items.filter((item) => ["TESTING", "RETEST"].includes(item.state));
    return (
      <AppShell workspaceId={workspaceId}>
        <div className="page-head engagement-head">
          <div>
            <h1>Select an engagement</h1>
            <p className="muted">Every execution belongs to an authorized testing engagement.</p>
          </div>
        </div>
        {ready.map((item) => (
          <Link
            className="data-row"
            key={item.id}
            href={`${workspaceHref("/scans/new", workspaceId)}&engagementId=${item.id}`}
          >
            <span>{item.name}</span>
            <small>{item.client.name}</small>
          </Link>
        ))}
        {!ready.length && (
          <p className="empty">
            No engagements are in testing or retest.{" "}
            <Link href={workspaceHref("/engagements", workspaceId)}>Open engagements</Link> to
            configure scope and authorization.
          </p>
        )}
      </AppShell>
    );
  }
  const engagement = await platformGet<EngagementDetail>(
    `workspaces/${workspaceId}/engagements/${engagementId}`,
  );
  const policy = engagement.policies[0];
  const targets =
    policy?.targets
      .map((item) => item.target)
      .filter((target) => ["READY", "COMPLETED", "FAILED", "CANCELLED"].includes(target.status)) ??
    [];
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head engagement-head">
        <div>
          <p className="eyebrow">{engagement.name}</p>
          <h1>Configure allowed test</h1>
          <p className="muted">
            Scope, current permission and rules are checked when queued and before each request.
          </p>
        </div>
      </div>
      {policy &&
      targets.length &&
      engagement.canExecute &&
      ["TESTING", "RETEST"].includes(engagement.state) ? (
        <ScanForm
          workspaceId={workspaceId}
          engagementId={engagementId}
          targets={targets}
          limits={policy}
        />
      ) : (
        <p className="empty">
          No execution is available in the current engagement state.{" "}
          <Link href={workspaceHref(`/engagements/${engagementId}`, workspaceId)}>
            Review engagement
          </Link>
          .
        </p>
      )}
    </AppShell>
  );
}
