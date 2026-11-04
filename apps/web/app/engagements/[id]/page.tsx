import Link from "next/link";
import { AppShell } from "../../../components/app-shell";
import {
  AuthorizationForms,
  ConfigureEngagementPolicy,
  EngagementActions,
} from "../../../components/engagement-forms";
import { platformGet, workspaceHref } from "../../../lib/platform";
import type { EngagementDetail } from "../../../lib/engagements";

export default async function EngagementPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { workspaceId } = await searchParams;
  if (!workspaceId)
    return (
      <main className="auth-shell">
        <Link href="/workspaces">Select a workspace</Link>
      </main>
    );
  const { id } = await params;
  const [engagement, targets] = await Promise.all([
    platformGet<EngagementDetail>(`workspaces/${workspaceId}/engagements/${id}`),
    platformGet<Array<{ id: string; name: string; origin: string; status: string }>>(
      `workspaces/${workspaceId}/targets`,
    ),
  ]);
  const policy = engagement.policies[0];
  const grant = engagement.grants.find(
    (item) => !item.revocation && item.policyRevision === engagement.policyRevision,
  );
  const stale = policy?.targets.some((item) => item.scopeRevision !== item.target.scopeRevision);
  const permissionLabel = stale
    ? "Scope changed · revise authorization"
    : !grant
      ? "Authorization required"
      : new Date(grant.validUntil) <= new Date()
        ? "Authorization expired"
        : new Date(grant.validFrom) > new Date()
          ? "Authorization starts later"
          : "Authorization on file";
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head engagement-head">
        <div>
          <Link className="eyebrow" href={workspaceHref("/engagements", workspaceId)}>
            {engagement.client.name} / Engagements
          </Link>
          <h1>{engagement.name}</h1>
          <p className="muted">{engagement.objective}</p>
        </div>
        <span className="badge">{engagement.state.replaceAll("_", " ")}</span>
      </div>
      <div className="engagement-status">
        <span>{permissionLabel}</span>
        <span>{engagement.environment}</span>
        <span>
          {engagement.requestsMade.toLocaleString()} / {policy?.maxRequests.toLocaleString() ?? "—"}{" "}
          requests
        </span>
        <span>Revision {engagement.policyRevision}</span>
      </div>
      <div className="engagement-columns">
        <section>
          <section className="engagement-panel">
            <div className="status-line">
              <h2>Scope & rules of engagement</h2>
              <Link href={workspaceHref("/targets", workspaceId)}>Target registry</Link>
            </div>
            {policy ? (
              <>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Target</th>
                        <th>Scope revision</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.targets.map((item) => (
                        <tr key={item.target.id}>
                          <td>
                            {item.target.name}
                            <small className="mono">{item.target.origin}</small>
                          </td>
                          <td>
                            {item.scopeRevision}
                            {item.target.scopeRevision !== item.scopeRevision ? " · changed" : ""}
                          </td>
                          <td>{item.target.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <dl className="engagement-facts">
                  <div>
                    <dt>Testing window</dt>
                    <dd>
                      {new Date(policy.windowStartsAt).toLocaleString()} →{" "}
                      {new Date(policy.windowEndsAt).toLocaleString()}
                    </dd>
                  </div>
                  <div>
                    <dt>Network limits</dt>
                    <dd>
                      {policy.requestsPerSecond} requests/s · {policy.maxConcurrency} concurrent per
                      execution
                    </dd>
                  </div>
                  <div>
                    <dt>Permitted tests</dt>
                    <dd>{policy.allowedCategories.join(" · ")}</dd>
                  </div>
                  <div>
                    <dt>Maximum impact</dt>
                    <dd>{policy.maxRisk}</dd>
                  </div>
                  <div>
                    <dt>Tester restrictions</dt>
                    <dd>{policy.restrictions}</dd>
                  </div>
                </dl>
              </>
            ) : (
              <p className="muted">
                Select authorized targets and define the testing window before requesting
                authorization.
              </p>
            )}
            {engagement.canManage && ["DRAFT", "SCOPING"].includes(engagement.state) && (
              <details>
                <summary>{policy ? "Revise scope and rules" : "Configure scope and rules"}</summary>
                <ConfigureEngagementPolicy
                  workspaceId={workspaceId}
                  engagement={engagement}
                  targets={targets.filter(
                    (target) => !["DRAFT", "DISABLED", "SCANNING"].includes(target.status),
                  )}
                />
              </details>
            )}
          </section>
          <section className="engagement-panel">
            <div className="status-line">
              <h2>Testing activity</h2>
              {engagement.canExecute && ["TESTING", "RETEST"].includes(engagement.state) && (
                <Link
                  className="button"
                  href={`${workspaceHref("/scans/new", workspaceId)}&engagementId=${id}`}
                >
                  Configure allowed test
                </Link>
              )}
            </div>
            {engagement.scans.length ? (
              <div className="data-list">
                {engagement.scans.map((scan) => (
                  <Link
                    className="data-row"
                    key={scan.id}
                    href={workspaceHref(`/scans/${scan.id}`, workspaceId)}
                  >
                    <span>{scan.name}</span>
                    <span className="badge">{scan.state.replaceAll("_", " ")}</span>
                  </Link>
                ))}
              </div>
            ) : (
              <p className="muted">
                Testing becomes available after authorization, scheduling and activation.
              </p>
            )}
          </section>
          <section className="engagement-panel">
            <h2>Lifecycle history</h2>
            {engagement.transitions.length ? (
              <ol className="engagement-timeline">
                {engagement.transitions.map((transition) => (
                  <li key={transition.id}>
                    <strong>{transition.toState.replaceAll("_", " ")}</strong>
                    <small>
                      {new Date(transition.createdAt).toLocaleString()} ·{" "}
                      {transition.authorizationBasis}
                    </small>
                    <p>{transition.reason}</p>
                  </li>
                ))}
              </ol>
            ) : (
              <p className="muted">
                This engagement is in draft. Each transition records its actor, reason and
                authorization.
              </p>
            )}
          </section>
        </section>
        <aside>
          <section className="engagement-panel">
            <h2>Move engagement forward</h2>
            <EngagementActions workspaceId={workspaceId} engagement={engagement} />
            {!engagement.allowedTransitions.length && (
              <p className="muted">
                No lifecycle actions are available for your role and the current state.
              </p>
            )}
          </section>
          <section className="engagement-panel">
            <h2>Authorization & custody</h2>
            {engagement.documents.map((doc) => (
              <div key={doc.id} className="document-row">
                {engagement.canReadDocuments ? (
                  <a
                    href={`/api/platform/workspaces/${workspaceId}/engagements/${id}/documents/${doc.id}/content`}
                  >
                    {doc.filename}
                  </a>
                ) : (
                  <span>{doc.filename}</span>
                )}
                <small className="mono" title={doc.sha256}>
                  SHA-256 {doc.sha256}
                </small>
              </div>
            ))}
            {engagement.grants.map((item) => (
              <p key={item.id} className="muted">
                {item.revocation ? "Revoked" : "Recorded"} · {item.authorizedBy}
                <small>
                  Policy {item.policyRevision} · expires{" "}
                  {new Date(item.validUntil).toLocaleString()}
                </small>
              </p>
            ))}
            {engagement.canAuthorize && (
              <AuthorizationForms workspaceId={workspaceId} engagement={engagement} />
            )}
          </section>
        </aside>
      </div>
    </AppShell>
  );
}
