import { AppShell } from "../../../components/app-shell";
import { TargetForm } from "../../../components/target-form";
export default async function NewTarget({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return null;
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Engagement scope</p>
          <h1>Register a target</h1>
          <p className="lede">
            Record the target and its authorized technical boundary. No domain ownership challenge
            is performed.
          </p>
        </div>
      </div>
      <TargetForm workspaceId={workspaceId} />
    </AppShell>
  );
}
