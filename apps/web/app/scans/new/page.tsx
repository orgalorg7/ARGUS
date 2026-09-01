import { AppShell } from "../../../components/app-shell";
import { ScanForm } from "../../../components/scan-form";
import { platformGet } from "../../../lib/platform";
interface Target {
  id: string;
  name: string;
  origin: string;
  status: string;
}
export default async function NewScan({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return null;
  const all = await platformGet<Target[]>(`workspaces/${workspaceId}/targets`);
  const targets = all.filter(({ status }) =>
    ["READY", "COMPLETED", "FAILED", "CANCELLED"].includes(status),
  );
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Controlled assessment</p>
          <h1>Configure scan</h1>
          <p className="lede">
            All profiles are bounded and non-destructive. Every request remains subject to scope
            enforcement.
          </p>
        </div>
      </div>
      {targets.length ? (
        <ScanForm workspaceId={workspaceId} targets={targets} />
      ) : (
        <p className="empty">No enabled target with a valid saved scope is available.</p>
      )}
    </AppShell>
  );
}
