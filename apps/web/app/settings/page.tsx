import { AppShell } from "../../components/app-shell";
export default async function Settings({
  searchParams,
}: {
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const workspaceId = (await searchParams).workspaceId!;
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Private inference</p>
          <h1>Settings</h1>
        </div>
      </div>
      <section className="form-panel">
        <h2>Qwen 27B provider</h2>
        <p>
          Core reasoning uses the workspace or internal Qwen-compatible provider configured through
          the authenticated provider API. The model is never granted network or scope control.
        </p>
        <p className="note">
          Provider status and secret management remain backend-enforced. A missing provider leaves
          scans in AI_ANALYSIS_WAITING_FOR_PROVIDER; deterministic evidence is preserved.
        </p>
      </section>
    </AppShell>
  );
}
