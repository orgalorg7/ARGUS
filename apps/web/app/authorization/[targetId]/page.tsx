import { AppShell } from "../../../components/app-shell";
import { AuthorizationSetup } from "../../../components/authorization-setup";
import { platformGet } from "../../../lib/platform";

interface Identity {
  id: string;
  label: string;
  role: string;
  tenant: string | null;
  authenticationType: string;
  authenticationState: string;
  credentialConfigured: boolean;
  enabled: boolean;
}

interface Resource {
  id: string;
  resourceType: string;
  externalId: string;
  tenant: string | null;
  provenance: string;
  ownerIdentity: { id: string; label: string } | null;
}

interface TestCase {
  id: string;
  name: string;
  endpointTemplate: string;
  method: string;
  identityIds: string[];
  mutationRisk: string;
  enabled: boolean;
}

export default async function AuthorizationSetupPage({
  params,
  searchParams,
}: {
  params: Promise<{ targetId: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { targetId } = await params;
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return null;
  const base = `workspaces/${workspaceId}/targets/${targetId}/authorization`;
  const [identities, resources, testCases] = await Promise.all([
    platformGet<Identity[]>(`${base}/identities`),
    platformGet<Resource[]>(`${base}/resources`),
    platformGet<TestCase[]>(`${base}/test-cases`),
  ]);
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Controlled authorization matrix</p>
          <h1>Identity &amp; resource setup</h1>
          <p className="mono">Target {targetId}</p>
        </div>
      </div>
      <AuthorizationSetup
        workspaceId={workspaceId}
        targetId={targetId}
        identities={identities}
        resources={resources}
        testCases={testCases}
      />
    </AppShell>
  );
}
