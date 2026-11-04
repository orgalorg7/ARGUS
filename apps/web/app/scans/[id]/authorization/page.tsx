import { AppShell } from "../../../../components/app-shell";
import { platformGet } from "../../../../lib/platform";

interface MatrixResult {
  id: string;
  degraded: boolean;
  incompleteIdentityIds: string[];
  testCase: { name: string; method: string; endpointTemplate: string };
  matrix: {
    observations?: Array<{
      identityId: string;
      identityLabel: string;
      expected: string;
      response: { statusCode: number };
    }>;
    differences?: Array<{
      comparisonIdentityId: string;
      classification: string;
      confidence: number;
      severity: string;
    }>;
  };
}

export default async function AuthorizationMatrixPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ workspaceId?: string }>;
}) {
  const { id } = await params;
  const workspaceId = (await searchParams).workspaceId;
  if (!workspaceId) return null;
  const results = await platformGet<MatrixResult[]>(
    `workspaces/${workspaceId}/scans/${id}/authorization-matrix`,
  );
  return (
    <AppShell workspaceId={workspaceId}>
      <div className="page-head">
        <div>
          <p className="eyebrow">Differential authorization</p>
          <h1>Authorization matrix</h1>
          <p>{results.length} configured test cases executed.</p>
        </div>
      </div>
      {results.map((result) => (
        <section className="panel" key={result.id}>
          <h2>{result.testCase.name}</h2>
          <p className="mono">
            {result.testCase.method} {result.testCase.endpointTemplate}
          </p>
          {result.degraded && (
            <p className="error">
              Incomplete identity coverage: {result.incompleteIdentityIds.join(", ")}
            </p>
          )}
          <div className="matrix-table">
            <div className="matrix-head">Identity</div>
            <div className="matrix-head">Expected</div>
            <div className="matrix-head">Observed</div>
            <div className="matrix-head">Analysis</div>
            {(result.matrix.observations ?? []).map((observation) => {
              const difference = (result.matrix.differences ?? []).find(
                ({ comparisonIdentityId }) => comparisonIdentityId === observation.identityId,
              );
              return (
                <div className="matrix-row" key={observation.identityId}>
                  <span>{observation.identityLabel}</span>
                  <span>{observation.expected}</span>
                  <span>HTTP {observation.response.statusCode}</span>
                  <span
                    className={difference?.classification.startsWith("POTENTIAL_") ? "error" : ""}
                  >
                    {difference
                      ? `${difference.classification} · ${Math.round(difference.confidence * 100)}%`
                      : "BASELINE"}
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      ))}
      {results.length === 0 && <p>No authorization test cases were configured for this scan.</p>}
    </AppShell>
  );
}
