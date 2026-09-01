# Reports

The report worker consumes only persisted, workspace-scoped scan records. It refuses to generate a vulnerability report when a finding has no linked evidence. Target-controlled values and evidence excerpts are HTML-escaped, session material is expected to have been redacted by the evidence engine, and generated HTML carries a restrictive content security policy.

For scan `<scan-id>` the worker atomically writes:

```text
reports/<scan-id>/scan-report.html
reports/<scan-id>/scan-report.json
reports/<scan-id>/scan-report.pdf-ready.html
reports/<scan-id>/findings/FIND-0001.html
reports/<scan-id>/findings/FIND-0001.json
```

The worker records SHA-256 hashes and file metadata in PostgreSQL before completing the scan. Standard and PDF-ready HTML are hashed independently against their actual bytes. Once all report files exist, the worker refreshes their document snapshots with the terminal scan state and completed report-stage units before committing scan completion. API downloads require JWT authentication, workspace RBAC, a matching workspace/scan/report tuple, a `GENERATED` report state, and a path contained by `REPORTS_ROOT`. API and worker containers mount the same private `reports-data` volume; the report directory is not served as a public static directory.

The complete report separates observed coverage, findings, limitations, degraded stages, and remediation priorities. Standalone reports include classification, affected surface, evidence, confidence and false-positive analysis, remediation, retest guidance, timestamps, and the manual-verification flag. Model failures do not erase deterministic evidence and are reported as degraded coverage.

For a CPU-only report demonstration based on the real owned-fixture scanner artifact:

```bash
pnpm --filter @aasp/worker demo:day5
```

This command does not invoke or simulate Qwen. Its output explicitly records `aiAnalysisPerformed: false`.

The Day 7 authenticated integrity check downloads every persisted report and compares its bytes with the database hash. It also requires terminal state in complete and per-finding JSON and linked evidence in every finding:

```bash
ADMIN_PASSWORD="$ADMIN_PASSWORD" \
DAY7_SOURCE_ACCEPTANCE_ARTIFACT=artifacts/day7-report-runtime-acceptance.json \
bash scripts/day7-report-integrity-test.sh
```
