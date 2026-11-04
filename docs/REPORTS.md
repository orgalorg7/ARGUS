# Reports

The report worker consumes only persisted, workspace-scoped scan records. It refuses to generate a vulnerability report when a finding has no linked evidence. Target-controlled values and evidence excerpts are HTML-escaped, session material is expected to have been redacted by the evidence engine, and generated HTML carries a restrictive content security policy.

For scan `<scan-id>` the worker atomically writes:

```text
reports/<scan-id>/scan-report.html
reports/<scan-id>/scan-report.json
reports/<scan-id>/scan-report.pdf-ready.html
reports/<scan-id>/executive-report.html
reports/<scan-id>/executive-report.json
reports/<scan-id>/executive-report.pdf-ready.html
reports/<scan-id>/findings/FIND-0001.html
reports/<scan-id>/findings/FIND-0001.json
```

The worker records SHA-256 hashes and file metadata in PostgreSQL before completing the scan. Standard and PDF-ready HTML are hashed independently against their actual bytes. Once all report files exist, the worker refreshes their document snapshots with the terminal scan state and completed report-stage units before committing scan completion. API downloads require JWT authentication, workspace RBAC, a matching workspace/scan/report tuple, a `GENERATED` report state, and a path contained by `REPORTS_ROOT`. API and worker containers mount the same private `reports-data` volume; the report directory is not served as a public static directory.

The executive report is a management-focused deliverable with overall posture, top five risks, affected weakness areas, monthly movement, remediation priorities, and a 30-day action plan. The complete report separates observed coverage, attack surface, findings, limitations, degraded stages, Qwen status, month-over-month comparison, and remediation priorities. Its JSON and HTML include overall risk, counts by severity, ranked weakness categories, risk scores, affected areas, important evidence IDs, most exposed assets, and highest-priority fixes. When no finding exists, reports state **NO FINDINGS OBSERVED** and explicitly reject any implication that the target was proven secure. Standalone reports include classification, affected surface, evidence, confidence and false-positive analysis, remediation, retest guidance, first/last-seen lineage, recurrence, and the manual-verification flag. Model failures do not erase deterministic evidence and are reported explicitly.

Before reports are generated, the worker compares the scan with the most recent completed scan for the same target. A prior finding is marked `RESOLVED` only when URL, endpoint, request, profile, and module coverage are comparable and the current scan has no failed/degraded module. Otherwise a missing prior finding is `UNVERIFIED`. Current findings are classified as `NEW`, `RECURRING`, `REGRESSED`, or `CHANGED` using stable correlation keys. Prioritization produces `FIX_NOW`, `FIX_NEXT`, `PLANNED`, or `HARDENING` from severity, confidence, breadth, and recurrence without inventing unavailable asset-criticality or remediation-effort data.

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

## Governance increment

Reports remain internal working artifacts until a separate reviewer/publication workflow is implemented. Model confidence never establishes confirmation or a false-positive decision. Recognized raw secrets block generation. Every download is audited, confined to the report store, and checked against the stored HTML/JSON hash. Legacy JSON artifacts must be regenerated to establish their digest. The download limit is 64 MiB. See [FOUNDATION.md](FOUNDATION.md).
