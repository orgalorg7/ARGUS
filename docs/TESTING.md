# Testing

Run the complete local quality gate:

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

The suite covers URL canonicalization, crawl traps, budgets, cancellation, scope blocking, DNS-pinned Node 24 transport, API discovery, technology fingerprinting, evidence redaction, authorization, scan transitions, RBAC, report evidence requirements, HTML escaping, and report-store path containment.

Day 4 tests additionally cover evidence-required normalization, inventory-observation exclusion, contextual CWE/OWASP mapping, site-wide and endpoint-specific deduplication, evidence preservation, prompt-policy separation, invented evidence-ID rejection and correction retry, provider outage signaling, provider-secret authenticated encryption, provider host allowlisting, system-admin provider configuration, and finding tenant boundaries.

Docker-backed PostgreSQL/Redis integration has been exercised against the owned fixture and persisted discovery, crawling, endpoints, observations, findings, and report stages. The Qwen-backed branch remains mandatory before final acceptance and requires Colab or a GPU server.

Run the reproducible Day 6 container acceptance after the stack is healthy:

```bash
ADMIN_PASSWORD="$ADMIN_PASSWORD" bash scripts/day6-runtime-acceptance.sh
JWT_SECRET="$JWT_SECRET" \
ADMIN_PASSWORD="$ADMIN_PASSWORD" \
MODEL_PROVIDER_ENCRYPTION_KEY="$MODEL_PROVIDER_ENCRYPTION_KEY" \
bash scripts/day6-worker-recovery-test.sh
```

The executed acceptance artifacts record 16 URLs, 19 endpoints, 9 evidence-backed findings, 11 reports, authenticated report HTTP 200, cancellation, and queue recovery after a worker stop/restart. They are `artifacts/day6-runtime-acceptance.json` and `artifacts/day6-worker-recovery.json`. These counts are observations from the owned fixture run, not hardcoded product output.

Day 7 adds a clean-volume installation test, black-box cross-workspace resource checks, and authenticated file/hash validation:

```bash
JWT_SECRET="$JWT_SECRET" \
ADMIN_PASSWORD="$ADMIN_PASSWORD" \
MODEL_PROVIDER_ENCRYPTION_KEY="$MODEL_PROVIDER_ENCRYPTION_KEY" \
bash scripts/day7-fresh-install-acceptance.sh

ADMIN_PASSWORD="$ADMIN_PASSWORD" \
DAY7_SOURCE_ACCEPTANCE_ARTIFACT=artifacts/day7-report-runtime-acceptance.json \
bash scripts/day7-report-integrity-test.sh
```

The executed clean installation applied the committed migration to new PostgreSQL/Redis/report volumes and repeated the scan, cancellation, worker-restart, and tenant-isolation acceptance paths. The integrity run verified all 11 served report hashes against actual bytes and required terminal scan/report-stage state in JSON. Results are retained under `artifacts/day7-*.json`; the corrected sample is `reports/day7-final-acceptance/`.

Notebook 02 executed locally. Notebook 03 validated its fail-loud guard; no baseline was generated because Qwen was unavailable. Notebooks 06-11 passed JSON/Python syntax validation but were not executed because this host lacks a suitable CUDA runtime and model weights.
