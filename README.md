# Authorized AI Security Assessment Platform

Production-oriented MVP implementation for controlled, evidence-backed assessment of explicitly authorized web targets. The governing contract is `CODEX_MISSION_AUTHORIZED_AI_SECURITY_PLATFORM.md`.

## Current delivery state

Days 1 through 7 are implemented: monorepo tooling, Prisma data model and migration, authentication/RBAC, three target authorization methods, target-specific scope policy, SSRF/DNS-rebinding/redirect defenses, persisted BullMQ orchestration, scope-guarded discovery, evidence persistence, deterministic scanners, finding correlation, evidence-gated Qwen integration, professional reports, the complete dashboard, cancellation, owned fixtures, hardened containers, clean-install acceptance, tenant-isolation acceptance, and notebooks 00-11.

The deterministic authorized pipeline and report path run end to end. With no Qwen provider configured, AI analysis is explicitly degraded and reports use preserved deterministic findings. A configured but temporarily unreachable provider pauses at `AI_ANALYSIS_WAITING_FOR_PROVIDER`. A validated Qwen-backed run remains outstanding until Colab/GPU is connected; no model output is synthesized.

## Repository map

```text
apps/api                 NestJS API
apps/web                 Next.js web application
apps/worker              BullMQ orchestration worker
packages/database        Prisma schema, migration, and seed
packages/schemas         Validated cross-service contracts
packages/security-core   Authorization, state, redaction, integrity primitives
packages/logger          Structured JSON logging
services/scope-engine    Scope validation and pinned outbound HTTP client
services/crawler         Asynchronous discovery and crawl-trap controls
services/api-discovery   OpenAPI, form, route, and GraphQL-surface extraction
services/evidence-engine Redaction, integrity hashing, and observation persistence
services/finding-engine Deterministic observation normalization and scoring
services/correlation-engine Evidence-preserving finding deduplication
services/ai-engine       Private Qwen client, prompt boundaries, schema/grounding validation
services/report-engine   Complete and per-finding evidence-backed report rendering
services/technology-fingerprinter Evidence-backed public technology signatures
services/scanner-*       Canonical deterministic passive and safe-active scanners
fixtures/vulnerable-web  Owned deliberately misconfigured local fixture
notebooks                Colab-compatible environment and dataset workflows
tests                    Unit and security tests
docker                   Platform container build
```

## Local start

Prerequisites: Docker Engine with Compose, Git, and a browser. Generate secrets locally; never commit the resulting `.env`.

```bash
cp .env.example .env
openssl rand -base64 48
```

Put the generated value in `JWT_SECRET`, set an `ADMIN_PASSWORD` of at least 16 characters, then run:

```bash
docker compose up --build
```

Open `http://localhost:3000` and sign in with `ADMIN_EMAIL` and `ADMIN_PASSWORD`. The API health endpoint is `http://localhost:3001/api/health`.

To run JavaScript tooling outside containers:

```bash
pnpm install
DATABASE_URL='postgresql://aasp:aasp_dev_only@localhost:5432/aasp?schema=public' pnpm prisma:generate
pnpm test
pnpm typecheck
pnpm lint
pnpm build
```

## Authorized fixture flow

1. Sign in and create a workspace.
2. Use `POST /api/workspaces/:workspaceId/targets` with `MANUAL_ADMIN` for an owned local/internal fixture, or use DNS TXT/well-known proof for a public authorized hostname.
3. Complete `POST /api/workspaces/:workspaceId/targets/:targetId/verify`.
4. Create a scan with `POST /api/workspaces/:workspaceId/scans`.
5. Start it with `POST /api/workspaces/:workspaceId/scans/:scanId/start`.
6. Observe persisted discovery, crawling, analysis, normalization, correlation, Qwen, and report stages.
7. Retrieve correlated findings and open the complete and per-finding reports. Without a provider, reports explicitly record degraded AI coverage.

The standalone Day 2 crawler demonstration can be run without PostgreSQL/Redis:

```bash
pnpm --filter @aasp/fixture-web build
pnpm --filter @aasp/fixture-web start
# In a second terminal:
FIXTURE_URL='http://127.0.0.1:4010' pnpm --filter @aasp/worker demo:day2
```

It writes the measured result to `artifacts/day2-crawl-result.json`.

The Day 3 scanner demonstration uses the same owned fixture and real scope-checked requests:

```bash
pnpm --filter @aasp/fixture-web build
pnpm --filter @aasp/fixture-web start
# In a second terminal:
DAY3_DEMO_TARGET='http://127.0.0.1:4010' pnpm --filter @aasp/worker demo:day3
```

It writes redacted canonical observations to `artifacts/day3-scanner-observations.json`. These are scanner observations, not correlated findings.

Normalize and correlate that real observation artifact without a database or model runtime:

```bash
pnpm --filter @aasp/worker demo:day4
```

It writes `artifacts/day4-correlated-findings.json`. The artifact explicitly records `aiAnalysisPerformed: false`; it contains deterministic evidence-backed findings and never substitutes canned model output.

With the Docker stack healthy, the Day 6 deterministic runtime and recovery checks are reproducible with:

```bash
ADMIN_PASSWORD="$ADMIN_PASSWORD" bash scripts/day6-runtime-acceptance.sh
JWT_SECRET="$JWT_SECRET" \
ADMIN_PASSWORD="$ADMIN_PASSWORD" \
MODEL_PROVIDER_ENCRYPTION_KEY="$MODEL_PROVIDER_ENCRYPTION_KEY" \
bash scripts/day6-worker-recovery-test.sh
```

The scripts create only privileged-approved owned fixture targets. They fail on missing evidence, missing report layers, incorrect AI-degraded state, failed authenticated delivery, cancellation failure, or lost queued work.

Day 7 clean-install, tenant-boundary, and report-integrity checks are available as:

```bash
JWT_SECRET="$JWT_SECRET" \
ADMIN_PASSWORD="$ADMIN_PASSWORD" \
MODEL_PROVIDER_ENCRYPTION_KEY="$MODEL_PROVIDER_ENCRYPTION_KEY" \
bash scripts/day7-fresh-install-acceptance.sh

ADMIN_PASSWORD="$ADMIN_PASSWORD" \
DAY7_SOURCE_ACCEPTANCE_ARTIFACT=artifacts/day7-report-runtime-acceptance.json \
bash scripts/day7-report-integrity-test.sh
```

The clean-install script preserves the original Compose volumes, uses separate fresh data volumes, restores the original stack, and leaves the fresh volumes available for audit. The Qwen-backed branch still requires the real Colab/GPU endpoint and is not represented as complete.

All workspace API routes require `Authorization: Bearer <token>`. Only OWNER, ADMIN, and ANALYST roles can create targets or start scans; VIEWER is read-only.

## GPU service

The Qwen service definition intentionally publishes no host port. On a GPU host attached to the private platform network:

```bash
docker network create aasp-private
export QWEN_API_KEY="$(openssl rand -base64 48)"
export QWEN_MODEL='Qwen/Qwen3.8-27B'
docker compose -f docker-compose.gpu.yml up -d
```

Model loading was not executed on this developer host because notebook 00 detected no CUDA GPU. See `docs/COLAB.md` and `docs/QWEN27B.md`.

## Verified quality gates

GitHub Actions runs locked dependency installation, formatting, linting, typechecking, tests, builds, dependency audit, Compose validation, CodeQL, and container publication. Production deployment is gated by environment secrets and an explicit repository variable. See [`docs/CI_CD.md`](docs/CI_CD.md).

The CPU stack completed a fresh image build and authenticated containerized assessment. Current results and remaining Qwen/GPU limitations are recorded in `docs/IMPLEMENTATION_AUDIT.md`.
