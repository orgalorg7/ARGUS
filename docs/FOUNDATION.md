# Engagement-governed foundation

This increment replaces implicit business authorization with persisted, enforced
engagement governance. It extends the existing NestJS/Next.js/Prisma/BullMQ stack.
It is the first delivery increment of the pentest operating system, not a claim
that the entire commercial platform is complete.

## Implemented workflow

1. Sign in and create a workspace. New workspaces belong to an organization.
   `POST /api/workspaces` also accepts an existing `organizationId` when the actor
   has organization administration membership. Neither system-admin flags nor
   supplied organization IDs grant access to tenant data.
2. Open **Engagements**, create a client, and create its engagement.
3. Register targets with saved scope. Define an engagement policy with selected
   targets, testing window, total request budget, aggregate request rate,
   concurrency per execution, protocol/category allowlists, and maximum impact.
4. Move through SCOPING and AWAITING_AUTHORIZATION. Upload the actual permission
   document and record the client's authorizing signatory and validity interval.
   An authorized operator must review the document; uploading a PDF does not
   authenticate its signature or prove permission by itself.
5. Move through AUTHORIZED, SCHEDULED, ACTIVE and TESTING. Configure an allowed
   scan from the engagement. API requests to create scans now require
   `engagementId`; targets must belong to its current policy revision.
6. Queue admission validates current membership, grant, scope revision, ROE,
   testing window, action classification and configured limits. A denial is
   persisted without creating a job. Grant selection, actor binding, target
   reservation and job outbox creation commit together.
7. Every production worker HTTP transport rechecks the database gate, including
   redirects and identity comparisons. Expiry, revocation, membership removal,
   cancellation, scope change and budget exhaustion block subsequent requests.

The backend provides legal next states to the UI. Transitions require an expected
record version, actor, reason and permission basis. PostgreSQL verifies state
edges and requires a corresponding immutable transition record at commit.

## Security boundaries

- **Tenancy:** organization membership and workspace role are loaded server-side.
  New domain services enforce permission themselves, including non-controller
  callers. Composite foreign keys bind clients, engagements, policies, grants,
  scans, targets, observations, evidence and several lineage records to their
  tenant. Legacy finding/evidence and resource/identity joins have database guards.
  Parent tenant/assessment reassignment is prohibited.
- **Authorization:** grants bind immutable ROE revisions and preserved documents.
  Target assignments bind a scope revision and canonical scope digest. Editing
  target scope retains previous rules and creates an atomic audit event. A stale
  grant cannot widen scope. Returning an engagement to scoping cancels active work.
- **Execution:** risk derives from an internal capability/category mapping and
  actual HTTP method, not a caller's approval or AI risk flag. Current production
  capabilities permit bounded GET/HEAD/OPTIONS only. State-changing methods remain
  denied, even for owners, until a separate sensitive-operation approval and
  sandbox implementation exists. No generic shell endpoint was added.
- **Distributed limits:** workers serialize request admission on the engagement
  row, use PostgreSQL time, and share its request count/rate gate. Rate waits occur
  outside transactions and recheck policy after waiting. Each redirect consumes
  budget. Failed admitted requests consume budget conservatively. A request
  already admitted before revocation may complete under its transport timeout;
  revocation cannot undo an already-sent request.
- **Network:** actual destinations are checked against persisted scope even if a
  worker accidentally supplies a broader transport policy. IPv6 mapped/expanded
  forms and encoded traversal paths cannot bypass the corrected scope checks.
- **Custody:** authorization originals use AES-256-GCM with tenant/engagement/
  document authenticated context, a random nonce and SHA-256 of the original.
  Originals are limited to 1 MiB PDF/text. No ciphertext is returned by read APIs.
  Document downloads are permissioned and audited. Evidence, audit records,
  documents, policies, grants, revocations, transitions and decisions are
  append-only through database triggers. Database owners remain privileged;
  these triggers are not external tamper-proof storage.
- **Epistemic state:** Qwen reviews are stored as suggestions/history; the worker
  no longer overwrites finding prose, severity, confidence or status. Neither a
  confidence threshold nor an AI false-positive suggestion establishes a human
  decision. Generated reports remain internal working artifacts.
- **Report safety:** recognized unredacted credentials/private keys block new
  HTML/JSON report generation. Downloaded bytes must match their recorded digest;
  HTML, print-ready HTML and JSON have integrity metadata. Downloads reject
  symlink escapes, have a 64 MiB bound and carry a sandbox CSP and no-store policy.
  Secret detection is conservative pattern detection, not comprehensive DLP or
  a replacement for reviewer redaction/publication approval.

## Configuration and upgrades

Set `EVIDENCE_ENCRYPTION_KEY` to an independently generated 32-byte base64 key:

```bash
openssl rand -base64 32
```

Store it in deployment secret management, provision it to the API, and retain it
with protected backups. Missing or malformed keys fail document operations closed.
Key rotation/versioned key management is not implemented in this increment; do not
replace this key in an existing installation without a reviewed re-encryption plan.

Run `pnpm prisma:generate`, `pnpm prisma:migrate`, and the existing role seed.
Legacy workspaces are backfilled into separate organizations with their existing
members. Existing scans/evidence are retained; no client, engagement or grant is
invented for them. Historical scans remain readable, but a legacy scan cannot be
started without the new boundary. Create an engagement and a new scan to resume
testing. Seed no longer resets an existing administrator password or reactivates
a disabled administrator on every API restart.

The four new migrations are transactional. Inconsistent legacy tenant links cause
an upgrade failure requiring reviewed repair; they are not silently deleted.
Foreign keys and trigger functions are intentionally part of the migration
contract. [PostgreSQL's constraint guidance](https://www.postgresql.org/docs/current/ddl-constraints.html)
underpins the composite foreign-key approach. Preserve these triggers in backups
and future migrations.

Older JSON report artifacts do not have a recorded digest and must be regenerated
before downloading that format. Existing hashed HTML remains readable. Legacy
fixture acceptance scripts now create explicit, synthetic authorizations only for
loopback or the repository's `fixture.internal:4010` target. This helper refuses
external targets and must not be used as client permission.

## Verification

```bash
pnpm test
pnpm typecheck
pnpm lint
pnpm build

# Supply a dedicated migrated database whose name ends in _test.
DATABASE_URL="$AASP_TEST_DATABASE_URL" pnpm prisma:migrate
pnpm test:database
node scripts/foundation-upgrade-check.mjs

# Supply a dedicated Redis instance in AASP_TEST_REDIS_URL.
node scripts/foundation-acceptance.mjs

# Optional: installed Chrome, or set CHROME_BIN. Uses a disposable browser profile.
node scripts/foundation-acceptance.mjs --browser
```

Database acceptance covers tenant injection, cross-tenant foreign keys, client
privacy, analyst restrictions, missing grants, immutable encrypted originals,
audited lifecycle, concurrent policy updates, revocation, expiry, current scope,
broadened worker transport scope, unsupported mutations and distributed budgets.
Upgrade acceptance creates a temporary schema, runs the original four migrations,
inserts legacy state, applies the full chain and verifies preservation.

API/worker acceptance uses real Nest authentication, PostgreSQL, BullMQ, Redis and
an owned synthetic HTTP server. It creates NORTHSTAR FINANCIAL / API SECURITY
ASSESSMENT and exercises authorization before running the actual scanner/evidence/
report pipeline. Browser acceptance performs login and client creation and checks
the engagement view at 1440 px and 390 px. Artifacts go to the ignored
`artifacts/foundation-acceptance/`; no model result is fabricated. CI runs the
database, upgrade and API/worker checks; the browser check is an explicit local
acceptance command.

Verified locally on 2026-09-08 (Africa/Cairo):

- 139 unit, integration, API and security tests passed; 14 additional PostgreSQL
  governance tests passed.
- Full production build, typecheck, lint, formatting and `git diff --check` passed.
  The production dependency audit reported no known vulnerabilities.
- All migrations applied to an isolated PostgreSQL 18.6 database; Prisma reported
  no schema drift. The legacy-data upgrade acceptance passed. CI is configured to
  repeat database acceptance on PostgreSQL 17; its hosted run was not executed here.
- Ten live API/worker/browser assertions passed, including removed organization
  membership with an existing JWT, client-role isolation and audited integrity
  checks for HTML, JSON and print-ready HTML downloads. The owned fixture produced
  five candidate findings with evidence and nine report artifacts. Its scan ended
  `COMPLETED_WITH_WARNINGS` because no AI provider was configured. These counts are
  acceptance artifacts, not a claim of five human-confirmed vulnerabilities.
- Browser login and client creation persisted through the API; the engagement
  view rendered at desktop and mobile widths without overflow. The local result
  record is `artifacts/foundation-acceptance/result.json`, with screenshots beside it.

## Remaining delivery sequence and release blockers

| Next increment                | Dependency and exact next step                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Identity/session hardening    | Add durable login throttling, revocable sessions/logout audit and MFA/SSO; remove runtime migration/seed authority from production API. The existing short-lived JWT login is not full enterprise identity governance.                                                                                                                                                   |
| Evidence/reviewer/publication | Add encrypted object storage for all raw evidence, immutable metadata revisions, explicit client-safe derivatives, finding validation/reviewer decisions and a publication state machine. Reuse the document custody and tenant patterns, but support streaming large objects and retention/key rotation.                                                                |
| Tenant persistence completion | Replace remaining legacy ID arrays/JSON relationships with junctions, introduce tenant-aware repositories/RLS for legacy query paths, and finish fine-grained permissions on legacy modules. Current tenant-sensitive reads depend on reviewed application guards and constrained relationships, not RLS.                                                                |
| Worker isolation and approval | Replace day-numbered lifecycle duplication with an adapter/job registry, persist per-operation human approvals, enforce per-tool network/filesystem capabilities and credentials using deployment sandboxes. The common worker process/container is not per-tool isolation.                                                                                              |
| Pentest core                  | Introduce engagement-persistent assets/endpoints, identity/resource/action cells, manual observations, test coverage, hypothesis provenance and evidence-backed graph edges. Existing discovery and identities remain target/scan-centric. Import OpenAPI into this persistent registry and test an actual 143-endpoint fixture; no endpoint count is hardcoded into UI. |
| AI intelligence               | Add provider-neutral model/prompt registry, structured hypothesis/QA outputs, tenant-filtered hybrid retrieval, evaluation datasets and model routing. Keep recommendations separate from policy/execution. Benchmark Qwen only on an authenticated, available compute node using locally reproducible modules. No Colab/GPU benchmark ran in this increment.            |
| Commercial delivery           | Build approved client projections, remediation/retest comparisons, real PDF/DOCX rendering, recurring jobs, branding, integration adapters and delivery metrics. Do not provision client users as VIEWER to simulate a portal.                                                                                                                                           |
| Operations                    | Validate backups/restores, tenant export/retention, secret rotation, queue recovery under faults, tracing and scalable pagination/search; replace per-request DB decisions with measured equivalent controls only after preserving revocation and accounting invariants. Load/capacity claims are not established by these acceptance tests.                             |

No placeholder endpoints, fabricated model scores, synthetic production findings,
or inactive feature controls were introduced to stand in for these increments.
