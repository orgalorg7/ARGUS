# Architecture

The platform is a pnpm TypeScript monorepo. Next.js provides the browser application, NestJS exposes authenticated workspace-scoped APIs, PostgreSQL stores authoritative state through Prisma, and BullMQ/Redis carries recoverable job notifications. PostgreSQL remains the source of truth for scan/job status; Redis is not treated as durable assessment evidence.

## Security and data flow

```text
Browser -> Next.js session proxy -> NestJS API -> PostgreSQL
                                      |
                                      v
                              persisted ScanJob outbox
                                      |
                                      v
                                BullMQ workers
                                      |
                                      v
                         ScopeEngine + pinned HTTP client
```

The scope engine is a mandatory dependency of network-capable services. A target must have a valid persisted scope before scan creation and queueing; the API atomically reserves it as `SCANNING`, and workers reconstruct the policy from persisted target rules before execution. A DNS pin store prevents a hostname from introducing an address outside its initial approved answer set during a scan worker session. Every redirect is treated as a new outbound destination and checked before transport.

## Persistence model

All assessment entities carry `workspaceId` where they are directly queried. API lookups use both resource ID and workspace ID. The Prisma model includes the complete contract inventory: identity and membership, targets and scope rules, scans/stages/jobs, discovery records, observations/evidence/findings, AI analysis, reports, audit events, workers/heartbeats, and ephemeral model-provider records.

## Queue recovery

Starting a scan commits a `ScanJob` with a unique idempotency key in the same transaction as the `QUEUED` transition. The API attempts immediate BullMQ delivery. If Redis is unavailable, the job remains `CREATED`; workers periodically recover this outbox. BullMQ job IDs reuse persisted job IDs, preventing duplicate dispatch.

## Qwen boundary

The GPU service is on the private `aasp-private` network and has no published Internet port. The AI engine submits only structured policy, target metadata, observations, evidence, and known context. Model output cannot make network calls or alter scope and must pass schema and evidence-ID validation.
