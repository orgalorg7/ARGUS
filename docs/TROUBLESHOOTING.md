# Troubleshooting

## AI analysis is degraded

No provider was configured. Deterministic findings and reports remain available, but no model review occurred. Configure Qwen and start a new scan for a model-backed report.

## Scan waits for Qwen

`AI_ANALYSIS_WAITING_FOR_PROVIDER` means a configured provider was unavailable. Check its private route, bearer token, model identifier, vLLM readiness, and provider allowlist. Never substitute a mock response.

## `Invalid IP address: undefined`

This came from a Node lookup-all callback mismatch. Day 6 corrected the pinned transport and added a real socket regression test. Rebuild the worker image.

## Report volume is unwritable

Confirm `reports-init` completed before the worker. It changes only the dedicated report volume ownership. Do not run scanner workers as root.

## Container downloads pnpm at startup

Rebuild with the current Dockerfile. pnpm is installed in `COREPACK_HOME` during the image build, so service startup should not depend on package-manager downloads.

## Job survives a restart

This is expected. BullMQ retains queued/stalled jobs in Redis AOF; PostgreSQL records idempotency and stage state; recovery republishes missing `CREATED` jobs and replaces stale completed/failed Bull entries for persisted `QUEUED` work. Inspect `ScanJob`, `ScanStage`, heartbeat, and structured logs before manual intervention.

## Notebook or Qwen failure

Retain the raw error and checkpoint. Notebook 00 reports compatibility and notebook 11 resumes validated findings. Insufficient VRAM, endpoint errors, invalid JSON, or unsupported evidence IDs are failures, not successful inference.
