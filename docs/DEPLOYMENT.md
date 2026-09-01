# Deployment

The GitHub CI/CD pipeline, GHCR image contract, production environment secrets, and gated SSH deployment procedure are documented in [CI_CD.md](CI_CD.md).

## CPU platform

Set `JWT_SECRET`, `ADMIN_PASSWORD`, and a non-default `POSTGRES_PASSWORD` in an uncommitted `.env`, then run `docker compose up --build`. PostgreSQL and Redis are private services. API and web ports bind to loopback by default.

The API container runs the committed Prisma migration and idempotent role/admin seed before starting. The worker uses graceful shutdown, persisted job IDs, PostgreSQL outbox recovery, heartbeat records, and safe cancellation boundaries. A one-shot `reports-init` service grants the non-root application user access to the report volume. pnpm is prepared in the runtime image, so startup does not download a package manager.

## GPU platform

Run `docker-compose.gpu.yml` only on a host with a working NVIDIA container runtime and enough measured VRAM. The GPU service joins the externally created `aasp-private` network and binds its host port to `127.0.0.1` by default. Cross-host deployments must set `QWEN_BIND_ADDRESS` to a private routed/VPN address, restrict ingress to the CPU backend, and add that address to `QWEN_PROVIDER_ALLOWED_HOSTS`. Never bind vLLM to a public interface.

## Validation status

Both Compose files pass configuration rendering. Day 7 created a separate clean Compose project with new PostgreSQL, Redis, and report volumes; migration, seed, service health, authorized scanning, cancellation, worker recovery, tenant isolation, and report delivery all passed. The original stack and data were restored afterward. The GPU configuration renders for loopback and explicit private-interface binding, but the service has not been launched because this host has neither `nvidia-smi` nor an NVIDIA Docker runtime.
