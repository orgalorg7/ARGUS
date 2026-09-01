# CI/CD

## Pipeline

`.github/workflows/ci-cd.yml` runs for pull requests, pushes to `main`, version tags, and manual dispatches.

The quality job installs the lockfile exactly, generates Prisma, checks formatting and lint, typechecks every workspace package, runs the complete Vitest suite, builds the monorepo, audits production dependencies, and validates both Compose configurations. CodeQL runs independently with no application secrets. Private repositories without GitHub Code Security run the analysis without attempting an unsupported SARIF upload. After code scanning is enabled, set the repository variable `CODEQL_UPLOAD_ENABLED=true` to publish results into GitHub's Security tab.

After quality and CodeQL succeed, Docker Buildx builds `docker/Dockerfile.platform`. Pull requests build without publishing. Pushes to `main` and version tags publish an SBOM- and provenance-bearing image to:

```text
ghcr.io/orgalorg7/argus-platform
```

Every build receives an immutable `sha-<full-commit>` tag. `main` additionally updates `latest`; releases also receive the Git tag.

## Production deployment gate

Automatic SSH deployment is disabled until the repository variable below is explicitly set:

```text
PRODUCTION_DEPLOY_ENABLED=true
```

Configure these encrypted secrets on the GitHub `production` environment:

- `DEPLOY_HOST`: production server hostname or address.
- `DEPLOY_USER`: unprivileged deployment account with Docker access.
- `DEPLOY_PORT`: SSH port; optional, defaults to `22`.
- `DEPLOY_PATH`: dedicated remote directory such as `/opt/argus`.
- `DEPLOY_SSH_KEY`: private key restricted to the deployment account.
- `DEPLOY_KNOWN_HOSTS`: pinned `known_hosts` entry for the server. Do not generate it dynamically in CI.

The server must already contain `$DEPLOY_PATH/.env.production` with mode `600`. It must define at least strong `POSTGRES_PASSWORD`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `MODEL_PROVIDER_ENCRYPTION_KEY` values, plus the private Qwen endpoint configuration required by the worker. Never store this file in GitHub or the repository.

The deploy job transfers only the Compose definitions and deployment script, authenticates Docker to GHCR with the short-lived workflow token, and deploys the exact immutable image created by the preceding job. `scripts/deploy-production.sh` validates configuration and environment-file permissions, pulls the image, runs Prisma migration through API startup, starts services without local builds, and waits for health checks. The intentionally vulnerable fixture is excluded from production unless the `demo` profile is explicitly enabled.

## Manual server deployment

From the prepared server directory:

```bash
chmod 600 .env.production
export ARGUS_PLATFORM_IMAGE=ghcr.io/orgalorg7/argus-platform:sha-<full-commit-sha>
bash scripts/deploy-production.sh
```

Application ports remain bound to loopback. Terminate TLS and apply external access controls in an operator-managed reverse proxy. vLLM remains private and is deployed separately using `docker-compose.gpu.yml`.
