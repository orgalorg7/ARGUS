#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
environment_file=${ARGUS_ENV_FILE:-$repository_root/.env.production}
image=${ARGUS_PLATFORM_IMAGE:-}

fail() {
  printf '[ARGUS deploy] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -n "$image" ]] || fail "ARGUS_PLATFORM_IMAGE is required. Use an immutable sha-* tag."
[[ "$image" == ghcr.io/*:sha-* || "$image" == *@sha256:* ]] ||
  fail "ARGUS_PLATFORM_IMAGE must use an immutable sha-* tag or digest."
[[ -f "$environment_file" ]] || fail "Environment file not found: $environment_file"

environment_permissions=$(stat -c '%a' "$environment_file")
((10#$environment_permissions % 100 == 0)) ||
  fail "$environment_file must not be readable or writable by group/other (recommended mode: 600)."

compose=(
  docker compose
  --env-file "$environment_file"
  -f "$repository_root/docker-compose.yml"
  -f "$repository_root/docker-compose.production.yml"
)

export ARGUS_PLATFORM_IMAGE="$image"

printf '[ARGUS deploy] Validating Compose configuration.\n'
"${compose[@]}" config --quiet

printf '[ARGUS deploy] Pulling immutable application image %s.\n' "$image"
"${compose[@]}" pull api worker reports-init web

printf '[ARGUS deploy] Applying migrations and starting production services.\n'
"${compose[@]}" up \
  --detach \
  --no-build \
  --remove-orphans \
  --wait \
  --wait-timeout 300 \
  postgres redis reports-init api worker web

printf '[ARGUS deploy] Deployment healthy.\n'
"${compose[@]}" ps
