#!/usr/bin/env bash
set -euo pipefail

original_project="${DAY7_ORIGINAL_COMPOSE_PROJECT:-aasp}"
test_project="${DAY7_FRESH_COMPOSE_PROJECT:-aasp-day7}"
fresh_artifact="${DAY7_FRESH_ARTIFACT:-artifacts/day7-fresh-install.json}"
runtime_artifact="${DAY7_RUNTIME_ARTIFACT:-artifacts/day7-fresh-runtime-acceptance.json}"
recovery_artifact="${DAY7_RECOVERY_ARTIFACT:-artifacts/day7-fresh-worker-recovery.json}"
tenant_artifact="${DAY7_TENANT_ARTIFACT:-artifacts/day7-fresh-tenant-isolation.json}"
: "${JWT_SECRET:?JWT_SECRET is required}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
: "${MODEL_PROVIDER_ENCRYPTION_KEY:?MODEL_PROVIDER_ENCRYPTION_KEY is required}"

compose_original() {
  docker compose -p "$original_project" "$@"
}

compose_test() {
  docker compose -p "$test_project" "$@"
}

test_stack_started=false
original_stopped=false
cleanup() {
  local exit_code=$?
  trap - EXIT
  set +e
  if [[ "$test_stack_started" = true ]]; then
    compose_test down --remove-orphans >/dev/null
  fi
  if [[ "$original_stopped" = true ]]; then
    compose_original up -d >/dev/null
  fi
  exit "$exit_code"
}
trap cleanup EXIT

# Preserve the original named volumes while freeing the fixed local ports and
# private network. The fresh project receives a distinct set of data volumes.
compose_original down
original_stopped=true
test_stack_started=true
compose_test up -d --build

healthy=false
for _ in $(seq 1 120); do
  if curl --fail --silent http://127.0.0.1:3001/api/health >/dev/null &&
    curl --fail --silent http://127.0.0.1:4010/health >/dev/null &&
    [[ "$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:3000/login)" = "200" ]]; then
    healthy=true
    break
  fi
  sleep 2
done
test "$healthy" = true

ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  DAY6_ACCEPTANCE_ARTIFACT="$runtime_artifact" \
  bash scripts/day6-runtime-acceptance.sh >/dev/null

ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  DAY7_SOURCE_ACCEPTANCE_ARTIFACT="$runtime_artifact" \
  DAY7_TENANT_ARTIFACT="$tenant_artifact" \
  bash scripts/day7-tenant-isolation-test.sh >/dev/null

COMPOSE_PROJECT_NAME="$test_project" \
  JWT_SECRET="$JWT_SECRET" \
  ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  MODEL_PROVIDER_ENCRYPTION_KEY="$MODEL_PROVIDER_ENCRYPTION_KEY" \
  DAY6_ACCEPTANCE_ARTIFACT="$runtime_artifact" \
  DAY6_RECOVERY_ARTIFACT="$recovery_artifact" \
  bash scripts/day6-worker-recovery-test.sh >/dev/null

container_state=$(compose_test ps --format json | jq -s '.')
migration_count=$(compose_test exec -T postgres psql -U aasp -d aasp -Atc 'SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL;')
test "$migration_count" -gt 0

mkdir -p "$(dirname "$fresh_artifact")"
jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg composeProject "$test_project" \
  --argjson migrationCount "$migration_count" \
  --slurpfile runtime "$runtime_artifact" \
  --slurpfile recovery "$recovery_artifact" \
  --slurpfile tenant "$tenant_artifact" \
  --argjson containers "$container_state" \
  '{generatedAt:$generatedAt,composeProject:$composeProject,freshDataVolumes:true,migrationCount:$migrationCount,services:$containers,runtimeAcceptance:$runtime[0],workerRecovery:$recovery[0],tenantIsolation:$tenant[0],qwenInferencePerformed:false}' >"$fresh_artifact"
cat "$fresh_artifact"

# The trap stops the temporary containers without deleting their fresh volumes,
# then restores the original development stack and its pre-existing data.
