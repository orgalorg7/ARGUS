#!/usr/bin/env bash
set -euo pipefail

api_url="${AASP_API_URL:-http://127.0.0.1:3001/api}"
acceptance_artifact="${DAY6_ACCEPTANCE_ARTIFACT:-artifacts/day6-runtime-acceptance.json}"
recovery_artifact="${DAY6_RECOVERY_ARTIFACT:-artifacts/day6-worker-recovery.json}"
admin_email="${ADMIN_EMAIL:-admin@local.test}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
: "${JWT_SECRET:?JWT_SECRET is required by Docker Compose}"
: "${MODEL_PROVIDER_ENCRYPTION_KEY:?MODEL_PROVIDER_ENCRYPTION_KEY is required by Docker Compose}"

workspace_id=$(jq -er '.workspaceId' "$acceptance_artifact")
target_id=$(jq -er '.targetId' "$acceptance_artifact")
login_payload=$(jq -n --arg email "$admin_email" --arg password "$ADMIN_PASSWORD" '{email:$email,password:$password}')
token=$(curl --fail --silent --show-error -X POST "$api_url/auth/login" -H 'content-type: application/json' --data "$login_payload" | jq -er '.accessToken')
authorization="authorization: Bearer $token"

ensure_worker_started() {
  docker compose start worker >/dev/null 2>&1 || true
}
trap ensure_worker_started EXIT

docker compose stop worker >/dev/null
scan=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans" -H "$authorization" -H 'content-type: application/json' --data "{\"targetId\":\"$target_id\",\"name\":\"Day 6 worker recovery $(date -u +%Y%m%d%H%M%S)\",\"profile\":\"LIGHT\"}")
scan_id=$(jq -er '.id' <<<"$scan")
curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans/$scan_id/start" -H "$authorization" -H 'content-type: application/json' --data '{}' >/dev/null

queued_scan=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id" -H "$authorization")
queued_state=$(jq -r '.state' <<<"$queued_scan")
test "$queued_state" = "QUEUED"

docker compose start worker >/dev/null
state="$queued_state"
for _ in $(seq 1 90); do
  scan=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id" -H "$authorization")
  state=$(jq -r '.state' <<<"$scan")
  case "$state" in
    COMPLETED|COMPLETED_WITH_WARNINGS|FAILED|CANCELLED) break ;;
  esac
  sleep 2
done
test "$state" = "COMPLETED_WITH_WARNINGS"

findings=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/findings" -H "$authorization")
reports=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports" -H "$authorization")
finding_count=$(jq 'length' <<<"$findings")
report_count=$(jq 'length' <<<"$reports")
test "$finding_count" -gt 0
test "$(jq 'all(.[]; (.evidenceLinks | length) > 0)' <<<"$findings")" = "true"
test "$report_count" -eq $((finding_count + 2))

mkdir -p "$(dirname "$recovery_artifact")"
jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg workspaceId "$workspace_id" \
  --arg scanId "$scan_id" \
  --arg queuedState "$queued_state" \
  --arg finalState "$state" \
  --argjson findings "$finding_count" \
  --argjson reports "$report_count" \
  '{generatedAt:$generatedAt,workspaceId:$workspaceId,scanId:$scanId,workerStoppedBeforeQueueing:true,queuedState:$queuedState,workerRestarted:true,finalState:$finalState,findings:$findings,reports:$reports,everyFindingHasEvidence:true}' >"$recovery_artifact"
cat "$recovery_artifact"
