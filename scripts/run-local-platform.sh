#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

environment_file="${AASP_CPU_ENV_FILE:-$repository_root/.env.aasp-cpu}"
action="${1:-start}"
compose=(
  docker compose
  --env-file "$environment_file"
  -f "$repository_root/docker-compose.yml"
  -f "$repository_root/docker-compose.local.yml"
)

info() {
  printf '[ARGUS LOCAL] %s\n' "$*"
}

fail() {
  printf '[ARGUS LOCAL] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"
}

generate_environment_file() {
  [[ ! -e "$environment_file" ]] || return 0
  umask 077
  {
    printf 'NODE_ENV=production\n'
    printf 'API_PORT=3001\n'
    printf 'WEB_PORT=3000\n'
    printf 'FIXTURE_PORT=4010\n'
    printf 'ADMIN_EMAIL=admin@local.test\n'
    printf 'ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 20)"
    printf 'JWT_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'MODEL_PROVIDER_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32 | tr -d '\n')"
    printf 'IDENTITY_SECRET_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32 | tr -d '\n')"
    printf 'EVIDENCE_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32)"
    printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 20)"
    printf 'QWEN_BASE_URL=\n'
    printf 'QWEN_API_KEY=\n'
    printf 'QWEN_MODEL=Qwen/Qwen3.8-27B\n'
    printf 'QWEN_PROVIDER_ALLOWED_HOSTS=qwen,localhost,127.0.0.1\n'
    printf 'APP_BASE_URL=http://localhost:3000\n'
    printf 'API_BASE_URL=http://localhost:3001\n'
  } >"$environment_file"
  chmod 600 "$environment_file"
  info "Created private CPU-only configuration: $environment_file"
}

load_environment() {
  generate_environment_file
  set -a
  # Generated locally by this script and excluded from Git.
  # shellcheck disable=SC1090
  source "$environment_file"
  set +a
  : "${ADMIN_EMAIL:?ADMIN_EMAIL is missing}"
  : "${ADMIN_PASSWORD:?ADMIN_PASSWORD is missing}"
  : "${JWT_SECRET:?JWT_SECRET is missing}"
  : "${MODEL_PROVIDER_ENCRYPTION_KEY:?MODEL_PROVIDER_ENCRYPTION_KEY is missing}"
  : "${IDENTITY_SECRET_ENCRYPTION_KEY:?IDENTITY_SECRET_ENCRYPTION_KEY is missing}"
  : "${EVIDENCE_ENCRYPTION_KEY:?Generate a 32-byte base64 EVIDENCE_ENCRYPTION_KEY in the local environment file}"
  : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is missing}"
  : "${API_PORT:=3001}"
  : "${WEB_PORT:=3000}"
  : "${FIXTURE_PORT:=4010}"
  export ADMIN_EMAIL ADMIN_PASSWORD JWT_SECRET MODEL_PROVIDER_ENCRYPTION_KEY IDENTITY_SECRET_ENCRYPTION_KEY
  export EVIDENCE_ENCRYPTION_KEY POSTGRES_PASSWORD API_PORT WEB_PORT FIXTURE_PORT
}

prepare_persistent_services() {
  local ready=false
  info "Starting PostgreSQL and Redis."
  "${compose[@]}" up -d postgres redis
  for _ in $(seq 1 60); do
    if "${compose[@]}" exec -T postgres pg_isready -U aasp -d aasp >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 2
  done
  [[ "$ready" == true ]] || fail "PostgreSQL did not become healthy within two minutes."

  # A preserved PostgreSQL volume may have been created with another local env
  # file. Reconcile only the dedicated aasp role; no data or volume is deleted.
  [[ "$POSTGRES_PASSWORD" =~ ^[A-Fa-f0-9]{40}$ ]] ||
    fail "POSTGRES_PASSWORD in $environment_file has an unexpected format."
  printf "ALTER ROLE aasp WITH PASSWORD '%s';\n" "$POSTGRES_PASSWORD" |
    "${compose[@]}" exec -T postgres \
      psql -v ON_ERROR_STOP=1 -U aasp -d aasp --quiet >/dev/null
}

ensure_build_capacity() {
  local docker_root available_kib minimum_kib
  [[ "${AASP_SKIP_BUILD:-0}" == 1 ]] && return 0
  docker_root=$(docker info --format '{{.DockerRootDir}}')
  available_kib=$(df -Pk "$docker_root" | awk 'NR == 2 {print $4}')
  minimum_kib=$((2 * 1024 * 1024))
  if [[ ! "$available_kib" =~ ^[0-9]+$ ]] || ((available_kib < minimum_kib)); then
    fail "Docker needs at least 2 GiB free to build reliably. Free unused Docker build cache yourself (for example: docker builder prune), then rerun. No cache was deleted automatically."
  fi
}

wait_for_platform() {
  local ready=false api_url web_url fixture_url
  api_url="http://127.0.0.1:${API_PORT}/api/health"
  web_url="http://127.0.0.1:${WEB_PORT}/login"
  fixture_url="http://127.0.0.1:${FIXTURE_PORT}/health"
  info "Waiting for API, worker dependencies, frontend, and owned fixture."
  for _ in $(seq 1 120); do
    if curl --fail --silent --max-time 3 "$api_url" >/dev/null 2>&1 &&
      curl --fail --silent --max-time 3 "$fixture_url" >/dev/null 2>&1 &&
      [[ $(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 "$web_url") == 200 ]]; then
      ready=true
      break
    fi
    sleep 2
  done
  if [[ "$ready" != true ]]; then
    "${compose[@]}" ps
    "${compose[@]}" logs --tail=150 api worker web fixture
    fail "The platform did not become healthy within four minutes."
  fi
}

start_platform() {
  local up_arguments=(-d)
  ensure_build_capacity
  prepare_persistent_services
  info "Building and starting the complete CPU-only platform."
  "${compose[@]}" config --quiet
  if [[ "${AASP_SKIP_BUILD:-0}" == 1 ]]; then
    docker image inspect argus-local-cpu-platform:latest >/dev/null 2>&1 ||
      fail "AASP_SKIP_BUILD=1 was requested, but argus-local-cpu-platform:latest does not exist."
    info "Using the existing local platform image because AASP_SKIP_BUILD=1."
  else
    up_arguments+=(--build)
  fi
  "${compose[@]}" up "${up_arguments[@]}"
  wait_for_platform
  info "Frontend: http://127.0.0.1:${WEB_PORT}/login"
  info "API health: http://127.0.0.1:${API_PORT}/api/health"
  info "Email: $ADMIN_EMAIL"
  info "Password: $ADMIN_PASSWORD"
  info "Qwen: NOT CONFIGURED. Deterministic evidence and reports remain enabled."
}

run_full_stack_test() {
  local api_url token authorization suffix workspace workspace_id target target_id
  local scan scan_id state previous_state urls endpoints findings reports summary
  local finding_count report_count report_directory artifact_path
  api_url="http://127.0.0.1:${API_PORT}/api"

  info "Testing backend authentication and tenant-scoped APIs."
  token=$(curl --fail --silent --show-error -X POST "$api_url/auth/login" \
    -H 'content-type: application/json' \
    --data "$(jq -n --arg email "$ADMIN_EMAIL" --arg password "$ADMIN_PASSWORD" \
      '{email:$email,password:$password}')" | jq -er '.accessToken')
  authorization="authorization: Bearer $token"
  suffix=$(date -u +%Y%m%d%H%M%S)

  workspace=$(curl --fail --silent --show-error -X POST "$api_url/workspaces" \
    -H "$authorization" -H 'content-type: application/json' \
    --data "$(jq -n --arg name "Local Full Stack $suffix" '{name:$name}')")
  workspace_id=$(jq -er '.id' <<<"$workspace")

  target=$(curl --fail --silent --show-error -X POST \
    "$api_url/workspaces/$workspace_id/targets" \
    -H "$authorization" -H 'content-type: application/json' \
    --data '{"name":"Owned Docker Fixture","url":"http://fixture.internal:4010","scope":{"allowedDomains":["fixture.internal"],"includeSubdomains":false,"allowedPorts":[4010],"excludedPaths":[],"allowPrivateNetwork":true}}')
  target_id=$(jq -er '.id' <<<"$target")
  [[ $(jq -r '.status' <<<"$target") == READY ]] ||
    fail "The owned fixture target did not reach READY."

  info "Starting a real DEEP_SAFE scan against the owned fixture."
  source "$(dirname "${BASH_SOURCE[0]}")/authorize-fixture.sh"
  engagement_id=$(authorize_owned_fixture)
  scan=$(curl --fail --silent --show-error -X POST \
    "$api_url/workspaces/$workspace_id/scans" \
    -H "$authorization" -H 'content-type: application/json' \
    --data "$(jq -n --arg targetId "$target_id" --arg engagementId "$engagement_id" --arg name "Local DEEP_SAFE $suffix" \
      '{targetId:$targetId,engagementId:$engagementId,name:$name,profile:"DEEP_SAFE"}')")
  scan_id=$(jq -er '.id' <<<"$scan")
  curl --fail --silent --show-error -X POST \
    "$api_url/workspaces/$workspace_id/scans/$scan_id/start" \
    -H "$authorization" -H 'content-type: application/json' --data '{}' >/dev/null

  state=QUEUED
  previous_state=
  for _ in $(seq 1 300); do
    scan=$(curl --fail --silent --show-error \
      "$api_url/workspaces/$workspace_id/scans/$scan_id" -H "$authorization")
    state=$(jq -r '.state' <<<"$scan")
    if [[ "$state" != "$previous_state" ]]; then
      info "Scan state: $state"
      previous_state=$state
    fi
    case "$state" in
      COMPLETED|COMPLETED_WITH_WARNINGS|FAILED|CANCELLED) break ;;
    esac
    sleep 2
  done
  case "$state" in
    COMPLETED|COMPLETED_WITH_WARNINGS) ;;
    *)
      "${compose[@]}" logs --tail=200 worker api
      fail "The DEEP_SAFE fixture scan ended or stalled in state: $state"
      ;;
  esac

  urls=$(curl --fail --silent --show-error \
    "$api_url/workspaces/$workspace_id/scans/$scan_id/urls" -H "$authorization")
  endpoints=$(curl --fail --silent --show-error \
    "$api_url/workspaces/$workspace_id/scans/$scan_id/endpoints" -H "$authorization")
  findings=$(curl --fail --silent --show-error \
    "$api_url/workspaces/$workspace_id/scans/$scan_id/findings" -H "$authorization")
  reports=$(curl --fail --silent --show-error \
    "$api_url/workspaces/$workspace_id/scans/$scan_id/reports" -H "$authorization")
  summary=$(curl --fail --silent --show-error \
    "$api_url/workspaces/$workspace_id/scans/$scan_id/assessment-summary" \
    -H "$authorization")
  finding_count=$(jq 'length' <<<"$findings")
  report_count=$(jq 'length' <<<"$reports")

  [[ $(jq 'length' <<<"$urls") -gt 0 ]] || fail "No URLs were persisted."
  [[ $(jq 'length' <<<"$endpoints") -gt 0 ]] || fail "No endpoints were persisted."
  [[ "$finding_count" -gt 0 ]] || fail "No evidence-backed fixture findings were produced."
  [[ $(jq 'all(.[]; (.evidenceLinks | length) > 0)' <<<"$findings") == true ]] ||
    fail "At least one finding is missing evidence."
  [[ "$report_count" -eq $((finding_count + 4)) ]] ||
    fail "Expected four scan-level reports plus one report per finding; observed $report_count."
  for report_type in EXECUTIVE EXECUTIVE_PDF_READY COMPLETE_SCAN COMPLETE_SCAN_PDF_READY; do
    jq -e --arg type "$report_type" 'any(.[]; .type == $type and .status == "GENERATED")' \
      <<<"$reports" >/dev/null || fail "Missing generated report type: $report_type"
  done
  [[ $(jq -r '.qwenAnalysis.status' <<<"$summary") == NOT_CONFIGURED ]] ||
    fail "CPU-only test must explicitly report Qwen as NOT_CONFIGURED."

  report_directory="$repository_root/reports/$scan_id"
  mkdir -p "$report_directory"
  "${compose[@]}" cp "api:/app/reports/$scan_id/." "$report_directory"
  [[ -s "$report_directory/executive-report.html" ]] || fail "Executive report was not copied."
  [[ -s "$report_directory/scan-report.html" ]] || fail "Technical report was not copied."
  [[ -n $(find "$report_directory/findings" -maxdepth 1 -type f -name 'FIND-*.html' -print -quit) ]] ||
    fail "No per-finding HTML report was copied."

  artifact_path="$repository_root/artifacts/local-full-stack-acceptance.json"
  mkdir -p "$(dirname "$artifact_path")"
  jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg workspaceId "$workspace_id" \
    --arg targetId "$target_id" \
    --arg scanId "$scan_id" \
    --arg scanState "$state" \
    --arg reportDirectory "$report_directory" \
    --argjson urls "$(jq 'length' <<<"$urls")" \
    --argjson endpoints "$(jq 'length' <<<"$endpoints")" \
    --argjson findings "$finding_count" \
    --argjson reports "$report_count" \
    --argjson summary "$summary" \
    '{generatedAt:$generatedAt,workspaceId:$workspaceId,targetId:$targetId,scanId:$scanId,scanState:$scanState,profile:"DEEP_SAFE",urls:$urls,endpoints:$endpoints,findings:$findings,reports:$reports,everyFindingHasEvidence:true,qwenAnalysisPerformed:false,qwenStatus:$summary.qwenAnalysis.status,reportDirectory:$reportDirectory}' \
    >"$artifact_path"

  info "FULL LOCAL TEST PASSED"
  info "Frontend: http://127.0.0.1:${WEB_PORT}/scans/$scan_id/findings?workspaceId=$workspace_id"
  info "Technical report: $report_directory/scan-report.html"
  info "Executive report: $report_directory/executive-report.html"
  info "Acceptance artifact: $artifact_path"
}

show_credentials() {
  info "Frontend: http://127.0.0.1:${WEB_PORT}/login"
  info "Email: $ADMIN_EMAIL"
  info "Password: $ADMIN_PASSWORD"
  info "Configuration: $environment_file"
}

require_command docker
require_command curl
require_command jq
require_command openssl
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is unavailable."

case "$action" in
  init)
    load_environment
    show_credentials
    ;;
  start)
    load_environment
    start_platform
    ;;
  test)
    load_environment
    start_platform
    run_full_stack_test
    ;;
  status)
    load_environment
    "${compose[@]}" ps
    show_credentials
    ;;
  logs)
    load_environment
    "${compose[@]}" logs -f --tail=200 api worker web fixture postgres redis
    ;;
  credentials)
    load_environment
    show_credentials
    ;;
  stop)
    load_environment
    "${compose[@]}" down --remove-orphans
    info "Platform stopped. PostgreSQL, Redis, reports, and credentials were preserved."
    ;;
  *)
    fail "Usage: $0 {init|start|test|status|logs|credentials|stop}"
    ;;
esac
