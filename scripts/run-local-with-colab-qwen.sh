#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

environment_file="${AASP_LOCAL_ENV_FILE:-$repository_root/.env.aasp-local}"
compose=(docker compose --env-file "$environment_file")
action="${1:-start}"

info() {
  printf '[AASP] %s\n' "$*"
}

fail() {
  printf '[AASP] ERROR: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"
}

generate_environment_file() {
  local qwen_base_url qwen_api_key qwen_host

  printf 'Paste the private QWEN_BASE_URL printed by the Colab notebook\n'
  printf 'Example: http://aasp-colab-qwen-abcdef.example-tailnet.ts.net\n'
  read -r -p 'QWEN_BASE_URL: ' qwen_base_url
  read -r -s -p 'QWEN_API_KEY (the same value stored in Colab Secrets): ' qwen_api_key
  printf '\n'

  [[ -n "$qwen_base_url" ]] || fail "QWEN_BASE_URL cannot be empty."
  [[ ${#qwen_api_key} -ge 32 ]] || fail "QWEN_API_KEY must contain at least 32 characters."
  qwen_host=$(python3 - "$qwen_base_url" <<'PY'
import sys
from urllib.parse import urlsplit
print(urlsplit(sys.argv[1]).hostname or "")
PY
  )
  [[ -n "$qwen_host" ]] || fail "QWEN_BASE_URL does not contain a valid hostname."

  umask 077
  {
    printf 'NODE_ENV=production\n'
    printf 'API_PORT=3001\n'
    printf 'WEB_PORT=3000\n'
    printf 'ADMIN_EMAIL=admin@local.test\n'
    printf 'ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 20)"
    printf 'JWT_SECRET=%s\n' "$(openssl rand -hex 32)"
    printf 'MODEL_PROVIDER_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32 | tr -d '\n')"
    printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 20)"
    printf 'FIXTURE_VERIFICATION_TOKEN=%s\n' "$(openssl rand -hex 24)"
    printf 'QWEN_BASE_URL=%s\n' "$qwen_base_url"
    printf 'QWEN_API_KEY=%s\n' "$qwen_api_key"
    printf 'QWEN_MODEL=Qwen/Qwen3.8-27B\n'
    printf 'QWEN_PROVIDER_ALLOWED_HOSTS=qwen,localhost,127.0.0.1,%s\n' "$qwen_host"
    printf 'APP_BASE_URL=http://localhost:3000\n'
    printf 'API_BASE_URL=http://localhost:3001\n'
  } >"$environment_file"
  chmod 600 "$environment_file"
  info "Created private runtime configuration at $environment_file (mode 600)."
}

load_environment() {
  [[ -f "$environment_file" ]] || generate_environment_file
  # This file is generated locally by this script, is excluded by .gitignore,
  # and is deliberately sourced so Docker Compose and acceptance checks share
  # the same runtime secrets.
  set -a
  # shellcheck disable=SC1090
  source "$environment_file"
  set +a
  : "${ADMIN_PASSWORD:?ADMIN_PASSWORD is missing from $environment_file}"
  : "${JWT_SECRET:?JWT_SECRET is missing from $environment_file}"
  : "${MODEL_PROVIDER_ENCRYPTION_KEY:?MODEL_PROVIDER_ENCRYPTION_KEY is missing from $environment_file}"
  : "${QWEN_BASE_URL:?QWEN_BASE_URL is missing from $environment_file}"
  : "${QWEN_API_KEY:?QWEN_API_KEY is missing from $environment_file}"
  : "${QWEN_MODEL:=Qwen/Qwen3.8-27B}"
  QWEN_BASE_URL=${QWEN_BASE_URL%/}
  export QWEN_BASE_URL QWEN_API_KEY QWEN_MODEL
}

update_qwen_connection() {
  local new_base_url new_api_key new_host existing_api_key
  [[ -f "$environment_file" ]] || fail "Run '$0 init' first."
  existing_api_key=$(sed -n 's/^QWEN_API_KEY=//p' "$environment_file" | head -n 1)
  printf 'Paste the new private QWEN_BASE_URL printed by the current Colab runtime.\n'
  read -r -p 'QWEN_BASE_URL: ' new_base_url
  read -r -s -p 'QWEN_API_KEY (press Enter to keep the saved key): ' new_api_key
  printf '\n'
  [[ -n "$new_base_url" ]] || fail "QWEN_BASE_URL cannot be empty."
  if [[ -z "$new_api_key" ]]; then
    new_api_key=$existing_api_key
  fi
  [[ ${#new_api_key} -ge 32 ]] || fail "QWEN_API_KEY must contain at least 32 characters."

  QWEN_BASE_URL=${new_base_url%/}
  export QWEN_BASE_URL
  new_host=$(validate_private_qwen_url)

  AASP_NEW_QWEN_BASE_URL="$QWEN_BASE_URL" \
    AASP_NEW_QWEN_API_KEY="$new_api_key" \
    AASP_NEW_QWEN_HOST="$new_host" \
    python3 - "$environment_file" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
updates = {
    "QWEN_BASE_URL": os.environ["AASP_NEW_QWEN_BASE_URL"],
    "QWEN_API_KEY": os.environ["AASP_NEW_QWEN_API_KEY"],
    "QWEN_PROVIDER_ALLOWED_HOSTS": (
        "qwen,localhost,127.0.0.1," + os.environ["AASP_NEW_QWEN_HOST"]
    ),
}
seen = set()
output = []
for line in path.read_text(encoding="utf-8").splitlines():
    key = line.split("=", 1)[0]
    if key in updates:
        output.append(f"{key}={updates[key]}")
        seen.add(key)
    else:
        output.append(line)
for key, value in updates.items():
    if key not in seen:
        output.append(f"{key}={value}")
path.write_text("\n".join(output) + "\n", encoding="utf-8")
PY
  chmod 600 "$environment_file"
  QWEN_API_KEY=$new_api_key
  export QWEN_API_KEY
  info "Updated only the ephemeral Qwen connection in $environment_file."
}

validate_private_qwen_url() {
  python3 - "$QWEN_BASE_URL" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit

raw = sys.argv[1]
parsed = urlsplit(raw)
if parsed.scheme not in {"http", "https"}:
    raise SystemExit("QWEN_BASE_URL must use http or https")
if parsed.username or parsed.password or parsed.query or parsed.fragment:
    raise SystemExit("QWEN_BASE_URL must not contain credentials, a query, or a fragment")
if parsed.path not in {"", "/"}:
    raise SystemExit("QWEN_BASE_URL must not include /v1 or another path")
host = parsed.hostname or ""
private_tailnet = False
try:
    private_tailnet = ipaddress.ip_address(host) in ipaddress.ip_network("100.64.0.0/10")
except ValueError:
    private_tailnet = host.lower().endswith(".ts.net")
if not private_tailnet:
    raise SystemExit(
        "QWEN_BASE_URL must use a Tailscale 100.64.0.0/10 address or a .ts.net name; "
        "public tunnels are intentionally rejected"
    )
print(host)
PY
}

verify_local_tailscale() {
  require_command tailscale
  tailscale status --json | jq -e '.BackendState == "Running"' >/dev/null ||
    fail "Tailscale is not connected on this machine. Run: sudo tailscale up"
}

verify_qwen_from_host() {
  local model_inventory
  info "Checking the private Qwen endpoint from the host."
  curl --fail --silent --show-error --max-time 15 "$QWEN_BASE_URL/health" >/dev/null ||
    fail "Qwen health check failed. Keep the Colab server cell running and verify Tailscale."
  model_inventory=$(curl --fail --silent --show-error --max-time 30 \
    -H "Authorization: Bearer $QWEN_API_KEY" \
    "$QWEN_BASE_URL/v1/models") || fail "Authenticated Qwen model check failed."
  jq -e --arg model "$QWEN_MODEL" '.data | any(.id == $model)' <<<"$model_inventory" >/dev/null ||
    fail "The endpoint is online but does not advertise $QWEN_MODEL."
  info "Private Qwen endpoint is authenticated and serves $QWEN_MODEL."
}

prepare_persistent_database() {
  local postgres_ready=false
  info "Starting PostgreSQL and reconciling its persisted development credential."
  "${compose[@]}" up -d postgres redis
  for _ in $(seq 1 60); do
    if "${compose[@]}" exec -T postgres pg_isready -U aasp -d aasp >/dev/null 2>&1; then
      postgres_ready=true
      break
    fi
    sleep 2
  done
  [[ "$postgres_ready" == true ]] || fail "PostgreSQL did not become ready within two minutes."
  [[ "${POSTGRES_PASSWORD:-}" =~ ^[A-Fa-f0-9]{40}$ ]] ||
    fail "POSTGRES_PASSWORD must retain the generated 40-character hexadecimal format."
  printf "ALTER ROLE aasp WITH PASSWORD '%s';\n" "$POSTGRES_PASSWORD" |
    "${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U aasp -d aasp --quiet >/dev/null
}

wait_for_platform() {
  local ready=false
  for _ in $(seq 1 120); do
    if curl --fail --silent --max-time 3 http://127.0.0.1:3001/api/health >/dev/null 2>&1 &&
      curl --fail --silent --max-time 3 http://127.0.0.1:4010/health >/dev/null 2>&1 &&
      [[ $(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 http://127.0.0.1:3000/login) == 200 ]]; then
      ready=true
      break
    fi
    sleep 2
  done
  [[ "$ready" == true ]] || {
    "${compose[@]}" ps
    "${compose[@]}" logs --tail=100 api worker web fixture
    fail "The local platform did not become healthy within four minutes."
  }
}

verify_qwen_from_worker() {
  info "Checking that the Docker worker can reach Qwen through Tailscale."
  "${compose[@]}" exec -T worker node --input-type=module -e '
    const base = process.env.QWEN_BASE_URL?.replace(/\/$/, "");
    const key = process.env.QWEN_API_KEY;
    const model = process.env.QWEN_MODEL;
    if (!base || !key || !model) throw new Error("Worker Qwen environment is incomplete");
    const health = await fetch(`${base}/health`, { signal: AbortSignal.timeout(15000) });
    if (!health.ok) throw new Error(`Qwen health returned HTTP ${health.status}`);
    const response = await fetch(`${base}/v1/models`, {
      headers: { authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error(`Qwen inventory returned HTTP ${response.status}`);
    const inventory = await response.json();
    if (!inventory.data?.some((entry) => entry.id === model)) {
      throw new Error(`Expected model ${model} was not advertised`);
    }
    process.stdout.write(`Docker worker reached ${model} through the private endpoint.\n`);
  ' || fail "The host can reach Qwen, but the Docker worker cannot. Check Docker forwarding/firewall rules for tailscale0."
}

start_platform() {
  verify_local_tailscale
  validate_private_qwen_url >/dev/null
  verify_qwen_from_host
  prepare_persistent_database
  info "Building and starting PostgreSQL, Redis, API, worker, fixture, and web UI."
  "${compose[@]}" up -d --build
  wait_for_platform
  verify_qwen_from_worker
  info "Platform is ready: http://127.0.0.1:3000/login"
  info "Login email: ${ADMIN_EMAIL:-admin@local.test}"
  info "The password is stored only in $environment_file"
}

run_qwen_demo() {
  local api_url="http://127.0.0.1:3001/api"
  local token authorization suffix workspace workspace_id target target_id scan scan_id state previous_state
  local findings reports finding_count report_count ai_counts ai_total ai_valid report_directory artifact_path

  info "Starting one real authorized scan of the owned Docker fixture."
  token=$(curl --fail --silent --show-error -X POST "$api_url/auth/login" \
    -H 'content-type: application/json' \
    --data "$(jq -n --arg email "${ADMIN_EMAIL:-admin@local.test}" --arg password "$ADMIN_PASSWORD" '{email:$email,password:$password}')" |
    jq -er '.accessToken')
  authorization="authorization: Bearer $token"
  suffix=$(date -u +%Y%m%d%H%M%S)

  workspace=$(curl --fail --silent --show-error -X POST "$api_url/workspaces" \
    -H "$authorization" -H 'content-type: application/json' \
    --data "$(jq -n --arg name "Qwen Colab Demo $suffix" '{name:$name}')")
  workspace_id=$(jq -er '.id' <<<"$workspace")
  target=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/targets" \
    -H "$authorization" -H 'content-type: application/json' \
    --data '{"name":"Owned Docker Fixture","url":"http://fixture.internal:4010","method":"MANUAL_ADMIN"}')
  target_id=$(jq -er '.target.id' <<<"$target")
  [[ $(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/targets/$target_id/verify" \
    -H "$authorization" -H 'content-type: application/json' --data '{}' | jq -r '.status') == VERIFIED ]] ||
    fail "Owned fixture authorization did not reach VERIFIED."

  scan=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans" \
    -H "$authorization" -H 'content-type: application/json' \
    --data "$(jq -n --arg targetId "$target_id" --arg name "Qwen evidence pipeline $suffix" '{targetId:$targetId,name:$name,profile:"LIGHT"}')")
  scan_id=$(jq -er '.id' <<<"$scan")
  curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans/$scan_id/start" \
    -H "$authorization" -H 'content-type: application/json' --data '{}' >/dev/null

  state=QUEUED
  previous_state=
  for _ in $(seq 1 600); do
    scan=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id" -H "$authorization")
    state=$(jq -r '.state' <<<"$scan")
    if [[ "$state" != "$previous_state" ]]; then
      info "Scan $scan_id state: $state"
      previous_state=$state
    fi
    case "$state" in
      COMPLETED|COMPLETED_WITH_WARNINGS|FAILED|CANCELLED|AI_ANALYSIS_WAITING_FOR_PROVIDER) break ;;
    esac
    sleep 3
  done
  case "$state" in
    COMPLETED|COMPLETED_WITH_WARNINGS) ;;
    AI_ANALYSIS_WAITING_FOR_PROVIDER)
      "${compose[@]}" logs --tail=150 worker
      fail "The persisted scan is waiting because the Qwen provider became unavailable."
      ;;
    *)
      "${compose[@]}" logs --tail=150 worker
      fail "The scan did not complete successfully; terminal/current state: $state"
      ;;
  esac

  findings=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/findings" -H "$authorization")
  reports=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports" -H "$authorization")
  finding_count=$(jq 'length' <<<"$findings")
  report_count=$(jq 'length' <<<"$reports")
  [[ "$finding_count" -gt 0 ]] || fail "The scan completed without evidence-backed findings."
  [[ $(jq 'all(.[]; (.evidenceLinks | length) > 0)' <<<"$findings") == true ]] ||
    fail "At least one finding has no evidence link."

  [[ "$scan_id" =~ ^[A-Za-z0-9_-]+$ ]] || fail "Unexpected scan identifier format."
  ai_counts=$("${compose[@]}" exec -T postgres psql -U aasp -d aasp -At -F '|' -c \
    "SELECT count(*), count(*) FILTER (WHERE status = 'COMPLETED' AND \"schemaValid\" = true AND \"evidenceValid\" = true) FROM \"AIAnalysis\" WHERE \"scanId\" = '$scan_id';")
  IFS='|' read -r ai_total ai_valid <<<"$ai_counts"
  [[ "$ai_total" -gt 0 ]] || fail "No real Qwen analysis records were persisted."
  [[ "$ai_valid" -eq "$ai_total" ]] || fail "Only $ai_valid of $ai_total Qwen analyses passed schema and evidence validation."

  report_directory="$repository_root/reports/$scan_id"
  mkdir -p "$report_directory"
  "${compose[@]}" cp "api:/app/reports/$scan_id/." "$report_directory"
  [[ -s "$report_directory/scan-report.html" ]] || fail "Complete HTML scan report was not copied."
  [[ -s "$report_directory/scan-report.json" ]] || fail "Complete JSON scan report was not copied."
  [[ -n $(find "$report_directory/findings" -maxdepth 1 -type f -name 'FIND-*.html' -print -quit) ]] ||
    fail "No individual HTML vulnerability report was copied."

  artifact_path="$repository_root/artifacts/qwen-colab-runtime-acceptance.json"
  mkdir -p "$(dirname "$artifact_path")"
  jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg workspaceId "$workspace_id" \
    --arg targetId "$target_id" \
    --arg scanId "$scan_id" \
    --arg scanState "$state" \
    --arg qwenModel "$QWEN_MODEL" \
    --arg reportDirectory "$report_directory" \
    --argjson findings "$finding_count" \
    --argjson reports "$report_count" \
    --argjson aiAnalyses "$ai_total" \
    '{generatedAt:$generatedAt,workspaceId:$workspaceId,targetId:$targetId,scanId:$scanId,scanState:$scanState,qwenModel:$qwenModel,findings:$findings,reports:$reports,validatedAIAnalyses:$aiAnalyses,everyFindingHasEvidence:true,reportDirectory:$reportDirectory}' \
    >"$artifact_path"

  info "AUTHORIZED FIXTURE -> EVIDENCE -> FINDINGS -> QWEN -> REPORTS completed."
  info "Acceptance artifact: $artifact_path"
  info "Complete report: $report_directory/scan-report.html"
  info "Finding reports: $report_directory/findings/"
}

require_command docker
require_command curl
require_command jq
require_command openssl
require_command python3
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is unavailable."

case "$action" in
  init)
    [[ ! -e "$environment_file" ]] || fail "$environment_file already exists. Remove it manually only if you intend to rotate every local secret."
    generate_environment_file
    ;;
  start)
    load_environment
    start_platform
    ;;
  connect)
    update_qwen_connection
    load_environment
    verify_local_tailscale
    verify_qwen_from_host
    info "Connection updated. Restart the worker with: $0 start"
    ;;
  demo)
    load_environment
    start_platform
    run_qwen_demo
    ;;
  scan)
    load_environment
    verify_local_tailscale
    validate_private_qwen_url >/dev/null
    verify_qwen_from_host
    wait_for_platform
    verify_qwen_from_worker
    run_qwen_demo
    ;;
  status)
    load_environment
    "${compose[@]}" ps
    verify_local_tailscale
    validate_private_qwen_url >/dev/null
    verify_qwen_from_host
    ;;
  logs)
    load_environment
    "${compose[@]}" logs -f --tail=200 api worker web fixture postgres redis
    ;;
  stop)
    load_environment
    "${compose[@]}" down --remove-orphans
    info "Platform stopped. PostgreSQL, Redis, and report volumes were preserved."
    ;;
  *)
    fail "Usage: $0 {init|connect|start|demo|scan|status|logs|stop}"
    ;;
esac
