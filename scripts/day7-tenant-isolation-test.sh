#!/usr/bin/env bash
set -euo pipefail

api_url="${AASP_API_URL:-http://127.0.0.1:3001/api}"
acceptance_artifact="${DAY7_SOURCE_ACCEPTANCE_ARTIFACT:-artifacts/day6-runtime-acceptance.json}"
tenant_artifact="${DAY7_TENANT_ARTIFACT:-artifacts/day7-tenant-isolation.json}"
admin_email="${ADMIN_EMAIL:-admin@local.test}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"

workspace_a=$(jq -er '.workspaceId' "$acceptance_artifact")
target_a=$(jq -er '.targetId' "$acceptance_artifact")
scan_a=$(jq -er '.scanId' "$acceptance_artifact")
login_payload=$(jq -n --arg email "$admin_email" --arg password "$ADMIN_PASSWORD" '{email:$email,password:$password}')
token=$(curl --fail --silent --show-error -X POST "$api_url/auth/login" -H 'content-type: application/json' --data "$login_payload" | jq -er '.accessToken')
authorization="authorization: Bearer $token"

workspace_b_response=$(curl --fail --silent --show-error -X POST "$api_url/workspaces" -H "$authorization" -H 'content-type: application/json' --data "{\"name\":\"Day 7 Isolation Boundary $(date -u +%Y%m%d%H%M%S)\"}")
workspace_b=$(jq -er '.id' <<<"$workspace_b_response")
findings_a=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_a/scans/$scan_a/findings" -H "$authorization")
reports_a=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_a/scans/$scan_a/reports" -H "$authorization")
finding_a=$(jq -er '.[0].id' <<<"$findings_a")
report_a=$(jq -er '.[0].id' <<<"$reports_a")

assert_status() {
  local expected="$1"
  local method="$2"
  local url="$3"
  local body="${4:-}"
  local status
  if [[ -n "$body" ]]; then
    status=$(curl --silent --show-error --output /tmp/aasp-day7-isolation-response.json --write-out '%{http_code}' -X "$method" "$url" -H "$authorization" -H 'content-type: application/json' --data "$body")
  else
    status=$(curl --silent --show-error --output /tmp/aasp-day7-isolation-response.json --write-out '%{http_code}' -X "$method" "$url" -H "$authorization")
  fi
  if [[ "$status" != "$expected" ]]; then
    printf 'Expected HTTP %s but received %s for %s %s\n' "$expected" "$status" "$method" "$url" >&2
    sed -n '1,20p' /tmp/aasp-day7-isolation-response.json >&2
    return 1
  fi
}

# The same authenticated owner belongs to both workspaces, so these checks
# exercise resource scoping rather than merely failing the workspace guard.
assert_status 404 PUT "$api_url/workspaces/$workspace_b/targets/$target_a/scope" '{"allowedDomains":["fixture.internal"],"includeSubdomains":false,"allowedPorts":[4010],"excludedPaths":[],"allowPrivateNetwork":true}'
assert_status 404 POST "$api_url/workspaces/$workspace_b/scans" "{\"targetId\":\"$target_a\",\"name\":\"Cross-tenant target rejection\",\"profile\":\"LIGHT\"}"

for resource in "" assets urls endpoints technologies evidence findings reports; do
  suffix="${resource:+/$resource}"
  assert_status 404 GET "$api_url/workspaces/$workspace_b/scans/$scan_a$suffix"
done

assert_status 404 GET "$api_url/workspaces/$workspace_b/scans/$scan_a/findings/$finding_a"
assert_status 404 GET "$api_url/workspaces/$workspace_b/scans/$scan_a/reports/$report_a/content"

mkdir -p "$(dirname "$tenant_artifact")"
jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg workspaceA "$workspace_a" \
  --arg workspaceB "$workspace_b" \
  --arg targetA "$target_a" \
  --arg scanA "$scan_a" \
  --arg findingA "$finding_a" \
  --arg reportA "$report_a" \
  '{generatedAt:$generatedAt,workspaceA:$workspaceA,workspaceB:$workspaceB,targetA:$targetA,scanA:$scanA,findingA:$findingA,reportA:$reportA,crossWorkspaceScopeConfiguration:"BLOCKED",crossWorkspaceScanCreation:"BLOCKED",crossWorkspaceAssets:"BLOCKED",crossWorkspaceUrls:"BLOCKED",crossWorkspaceEndpoints:"BLOCKED",crossWorkspaceTechnologies:"BLOCKED",crossWorkspaceEvidence:"BLOCKED",crossWorkspaceFindings:"BLOCKED",crossWorkspaceReports:"BLOCKED",crossWorkspaceReportContent:"BLOCKED"}' >"$tenant_artifact"
cat "$tenant_artifact"
