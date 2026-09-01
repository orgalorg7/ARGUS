#!/usr/bin/env bash
set -euo pipefail

api_url="${AASP_API_URL:-http://127.0.0.1:3001/api}"
admin_email="${ADMIN_EMAIL:-admin@local.test}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"
artifact_path="${DAY6_ACCEPTANCE_ARTIFACT:-artifacts/day6-runtime-acceptance.json}"

login_payload=$(jq -n --arg email "$admin_email" --arg password "$ADMIN_PASSWORD" '{email:$email,password:$password}')
token=$(curl --fail --silent --show-error -X POST "$api_url/auth/login" -H 'content-type: application/json' --data "$login_payload" | jq -er '.accessToken')
authorization="authorization: Bearer $token"
suffix=$(date -u +%Y%m%d%H%M%S)

workspace=$(curl --fail --silent --show-error -X POST "$api_url/workspaces" -H "$authorization" -H 'content-type: application/json' --data "{\"name\":\"Day 6 Acceptance $suffix\"}")
workspace_id=$(jq -er '.id' <<<"$workspace")
target=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/targets" -H "$authorization" -H 'content-type: application/json' --data '{"name":"Owned Docker Fixture","url":"http://fixture.internal:4010","scope":{"allowedDomains":["fixture.internal"],"includeSubdomains":false,"allowedPorts":[4010],"excludedPaths":[],"allowPrivateNetwork":true}}')
target_id=$(jq -er '.id' <<<"$target")
test "$(jq -r '.status' <<<"$target")" = "READY"

scan=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans" -H "$authorization" -H 'content-type: application/json' --data "{\"targetId\":\"$target_id\",\"name\":\"Day 6 evidence pipeline $suffix\",\"profile\":\"LIGHT\"}")
scan_id=$(jq -er '.id' <<<"$scan")
curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans/$scan_id/start" -H "$authorization" -H 'content-type: application/json' --data '{}' >/dev/null

state="QUEUED"
for _ in $(seq 1 90); do
  scan=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id" -H "$authorization")
  state=$(jq -r '.state' <<<"$scan")
  case "$state" in
    COMPLETED|COMPLETED_WITH_WARNINGS|FAILED|CANCELLED) break ;;
  esac
  sleep 2
done
test "$state" = "COMPLETED_WITH_WARNINGS"

urls=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/urls" -H "$authorization")
endpoints=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/endpoints" -H "$authorization")
findings=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/findings" -H "$authorization")
reports=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports" -H "$authorization")
finding_count=$(jq 'length' <<<"$findings")
report_count=$(jq 'length' <<<"$reports")
test "$finding_count" -gt 0
test "$(jq 'all(.[]; (.evidenceLinks | length) > 0)' <<<"$findings")" = "true"
test "$report_count" -eq $((finding_count + 2))

complete_report_id=$(jq -er '.[] | select(.type=="COMPLETE_SCAN") | .id' <<<"$reports")
report_status=$(curl --silent --show-error -o /tmp/aasp-day6-report.html -w '%{http_code}' "$api_url/workspaces/$workspace_id/scans/$scan_id/reports/$complete_report_id/content" -H "$authorization")
test "$report_status" = "200"
grep -q 'Complete scan report' /tmp/aasp-day6-report.html

cancel_scan=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans" -H "$authorization" -H 'content-type: application/json' --data "{\"targetId\":\"$target_id\",\"name\":\"Day 6 cancellation check $suffix\",\"profile\":\"LIGHT\"}")
cancel_scan_id=$(jq -er '.id' <<<"$cancel_scan")
cancel_result=$(curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/scans/$cancel_scan_id/cancel" -H "$authorization" -H 'content-type: application/json' --data '{}')
test "$(jq -r '.state' <<<"$cancel_result")" = "CANCELLED"

mkdir -p "$(dirname "$artifact_path")"
jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg workspaceId "$workspace_id" \
  --arg targetId "$target_id" \
  --arg scanId "$scan_id" \
  --arg scanState "$state" \
  --arg cancelledScanId "$cancel_scan_id" \
  --argjson urls "$(jq 'length' <<<"$urls")" \
  --argjson endpoints "$(jq 'length' <<<"$endpoints")" \
  --argjson findings "$finding_count" \
  --argjson reports "$report_count" \
  '{generatedAt:$generatedAt,workspaceId:$workspaceId,targetId:$targetId,scanId:$scanId,scanState:$scanState,urls:$urls,endpoints:$endpoints,findings:$findings,reports:$reports,everyFindingHasEvidence:true,aiAnalysisPerformed:false,aiStageExpected:"DEGRADED",authenticatedReportHttpStatus:200,cancelledScanId:$cancelledScanId,cancellationState:"CANCELLED"}' >"$artifact_path"
cat "$artifact_path"
