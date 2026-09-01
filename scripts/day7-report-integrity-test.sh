#!/usr/bin/env bash
set -euo pipefail

api_url="${AASP_API_URL:-http://127.0.0.1:3001/api}"
acceptance_artifact="${DAY7_SOURCE_ACCEPTANCE_ARTIFACT:-artifacts/day7-report-runtime-acceptance.json}"
integrity_artifact="${DAY7_REPORT_INTEGRITY_ARTIFACT:-artifacts/day7-report-integrity.json}"
admin_email="${ADMIN_EMAIL:-admin@local.test}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD is required}"

workspace_id=$(jq -er '.workspaceId' "$acceptance_artifact")
scan_id=$(jq -er '.scanId' "$acceptance_artifact")
login_payload=$(jq -n --arg email "$admin_email" --arg password "$ADMIN_PASSWORD" '{email:$email,password:$password}')
token=$(curl --fail --silent --show-error -X POST "$api_url/auth/login" -H 'content-type: application/json' --data "$login_payload" | jq -er '.accessToken')
authorization="authorization: Bearer $token"
reports=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports" -H "$authorization")
report_count=$(jq 'length' <<<"$reports")
test "$report_count" -gt 2

hashes_verified=0
while IFS=$'\t' read -r report_id expected_hash; do
  curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports/$report_id/content" -H "$authorization" --output /tmp/aasp-day7-report-content
  actual_hash=$(sha256sum /tmp/aasp-day7-report-content | cut -d ' ' -f 1)
  test "$actual_hash" = "$expected_hash"
  hashes_verified=$((hashes_verified + 1))
done < <(jq -r '.[] | [.id, .sha256] | @tsv' <<<"$reports")

complete_report_id=$(jq -er '.[] | select(.type=="COMPLETE_SCAN") | .id' <<<"$reports")
complete_json=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports/$complete_report_id/content?format=json" -H "$authorization")
test "$(jq -r '.scan.state' <<<"$complete_json")" = "COMPLETED_WITH_WARNINGS"
test "$(jq -r '[.stages[] | select(.name=="GENERATING_SCAN_REPORT" or .name=="GENERATING_VULNERABILITY_REPORTS") | .status] | all(.=="COMPLETED")' <<<"$complete_json")" = "true"
test "$(jq -r 'all(.findings[]; (.evidence | length) > 0)' <<<"$complete_json")" = "true"

vulnerability_states_valid=true
while IFS= read -r report_id; do
  vulnerability_json=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/scans/$scan_id/reports/$report_id/content?format=json" -H "$authorization")
  if [[ "$(jq -r '.scan.state' <<<"$vulnerability_json")" != "COMPLETED_WITH_WARNINGS" ]] ||
    [[ "$(jq -r '(.finding.evidence | length) > 0' <<<"$vulnerability_json")" != "true" ]]; then
    vulnerability_states_valid=false
    break
  fi
done < <(jq -r '.[] | select(.type=="VULNERABILITY") | .id' <<<"$reports")
test "$vulnerability_states_valid" = true

mkdir -p "$(dirname "$integrity_artifact")"
jq -n \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg workspaceId "$workspace_id" \
  --arg scanId "$scan_id" \
  --arg scanState "$(jq -r '.scan.state' <<<"$complete_json")" \
  --argjson reportCount "$report_count" \
  --argjson hashesVerified "$hashes_verified" \
  '{generatedAt:$generatedAt,workspaceId:$workspaceId,scanId:$scanId,reportCount:$reportCount,hashesVerified:$hashesVerified,completeReportState:$scanState,reportStagesCompleted:true,everyCompleteReportFindingHasEvidence:true,everyVulnerabilityReportHasEvidence:true,everyVulnerabilityReportUsesTerminalState:true}' >"$integrity_artifact"
cat "$integrity_artifact"
