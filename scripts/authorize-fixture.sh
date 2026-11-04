#!/usr/bin/env bash
# Source this helper from acceptance scripts. It can authorize only an owned local fixture.
authorize_owned_fixture() (
  set -euo pipefail
  local target_origin client engagement engagement_id version doc starts ends payload
  target_origin=$(curl --fail --silent --show-error "$api_url/workspaces/$workspace_id/targets" -H "$authorization" | jq -er --arg id "$target_id" '.[] | select(.id==$id) | .origin')
  case "$target_origin" in
    http://fixture.internal:4010|http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) ;;
    *) printf 'Fixture authorization refuses non-local target: %s\n' "$target_origin" >&2; exit 1 ;;
  esac
  fixture_post() { curl --fail --silent --show-error -X POST "$api_url/workspaces/$workspace_id/$1" -H "$authorization" -H 'content-type: application/json' --data "$2"; }
  client=$(fixture_post clients '{"name":"Owned acceptance fixtures","legalName":"Local development fixtures"}')
  engagement=$(fixture_post engagements "$(jq -n --arg clientId "$(jq -r .id <<<"$client")" '{clientId:$clientId,name:"Owned fixture acceptance",objective:"Validate the platform against its owned local fixture.",environment:"LAB"}')")
  engagement_id=$(jq -er .id <<<"$engagement")
  starts=$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%SZ)
  ends=$(date -u -d '+4 hours' +%Y-%m-%dT%H:%M:%SZ)
  payload=$(jq -n --arg targetId "$target_id" --arg starts "$starts" --arg ends "$ends" '{expectedVersion:1,reason:"Owned local fixture acceptance authorization.",targetIds:[$targetId],windowStartsAt:$starts,windowEndsAt:$ends,maxRequests:50000,requestsPerSecond:20,maxConcurrency:10,maxRisk:"LOW_IMPACT",allowedCategories:["DISCOVERY","HTTP_CONFIGURATION","AUTHORIZATION"],allowedProtocols:["http:"],restrictions:"Only the owned local fixture. No mutation or third-party targets."}')
  engagement=$(fixture_post "engagements/$engagement_id/policies" "$payload")
  for state in SCOPING AWAITING_AUTHORIZATION; do
    version=$(jq -er .version <<<"$engagement")
    engagement=$(fixture_post "engagements/$engagement_id/transitions" "$(jq -n --arg to "$state" --argjson version "$version" '{to:$to,expectedVersion:$version,reason:"Owned local fixture acceptance transition."}')")
  done
  doc=$(fixture_post "engagements/$engagement_id/documents" "$(jq -n --arg content "$(printf 'Synthetic permission for the owned local fixture only. No external client authorization.' | base64 -w0)" '{filename:"owned-fixture-permission.txt",contentType:"text/plain",contentBase64:$content}')")
  engagement=$(fixture_post "engagements/$engagement_id/authorizations" "$(jq -n --arg doc "$(jq -er .id <<<"$doc")" --argjson version "$(jq -er .version <<<"$engagement")" --arg starts "$starts" --arg ends "$ends" '{expectedVersion:$version,documentId:$doc,authorizedBy:"Local fixture owner",validFrom:$starts,validUntil:$ends,reason:"Owned local fixture acceptance authorization."}')" | jq -c .engagement)
  for state in SCHEDULED ACTIVE TESTING; do
    engagement=$(fixture_post "engagements/$engagement_id/transitions" "$(jq -n --arg to "$state" --argjson version "$(jq -er .version <<<"$engagement")" '{to:$to,expectedVersion:$version,reason:"Owned local fixture acceptance transition."}')")
  done
  printf '%s\n' "$engagement_id"
)
