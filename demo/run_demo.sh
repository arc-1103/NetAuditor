#!/usr/bin/env bash
set -euo pipefail

API_BASE="${NETAUDIT_API_BASE:-http://localhost:8000}"
DEMO_EMAIL="${NETAUDIT_DEMO_EMAIL:-admin@netaudit.local}"
DEMO_PASSWORD="${NETAUDIT_DEMO_PASSWORD:-changeme}"
CONFIG_PATH="${1:-demo/cisco_insecure.cfg}"

for command in curl python3; do
  command -v "$command" >/dev/null || { echo "Required command missing: $command" >&2; exit 1; }
done
test -f "$CONFIG_PATH" || { echo "Configuration not found: $CONFIG_PATH" >&2; exit 1; }

echo "[1/6] Checking gateway"
curl --fail --silent --show-error "$API_BASE/health" >/dev/null

echo "[2/6] Authenticating demo operator"
LOGIN_RESPONSE="$(curl --fail --silent --show-error -X POST "$API_BASE/api/login" -H 'Content-Type: application/json' -d "{\"email\":\"$DEMO_EMAIL\",\"password\":\"$DEMO_PASSWORD\"}")"
TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$LOGIN_RESPONSE")"

echo "[3/6] Uploading $CONFIG_PATH"
UPLOAD_RESPONSE="$(curl --fail --silent --show-error -X POST "$API_BASE/api/upload" -H "Authorization: Bearer $TOKEN" -F "file=@$CONFIG_PATH;type=text/plain")"
RUN_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])' <<<"$UPLOAD_RESPONSE")"
echo "Audit run: $RUN_ID"

echo "[4/6] Waiting for deterministic policy evaluation"
for attempt in $(seq 1 60); do
  AUDIT_RESPONSE="$(curl --fail --silent --show-error "$API_BASE/api/audit-runs/$RUN_ID" -H "Authorization: Bearer $TOKEN")"
  STATUS="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", "UNKNOWN"))' <<<"$AUDIT_RESPONSE")"
  case "$STATUS" in
    EVALUATED|COMPLETE) break ;;
    FAILED|NEEDS_REVIEW) echo "$AUDIT_RESPONSE"; echo "Audit stopped with status $STATUS" >&2; exit 1 ;;
  esac
  sleep 2
done
test "${STATUS:-UNKNOWN}" = "EVALUATED" -o "${STATUS:-UNKNOWN}" = "COMPLETE" || { echo "Timed out waiting for evaluation" >&2; exit 1; }

echo "[5/6] Generating and preflighting remediation"
curl --fail --silent --show-error -X POST "$API_BASE/api/remediation/audit-runs/$RUN_ID/generate" -H "Authorization: Bearer $TOKEN" >/dev/null

echo "[6/6] Generating evidence report"
REPORT_RESPONSE="$(curl --fail --silent --show-error -X POST "$API_BASE/api/reports/generate" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"audit_run_id\":\"$RUN_ID\"}")"

python3 -m json.tool <<<"$AUDIT_RESPONSE"
echo "$REPORT_RESPONSE" | python3 -m json.tool
echo "Demo completed. Open the dashboard and use audit run $RUN_ID"
