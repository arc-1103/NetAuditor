# Remediation + Reporting demo runbook

This is the shortest reliable judging flow after an audit has reached
`EVALUATED`. Replace `$TOKEN` and `$RUN_ID` with the login token and upload/audit
identifier shown by the dashboard.

```bash
# 1. Generate deterministic remediation proposals for every failed control.
curl -s -X POST "http://localhost:8000/api/remediation/audit-runs/$RUN_ID/generate" \
  -H "Authorization: Bearer $TOKEN"

# 2. Inspect preflight results. SAFE fixes are eligible for approval;
#    RISK_FLAGS identify placeholders/environment-specific values.
curl -s "http://localhost:8000/api/remediation/audit-runs/$RUN_ID" \
  -H "Authorization: Bearer $TOKEN"

# 3. Approve one SAFE proposal (example control).
curl -s -X POST "http://localhost:8000/api/remediation/CIS-IOS-1.1.1/approve" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"approved\":true,\"audit_run_id\":\"$RUN_ID\",\"comment\":\"Demo approval\"}"

# 4. Generate the report, then open its preview/download URLs.
curl -s -X POST http://localhost:8000/api/reports/generate \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"audit_run_id\":\"$RUN_ID\"}"

# 5. Optional: show machine-readable and SIEM-compatible evidence exports.
curl -s "http://localhost:8000/api/reports/$RUN_ID/json" -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:8000/api/reports/$RUN_ID/cef" -H "Authorization: Bearer $TOKEN"
```

## What to say during the demo

1. OPA alone decides compliance; the SLM never emits a verdict.
2. Each failed control names a version-controlled remediation template.
3. The engine refuses approval unless preflight is `SAFE`.
4. The PDF ties evidence and remediation back to the uploaded file's SHA-256.
5. Regenerating a proposal clears its approval, preventing stale authorization.

## Before presenting

- Use a fresh Postgres volume or apply the new tables from `infra/postgres/init.sql`.
- Keep `USE_MOCK_BATFISH=true` unless a real Batfish topology snapshot is prepared.
- Pre-pull/build images and generate one backup PDF before the venue network is disconnected.
- Do not approve scripts containing `RISK_FLAGS`; supply correct site variables and regenerate them.
