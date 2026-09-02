# Gateway Routes (draft — Gateway lane owns final source of truth)

| Method | Path | Auth | Returns | Owning service |
|---|---|---|---|---|
| POST | /api/upload | JWT | AuditRun (status=INGESTED) | ingestion |
| GET | /api/audit-runs/{id} | JWT | AuditRun + findings[] | compliance |
| POST | /api/reports/generate | JWT | PDF download link | reporting |
| GET | /api/learning/queue | JWT | UnrecognizedBlock[] | learning |
| POST | /api/learning/map | JWT | MappingConfirmation | learning |
| POST | /api/remediation/{control_id}/approve | JWT | ApprovalResult | remediation |

Frontend should build against this table with mock data (`NEXT_PUBLIC_USE_MOCK_API=true`)
until the real routes exist — don't wait for Gateway lane to finish first.
