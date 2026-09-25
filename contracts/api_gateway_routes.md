# Gateway Routes (draft — Gateway lane owns final source of truth)

| Method | Path | Auth | Returns | Owning service |
|---|---|---|---|---|
| POST | /api/upload | JWT | AuditRun (status=INGESTED) | ingestion |
| GET | /api/audit-runs/{id} | JWT | AuditRun + findings[] | compliance |
| POST | /api/reports/generate | JWT | PDF download link | reporting |
| GET | /api/learning/queue | JWT | UnrecognizedBlock[] | learning |
| POST | /api/learning/map | JWT | MappingConfirmation | learning |
| POST | /api/remediation/{control_id}/approve | JWT | ApprovalResult | remediation |
| POST | /api/remediation/generate | JWT | RemediationProposal | remediation |
| GET | /api/remediation/audit-runs/{id} | JWT | RemediationProposal[] | remediation |
| POST | /api/remediation/audit-runs/{id}/generate | JWT | RemediationProposal[] | remediation |
| GET | /api/reports/{id}/download | JWT | PDF file | reporting |
| GET | /api/reports/{id}/preview | JWT | HTML report preview | reporting |
| GET | /api/reports/{id}/json | JWT | SIEM/archive JSON | reporting |
| GET | /api/reports/{id}/cef | JWT | CEF event stream | reporting |
| GET | /api/fleet-score | JWT | FleetScore (docs/Additional-Features.md §1) | compliance |
| POST | /api/reachability-diff | JWT | ACL diff / approximate blast radius (docs/Additional-Features.md §4) | compliance |
| GET | /api/executive-report | JWT | Fleet score, trend, top-5 exposure, MTTR (docs/Additional-Features.md §6) | reporting |
| GET | /api/provenance/{run_id}/{control_id} | JWT | Ledger provenance chain for one finding (docs/Additional-Features.md §6) | reporting |
| GET | /api/mttr | JWT | MTTR by severity tier (docs/Additional-Features.md §5) | reporting |
| POST | /api/remediation/{control_id}/apply | JWT | RemediationProposal (docs/Additional-Features.md §3) | remediation |
| POST | /api/remediation/{control_id}/rollback | JWT | RemediationProposal (docs/Additional-Features.md §3) | remediation |

Frontend should build against this table with mock data (`NEXT_PUBLIC_USE_MOCK_API=true`)
until the real routes exist — don't wait for Gateway lane to finish first.
