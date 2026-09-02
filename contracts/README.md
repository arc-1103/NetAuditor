# Contracts

This folder is the source of truth for shapes that cross lane boundaries.
Nobody should have to read another lane's implementation code to know
what JSON they'll get. Update these BEFORE building against them, not after.

- `security_baseline.schema.json` — output of Parsing, input of Compliance
- `compliance_finding.schema.json` — output of Compliance, input of Remediation/Reporting/Frontend
- `api_gateway_routes.md` — every route the frontend can call, and what each returns
