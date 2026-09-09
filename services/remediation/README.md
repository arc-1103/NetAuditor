# Remediation service

Deterministically renders vendor remediation commands from the template name
on each compliance finding. When a finding's vendor has **no** committed
template, an agentic RAG fallback synthesizes one instead — see
`app/rag_remediation.py` and the Agentic RAG fallback section below. It
performs fail-safe preflight checks, stores the proposal, and records
explicit human approval or rejection.

## Safety model

- The default, primary path is still **no free-form AI command generation**:
  every finding with a template gets a version-controlled Jinja2 script,
  exactly as before.
- Template paths are allow-listed and traversal is rejected.
- Lockout commands, placeholders, and environment-specific defaults produce `RISK_FLAGS`.
- A proposal can only be approved when its preflight status is `SAFE`.
- A missing/unconfigured Batfish snapshot returns `UNAVAILABLE`, never `SAFE`.
- Regeneration resets any old approval to prevent stale approvals after a script changes.
- The agentic RAG fallback (only for a vendor with no template) can **never**
  reach `SAFE` — see below. It cannot be approved through the normal flow at
  all, by design.

## Agentic RAG fallback (no committed template)

`POST /remediation/generate` only takes this path when `finding.remediation`
is null (the vendor has no row in compliance's `remediation_templates`
table) and a device vendor was supplied in the request body:

1. **Remediation Index Query** — `app/manual_provider.py` asks Learning's
   `/learning/remediation-manuals/search` for vendor manual excerpts indexed
   under this exact `[control_id, vendor, OS]` key (an exact metadata match,
   not a fuzzy embedding search — a close-but-wrong manual would be
   dangerous grounding for CLI synthesis).
2. **Contextual CLI Synthesis** — `app/slm_client.py` asks an SLM to produce
   CLI from that context (or with no context, if nothing was indexed).
3. **Rollback Generation** — the SLM is asked for a mandatory inverse
   rollback script alongside the remediation CLI.

The result is **always** persisted with `preflight_status: RISK_FLAGS` and
`source: "agentic_rag"`, never `SAFE`, regardless of how well-grounded the
synthesis was or whether a rollback was produced — `db.approve()` only
accepts an approval when `preflight_status == 'SAFE'`, so an agentic-RAG
proposal can be read, manually verified against the real vendor
documentation, and applied out-of-band, or rejected, but it can never be
approved through the normal flow the way a reviewed template can. It never
earns the same trust label a committed `.j2` template does.

Findings that already have a template are entirely unaffected — this
fallback only exists for the gap compliance's README already documents
("every other vendor gets a full compliance verdict but `remediation: null`
until someone adds a `.j2` template"). The bulk
`POST /remediation/audit-runs/{id}/generate` endpoint does not use this
fallback yet: `db.get_findings()` only selects persisted compliance-finding
columns, which don't include device vendor/OS, so there's nothing to query
the manual index or the SLM with for that path today.

## Deploying to an existing database

`rollback_script` and `source` on `remediation_proposals` are new columns.
`infra/postgres/init.sql` only runs against a brand-new `pgdata` volume — an
existing database needs `infra/postgres/migrations/0001_add_graphrag_and_agentic_rag_columns.sql`
applied by hand first, or every `save_proposal` call fails with
`UndefinedColumn` after this deploys.

## Run and test

```bash
cp .env.example .env
pip install -r requirements-dev.txt
pytest -q
uvicorn app.main:app --reload --port 8004
```

Useful endpoints:

- `POST /remediation/audit-runs/{id}/generate` — generate every fix for a completed evaluation.
- `POST /remediation/generate` — generate one proposal with optional template variables.
- `GET /remediation/audit-runs/{id}` — list scripts and approval state.
- `POST /remediation/{control_id}/approve` — approve/reject with `audit_run_id` in the body.

`USE_MOCK_BATFISH=true` is intended for the prototype demo. It still runs the
local lockout checks. Real Batfish mode intentionally requires a prepared
network snapshot before it will produce a safe verdict.
