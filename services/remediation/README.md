# Remediation service

Deterministically renders Cisco IOS remediation commands from the template name
on each compliance finding. It performs fail-safe preflight checks, stores the
proposal, and records explicit human approval or rejection.

## Safety model

- No free-form AI command generation; all commands are version-controlled Jinja2 templates.
- Template paths are allow-listed and traversal is rejected.
- Lockout commands, placeholders, and environment-specific defaults produce `RISK_FLAGS`.
- A proposal can only be approved when its preflight status is `SAFE`.
- A missing/unconfigured Batfish snapshot returns `UNAVAILABLE`, never `SAFE`.
- Regeneration resets any old approval to prevent stale approvals after a script changes.

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
