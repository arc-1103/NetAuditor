# compliance service — Deterministic Compliance Engine

Owner: Compliance / OPA lane (see `/TEAM_OWNERSHIP.md`)

Blueprint §2.1 `System_Boundary(compliance)`. This is the deterministic half
of the pipeline: the same normalized baseline always produces the same
verdict, and every verdict carries the evidence that produced it. Nothing in
here calls an LLM.

## What's in here

| File | Role |
|---|---|
| `policies/cis/cisco_ios_level1.rego` | The rules. CIS Cisco IOS L1, illustrative subset per blueprint §7 |
| `policies/cis/cisco_ios_level1_test.rego` | `opa test` cases — one compliant + one violating baseline per control |
| `app/opa_client.py` | Posts the baseline to OPA, walks the result for `deny` sets |
| `app/risk_scorer.py` | Severity → risk weight, and the per-run summary |
| `app/evaluator.py` | The one pass: evaluate → score → persist |
| `app/worker.py` | Celery consumer for `compliance.evaluate_baseline` (from Parsing) |
| `app/main.py` | HTTP: `GET /audit-runs/{id}` (the Gateway proxies here), `POST /evaluate` |
| `app/db.py` | `compliance_findings` table + `audit_runs.status` |
| `tests/test_contracts.py` | Drift guards on the seams other lanes depend on — see below |

## The drift tests

`tests/test_contracts.py` is the one file that reaches outside this service. It
checks the seams nothing else in the repo would notice breaking until
integration day:

- Every finding the real Rego bundle emits validates against
  `contracts/compliance_finding.schema.json`, names a `.j2` template, and uses
  a severity `risk_scorer` can weigh.
- `infra/postgres/init.sql`'s columns match what `app/db.py` inserts.
  `tests/test_db.py` declares its own SQLite table, so without this the two can
  drift apart silently.
- `docker-compose.yml` still starts OPA with `run --server` and the bundle
  mounted, still runs a Celery worker, and MinIO still has its data volume.

The OPA-backed half needs the `opa` binary on PATH and skips without it, so
`pytest` is green either way (57 tests with opa, 51 + 6 skipped without).

## Run standalone

```bash
cp .env.example .env

# 1. The policies — no Docker, no Python, no running services needed.
opa test policies/ -v
opa check --strict policies/

# 2. The Python around them.
pip install -r requirements-dev.txt
pytest

# 3. The service against a live OPA.
opa run --server --addr localhost:8181 policies/ &
OPA_URL=http://localhost:8181/v1/data uvicorn app.main:app --reload --port 8002
```

Then evaluate a config without needing Ingestion, Parsing, or Postgres —
`audit_run_id` is what turns persistence on, so leaving it out is a dry run:

```bash
curl -s localhost:8002/evaluate -H 'Content-Type: application/json' -d '{
  "framework": "CIS",
  "baseline": {
    "device": {"detected_vendor": "cisco", "config_sha256": "'"$(printf a%.0s {1..64})"'", "parsing_confidence": 0.9},
    "ssh": {"enabled": true, "version": "1-2"},
    "telnet": {"enabled": "ENABLED"},
    "snmp": {"enabled": true, "version": "v2c", "community_strings": ["public"]}
  }
}' | python3 -m json.tool
```

In the full stack: `docker compose up opa compliance compliance-worker`.

## The two contracts this lane sits between

**In** — `contracts/security_baseline.schema.json`, from Parsing. Arrives
either as a Celery task or as a `POST /evaluate` body:

```json
{
  "audit_run_id": "<the job_id Ingestion generated>",
  "framework": "CIS",
  "baseline": { "device": {...}, "ssh": {...}, ... }
}
```

Task name is `compliance.evaluate_baseline` on the Redis broker. Celery queues
it, so the Parsing lane never blocks on this service being up.

**Out** — `contracts/compliance_finding.schema.json`, to Remediation,
Reporting and the Frontend. Only failures are emitted; a control absent from
the list passed. `remediation` names the Jinja2 template the Remediation lane
should render.

## Adding a control, or a vendor

A control is one `deny` rule in the relevant `.rego` file plus two cases in
its `_test.rego`. A whole new vendor is a new file under `policies/<framework>/`
— **no Python change**: `opa_client.py` evaluates the entire
`data.compliance.<framework>` subtree in one call and collects every `deny` set
it finds.

The cost of that is that every package sees every device, so **every rule must
guard on `input.device.detected_vendor`** via the package's `applies` rule.
Without it, a Juniper config gets judged against Cisco rules.
`cisco_ios_level1_test.rego::test_non_cisco_device_is_ignored` is there to
catch a forgotten guard.

The second rule is to read optional fields through `object.get` with an
explicit default. `input.ssh.version` on a config with no SSH block is
*undefined*, and an undefined expression makes the rule body fail — so the
device would silently pass "SSH must be v2". The header of
`cisco_ios_level1.rego` explains which way each default should point.

## Known gaps

- Only the CIS Cisco IOS bundle exists. `NIST` and `STIG` are accepted
  framework names but have no policy files, and `opa_client` raises rather
  than returning "compliant" for a framework with no bundle loaded.
- `POST /evaluate` is unauthenticated. It sits on the internal network behind
  the Gateway, same as the Ingestion hop.
