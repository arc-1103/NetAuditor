# NetAudit Engine

Explainable, air-gap-ready network configuration compliance for SIH 26155.

NetAudit ingests raw network-device configuration, redacts secrets, identifies
the platform, converts vendor syntax into a strict normalized security model,
and evaluates that model with deterministic OPA policies. AI assists extraction;
it never decides whether a control passes or fails.

## Prototype capability

| Capability | Current evidence |
|---|---|
| Upload, SHA-256 fingerprinting, MinIO storage | Implemented |
| Schema-constrained local parsing | Deterministic mock and Ollama modes |
| Compliance verdicts | 11-control CIS-style generic Level 1 prototype bundle |
| Demonstrated vendors | Cisco IOS-XE and Fortinet FortiOS fixtures |
| Deterministic remediation | Cisco and partial Fortinet Jinja2 templates |
| Safety gate | Only `SAFE` preflight proposals can be approved |
| Reporting | Browser preview, PDF, JSON and CEF |
| Optional context | Learning queue, anomaly signal and topology blast radius |

This repository does not claim CIS certification or complete CIS, NIST, STIG or
ISO 27001 coverage. Official policy content and additional validated vendor
adapters are expansion work.

## Decision boundary

```text
Configuration → secret redaction → local AI extraction → Pydantic validation
              → deterministic OPA verdict → preflighted remediation
              → human approval → versioned evidence report
```

Low-confidence or invalid parsing becomes `NEEDS_REVIEW`; it is never displayed
as compliant. AI-synthesized remediation is permanently marked `RISK_FLAGS` and
cannot pass the normal approval gate.

## Fast presentation setup

Requirements: Docker Engine with Compose v2, at least 12 GB RAM for the complete
local-model stack, and internet access during the first image/model pull.

```bash
./scripts/setup_demo.sh
docker compose up --build -d
python scripts/wait_for_stack.py
python scripts/seed_admin.py
```

Open `http://localhost:3000`, then upload `demo/cisco_insecure.cfg`.
See `demo/DEMO_SCRIPT.md` for the four-minute narration and
`docs/PRESENTATION_CLAIMS_CHECKLIST.md` for defensible wording.

Set `NEXT_PUBLIC_USE_MOCK_API=true` before building the frontend for the
deterministic venue fallback. The dashboard labels fallback mode clearly.
For a UI-only fallback that needs no backend, run `npm run demo` inside
`frontend/`; any accepted configuration file opens the deterministic walkthrough.

The default Compose startup is the presentation core. Optional topology,
learning and local-model services can be included with
`docker compose --profile advanced --profile model up --build -d`.

## Repository map

- `frontend/` — Next.js operations console
- `gateway/` — authentication, authorization and API boundary
- `services/ingestion/` — validation, redaction, storage and queue dispatch
- `services/parsing/` and `services/schema/` — normalized extraction contract
- `services/compliance/` — OPA policies, risk scoring and immutable evaluations
- `services/learning/` — reviewed mappings and optional statistical context
- `services/remediation/` — templates, preflight and approval gate
- `services/reporting/` — HTML/PDF/JSON/CEF evidence
- `demo/` and `benchmarks/` — presentation fixtures and measured validation

## Verification

GitHub Actions tests every lane independently, builds the locked frontend and
runs static/demo gates. Before a live demo, also run `docker compose config` and
the end-to-end smoke test on the presentation machine.

## Security notes

- Production startup rejects the known default JWT secret.
- Dashboard roles are `admin`, `operator` and read-only `auditor`.
- Uploaded files are bounded, MIME checked, credential-redacted and hashed.
- Internal services live on an isolated network; only gateway/dashboard publish ports.
- Every re-evaluation appends policy, schema, baseline and findings provenance.

Review `docs/THREAT_MODEL.md` before deployment. This is a prototype engineering
aid, not authorization to modify production devices.
