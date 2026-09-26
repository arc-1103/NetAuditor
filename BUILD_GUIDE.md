# Build Guide — What to build in each folder, and how to run it

Read `TEAM_OWNERSHIP.md` first to know which row is yours.
Read `contracts/` before writing any code that crosses a lane boundary.

| Folder | What you build | Execute (standalone) | Execute (in full stack) |
|---|---|---|---|
| `services/ingestion/app/` | `main.py` (FastAPI upload endpoint), `uploader.py` (python-magic validation, SHA-256, EXIF strip), `chunker.py` (textfsm block splitter), `queue_producer.py` (Celery dispatch) | `cd services/ingestion && cp .env.example .env && uvicorn app.main:app --reload --port 8001` | `docker compose up ingestion` |
| `services/parsing/app/` | `vendor_detector.py`, `slm_client.py` (Ollama call), `grammar_constraints.py` (Outlines/Instructor schema enforcement), `schema_validator.py`, `normalizer.py` | `cd services/parsing && cp .env.example .env && USE_MOCK_SLM=true python -m app.worker` | `docker compose up parsing ollama chromadb` |
| `services/schema/` | `security_baseline.py`, `enums.py` — the shared Pydantic models. **Not a service, a library.** Other lanes `pip install -e ../schema` | `cd services/schema && pip install -e .` then `pytest` | Pulled in as a dependency by parsing/compliance images at build time |
| `services/compliance/app/` + `policies/` | `opa_client.py`, `risk_scorer.py`, and the actual `.rego` files per vendor/framework under `policies/` | `cd services/compliance && cp .env.example .env && opa test policies/ -v` then `python -m app.worker` | `docker compose up compliance opa` |
| `services/learning/backend/` | Reviewed mappings, vendor fingerprints, RAG retrieval and anomaly context | `cd services/learning/backend && cp ../.env.example .env && uvicorn app.main:app --port 8003` | `docker compose --profile advanced up learning chromadb` |
| `services/remediation/app/` + `templates/` | Deterministic templates, optional Batfish preflight, approval API and agentic-RAG fallback | `cd services/remediation && cp .env.example .env && uvicorn app.main:app --port 8004` | `docker compose up remediation` (`--profile advanced` adds Batfish) |
| `services/reporting/app/` | `pdf_service.py` (WeasyPrint), `html_templates/` (Jinja2→HTML) | `cd services/reporting && cp .env.example .env && python -m app.pdf_service --test` | `docker compose up reporting` |
| `gateway/app/` | `main.py` (route table from `contracts/api_gateway_routes.md`), `auth.py` (JWT) | `cd gateway && cp .env.example .env && uvicorn app.main:app --port 8000` | `docker compose up gateway` |
| `frontend/src/` | Next.js pages under `app/` (overview, inventory, audit history, learning queue), `components/`, API client in `lib/` | `cd frontend && cp .env.local.example .env.local && npm install && npm run dev` | `docker compose up frontend` |
| `infra/` | PostgreSQL schema and migrations | n/a — consumed by Docker Compose | `docker compose up` (presentation core) |
| `contracts/` | JSON schema files + route table — **write these before the code that depends on them**, not after | n/a | n/a |

## Order of operations if you're unsure where to start
1. `services/schema/` must exist (even a stub) before Parsing or Compliance can be meaningfully tested.
2. `contracts/api_gateway_routes.md` must be filled in before Frontend or Gateway write real code — build against the mock in the meantime.
3. Everything else can start in parallel from day 1 using mock flags.

## Full local run, from a clean clone
```bash
./scripts/setup_demo.sh
docker compose up --build -d
python3 scripts/wait_for_stack.py
python3 scripts/seed_admin.py
```

The default stack is the reliable presentation core. Add
`--profile advanced --profile model` only after the core demo is verified.
