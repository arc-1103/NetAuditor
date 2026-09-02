# Architecture — Ingestion + Gateway

## Component diagram (this lane only)

```
                    ┌─────────────────────────────────────┐
   Frontend  ──────▶│  Gateway (gateway/)                  │
   (Next.js)  HTTPS │  - /api/login   (issues JWT)         │
   JWT Bearer        │  - /api/upload  (proxy → Ingestion)  │
                    │  - /api/audit-runs/{id} (proxy → Compliance) │
                    │  auth.py: validates + issues JWT      │
                    │  db.py: Postgres — users table only   │
                    └──────────────┬────────────────────────┘
                                   │ proxies raw upload (httpx)
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  Ingestion (services/ingestion/)      │
                    │  - POST /upload                       │
                    │  uploader.py: validate, hash, store    │
                    │  chunker.py: split into blocks         │
                    │  queue_producer.py: enqueue job         │
                    └───┬───────────────────┬────────────────┘
                        │                   │
                        ▼                   ▼
                 ┌────────────┐      ┌──────────────┐
                 │   MinIO    │      │  Redis/Celery │
                 │ raw-configs│      │  job queue     │
                 └────────────┘      └──────┬────────┘
                                             │ contracts/ingestion_job.schema.json
                                             ▼
                                    Parsing lane (out of scope)
```

## Two separate Postgres relationships — do not conflate

1. **Gateway owns `users`** (`infra/postgres/init.sql`). This is the only
   table Gateway reads/writes. Login → bcrypt check → JWT issue.
2. **Ingestion writes `AuditRun` records** (status=INGESTED) per the
   master blueprint sequence — **not yet implemented** in
   `uploader.py`. Currently ingestion only writes to MinIO, not
   Postgres. This is a real gap: `services/ingestion/.env.example`
   declares `POSTGRES_DSN` but no code path uses it yet.

Both services connect to the same physical Postgres instance but own
disjoint tables. Never let one service's migration touch the other's
table without a heads-up — see `TEAM_OWNERSHIP.md`.

## Request flow, step by step

1. Frontend calls `POST /api/login` with email/password.
2. Gateway (`auth.py::authenticate_user`) checks `users` table, verifies
   bcrypt hash, issues JWT (`issue_token`).
3. Frontend calls `POST /api/upload` with `Authorization: Bearer <jwt>`
   and the file.
4. Gateway (`main.py::upload`) validates the JWT via `get_current_user`,
   then proxies the raw file to Ingestion over internal HTTP (`httpx`),
   unauthenticated at that hop (internal network, not internet-facing).
5. Ingestion (`uploader.py::validate_and_store`) checks size + extension,
   computes SHA-256, builds a MinIO storage path. **MinIO write itself is
   still a TODO** — currently returns the intended path without actually
   calling `put_object`.
6. Ingestion (`queue_producer.py::enqueue_parsing_job`) builds a payload
   matching `contracts/ingestion_job.schema.json` and sends a Celery task
   `parsing.process_config` to Redis.
7. Gateway returns `{job_id, status: "queued"}` to the frontend.

## Dependency boundaries (what this lane touches vs. doesn't)

| Depends on | How | Owned by |
|---|---|---|
| Postgres `users` table | direct SQL (`gateway/app/db.py`) | Gateway (you) |
| Postgres `AuditRun` table | not yet wired | Ingestion (you) — **TODO** |
| MinIO | not yet wired (stub) | Ingestion (you) — **TODO** |
| Redis/Celery | `queue_producer.py` | Ingestion (you) |
| Parsing lane's queue consumer | contract only, `contracts/ingestion_job.schema.json` | Parsing lane |
| Compliance service | HTTP proxy, `COMPLIANCE_URL` | Compliance lane |
| JWT secret (`JWT_SECRET`) | shared value, root `.env` | Whoever else validates tokens — currently nobody else does |

Nothing downstream (Parsing, Compliance, Remediation, Reporting, Learning)
needs your code to import or call directly. The only coupling points are
the two contract files above — treat them as your public API.