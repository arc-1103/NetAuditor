-- Runs automatically on first `docker compose up postgres` via
-- docker-entrypoint-initdb.d (only fires against an empty data volume).
-- Referenced by gateway/app/auth.py and scripts/seed_admin.py.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Owned by Ingestion lane (see services/ingestion/app/db.py). `id` is
-- supplied by the app as the same job_id sent to the Parsing queue, so
-- /api/audit-runs/{id} can look up a run by the id returned from upload.
-- Compliance lane updates `status` (and appends findings elsewhere) as
-- the audit progresses.
CREATE TABLE IF NOT EXISTS audit_runs (
    id                UUID PRIMARY KEY,
    file_hash         TEXT NOT NULL,
    original_filename TEXT,
    storage_path      TEXT NOT NULL,
    uploaded_by       UUID REFERENCES users(id),
    status            TEXT NOT NULL DEFAULT 'INGESTED',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Owned by Compliance lane (see services/compliance/app/db.py). One row per
-- FAILED control; a control that passed is simply absent. Shape mirrors
-- contracts/compliance_finding.schema.json, which Remediation, Reporting and
-- the Frontend all read.
--
-- Current state, not an append-only log: re-running an audit after a policy
-- change deletes this run's rows and reinserts, so findings can never be stale
-- with respect to the bundle. The immutable trail lives in audit_runs.
CREATE TABLE IF NOT EXISTS compliance_findings (
    audit_run_id  UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    control_id    TEXT NOT NULL,
    framework     TEXT NOT NULL,
    title         TEXT NOT NULL,
    status        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT,
    remediation   TEXT,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (audit_run_id, control_id)
);

-- The dashboard's main query is "all findings for this run, worst first".
CREATE INDEX IF NOT EXISTS idx_findings_run_severity
    ON compliance_findings (audit_run_id, severity);
