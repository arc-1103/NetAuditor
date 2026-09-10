-- Runs automatically on first `docker compose up postgres` via
-- docker-entrypoint-initdb.d (only fires against an empty data volume).
-- Referenced by gateway/app/auth.py and scripts/seed_admin.py.
--
-- Deploying a schema change to an EXISTING database: this file will not
-- re-run against a populated pgdata volume. Apply infra/postgres/migrations/
-- in order by hand (psql "$POSTGRES_DSN" -f infra/postgres/migrations/<file>)
-- before deploying code that depends on the new columns.

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
-- `status_detail` is written by Parsing (see services/parsing/app/db.py) when
-- a job comes back human_review (unsupported vendor, or confidence below
-- threshold) and never reaches Compliance. Without it, such a run stalls at
-- INGESTED forever with no trace of why — status alone isn't enough because
-- Ingestion, Parsing and Compliance all move it, and only Parsing knows the
-- human_review reason at the point it happens.
CREATE TABLE IF NOT EXISTS audit_runs (
    id                UUID PRIMARY KEY,
    file_hash         TEXT NOT NULL,
    original_filename TEXT,
    storage_path      TEXT NOT NULL,
    uploaded_by       UUID REFERENCES users(id),
    status            TEXT NOT NULL DEFAULT 'INGESTED',
    status_detail     JSONB,
    detected_vendor   TEXT,
    detected_os       TEXT,
    parsing_confidence DOUBLE PRECISION,
    schema_version    TEXT,
    baseline_snapshot JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Owned by Learning lane (see services/learning/backend/app/). One row per
-- config chunk that failed Pydantic schema validation during Parsing and
-- needs a human to map its CLI tokens to a SecurityBaseline field. `block_id`
-- is the stable identity Parsing/Learning pass back and forth (e.g.
-- "<audit_run_id>:<chunk_index>"), not a generated surrogate key, so a
-- resubmitted mapping for the same block is an update, not a duplicate row.
-- `chunk_context` carries the device metadata known at parse time (vendor,
-- os, hostname, surrounding chunk text) so the mapping UI can show it without
-- a second round-trip to Parsing.
CREATE TABLE IF NOT EXISTS learning_queue (
    block_id      TEXT PRIMARY KEY,
    audit_run_id  UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    raw_text      TEXT NOT NULL,
    chunk_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    status        TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'MAPPED', 'DISMISSED')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The mapping UI's main query is "oldest unresolved blocks first".
CREATE INDEX IF NOT EXISTS idx_learning_queue_status
    ON learning_queue (status, created_at);

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
    -- GraphRAG blast radius (see services/compliance/app/graph_client.py):
    -- device ids reachable from this finding's device via routing adjacency.
    -- Empty when the topology graph is unavailable or the device has no
    -- known routing neighbors, not when the finding is absent.
    blast_radius  JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_lines  JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (audit_run_id, control_id)
);

-- The dashboard's main query is "all findings for this run, worst first".
CREATE INDEX IF NOT EXISTS idx_findings_run_severity
    ON compliance_findings (audit_run_id, severity);

CREATE TABLE IF NOT EXISTS audit_evaluations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_run_id          UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    framework             TEXT NOT NULL,
    policy_bundle_version TEXT NOT NULL,
    schema_version        TEXT,
    baseline_sha256       TEXT NOT NULL,
    findings_snapshot     JSONB NOT NULL,
    evaluated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_evaluations_run
    ON audit_evaluations (audit_run_id, evaluated_at DESC);

-- Unsupervised semantic anomaly detection (services/compliance/app/anomaly_client.py).
-- A separate table from compliance_findings, not a column on it: this is a
-- statistical signal (IsolationForest over a vendor+OS peer cohort's
-- embeddings, computed by services/learning) that can flip over time as
-- more peers get scanned, with nothing about the baseline itself changing —
-- unlike a compliance_findings row, which the same baseline always
-- reproduces identically. One row per audit run, not per control.
CREATE TABLE IF NOT EXISTS configuration_anomalies (
    audit_run_id   UUID PRIMARY KEY REFERENCES audit_runs(id) ON DELETE CASCADE,
    device_id      TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('scored', 'insufficient_peers', 'not_ingested', 'unavailable')),
    -- is_anomaly/anomaly_score/peer_count are only set when status = 'scored'.
    is_anomaly     BOOLEAN,
    anomaly_score  DOUBLE PRECISION,
    peer_count     INTEGER,
    checked_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Deterministic remediation proposals. A proposal is regenerated in place so
-- stale approvals cannot survive a template or preflight change.
CREATE TABLE IF NOT EXISTS remediation_proposals (
    audit_run_id       UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    control_id         TEXT NOT NULL,
    template_name      TEXT NOT NULL,
    script             TEXT NOT NULL,
    -- Mandatory inverse script for an agentic-RAG proposal (NULL for a
    -- template proposal — the template itself is trusted, version-controlled
    -- CLI, not a synthesized change to revert). See app/rag_remediation.py.
    rollback_script    TEXT,
    -- 'template': rendered from a version-controlled .j2 file (the
    -- safety-model-preserving default). 'agentic_rag': SLM-synthesized,
    -- used only when no template exists for this control's vendor.
    source             TEXT NOT NULL DEFAULT 'template' CHECK (source IN ('template', 'agentic_rag')),
    preflight_status   TEXT NOT NULL CHECK (preflight_status IN ('SAFE', 'RISK_FLAGS', 'UNAVAILABLE')),
    risk_flags         JSONB NOT NULL DEFAULT '[]'::jsonb,
    approval_status    TEXT NOT NULL DEFAULT 'PENDING' CHECK (approval_status IN ('PENDING', 'APPROVED', 'REJECTED')),
    approved_by        TEXT,
    approval_comment   TEXT,
    approved_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (audit_run_id, control_id),
    FOREIGN KEY (audit_run_id, control_id)
        REFERENCES compliance_findings(audit_run_id, control_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS generated_reports (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_run_id  UUID NOT NULL REFERENCES audit_runs(id) ON DELETE CASCADE,
    file_path     TEXT NOT NULL,
    generated_by TEXT,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_reports_audit_run ON generated_reports (audit_run_id, generated_at DESC);
