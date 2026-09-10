ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS detected_vendor TEXT;
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS detected_os TEXT;
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS parsing_confidence DOUBLE PRECISION;
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS schema_version TEXT;
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS baseline_snapshot JSONB;
ALTER TABLE compliance_findings ADD COLUMN IF NOT EXISTS source_lines JSONB NOT NULL DEFAULT '[]'::jsonb;

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
