-- Masked credential evidence (see docs/ArchitecturalChanges.md §2): last-4-
-- character mask, line number, pattern type, and a SHA-256 of the raw
-- secret, captured before redact_credentials() runs. Never the raw secret
-- itself. Empty array when nothing matched, never NULL by default.
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS credential_evidence JSONB;
