-- AI Interpretation Trust Layer (docs/Suggestions.md item 7, docs/action.md
-- Phase 3) — the deterministic (TextFSM) cross-check's own partial
-- extraction (services/parsing/app/deterministic_extractor.py), stored
-- alongside the SLM's full merged baseline (baseline_snapshot) so
-- app/trust.py can diff the two on read rather than needing a separate
-- per-field comparison table. NULL/empty for a vendor the cross-check
-- doesn't cover yet — same "no signal" meaning as everywhere else this
-- session's work has used it.
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS deterministic_baseline JSONB;
