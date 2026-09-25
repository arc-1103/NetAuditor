-- Deterministic-vs-SLM agreement (docs/action.md Phase 2, docs/Suggestions.md
-- item 7) — Parsing's independent TextFSM cross-check
-- (services/parsing/app/agreement.py) against its own SLM extraction, 0..1,
-- NULL when the deterministic extractor abstained entirely (unsupported
-- vendor) rather than 0.0/1.0, which would misrepresent "no comparison
-- possible" as a confident score. Distinct column from parsing_confidence —
-- see that column's own history — because it's a different signal (external
-- agreement vs. self-reported confidence), not a replacement for it.
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS parser_agreement DOUBLE PRECISION;
