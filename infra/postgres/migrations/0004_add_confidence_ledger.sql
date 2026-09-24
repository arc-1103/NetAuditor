-- Confidence ledger: surfaces the SLM's own gate signals (mean per-token
-- logprob, reverse-translation fidelity) that Parsing already computes to
-- decide human_review vs. submitted, instead of discarding them once the
-- gate decision is made. NULL means "not measured" (mock mode, an older
-- Ollama without logprobs, or reverse translation disabled) — never 0.
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS mean_logprob DOUBLE PRECISION;
ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS reverse_translation_fidelity DOUBLE PRECISION;
