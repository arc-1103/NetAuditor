-- Ingestion dedups by file_hash with a check-then-insert (services/ingestion/app/main.py);
-- two concurrent uploads of the same bytes could both pass the check and create two
-- audit runs. The unique index makes the database the arbiter: the loser's
-- INSERT ... ON CONFLICT DO NOTHING inserts nothing and it reopens the winner's run.
-- Fails if duplicate hashes already exist — merge or delete the extra runs first.
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_runs_file_hash ON audit_runs (file_hash);
