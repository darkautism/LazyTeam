-- Immutable per-attempt backend snapshots for Host Insights breakdowns.
--
-- Worker provider/model/backend selections live on the mutable workers table
-- and can change at any time, so joining historical execution/review rows to
-- current worker metadata would rewrite history. Snapshot the values in effect
-- at claim time on each durable attempt row instead. Rows written before this
-- migration keep NULL (rendered as "unrecorded") so denominators stay honest.
ALTER TABLE executions ADD COLUMN worker_agent_type TEXT;
ALTER TABLE executions ADD COLUMN worker_provider TEXT;
ALTER TABLE executions ADD COLUMN worker_model TEXT;
ALTER TABLE reviews ADD COLUMN reviewer_agent_type TEXT;
ALTER TABLE reviews ADD COLUMN reviewer_provider TEXT;
ALTER TABLE reviews ADD COLUMN reviewer_model TEXT;
