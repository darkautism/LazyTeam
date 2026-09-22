-- Interactive MCP work leases reuse the existing execution/review ownership
-- foreign keys through hidden internal actors. No second lease-authority table
-- is introduced: executions/reviews remain the single source of truth.
ALTER TABLE workers ADD COLUMN internal_actor INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_workers_internal_actor ON workers(internal_actor, retired_at);

-- A task may have at most one authoritative live review lease. The service
-- still uses a transactional claim predicate; this partial unique index is the
-- final database-level race guard.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_one_active_per_task
ON reviews(task_id) WHERE state IN ('assigned','running');
