-- Interactive MCP work leases reuse the existing execution/review ownership
-- foreign keys through hidden internal actors. No second lease-authority table
-- is introduced: executions/reviews remain the single source of truth.
ALTER TABLE workers ADD COLUMN internal_actor INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_workers_internal_actor ON workers(internal_actor, retired_at);

-- Heal any duplicate active review leases left by the pre-CAS implementation
-- before adding the invariant. Keep the newest row authoritative and cancel
-- older duplicates without counting them as reviewer failure/retry.
UPDATE reviews
SET state='cancelled', lease_capability_hash=NULL, finished_at=COALESCE(finished_at, created_at)
WHERE state IN ('assigned','running')
  AND EXISTS (
    SELECT 1 FROM reviews newer
    WHERE newer.task_id=reviews.task_id
      AND newer.state IN ('assigned','running')
      AND (newer.created_at > reviews.created_at
           OR (newer.created_at = reviews.created_at AND newer.id > reviews.id))
  );

-- Reconcile slot accounting after cancelling duplicate legacy leases. Slots
-- are derived solely from active execution/review ownership.
UPDATE workers
SET running_slots =
    (SELECT COUNT(*) FROM executions e WHERE e.worker_id=workers.id AND e.state IN ('assigned','running')) +
    (SELECT COUNT(*) FROM reviews r WHERE r.reviewer_worker_id=workers.id AND r.state IN ('assigned','running')),
    state = CASE
      WHEN state IN ('pending','draining','degraded') THEN state
      WHEN ((SELECT COUNT(*) FROM executions e WHERE e.worker_id=workers.id AND e.state IN ('assigned','running')) +
            (SELECT COUNT(*) FROM reviews r WHERE r.reviewer_worker_id=workers.id AND r.state IN ('assigned','running'))) > 0 THEN 'busy'
      ELSE 'idle'
    END;

-- A task may have at most one authoritative live review lease. The service
-- still uses a transactional claim predicate; this partial unique index is the
-- final database-level race guard.
CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_one_active_per_task
ON reviews(task_id) WHERE state IN ('assigned','running');
