-- Review cycles separate current-cycle retries (which gate automatic
-- reviewer redispatch blocking) from durable lifetime history (which stays
-- observable forever). A manual re-publish/retry starts a fresh cycle by
-- bumping tasks.review_cycle; automatic reviewer retry redispatch stays in
-- the same cycle. Historical review rows are never deleted to fake a reset.
ALTER TABLE tasks ADD COLUMN review_cycle INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reviews ADD COLUMN review_cycle INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_reviews_task_cycle
ON reviews(task_id, review_cycle);
