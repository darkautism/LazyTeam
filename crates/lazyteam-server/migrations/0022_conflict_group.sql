-- Optional operator-supplied conflict/concurrency group for coarse hotspots.
-- Metadata only: scheduler/claim behavior must ignore this column.
ALTER TABLE tasks ADD COLUMN conflict_group TEXT;
