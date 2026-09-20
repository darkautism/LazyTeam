-- Pin the upstream/integrated snapshot that each review actually saw.
-- This extends existing review/gate entities; no separate integration/conflict table.
ALTER TABLE reviews ADD COLUMN upstream_sha TEXT;
ALTER TABLE reviews ADD COLUMN integration_sha TEXT;
ALTER TABLE reviews ADD COLUMN effective_diff_hash TEXT;

-- Structured merge-conflict evidence belongs to the existing main-gate history row.
ALTER TABLE main_gate_events ADD COLUMN evidence TEXT;
