ALTER TABLE workers ADD COLUMN retired_at TEXT;

-- Protocol-v5 registrations cannot claim protocol-v6 work. Retire those stale
-- registrations on upgrade while retaining execution/review audit rows.
UPDATE workers
SET retired_at = COALESCE(retired_at, CURRENT_TIMESTAMP),
    credential_hash = NULL,
    running_slots = 0,
    state = 'draining'
WHERE protocol_version < 6;
