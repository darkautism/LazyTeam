ALTER TABLE workers ADD COLUMN managed_capabilities TEXT NOT NULL DEFAULT '[]';
ALTER TABLE workers ADD COLUMN installed_capabilities TEXT NOT NULL DEFAULT '[]';
ALTER TABLE workers ADD COLUMN capability_error TEXT;
