ALTER TABLE workers ADD COLUMN agent_type TEXT NOT NULL DEFAULT 'pi';
ALTER TABLE workers ADD COLUMN agent_provider TEXT;
ALTER TABLE workers ADD COLUMN agent_model TEXT;
ALTER TABLE workers ADD COLUMN initial_prompt TEXT NOT NULL DEFAULT '';
ALTER TABLE workers ADD COLUMN agent_capabilities TEXT NOT NULL DEFAULT '{}';
