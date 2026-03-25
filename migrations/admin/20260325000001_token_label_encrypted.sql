-- Add label and encrypted token to agent tokens
ALTER TABLE hycert_agent_tokens ADD COLUMN IF NOT EXISTS label VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE hycert_agent_tokens ADD COLUMN IF NOT EXISTS token_encrypted TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_hycert_agt_label ON hycert_agent_tokens (label) WHERE deleted_at IS NULL AND status = 'active';
