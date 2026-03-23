-- Agent registrations (tenant DB)
CREATE TABLE IF NOT EXISTS hycert_agent_registrations (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        VARCHAR(36) NOT NULL UNIQUE,
    agent_token_id  BIGINT NOT NULL,
    name            VARCHAR(255) NOT NULL DEFAULT '',
    hostname        VARCHAR(255) NOT NULL DEFAULT '',
    ip_addresses    JSONB DEFAULT '[]',
    os              VARCHAR(50) DEFAULT '',
    version         VARCHAR(50) DEFAULT '',
    poll_interval   INT DEFAULT 3600,
    status          VARCHAR(20) DEFAULT 'active',
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_agent_reg_token ON hycert_agent_registrations (agent_token_id);
CREATE INDEX IF NOT EXISTS idx_hycert_agent_reg_status ON hycert_agent_registrations (status) WHERE deleted_at IS NULL;

-- Add agent_id column to deployments
ALTER TABLE hycert_deployments ADD COLUMN IF NOT EXISTS agent_id VARCHAR(36);
CREATE INDEX IF NOT EXISTS idx_hycert_deploy_agent_id ON hycert_deployments (agent_id) WHERE deleted_at IS NULL;
