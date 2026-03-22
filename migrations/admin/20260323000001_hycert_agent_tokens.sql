-- hycert Agent Token — 存放於 admin DB（認證時先查 token 取 tenant_code）

CREATE TABLE IF NOT EXISTS hycert_agent_tokens (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    token_hash      VARCHAR(255) NOT NULL UNIQUE,
    token_prefix    VARCHAR(20) NOT NULL,        -- "hycert_agt_" + 前 8 hex，用於 UI 識別
    tenant_code     VARCHAR(100) NOT NULL,
    allowed_hosts   JSONB DEFAULT '[]',          -- 限制主機名，空 = 不限
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,                 -- null = 不過期
    status          VARCHAR(20) DEFAULT 'active',
    created_by      VARCHAR(255),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_agt_hash ON hycert_agent_tokens (token_hash) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_hycert_agt_tenant ON hycert_agent_tokens (tenant_code);
