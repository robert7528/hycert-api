-- hycert 部署歷史 + ACME 帳戶/訂單 — 存放於 tenant DB

-- ── 部署歷史 ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hycert_deployment_history (
    id              BIGSERIAL PRIMARY KEY,
    deployment_id   BIGINT NOT NULL,
    certificate_id  BIGINT NOT NULL,
    agent_token_id  BIGINT,
    fingerprint     VARCHAR(255),
    action          VARCHAR(20) NOT NULL,        -- deploy / rollback / verify
    status          VARCHAR(20) NOT NULL,        -- success / failed
    error_message   TEXT,
    duration_ms     INT,
    deployed_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hycert_dh_deploy ON hycert_deployment_history (deployment_id);
CREATE INDEX IF NOT EXISTS idx_hycert_dh_time ON hycert_deployment_history (deployed_at);

-- ── 擴展 deployments 表 ──────────────────────────────────────────────────────
ALTER TABLE hycert_deployments
    ADD COLUMN IF NOT EXISTS last_fingerprint VARCHAR(255),
    ADD COLUMN IF NOT EXISTS last_deployed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS agent_token_id   BIGINT,
    ADD COLUMN IF NOT EXISTS deploy_status    VARCHAR(20) DEFAULT 'pending';

-- deploy_status: pending / deploying / deployed / failed
-- 與現有 status (active/removed) 區分：status 是邏輯生命週期，deploy_status 是部署狀態

CREATE INDEX IF NOT EXISTS idx_hycert_deploy_host
ON hycert_deployments (target_host) WHERE deleted_at IS NULL;

-- ── ACME 帳戶 ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hycert_acme_accounts (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    directory_url   VARCHAR(500) NOT NULL,
    private_key_enc TEXT NOT NULL,               -- Tink 加密的 ACME 帳戶私鑰
    registration    JSONB,                       -- ACME 註冊資源 JSON
    status          VARCHAR(20) DEFAULT 'active',
    created_by      VARCHAR(255),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_acme_acct_del ON hycert_acme_accounts (deleted_at);

-- ── ACME 訂單 ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hycert_acme_orders (
    id                  BIGSERIAL PRIMARY KEY,
    account_id          BIGINT NOT NULL,
    certificate_id      BIGINT,                  -- 完成後關聯到 hycert_certificates
    domains             JSONB NOT NULL,           -- ["example.com", "*.example.com"]
    challenge_type      VARCHAR(20) NOT NULL,     -- dns-01 / http-01
    dns_provider        VARCHAR(50),              -- cloudflare / route53 / manual
    dns_config_enc      TEXT,                     -- Tink 加密的 DNS provider credentials
    key_type            VARCHAR(20) DEFAULT 'ec256',
    status              VARCHAR(20) DEFAULT 'pending',
    error_message       TEXT,
    order_url           VARCHAR(500),
    renew_from_id       BIGINT,                  -- 上一張憑證 ID（續約追蹤）
    auto_renew          BOOLEAN DEFAULT true,
    renew_before_days   INT DEFAULT 30,
    last_renewed_at     TIMESTAMPTZ,
    requested_by        VARCHAR(255),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_acme_ord_acct ON hycert_acme_orders (account_id);
CREATE INDEX IF NOT EXISTS idx_hycert_acme_ord_cert ON hycert_acme_orders (certificate_id);
CREATE INDEX IF NOT EXISTS idx_hycert_acme_ord_status ON hycert_acme_orders (status);
CREATE INDEX IF NOT EXISTS idx_hycert_acme_ord_del ON hycert_acme_orders (deleted_at);
