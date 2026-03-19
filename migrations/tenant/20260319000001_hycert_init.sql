-- hycert 憑證管理模組 — 初始 schema
-- 存放於 tenant DB（與 hyadmin_* 同 DB，前綴 hycert_ 區分）

-- ── 憑證主表 ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hycert_certificates (
    id                  BIGSERIAL PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    common_name         VARCHAR(255) NOT NULL,
    sans                JSONB,
    serial_number       VARCHAR(255),
    issuer_cn           VARCHAR(255),
    not_before          TIMESTAMPTZ,
    not_after           TIMESTAMPTZ,
    key_algorithm       VARCHAR(50),
    fingerprint_sha256  VARCHAR(255),
    status              VARCHAR(20) DEFAULT 'active',
    source              VARCHAR(20) DEFAULT 'manual',
    cert_pem            TEXT NOT NULL,
    private_key_enc     TEXT,
    key_encrypted       BOOLEAN DEFAULT false,
    csr_id              BIGINT,
    tags                JSONB DEFAULT '[]',
    notes               TEXT,
    created_by          VARCHAR(255),
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_cert_not_after    ON hycert_certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_hycert_cert_status       ON hycert_certificates (status);
CREATE INDEX IF NOT EXISTS idx_hycert_cert_fingerprint  ON hycert_certificates (fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_hycert_cert_deleted_at   ON hycert_certificates (deleted_at);

-- ── CSR 記錄 ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hycert_csrs (
    id                  BIGSERIAL PRIMARY KEY,
    common_name         VARCHAR(255) NOT NULL,
    sans                JSONB,
    subject             JSONB,
    key_algorithm       VARCHAR(50),
    key_bits            INT,
    csr_pem             TEXT NOT NULL,
    private_key_enc     TEXT NOT NULL,
    status              VARCHAR(20) DEFAULT 'pending',
    certificate_id      BIGINT,
    created_by          VARCHAR(255),
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_csr_status     ON hycert_csrs (status);
CREATE INDEX IF NOT EXISTS idx_hycert_csr_deleted_at ON hycert_csrs (deleted_at);

-- ── 部署目標 ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hycert_deployments (
    id                  BIGSERIAL PRIMARY KEY,
    certificate_id      BIGINT NOT NULL,
    target_host         VARCHAR(255) NOT NULL,
    target_service      VARCHAR(100) NOT NULL,
    target_detail       TEXT,
    port                INT,
    status              VARCHAR(20) DEFAULT 'active',
    deployed_at         TIMESTAMPTZ,
    deployed_by         VARCHAR(255),
    notes               TEXT,
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ,
    deleted_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hycert_deploy_cert       ON hycert_deployments (certificate_id);
CREATE INDEX IF NOT EXISTS idx_hycert_deploy_deleted_at ON hycert_deployments (deleted_at);

-- 同一憑證不能重複部署到同一主機的同一服務（未刪除）
CREATE UNIQUE INDEX IF NOT EXISTS uk_hycert_deploy_cert_target
ON hycert_deployments (certificate_id, target_host, target_service)
WHERE deleted_at IS NULL;
