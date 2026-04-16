-- ACME 帳戶支援 EAB (External Account Binding)
-- 用於 Sectigo、ZeroSSL 等需要 EAB 的 CA

ALTER TABLE hycert_acme_accounts
    ADD COLUMN IF NOT EXISTS eab_kid          VARCHAR(255),
    ADD COLUMN IF NOT EXISTS eab_hmac_key_enc TEXT;
