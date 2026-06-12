-- ACME order 續約重試支援
-- retry_count: 續約失敗累計次數（達上限後停止自動重試，改由 dashboard 提示人工處理）
-- last_attempt_at: 最近一次續約嘗試時間（用於 backoff 計算）

ALTER TABLE hycert_acme_orders
    ADD COLUMN IF NOT EXISTS retry_count     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;
