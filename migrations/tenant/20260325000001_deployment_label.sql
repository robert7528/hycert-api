-- Add label to deployments for token-based grouping
ALTER TABLE hycert_deployments ADD COLUMN IF NOT EXISTS label VARCHAR(100) NOT NULL DEFAULT '';
