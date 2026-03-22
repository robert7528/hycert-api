-- Fix: token_prefix VARCHAR(10) too short for "hycert_agt_" + 8 hex = 19 chars
ALTER TABLE hycert_agent_tokens ALTER COLUMN token_prefix TYPE VARCHAR(20);
