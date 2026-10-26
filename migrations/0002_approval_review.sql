-- Local-only human approval workflow schema v2; apply AFTER 0001.
-- No tool arguments or bank-account values are stored.
ALTER TABLE approval_requests ADD COLUMN decision_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_request_decision_id
  ON approval_requests (decision_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_decisions_once
  ON approval_decisions (approval_id);
INSERT OR IGNORE INTO schema_migrations (version, applied_at_ms) VALUES (2, 0);
