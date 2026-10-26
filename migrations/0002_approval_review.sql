-- Local-only human approval workflow schema v2; apply AFTER 0001.
-- No tool arguments or bank-account values are stored.
ALTER TABLE approval_requests ADD COLUMN decision_id TEXT;
ALTER TABLE approval_requests ADD COLUMN consume_event_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_request_decision_id
  ON approval_requests (decision_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_decisions_once
  ON approval_decisions (approval_id);
-- Bind each review event to its specific request, not just shared action digest.
ALTER TABLE audit_events ADD COLUMN approval_id TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_approval_tenant
  ON audit_events (tenant_id, approval_id, occurred_at_ms);
INSERT OR IGNORE INTO schema_migrations (version, applied_at_ms) VALUES (2, 0);
