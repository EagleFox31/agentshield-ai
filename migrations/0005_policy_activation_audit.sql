-- P0 local-only: atomic compare-and-swap policy activation and durable evidence.
-- After 0004. Never run as part of an untrusted incoming HTTP request.
ALTER TABLE active_policy_versions ADD COLUMN activation_marker TEXT;
CREATE TABLE IF NOT EXISTS policy_activation_history (
  activation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  previous_version TEXT NOT NULL,
  new_version TEXT NOT NULL,
  new_sha256 TEXT NOT NULL CHECK(length(new_sha256) = 64),
  operator_id TEXT NOT NULL,
  activated_at_ms INTEGER NOT NULL CHECK(activated_at_ms > 0),
  audit_event_id TEXT NOT NULL UNIQUE,
  FOREIGN KEY(tenant_id, new_version)
    REFERENCES policy_versions(tenant_id, version)
);
CREATE INDEX IF NOT EXISTS idx_policy_activation_tenant_time
 ON policy_activation_history(tenant_id, activated_at_ms, activation_id);
CREATE TRIGGER IF NOT EXISTS immutable_activation_history_update
 BEFORE UPDATE ON policy_activation_history
 BEGIN SELECT RAISE(ABORT, 'activation history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_activation_history_delete
 BEFORE DELETE ON policy_activation_history
 BEGIN SELECT RAISE(ABORT, 'activation history is immutable'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES(5,0);
