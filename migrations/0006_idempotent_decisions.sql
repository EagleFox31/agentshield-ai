-- P0 local decision idempotency. Apply only by reviewed migration scripts.
-- A unique (tenant, request_id) binds one signed principal, scoped request,
-- active-policy generation and redacted audit event, including after retry.
CREATE TABLE IF NOT EXISTS decision_requests (
  tenant_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
  policy_version TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256) = 64),
  active_at_ms INTEGER NOT NULL CHECK(active_at_ms > 0),
  active_marker TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  effect TEXT NOT NULL CHECK(effect IN ('allow','deny','require_approval')),
  reason_codes_json TEXT NOT NULL,
  matched_rule_ids_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms > 0),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms),
  PRIMARY KEY(tenant_id, request_id),
  FOREIGN KEY(tenant_id,policy_version) REFERENCES policy_versions(tenant_id,version)
);
CREATE INDEX IF NOT EXISTS idx_decision_tenant_created
 ON decision_requests(tenant_id,created_at_ms);
CREATE TRIGGER IF NOT EXISTS immutable_decision_request_update
 BEFORE UPDATE ON decision_requests
 BEGIN SELECT RAISE(ABORT,'decision receipt immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_decision_request_delete
 BEFORE DELETE ON decision_requests
 BEGIN SELECT RAISE(ABORT,'decision receipt immutable'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES(6,0);
