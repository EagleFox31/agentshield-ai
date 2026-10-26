-- AgentShield AI audit schema v1. Portable SQLite/D1. No raw prompts or tool args.
-- Apply deliberately via local migration tooling; NEVER on an incoming request.
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at_ms INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_migrations (version, applied_at_ms) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS policy_versions (
  tenant_id TEXT NOT NULL,
  version TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS audit_events (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  action_digest TEXT NOT NULL CHECK(length(action_digest) = 64),
  effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny', 'require_approval')),
  reason_codes_json TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  occurred_at_ms INTEGER NOT NULL,
  retention_until_ms INTEGER NOT NULL,
  event_sha256 TEXT NOT NULL CHECK(length(event_sha256) = 64)
);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_time
  ON audit_events (tenant_id, occurred_at_ms, event_id);

CREATE TABLE IF NOT EXISTS approval_requests (
  approval_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  action_digest TEXT NOT NULL CHECK(length(action_digest) = 64),
  policy_version TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK(state IN ('pending', 'approved', 'rejected', 'consumed', 'expired')),
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  consumed_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS idx_approval_tenant_state
  ON approval_requests (tenant_id, state, expires_at_ms);

CREATE TABLE IF NOT EXISTS approval_decisions (
  decision_id TEXT PRIMARY KEY,
  approval_id TEXT NOT NULL REFERENCES approval_requests(approval_id),
  tenant_id TEXT NOT NULL,
  approver_id TEXT NOT NULL,
  decision TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
  decided_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS used_action_nonces (
  tenant_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  used_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, nonce)
);

CREATE TABLE IF NOT EXISTS evidence_batches (
  batch_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  root_sha256 TEXT NOT NULL CHECK(length(root_sha256) = 64),
  manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64),
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_batches_tenant
  ON evidence_batches (tenant_id, created_at_ms);
