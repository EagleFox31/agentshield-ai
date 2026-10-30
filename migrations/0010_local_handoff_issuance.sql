-- LOCAL host-issued handoff evidence only; NO public issuer or provider I/O.
-- Single handoff per tenant/command and irreversible database audit linkage.
-- The host-only P-256 key never enters a Cloudflare Worker.
CREATE TABLE IF NOT EXISTS local_handoff_issuances (
  tenant_id TEXT NOT NULL,
  command_id TEXT NOT NULL,
  issuance_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL,
  dispatch_id TEXT NOT NULL,
  dispatch_audit_event_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
  action_digest TEXT NOT NULL CHECK(length(action_digest)=64),
  jti_sha256 TEXT NOT NULL CHECK(length(jti_sha256)=64),
  token_sha256 TEXT NOT NULL CHECK(length(token_sha256)=64),
  issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>0),
  expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms=issued_at_ms+30000),
  audit_event_id TEXT NOT NULL UNIQUE,
  PRIMARY KEY (tenant_id,command_id),
  UNIQUE(tenant_id,jti_sha256),
  FOREIGN KEY (tenant_id,command_id)
    REFERENCES local_mock_dispatch_reservations(tenant_id,command_id)
);
CREATE TRIGGER IF NOT EXISTS local_handoff_issuance_no_delete
 BEFORE DELETE ON local_handoff_issuances
 BEGIN SELECT RAISE(ABORT,'handoff issuance cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS local_handoff_issuance_no_update
 BEFORE UPDATE ON local_handoff_issuances
 BEGIN SELECT RAISE(ABORT,'handoff issuance is immutable'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES(10,0);
