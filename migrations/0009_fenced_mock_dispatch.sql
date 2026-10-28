-- Local-only one-shot synthetic dispatch reservation, NOT external execution.
-- Original outbox state machine remains queued -> claimed -> uncertain.
CREATE UNIQUE INDEX IF NOT EXISTS idx_local_outbox_tenant_command
 ON local_command_outbox(tenant_id,command_id);
CREATE TABLE IF NOT EXISTS local_mock_dispatch_reservations (
  tenant_id TEXT NOT NULL,
  command_id TEXT NOT NULL,
  dispatch_id TEXT NOT NULL UNIQUE,
  request_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  claim_audit_event_id TEXT NOT NULL,
  dispatch_audit_event_id TEXT NOT NULL UNIQUE,
  decision_sha256 TEXT NOT NULL CHECK(length(decision_sha256)=64),
  reserved_at_ms INTEGER NOT NULL CHECK(reserved_at_ms>0),
  PRIMARY KEY(tenant_id,command_id),
  FOREIGN KEY(tenant_id,request_id)
    REFERENCES decision_requests(tenant_id,request_id),
  FOREIGN KEY(tenant_id,command_id)
    REFERENCES local_command_outbox(tenant_id,command_id)
);
CREATE TRIGGER IF NOT EXISTS local_dispatch_immutable_update
 BEFORE UPDATE ON local_mock_dispatch_reservations
 BEGIN SELECT RAISE(ABORT,'mock dispatch reservation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS local_dispatch_immutable_delete
 BEFORE DELETE ON local_mock_dispatch_reservations
 BEGIN SELECT RAISE(ABORT,'mock dispatch reservation cannot be deleted'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES(9,0);
