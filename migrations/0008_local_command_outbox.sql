-- P0 LOCAL command outbox only. NO real external tool invocation.
-- Every queued command refers to an existing immutable, audit-backed ALLOW
-- decision. A claimed command is NEVER auto-replayed after a crash.
CREATE TABLE IF NOT EXISTS local_command_outbox (
  tenant_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  command_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL,
  decision_event_id TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL CHECK(length(policy_sha256)=64),
  active_at_ms INTEGER NOT NULL,
  active_marker TEXT NOT NULL,
  action_digest TEXT NOT NULL CHECK(length(action_digest)=64),
  state TEXT NOT NULL CHECK(state IN ('queued','claimed','uncertain')),
  claim_token TEXT,
  created_at_ms INTEGER NOT NULL CHECK(created_at_ms>0),
  claimed_at_ms INTEGER,
  updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>0),
  PRIMARY KEY(tenant_id,request_id),
  FOREIGN KEY(tenant_id,request_id) REFERENCES decision_requests(tenant_id,request_id),
  CHECK (
    (state='queued' AND claim_token IS NULL AND claimed_at_ms IS NULL)
    OR
    (state IN ('claimed','uncertain') AND claim_token IS NOT NULL
      AND claimed_at_ms IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS idx_local_command_state
 ON local_command_outbox(tenant_id,state,created_at_ms);
-- Do not allow deletion or alteration of identity/decision binding after queueing.
CREATE TRIGGER IF NOT EXISTS local_outbox_no_delete
 BEFORE DELETE ON local_command_outbox
 BEGIN SELECT RAISE(ABORT,'outbox record may not be deleted'); END;
CREATE TRIGGER IF NOT EXISTS local_outbox_binding_immutable
 BEFORE UPDATE ON local_command_outbox
 WHEN NEW.tenant_id!=OLD.tenant_id
 OR NEW.request_id!=OLD.request_id
 OR NEW.command_id!=OLD.command_id
 OR NEW.principal_id!=OLD.principal_id
 OR NEW.decision_event_id!=OLD.decision_event_id
 OR NEW.policy_version!=OLD.policy_version
 OR NEW.policy_sha256!=OLD.policy_sha256
 OR NEW.active_at_ms!=OLD.active_at_ms
 OR NEW.active_marker!=OLD.active_marker
 OR NEW.action_digest!=OLD.action_digest
 OR NEW.created_at_ms!=OLD.created_at_ms
 BEGIN SELECT RAISE(ABORT,'outbox authorization binding immutable'); END;
CREATE TRIGGER IF NOT EXISTS local_outbox_forward_only
 BEFORE UPDATE ON local_command_outbox
 WHEN NOT (
   (OLD.state='queued' AND NEW.state='claimed'
     AND NEW.claim_token IS NOT NULL AND NEW.claimed_at_ms IS NOT NULL)
   OR
   (OLD.state='claimed' AND NEW.state='uncertain'
     AND NEW.claim_token=OLD.claim_token AND NEW.claimed_at_ms=OLD.claimed_at_ms)
 )
 BEGIN SELECT RAISE(ABORT,'unsafe outbox state transition'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES(8,0);
