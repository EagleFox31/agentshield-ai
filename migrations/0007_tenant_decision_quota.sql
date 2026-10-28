-- P0 LOCAL bounded tenant decision admission. Applied after migration 0006.
-- One request ID consumes at most one slot, even when retried in later windows.
-- A slot and its decision receipt/audit are created in the same D1 batch.
CREATE TABLE IF NOT EXISTS tenant_decision_rate_slots (
  tenant_id TEXT NOT NULL,
  window_start_ms INTEGER NOT NULL CHECK(window_start_ms >= 0),
  request_id TEXT NOT NULL,
  admitted_at_ms INTEGER NOT NULL CHECK(admitted_at_ms > 0),
  PRIMARY KEY (tenant_id, request_id),
  CHECK (window_start_ms <= admitted_at_ms)
);
CREATE INDEX IF NOT EXISTS idx_tenant_decision_window
 ON tenant_decision_rate_slots(tenant_id,window_start_ms);
CREATE TRIGGER IF NOT EXISTS immutable_tenant_rate_slot_update
 BEFORE UPDATE ON tenant_decision_rate_slots
 BEGIN SELECT RAISE(ABORT,'tenant admission immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_tenant_rate_slot_delete
 BEFORE DELETE ON tenant_decision_rate_slots
 BEGIN SELECT RAISE(ABORT,'tenant admission immutable'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES(7,0);
