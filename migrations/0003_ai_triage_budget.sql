-- AgentShield AI — AI triage budget v3 (local only; NO model binding).
-- Migrate after 0001/0002. Quotas are CLOSED until a trusted operator
-- provisions an explicit tenant/day ceiling. No automatic billing approval.
CREATE TABLE IF NOT EXISTS ai_triage_daily_budget (
  tenant_id TEXT NOT NULL,
  utc_day TEXT NOT NULL,
  max_requests INTEGER NOT NULL CHECK(max_requests BETWEEN 1 AND 10000),
  max_reserved_tokens INTEGER NOT NULL CHECK(max_reserved_tokens BETWEEN 1 AND 100000000),
  used_requests INTEGER NOT NULL DEFAULT 0 CHECK(used_requests >= 0),
  reserved_tokens INTEGER NOT NULL DEFAULT 0 CHECK(reserved_tokens >= 0),
  PRIMARY KEY (tenant_id, utc_day)
);

CREATE TABLE IF NOT EXISTS ai_triage_reservations (
  tenant_id TEXT NOT NULL,
  utc_day TEXT NOT NULL,
  request_id TEXT NOT NULL,
  reserved_input_tokens INTEGER NOT NULL CHECK(reserved_input_tokens BETWEEN 1 AND 4096),
  reserved_output_tokens INTEGER NOT NULL CHECK(reserved_output_tokens BETWEEN 1 AND 256),
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, utc_day, request_id)
);
CREATE INDEX IF NOT EXISTS idx_ai_triage_reservations_day
  ON ai_triage_reservations (tenant_id, utc_day);

-- Atomic budget checks + increments in one SQLite/D1 transaction, even when
-- independent Cloudflare Worker instances insert concurrently.
CREATE TRIGGER IF NOT EXISTS triage_budget_guard
BEFORE INSERT ON ai_triage_reservations
BEGIN
  SELECT RAISE(ABORT, 'triage_budget_missing_or_exhausted')
  WHERE NOT EXISTS (
    SELECT 1 FROM ai_triage_daily_budget
    WHERE tenant_id=NEW.tenant_id AND utc_day=NEW.utc_day
      AND used_requests < max_requests
      AND reserved_tokens + NEW.reserved_input_tokens + NEW.reserved_output_tokens
          <= max_reserved_tokens
  );
END;

CREATE TRIGGER IF NOT EXISTS triage_budget_increment
AFTER INSERT ON ai_triage_reservations
BEGIN
  UPDATE ai_triage_daily_budget
  SET used_requests = used_requests + 1,
      reserved_tokens = reserved_tokens + NEW.reserved_input_tokens + NEW.reserved_output_tokens
  WHERE tenant_id=NEW.tenant_id AND utc_day=NEW.utc_day;
END;

INSERT OR IGNORE INTO schema_migrations (version, applied_at_ms) VALUES (3, 0);
