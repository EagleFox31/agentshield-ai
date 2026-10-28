-- Extend existing policy_versions; no duplicate PolicyEngine or policy registry.
-- Apply after 0001..0003, LOCAL D1 only. Never migrate on HTTP requests.
ALTER TABLE policy_versions ADD COLUMN rules_json TEXT;
CREATE TABLE IF NOT EXISTS active_policy_versions (
  tenant_id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  activated_at_ms INTEGER NOT NULL CHECK (activated_at_ms > 0),
  FOREIGN KEY (tenant_id, version) REFERENCES policy_versions (tenant_id, version)
);
-- Published snapshots are immutable. Changing policy requires a new version,
-- offline-reviewed activation and an independent signed audit of the change.
CREATE TRIGGER IF NOT EXISTS immutable_policy_version_update
BEFORE UPDATE ON policy_versions
BEGIN SELECT RAISE(ABORT, 'published policy version is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_policy_version_delete
BEFORE DELETE ON policy_versions
BEGIN SELECT RAISE(ABORT, 'published policy version is immutable'); END;
INSERT OR IGNORE INTO schema_migrations(version,applied_at_ms) VALUES (4,0);
