"""SQLite audit security contract: immutable events, fail-closed and nonce replay."""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import unittest
from pathlib import Path

from agentshield.audit import AuditConflict, AuditEvent, AuditStorageError, action_digest
from agentshield.audit_service import decide_and_audit
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.policy import Effect, PolicyEngine, Principal, Rule, ToolAction

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "migrations/0001_audit_core.sql").read_text(encoding="utf-8")


def run(coro):
    return asyncio.run(coro)


def sample(*, event_id="audit-event-0001", tenant="tenant_a", effect="deny"):
    return AuditEvent(
        event_id=event_id, tenant_id=tenant, principal_id=tenant + ":agent-01",
        action_digest=action_digest("suppliers", "update_bank_account", "supplier/482"),
        effect=effect, reason_codes=("NO_MATCHING_POLICY",),
        policy_version="baseline-v1", occurred_at_ms=1_790_000_000_000,
        retention_until_ms=1_790_000_000_000 + 30 * 86_400_000,
    )


class AuditSQLiteTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(SQL)
        self.repo = SQLiteAuditRepository(self.db)

    def tearDown(self):
        self.db.close()

    def test_migration_can_be_reapplied_and_schema_is_versioned(self):
        self.db.executescript(SQL)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0], 1)
        tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"audit_events", "policy_versions", "approval_requests", "approval_decisions",
                         "used_action_nonces", "evidence_batches"}.issubset(tables))

    def test_event_retry_is_idempotent_and_event_is_tenant_scoped(self):
        event = sample()
        self.assertTrue(run(self.repo.record_event(event)))
        self.assertFalse(run(self.repo.record_event(event)))
        self.assertEqual(run(self.repo.get_event("tenant_a", event.event_id)), event)
        self.assertIsNone(run(self.repo.get_event("tenant_b", event.event_id)))
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 1,
        )

    def test_collision_fails_closed_even_across_tenants(self):
        event = sample()
        run(self.repo.record_event(event))
        with self.assertRaises(AuditConflict):
            run(self.repo.record_event(sample(effect="allow")))
        with self.assertRaises(AuditConflict):
            run(self.repo.record_event(sample(tenant="tenant_b")))
        self.assertEqual(run(self.repo.get_event("tenant_a", event.event_id)), event)

    def test_modified_record_is_detected_on_read(self):
        event = sample()
        run(self.repo.record_event(event))
        self.db.execute(
            "UPDATE audit_events SET effect='allow' WHERE event_id=?", (event.event_id,)
        )
        self.db.commit()
        with self.assertRaises(AuditStorageError):
            run(self.repo.get_event("tenant_a", event.event_id))

    def test_repeated_nonce_is_single_use_and_tenant_scoped(self):
        ts = 1_790_000_000_000
        self.assertTrue(run(self.repo.consume_nonce("tenant_a", "nonce_identifier_1", ts, ts + 60_000)))
        self.assertFalse(run(self.repo.consume_nonce("tenant_a", "nonce_identifier_1", ts, ts + 60_000)))
        self.assertTrue(run(self.repo.consume_nonce("tenant_b", "nonce_identifier_1", ts, ts + 60_000)))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM used_action_nonces").fetchone()[0], 2)

    def test_nonce_race_across_independent_connections(self):
        ts = 1_790_000_000_000
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.sqlite"
            first = sqlite3.connect(path)
            first.executescript(SQL)
            first.close()
            winners = []
            for _ in range(2):
                conn = sqlite3.connect(path)
                winners.append(run(SQLiteAuditRepository(conn).consume_nonce(
                    "tenant_a", "simultaneous_nonce", ts, ts + 60_000,
                )))
                conn.close()
            self.assertEqual(winners, [True, False])

    def test_concurrent_nonce_claims_one_winner_across_connections(self):
        ts = 1_790_000_000_000
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "shared-audit.sqlite"
            setup = sqlite3.connect(path)
            setup.executescript(SQL)
            setup.close()
            n = 6
            ready = Barrier(n)

            def claim(_):
                connection = sqlite3.connect(path, timeout=5)
                try:
                    ready.wait(timeout=5)
                    return run(SQLiteAuditRepository(connection).consume_nonce(
                        "tenant_a", "concurrent_shared_nonce", ts, ts + 60_000,
                    ))
                finally:
                    connection.close()

            with ThreadPoolExecutor(max_workers=n) as pool:
                results = list(pool.map(claim, range(n)))
            self.assertEqual(results.count(True), 1)
            self.assertEqual(results.count(False), n - 1)

    def test_write_failure_never_returns_allow(self):
        class BrokenRepository:
            async def record_event(self, event):
                raise AuditStorageError("Simulated D1 outage")
        engine = PolicyEngine([Rule(
            id="allow-invoice-read", principal_id="tenant_a:agent-01",
            tool="invoices", operation="read", resource="invoice/42",
            required_scope="invoice:read", effect=Effect.ALLOW,
        )])
        with self.assertRaises(AuditStorageError):
            run(decide_and_audit(
                engine, BrokenRepository(), Principal("tenant_a:agent-01", frozenset({"invoice:read"})),
                "tenant_a", ToolAction("invoices", "read", "invoice/42"),
                event_id="audit-event-0002", policy_version="baseline-v1",
                occurred_at_ms=1_790_000_000_000,
            ))
        result = run(decide_and_audit(
            engine, self.repo, Principal("tenant_a:agent-01", frozenset({"invoice:read"})),
            "tenant_a", ToolAction("invoices", "read", "invoice/42"),
            event_id="audit-event-0002", policy_version="baseline-v1",
            occurred_at_ms=1_790_000_000_000,
        ))
        self.assertEqual(result.effect, Effect.ALLOW)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 1)

    def test_untrusted_cross_tenant_principal_cannot_persist_decision(self):
        engine = PolicyEngine([])
        with self.assertRaises(ValueError):
            run(decide_and_audit(
                engine, self.repo, Principal("tenant_b:agent-01", frozenset({"invoice:read"})),
                "tenant_a", ToolAction("invoices", "read", "invoice/42"),
                event_id="audit-event-0002", policy_version="baseline-v1",
                occurred_at_ms=1_790_000_000_000,
            ))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)

    def test_only_redacted_known_fields_are_persisted(self):
        event = sample()
        run(self.repo.record_event(event))
        dump = "\n".join(self.db.iterdump()).lower()
        self.assertNotIn("supplier/482", dump)
        self.assertNotIn("update_bank_account", dump)
        self.assertNotIn("secret", dump)
        self.assertIn(event.fingerprint, dump)
        self.assertEqual(len(event.action_digest), 64)

    def test_reject_unsafe_event_or_nonce_inputs(self):
        with self.assertRaises(ValueError):
            sample(effect="admin")
        for bad in ("", "short", "../other", "abc 123456", "x" * 150):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                run(self.repo.consume_nonce("tenant_a", bad, 1_790_000_000_000, 1_790_000_060_000))


    def test_approval_is_bound_to_tenant_digest_expiry_and_single_use(self):
        digest = sample().action_digest
        self.db.execute(
            "INSERT INTO approval_requests "
            "(approval_id,tenant_id,principal_id,action_digest,policy_version,state,expires_at_ms,created_at_ms) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("approval_fixture_0001", "tenant_a", "tenant_a:agent-01", digest,
             "baseline-v1", "approved", 1_790_000_060_000, 1_790_000_000_000),
        )
        self.db.commit()
        consume = lambda tenant, d, at: run(self.repo.consume_approved_request(
            tenant, "approval_fixture_0001", d, at,
        ))
        self.assertFalse(consume("tenant_b", digest, 1_790_000_010_000))
        self.assertFalse(consume("tenant_a", "0" * 64, 1_790_000_010_000))
        self.assertTrue(consume("tenant_a", digest, 1_790_000_010_000))
        self.assertFalse(consume("tenant_a", digest, 1_790_000_010_000))

    def test_expired_approval_is_not_consumable(self):
        digest = sample().action_digest
        self.db.execute(
            "INSERT INTO approval_requests "
            "(approval_id,tenant_id,principal_id,action_digest,policy_version,state,expires_at_ms,created_at_ms) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("approval_expired_001", "tenant_a", "tenant_a:agent-01", digest,
             "baseline-v1", "approved", 1_790_000_010_000, 1_790_000_000_000),
        )
        self.db.commit()
        self.assertFalse(run(self.repo.consume_approved_request(
            "tenant_a", "approval_expired_001", digest, 1_790_000_010_000,
        )))


if __name__ == "__main__":
    unittest.main()
