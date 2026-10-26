"""D1 compatibility contract through a SQLite-backed prepared-statement stub.

The *real* D1 Worker binding is exercised separately by pywrangler dev CI.
"""
import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.audit import AuditConflict, AuditStorageError
from agentshield.audit_d1 import D1AuditRepository
from test_audit_sqlite import SQL, sample


class Statement:
    def __init__(self, connection, sql, params=()):
        self.connection, self.sql, self.params = connection, sql, params

    def bind(self, *values):
        return Statement(self.connection, self.sql, values)

    async def first(self):
        row = self.connection.execute(self.sql, self.params).fetchone()
        self.connection.commit()
        return dict(row) if row is not None else None


class Binding:
    def __init__(self, connection):
        self.connection = connection

    def prepare(self, sql):
        return Statement(self.connection, sql)


def run(coro):
    return asyncio.run(coro)


class D1ContractTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SQL)
        self.repo = D1AuditRepository(Binding(self.connection))

    def tearDown(self):
        self.connection.close()

    def test_portable_record_retry_and_tenant_isolation(self):
        event = sample()
        self.assertTrue(run(self.repo.record_event(event)))
        self.assertFalse(run(self.repo.record_event(event)))
        self.assertEqual(run(self.repo.get_event("tenant_a", event.event_id)), event)
        self.assertIsNone(run(self.repo.get_event("tenant_other", event.event_id)))

    def test_collision_and_nonce_uniqueness(self):
        run(self.repo.record_event(sample()))
        with self.assertRaises(AuditConflict):
            run(self.repo.record_event(sample(effect="allow")))
        ts = 1_790_000_000_000
        self.assertTrue(run(self.repo.consume_nonce("tenant_a", "d1_nonce_identifier", ts, ts + 60_000)))
        self.assertFalse(run(self.repo.consume_nonce("tenant_a", "d1_nonce_identifier", ts, ts + 60_000)))

    def test_d1_failure_does_not_return_success(self):
        class Unavailable:
            def prepare(self, sql):
                raise RuntimeError("INTERNAL-D1-SECRET")
        repo = D1AuditRepository(Unavailable())
        with self.assertRaises(AuditStorageError) as context:
            run(repo.record_event(sample()))
        self.assertNotIn("INTERNAL-D1-SECRET", str(context.exception))

    def test_corrupted_d1_result_refuses_event(self):
        class BadBinding:
            def prepare(self, sql):
                class Broken:
                    def bind(self, *values):
                        return self

                    async def first(self):
                        return "not a D1 row"
                return Broken()
        with self.assertRaises(AuditStorageError):
            run(D1AuditRepository(BadBinding()).record_event(sample()))


    def test_d1_approval_consumption_uses_single_conditional_update(self):
        digest = sample().action_digest
        self.connection.execute(
            "INSERT INTO approval_requests "
            "(approval_id,tenant_id,principal_id,action_digest,policy_version,state,expires_at_ms,created_at_ms) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("approval_d1_fixture", "tenant_a", "tenant_a:agent-01", digest,
             "baseline-v1", "approved", 1_790_000_060_000, 1_790_000_000_000),
        )
        self.connection.commit()
        self.assertFalse(run(self.repo.consume_approved_request(
            "tenant_b", "approval_d1_fixture", digest, 1_790_000_010_000,
        )))
        self.assertTrue(run(self.repo.consume_approved_request(
            "tenant_a", "approval_d1_fixture", digest, 1_790_000_010_000,
        )))
        self.assertFalse(run(self.repo.consume_approved_request(
            "tenant_a", "approval_d1_fixture", digest, 1_790_000_010_000,
        )))


if __name__ == "__main__":
    unittest.main()
