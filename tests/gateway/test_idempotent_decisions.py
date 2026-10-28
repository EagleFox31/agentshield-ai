"""Offline idempotent receipt safety: retries, collision, policy drift, audit."""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.approvals import SQLiteApprovalStore
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.identity import VerifiedAgent
from agentshield.idempotent_decisions import decide_idempotently, DecisionReplayConflict
from agentshield.policy import Principal, ToolAction
from agentshield.policy_registry import SQLitePolicyRegistry
from scripts.seed_local_policy_registry import make_sql, reviewed_v2_sql

ROOT = Path(__file__).resolve().parents[2]
NOW = 1790000100000
KEY = "decision-retry-000001"
INVOICE = ToolAction("invoices", "read", "invoice/42")
SUPPLIER = ToolAction("suppliers", "update_bank_account", "supplier/482")


def run(coro):
    return asyncio.run(coro)


class IdempotentDecisionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for filename in ("0001_audit_core.sql", "0004_policy_snapshots.sql",
                         "0005_policy_activation_audit.sql",
                         "0006_idempotent_decisions.sql"):
            self.db.executescript((ROOT / "migrations" / filename).read_text())
        self.db.executescript(make_sql() + reviewed_v2_sql())
        self.store = SQLiteApprovalStore(self.db)
        self.audit = SQLiteAuditRepository(self.db)
        self.registry = SQLitePolicyRegistry(self.db)
        self.agent = self.identity()

    def tearDown(self):
        self.db.close()

    def identity(self, tenant="ci_local", subject="local-demo-agent",
                 scopes=("invoice:read",)):
        return VerifiedAgent(
            Principal(tenant + ":" + subject, frozenset(scopes)),
            tenant, subject, "signed-jti-00001", 1790000000, 1790000300,
        )

    def decide(self, action=INVOICE, *, key=KEY, agent=None, store=None,
               now=NOW, registry=None):
        return run(decide_idempotently(
            store or self.store, self.audit, registry or self.registry,
            agent or self.agent, action, request_id=key, now_ms=now,
        ))

    def counts(self):
        return (
            self.db.execute("SELECT COUNT(*) FROM decision_requests").fetchone()[0],
            self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
        )

    def test_exact_retries_have_one_receipt_and_one_audit(self):
        a = self.decide()
        b = self.decide()
        self.assertEqual(a.event_id, b.event_id)
        self.assertEqual(a.policy_version, b.policy_version)
        self.assertEqual(a.effect, "allow")
        self.assertFalse(a.replayed)
        self.assertTrue(b.replayed)
        self.assertEqual(self.counts(), (1, 1))
        self.assertEqual(self.db.execute(
            "SELECT event_id FROM audit_events").fetchone()[0], a.event_id)

    def test_changed_action_or_signed_scope_cannot_reuse_request_key(self):
        self.decide()
        for action, actor in (
            (SUPPLIER, self.agent),
            (INVOICE, self.identity(scopes=("invoice:read", "supplier:write"))),
            (INVOICE, self.identity(subject="another-agent")),
        ):
            with self.subTest(actor=actor.principal.id, action=action):
                with self.assertRaises(DecisionReplayConflict):
                    self.decide(action, agent=actor)
        self.assertEqual(self.counts(), (1, 1))

    def test_same_tenant_different_key_produces_new_event(self):
        a = self.decide()
        b = self.decide(key="decision-retry-000002")
        self.assertNotEqual(a.event_id, b.event_id)
        self.assertEqual(self.counts(), (2, 2))

    def test_tenant_scoped_missing_policy_refuses_without_evidence(self):
        with self.assertRaises(AuditStorageError):
            self.decide(agent=self.identity(tenant="tenant_other"))
        self.assertEqual(self.counts(), (0, 0))

    def test_policy_version_switch_invalidates_old_request_even_same_rules(self):
        old = self.decide()
        self.db.execute(
            "UPDATE active_policy_versions SET version=?, activated_at_ms=?,"
            "activation_marker=? WHERE tenant_id=?",
            ("ci-local-policy-v2", NOW + 1, "activation-ci-v2", "ci_local"),
        )
        with self.assertRaises(DecisionReplayConflict):
            self.decide(now=NOW + 2)
        self.assertEqual(self.counts(), (1, 1))
        # The changed active version may produce a new audited request key.
        fresh = self.decide(key="decision-retry-000002", now=NOW + 2)
        self.assertEqual(fresh.policy_version, "ci-local-policy-v2")
        self.assertFalse(fresh.replayed)
        self.assertNotEqual(old.event_id, fresh.event_id)

    def test_return_to_same_version_cannot_resurrect_old_generation(self):
        self.decide()
        self.db.execute(
            "UPDATE active_policy_versions SET version=?, activated_at_ms=?,"
            "activation_marker=? WHERE tenant_id=?",
            ("ci-local-policy-v2", NOW + 1, "switch-0001", "ci_local"),
        )
        self.db.execute(
            "UPDATE active_policy_versions SET version=?, activated_at_ms=?,"
            "activation_marker=? WHERE tenant_id=?",
            ("ci-local-policy-v1", NOW + 2, "switch-0002", "ci_local"),
        )
        with self.assertRaises(DecisionReplayConflict):
            self.decide(now=NOW + 3)
        self.assertEqual(self.counts(), (1, 1))

    def test_stale_writer_during_atomic_insert_never_reports_allow(self):
        class ConcurrentStore:
            first = self.store.first
            async def atomic(_self, statements):
                self.db.execute(
                    "UPDATE active_policy_versions SET version=?,activated_at_ms=?,"
                    "activation_marker=? WHERE tenant_id=?",
                    ("ci-local-policy-v2", NOW + 1, "switched", "ci_local"),
                )
                await self.store.atomic(statements)
        with self.assertRaises(DecisionReplayConflict):
            self.decide(store=ConcurrentStore())
        self.assertEqual(self.counts(), (0, 0))

    def test_failure_in_audit_insert_rolls_back_receipt(self):
        self.db.execute(
            "CREATE TRIGGER reject_decision_audit BEFORE INSERT ON audit_events "
            "WHEN NEW.event_id LIKE 'decision-%' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END"
        )
        with self.assertRaises(AuditStorageError):
            self.decide()
        self.assertEqual(self.counts(), (0, 0))

    def test_corrupt_audit_never_returns_cached_allow(self):
        self.decide()
        self.db.execute("DELETE FROM audit_events")
        with self.assertRaises(AuditStorageError):
            self.decide()
        self.assertEqual(self.counts(), (1, 0))

    def test_expired_receipt_cannot_be_reused(self):
        self.decide()
        with self.assertRaises(DecisionReplayConflict):
            self.decide(now=NOW + 30 * 86400000)
        self.assertEqual(self.counts(), (1, 1))

    def test_immutable_receipts_reject_update_and_delete(self):
        self.decide()
        for sql in (
            "DELETE FROM decision_requests",
            "UPDATE decision_requests SET effect='deny'",
        ):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                self.db.execute(sql)
        self.assertEqual(self.counts(), (1, 1))

    def test_input_bounds(self):
        for key in ("tiny", "bad key with spaces", "a" * 97):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.decide(key=key)
        self.assertEqual(self.counts(), (0, 0))


if __name__ == "__main__":
    unittest.main()
