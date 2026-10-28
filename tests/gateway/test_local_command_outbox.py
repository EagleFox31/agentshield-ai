"""P0 synthetic outbox: auditable queue, fenced operator claim, no redelivery."""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.approvals import SQLiteApprovalStore
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.identity import VerifiedAgent
from agentshield.local_command_outbox import (
    CommandConflict, claim_local_command, mark_local_uncertain, queue_local_invoice,
)
from agentshield.policy import Principal
from agentshield.policy_registry import SQLitePolicyRegistry
from scripts.seed_local_policy_registry import make_sql, reviewed_v2_sql

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_790_000_100_000
KEY = "outbox-test-request-00001"


def run(coro):
    return asyncio.run(coro)


class LocalOutboxTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for name in ("0001_audit_core.sql", "0004_policy_snapshots.sql",
                     "0005_policy_activation_audit.sql",
                     "0006_idempotent_decisions.sql",
                     "0007_tenant_decision_quota.sql",
                     "0008_local_command_outbox.sql"):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.db.executescript(make_sql() + reviewed_v2_sql())
        self.store = SQLiteApprovalStore(self.db)
        self.audit = SQLiteAuditRepository(self.db)
        self.registry = SQLitePolicyRegistry(self.db)
        self.agent = self.identity()
        self.operator = self.identity(subject="reviewer-01", scopes=(
            "commands:claim", "commands:reconcile",
        ))

    def tearDown(self):
        self.db.close()

    def identity(self, tenant="ci_local", subject="local-demo-agent",
                 scopes=("invoice:read",)):
        return VerifiedAgent(
            Principal(tenant + ":" + subject, frozenset(scopes)),
            tenant, subject, "local-token-abc123", 1790000000, 1790000300,
        )

    def enqueue(self, request_id=KEY, agent=None, now=NOW, store=None):
        return run(queue_local_invoice(
            store or self.store, self.audit, self.registry,
            agent or self.agent, request_id=request_id, now_ms=now,
        ))

    def claim(self, command_id, operator=None, now=NOW + 1, store=None):
        return run(claim_local_command(
            store or self.store, self.audit, self.registry,
            operator or self.operator, command_id=command_id, now_ms=now,
        ))

    def uncertain(self, command_id, operator=None, now=NOW + 2, store=None):
        return run(mark_local_uncertain(
            store or self.store, self.audit,
            operator or self.operator, command_id=command_id, now_ms=now,
        ))

    def counts(self):
        return (
            self.db.execute("SELECT count(*) FROM decision_requests").fetchone()[0],
            self.db.execute("SELECT count(*) FROM local_command_outbox").fetchone()[0],
            self.db.execute("SELECT count(*) FROM audit_events").fetchone()[0],
        )

    def test_queue_once_and_exact_retries_preserve_canonical_evidence(self):
        first = self.enqueue()
        again = self.enqueue()
        self.assertEqual(first.command_id, again.command_id)
        self.assertEqual(first.decision_event_id, again.decision_event_id)
        self.assertEqual(first.queue_audit_event_id, again.queue_audit_event_id)
        self.assertEqual(first.state, "queued")
        self.assertFalse(first.replayed)
        self.assertTrue(again.replayed)
        self.assertEqual(self.counts(), (1, 1, 2))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM tenant_decision_rate_slots"
        ).fetchone()[0], 1)

    def test_claimed_is_one_way_and_crash_recovery_never_requeues(self):
        queued = self.enqueue()
        result = self.claim(queued.command_id)
        self.assertEqual(result["state"], "claimed")
        self.assertFalse(result["real_tool_called"])
        self.assertEqual(self.counts(), (1, 1, 3))
        with self.assertRaises(CommandConflict):
            self.claim(queued.command_id)
        recovery = self.uncertain(queued.command_id)
        self.assertEqual(recovery["state"], "uncertain")
        self.assertFalse(recovery["executed"])
        with self.assertRaises(CommandConflict):
            self.claim(queued.command_id)
        with self.assertRaises(CommandConflict):
            self.uncertain(queued.command_id)
        self.assertEqual(self.counts(), (1, 1, 4))

    def test_operator_scope_tenant_and_agent_denied_for_claim(self):
        item = self.enqueue()
        unauthorized = self.identity(
            subject="reviewer-01", scopes=("approvals:read",),
        )
        with self.assertRaises(CommandConflict):
            self.claim(item.command_id, operator=unauthorized)
        wrong_tenant = self.identity(
            tenant="other", subject="reviewer-01",
            scopes=("commands:claim",),
        )
        with self.assertRaises(CommandConflict):
            self.claim(item.command_id, operator=wrong_tenant)
        self.assertEqual(self.counts(), (1, 1, 2))

    def test_policy_switch_blocks_unclaimed_dispatch_even_identical_rules(self):
        item = self.enqueue()
        self.db.execute(
            "UPDATE active_policy_versions SET version=?,activated_at_ms=?,"
            "activation_marker=? WHERE tenant_id=?",
            ("ci-local-policy-v2", NOW + 1, "switch-marker", "ci_local"),
        )
        with self.assertRaises(CommandConflict):
            self.claim(item.command_id, now=NOW + 2)
        self.assertEqual(self.counts(), (1, 1, 2))

    def test_cross_agent_request_id_collision_never_creates_second_command(self):
        first = self.enqueue()
        other = self.identity(subject="some-other-agent")
        from agentshield.idempotent_decisions import DecisionReplayConflict
        with self.assertRaises(DecisionReplayConflict):
            self.enqueue(agent=other)
        self.assertEqual(self.counts(), (1, 1, 2))
        self.assertEqual(first.state, "queued")

    def test_queue_audit_failure_leaves_decision_but_no_command(self):
        self.db.execute(
            "CREATE TRIGGER reject_outbox_audit BEFORE INSERT ON audit_events "
            "WHEN NEW.event_id LIKE 'outbox-queued-%' "
            "BEGIN SELECT RAISE(ABORT,'simulated queue audit failure'); END"
        )
        with self.assertRaises(AuditStorageError):
            self.enqueue()
        # Decision and its audit committed in the earlier independent batch.
        self.assertEqual(self.counts(), (1, 0, 1))
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM tenant_decision_rate_slots").fetchone()[0], 1)

    def test_claim_audit_failure_rolls_back_claim(self):
        item = self.enqueue()
        self.db.execute(
            "CREATE TRIGGER reject_claim_audit BEFORE INSERT ON audit_events "
            "WHEN NEW.event_id LIKE 'outbox-claimed-%' "
            "BEGIN SELECT RAISE(ABORT,'simulated claim audit failure'); END"
        )
        with self.assertRaises(AuditStorageError):
            self.claim(item.command_id)
        self.assertEqual(self.db.execute(
            "SELECT state FROM local_command_outbox").fetchone()[0], "queued")
        self.assertEqual(self.counts(), (1, 1, 2))

    def test_queue_can_recover_after_lost_response_but_without_new_audit(self):
        first = self.enqueue()
        # Pretend the HTTP response was lost, even though the D1 commit survived.
        retried = self.enqueue()
        self.assertEqual(retried.command_id, first.command_id)
        self.assertTrue(retried.replayed)
        self.assertEqual(self.counts(), (1, 1, 2))

    def test_corrupt_queue_audit_blocks_claim(self):
        item = self.enqueue()
        self.db.execute(
            "DELETE FROM audit_events WHERE event_id=?", (item.queue_audit_event_id,)
        )
        with self.assertRaises(AuditStorageError):
            self.claim(item.command_id)
        self.assertEqual(self.db.execute(
            "SELECT state FROM local_command_outbox").fetchone()[0], "queued")

    def test_database_triggers_reject_forged_requeue_or_binding_change(self):
        item = self.enqueue()
        for sql in (
            "DELETE FROM local_command_outbox",
            "UPDATE local_command_outbox SET principal_id='another'",
            "UPDATE local_command_outbox SET state='uncertain'",
        ):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                self.db.execute(sql)
        self.claim(item.command_id)
        with self.assertRaises(sqlite3.DatabaseError):
            self.db.execute(
                "UPDATE local_command_outbox SET state='queued',claim_token=NULL,"
                "claimed_at_ms=NULL,claim_audit_event_id=NULL"
            )

    def test_invalid_or_denied_invoice_cannot_queue(self):
        no_scope = self.identity(scopes=())
        with self.assertRaises(CommandConflict):
            self.enqueue(agent=no_scope)
        self.assertEqual(self.counts(), (1, 0, 1))
        self.assertEqual(self.db.execute(
            "SELECT effect FROM decision_requests").fetchone()[0], "deny")


if __name__ == "__main__":
    unittest.main()
