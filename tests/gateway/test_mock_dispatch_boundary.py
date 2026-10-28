"""Security negative tests for claimed-command one-shot in-memory dispatch."""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.approvals import SQLiteApprovalStore
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.identity import VerifiedAgent
from agentshield.local_command_outbox import claim_local_command, queue_local_invoice
from agentshield.local_tool_gate import LocalDryRunAdapter
from agentshield.mock_dispatch_boundary import (
    MockDispatchRejected, dispatch_claimed_invoice_mock,
)
from agentshield.policy import Principal
from agentshield.policy_registry import SQLitePolicyRegistry
from scripts.seed_local_policy_registry import make_sql, reviewed_v2_sql

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_790_000_100_000


def run(coro):
    return asyncio.run(coro)


class FencedMockDispatchTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for name in (
            "0001_audit_core.sql", "0004_policy_snapshots.sql",
            "0005_policy_activation_audit.sql", "0006_idempotent_decisions.sql",
            "0007_tenant_decision_quota.sql", "0008_local_command_outbox.sql",
            "0009_fenced_mock_dispatch.sql",
        ):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.db.executescript(make_sql() + reviewed_v2_sql())
        self.store = SQLiteApprovalStore(self.db)
        self.audit = SQLiteAuditRepository(self.db)
        self.registry = SQLitePolicyRegistry(self.db)
        self.agent = self.actor("local-demo-agent", ("invoice:read",))
        self.operator = self.actor("reviewer-01", ("commands:claim",))
        self.adapter = LocalDryRunAdapter()

    def tearDown(self):
        self.db.close()

    def actor(self, subject, scopes, tenant="ci_local"):
        return VerifiedAgent(
            Principal(f"{tenant}:{subject}", frozenset(scopes)),
            tenant, subject, "synthetic-jti-001", 1790000000, 1790000300,
        )

    def enqueue(self):
        return run(queue_local_invoice(
            self.store, self.audit, self.registry, self.agent,
            request_id="fenced-dispatch-request-001", now_ms=NOW,
        ))

    def claim(self, command_id):
        return run(claim_local_command(
            self.store, self.audit, self.registry, self.operator,
            command_id=command_id, now_ms=NOW + 1,
        ))

    def dispatch(self, command_id, *, agent=None, adapter=None):
        return run(dispatch_claimed_invoice_mock(
            self.store, self.audit, self.registry, agent or self.agent,
            command_id=command_id, now_ms=NOW + 2,
            adapter=adapter or self.adapter,
        ))

    def attempts(self):
        return self.db.execute(
            "SELECT COUNT(*) FROM local_mock_dispatch_reservations"
        ).fetchone()[0]

    def test_signed_original_agent_and_operator_claim_allow_one_mock_only(self):
        command = self.enqueue()
        with self.assertRaises(MockDispatchRejected):
            self.dispatch(command.command_id)
        self.assertEqual(self.attempts(), 0)
        self.claim(command.command_id)
        receipt = self.dispatch(command.command_id)
        self.assertEqual(receipt.stub_name, "mock_invoice_read")
        self.assertEqual(self.adapter.calls, ["mock_invoice_read"])
        self.assertEqual(self.attempts(), 1)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0], 4)
        with self.assertRaises(MockDispatchRejected):
            self.dispatch(command.command_id)
        self.assertEqual(self.adapter.calls, ["mock_invoice_read"])

    def test_wrong_signed_principal_scopes_tenant_and_operator_fail(self):
        command = self.enqueue()
        self.claim(command.command_id)
        for actor in (
            self.actor("another-agent", ("invoice:read",)),
            self.actor("local-demo-agent", ("invoice:read", "supplier:write")),
            self.actor("local-demo-agent", ()),
            self.actor("local-demo-agent", ("invoice:read",), "other"),
            self.operator,
        ):
            with self.subTest(actor=actor.principal), self.assertRaises(MockDispatchRejected):
                self.dispatch(command.command_id, agent=actor)
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.attempts(), 0)

    def test_policy_activation_revokes_claimed_command_before_dispatch(self):
        command = self.enqueue()
        self.claim(command.command_id)
        self.db.execute(
            "UPDATE active_policy_versions SET version=?,activated_at_ms=?,"
            "activation_marker=? WHERE tenant_id=?",
            ("ci-local-policy-v2", NOW + 3, "new-generation", "ci_local"),
        )
        with self.assertRaises(MockDispatchRejected):
            self.dispatch(command.command_id)
        self.assertEqual(self.attempts(), 0)
        self.assertEqual(self.adapter.calls, [])

    def check_missing_evidence(self, which):
        cmd = self.enqueue()
        self.claim(cmd.command_id)
        row = self.db.execute(
            "SELECT * FROM local_command_outbox"
        ).fetchone()
        self.db.execute(
            "DELETE FROM audit_events WHERE event_id=?", (row[which],),
        )
        with self.assertRaises(AuditStorageError):
            self.dispatch(cmd.command_id)
        self.assertEqual(self.attempts(), 0)
        self.assertEqual(self.adapter.calls, [])

    def test_missing_original_decision_audit_blocks_stub(self):
        self.check_missing_evidence("decision_event_id")

    def test_missing_queue_audit_blocks_stub(self):
        self.check_missing_evidence("queue_audit_event_id")

    def test_missing_claim_audit_blocks_stub(self):
        self.check_missing_evidence("claim_audit_event_id")

    def test_audit_insert_failure_rolls_back_dispatch_reservation(self):
        cmd = self.enqueue()
        self.claim(cmd.command_id)
        self.db.execute(
            "CREATE TRIGGER refuse_mock_dispatch_audit BEFORE INSERT "
            "ON audit_events WHEN NEW.event_id LIKE 'mock-dispatch-audit-%' "
            "BEGIN SELECT RAISE(ABORT,'synthetic audit storage outage'); END"
        )
        with self.assertRaises(AuditStorageError):
            self.dispatch(cmd.command_id)
        self.assertEqual(self.attempts(), 0)
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0], 3)

    def test_adapter_crash_after_reservation_does_not_allow_retry(self):
        cmd = self.enqueue()
        self.claim(cmd.command_id)
        class BrokenAdapter:
            calls = 0
            def invoke(self, _action):
                self.calls += 1
                raise RuntimeError("simulated crash before result")
        adapter = BrokenAdapter()
        with self.assertRaises(RuntimeError):
            self.dispatch(cmd.command_id, adapter=adapter)
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(self.attempts(), 1)
        with self.assertRaises(MockDispatchRejected):
            self.dispatch(cmd.command_id)
        self.assertEqual(self.adapter.calls, [])

    def test_immutable_dispatch_record_and_foreign_command_rejected(self):
        cmd = self.enqueue()
        self.claim(cmd.command_id)
        self.dispatch(cmd.command_id)
        for sql in (
            "DELETE FROM local_mock_dispatch_reservations",
            "UPDATE local_mock_dispatch_reservations SET principal_id='forged'",
        ):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                self.db.execute(sql)
        with self.assertRaises(MockDispatchRejected):
            self.dispatch("local-command-" + "0" * 32)

    def test_marked_uncertain_cannot_be_dispatched(self):
        from agentshield.local_command_outbox import mark_local_uncertain
        cmd = self.enqueue()
        self.claim(cmd.command_id)
        reviewer = self.actor("reviewer-01", ("commands:reconcile",))
        run(mark_local_uncertain(
            self.store, self.audit, reviewer,
            command_id=cmd.command_id, now_ms=NOW + 2,
        ))
        with self.assertRaises(MockDispatchRejected):
            self.dispatch(cmd.command_id)
        self.assertEqual(self.adapter.calls, [])


if __name__ == "__main__":
    unittest.main()
