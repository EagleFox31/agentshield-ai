"""Offline security gates: mock invokes ONLY after durable audit and approval."""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.approvals import SQLiteApprovalStore, create_pending, review
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.demo_invoice import INVOICE, SUPPLIER_CHANGE, _rules
from agentshield.identity import VerifiedAgent
from agentshield.local_tool_gate import (
    LocalDryRunAdapter, MockGateRejected, execute_local_mock,
)
from agentshield.policy import Principal, ToolAction

ROOT = Path(__file__).resolve().parents[2]


def run(coro):
    return asyncio.run(coro)


class LocalMockExecutionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        for name in ("0001_audit_core.sql", "0002_approval_review.sql"):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.repo = SQLiteAuditRepository(self.db)
        self.store = SQLiteApprovalStore(self.db)
        self.now = 1_790_000_100_000
        self.adapter = LocalDryRunAdapter()
        self.agent = self.identity()

    def tearDown(self):
        self.db.close()

    def identity(self, *, tenant="ci_local", subject="demo-agent",
                 scopes=("invoice:read",), token_id="synthetic-token-1234"):
        return VerifiedAgent(
            Principal(f"{tenant}:{subject}", frozenset(scopes)),
            tenant, subject, token_id, 1_790_000_000, 1_790_000_300,
        )

    def invoke(self, action=INVOICE, *, agent=None, fixture="scenario-A",
               nonce="unique-nonce-0001", approval_id=None, repository=None,
               store=None, adapter=None):
        return run(execute_local_mock(
            repository or self.repo, store or self.store,
            agent or self.agent, action, fixture=fixture,
            nonce=nonce, approval_id=approval_id,
            now_ms=self.now, adapter=adapter or self.adapter,
        ))

    def approval(self, *, agent=None):
        actor = agent or self.identity(scopes=("invoice:read", "supplier:write"))
        row = run(create_pending(
            self.store, actor, SUPPLIER_CHANGE, {"fixture": "scenario-A"},
            _rules(actor.principal), self.now - 20,
        ))
        self.assertTrue(run(review(
            self.store, row.approval_id, actor.tenant_id,
            f"{actor.tenant_id}:human-reviewer", "approved", self.now - 10,
        )))
        return actor, row.approval_id

    def test_read_dispatches_only_existing_invoice_mock(self):
        result = self.invoke()
        self.assertEqual(result["mock_result"], "mock_invoice_read")
        self.assertEqual(self.adapter.calls, ["mock_invoice_read"])
        self.assertFalse(result["real_tool_called"])
        self.assertFalse(result["executed"])
        self.assertFalse(result["enforcement_ready"])
        count = self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM used_action_nonces").fetchone()[0], 1)

    def test_unknown_action_never_calls_adapter(self):
        with self.assertRaises(MockGateRejected):
            self.invoke(ToolAction("cloud", "delete_bucket", "bucket/demo"))
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM used_action_nonces").fetchone()[0], 0)

    def test_missing_scope_rejects_supplier_mutation(self):
        with self.assertRaises(MockGateRejected):
            self.invoke(SUPPLIER_CHANGE)
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM used_action_nonces").fetchone()[0], 0)

    def test_review_required_and_single_use_consumption(self):
        actor, approval_id = self.approval()
        with self.assertRaises(MockGateRejected):
            self.invoke(SUPPLIER_CHANGE, agent=actor)
        self.assertEqual(self.adapter.calls, [])
        success = self.invoke(SUPPLIER_CHANGE, agent=actor, approval_id=approval_id)
        self.assertEqual(success["mock_result"], "mock_supplier_write_dry_run")
        self.assertEqual(self.adapter.calls, ["mock_supplier_write_dry_run"])
        self.assertFalse(success["real_tool_called"])
        self.assertEqual(self.db.execute(
            "SELECT state FROM approval_requests WHERE approval_id=?", (approval_id,)
        ).fetchone()[0], "consumed")
        with self.assertRaises(MockGateRejected):
            self.invoke(SUPPLIER_CHANGE, agent=actor, approval_id=approval_id,
                        nonce="unique-nonce-0002")
        self.assertEqual(len(self.adapter.calls), 1)

    def test_nonce_replay_rejected_even_for_allowed_action(self):
        self.invoke()
        with self.assertRaises(MockGateRejected):
            self.invoke()
        self.assertEqual(self.adapter.calls, ["mock_invoice_read"])

    def test_changed_fixture_cannot_reuse_grant(self):
        actor, approval_id = self.approval()
        with self.assertRaises(MockGateRejected):
            self.invoke(SUPPLIER_CHANGE, agent=actor, approval_id=approval_id,
                        fixture="scenario-B")
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute(
            "SELECT state FROM approval_requests WHERE approval_id=?", (approval_id,)
        ).fetchone()[0], "approved")

    def test_expired_grant_cannot_dispatch(self):
        actor, approval_id = self.approval()
        self.now += 120_001
        with self.assertRaises(MockGateRejected):
            self.invoke(SUPPLIER_CHANGE, agent=actor, approval_id=approval_id)
        self.assertEqual(self.adapter.calls, [])

    def test_cross_tenant_and_changed_scopes_cannot_dispatch(self):
        actor, approval_id = self.approval()
        for changed in (
            self.identity(tenant="other", scopes=("invoice:read", "supplier:write")),
            self.identity(subject="another-agent", scopes=("invoice:read", "supplier:write")),
            self.identity(scopes=("supplier:write",)),
        ):
            with self.subTest(changed=changed.principal.id), self.assertRaises(MockGateRejected):
                self.invoke(SUPPLIER_CHANGE, agent=changed, approval_id=approval_id,
                            nonce="unique-nonce-" + changed.agent_id.replace("_", "-"))
        self.assertEqual(self.adapter.calls, [])

    def test_audit_outage_blocks_even_permitted_read(self):
        class BrokenAudit:
            async def record_event(self, event):
                raise AuditStorageError("synthetic D1 outage")
        with self.assertRaises(AuditStorageError):
            self.invoke(repository=BrokenAudit())
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM used_action_nonces").fetchone()[0], 0)

    def test_nonce_storage_outage_blocks_execution(self):
        class BrokenNonce:
            async def record_event(_, event):
                return await self.repo.record_event(event)

            async def consume_nonce(_, *args):
                raise AuditStorageError("synthetic nonce failure")
        with self.assertRaises(AuditStorageError):
            self.invoke(repository=BrokenNonce())
        self.assertEqual(self.adapter.calls, [])

    def test_approval_audit_transaction_failure_prevents_dispatch(self):
        actor, approval_id = self.approval()
        self.db.execute("""
            CREATE TRIGGER refuse_consumption_audit BEFORE INSERT ON audit_events
            WHEN NEW.reason_codes_json LIKE '%HUMAN_APPROVAL_CONSUMED%'
            BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END
        """)
        with self.assertRaises(AuditStorageError):
            self.invoke(SUPPLIER_CHANGE, agent=actor, approval_id=approval_id)
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute(
            "SELECT state FROM approval_requests WHERE approval_id=?", (approval_id,)
        ).fetchone()[0], "approved")

    def test_adapter_does_not_accept_unlisted_tools_even_on_direct_call(self):
        with self.assertRaises(MockGateRejected):
            self.adapter.invoke(ToolAction("cloud", "deploy", "site/demo"))
        self.assertEqual(self.adapter.calls, [])


if __name__ == "__main__":
    unittest.main()
