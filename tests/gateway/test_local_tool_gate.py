"""Offline security gates: mock invokes ONLY after durable audit and approval."""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.approvals import SQLiteApprovalStore, create_pending, review
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.demo_invoice import INVOICE, SUPPLIER_CHANGE, _rules, demo_rule_records
from agentshield.policy_registry import SQLitePolicyRegistry, canonical_snapshot
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
        for name in ("0001_audit_core.sql", "0002_approval_review.sql", "0004_policy_snapshots.sql"):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.repo = SQLiteAuditRepository(self.db)
        self.store = SQLiteApprovalStore(self.db)
        self.version = "ci-local-policy-v1"
        fixture_principal = Principal("ci_local:demo-agent",
                                      frozenset({"invoice:read", "supplier:write"}))
        encoded, digest = canonical_snapshot(
            "ci_local", self.version, demo_rule_records(fixture_principal))
        self.db.execute(
            "INSERT INTO policy_versions "
            "(tenant_id,version,sha256,created_at_ms,rules_json) VALUES (?,?,?,?,?)",
            ("ci_local", self.version, digest, 1790000000000, encoded),
        )
        self.db.execute(
            "INSERT INTO active_policy_versions "
            "(tenant_id,version,activated_at_ms) VALUES (?,?,?)",
            ("ci_local", self.version, 1790000000000),
        )
        self.registry = SQLitePolicyRegistry(self.db)
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
            self.registry, agent or self.agent, action, fixture=fixture,
            nonce=nonce, approval_id=approval_id,
            now_ms=self.now, adapter=adapter or self.adapter,
        ))

    def approval(self, *, agent=None):
        actor = agent or self.identity(scopes=("invoice:read", "supplier:write"))
        row = run(create_pending(
            self.store, actor, SUPPLIER_CHANGE, {"fixture": "scenario-A"},
            _rules(actor.principal), self.now - 20,
            policy_version=self.version,
        ))
        self.assertTrue(run(review(
            self.store, row.approval_id, actor.tenant_id,
            f"{actor.tenant_id}:human-reviewer", "approved", self.now - 10,
            current_policy_version=self.version,
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
        # Unknown actions must still leave a redacted DENY audit event.
        self.assertEqual(self.db.execute(
            "SELECT effect FROM audit_events ORDER BY occurred_at_ms LIMIT 1"
        ).fetchone()[0], "deny")
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
            with self.subTest(changed=changed.principal.id), self.assertRaises((MockGateRejected, AuditStorageError)):
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

    def activate_same_rules_with_new_version(self):
        new_version = "ci-local-policy-v2"
        fixture_principal = Principal("ci_local:demo-agent",
                                      frozenset({"invoice:read", "supplier:write"}))
        raw, digest = canonical_snapshot(
            "ci_local", new_version, demo_rule_records(fixture_principal))
        self.db.execute(
            "INSERT INTO policy_versions "
            "(tenant_id,version,sha256,created_at_ms,rules_json) VALUES (?,?,?,?,?)",
            ("ci_local", new_version, digest, self.now, raw),
        )
        self.db.execute(
            "UPDATE active_policy_versions SET version=?,activated_at_ms=? "
            "WHERE tenant_id='ci_local'", (new_version, self.now),
        )
        return new_version

    def test_grant_from_old_policy_revoked_even_when_new_rules_are_identical(self):
        actor, approval_id = self.approval()
        self.activate_same_rules_with_new_version()
        with self.assertRaises(MockGateRejected):
            self.invoke(SUPPLIER_CHANGE, agent=actor, approval_id=approval_id)
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.db.execute(
            "SELECT state FROM approval_requests WHERE approval_id=?", (approval_id,)
        ).fetchone()[0], "approved")
        stored = self.db.execute(
            "SELECT effect,policy_version FROM audit_events "
            "WHERE event_id LIKE 'mock-decision-%' ORDER BY occurred_at_ms DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(tuple(stored), ("require_approval", "ci-local-policy-v2"))

    def test_no_stale_grant_creation_when_current_version_changed(self):
        actor = self.identity(scopes=("invoice:read", "supplier:write"))
        self.activate_same_rules_with_new_version()
        from agentshield.approvals import ApprovalRejected
        with self.assertRaises(ApprovalRejected):
            run(create_pending(
                self.store, actor, SUPPLIER_CHANGE, {"fixture": "scenario-A"},
                _rules(actor.principal), self.now,
                policy_version=self.version,
            ))
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM approval_requests").fetchone()[0], 0)

    def test_pending_old_version_cannot_be_reviewed_after_switch(self):
        actor = self.identity(scopes=("invoice:read", "supplier:write"))
        row = run(create_pending(
            self.store, actor, SUPPLIER_CHANGE, {"fixture": "scenario-A"},
            _rules(actor.principal), self.now - 30,
            policy_version=self.version,
        ))
        self.activate_same_rules_with_new_version()
        self.assertFalse(run(review(
            self.store, row.approval_id, actor.tenant_id,
            f"{actor.tenant_id}:human-reviewer", "approved", self.now,
            current_policy_version="ci-local-policy-v2",
        )))
        self.assertEqual(self.db.execute(
            "SELECT state FROM approval_requests WHERE approval_id=?",
            (row.approval_id,)
        ).fetchone()[0], "pending")

    def test_activation_between_policy_read_and_mock_dispatch_rejects(self):
        original_registry = self.registry

        class SwitchingRegistry:
            calls = 0

            async def load_active(inner, tenant_id):
                inner.calls += 1
                if inner.calls == 2:
                    self.activate_same_rules_with_new_version()
                return await original_registry.load_active(tenant_id)

        self.registry = SwitchingRegistry()
        with self.assertRaises(MockGateRejected):
            self.invoke()
        self.assertEqual(self.adapter.calls, [])

    def test_adapter_does_not_accept_unlisted_tools_even_on_direct_call(self):
        with self.assertRaises(MockGateRejected):
            self.adapter.invoke(ToolAction("cloud", "deploy", "site/demo"))
        self.assertEqual(self.adapter.calls, [])


if __name__ == "__main__":
    unittest.main()
