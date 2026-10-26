"""Offline security contract for signed-human approval state transitions."""
from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from agentshield.approvals import (
    ApprovalRejected, D1ApprovalStore, SQLiteApprovalStore,
    POLICY_VERSION, consume_mock, create_pending, expire_if_needed,
    get_approval, list_approvals, review,
)
from agentshield.audit import AuditStorageError
from agentshield.identity import VerifiedAgent
from agentshield.policy import Effect, PolicyEngine, Principal, Rule, ToolAction

ROOT = Path(__file__).resolve().parents[2]
SQL = [(ROOT / "migrations" / path).read_text(encoding="utf-8")
       for path in ("0001_audit_core.sql", "0002_approval_review.sql")]
ACTION = ToolAction("suppliers", "update_bank_account", "supplier/482")


def run(coroutine):
    return asyncio.run(coroutine)


def principal(tenant="ci_local", sub="agent-01", scopes=("supplier:write",)):
    return VerifiedAgent(
        Principal(f"{tenant}:{sub}", frozenset(scopes)), tenant, sub,
        "signed-token-identifier", 1_790_000_000, 1_790_000_300,
    )


def engine(agent):
    return PolicyEngine([Rule(
        id="requires-human-review", principal_id=agent.principal.id,
        tool=ACTION.tool, operation=ACTION.operation, resource=ACTION.resource,
        required_scope="supplier:write", effect=Effect.REQUIRE_APPROVAL,
    )])


class SQLiteApprovalsTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        for statement in SQL:
            self.db.executescript(statement)
        self.store = SQLiteApprovalStore(self.db)
        self.agent = principal()
        self.now = 1_790_000_010_000

    def tearDown(self):
        self.db.close()

    def request(self):
        return run(create_pending(
            self.store, self.agent, ACTION, {"fixture": "scenario-A"},
            engine(self.agent), self.now,
        ))

    def test_approve_and_simulate_at_most_once_with_audit(self):
        row = self.request()
        self.assertEqual(row.state, "pending")
        self.assertEqual(len(run(list_approvals(self.store, "ci_local"))), 1)
        self.assertEqual(len(run(list_approvals(self.store, "other_tenant"))), 0)
        self.assertTrue(run(review(
            self.store, row.approval_id, "ci_local", "ci_local:reviewer-01",
            "approved", self.now + 500,
        )))
        self.assertFalse(run(review(
            self.store, row.approval_id, "ci_local", "ci_local:reviewer-02",
            "rejected", self.now + 600,
        )))
        self.assertFalse(run(consume_mock(
            self.store, self.agent, row.approval_id, ACTION,
            {"fixture": "scenario-B"}, engine(self.agent), self.now + 650,
        )))
        self.assertTrue(run(consume_mock(
            self.store, self.agent, row.approval_id, ACTION,
            {"fixture": "scenario-A"}, engine(self.agent), self.now + 700,
        )))
        self.assertFalse(run(consume_mock(
            self.store, self.agent, row.approval_id, ACTION,
            {"fixture": "scenario-A"}, engine(self.agent), self.now + 800,
        )))
        self.assertEqual(
            self.db.execute("SELECT state FROM approval_requests").fetchone()[0],
            "consumed",
        )
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM approval_decisions").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 3)

    def test_expiry_audited_and_unusable(self):
        row = self.request()
        self.assertTrue(run(expire_if_needed(
            self.store, "ci_local", row.approval_id, self.now + 120_000,
        )))
        self.assertFalse(run(review(
            self.store, row.approval_id, "ci_local", "ci_local:reviewer-01",
            "approved", self.now + 120_010,
        )))
        self.assertEqual(
            self.db.execute("SELECT state FROM approval_requests").fetchone()[0],
            "expired",
        )
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 2)

    def test_denied_or_unscoped_action_cannot_request_approval(self):
        unscoped = principal(scopes=("invoice:read",))
        with self.assertRaises(ApprovalRejected):
            run(create_pending(
                self.store, unscoped, ACTION, {"fixture": "scenario-A"},
                engine(unscoped), self.now,
            ))
        deny = PolicyEngine([Rule(
            id="explicit-denial", principal_id=self.agent.principal.id,
            tool=ACTION.tool, operation=ACTION.operation, resource=ACTION.resource,
            required_scope="supplier:write", effect=Effect.DENY,
        )])
        with self.assertRaises(ApprovalRejected):
            run(create_pending(
                self.store, self.agent, ACTION, {"fixture": "scenario-A"},
                deny, self.now,
            ))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0], 0)

    def test_cannot_change_agent_tenant_or_scopes_after_approval(self):
        row = self.request()
        run(review(self.store, row.approval_id, "ci_local", "ci_local:reviewer-01",
                   "approved", self.now + 200))
        other_agent = principal(sub="agent-02")
        self.assertFalse(run(consume_mock(
            self.store, other_agent, row.approval_id, ACTION,
            {"fixture": "scenario-A"}, engine(other_agent), self.now + 250,
        )))
        other_scopes = principal(scopes=("supplier:write", "invoice:read"))
        self.assertFalse(run(consume_mock(
            self.store, other_scopes, row.approval_id, ACTION,
            {"fixture": "scenario-A"}, engine(other_scopes), self.now + 260,
        )))
        cross_tenant = principal(tenant="ci_other")
        self.assertFalse(run(consume_mock(
            self.store, cross_tenant, row.approval_id, ACTION,
            {"fixture": "scenario-A"}, engine(cross_tenant), self.now + 280,
        )))

    def test_no_self_approval(self):
        row = self.request()
        with self.assertRaises(ApprovalRejected):
            run(review(self.store, row.approval_id, "ci_local", row.principal_id,
                       "approved", self.now + 10))
        self.assertEqual(
            self.db.execute("SELECT state FROM approval_requests").fetchone()[0],
            "pending",
        )

    def test_failed_atomic_audit_rolls_back_approved_state(self):
        row = self.request()
        self.db.execute("""
            CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events
            BEGIN SELECT RAISE(ABORT, 'simulated audit outage'); END
        """)
        with self.assertRaises(AuditStorageError):
            run(review(self.store, row.approval_id, "ci_local",
                       "ci_local:reviewer-01", "approved", self.now + 20))
        self.assertEqual(
            self.db.execute("SELECT state FROM approval_requests").fetchone()[0],
            "pending",
        )
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM approval_decisions").fetchone()[0], 0)

    def test_concurrent_reviews_have_single_winner_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approvals.db"
            creator = sqlite3.connect(path)
            for statement in SQL:
                creator.executescript(statement)
            store = SQLiteApprovalStore(creator)
            row = run(create_pending(store, self.agent, ACTION, {"fixture": "scenario-A"},
                                     engine(self.agent), self.now))
            creator.close()
            barrier = Barrier(4)
            def attempt(number):
                connection = sqlite3.connect(path, timeout=8)
                try:
                    barrier.wait(timeout=5)
                    return run(review(
                        SQLiteApprovalStore(connection), row.approval_id, "ci_local",
                        f"ci_local:reviewer-{number:02d}",
                        "approved", self.now + 150,
                    ))
                finally:
                    connection.close()
            with ThreadPoolExecutor(max_workers=4) as pool:
                outcomes = list(pool.map(attempt, range(4)))
            self.assertEqual(outcomes.count(True), 1)
            self.assertEqual(outcomes.count(False), 3)
            verifier = sqlite3.connect(path)
            self.assertEqual(verifier.execute("SELECT COUNT(*) FROM approval_decisions").fetchone()[0], 1)
            self.assertEqual(verifier.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 2)
            verifier.close()

    def test_no_sensitive_argument_string_persisted(self):
        self.request()
        stored = "\n".join(self.db.iterdump())
        self.assertNotIn("scenario-A", stored)
        self.assertNotIn("supplier/482", stored)
        self.assertNotIn("update_bank_account", stored)


if __name__ == "__main__":
    unittest.main()
