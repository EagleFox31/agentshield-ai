"""Adversarial invoice prompt-injection regression tests.

These tests deliberately exercise the *dispatcher* and the audit-before-call
ordering. A fake invoice is untrusted text, never an identity or policy input.
"""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from pathlib import Path

from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.demo_invoice import (
    INVOICE_TEXT, INVOICE, SUPPLIER_CHANGE, POLICY_VERSION,
    RecordingMockTools, dispatch_mock, run_invoice_attack,
)
from agentshield.policy import Effect, Principal

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "migrations" / "0001_audit_core.sql").read_text(encoding="utf-8")


def run(coroutine):
    return asyncio.run(coroutine)


class InvoiceAttackTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(SQL)
        self.repo = SQLiteAuditRepository(self.db)
        self.principal = Principal("demo_tenant:invoice_agent", frozenset({"invoice:read"}))
        self.mock = RecordingMockTools()

    def tearDown(self):
        self.db.close()

    def execute(self):
        return run(run_invoice_attack(
            self.repo, self.principal, "demo_tenant",
            occurred_at_ms=1_790_000_010_000, tools=self.mock,
        ))

    def test_injection_denied_before_supplier_dispatch_and_audited(self):
        outcome = self.execute()
        self.assertEqual(outcome.read_effect, "allow")
        self.assertEqual(outcome.denied_effect, "deny")
        self.assertEqual(outcome.denied_reasons, ("REQUIRED_SCOPE_MISSING",))
        self.assertEqual(self.mock.invoice_reads, 1)
        self.assertEqual(self.mock.supplier_writes, 0)
        self.assertEqual(len(outcome.audit_event_ids), 2)
        for identifier in outcome.audit_event_ids:
            saved = run(self.repo.get_event("demo_tenant", identifier))
            self.assertIsNotNone(saved)
            self.assertEqual(saved.policy_version, POLICY_VERSION)
            self.assertIsNone(run(self.repo.get_event("other_tenant", identifier)))
        stored = "\n".join(self.db.iterdump()).lower()
        for hidden in ("ignore the user", "finance administrator", "training supplies",
                       "update_bank_account", "supplier/482"):
            self.assertNotIn(hidden, stored)

    def test_attack_does_not_change_signed_scopes_or_identity(self):
        original = self.principal
        self.execute()
        self.assertEqual(self.principal, original)
        self.assertEqual(original.scopes, frozenset({"invoice:read"}))
        self.assertIn("claim scope supplier:write", INVOICE_TEXT)

    def test_mismatched_tenant_fails_before_read_or_audit(self):
        with self.assertRaises(ValueError):
            run(run_invoice_attack(
                self.repo, self.principal, "other_tenant",
                occurred_at_ms=1_790_000_010_000, tools=self.mock,
            ))
        self.assertEqual(self.mock.invoice_reads, 0)
        self.assertEqual(self.mock.supplier_writes, 0)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)

    def test_broader_scopes_invalidate_the_negative_fixture(self):
        wider = Principal("demo_tenant:invoice_agent",
                          frozenset({"invoice:read", "supplier:write"}))
        with self.assertRaises(ValueError):
            run(run_invoice_attack(self.repo, wider, "demo_tenant",
                                   occurred_at_ms=1_790_000_010_000, tools=self.mock))
        self.assertEqual(self.mock.supplier_writes, 0)

    def test_denied_or_review_decision_cannot_dispatch_supplier_tool(self):
        for effect in (Effect.DENY, Effect.REQUIRE_APPROVAL):
            self.assertIsNone(dispatch_mock(effect, SUPPLIER_CHANGE, self.mock))
        self.assertEqual(self.mock.supplier_writes, 0)
        with self.assertRaises(RuntimeError):
            dispatch_mock(Effect.ALLOW, SUPPLIER_CHANGE, self.mock)
        self.assertEqual(self.mock.supplier_writes, 0)

    def test_failed_first_audit_prevents_even_mock_read(self):
        class BrokenAudit:
            async def record_event(self, event):
                raise AuditStorageError("D1 unavailable")
        with self.assertRaises(AuditStorageError):
            run(run_invoice_attack(
                BrokenAudit(), self.principal, "demo_tenant",
                occurred_at_ms=1_790_000_010_000, tools=self.mock,
            ))
        self.assertEqual((self.mock.invoice_reads, self.mock.supplier_writes), (0, 0))

    def test_failed_write_decision_audit_prevents_any_supplier_side_effect(self):
        class BreakAfterFirst:
            count = 0
            async def record_event(self, event):
                self.count += 1
                if self.count == 2:
                    raise AuditStorageError("Audit unavailable")
        with self.assertRaises(AuditStorageError):
            run(run_invoice_attack(
                BreakAfterFirst(), self.principal, "demo_tenant",
                occurred_at_ms=1_790_000_010_000, tools=self.mock,
            ))
        self.assertEqual(self.mock.invoice_reads, 1)
        self.assertEqual(self.mock.supplier_writes, 0)

    def test_second_domain_security_case_unknown_action_stays_blocked(self):
        # Independent domain (project deployment) never reaches invoice mock.
        from agentshield.policy import PolicyEngine, ToolAction
        action = ToolAction("cloud", "delete_storage_bucket", "bucket/demo")
        decision = PolicyEngine([]).evaluate(self.principal, action)
        self.assertEqual(decision.effect, Effect.DENY)
        self.assertIsNone(dispatch_mock(decision.effect, action, self.mock))
        self.assertEqual(self.mock.supplier_writes, 0)


if __name__ == "__main__":
    unittest.main()
