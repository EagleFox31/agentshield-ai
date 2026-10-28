"""Local-only signed operator policy activation: SQLite regression tests."""
import asyncio
import sqlite3
import unittest
from pathlib import Path
from agentshield.approvals import SQLiteApprovalStore
from agentshield.audit import AuditStorageError, decode_event
from agentshield.identity import VerifiedAgent
from agentshield.policy import Principal, Rule, Effect
from agentshield.policy_registry import SQLitePolicyRegistry, PolicyUnavailable, canonical_snapshot
from agentshield.policy_activation import activate_policy, PolicyActivationConflict
from scripts.seed_local_policy_registry import make_sql

ROOT = Path(__file__).resolve().parents[2]
NOW = 1790000100000


def run(awaitable):
    return asyncio.run(awaitable)


class PolicyActivationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for name in ("0001_audit_core.sql", "0004_policy_snapshots.sql",
                     "0005_policy_activation_audit.sql"):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.db.executescript(make_sql())
        self.store = SQLiteApprovalStore(self.db)
        self.registry = SQLitePolicyRegistry(self.db)
        self.operator = VerifiedAgent(
            Principal("ci_local:reviewer-01",
                      frozenset({"approvals:decide", "policies:activate"})),
            "ci_local", "reviewer-01", "op-token-000001",
            1790000000, 1790000300,
        )
        principal = Principal("ci_local:local-demo-agent",
                              frozenset({"invoice:read"}))
        rule = Rule("deny-invoice-read", principal.id, "invoices", "read",
                    "invoice/42", "invoice:read", Effect.DENY)
        raw, self.digest = canonical_snapshot(
            "ci_local", "ci-local-policy-v2", [rule])
        self.db.execute(
            "INSERT INTO policy_versions "
            "(tenant_id,version,sha256,created_at_ms,rules_json) "
            "VALUES (?,?,?,?,?)",
            ("ci_local", "ci-local-policy-v2", self.digest, NOW - 200, raw),
        )

    def tearDown(self):
        self.db.close()

    def activate(self, **kwargs):
        return run(activate_policy(
            kwargs.get("store", self.store), self.registry,
            kwargs.get("operator", self.operator),
            expected_version=kwargs.get("expected", "ci-local-policy-v1"),
            target_version=kwargs.get("target", "ci-local-policy-v2"),
            target_sha256=kwargs.get("sha", self.digest),
            now_ms=NOW,
        ))

    def test_success_and_immutable_evidence(self):
        receipt = self.activate()
        self.assertEqual(receipt.new_version, "ci-local-policy-v2")
        self.assertEqual(run(self.registry.load_active("ci_local")).version,
                         "ci-local-policy-v2")
        row = self.db.execute(
            "SELECT * FROM audit_events WHERE event_id=?",
            (receipt.audit_event_id,)).fetchone()
        event = decode_event(dict(row))
        self.assertEqual(event.reason_codes, ("POLICY_VERSION_ACTIVATED",))
        self.assertEqual(event.principal_id, self.operator.principal.id)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM policy_activation_history").fetchone()[0], 1)
        with self.assertRaises(sqlite3.DatabaseError):
            self.db.execute(
                "UPDATE policy_activation_history SET new_version='bad'"
            )

    def test_duplicate_expected_version_cannot_activate_again(self):
        self.activate()
        with self.assertRaises(PolicyActivationConflict):
            self.activate()
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM audit_events").fetchone()[0], 1)

    def test_target_mismatch_and_missing_scope_fail_closed(self):
        for kwargs in ({"sha": "0" * 64},
                       {"target": "ci-local-unknown-version"},
                       {"target": "ci-local-policy-v1"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(PolicyActivationConflict):
                self.activate(**kwargs)
        missing = VerifiedAgent(
            Principal("ci_local:reviewer-01", frozenset({"approvals:decide"})),
            "ci_local", "reviewer-01", "op-token-000002",
            1790000000, 1790000300,
        )
        with self.assertRaises(PolicyActivationConflict):
            self.activate(operator=missing)
        self.assertEqual(run(self.registry.load_active("ci_local")).version,
                         "ci-local-policy-v1")

    def test_tenant_isolation(self):
        wrong = VerifiedAgent(
            Principal("other:reviewer-01", frozenset({"policies:activate"})),
            "other", "reviewer-01", "op-token-000003",
            1790000000, 1790000300,
        )
        with self.assertRaises(PolicyUnavailable):
            self.activate(operator=wrong)

    def test_database_audit_failure_rolls_back_activation(self):
        # Real SQLite transaction, unlike a mock that fails before writing.
        self.db.execute(
            "CREATE TRIGGER prevent_activation_audit BEFORE INSERT "
            "ON audit_events "
            "WHEN NEW.reason_codes_json LIKE '%POLICY_VERSION_ACTIVATED%' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END"
        )
        with self.assertRaises(AuditStorageError):
            self.activate()
        self.assertEqual(
            run(self.registry.load_active("ci_local")).version,
            "ci-local-policy-v1",
        )
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM policy_activation_history").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0],
            0,
        )

    def test_storage_failure_keeps_previous_version(self):
        class Broken:
            first = self.store.first

            async def atomic(_self, _statements):
                raise AuditStorageError("simulated audit outage")
        with self.assertRaises(AuditStorageError):
            self.activate(store=Broken())
        self.assertEqual(run(self.registry.load_active("ci_local")).version,
                         "ci-local-policy-v1")
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
