"""Portable SQLite validation of tenant-versioned snapshots and hash checks."""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import unittest
from pathlib import Path

from agentshield.audit import AuditStorageError
from agentshield.audit_service import decide_and_audit
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.demo_invoice import INVOICE, demo_rule_records
from agentshield.policy import Effect, Principal, Rule
from agentshield.policy_registry import (
    D1PolicyRegistry, PolicyUnavailable, SQLitePolicyRegistry,
    canonical_snapshot,
)
from scripts.seed_local_policy_registry import make_sql

ROOT = Path(__file__).resolve().parents[2]


def run(coro):
    return asyncio.run(coro)


class PolicyRegistryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for name in ("0001_audit_core.sql", "0004_policy_snapshots.sql"):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.db.executescript(make_sql())
        self.repo = SQLitePolicyRegistry(self.db)

    def tearDown(self):
        self.db.close()

    def load(self, tenant="ci_local"):
        return run(self.repo.load_active(tenant))

    def test_idempotent_offline_seed_and_active_policy(self):
        self.db.executescript(make_sql())
        p = self.load()
        self.assertEqual(p.version, "ci-local-policy-v1")
        self.assertEqual(len(p.sha256), 64)
        self.assertEqual(
            p.engine.evaluate(Principal("ci_local:local-demo-agent",
                                        frozenset({"invoice:read"})), INVOICE).effect,
            Effect.ALLOW,
        )
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM policy_versions").fetchone()[0], 1)

    def test_tenant_isolation_and_absent_policy_fail_closed(self):
        for tenant in ("other_tenant", "ci-local", "ci_local2"):
            with self.subTest(tenant=tenant), self.assertRaises(PolicyUnavailable):
                self.load(tenant)

    def test_cross_tenant_rule_rejected_before_publish(self):
        p = Principal("other:agent", frozenset({"invoice:read"}))
        with self.assertRaises(ValueError):
            canonical_snapshot("ci_local", "policy-version-02",
                               demo_rule_records(p))

    def test_canonical_order_and_ambiguous_rule_ids(self):
        p = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        rules = demo_rule_records(p)
        self.assertEqual(canonical_snapshot("ci_local", "policy-version-02", rules),
                         canonical_snapshot("ci_local", "policy-version-02", rules[::-1]))
        with self.assertRaises(ValueError):
            canonical_snapshot("ci_local", "policy-version-02",
                               [rules[0], rules[0]])

    def test_published_versions_immutable_at_storage_layer(self):
        for sql in (
            "UPDATE policy_versions SET sha256='x' WHERE tenant_id='ci_local'",
            "DELETE FROM policy_versions WHERE tenant_id='ci_local'",
        ):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                self.db.execute(sql)
        self.assertEqual(self.load().version, "ci-local-policy-v1")

    def test_tampered_digest_blocks_authority(self):
        base = self.load()
        self.db.execute(
            "INSERT INTO policy_versions "
            "(tenant_id,version,sha256,created_at_ms,rules_json) "
            "VALUES (?,?,?,?,?)",
            ("ci_local", "policy-tampered-02", "0" * 64, 1790000000000,
             base.rules_json),
        )
        self.db.execute(
            "UPDATE active_policy_versions SET version=? WHERE tenant_id=?",
            ("policy-tampered-02", "ci_local"),
        )
        with self.assertRaises(PolicyUnavailable):
            self.load()

    def test_wrong_tenant_activation_rejected_by_composite_fk(self):
        self.db.execute(
            "INSERT INTO policy_versions "
            "(tenant_id,version,sha256,created_at_ms,rules_json) VALUES (?,?,?,?,?)",
            ("other", "policy-other-v1", "0" * 64, 1790000000000, "{}"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO active_policy_versions "
                "(tenant_id,version,activated_at_ms) VALUES (?,?,?)",
                ("ci_local", "policy-other-v1", 1790000000100),
            )

    def test_reviewed_new_version_switches_without_mutating_old(self):
        p = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        deny = Rule("deny-invoice-read", p.id, "invoices", "read",
                    "invoice/42", "invoice:read", Effect.DENY)
        raw, digest = canonical_snapshot("ci_local", "ci-local-policy-v2", [deny])
        self.db.execute(
            "INSERT INTO policy_versions "
            "(tenant_id,version,sha256,created_at_ms,rules_json) VALUES (?,?,?,?,?)",
            ("ci_local", "ci-local-policy-v2", digest, 1790000000200, raw),
        )
        previous = self.load()
        self.db.execute(
            "UPDATE active_policy_versions SET version=?,activated_at_ms=? "
            "WHERE tenant_id=?",
            ("ci-local-policy-v2", 1790000000300, "ci_local"),
        )
        current = self.load()
        self.assertEqual(current.engine.evaluate(p, INVOICE).effect, Effect.DENY)
        self.assertNotEqual(previous.sha256, current.sha256)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM policy_versions WHERE tenant_id='ci_local'"
        ).fetchone()[0], 2)

    def test_decision_audit_records_selected_version(self):
        p = self.load()
        principal = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        result = run(decide_and_audit(
            p.engine, SQLiteAuditRepository(self.db), principal, "ci_local",
            INVOICE, event_id="registry-event-00000001",
            policy_version=p.version, occurred_at_ms=1790000000200,
        ))
        self.assertEqual(result.effect, Effect.ALLOW)
        audit = self.db.execute(
            "SELECT policy_version, effect FROM audit_events "
            "WHERE event_id='registry-event-00000001'"
        ).fetchone()
        self.assertEqual(tuple(audit), (p.version, "allow"))

    def test_invalid_license_or_wildcard_is_never_accepted(self):
        p = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        wildcard = Rule("allow-glob", p.id, "invoices", "read",
                        "invoice/*", "invoice:read", Effect.ALLOW)
        with self.assertRaises(ValueError):
            canonical_snapshot("ci_local", "ci-local-policy-v2", [wildcard])

    def test_d1_unavailable_fails_closed(self):
        class BrokenBinding:
            def prepare(self, _sql):
                raise RuntimeError("D1 down")
        with self.assertRaises(PolicyUnavailable):
            run(D1PolicyRegistry(BrokenBinding()).load_active("ci_local"))
        with self.assertRaises(PolicyUnavailable):
            D1PolicyRegistry(None)


if __name__ == "__main__":
    unittest.main()
