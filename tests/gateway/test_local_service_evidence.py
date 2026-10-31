"""Host/Worker handoff evidence is an audit-verified *read*, not permission.

Reuse the existing complete locally signed issuance fixture and SQLite ports.
Real native Pyodide/Worker/D1 JWT trust separation is checked by CI smoke.
"""
from __future__ import annotations

import asyncio
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

import test_host_signed_handoff as signed
from agentshield.approvals import SQLiteApprovalStore
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.gateway import app
from agentshield.identity import VerifiedAgent
from agentshield.local_service_evidence import (
    EvidenceUnavailable, read_local_handoff_evidence,
)
from agentshield.policy import Principal


class LocalEnv:
    def __init__(self, env):
        self.env = env

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["env"] = self.env
        await app(scope, receive, send)


class LocalServiceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fx = signed.SignedHandoffTests(
            "test_existing_d1_audit_proves_host_signed_one_use_handoff"
        )
        self.fx.setUp()
        self.command = self.fx.prepare()

    def tearDown(self):
        self.fx.tearDown()

    def read(self, *, tenant="ci_local", command=None):
        return asyncio.run(read_local_handoff_evidence(
            self.fx.store, self.fx.audit,
            tenant_id=tenant, command_id=command or self.command,
        ))

    def test_dispatch_without_source_issuance_is_not_a_token_authorization(self):
        before = self.fx.db.execute("SELECT count(*) FROM audit_events").fetchone()[0]
        result = self.read()
        self.assertTrue(result["dispatch_recorded"])
        self.assertFalse(result["issuance_recorded"])
        self.assertIsNone(result["token_sha256"])
        for key in ("execution_authorized", "transport_attested", "production_ready"):
            self.assertFalse(result[key])
        self.assertEqual(result["tenant_id"], "ci_local")
        self.assertEqual(self.fx.db.execute(
            "SELECT count(*) FROM audit_events"
        ).fetchone()[0], before)

    def test_issued_token_is_never_exposed_only_sha256(self):
        import hashlib
        token = self.fx.issue(self.command)
        result = self.read()
        self.assertTrue(result["issuance_recorded"])
        self.assertEqual(result["token_sha256"], hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, repr(result))
        self.assertNotIn("jti", str(result).lower())
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["transport_attested"])

    def test_tenant_confusion_and_invalid_command_disclose_no_evidence(self):
        for tenant, command in (
            ("other_tenant", self.command),
            ("ci_local", "local-command-" + "0" * 32),
            ("ci_local", "../operator"),
            ("ci_local", "local-command-" + "x" * 32),
        ):
            with self.subTest(tenant=tenant, command=command), self.assertRaises(
                EvidenceUnavailable
            ):
                self.read(tenant=tenant, command=command)

    def test_missing_canonical_dispatch_audit_fails_closed(self):
        row = self.fx.db.execute(
            "SELECT dispatch_audit_event_id FROM local_mock_dispatch_reservations"
        ).fetchone()
        self.fx.db.execute("DELETE FROM audit_events WHERE event_id=?",
                           (row["dispatch_audit_event_id"],))
        with self.assertRaises(AuditStorageError):
            self.read()

    def test_missing_signed_issuance_audit_fails_closed(self):
        self.fx.issue(self.command)
        audit_id = self.fx.db.execute(
            "SELECT audit_event_id FROM local_handoff_issuances"
        ).fetchone()[0]
        self.fx.db.execute("DELETE FROM audit_events WHERE event_id=?", (audit_id,))
        with self.assertRaises(AuditStorageError):
            self.read()

    @staticmethod
    def service(sub="local-host-reconciler", tenant="ci_local"):
        return VerifiedAgent(
            Principal(tenant + ":" + sub, frozenset({"handoff:evidence:read"})),
            tenant, sub, "service-ci-token", 1, 9999999999,
        )

    def http(self, *, local=True, sub="local-host-reconciler", storage=True):
        # Starlette TestClient serves ASGI in another thread. Clone the
        # SQLite evidence into a separate thread-capable, read-only test fixture.
        # The production D1 adapter has no such CPython thread constraint.
        http_db = sqlite3.connect(":memory:", check_same_thread=False)
        self.fx.db.backup(http_db)
        env = SimpleNamespace(
            LOCAL_SMOKE_ENABLED="true" if local else "false",
            DB=http_db if storage else None,
        )

        async def service_identity(_request, _kind, _scope):
            self.assertEqual((_kind, _scope), ("SERVICE", "handoff:evidence:read"))
            return self.service(sub=sub)

        def store_or_fail(db):
            if db is None:
                raise AuditStorageError("Local DB binding missing")
            return SQLiteApprovalStore(db)

        with patch("agentshield.gateway._verified_local_identity", service_identity):
            with patch("agentshield.gateway.D1ApprovalStore", store_or_fail):
                with patch("agentshield.gateway.D1AuditRepository", SQLiteAuditRepository):
                    try:
                        with TestClient(LocalEnv(env)) as client:
                            return client.get(
                                f"/_local/commands/{self.command}/service-evidence"
                            )
                    finally:
                        http_db.close()

    def test_http_is_service_only_and_always_returns_non_authorizing_response(self):
        response = self.http()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertTrue(response.json()["evidence_verified_locally"])
        self.assertFalse(response.json()["execution_authorized"])

    def test_http_wrong_service_subject_rejected(self):
        response = self.http(sub="human-reviewer")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("token_sha256", response.text)

    def test_http_disabled_local_flag_and_missing_d1_fail_closed(self):
        self.assertEqual(self.http(local=False).status_code, 404)
        self.assertEqual(self.http(storage=False).status_code, 503)


if __name__ == "__main__":
    unittest.main()
