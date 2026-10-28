"""Authenticated/local-only decision API: audit first, no execution token.

Test uses the independent host identity stub only for HTTP/policy behavior.
The real Pyodide/Worker CI signs agent ES256 JWTs and persists to local D1.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from agentshield.audit import AuditStorageError, action_digest
from agentshield.gateway import app
from agentshield.identity import VerifiedAgent
from agentshield.policy import Principal


class ScopeEnv:
    def __init__(self, env):
        self.env = env

    async def __call__(self, scope, receive, send):
        local = dict(scope)
        local["env"] = self.env
        await app(local, receive, send)


class RecordingAudit:
    def __init__(self, fail=False):
        self.events = []
        self.fail = fail

    async def record_event(self, event):
        if self.fail:
            raise AuditStorageError("simulated persistence failure")
        self.events.append(event)
        return True


class LocalDecisionAPITests(unittest.TestCase):
    def make_identity(self, scopes):
        async def verified(*_args):
            principal = Principal("tenant_01:invoice-agent", frozenset(scopes))
            return VerifiedAgent(principal, "tenant_01", "invoice-agent",
                                 "unit-token-12345", 1, 9_999_999_999)
        return verified

    def post(self, action, *, scopes=("invoice:read",), audit=None, enabled=True):
        store = audit if audit is not None else RecordingAudit()
        env = SimpleNamespace(LOCAL_SMOKE_ENABLED="true" if enabled else "false", DB=object())
        with patch("agentshield.gateway._verified_local_identity",
                   new=self.make_identity(scopes)):
            with patch("agentshield.gateway.D1AuditRepository", return_value=store):
                with TestClient(ScopeEnv(env)) as client:
                    response = client.post("/_local/decisions", json=action)
        return response, store

    def test_signed_read_allowed_only_after_redacted_audit(self):
        action = {"tool": "invoices", "operation": "read", "resource": "invoice/42"}
        response, store = self.post(action)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["effect"], "allow")
        self.assertEqual(data["reason_codes"], ["EXPLICIT_ALLOW"])
        self.assertEqual(len(store.events), 1)
        event = store.events[0]
        self.assertEqual(event.principal_id, "tenant_01:invoice-agent")
        self.assertEqual(event.effect, "allow")
        self.assertEqual(event.event_id, data["event_id"])
        self.assertEqual(event.action_digest, action_digest(**action))
        self.assertTrue(data["audit_recorded"])
        for key in ("execution_authorized", "executed", "enforcement_ready"):
            self.assertFalse(data[key])
        self.assertNotIn("invoice/42", event.canonical_payload())

    def test_unsigned_supplier_write_refused_and_recorded(self):
        action = {"tool": "suppliers", "operation": "update_bank_account",
                  "resource": "supplier/482"}
        response, store = self.post(action)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["effect"], "deny")
        self.assertEqual(response.json()["reason_codes"], ["REQUIRED_SCOPE_MISSING"])
        self.assertEqual(store.events[0].effect, "deny")
        self.assertFalse(response.json()["execution_authorized"])
        self.assertNotIn("supplier/482", store.events[0].canonical_payload())

    def test_signed_supplier_write_requires_human_review_not_execution(self):
        response, store = self.post(
            {"tool": "suppliers", "operation": "update_bank_account",
             "resource": "supplier/482"},
            scopes=("invoice:read", "supplier:write"),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["effect"], "require_approval")
        self.assertEqual(store.events[0].effect, "require_approval")
        self.assertFalse(response.json()["execution_authorized"])

    def test_unknown_action_default_denied_and_audited(self):
        response, store = self.post(
            {"tool": "cloud", "operation": "delete_bucket", "resource": "bucket/sample"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["effect"], "deny")
        self.assertEqual(response.json()["reason_codes"], ["NO_MATCHING_POLICY"])
        self.assertEqual(len(store.events), 1)

    def test_audit_failure_blocks_result_and_any_execution(self):
        response, store = self.post(
            {"tool": "invoices", "operation": "read", "resource": "invoice/42"},
            audit=RecordingAudit(fail=True),
        )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("allow", response.text)
        self.assertEqual(store.events, [])

    def test_invalid_or_privilege_forging_input_rejected_before_audit(self):
        store = RecordingAudit()
        samples = [
            {"tool": "invoices", "operation": "read", "resource": "invoice/42",
             "scopes": ["supplier:write"]},
            {"tool": "invoices", "operation": "read", "resource": "invoice/42",
             "tenant_id": "other_tenant"},
            {"tool": "invoices", "operation": "read", "resource": "invoice/42",
             "arguments": {"bank": "untrusted"}},
            {"tool": "invoices", "operation": "read", "resource": "../admin"},
        ]
        for payload in samples:
            with self.subTest(payload=payload):
                response, _ = self.post(payload, audit=store)
                self.assertEqual(response.status_code, 422)
        self.assertEqual(store.events, [])

    def test_local_route_hidden_without_flag(self):
        response, audit = self.post(
            {"tool": "invoices", "operation": "read", "resource": "invoice/42"},
            enabled=False,
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(audit.events, [])

    def test_missing_d1_binding_rejects_before_allow(self):
        env = SimpleNamespace(LOCAL_SMOKE_ENABLED="true")
        with patch("agentshield.gateway._verified_local_identity",
                   new=self.make_identity(("invoice:read",))):
            with TestClient(ScopeEnv(env)) as client:
                response = client.post("/_local/decisions", json={
                    "tool": "invoices", "operation": "read", "resource": "invoice/42",
                })
        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()
