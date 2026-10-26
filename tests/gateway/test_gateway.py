"""Local-only HTTP smoke tests with fake Worker/D1 bindings."""
import unittest
from types import SimpleNamespace

from fastapi.testclient import TestClient
from agentshield.gateway import app


class StubStatement:
    def __init__(self, db, query):
        self.db, self.query = db, query

    async def run(self):
        self.db.statements.append(self.query)
        return {"success": True}

    async def first(self):
        self.db.statements.append(self.query)
        return {"value": "ready"}


class StubD1:
    def __init__(self):
        self.statements = []

    def prepare(self, query):
        if "password" in query.lower():
            raise AssertionError("Unsafe query")
        return StubStatement(self, query)


class ScopeEnv:
    def __init__(self, env):
        self.env = env

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["env"] = self.env
        await app(scope, receive, send)


class GatewayTests(unittest.TestCase):
    def test_health_never_claims_enforcement_ready(self):
        with TestClient(app) as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json()["enforcement_ready"])
            self.assertFalse(response.json()["audit_ready"])

    def test_local_routes_default_to_not_found(self):
        with TestClient(app) as client:
            for path in ("/_local/policy", "/_local/d1-smoke"):
                response = client.post(
                    path,
                    json={"tool": "invoices", "operation": "read", "resource": "invoice/42"},
                )
                self.assertEqual(response.status_code, 404)

    def test_dev_policy_is_deterministic_and_never_executes(self):
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true"))) as client:
            allowed = client.post("/_local/policy", json={
                "tool": "invoices", "operation": "read", "resource": "invoice/42",
            })
            self.assertEqual(allowed.status_code, 200)
            self.assertEqual(allowed.json()["effect"], "allow")
            self.assertFalse(allowed.json()["executed"])
            denied = client.post("/_local/policy", json={
                "tool": "suppliers", "operation": "update_bank_account",
                "resource": "supplier/482",
            })
            self.assertEqual(denied.status_code, 200)
            self.assertEqual(denied.json()["effect"], "deny")
            self.assertFalse(denied.json()["executed"])
            self.assertEqual(denied.json()["reason_codes"], ["NO_MATCHING_POLICY"])

    def test_dev_route_does_not_accept_forged_identity_or_scopes(self):
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true"))) as client:
            response = client.post("/_local/policy", json={
                "tool": "invoices", "operation": "read", "resource": "invoice/42",
                "principal_id": "admin", "scopes": ["*"],
            })
            self.assertEqual(response.status_code, 422)

    def test_missing_d1_fails_closed(self):
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true"))) as client:
            response = client.post("/_local/d1-smoke")
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("Traceback", response.text)

    def test_d1_binding_smoke_uses_fixed_queries(self):
        db = StubD1()
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true", DB=db))) as client:
            response = client.post("/_local/d1-smoke")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["d1_local_probe"], "ok")
            self.assertFalse(response.json()["persistent_audit_ready"])
            self.assertEqual(len(db.statements), 3)

    def test_d1_binding_failure_returns_no_details(self):
        class BrokenD1:
            def prepare(self, query):
                raise RuntimeError("SECRET-DB-URL")
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true", DB=BrokenD1()))) as client:
            response = client.post("/_local/d1-smoke")
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("SECRET-DB-URL", response.text)

    def test_local_flag_must_be_explicit(self):
        for value in (None, "false", "1", True):
            with self.subTest(value=value), TestClient(
                ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED=value))
            ) as client:
                self.assertEqual(client.post("/_local/d1-smoke").status_code, 404)


if __name__ == "__main__":
    unittest.main()
