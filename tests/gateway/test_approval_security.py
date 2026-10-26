"""Security boundaries for the local human approval UI and CLI."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from agentshield.gateway import app

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from approval_cli import api


class ScopeEnv:
    def __init__(self, env):
        self.env = env

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["env"] = self.env
        await app(scope, receive, send)


class ApprovalBoundaryTests(unittest.TestCase):
    def test_every_approval_route_disappears_without_local_flag(self):
        with TestClient(app) as client:
            for method, path in [
                ("GET", "/_local/dashboard"), ("GET", "/_local/approvals"),
                ("POST", "/_local/demo/approval-requests"),
                ("POST", "/_local/approvals/approval-example/approve"),
                ("POST", "/_local/demo/approvals/approval-example/consume"),
            ]:
                self.assertEqual(client.request(method, path).status_code, 404)

    def test_missing_operator_root_fails_closed(self):
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true"))) as client:
            self.assertEqual(
                client.get("/_local/approvals", headers={"Authorization": "Bearer invalid"}).status_code,
                503,
            )

    def test_local_dashboard_never_sets_auth_cookies(self):
        with TestClient(ScopeEnv(SimpleNamespace(LOCAL_SMOKE_ENABLED="true"))) as client:
            res = client.get("/_local/dashboard")
            self.assertEqual(res.status_code, 200)
            self.assertIn("frame-ancestors 'none'", res.headers["content-security-policy"])
            self.assertEqual(res.headers["cache-control"], "no-store")
            self.assertNotIn("set-cookie", res.headers)
            self.assertNotIn("localStorage", res.text)
            self.assertIn("Human review", res.text)

    def test_cli_rejects_remote_destinations_and_credentialed_urls(self):
        for base in (
            "https://example.com", "http://evil.example",
            "http://user:password@127.0.0.1:8787",
            "http://127.0.0.1:8787/redirect", "http://127.0.0.1:8787?token=secret",
            "file:///etc/passwd",
        ):
            with self.subTest(base=base), self.assertRaises(ValueError):
                api(base, "ephemeral-sample", "/_local/approvals")


if __name__ == "__main__":
    unittest.main()
