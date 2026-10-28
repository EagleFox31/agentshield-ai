"""Security regressions for trusted JWT agent identity.

Private keys are generated ephemerally in tests and never committed.
"""
import base64
import copy
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from agentshield.gateway import app
from agentshield.identity import (
    AgentAuthenticationError, IdentityConfigurationError,
    require_bearer, verify_agent_jwt,
)


def b64u(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()


class ScopeEnv:
    def __init__(self, settings: dict):
        self.env = SimpleNamespace(**settings)

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope["env"] = self.env
        await app(scope, receive, send)


async def host_only_test_oracle(authorization, settings):
    """CPython HTTP-contract fixture; real Worker CI uses native Web Crypto."""
    return require_bearer(authorization, settings)


class JwtIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = ec.generate_private_key(ec.SECP256R1())
        cls.other_signer = ec.generate_private_key(ec.SECP256R1())
        public = cls.signer.public_key().public_numbers()
        cls.public_jwk = {
            "kid": "agent-key-1", "kty": "EC", "crv": "P-256", "alg": "ES256",
            "use": "sig", "key_ops": ["verify"],
            "x": b64u(public.x), "y": b64u(public.y),
        }
        cls.settings = {
            "AGENT_JWT_ISSUER": "https://identity.test.example",
            "AGENT_JWT_AUDIENCE": "urn:agentshield:agents",
            "AGENT_JWKS_JSON": json.dumps({"keys": [cls.public_jwk]}, separators=(",", ":")),
        }

    def claims(self, **override):
        now = int(time.time())
        data = {
            "iss": "https://identity.test.example",
            "aud": "urn:agentshield:agents",
            "sub": "invoice-agent-1",
            "tenant_id": "tenant_01",
            "scope": "invoice:read supplier:lookup",
            "jti": "nonce123456789",
            "iat": now - 1, "nbf": now - 1, "exp": now + 180,
        }
        data.update(override)
        return data

    def token(self, claims=None, signer=None, **headers):
        return jwt.encode(
            claims if claims is not None else self.claims(),
            signer or self.signer,
            algorithm="ES256",
            headers={"kid": "agent-key-1", **headers},
        )

    def test_valid_token_constructs_tenant_bound_principal(self):
        result = verify_agent_jwt(self.token(), self.settings)
        self.assertEqual(result.principal.id, "tenant_01:invoice-agent-1")
        self.assertEqual(result.principal.scopes, frozenset({"invoice:read", "supplier:lookup"}))
        self.assertEqual(result.token_id, "nonce123456789")

    def test_authenticated_http_endpoint_never_executes_or_claims_ready(self):
        with patch("agentshield.gateway.require_bearer_webcrypto", new=host_only_test_oracle):
            with TestClient(ScopeEnv(self.settings)) as client:
                res = client.get("/v1/identity", headers={"Authorization": "Bearer " + self.token()})
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.json()["tenant_id"], "tenant_01")
                self.assertEqual(res.json()["agent_id"], "invoice-agent-1")
                self.assertFalse(res.json()["enforcement_ready"])
                self.assertFalse(res.json()["executed"])
                self.assertNotIn("jti", res.text)

    def test_native_worker_verifier_fails_closed_without_js_ffi(self):
        # No automatic fallback to patched host PyJWT on plain CPython.
        with TestClient(ScopeEnv(self.settings)) as client:
            res = client.get("/v1/identity", headers={
                "Authorization": "Bearer " + self.token(),
            })
            self.assertEqual(res.status_code, 401)
            self.assertNotIn("token", res.text.lower())

    def test_missing_verifier_or_token_fails_closed(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/v1/identity", headers={"Authorization": "Bearer " + self.token()}).status_code, 503)
        with TestClient(ScopeEnv(self.settings)) as client:
            res = client.get("/v1/identity")
            self.assertEqual(res.status_code, 401)
            self.assertEqual(res.headers["www-authenticate"], "Bearer")
            self.assertEqual(client.get("/v1/identity", headers={"Authorization": "basic 123"}).status_code, 401)

    def test_modified_signature_rejected(self):
        self.assertRaises(AgentAuthenticationError, verify_agent_jwt,
                          self.token(signer=self.other_signer), self.settings)

    def test_wrong_issuer_audience_missing_required_claims_and_expiry(self):
        for claims in [
            self.claims(iss="https://attacker.example"),
            self.claims(aud="urn:agentshield:other"),
            self.claims(exp=int(time.time()) - 30),
            self.claims(nbf=int(time.time()) + 300),
            self.claims(iat=int(time.time()) + 300),
            self.claims(exp=int(time.time()) + 800),
            self.claims(aud=["urn:agentshield:agents", "urn:agentshield:other"]),
        ]:
            with self.subTest(claims=claims):
                with self.assertRaises(AgentAuthenticationError):
                    verify_agent_jwt(self.token(claims), self.settings)
        for required in ["exp", "nbf", "iat", "sub", "iss", "aud", "scope", "tenant_id", "jti"]:
            claims = self.claims()
            del claims[required]
            with self.subTest(required=required), self.assertRaises(AgentAuthenticationError):
                verify_agent_jwt(self.token(claims), self.settings)

    def test_reject_forged_scopes_tenants_and_subs(self):
        for patch in [
            {"scope": "invoice:read *"},
            {"scope": "invoice:read invoice:read"},
            {"scope": "invoice:read  supplier:lookup"},
            {"scope": ""},
            {"scope": ["invoice:read", "admin"]},
            {"tenant_id": "../other"},
            {"tenant_id": ""},
            {"tenant_id": 27},
            {"sub": ""},
            {"sub": "admin/../secrets"},
            {"jti": "short"},
            {"jti": 5},
            {"exp": "not a timestamp"},
            {"iat": True},
        ]:
            with self.subTest(patch=patch), self.assertRaises(AgentAuthenticationError):
                verify_agent_jwt(self.token(self.claims(**patch)), self.settings)

    def test_bad_alg_header_and_key_selection_rejected(self):
        for headers in [
            {"kid": "unknown"},
            {"kid": "https://evil.example/key"},
            {"jku": "https://evil.example/keys.json"},
            {"crit": ["b64"]},
            {"jwk": self.public_jwk},
            {"typ": "JWE"},
        ]:
            with self.subTest(headers=headers), self.assertRaises(AgentAuthenticationError):
                verify_agent_jwt(self.token(**headers), self.settings)
        none_token = jwt.encode(self.claims(), key="", algorithm="none", headers={"kid": "agent-key-1"})
        with self.assertRaises(AgentAuthenticationError):
            verify_agent_jwt(none_token, self.settings)
        hs_token = jwt.encode(self.claims(), key="attacker-controlled-key-that-is-long-enough", algorithm="HS256", headers={"kid": "agent-key-1"})
        with self.assertRaises(AgentAuthenticationError):
            verify_agent_jwt(hs_token, self.settings)

    def test_malformed_keys_and_ambiguous_jwks_rejected(self):
        for invalid_jwks in [
            {"keys": []},
            {"keys": [self.public_jwk, self.public_jwk]},
            {"keys": [{**self.public_jwk, "alg": "HS256"}]},
            {"keys": [{**self.public_jwk, "d": "private-exposure"}]},
            {"keys": [{**self.public_jwk, "key_ops": ["sign"]}]},
            {"keys": [{**self.public_jwk, "jku": "https://attacker.example"}]},
        ]:
            settings = {**self.settings, "AGENT_JWKS_JSON": json.dumps(invalid_jwks)}
            with self.subTest(keys=invalid_jwks), self.assertRaises(IdentityConfigurationError):
                verify_agent_jwt(self.token(), settings)

    def test_safe_key_rotation(self):
        other = ec.generate_private_key(ec.SECP256R1())
        coords = other.public_key().public_numbers()
        second = {**self.public_jwk, "kid": "agent-key-2", "x": b64u(coords.x), "y": b64u(coords.y)}
        config = {**self.settings, "AGENT_JWKS_JSON": json.dumps({"keys": [self.public_jwk, second]})}
        rotated = self.token(signer=other, kid="agent-key-2")
        self.assertEqual(verify_agent_jwt(rotated, config).tenant_id, "tenant_01")
        removed = {**config, "AGENT_JWKS_JSON": json.dumps({"keys": [second]})}
        with self.assertRaises(AgentAuthenticationError):
            verify_agent_jwt(self.token(), removed)

    def test_incorrect_bearer_format_is_rejected(self):
        token = self.token()
        for bearer in ["bearer " + token, "Bearer  " + token, "Bearer " + token + " ", token]:
            with self.subTest(bearer=bearer[:14]), self.assertRaises(AgentAuthenticationError):
                require_bearer(bearer, self.settings)


if __name__ == "__main__":
    unittest.main()
