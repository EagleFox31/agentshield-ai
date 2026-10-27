"""Claim-validation parity of candidate vs incumbent, not a crypto unit test.

Cryptography validity MUST separately pass the real Pyodide/Workers CI.
This suite mocks the crypto port only to isolate deterministic claim handling.
"""
import asyncio
import base64
import json
import time
import unittest
from unittest.mock import AsyncMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.identity import AgentAuthenticationError, verify_agent_jwt
from agentshield.webcrypto_jwt_candidate import (
    require_bearer_webcrypto, verify_agent_jwt_webcrypto,
)


def b64u(number):
    return base64.urlsafe_b64encode(number.to_bytes(32, "big")).rstrip(b"=").decode()


class CandidateClaimsParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        public = cls.key.public_key().public_numbers()
        cls.settings = {
            "AGENT_JWT_ISSUER": "https://identity.test.example",
            "AGENT_JWT_AUDIENCE": "urn:agentshield:agents",
            "AGENT_JWKS_JSON": json.dumps({"keys": [{
                "kid": "candidate-unit", "kty": "EC", "crv": "P-256",
                "alg": "ES256", "use": "sig", "key_ops": ["verify"],
                "x": b64u(public.x), "y": b64u(public.y),
            }]}),
        }

    def claims(self, **changes):
        now = int(time.time())
        value = {
            "iss": self.settings["AGENT_JWT_ISSUER"],
            "aud": self.settings["AGENT_JWT_AUDIENCE"],
            "sub": "agent-01", "tenant_id": "ci_local",
            "scope": "invoice:read supplier:lookup",
            "jti": "unique-test-jti-123", "iat": now - 1,
            "nbf": now - 1, "exp": now + 180,
        }
        return {**value, **changes}

    def signed(self, payload):
        return jwt.encode(
            payload, self.key, algorithm="ES256",
            headers={"kid": "candidate-unit"},
        )

    def candidate(self, token, *, signature=True):
        # An injected positive result does not certify a real signature!
        with patch("agentshield.webcrypto_jwt_candidate.verify_es256_signature_webcrypto",
                   new=AsyncMock(return_value=signature)):
            return asyncio.run(verify_agent_jwt_webcrypto(token, self.settings))

    def test_valid_principal_matches_pinned_pyjwt_verifier(self):
        token = self.signed(self.claims())
        reference = verify_agent_jwt(token, self.settings)
        candidate = self.candidate(token)
        self.assertEqual(candidate, reference)
        self.assertEqual(candidate.principal.scopes, frozenset({
            "invoice:read", "supplier:lookup",
        }))

    def test_bad_signature_never_reaches_claims(self):
        token = self.signed(self.claims())
        with self.assertRaises(AgentAuthenticationError):
            self.candidate(token, signature=False)

    def test_invalid_signed_claims_fail_even_with_signature(self):
        now = int(time.time())
        invalid = [
            {"iss": "https://wrong.example"},
            {"aud": "urn:agentshield:other"},
            {"aud": [self.settings["AGENT_JWT_AUDIENCE"]]},
            {"iat": now + 50}, {"nbf": now + 50},
            {"exp": now - 10}, {"exp": now + 1000},
            {"iat": True}, {"exp": "10000000"},
            {"scope": "*"}, {"scope": "invoice:read invoice:read"},
            {"scope": "invoice:read  supplier:lookup"},
            {"scope": []}, {"tenant_id": "../foreign"},
            {"sub": "../root"}, {"jti": "short"},
        ]
        for patch_claims in invalid:
            with self.subTest(claims=patch_claims):
                token = self.signed(self.claims(**patch_claims))
                with self.assertRaises(AgentAuthenticationError):
                    self.candidate(token)

    def test_missing_required_claims_fail(self):
        for name in ("iss", "aud", "sub", "exp", "iat", "nbf",
                     "tenant_id", "scope", "jti"):
            claims = self.claims()
            claims.pop(name)
            with self.subTest(missing=name), self.assertRaises(AgentAuthenticationError):
                self.candidate(self.signed(claims))

    def test_rejected_duplicate_payload_field_even_with_crypto_mock(self):
        token = self.signed(self.claims())
        header, _, sig = token.split(".")
        duplicate = (
            '{"iss":"https://identity.test.example","iss":"https://evil.example",'
            '"aud":"urn:agentshield:agents"}'
        )
        payload = base64.urlsafe_b64encode(duplicate.encode()).rstrip(b"=").decode()
        with self.assertRaises(AgentAuthenticationError):
            self.candidate(header + "." + payload + "." + sig)

    def test_strict_bearer_format(self):
        token = self.signed(self.claims())
        for raw in ("bearer " + token, "Bearer  " + token, "Bearer " + token + " ", token):
            with self.subTest(bearer=raw[:13]):
                with patch("agentshield.webcrypto_jwt_candidate.verify_es256_signature_webcrypto",
                           new=AsyncMock(return_value=True)):
                    with self.assertRaises(AgentAuthenticationError):
                        asyncio.run(require_bearer_webcrypto(raw, self.settings))


if __name__ == "__main__":
    unittest.main()
