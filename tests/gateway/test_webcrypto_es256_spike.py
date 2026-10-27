"""ES256 WebCrypto signature-only spike; production JWT path is untouched."""
import base64
import json
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.webcrypto_es256_spike import prepare_es256_probe


def b64u(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()


class ES256ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = ec.generate_private_key(ec.SECP256R1())
        coords = cls.signer.public_key().public_numbers()
        cls.key = {
            "kid": "local-probe-key", "kty": "EC", "crv": "P-256",
            "alg": "ES256", "use": "sig", "key_ops": ["verify"],
            "x": b64u(coords.x), "y": b64u(coords.y),
        }
        cls.settings = {
            "AGENT_JWT_ISSUER": "https://identity.test.example",
            "AGENT_JWT_AUDIENCE": "urn:agentshield:agents",
            "AGENT_JWKS_JSON": json.dumps({"keys": [cls.key]}),
        }

    def token(self, *, issuer="https://identity.test.example", kid="local-probe-key"):
        now = int(time.time())
        return jwt.encode({
            "iss": issuer, "aud": "urn:agentshield:agents",
            "sub": "synthetic-agent", "scope": "invoice:read",
            "tenant_id": "ci_local", "jti": "test-token-12345",
            "iat": now - 1, "nbf": now - 1, "exp": now + 100,
        }, self.signer, algorithm="ES256", headers={"kid": kid})

    def test_prepare_canonical_es256_jws_and_p1363_signature(self):
        token = self.token()
        prepared = prepare_es256_probe(token, self.settings)
        self.assertEqual(len(prepared.raw_signature), 64)
        self.assertEqual(prepared.protected_input, token.rsplit(".", 1)[0].encode("ascii"))
        self.assertEqual(prepared.x, self.key["x"])

    def test_signature_primitive_is_not_claim_verification(self):
        # A token signed by our key with the WRONG issuer still prepares for
        # signature testing; claim validation must remain with trusted identity.py.
        token = self.token(issuer="https://wrong.example")
        self.assertEqual(len(prepare_es256_probe(token, self.settings).raw_signature), 64)

    def test_disallow_header_selected_remote_keys_wrong_alg_and_kid(self):
        token = self.token()
        h, p, s = token.split(".")
        variants = [
            self.token(kid="unknown"),
            jwt.encode({"x": 1}, "synthetic", algorithm="HS256",
                       headers={"kid": "local-probe-key"}),
            "none." + p + "." + s,
            h + "." + p + ".",
            h + "." + p + "." + s + "=",
            h + "." + p + "." + s[:-1],
        ]
        for variant in variants:
            with self.subTest(variant=variant[:25]), self.assertRaises((ValueError, KeyError, json.JSONDecodeError)):
                prepare_es256_probe(variant, self.settings)

    def test_reject_untrusted_header_extensions_and_duplicate_json(self):
        token = self.token()
        _, payload, sig = token.split(".")
        for header_text in [
            '{"alg":"ES256","kid":"local-probe-key","jku":"https://attacker.invalid"}',
            '{"alg":"ES256","alg":"ES256","kid":"local-probe-key"}',
            '{"alg":"none","kid":"local-probe-key"}',
        ]:
            header = base64.urlsafe_b64encode(header_text.encode()).rstrip(b"=").decode()
            with self.subTest(header=header_text), self.assertRaises(ValueError):
                prepare_es256_probe(header + "." + payload + "." + sig, self.settings)

    def test_invalid_jwk_coordinate_fails_before_ffi(self):
        settings = {**self.settings, "AGENT_JWKS_JSON": json.dumps({
            "keys": [{**self.key, "x": "AQ"}]})}
        with self.assertRaises(ValueError):
            prepare_es256_probe(self.token(), settings)


if __name__ == "__main__":
    unittest.main()
