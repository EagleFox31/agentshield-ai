"""Create throwaway local JWT fixtures; never provisions/contacts an issuer.

For CI's **local** Pywrangler process only. Generates a fresh EC signing key
in memory, writes public JWK configuration and short-lived test tokens.
"""
from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / ".local-jwt"
ISSUER = "https://identity.test.example"
AUDIENCE = "urn:agentshield:agents"


def b64u(value: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode("ascii")


def main() -> None:
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    n = signer.public_key().public_numbers()
    public_jwk = {
        "kid": "ci-ephemeral-key-1", "kty": "EC", "crv": "P-256",
        "alg": "ES256", "use": "sig", "key_ops": ["verify"],
        "x": b64u(n.x), "y": b64u(n.y),
    }
    now = int(time.time())
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": "local-demo-agent",
        "tenant_id": "ci_local", "scope": "invoice:read",
        "iat": now - 1, "nbf": now - 1, "exp": now + 240,
        "jti": "ephemeral-ci-token-123",
    }
    OUTPUT.mkdir(exist_ok=True)
    tokens = {
        "valid": jwt.encode(claims, signer, algorithm="ES256", headers={"kid": "ci-ephemeral-key-1"}),
        "bad_signature": jwt.encode(claims, other, algorithm="ES256", headers={"kid": "ci-ephemeral-key-1"}),
        "wrong_audience": jwt.encode(
            {**claims, "aud": "urn:agentshield:other"},
            signer, algorithm="ES256", headers={"kid": "ci-ephemeral-key-1"},
        ),
        "expired": jwt.encode(
            {**claims, "iat": now - 600, "nbf": now - 600, "exp": now - 300},
            signer, algorithm="ES256", headers={"kid": "ci-ephemeral-key-1"},
        ),
    }
    for name, token in tokens.items():
        (OUTPUT / f"{name}.txt").write_text(token, encoding="utf-8")
    jwks = json.dumps({"keys": [public_jwk]}, separators=(",", ":"))
    (ROOT / ".dev.vars").write_text(
        "LOCAL_SMOKE_ENABLED=true\n"
        f'AGENT_JWT_ISSUER="{ISSUER}"\n'
        f'AGENT_JWT_AUDIENCE="{AUDIENCE}"\n'
        f"AGENT_JWKS_JSON='{jwks}'\n",
        encoding="utf-8",
    )
    print("Prepared ephemeral ES256 fixtures and local-only public JWK configuration.")


if __name__ == "__main__":
    main()
