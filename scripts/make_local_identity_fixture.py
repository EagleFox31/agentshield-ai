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
from cryptography.hazmat.primitives import serialization


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
    # Second explicitly approved agent key proves native JWKS rotation.
    rotated_signer = ec.generate_private_key(ec.SECP256R1())
    rotated_coords = rotated_signer.public_key().public_numbers()
    rotated_public_jwk = {
        **public_jwk, "kid": "ci-ephemeral-key-2",
        "x": b64u(rotated_coords.x), "y": b64u(rotated_coords.y),
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
    # Negative signed-claims fixtures for the full WebCrypto candidate.
    # Signatures are VALID; claim validation, not crypto, must reject them.
    candidate_invalid_claims = {
        "wrong_issuer": {**claims, "iss": "https://attacker.test.example"},
        "future_claims": {**claims, "iat": now + 400,
                          "nbf": now + 400, "exp": now + 590},
        "invalid_scope": {**claims, "scope": "invoice:read *"},
        "invalid_tenant": {**claims, "tenant_id": "../other"},
        "audience_list": {**claims, "aud": [
            AUDIENCE, "urn:agentshield:other",
        ]},
        "missing_jti": {k: v for k, v in claims.items() if k != "jti"},
    }
    for name, invalid_claims in candidate_invalid_claims.items():
        tokens[name] = jwt.encode(
            invalid_claims, signer, algorithm="ES256",
            headers={"kid": "ci-ephemeral-key-1"},
        )
    tokens["rotated_valid"] = jwt.encode(
        {**claims, "jti": "rotated-ci-token-123"},
        rotated_signer, algorithm="ES256",
        headers={"kid": "ci-ephemeral-key-2"},
    )
    tokens["unknown_kid"] = jwt.encode(
        claims, other, algorithm="ES256",
        headers={"kid": "untrusted-agent-key"},
    )
    # Separate issuer, audience and public signing key for the human.
    operator_signer = ec.generate_private_key(ec.SECP256R1())
    operator_coords = operator_signer.public_key().public_numbers()
    operator_public_jwk = {
        "kid": "ci-operator-key-1", "kty": "EC", "crv": "P-256",
        "alg": "ES256", "use": "sig", "key_ops": ["verify"],
        "x": b64u(operator_coords.x), "y": b64u(operator_coords.y),
    }
    operator_issuer = "https://operators.test.example"
    operator_audience = "urn:agentshield:operators"
    operator_claims = {
        **claims, "iss": operator_issuer, "aud": operator_audience,
        "sub": "reviewer-01", "scope": "approvals:read approvals:decide policies:activate commands:claim commands:reconcile",
        "jti": "operator-ci-token-123",
    }
    tokens["approval_agent"] = jwt.encode(
        {**claims, "scope": "invoice:read supplier:write",
         "jti": "approval-agent-token-123"},
        signer, algorithm="ES256", headers={"kid": "ci-ephemeral-key-1"},
    )
    tokens["operator_valid"] = jwt.encode(
        operator_claims, operator_signer, algorithm="ES256",
        headers={"kid": "ci-operator-key-1"},
    )
    tokens["operator_readonly"] = jwt.encode(
        {**operator_claims, "scope": "approvals:read",
         "jti": "operator-readonly-token-123"},
        operator_signer, algorithm="ES256",
        headers={"kid": "ci-operator-key-1"},
    )

    # Independent ephemeral service issuer: no agent or operator credential is trusted.
    service_signer = ec.generate_private_key(ec.SECP256R1())
    service_coords = service_signer.public_key().public_numbers()
    service_jwk = {
        **public_jwk, "kid": "ci-host-service-key-1",
        "x": b64u(service_coords.x), "y": b64u(service_coords.y),
    }
    service_issuer = "https://services.test.example"
    service_audience = "urn:agentshield:host-evidence"
    service_claims = {
        **claims, "iss": service_issuer, "aud": service_audience,
        "sub": "local-host-reconciler", "scope": "handoff:evidence:read",
        "jti": "service-evidence-ci-token-123",
    }
    tokens["service_evidence"] = jwt.encode(
        service_claims, service_signer, algorithm="ES256",
        headers={"kid": "ci-host-service-key-1"},
    )
    tokens["service_no_scope"] = jwt.encode(
        {**service_claims, "scope": "invoice:read", "jti": "service-no-scope-123"},
        service_signer, algorithm="ES256", headers={"kid": "ci-host-service-key-1"},
    )
    tokens["service_other_tenant"] = jwt.encode(
        {**service_claims, "tenant_id": "other_tenant", "jti": "service-other-tenant-123"},
        service_signer, algorithm="ES256", headers={"kid": "ci-host-service-key-1"},
    )
    tokens["service_wrong_signer"] = jwt.encode(
        service_claims, signer, algorithm="ES256",
        headers={"kid": "ci-host-service-key-1"},
    )

    for name, token in tokens.items():
        (OUTPUT / f"{name}.txt").write_text(token, encoding="utf-8")
    jwks = json.dumps({"keys": [public_jwk, rotated_public_jwk]}, separators=(",", ":"))
    operator_jwks = json.dumps({"keys": [operator_public_jwk]}, separators=(",", ":"))
    service_jwks = json.dumps({"keys": [service_jwk]}, separators=(",", ":"))
    # Distinct ephemeral Worker evidence signer. This PRIVATE test key only
    # enters ignored .dev.vars, never Git or the D1 database. The host pins
    # the separately exported PUBLIC PEM, not a public key from HTTP output.
    worker_attestor = ec.generate_private_key(ec.SECP256R1())
    p = worker_attestor.private_numbers()
    coords = p.public_numbers
    worker_attestor_jwk = json.dumps({
        "kty": "EC", "crv": "P-256", "x": b64u(coords.x),
        "y": b64u(coords.y), "d": b64u(p.private_value),
    }, separators=(",", ":"))
    (OUTPUT / "worker-evidence-public.pem").write_bytes(
        worker_attestor.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    (ROOT / ".dev.vars").write_text(
        "LOCAL_SMOKE_ENABLED=true\n"
        f'AGENT_JWT_ISSUER="{ISSUER}"\n'
        f'AGENT_JWT_AUDIENCE="{AUDIENCE}"\n'
        f"AGENT_JWKS_JSON='{jwks}'\n"
        f'OPERATOR_JWT_ISSUER="{operator_issuer}"\n'
        f'OPERATOR_JWT_AUDIENCE="{operator_audience}"\n'
        f"OPERATOR_JWKS_JSON='{operator_jwks}'\n"
        f'SERVICE_JWT_ISSUER="{service_issuer}"\n'
        f'SERVICE_JWT_AUDIENCE="{service_audience}"\n'
        f"SERVICE_JWKS_JSON='{service_jwks}'\n"
        f"LOCAL_WORKER_ATTEST_PRIVATE_JWK='{worker_attestor_jwk}'\\n",
        encoding="utf-8",
    )
    print("Prepared ephemeral ES256 fixtures and local-only public JWK configuration.")


if __name__ == "__main__":
    main()
