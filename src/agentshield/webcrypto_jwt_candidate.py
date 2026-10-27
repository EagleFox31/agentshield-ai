"""Candidate full ES256 JWT verifier for Python Workers — NOT active.

Reuses the already tested native Web Crypto signature port and the exact
claim-to-principal contract shared with the incumbent PyJWT verifier.
Never call claim parsing until the signature was verified successfully.

No production route, policy, approval or tool execution uses this candidate.
"""
from __future__ import annotations

import json
from typing import Mapping

from agentshield.identity import (
    AgentAuthenticationError, VerifiedAgent, _trust_store,
    validated_claims_to_agent,
)
from agentshield.webcrypto_es256_spike import (
    _decode_url, _unique_json_pairs, verify_es256_signature_webcrypto,
)


def _invalid_json_constant(value: str):
    raise ValueError("Nonstandard JSON constant")


async def verify_agent_jwt_webcrypto(
    token: str,
    settings: Mapping[str, str],
    *,
    now: int | None = None,
) -> VerifiedAgent:
    """Verify a signed compact JWS + all existing AgentShield JWT claims.

    Signature-only candidate is never accepted as authorization. A valid
    signature with wrong issuer, audience, scope or time MUST fail.
    """
    issuer, audience, _ = _trust_store(settings)
    try:
        if not await verify_es256_signature_webcrypto(token, dict(settings)):
            raise AgentAuthenticationError("Invalid agent bearer token")

        # Parse ONLY the payload that was checked by native Web Crypto.
        payload_encoded = token.split(".")[1]
        raw = _decode_url(payload_encoded, max_chars=7000)
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=_invalid_json_constant,
        )
        return validated_claims_to_agent(
            payload, issuer=issuer, audience=audience, now=now,
        )
    except AgentAuthenticationError:
        raise
    except (ValueError, UnicodeError, TypeError, IndexError, KeyError) as exc:
        # Never reveal JWT contents, public key material or JS stack traces.
        raise AgentAuthenticationError("Invalid agent bearer token") from exc


async def require_bearer_webcrypto(
    authorization: str | None,
    settings: Mapping[str, str],
    *,
    now: int | None = None,
) -> VerifiedAgent:
    """Same strict Bearer format, with async Worker crypto verification."""
    if not isinstance(authorization, str) or len(authorization) > 8199:
        raise AgentAuthenticationError("Bearer token required")
    if not authorization.startswith("Bearer ") or authorization.count(" ") != 1:
        raise AgentAuthenticationError("Bearer token required")
    return await verify_agent_jwt_webcrypto(
        authorization[7:], settings, now=now,
    )
