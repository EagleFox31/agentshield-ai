"""Trusted agent JWT verification for an isolated, policy-first security gateway.

Only a pinned local JWKS is accepted. The LLM, input body and JWT headers
cannot choose the issuer, accepted algorithm, remote JWKS URL or privileges.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Mapping

import jwt

from agentshield.policy import Principal


class AgentAuthenticationError(ValueError):
    """Untrusted or invalid bearer token; never include token contents."""


class IdentityConfigurationError(RuntimeError):
    """Missing/invalid verifier trust root; gateway must fail closed."""


@dataclass(frozen=True)
class VerifiedAgent:
    principal: Principal
    tenant_id: str
    agent_id: str
    token_id: str
    issued_at: int
    expires_at: int


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_KID = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
_SCOPE = re.compile(r"^[a-z][a-z0-9:_-]{0,95}$")
_JTI = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_ALLOWED_HEADER = {"typ", "alg", "kid"}
_REQUIRED_CLAIMS = [
    "iss", "aud", "sub", "exp", "iat", "nbf", "jti", "scope", "tenant_id",
]
_MAX_TOKEN_BYTES = 8192
_MAX_JWKS_BYTES = 32768


def _trust_store(settings: Mapping[str, str]) -> tuple[str, str, dict]:
    issuer = settings.get("AGENT_JWT_ISSUER", "")
    audience = settings.get("AGENT_JWT_AUDIENCE", "")
    raw = settings.get("AGENT_JWKS_JSON", "")
    if (
        not isinstance(issuer, str) or not issuer.startswith("https://")
        or len(issuer) > 256 or not isinstance(audience, str)
        or not audience or len(audience) > 200 or not audience.startswith("urn:agentshield:")
        or not isinstance(raw, str) or not (2 <= len(raw) <= _MAX_JWKS_BYTES)
    ):
        raise IdentityConfigurationError("Agent JWT trust configuration unavailable")
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise IdentityConfigurationError("Invalid trusted agent key set") from exc
    if not isinstance(data, dict) or set(data) != {"keys"} or not isinstance(data["keys"], list):
        raise IdentityConfigurationError("Invalid trusted agent key set")
    keys = data["keys"]
    if not (1 <= len(keys) <= 8):
        raise IdentityConfigurationError("Invalid trusted key count")
    lookup = {}
    for key in keys:
        if not isinstance(key, dict):
            raise IdentityConfigurationError("Invalid trusted signing key")
        kid = key.get("kid")
        if not isinstance(kid, str) or not _KID.fullmatch(kid) or kid in lookup:
            raise IdentityConfigurationError("Duplicate/invalid trusted key id")
        if (key.get("kty"), key.get("crv"), key.get("alg")) != ("EC", "P-256", "ES256"):
            raise IdentityConfigurationError("Unsupported trusted signing key")
        if key.get("use", "sig") != "sig" or key.get("key_ops", ["verify"]) != ["verify"]:
            raise IdentityConfigurationError("Trusted key is not verification-only")
        if not isinstance(key.get("x"), str) or not isinstance(key.get("y"), str):
            raise IdentityConfigurationError("Missing trusted signing key coordinates")
        # Unexpected remote URLs, private key fields, certificates or extensions
        # cannot influence which verification key is accepted.
        if set(key) - {"kid", "kty", "crv", "alg", "use", "key_ops", "x", "y"}:
            raise IdentityConfigurationError("Unexpected field in trusted key set")
        lookup[kid] = key
    return issuer, audience, lookup


def verify_agent_jwt(token: str, settings: Mapping[str, str], *, now: int | None = None) -> VerifiedAgent:
    """Validate ES256 signature AND purpose-bound claims; return verified scopes.

    JWT jti is retained for future durable one-time action consumption in #11.
    This function does *not* claim to prevent reuse of an access token.
    """
    issuer, audience, keys = _trust_store(settings)
    if (
        not isinstance(token, str) or not 32 <= len(token) <= _MAX_TOKEN_BYTES
        or any(ord(char) < 33 or ord(char) > 126 for char in token)
        or token.count(".") != 2
    ):
        raise AgentAuthenticationError("Invalid agent bearer token")

    try:
        header = jwt.get_unverified_header(token)
        if not isinstance(header, dict) or set(header) - _ALLOWED_HEADER:
            raise AgentAuthenticationError("Disallowed JWT header")
        kid = header.get("kid")
        if header.get("alg") != "ES256" or header.get("typ", "JWT") != "JWT":
            raise AgentAuthenticationError("Disallowed JWT algorithm/type")
        if not isinstance(kid, str) or not _KID.fullmatch(kid) or kid not in keys:
            raise AgentAuthenticationError("Unknown agent verification key")
        trusted_key = jwt.PyJWK.from_dict(keys[kid], algorithm="ES256").key
        payload = jwt.decode(
            token, key=trusted_key, algorithms=["ES256"],
            issuer=issuer, audience=audience,
            leeway=10,
            options={"require": _REQUIRED_CLAIMS, "strict_aud": True},
        )
    except AgentAuthenticationError:
        raise
    except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
        raise AgentAuthenticationError("Invalid agent bearer token") from exc

    current_time = int(time.time()) if now is None else now
    for name in ("exp", "iat", "nbf"):
        if type(payload.get(name)) is not int:
            raise AgentAuthenticationError("Invalid token time claims")
    issued, expiry, not_before = (payload[name] for name in ("iat", "exp", "nbf"))
    if (expiry <= current_time or not_before > current_time + 10
        or issued > current_time + 10 or issued > not_before + 10
        or expiry - issued > 300 or expiry <= not_before):
        raise AgentAuthenticationError("Invalid agent token lifetime")
    tenant = payload.get("tenant_id")
    subject = payload.get("sub")
    jti = payload.get("jti")
    scope_string = payload.get("scope")
    if (not isinstance(tenant, str) or not _TENANT.fullmatch(tenant)
        or not isinstance(subject, str) or not _NAME.fullmatch(subject)
        or not isinstance(jti, str) or not _JTI.fullmatch(jti)):
        raise AgentAuthenticationError("Invalid agent identity claims")
    if not isinstance(scope_string, str) or len(scope_string) > 1024:
        raise AgentAuthenticationError("Invalid agent scope")
    scopes = scope_string.split(" ")
    if (not 1 <= len(scopes) <= 24 or any(
        not _SCOPE.fullmatch(value) for value in scopes
    ) or len(set(scopes)) != len(scopes)):
        raise AgentAuthenticationError("Invalid agent scope")
    principal = Principal(f"{tenant}:{subject}", frozenset(scopes))
    return VerifiedAgent(principal, tenant, subject, jti, issued, expiry)


def require_bearer(authorization: str | None, settings: Mapping[str, str]) -> VerifiedAgent:
    if not isinstance(authorization, str) or len(authorization) > _MAX_TOKEN_BYTES + 7:
        raise AgentAuthenticationError("Bearer token required")
    # Exact format avoids ambiguities between proxies and HTTP middleware.
    if not authorization.startswith("Bearer ") or authorization.count(" ") != 1:
        raise AgentAuthenticationError("Bearer token required")
    return verify_agent_jwt(authorization[7:], settings)
