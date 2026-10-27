"""LOCAL-ONLY Web Crypto ES256 signature probe (not a JWT authenticator).

This spike reuses the *existing* pinned trust-store validation from identity.py.
It deliberately verifies signatures ONLY: it does not parse/validate claims,
issue VerifiedAgent, assign scopes, change approval or execute tools.

The production authorization path continues to use PyJWT until a complete
independently reviewed ES256 + claims implementation is approved.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

from agentshield.identity import _trust_store

_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_HEADER_KEYS = {"typ", "alg", "kid"}


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON field")
        result[name] = value
    return result


def _decode_url(value: str, *, max_chars: int) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= max_chars:
        raise ValueError("Invalid base64url segment length")
    if not _B64URL.fullmatch(value):
        raise ValueError("Invalid base64url alphabet")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Malformed base64url") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("Noncanonical base64url encoding")
    return raw


@dataclass(frozen=True)
class ES256Probe:
    protected_input: bytes
    raw_signature: bytes
    x: str
    y: str


def prepare_es256_probe(token: str, settings: dict[str, str]) -> ES256Probe:
    """Use a preconfigured JWKS; refuse header-supplied keys and algorithms."""
    _, _, trusted_keys = _trust_store(settings)
    if (not isinstance(token, str) or not 32 <= len(token) <= 8192
            or not token.isascii() or token.count(".") != 2):
        raise ValueError("Invalid compact JWS")
    header_b64, claims_b64, signature_b64 = token.split(".")
    header_raw = _decode_url(header_b64, max_chars=512)
    # The payload is NOT interpreted by this signature-only probe.
    _decode_url(claims_b64, max_chars=7000)
    signature = _decode_url(signature_b64, max_chars=128)
    if len(signature) != 64:
        raise ValueError("ES256 requires a 64-byte P1363 signature")
    header = json.loads(header_raw.decode("utf-8"), object_pairs_hook=_unique_json_pairs)
    if not isinstance(header, dict) or set(header) - _HEADER_KEYS:
        raise ValueError("Unexpected JOSE header")
    if header.get("alg") != "ES256" or header.get("typ", "JWT") != "JWT":
        raise ValueError("Unsupported JOSE algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in trusted_keys:
        raise ValueError("Untrusted key identifier")
    key = trusted_keys[kid]
    for coordinate in ("x", "y"):
        if len(_decode_url(key[coordinate], max_chars=48)) != 32:
            raise ValueError("Invalid P-256 coordinate")
    return ES256Probe(
        protected_input=(header_b64 + "." + claims_b64).encode("ascii"),
        raw_signature=signature,
        x=key["x"],
        y=key["y"],
    )


def _js_bytes(value: bytes, uint8array: object):
    """Explicit typed array conversion, no runtime-specific byte coercion."""
    result = uint8array.new(len(value))
    for index, byte in enumerate(value):
        result[index] = byte
    return result


async def verify_es256_signature_webcrypto(token: str, settings: dict[str, str]) -> bool:
    """Return only signature validity; all failures become False (fail closed).

    Local isolated compatibility probe; NOT suitable as authorization or JWT
    verification, because it does not validate issuer/audience/time/scopes.
    """
    try:
        probe = prepare_es256_probe(token, settings)
        # Import only in Pyodide/Cloudflare; CPython exercises parser separately.
        from js import Object, Uint8Array, crypto
        from pyodide.ffi import to_js

        def js_object(data: dict):
            return to_js(data, dict_converter=Object.fromEntries)

        key = await crypto.subtle.importKey(
            "jwk",
            js_object({"kty": "EC", "crv": "P-256",
                       "x": probe.x, "y": probe.y, "ext": False}),
            js_object({"name": "ECDSA", "namedCurve": "P-256"}),
            False,
            to_js(["verify"]),
        )
        valid = await crypto.subtle.verify(
            js_object({"name": "ECDSA", "hash": "SHA-256"}),
            key,
            _js_bytes(probe.raw_signature, Uint8Array),
            _js_bytes(probe.protected_input, Uint8Array),
        )
        return bool(valid)
    except Exception:
        # Do not reveal token text, key coordinates, JS exception or stack.
        return False
