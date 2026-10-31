"""LOCAL Worker-side asymmetric evidence attestation, NOT authorization.

Uses native Pyodide/WebCrypto P-256 signing only, ephemeral test key from
explicit local .dev.vars. No cryptography/PyJWT Worker dependency.
The signature is over a versioned, canonical and challenge-bound envelope.
"""
from __future__ import annotations

import base64
import json
import re
import time

from agentshield.webcrypto_es256_spike import _js_bytes

_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_KID = "ci-worker-evidence-v1"
_TYPE = "agentshield.local.d1-evidence.v1"
_TTL_MS = 10_000
_EVIDENCE_KEYS = frozenset({
    "command_id", "tenant_id", "state", "policy_version", "action_sha256",
    "dispatch_recorded", "issuance_recorded", "token_sha256",
    "evidence_verified_locally", "transport_attested",
    "execution_authorized", "external_network_used", "production_ready", "local_only",
})


class AttestationUnavailable(ValueError):
    """No valid local signer or challenge was configured."""


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def _private_jwk(value: str) -> dict:
    if not isinstance(value, str) or not 2 <= len(value) <= 2048:
        raise AttestationUnavailable("Local test signer missing")
    try:
        data = json.loads(value)
        if (not isinstance(data, dict)
            or set(data) != {"kty", "crv", "x", "y", "d"}
            or data["kty"] != "EC" or data["crv"] != "P-256"
            or any(not isinstance(data[k], str) or
                   re.fullmatch(r"[A-Za-z0-9_-]{43}", data[k]) is None
                   for k in ("x", "y", "d"))):
            raise ValueError("Signer cannot be trusted")
    except (ValueError, KeyError, TypeError) as exc:
        raise AttestationUnavailable("Invalid local signer") from exc
    return data


async def attest_local_evidence(
    evidence: dict, *, nonce: str, tenant: str, command: str, signer: str,
    now_ms: int | None = None,
) -> dict:
    """Sign verified D1 metadata AFTER authenticated SERVICE and D1 reads.

    Client challenge is 256-bit random and must match exact request. This
    gives fresh response-origin proof, not trusted tool execution or a
    production-managed identity. The signer must never sign arbitrary data.
    """
    if (not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None
        or not isinstance(evidence, dict) or set(evidence) != _EVIDENCE_KEYS
        or evidence.get("tenant_id") != tenant
        or evidence.get("command_id") != command
        or evidence.get("execution_authorized") is not False
        or evidence.get("production_ready") is not False
        or evidence.get("transport_attested") is not False
        or evidence.get("local_only") is not True
        or evidence.get("evidence_verified_locally") is not True):
        raise AttestationUnavailable("Invalid attestation request")
    key_fields = _private_jwk(signer)
    timestamp = int(time.time() * 1000) if now_ms is None else now_ms
    if type(timestamp) is not int or timestamp <= 0:
        raise AttestationUnavailable("Invalid signer clock")
    payload = {
        "type": _TYPE, "kid": _KID, "nonce": nonce,
        "issued_at_ms": timestamp,
        "expires_at_ms": timestamp + _TTL_MS,
        "evidence": evidence,
    }
    message = canonical_bytes(payload)
    if len(message) > 2048:
        raise AttestationUnavailable("Evidence too large")
    try:
        from js import Object, Uint8Array, crypto
        from pyodide.ffi import to_js

        js_object = lambda data: to_js(data, dict_converter=Object.fromEntries)
        imported_key = await crypto.subtle.importKey(
            "jwk",
            js_object({**key_fields, "key_ops": ["sign"], "ext": False}),
            js_object({"name": "ECDSA", "namedCurve": "P-256"}),
            False,
            to_js(["sign"]),
        )
        signed = await crypto.subtle.sign(
            js_object({"name": "ECDSA", "hash": "SHA-256"}),
            imported_key, _js_bytes(message, Uint8Array),
        )
        signature = bytes(signed.to_py())
        if len(signature) != 64:
            raise ValueError("Unexpected WebCrypto signature length")
    except Exception as exc:
        raise AttestationUnavailable("Worker local signer unavailable") from exc
    return {
        "payload": payload,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
