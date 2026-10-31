"""HOST ONLY: independently pin and verify Worker-signed LOCAL D1 evidence.

Signature proves the payload came from the ephemeral test signer *if* the
pinned key was provisioned securely. It is NOT a production remote-D1 trust
root, tool authorization, source-completeness proof or execution grant.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentshield.local_worker_evidence_attestation import canonical_bytes
from agentshield.webcrypto_es256_spike import _decode_url

_TYPE = "agentshield.local.d1-evidence.v1"
_KID = "ci-worker-evidence-v1"
_EVIDENCE_FIELDS = {
    "command_id", "tenant_id", "state", "policy_version", "action_sha256",
    "dispatch_recorded", "issuance_recorded", "token_sha256",
    "evidence_verified_locally", "transport_attested",
    "execution_authorized", "external_network_used", "production_ready",
    "local_only",
}


class AttestationRejected(ValueError):
    """Missing, altered, stale or replayed local Worker source proof."""


def verify_local_worker_attestation(
    envelope: object, *, nonce: str, tenant: str, command: str,
    trusted_public_key_pem: bytes, now_ms: int,
) -> dict:
    """Verify fresh, exact challenge/tenant/command and a pinned ES256 proof.

    Challenge MUST be generated anew by the caller, never reused or obtained
    from the untrusted response. Neither this function nor the signed data
    ever authorizes or invokes external tools.
    """
    try:
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise AttestationRejected("Unexpected attestation envelope")
        payload, signature = envelope["payload"], envelope["signature"]
        if not isinstance(payload, dict) or set(payload) != {
            "type", "kid", "nonce", "issued_at_ms", "expires_at_ms", "evidence",
        }:
            raise AttestationRejected("Unexpected signed claim schema")
        if (payload["type"] != _TYPE or payload["kid"] != _KID
            or payload["nonce"] != nonce or type(now_ms) is not int
            or type(payload["issued_at_ms"]) is not int
            or type(payload["expires_at_ms"]) is not int
            or not (payload["issued_at_ms"] - 1000 <= now_ms
                    <= payload["expires_at_ms"])
            or payload["expires_at_ms"] - payload["issued_at_ms"] != 10000):
            raise AttestationRejected("Wrong challenge/clock/source")
        evidence = payload["evidence"]
        if (not isinstance(evidence, dict) or set(evidence) != _EVIDENCE_FIELDS
            or evidence["tenant_id"] != tenant or evidence["command_id"] != command
            or evidence["state"] not in ("queued", "claimed", "uncertain")
            or not isinstance(evidence["policy_version"], str)
            or not isinstance(evidence["action_sha256"], str)
            or len(evidence["action_sha256"]) != 64
            or any(type(evidence[name]) is not bool for name in (
                "dispatch_recorded", "issuance_recorded",
                "evidence_verified_locally", "transport_attested",
                "execution_authorized", "external_network_used",
                "production_ready", "local_only"
            ))
            or evidence["evidence_verified_locally"] is not True
            or evidence["transport_attested"] is not False
            or evidence["execution_authorized"] is not False
            or evidence["external_network_used"] is not False
            or evidence["production_ready"] is not False
            or evidence["local_only"] is not True
            or (evidence["token_sha256"] is None) != (
                evidence["issuance_recorded"] is False)):
            raise AttestationRejected("Invalid signed evidence scope")
        signed_message = canonical_bytes(payload)
        if len(signed_message) > 2048:
            raise AttestationRejected("Oversized signed payload")
        sig = _decode_url(signature, max_chars=100)
        if len(sig) != 64:
            raise AttestationRejected("Invalid raw ES256 signature")
        if not isinstance(trusted_public_key_pem, bytes) or len(trusted_public_key_pem) > 1024:
            raise AttestationRejected("Invalid pinned public key")
        key = serialization.load_pem_public_key(trusted_public_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise AttestationRejected("Wrong pinned algorithm")
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        key.verify(utils.encode_dss_signature(r, s), signed_message, ec.ECDSA(hashes.SHA256()))
        return evidence
    except (ValueError, KeyError, TypeError, UnicodeError, InvalidSignature) as exc:
        raise AttestationRejected("Local signed Worker evidence rejected") from exc
