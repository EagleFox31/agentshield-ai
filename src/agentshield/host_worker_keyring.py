"""HOST ONLY: provisioned, local Worker attestation key lifecycle (offline).

A trust manifest is an operator-provisioned LOCAL file, never fetched from
HTTP, D1, JWT, an agent or the model. It is NOT signed/KMS-backed, and cannot
prove production provenance. The host pins a minimum manifest generation.
"""
from __future__ import annotations

import json
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.host_worker_attestation import (
    AttestationRejected, verify_local_worker_attestation,
)

_SCHEMA = "agentshield.local.worker-keyring.v1"
_KID = re.compile(r"ci-worker-evidence-v[1-9][0-9]{0,2}\Z")
_ALLOWED = {"active", "retiring", "revoked"}
_KEYS = {"kid", "status", "not_before_ms", "not_after_ms", "public_key_pem"}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AttestationRejected("Duplicate trust manifest member")
        result[key] = value
    return result


def verify_rotating_worker_attestation(
    envelope: object, *, nonce: str, tenant: str, command: str,
    trusted_manifest_bytes: bytes, minimum_generation: int, now_ms: int,
) -> dict:
    """Verify exact signed evidence against preprovisioned active/retiring keys.

    Revocation applies immediately regardless of message signing time.
    A retiring key is accepted only while explicitly inside its local overlap
    window; a revoked or expired key cannot be revived by replaying old JSON.
    """
    try:
        if (not isinstance(trusted_manifest_bytes, bytes)
            or not 10 <= len(trusted_manifest_bytes) <= 7000
            or type(minimum_generation) is not int or minimum_generation < 1
            or type(now_ms) is not int or now_ms <= 0):
            raise AttestationRejected("Invalid local trust provisioning")
        manifest = json.loads(
            trusted_manifest_bytes.decode("ascii"), object_pairs_hook=_unique_pairs,
            parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("Bad JSON number")),
        )
        if (not isinstance(manifest, dict)
            or set(manifest) != {"schema", "generation", "keys"}
            or manifest["schema"] != _SCHEMA
            or type(manifest["generation"]) is not int
            or manifest["generation"] < minimum_generation
            or not isinstance(manifest["keys"], list)
            or not 1 <= len(manifest["keys"]) <= 4):
            raise AttestationRejected("Invalid or rolled-back trust manifest")
        trusted: dict[str, dict] = {}
        public_material = set()
        active = 0
        for record in manifest["keys"]:
            if not isinstance(record, dict) or set(record) != _KEYS:
                raise AttestationRejected("Unexpected key record")
            kid, state = record["kid"], record["status"]
            start, end = record["not_before_ms"], record["not_after_ms"]
            pem = record["public_key_pem"]
            if (not isinstance(kid, str) or not _KID.fullmatch(kid)
                or kid in trusted or state not in _ALLOWED
                or type(start) is not int or type(end) is not int
                or start <= 0 or end <= start
                or not isinstance(pem, str) or not 100 <= len(pem) <= 1024):
                raise AttestationRejected("Malformed or duplicate trust key")
            key = serialization.load_pem_public_key(pem.encode("ascii"))
            if (not isinstance(key, ec.EllipticCurvePublicKey)
                or not isinstance(key.curve, ec.SECP256R1)):
                raise AttestationRejected("Unexpected trusted public key family")
            fingerprint = key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if fingerprint in public_material:
                raise AttestationRejected("Same public key reused under different IDs")
            public_material.add(fingerprint)
            active += state == "active"
            trusted[kid] = record
        if active != 1:
            raise AttestationRejected("Must provision exactly one active key")
        if (not isinstance(envelope, dict)
            or not isinstance(envelope.get("payload"), dict)):
            raise AttestationRejected("Missing signed evidence")
        kid = envelope["payload"].get("kid")
        if not isinstance(kid, str) or kid not in trusted:
            raise AttestationRejected("Unknown signing key ID")
        entry = trusted[kid]
        if (entry["status"] == "revoked"
            or not entry["not_before_ms"] <= now_ms < entry["not_after_ms"]):
            raise AttestationRejected("Retired, revoked or inactive signing key")
        # The shared verifier enforces the 10-second attestation lifetime,
        # exact challenge and signed intent. No alternate crypto path.
        return verify_local_worker_attestation(
            envelope, nonce=nonce, tenant=tenant, command=command,
            trusted_public_key_pem=entry["public_key_pem"].encode("ascii"),
            now_ms=now_ms, expected_kid=kid,
        )
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise AttestationRejected("Local keyring verification refused") from exc
