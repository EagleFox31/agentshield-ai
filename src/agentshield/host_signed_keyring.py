"""Host-only offline operator signature for local Worker keyring updates.

This signer trust root is independent of the Worker attestation key.
No KMS, remote D1, network bootstrap or execution authority.
"""
from __future__ import annotations

import hashlib
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentshield.host_worker_attestation import AttestationRejected
from agentshield.host_worker_keyring import _unique_pairs, validate_local_worker_keyring
from agentshield.local_worker_evidence_attestation import canonical_bytes
from agentshield.webcrypto_es256_spike import _decode_url

SCHEMA = "agentshield.local.signed-keyring.v1"
OPERATOR_KID = "ci-local-offline-operator-v1"


def parse_signed_keyring(blob: bytes, operator_public_pem: bytes) -> tuple[int, bytes, str]:
    """Return generation, canonical signed envelope and pinned root digest."""
    try:
        if (not isinstance(blob, bytes) or not 100 <= len(blob) <= 9000
            or not isinstance(operator_public_pem, bytes)
            or not 100 <= len(operator_public_pem) <= 1024):
            raise ValueError("Invalid local trust update")
        key = serialization.load_pem_public_key(operator_public_pem)
        if (not isinstance(key, ec.EllipticCurvePublicKey)
            or not isinstance(key.curve, ec.SECP256R1)):
            raise ValueError("Invalid operator signing root")
        envelope = json.loads(
            blob.decode("ascii"), object_pairs_hook=_unique_pairs,
            parse_constant=lambda _v: (_ for _ in ()).throw(ValueError("Invalid constant")),
        )
        if (not isinstance(envelope, dict)
            or set(envelope) != {"schema", "operator_kid", "manifest", "signature"}
            or envelope["schema"] != SCHEMA
            or envelope["operator_kid"] != OPERATOR_KID
            or not isinstance(envelope["manifest"], dict)):
            raise ValueError("Wrong signed keyring schema")
        manifest = envelope["manifest"]
        validate_local_worker_keyring(
            canonical_bytes(manifest), minimum_generation=2,
        )
        raw = _decode_url(envelope["signature"], max_chars=100)
        if len(raw) != 64:
            raise ValueError("Invalid ES256 length")
        message = canonical_bytes({
            "schema": SCHEMA, "operator_kid": OPERATOR_KID, "manifest": manifest,
        })
        key.verify(
            utils.encode_dss_signature(
                int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"),
            ), message, ec.ECDSA(hashes.SHA256()),
        )
        public_der = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return (manifest["generation"], canonical_bytes(envelope),
                hashlib.sha256(public_der).hexdigest())
    except (ValueError, KeyError, TypeError, UnicodeError, InvalidSignature) as exc:
        raise AttestationRejected("Invalid offline operator signature") from exc
