"""Independent, pure Python v1 Merkle verification for redacted AuditEvents.

No network, Worker, wallet, EVM calls, data storage or dependency on the
database adapter. IMPORTANT: a self-generated manifest is not proof that
history is complete or independently anchored. A trusted commitment must
be acquired outside the database to verify historical integrity.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping, Sequence

from agentshield.audit import AuditEvent

_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ZERO = "0" * 64
_VERSION = "agentshield.merkle.v1"
_LEAF_DOMAIN = b"AgentShield/Merkle/leaf/v1\x00"
_NODE_DOMAIN = b"AgentShield/Merkle/node/v1\x00"
_ANCHOR_DOMAIN = b"AgentShield/Merkle/commitment/v1\x00"
_KEYS = {
    "version", "tenant_id", "batch_id", "sequence", "previous_commitment",
    "created_at_ms", "count", "entries", "tree_root", "manifest_sha256",
    "commitment",
}
_ENTRY_KEYS = {"event_id", "event_sha256", "occurred_at_ms"}
_MAX_EVENTS = 4096


class InvalidEvidence(ValueError):
    """Malformed, falsified, incomplete or untrusted evidence."""


def _sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _digest(value: str) -> bytes:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise InvalidEvidence("Expected lowercase SHA-256 hex")
    return bytes.fromhex(value)


def _json(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _leaf(fingerprint: str, index: int) -> bytes:
    if not 0 <= index < _MAX_EVENTS:
        raise InvalidEvidence("Invalid Merkle leaf index")
    return _sha(_LEAF_DOMAIN + index.to_bytes(4, "big") + _digest(fingerprint))


def _node(left: bytes, right: bytes) -> bytes:
    return _sha(_NODE_DOMAIN + left + right)


def _levels(fingerprints: Sequence[str]) -> list[list[bytes]]:
    if not 1 <= len(fingerprints) <= _MAX_EVENTS:
        raise InvalidEvidence("Merkle batch size must be 1 to 4096")
    levels = [[_leaf(fp, i) for i, fp in enumerate(fingerprints)]]
    while len(levels[-1]) > 1:
        old = levels[-1]
        levels.append([
            _node(old[i], old[i + 1] if i + 1 < len(old) else old[i])
            for i in range(0, len(old), 2)
        ])
    return levels


def _event_key(event: AuditEvent) -> tuple[int, str]:
    return event.occurred_at_ms, event.event_id


def build_manifest(
    events: Sequence[AuditEvent], *,
    tenant_id: str, batch_id: str, created_at_ms: int,
    sequence: int = 0, previous_commitment: str = _ZERO,
) -> dict:
    """Build deterministic, immutable-in-content OFF-CHAIN evidence metadata.

    Batch IDs and sequence numbers are caller-assigned; coordination of batch
    creation across distributed D1 writers is deliberately out of scope.
    """
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise InvalidEvidence("Invalid tenant")
    if not isinstance(batch_id, str) or not _ID.fullmatch(batch_id):
        raise InvalidEvidence("Invalid batch ID")
    if type(sequence) is not int or not 0 <= sequence < 1_000_000_000:
        raise InvalidEvidence("Invalid sequence")
    _digest(previous_commitment)
    if (sequence == 0) != (previous_commitment == _ZERO):
        raise InvalidEvidence("Initial batch must have zero predecessor; others need a predecessor")
    if type(created_at_ms) is not int or created_at_ms <= 0:
        raise InvalidEvidence("Invalid creation timestamp")
    if not isinstance(events, (list, tuple)) or not 1 <= len(events) <= _MAX_EVENTS:
        raise InvalidEvidence("Invalid event count")
    if any(not isinstance(event, AuditEvent) or event.tenant_id != tenant_id for event in events):
        raise InvalidEvidence("Cross-tenant or invalid event")
    ordered = sorted(events, key=_event_key)
    ids = [event.event_id for event in ordered]
    if len(ids) != len(set(ids)):
        raise InvalidEvidence("Duplicate event ID")
    if ordered[-1].occurred_at_ms > created_at_ms:
        raise InvalidEvidence("Cannot batch events from the future")
    entries = [
        {"event_id": event.event_id, "event_sha256": event.fingerprint,
         "occurred_at_ms": event.occurred_at_ms}
        for event in ordered
    ]
    root = _levels([item["event_sha256"] for item in entries])[-1][0].hex()
    payload = {
        "version": _VERSION, "tenant_id": tenant_id,
        "batch_id": batch_id, "sequence": sequence,
        "previous_commitment": previous_commitment,
        "created_at_ms": created_at_ms, "count": len(entries),
        "entries": entries, "tree_root": root,
    }
    manifest_hash = _sha(_json(payload)).hex()
    commitment = _sha(_ANCHOR_DOMAIN + _digest(manifest_hash)).hex()
    return {**payload, "manifest_sha256": manifest_hash, "commitment": commitment}


def validate_manifest(manifest: Mapping, *, trusted_commitment: str | None = None) -> str:
    """Verify a manifest's internal hashes and optional INDEPENDENT commitment.

    Return consistent_unanchored without an external reference. Never treat
    a caller-supplied commitment copied from the same manifest as independent.
    """
    if not isinstance(manifest, dict) or set(manifest) != _KEYS:
        raise InvalidEvidence("Invalid manifest shape")
    if manifest["version"] != _VERSION:
        raise InvalidEvidence("Unsupported evidence version")
    tenant, batch = manifest["tenant_id"], manifest["batch_id"]
    if not isinstance(tenant, str) or not _TENANT.fullmatch(tenant):
        raise InvalidEvidence("Invalid batch tenant")
    if not isinstance(batch, str) or not _ID.fullmatch(batch):
        raise InvalidEvidence("Invalid batch identifier")
    seq, count, timestamp = manifest["sequence"], manifest["count"], manifest["created_at_ms"]
    if type(seq) is not int or not 0 <= seq < 1_000_000_000:
        raise InvalidEvidence("Invalid batch sequence")
    if type(count) is not int or not 1 <= count <= _MAX_EVENTS:
        raise InvalidEvidence("Invalid entry count")
    if type(timestamp) is not int or timestamp <= 0:
        raise InvalidEvidence("Invalid manifest timestamp")
    prior = manifest["previous_commitment"]
    _digest(prior)
    if (seq == 0) != (prior == _ZERO):
        raise InvalidEvidence("Invalid chain predecessor")
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != count:
        raise InvalidEvidence("Missing or extra batch entries")
    checked = []
    ids = set()
    for item in entries:
        if not isinstance(item, dict) or set(item) != _ENTRY_KEYS:
            raise InvalidEvidence("Invalid batch entry")
        identifier = item["event_id"]
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or identifier in ids:
            raise InvalidEvidence("Duplicate/invalid event identifier")
        ids.add(identifier)
        _digest(item["event_sha256"])
        at = item["occurred_at_ms"]
        if type(at) is not int or not 0 < at <= timestamp:
            raise InvalidEvidence("Invalid event timestamp")
        checked.append((at, identifier))
    if checked != sorted(checked):
        raise InvalidEvidence("Reordered batch entries")
    expected_tree = _levels([item["event_sha256"] for item in entries])[-1][0].hex()
    if expected_tree != manifest["tree_root"]:
        raise InvalidEvidence("Merkle root mismatch")
    payload = {k: manifest[k] for k in _KEYS - {"manifest_sha256", "commitment"}}
    expected_hash = _sha(_json(payload)).hex()
    if expected_hash != manifest["manifest_sha256"]:
        raise InvalidEvidence("Manifest hash mismatch")
    expected_commitment = _sha(_ANCHOR_DOMAIN + _digest(expected_hash)).hex()
    if expected_commitment != manifest["commitment"]:
        raise InvalidEvidence("Batch commitment mismatch")
    if trusted_commitment is not None:
        if _digest(trusted_commitment).hex() != expected_commitment:
            raise InvalidEvidence("Independent commitment disagrees with batch")
        return "matches_supplied_trust_root"
    return "consistent_unanchored"


def inclusion_path(manifest: Mapping, event_id: str) -> dict:
    """Create a deterministic Merkle path without accessing original plaintext."""
    validate_manifest(manifest)
    entries = manifest["entries"]
    indexes = [i for i, entry in enumerate(entries) if entry["event_id"] == event_id]
    if len(indexes) != 1:
        raise InvalidEvidence("Event not present in committed batch")
    index = indexes[0]
    levels = _levels([entry["event_sha256"] for entry in entries])
    position = index
    siblings = []
    for nodes in levels[:-1]:
        sibling = position ^ 1
        if sibling >= len(nodes):
            sibling = position
        siblings.append({"side": "left" if position & 1 else "right",
                         "sha256": nodes[sibling].hex()})
        position //= 2
    return {"version": _VERSION, "event_id": event_id, "leaf_index": index,
            "leaf_count": len(entries), "siblings": siblings}


def verify_inclusion(
    event: AuditEvent, manifest: Mapping, proof: Mapping,
    *, trusted_commitment: str,
) -> bool:
    """Validate full independent commitment AND a single event's path."""
    validate_manifest(manifest, trusted_commitment=trusted_commitment)
    if not isinstance(event, AuditEvent):
        raise InvalidEvidence("Invalid audit event")
    if (not isinstance(proof, dict) or
        set(proof) != {"version", "event_id", "leaf_index", "leaf_count", "siblings"}):
        raise InvalidEvidence("Invalid proof shape")
    index, width = proof["leaf_index"], proof["leaf_count"]
    if (proof["version"] != _VERSION or proof["event_id"] != event.event_id
        or type(index) is not int or type(width) is not int or
        not 0 <= index < width or width != manifest["count"] or
        event.tenant_id != manifest["tenant_id"] or
        manifest["entries"][index] != {
            "event_id": event.event_id, "event_sha256": event.fingerprint,
            "occurred_at_ms": event.occurred_at_ms,
        }):
        raise InvalidEvidence("Event identity or position mismatch")
    digest = _leaf(event.fingerprint, index)
    siblings = proof["siblings"]
    if not isinstance(siblings, list):
        raise InvalidEvidence("Invalid Merkle path")
    position = index
    for sibling in siblings:
        if width <= 1 or not isinstance(sibling, dict) or set(sibling) != {"side", "sha256"}:
            raise InvalidEvidence("Unexpected Merkle level")
        right = not (position % 2)
        if sibling["side"] != ("right" if right else "left"):
            raise InvalidEvidence("Incorrect sibling orientation")
        neighbour = _digest(sibling["sha256"])
        if right and position + 1 >= width and neighbour != digest:
            raise InvalidEvidence("Invalid odd-leaf duplication")
        digest = _node(digest, neighbour) if right else _node(neighbour, digest)
        position //= 2
        width = (width + 1) // 2
    if width != 1 or digest.hex() != manifest["tree_root"]:
        raise InvalidEvidence("Merkle inclusion verification failed")
    return True


def verify_complete_batch(
    events: Sequence[AuditEvent], manifest: Mapping,
    *, trusted_commitment: str,
) -> bool:
    """Detect missing, modified, inserted or reordered events within a pinned batch."""
    validate_manifest(manifest, trusted_commitment=trusted_commitment)
    if not isinstance(events, (list, tuple)):
        raise InvalidEvidence("Batch events missing")
    observed = [
        {"event_id": e.event_id, "event_sha256": e.fingerprint,
         "occurred_at_ms": e.occurred_at_ms}
        for e in events if isinstance(e, AuditEvent) and e.tenant_id == manifest["tenant_id"]
    ]
    if len(observed) != len(events) or observed != manifest["entries"]:
        raise InvalidEvidence("Batch coverage or ordering violated")
    return True


def verify_manifest_chain(manifests: Sequence[Mapping], *, trusted_head: str) -> bool:
    """Require an independently trusted head; reject missing or reordered batches."""
    _digest(trusted_head)
    if not isinstance(manifests, (list, tuple)) or not manifests:
        raise InvalidEvidence("Missing chain")
    first_seq = manifests[0].get("sequence") if isinstance(manifests[0], dict) else None
    if first_seq != 0:
        raise InvalidEvidence("Chain must start at genesis")
    expected = _ZERO
    tenant = None
    for index, manifest in enumerate(manifests):
        validate_manifest(manifest)
        if manifest["sequence"] != index or manifest["previous_commitment"] != expected:
            raise InvalidEvidence("Hash chain gap or reordering")
        if tenant is None:
            tenant = manifest["tenant_id"]
        elif manifest["tenant_id"] != tenant:
            raise InvalidEvidence("Mixed-tenant chain")
        expected = manifest["commitment"]
    if expected != trusted_head:
        raise InvalidEvidence("Trusted chain head mismatch")
    return True


def prepare_evm_anchor_intent(manifest: Mapping, *, chain_id: int, contract_address: str) -> dict:
    """Offline UNSIGNED request envelope; cannot transact or verify on-chain."""
    validate_manifest(manifest)
    if type(chain_id) is not int or not 1 <= chain_id <= 2**63:
        raise InvalidEvidence("Invalid EVM chain ID")
    if (not isinstance(contract_address, str) or
        re.fullmatch(r"0x[0-9a-fA-F]{40}", contract_address) is None or
        int(contract_address, 16) == 0):
        raise InvalidEvidence("Invalid EVM contract address")
    return {
        "version": "agentshield.evm.intent.v1",
        "chain_id": chain_id, "contract_address": contract_address,
        "commitment_bytes32": "0x" + manifest["commitment"],
        "previous_commitment_bytes32": "0x" + manifest["previous_commitment"],
        "status": "not_submitted", "signed": False, "tx_hash": None,
        "confirmed": False, "independent_receipt_verified": False,
    }


def summarize_anchor_evidence(
    *, expected_commitment: str, reported_commitment: str | None,
    reported_chain_id: int | None, expected_chain_id: int,
    reported_block_hash: str | None, canonical_block_hash: str | None,
    confirmations: int, required_confirmations: int,
    receipt_success: bool,
) -> str:
    """Conservative interpretation of UNTRUSTED, offline RPC snapshots.

    Even a reported match is NEVER proof of canonical on-chain finality:
    a trusted client must independently check chain, contract, log and header.
    """
    _digest(expected_commitment)
    if reported_commitment is None or reported_block_hash is None:
        return "unverified_no_receipt"
    if _digest(reported_commitment).hex() != expected_commitment:
        return "unverified_commitment_mismatch"
    if (type(reported_chain_id) is not int or reported_chain_id != expected_chain_id
        or not receipt_success):
        return "unverified_wrong_chain_or_failed_receipt"
    if canonical_block_hash is None or reported_block_hash != canonical_block_hash:
        return "unverified_reorg_or_block_mismatch"
    if (type(confirmations) is not int or type(required_confirmations) is not int
        or required_confirmations <= 0 or confirmations < required_confirmations):
        return "unverified_insufficient_confirmations"
    return "unverified_requires_independent_rpc_and_contract_log_check"
