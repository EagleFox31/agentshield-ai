"""Atomic host-only SQLite installation and non-rollback Worker keyring reads.

Local ledger prevents accidental rollback, not malicious host disk rollback.
Operator root lives outside the ledger and never arrives over HTTP.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass

from agentshield.host_signed_keyring import parse_signed_keyring
from agentshield.host_worker_attestation import AttestationRejected
from agentshield.host_worker_keyring import verify_rotating_worker_attestation
from agentshield.local_worker_evidence_attestation import canonical_bytes

_SCHEMA_SQL = (
    "CREATE TABLE IF NOT EXISTS local_worker_keyring_trust ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
    "generation INTEGER NOT NULL CHECK(generation>=2),"
    "operator_sha256 TEXT NOT NULL, envelope_sha256 TEXT NOT NULL,"
    "signed_envelope BLOB NOT NULL)"
)


@dataclass(frozen=True)
class LocalTrustInstallReceipt:
    generation: int
    changed: bool
    execution_authorized: bool = False
    production_ready: bool = False


def _db(path: str) -> sqlite3.Connection:
    if not isinstance(path, str) or not path or path == ":memory:":
        raise AttestationRejected("Durable local host trust path required")
    db = sqlite3.connect(path, timeout=2.0, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    return db


def _current(db: sqlite3.Connection, root: bytes):
    row = db.execute(
        "SELECT generation,operator_sha256,envelope_sha256,signed_envelope "
        "FROM local_worker_keyring_trust WHERE singleton=1"
    ).fetchone()
    if row is None:
        return None
    generation, root_digest, digest, blob = row
    actual, canonical, operator_digest = parse_signed_keyring(blob, root)
    if (generation != actual or root_digest != operator_digest
        or digest != hashlib.sha256(canonical).hexdigest() or blob != canonical):
        raise AttestationRejected("Host trust ledger inconsistent")
    return generation, canonical, operator_digest


def _transition(old_blob: bytes, new_blob: bytes) -> None:
    previous = json.loads(old_blob)["manifest"]["keys"]
    incoming = {
        key["kid"]: key for key in json.loads(new_blob)["manifest"]["keys"]
    }
    for old in previous:
        nxt = incoming.get(old["kid"])
        if nxt is None:
            raise AttestationRejected("Implicit trust key deletion denied")
        if (old["public_key_pem"] != nxt["public_key_pem"]
            or old["not_before_ms"] != nxt["not_before_ms"]
            or old["not_after_ms"] < nxt["not_after_ms"]
            or old["status"] == "revoked" and nxt["status"] != "revoked"
            or old["status"] == "retiring" and nxt["status"] == "active"):
            raise AttestationRejected("Trust key replaced, revived or extended")


def install_local_signed_keyring(
    *, ledger_path: str, signed_envelope: bytes, operator_public_pem: bytes,
) -> LocalTrustInstallReceipt:
    generation, canonical, root_digest = parse_signed_keyring(
        signed_envelope, operator_public_pem,
    )
    with closing(_db(ledger_path)) as db:
        try:
            db.execute(_SCHEMA_SQL)
            db.execute("BEGIN IMMEDIATE")
            old = _current(db, operator_public_pem)
            digest = hashlib.sha256(canonical).hexdigest()
            if old is None:
                db.execute(
                    "INSERT INTO local_worker_keyring_trust "
                    "(singleton,generation,operator_sha256,envelope_sha256,signed_envelope) "
                    "VALUES(1,?,?,?,?)",
                    (generation, root_digest, digest, canonical),
                )
                changed = True
            else:
                old_generation, old_blob, _ = old
                if generation < old_generation:
                    raise AttestationRejected("Keyring rollback")
                if generation == old_generation:
                    # ECDSA may produce a fresh signature for identical
                    # signed content. Compare the authenticated manifest,
                    # NOT variable signature bytes; never rewrite the
                    # existing committed generation for a no-op update.
                    if (json.loads(canonical)["manifest"]
                        != json.loads(old_blob)["manifest"]):
                        raise AttestationRejected("Conflicting same-generation trust update")
                    changed = False
                else:
                    _transition(old_blob, canonical)
                    db.execute(
                        "UPDATE local_worker_keyring_trust "
                        "SET generation=?,envelope_sha256=?,signed_envelope=? "
                        "WHERE singleton=1 AND generation=? AND operator_sha256=?",
                        (generation, digest, canonical, old_generation, root_digest),
                    )
                    if db.execute("SELECT changes()").fetchone()[0] != 1:
                        raise AttestationRejected("Concurrent keyring update")
                    changed = True
            db.execute("COMMIT")
            return LocalTrustInstallReceipt(generation, changed)
        except Exception:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise


def verify_installed_worker_evidence(
    envelope: object, *, nonce: str, tenant: str, command: str,
    ledger_path: str, operator_public_pem: bytes, now_ms: int,
) -> dict:
    if not os.path.isfile(ledger_path):
        raise AttestationRejected("Local trust ledger not provisioned")
    with closing(_db(ledger_path)) as db:
        try:
            current = _current(db, operator_public_pem)
            if current is None:
                raise AttestationRejected("Host trust not installed")
            generation, signed_blob, _ = current
            manifest = json.loads(signed_blob)["manifest"]
            return verify_rotating_worker_attestation(
                envelope, nonce=nonce, tenant=tenant, command=command,
                trusted_manifest_bytes=canonical_bytes(manifest),
                minimum_generation=generation, now_ms=now_ms,
            )
        except sqlite3.Error as exc:
            raise AttestationRejected("Local trust ledger unavailable") from exc
