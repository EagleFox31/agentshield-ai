"""Host-only operator-signed trust updates and durable rollback regression.

No Cloudflare deployment, KMS or external provider is involved. The operator
private signing root exists in test memory and never enters Worker fixtures.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import test_host_worker_keyring as keyring_fixture
from agentshield.host_worker_attestation import AttestationRejected
from agentshield.host_trust_ledger import (
    install_local_signed_keyring, verify_installed_worker_evidence,
)
from agentshield.host_signed_keyring import SCHEMA, OPERATOR_KID
from agentshield.local_worker_evidence_attestation import canonical_bytes


class SignedLocalTrustLedgerTests(unittest.TestCase):
    def setUp(self):
        self.fx = keyring_fixture.HostWorkerKeyringTests(
            "test_only_v2_active_and_signed_read_remains_non_authorizing"
        )
        self.fx.setUp()
        self.folder = tempfile.TemporaryDirectory()
        self.ledger = str(Path(self.folder.name) / "host-trust.sqlite")
        self.operator = ec.generate_private_key(ec.SECP256R1())
        self.foreign = ec.generate_private_key(ec.SECP256R1())
        self.operator_public = self.public(self.operator)
        self.manifest = json.loads(self.fx.manifest())

    def tearDown(self):
        self.folder.cleanup()
        self.fx.tearDown()

    @staticmethod
    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def signed(self, manifest=None, *, signer=None):
        message = {
            "schema": SCHEMA, "operator_kid": OPERATOR_KID,
            "manifest": self.manifest if manifest is None else manifest,
        }
        der = (signer or self.operator).sign(canonical_bytes(message), ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        message["signature"] = base64.urlsafe_b64encode(
            r.to_bytes(32, "big") + s.to_bytes(32, "big")
        ).rstrip(b"=").decode("ascii")
        return canonical_bytes(message)

    def install(self, signed=None, **kwargs):
        return install_local_signed_keyring(
            ledger_path=self.ledger, operator_public_pem=self.operator_public,
            signed_envelope=self.signed() if signed is None else signed,
            **kwargs,
        )

    def read(self, signed=None):
        return verify_installed_worker_evidence(
            self.fx.v2 if signed is None else signed,
            nonce=self.fx.fx.nonce, tenant="ci_local",
            command=self.fx.fx.command, ledger_path=self.ledger,
            operator_public_pem=self.operator_public, now_ms=self.fx.now + 1,
        )

    def test_install_and_restart_reads_previously_signed_manifest(self):
        first = self.install()
        self.assertEqual((first.generation, first.changed), (2, True))
        self.assertFalse(first.execution_authorized)
        self.assertFalse(self.install().changed)
        result = self.read()
        self.assertTrue(result["dispatch_recorded"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["production_ready"])

    def test_wrong_offline_root_and_modified_signed_manifest_fail_closed(self):
        manifest = self.signed()
        with self.assertRaises(AttestationRejected):
            install_local_signed_keyring(
                ledger_path=self.ledger, signed_envelope=manifest,
                operator_public_pem=self.public(self.foreign),
            )
        self.assertFalse(Path(self.ledger).exists())
        data = json.loads(manifest)
        data["manifest"]["generation"] = 999
        with self.assertRaises(AttestationRejected):
            self.install(canonical_bytes(data))
        self.assertFalse(Path(self.ledger).exists())

    def test_alternate_same_generation_even_validly_signed_is_denied(self):
        self.install()
        changed = copy.deepcopy(self.manifest)
        changed["keys"][0]["not_after_ms"] -= 1000
        with self.assertRaises(AttestationRejected):
            self.install(self.signed(changed))
        self.assertEqual(self.read()["state"], "claimed")

    def test_generation_three_installs_and_gen_two_rollback_rejected(self):
        previous = self.signed()
        self.install(previous)
        next_manifest = copy.deepcopy(self.manifest)
        next_manifest["generation"] = 3
        next_manifest["keys"][1]["status"] = "retiring"
        new_worker = ec.generate_private_key(ec.SECP256R1())
        next_manifest["keys"].append({
            "kid": "ci-worker-evidence-v3", "status": "active",
            "not_before_ms": self.fx.now - 100000,
            "not_after_ms": self.fx.now + 100000,
            "public_key_pem": self.public(new_worker).decode("ascii"),
        })
        update = self.signed(next_manifest)
        self.assertEqual(self.install(update).generation, 3)
        self.assertFalse(self.install(update).changed)
        self.assertFalse(self.read()["execution_authorized"])  # v2 retiring overlap
        with self.assertRaises(AttestationRejected):
            self.install(previous)
        with sqlite3.connect(self.ledger) as db:
            self.assertEqual(db.execute(
                "SELECT generation FROM local_worker_keyring_trust"
            ).fetchone()[0], 3)

    def test_revoked_key_cannot_be_revived_by_valid_offline_signature(self):
        self.install()
        updated = copy.deepcopy(self.manifest)
        updated["generation"] = 3
        updated["keys"][0]["status"] = "active"
        updated["keys"][1]["status"] = "retiring"
        with self.assertRaises(AttestationRejected):
            self.install(self.signed(updated))

    def test_missing_ledger_or_corrupt_snapshot_fails_closed(self):
        with self.assertRaises(AttestationRejected):
            self.read()
        self.install()
        with sqlite3.connect(self.ledger) as db:
            db.execute(
                "UPDATE local_worker_keyring_trust SET envelope_sha256=?",
                ("0" * 64,),
            )
        with self.assertRaises(AttestationRejected):
            self.read()
        with self.assertRaises(AttestationRejected):
            self.install()

    def test_injected_public_key_and_manifest_duplicate_json_are_denied(self):
        invalid = json.loads(self.signed())
        invalid["manifest"]["keys"][1]["public_key_pem"] = (
            self.public(self.foreign).decode("ascii")
        )
        with self.assertRaises(AttestationRejected):
            self.install(canonical_bytes(invalid))
        duplicated = self.signed().replace(
            b'"operator_kid":', b'"operator_kid":"ci-local-offline-operator-v1","operator_kid":',
        )
        with self.assertRaises(AttestationRejected):
            self.install(duplicated)

    def test_operator_private_key_is_never_stored_in_ledger(self):
        self.install()
        content = Path(self.ledger).read_bytes()
        self.assertNotIn(b"PRIVATE KEY", content)
        self.assertNotIn(b"operator_private", content)
        self.assertIn(hashlib.sha256(self.signed()).hexdigest().encode()[:0], content)

    def test_host_fails_if_root_replaced_after_install(self):
        self.install()
        self.operator_public = self.public(self.foreign)
        with self.assertRaises(AttestationRejected):
            self.read()


if __name__ == "__main__":
    unittest.main()
