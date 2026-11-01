"""Strict local trust lifecycle: rotation/revocation must not revive old proofs.

Synthetic ES256 signatures reuse the full prior host attestation fixtures;
production keys are NEVER installed, fetched or placed in D1.
"""
from __future__ import annotations

import copy
import json
import unittest
from cryptography.hazmat.primitives import serialization

import test_host_worker_attestation as prior
from agentshield.host_worker_attestation import AttestationRejected
from agentshield.host_worker_keyring import verify_rotating_worker_attestation


class HostWorkerKeyringTests(unittest.TestCase):
    def setUp(self):
        self.fx = prior.HostWorkerAttestationTests(
            "test_valid_pinned_signed_evidence_does_not_authorize",
        )
        self.fx.setUp()
        self.now = self.fx.now
        self.old_pub = self.fx.other_signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.current_pub = self.fx.public.decode("ascii")
        self.entries = [
            self.key("ci-worker-evidence-v1", "revoked", self.old_pub),
            self.key("ci-worker-evidence-v2", "active", self.current_pub),
        ]
        self.v2 = self.signed("ci-worker-evidence-v2")
        self.v1 = self.signed("ci-worker-evidence-v1", signer=self.fx.other_signer)

    def tearDown(self):
        self.fx.tearDown()

    def key(self, kid, status, pem):
        return {
            "kid": kid, "status": status, "public_key_pem": pem,
            "not_before_ms": self.now - 300_000,
            "not_after_ms": self.now + 300_000,
        }

    def signed(self, kid, *, signer=None):
        payload = self.fx.make()["payload"]
        payload["kid"] = kid
        return self.fx.make(payload=payload, signer=signer)

    def manifest(self, entries=None, generation=2):
        return json.dumps({
            "schema": "agentshield.local.worker-keyring.v1",
            "generation": generation,
            "keys": entries if entries is not None else self.entries,
        }, sort_keys=True, separators=(",", ":")).encode("ascii")

    def verify(self, envelope, *, blob=None, now=None, minimum=2):
        return verify_rotating_worker_attestation(
            envelope, nonce=self.fx.nonce, tenant="ci_local", command=self.fx.command,
            trusted_manifest_bytes=self.manifest() if blob is None else blob,
            minimum_generation=minimum, now_ms=self.now + 1 if now is None else now,
        )

    def test_only_v2_active_and_signed_read_remains_non_authorizing(self):
        outcome = self.verify(self.v2)
        self.assertTrue(outcome["dispatch_recorded"])
        self.assertFalse(outcome["execution_authorized"])
        self.assertFalse(outcome["production_ready"])

    def test_revoked_v1_is_denied_despite_valid_original_signature(self):
        with self.assertRaises(AttestationRejected):
            self.verify(self.v1)

    def test_rotating_overlap_accepts_v1_only_until_retirement(self):
        overlap = copy.deepcopy(self.entries)
        overlap[0]["status"] = "retiring"
        self.assertFalse(
            self.verify(self.v1, blob=self.manifest(overlap))["execution_authorized"],
        )
        overlap[0]["not_after_ms"] = self.now
        with self.assertRaises(AttestationRejected):
            self.verify(self.v1, blob=self.manifest(overlap))
        # Revocation is immediate regardless of an otherwise valid overlap.
        overlap[0]["not_after_ms"] = self.now + 300000
        overlap[0]["status"] = "revoked"
        with self.assertRaises(AttestationRejected):
            self.verify(self.v1, blob=self.manifest(overlap))

    def test_generation_downgrade_and_duplicate_signed_trust_fields_denied(self):
        with self.assertRaises(AttestationRejected):
            self.verify(self.v2, blob=self.manifest(generation=1))
        malformed = self.manifest().replace(b'"generation":2', b'"generation":2,"generation":3')
        with self.assertRaises(AttestationRejected):
            self.verify(self.v2, blob=malformed)

    def test_unknown_or_relabelled_kid_is_not_a_key_rotation(self):
        unknown = self.signed("ci-worker-evidence-v3")
        with self.assertRaises(AttestationRejected):
            self.verify(unknown)
        labelled = copy.deepcopy(self.v2)
        labelled["payload"]["kid"] = "ci-worker-evidence-v1"
        with self.assertRaises(AttestationRejected):
            self.verify(labelled)

    def test_reject_two_active_or_no_active_keys(self):
        for states in (("active", "active"), ("revoked", "retiring")):
            entries = copy.deepcopy(self.entries)
            for entry, state in zip(entries, states):
                entry["status"] = state
            with self.subTest(states=states), self.assertRaises(AttestationRejected):
                self.verify(self.v2, blob=self.manifest(entries))

    def test_reject_duplicate_kid_or_public_key_under_second_id(self):
        entries = copy.deepcopy(self.entries)
        entries[0]["kid"] = "ci-worker-evidence-v2"
        with self.assertRaises(AttestationRejected):
            self.verify(self.v2, blob=self.manifest(entries))
        entries = copy.deepcopy(self.entries)
        entries[0]["public_key_pem"] = entries[1]["public_key_pem"]
        with self.assertRaises(AttestationRejected):
            self.verify(self.v2, blob=self.manifest(entries))

    def test_invalid_expired_future_window_never_accepts(self):
        for key, value in (
            ("not_before_ms", self.now + 10_000),
            ("not_after_ms", self.now),
            ("not_after_ms", self.now - 10),
        ):
            entries = copy.deepcopy(self.entries)
            entries[1][key] = value
            with self.subTest(key=key), self.assertRaises(AttestationRejected):
                self.verify(self.v2, blob=self.manifest(entries))

    def test_manifest_extension_bool_generation_and_wrong_curve_refused(self):
        wrong = json.loads(self.manifest())
        wrong["unexpected"] = "remote-jwks"
        with self.assertRaises(AttestationRejected):
            self.verify(self.v2, blob=json.dumps(wrong).encode())
        for generation in (True, 0):
            with self.assertRaises(AttestationRejected):
                self.verify(self.v2, blob=self.manifest(generation=generation))
        wrong = copy.deepcopy(self.entries)
        wrong[1]["public_key_pem"] = "not a PEM"
        with self.assertRaises(AttestationRejected):
            self.verify(self.v2, blob=self.manifest(wrong))

    def test_tampered_signature_still_refused_after_valid_key_lookup(self):
        changed = copy.deepcopy(self.v2)
        changed["payload"]["evidence"]["dispatch_recorded"] = False
        with self.assertRaises(AttestationRejected):
            self.verify(changed)


if __name__ == "__main__":
    unittest.main()
