"""Host-side negative proof: challenge, tenant, TTL, pinned key, tampering.

Uses real host cryptography only to build synthetic signatures. Actual Worker
WebCrypto signing runs in the separate native Pyodide + D1 CI job.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import time
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import test_host_signed_handoff as signed_fixture
from agentshield.host_worker_attestation import (
    AttestationRejected, verify_local_worker_attestation,
)
from agentshield.local_worker_evidence_attestation import (
    AttestationUnavailable, canonical_bytes, attest_local_evidence,
)
from agentshield.local_service_evidence import read_local_handoff_evidence


class HostWorkerAttestationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = signed_fixture.SignedHandoffTests(
            "test_existing_d1_audit_proves_host_signed_one_use_handoff",
        )
        self.fixture.setUp()
        self.command = self.fixture.prepare()
        self.signer = ec.generate_private_key(ec.SECP256R1())
        self.other_signer = ec.generate_private_key(ec.SECP256R1())
        self.public = self.signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.nonce = "ab" * 32
        self.now = int(time.time() * 1000)
        self.evidence = asyncio.run(read_local_handoff_evidence(
            self.fixture.store, self.fixture.audit,
            tenant_id="ci_local", command_id=self.command,
        ))

    def tearDown(self):
        self.fixture.tearDown()

    def make(self, *, signer=None, payload=None):
        payload = payload or {
            "type": "agentshield.local.d1-evidence.v1",
            "kid": "ci-worker-evidence-v1", "nonce": self.nonce,
            "issued_at_ms": self.now, "expires_at_ms": self.now + 10000,
            "evidence": copy.deepcopy(self.evidence),
        }
        signed = (signer or self.signer).sign(
            canonical_bytes(payload), ec.ECDSA(hashes.SHA256()),
        )
        r, s = utils.decode_dss_signature(signed)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {
            "payload": payload,
            "signature": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        }

    def check(self, data, **overrides):
        params = {
            "nonce": self.nonce, "tenant": "ci_local", "command": self.command,
            "trusted_public_key_pem": self.public, "now_ms": self.now + 1,
        }
        params.update(overrides)
        return verify_local_worker_attestation(data, **params)

    def test_valid_pinned_signed_evidence_does_not_authorize(self):
        accepted = self.check(self.make())
        self.assertTrue(accepted["dispatch_recorded"])
        self.assertFalse(accepted["issuance_recorded"])
        self.assertFalse(accepted["execution_authorized"])
        self.assertFalse(accepted["production_ready"])

    def test_untrusted_signer_and_changed_evidence_rejected(self):
        forged = self.make(signer=self.other_signer)
        changed = self.make()
        changed["payload"]["evidence"]["issuance_recorded"] = True
        for sample in (forged, changed):
            with self.subTest(sample=sample["signature"][:8]), self.assertRaises(AttestationRejected):
                self.check(sample)

    def test_old_challenge_and_wrong_signed_scope_rejected(self):
        good = self.make()
        for overrides in (
            {"nonce": "cd" * 32}, {"tenant": "other_tenant"},
            {"command": "local-command-" + "0" * 32},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(AttestationRejected):
                self.check(good, **overrides)

    def test_stale_future_and_changed_ttl_rejected(self):
        sample = self.make()
        for now in (self.now - 5000, self.now + 10001):
            with self.subTest(now=now), self.assertRaises(AttestationRejected):
                self.check(sample, now_ms=now)
        payload = copy.deepcopy(sample["payload"])
        payload["expires_at_ms"] += 1000
        with self.assertRaises(AttestationRejected):
            self.check(self.make(payload=payload))

    def test_wrong_pinned_key_refused(self):
        foreign = self.other_signer.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaises(AttestationRejected):
            self.check(self.make(), trusted_public_key_pem=foreign)

    def test_signed_execution_flag_even_if_validly_signed_is_not_trusted(self):
        payload = self.make()["payload"]
        payload["evidence"]["execution_authorized"] = True
        with self.assertRaises(AttestationRejected):
            self.check(self.make(payload=payload))

    def test_extra_payload_fields_or_signature_encoding_rejected(self):
        forged = self.make()
        forged["payload"]["extra"] = "grant"
        with self.assertRaises(AttestationRejected):
            self.check(forged)
        bad = self.make()
        bad["signature"] = bad["signature"] + "="
        with self.assertRaises(AttestationRejected):
            self.check(bad)

    def test_invalid_worker_signer_fails_before_native_crypto(self):
        for invalid in (None, "", "{}", '{"kty":"RSA"}'):
            with self.subTest(invalid=invalid), self.assertRaises(AttestationUnavailable):
                asyncio.run(attest_local_evidence(
                    self.evidence, nonce=self.nonce, tenant="ci_local",
                    command=self.command, signer=invalid, now_ms=self.now,
                ))
        with self.assertRaises(AttestationUnavailable):
            asyncio.run(attest_local_evidence(
                self.evidence, nonce="x", tenant="ci_local",
                command=self.command, signer="{}", now_ms=self.now,
            ))


if __name__ == "__main__":
    unittest.main()
