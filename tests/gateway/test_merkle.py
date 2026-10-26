"""Merkle integrity, omission, ordering and EVM negative evidence tests.

Uses the SAME AuditEvent canonical fingerprint as the SQLite/D1 repositories.
No cryptographic claims depend on a mocked external EVM receipt.
"""
from __future__ import annotations

import copy
import unittest

from agentshield.audit import AuditEvent, action_digest
from agentshield.merkle import (
    InvalidEvidence, build_manifest, inclusion_path, prepare_evm_anchor_intent,
    summarize_anchor_evidence, validate_manifest, verify_complete_batch,
    verify_inclusion, verify_manifest_chain,
)

T = 1_790_000_010_000


def event(index: int, tenant: str = "tenant_a") -> AuditEvent:
    return AuditEvent(
        event_id=f"batch-event-{index:04d}", tenant_id=tenant,
        principal_id=f"{tenant}:agent-01",
        action_digest=action_digest("invoices", "read", f"invoice/{index}"),
        effect="deny" if index % 2 else "allow",
        reason_codes=("NO_MATCHING_POLICY",) if index % 2 else ("EXPLICIT_ALLOW",),
        policy_version="baseline-v1",
        occurred_at_ms=T + index,
        retention_until_ms=T + index + 30 * 86_400_000,
    )


def batch(events, *, seq=0, prev="0" * 64, batch_id="batch-evidence-001"):
    return build_manifest(
        events, tenant_id="tenant_a", batch_id=batch_id,
        created_at_ms=T + 10_000, sequence=seq, previous_commitment=prev,
    )


class MerkleTests(unittest.TestCase):
    def test_single_even_odd_and_many_leaf_batches(self):
        for size in (1, 2, 3, 5, 16, 17, 100):
            with self.subTest(size=size):
                events = [event(i) for i in range(size)]
                manifest = batch(list(reversed(events)))
                self.assertEqual(manifest["count"], size)
                self.assertEqual(validate_manifest(manifest), "consistent_unanchored")
                self.assertEqual(
                    validate_manifest(manifest, trusted_commitment=manifest["commitment"]),
                    "matches_supplied_trust_root",
                )
                self.assertTrue(verify_complete_batch(
                    events, manifest, trusted_commitment=manifest["commitment"],
                ))
                for member in events:
                    proof = inclusion_path(manifest, member.event_id)
                    self.assertTrue(verify_inclusion(
                        member, manifest, proof, trusted_commitment=manifest["commitment"],
                    ))

    def test_build_order_is_deterministic(self):
        events = [event(2), event(0), event(1)]
        self.assertEqual(batch(events), batch(list(reversed(events))))

    def test_modified_event_and_wrong_commitment_rejected(self):
        events = [event(i) for i in range(3)]
        manifest = batch(events)
        modified = copy.copy(events)
        original = events[1]
        modified[1] = AuditEvent(
            **{**original.__dict__, "reason_codes": ("EXPLICIT_DENY",)}
        )
        with self.assertRaises(InvalidEvidence):
            verify_complete_batch(modified, manifest, trusted_commitment=manifest["commitment"])
        with self.assertRaises(InvalidEvidence):
            verify_inclusion(modified[1], manifest, inclusion_path(manifest, original.event_id),
                             trusted_commitment=manifest["commitment"])
        with self.assertRaises(InvalidEvidence):
            validate_manifest(manifest, trusted_commitment="f" * 64)

    def test_deleted_inserted_and_reordered_event_rejected(self):
        events = [event(i) for i in range(5)]
        manifest = batch(events)
        mutations = [events[:-1], events[1:], events + [event(7)],
                     [events[1], events[0], *events[2:]]]
        for modified in mutations:
            with self.subTest(modified=[x.event_id for x in modified]):
                with self.assertRaises(InvalidEvidence):
                    verify_complete_batch(modified, manifest, trusted_commitment=manifest["commitment"])

    def test_manifest_rewrite_not_accepted_by_previously_trusted_anchor(self):
        events = [event(i) for i in range(3)]
        anchored = batch(events)
        attacker = batch([event(0), event(2)])
        # A self-consistent rewritten manifest is NOT sufficient to claim integrity.
        self.assertEqual(validate_manifest(attacker), "consistent_unanchored")
        with self.assertRaises(InvalidEvidence):
            validate_manifest(attacker, trusted_commitment=anchored["commitment"])

    def test_tampered_manifest_fields_or_siblings_fail(self):
        events = [event(i) for i in range(5)]
        manifest = batch(events)
        attempts = []
        for field, value in (
            ("batch_id", "batch-attacker-001"),
            ("tenant_id", "other"),
            ("sequence", 3),
            ("count", 4),
            ("tree_root", "0" * 64),
            ("manifest_sha256", "a" * 64),
            ("commitment", "f" * 64),
        ):
            invalid = copy.deepcopy(manifest)
            invalid[field] = value
            attempts.append(invalid)
        invalid = copy.deepcopy(manifest)
        invalid["entries"][2]["event_sha256"] = "f" * 64
        attempts.append(invalid)
        invalid = copy.deepcopy(manifest)
        invalid["entries"][2]["event_id"] = invalid["entries"][1]["event_id"]
        attempts.append(invalid)
        invalid = copy.deepcopy(manifest)
        invalid["entries"] = list(reversed(invalid["entries"]))
        attempts.append(invalid)
        for invalid in attempts:
            with self.assertRaises(InvalidEvidence):
                validate_manifest(invalid, trusted_commitment=manifest["commitment"])

        path = inclusion_path(manifest, events[4].event_id)
        for mutate in ("sibling", "direction", "index", "length", "odd"):
            proof = copy.deepcopy(path)
            if mutate == "sibling":
                proof["siblings"][0]["sha256"] = "f" * 64
            elif mutate == "direction":
                proof["siblings"][0]["side"] = "left"
            elif mutate == "index":
                proof["leaf_index"] = 0
            elif mutate == "length":
                proof["siblings"].pop()
            else:
                proof["siblings"][0]["sha256"] = "f" * 64
            with self.subTest(mutation=mutate), self.assertRaises(InvalidEvidence):
                verify_inclusion(events[4], manifest, proof,
                                 trusted_commitment=manifest["commitment"])

    def test_cross_tenant_and_duplicate_rejected(self):
        with self.assertRaises(InvalidEvidence):
            batch([event(0), event(1, "other")])
        with self.assertRaises(InvalidEvidence):
            batch([event(0), event(0)])
        with self.assertRaises(InvalidEvidence):
            batch([])

    def test_hash_chain_detects_gap_reorder_missing_head_and_cross_tenant(self):
        a = batch([event(0)], batch_id="batch-chain-000")
        b = batch([event(1)], seq=1, prev=a["commitment"], batch_id="batch-chain-001")
        c = batch([event(2)], seq=2, prev=b["commitment"], batch_id="batch-chain-002")
        self.assertTrue(verify_manifest_chain([a, b, c], trusted_head=c["commitment"]))
        for sequence in ([a, c], [b, c], [a, c, b], [a, b]):
            with self.assertRaises(InvalidEvidence):
                verify_manifest_chain(sequence, trusted_head=c["commitment"])
        with self.assertRaises(InvalidEvidence):
            verify_manifest_chain([a, b, c], trusted_head="9" * 64)

    def test_evm_intent_is_only_unsigned_and_never_a_finality_claim(self):
        manifest = batch([event(0), event(1)])
        proposal = prepare_evm_anchor_intent(
            manifest, chain_id=11155111,
            contract_address="0x" + "12" * 20,
        )
        self.assertEqual(proposal["commitment_bytes32"], "0x" + manifest["commitment"])
        self.assertFalse(proposal["signed"])
        self.assertFalse(proposal["confirmed"])
        self.assertEqual(proposal["status"], "not_submitted")
        self.assertIsNone(proposal["tx_hash"])
        with self.assertRaises(InvalidEvidence):
            prepare_evm_anchor_intent(manifest, chain_id=-1, contract_address="0x" + "12" * 20)
        with self.assertRaises(InvalidEvidence):
            prepare_evm_anchor_intent(manifest, chain_id=11155111,
                                      contract_address="0x" + "00" * 20)

    def test_reorg_wrong_chain_failed_receipt_and_missing_finality_never_verify(self):
        root = batch([event(0)])["commitment"]
        args = {
            "expected_commitment": root, "reported_commitment": root,
            "reported_chain_id": 11155111, "expected_chain_id": 11155111,
            "reported_block_hash": "0x" + "ab" * 32,
            "canonical_block_hash": "0x" + "ab" * 32,
            "confirmations": 20, "required_confirmations": 15,
            "receipt_success": True,
        }
        self.assertEqual(summarize_anchor_evidence(**args),
                         "unverified_requires_independent_rpc_and_contract_log_check")
        for patch, expected in [
            ({"reported_commitment": None}, "unverified_no_receipt"),
            ({"reported_commitment": "f" * 64}, "unverified_commitment_mismatch"),
            ({"reported_chain_id": 1}, "unverified_wrong_chain_or_failed_receipt"),
            ({"receipt_success": False}, "unverified_wrong_chain_or_failed_receipt"),
            ({"canonical_block_hash": "0x" + "cd" * 32}, "unverified_reorg_or_block_mismatch"),
            ({"confirmations": 2}, "unverified_insufficient_confirmations"),
        ]:
            with self.subTest(patch=patch):
                self.assertEqual(summarize_anchor_evidence(**{**args, **patch}), expected)


if __name__ == "__main__":
    unittest.main()
