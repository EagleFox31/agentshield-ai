"""Host-only ES256 handoff from existing audited D1 outbox reservation.

No network, no second mock call by consumer, no production signer.
The keypair and the host SQLite replay database exist only in tests.
"""
from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.approvals import SQLiteApprovalStore
from agentshield.audit import AuditStorageError
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.host_signed_handoff import (
    HandoffRejected, init_host_replay_db, issue_offline_handoff,
    verify_and_burn_local_handoff,
)
from agentshield.identity import VerifiedAgent
from agentshield.local_command_outbox import claim_local_command, queue_local_invoice
from agentshield.local_tool_gate import LocalDryRunAdapter
from agentshield.mock_dispatch_boundary import dispatch_claimed_invoice_mock
from agentshield.policy import Principal
from agentshield.policy_registry import SQLitePolicyRegistry
from scripts.seed_local_policy_registry import make_sql, reviewed_v2_sql

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_790_000_100_000


def run(coro):
    return asyncio.run(coro)


class SignedHandoffTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for name in (
            "0001_audit_core.sql", "0004_policy_snapshots.sql",
            "0005_policy_activation_audit.sql", "0006_idempotent_decisions.sql",
            "0007_tenant_decision_quota.sql", "0008_local_command_outbox.sql",
            "0009_fenced_mock_dispatch.sql",
            "0010_local_handoff_issuance.sql",
        ):
            self.db.executescript((ROOT / "migrations" / name).read_text())
        self.db.executescript(make_sql() + reviewed_v2_sql())
        self.store = SQLiteApprovalStore(self.db)
        self.audit = SQLiteAuditRepository(self.db)
        self.registry = SQLitePolicyRegistry(self.db)
        self.agent = self.actor("local-demo-agent", ("invoice:read",))
        self.operator = self.actor("reviewer-01", ("commands:claim",))
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.host = sqlite3.connect(":memory:", isolation_level=None)
        init_host_replay_db(self.host)
        self.adapter = LocalDryRunAdapter()

    def tearDown(self):
        self.host.close()
        self.db.close()

    def actor(self, sub, scopes, tenant="ci_local"):
        return VerifiedAgent(
            Principal(f"{tenant}:{sub}", frozenset(scopes)),
            tenant, sub, "host-local-jti", 1_790_000_000, 1_790_000_300,
        )

    def prepare(self):
        queued = run(queue_local_invoice(
            self.store, self.audit, self.registry, self.agent,
            request_id="host-handoff-request-000001", now_ms=NOW,
        ))
        run(claim_local_command(
            self.store, self.audit, self.registry, self.operator,
            command_id=queued.command_id, now_ms=NOW + 1,
        ))
        dispatch = run(dispatch_claimed_invoice_mock(
            self.store, self.audit, self.registry, self.agent,
            command_id=queued.command_id, now_ms=NOW + 2,
            adapter=self.adapter,
        ))
        self.assertEqual(dispatch.stub_name, "mock_invoice_read")
        self.assertEqual(self.adapter.calls, ["mock_invoice_read"])
        return queued.command_id

    def issue(self, cmd, agent=None, at=NOW + 3):
        return run(issue_offline_handoff(
            self.store, self.audit, self.registry, agent or self.agent,
            command_id=cmd, now_ms=at, private_key=self.key,
        ))

    def verify(self, token, cmd, *, at=NOW + 5, tenant="ci_local", key=None):
        return verify_and_burn_local_handoff(
            self.host, token, key or self.key.public_key(),
            now_ms=at, expected_tenant=tenant, expected_command_id=cmd,
        )

    def test_existing_d1_audit_proves_host_signed_one_use_handoff(self):
        cmd = self.prepare()
        token = self.issue(cmd)
        result = self.verify(token, cmd)
        self.assertEqual(result.command_id, cmd)
        self.assertEqual(result.tenant_id, "ci_local")
        self.assertTrue(result.token_used)
        self.assertFalse(result.external_network_used)
        self.assertFalse(result.execution_authorized)
        self.assertFalse(result.production_ready)
        self.assertEqual(self.host.execute(
            "SELECT COUNT(*) FROM used_local_handoffs"
        ).fetchone()[0], 1)
        with self.assertRaises(HandoffRejected):
            self.verify(token, cmd)
        self.assertEqual(self.adapter.calls, ["mock_invoice_read"])

    def test_source_issues_at_most_one_handoff_per_command(self):
        cmd = self.prepare()
        first = self.issue(cmd)
        with self.assertRaises(HandoffRejected):
            self.issue(cmd)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM local_handoff_issuances"
        ).fetchone()[0], 1)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM audit_events "
            "WHERE reason_codes_json='[\"LOCAL_SIGNED_HANDOFF_ISSUED_NO_EXECUTION\"]'"
        ).fetchone()[0], 1)
        self.verify(first, cmd)
        with self.assertRaises(HandoffRejected):
            self.verify(first, cmd)

    def test_audit_failure_rolls_back_source_issuance(self):
        cmd = self.prepare()
        self.db.execute(
            "CREATE TRIGGER fail_handoff_audit BEFORE INSERT ON audit_events "
            "WHEN NEW.event_id LIKE 'handoff-issued-%' "
            "BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END"
        )
        with self.assertRaises(AuditStorageError):
            self.issue(cmd)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM local_handoff_issuances"
        ).fetchone()[0], 0)

    def test_immutable_source_issuance_cannot_be_updated_or_deleted(self):
        cmd = self.prepare()
        token = self.issue(cmd)
        for query in (
            "DELETE FROM local_handoff_issuances",
            "UPDATE local_handoff_issuances SET tenant_id='other'",
            "UPDATE local_handoff_issuances SET token_sha256='0'",
        ):
            with self.subTest(query=query), self.assertRaises(sqlite3.DatabaseError):
                self.db.execute(query)
        self.verify(token, cmd)

    def test_lost_response_after_source_commit_is_fail_closed(self):
        cmd = self.prepare()
        _ = self.issue(cmd)
        # Even if HTTP response carrying the signed token were lost, a
        # second issuance must not silently reset the 30-second window.
        with self.assertRaises(HandoffRejected):
            self.issue(cmd, at=NOW + 4)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM local_handoff_issuances"
        ).fetchone()[0], 1)

    def test_untrusted_key_and_modified_signature_or_payload_denied(self):
        cmd = self.prepare()
        token = self.issue(cmd)
        foreign = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(HandoffRejected):
            self.verify(token, cmd, key=foreign.public_key())
        left, sig = token.split(".")
        raw = bytearray(base64.urlsafe_b64decode(left + "=" * (-len(left) % 4)))
        raw[12] ^= 1
        tampered = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        with self.assertRaises(HandoffRejected):
            self.verify(tampered + "." + sig, cmd)
        with self.assertRaises(HandoffRejected):
            self.verify(left + "." + sig[:-1] + ("A" if sig[-1] != "A" else "B"), cmd)
        self.assertEqual(self.host.execute(
            "SELECT COUNT(*) FROM used_local_handoffs"
        ).fetchone()[0], 0)

    def test_expiry_future_and_cross_tenant_binding(self):
        cmd = self.prepare()
        token = self.issue(cmd)
        for when, tenant, command in (
            (NOW + 3 + 30_000, "ci_local", cmd),
            (NOW + 2, "ci_local", cmd),
            (NOW + 5, "wrong", cmd),
            (NOW + 5, "ci_local", "local-command-" + "0" * 32),
        ):
            with self.subTest(when=when, tenant=tenant), self.assertRaises(HandoffRejected):
                self.verify(token, command, at=when, tenant=tenant)
        self.assertEqual(self.host.execute(
            "SELECT COUNT(*) FROM used_local_handoffs"
        ).fetchone()[0], 0)

    def test_signed_scope_change_wrong_tenant_or_missing_claim_denied_issuance(self):
        cmd = self.prepare()
        for actor in (
            self.actor("another-agent", ("invoice:read",)),
            self.actor("local-demo-agent", ("supplier:write",)),
            self.actor("local-demo-agent", ("invoice:read", "supplier:write")),
            self.actor("local-demo-agent", ("invoice:read",), "other"),
        ):
            with self.subTest(actor=actor.principal.id), self.assertRaises(
                (HandoffRejected, AuditStorageError)
            ):
                self.issue(cmd, agent=actor)

    def test_policy_activation_revokes_issuer_even_after_mock_reserved(self):
        cmd = self.prepare()
        self.db.execute(
            "UPDATE active_policy_versions SET version=?,activated_at_ms=?,"
            "activation_marker=? WHERE tenant_id=?",
            ("ci-local-policy-v2", NOW + 10, "changed", "ci_local"),
        )
        with self.assertRaises(HandoffRejected):
            self.issue(cmd)

    def test_missing_dispatch_or_claim_audit_blocks_signing(self):
        cmd = self.prepare()
        row = self.db.execute(
            "SELECT dispatch_audit_event_id FROM local_mock_dispatch_reservations "
            "WHERE command_id=?", (cmd,),
        ).fetchone()
        self.db.execute("DELETE FROM audit_events WHERE event_id=?",
                        (row["dispatch_audit_event_id"],))
        with self.assertRaises(AuditStorageError):
            self.issue(cmd)

    def test_no_issuance_without_actual_dispatch_reservation(self):
        queued = run(queue_local_invoice(
            self.store, self.audit, self.registry, self.agent,
            request_id="host-handoff-request-000001", now_ms=NOW,
        ))
        run(claim_local_command(
            self.store, self.audit, self.registry, self.operator,
            command_id=queued.command_id, now_ms=NOW + 1,
        ))
        with self.assertRaises(HandoffRejected):
            self.issue(queued.command_id)

    def test_consumed_token_survives_host_database_restart(self):
        command_id = self.prepare()
        token = self.issue(command_id)
        with tempfile.TemporaryDirectory(prefix="agentshield-handoff-") as folder:
            database = str(Path(folder) / "executor-replay.sqlite")
            first = sqlite3.connect(database, isolation_level=None)
            try:
                init_host_replay_db(first)
                consumed = verify_and_burn_local_handoff(
                    first, token, self.key.public_key(), now_ms=NOW + 5,
                    expected_tenant="ci_local", expected_command_id=command_id,
                )
                self.assertEqual(consumed.command_id, command_id)
            finally:
                first.close()
            reopened = sqlite3.connect(database, isolation_level=None)
            try:
                init_host_replay_db(reopened)
                with self.assertRaises(HandoffRejected):
                    verify_and_burn_local_handoff(
                        reopened, token, self.key.public_key(), now_ms=NOW + 6,
                        expected_tenant="ci_local", expected_command_id=command_id,
                    )
                self.assertEqual(
                    reopened.execute(
                        "SELECT COUNT(*) FROM used_local_handoffs"
                    ).fetchone()[0], 1,
                )
            finally:
                reopened.close()

    def test_durable_replay_failure_never_grants_access(self):
        cmd = self.prepare()
        token = self.issue(cmd)
        self.host.execute("DROP TABLE used_local_handoffs")
        with self.assertRaises(HandoffRejected):
            self.verify(token, cmd)

    def test_host_cannot_accept_unsigned_json_even_if_contents_look_valid(self):
        cmd = self.prepare()
        token = self.issue(cmd)
        raw, _ = token.split(".")
        with self.assertRaises(HandoffRejected):
            self.verify(raw, cmd)
        with self.assertRaises(HandoffRejected):
            self.verify(token + ".extra", cmd)


if __name__ == "__main__":
    unittest.main()
