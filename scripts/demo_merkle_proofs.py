"""Deterministic Merkle security demonstration with synthetic audited events.

No keys, network, D1 provisioning, Ethereum RPC, testnet gas or blockchain
transaction. Shows what integrity guarantees need an *external* trust root.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import tempfile
from dataclasses import asdict
from pathlib import Path

from agentshield.audit import AuditEvent, action_digest
from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.merkle import (
    InvalidEvidence, build_manifest, inclusion_path, prepare_evm_anchor_intent,
    validate_manifest, verify_complete_batch, verify_inclusion,
)

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "0001_audit_core.sql"
START = 1_790_000_010_000


async def demo_events() -> tuple[list[AuditEvent], dict]:
    db = sqlite3.connect(":memory:")
    try:
        db.executescript(MIGRATION.read_text(encoding="utf-8"))
        storage = SQLiteAuditRepository(db)
        events = []
        for index, effect in enumerate(("allow", "deny", "require_approval")):
            event = AuditEvent(
                event_id=f"fixture-evidence-{index:04d}",
                tenant_id="demo_tenant", principal_id="demo_tenant:agent-01",
                action_digest=action_digest(
                    "invoices", "read" if index == 0 else "restricted_action",
                    f"record/{index}",
                ),
                effect=effect,
                reason_codes=(
                    "EXPLICIT_ALLOW" if index == 0 else
                    "REQUIRED_SCOPE_MISSING" if index == 1 else
                    "HUMAN_APPROVAL_REQUIRED",
                ),
                policy_version="demo-policy-v1",
                occurred_at_ms=START + index,
                retention_until_ms=START + index + 30 * 86_400_000,
            )
            assert await storage.record_event(event)
            events.append(await storage.get_event(event.tenant_id, event.event_id))
        manifest = build_manifest(
            events, tenant_id="demo_tenant", batch_id="batch-offline-fixture-001",
            created_at_ms=START + 10,
        )
        return events, manifest
    finally:
        db.close()


def demo() -> dict:
    events, manifest = asyncio.run(demo_events())
    result = validate_manifest(manifest)
    pinned = manifest["commitment"]  # illustrative pin, NOT independently published
    original_passes = verify_complete_batch(events, manifest, trusted_commitment=pinned)
    included = verify_inclusion(
        events[-1], manifest, inclusion_path(manifest, events[-1].event_id),
        trusted_commitment=pinned,
    )
    removed_detected = False
    try:
        verify_complete_batch(events[:-1], manifest, trusted_commitment=pinned)
    except InvalidEvidence:
        removed_detected = True
    reorder_detected = False
    try:
        verify_complete_batch([events[1], events[0], events[2]], manifest,
                              trusted_commitment=pinned)
    except InvalidEvidence:
        reorder_detected = True
    changed = AuditEvent(**{**asdict(events[1]), "effect": "allow"})
    modified_detected = False
    try:
        verify_complete_batch([events[0], changed, events[2]], manifest,
                              trusted_commitment=pinned)
    except InvalidEvidence:
        modified_detected = True
    result_envelope = {
        "batch_id": manifest["batch_id"], "leaf_count": manifest["count"],
        "root_sha256": manifest["tree_root"],
        "commitment_sha256": manifest["commitment"],
        "status_without_independent_anchor": result,
        "locally_pinned_fixture_matches": original_passes and included,
        "removed_detected": removed_detected,
        "reordered_detected": reorder_detected,
        "modified_detected": modified_detected,
        "evm_proposal_not_submitted": True,
        "onchain_verified": False,
    }
    return result_envelope


def main() -> int:
    p = argparse.ArgumentParser(description="AgentShield deterministic offline Merkle integrity demo")
    p.add_argument("--assert-secure", action="store_true")
    args = p.parse_args()
    outcome = demo()
    print(json.dumps(outcome, sort_keys=True, indent=2))
    if args.assert_secure:
        required = ("locally_pinned_fixture_matches", "removed_detected",
                    "reordered_detected", "modified_detected", "evm_proposal_not_submitted")
        return 0 if all(outcome[k] for k in required) and not outcome["onchain_verified"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
