"""Read-only LOCAL D1 evidence for a separately signed host SERVICE principal.

This is a diagnostic and manual reconciliation input, NEVER an execution
permit. No raw signed token, JTI, credentials, prompts, or arbitrary queries.
The caller's tenant comes solely from verified SERVICE JWT claims.
"""
from __future__ import annotations

import re

from agentshield.approvals import ApprovalStore
from agentshield.audit import AuditRepository, AuditStorageError
from agentshield.local_command_outbox import _verify_audit

_COMMAND = re.compile(r"local-command-[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_READ = (
    "SELECT c.state,c.principal_id,c.policy_version,c.action_digest,"
    "c.decision_event_id,c.queue_audit_event_id,c.claim_audit_event_id,"
    "r.dispatch_id,r.dispatch_audit_event_id,"
    "i.issuance_id,i.token_sha256,i.audit_event_id AS issuance_audit_id "
    "FROM local_command_outbox c "
    "LEFT JOIN local_mock_dispatch_reservations r "
    "ON r.tenant_id=c.tenant_id AND r.command_id=c.command_id "
    "LEFT JOIN local_handoff_issuances i "
    "ON i.tenant_id=c.tenant_id AND i.command_id=c.command_id "
    "WHERE c.tenant_id=? AND c.command_id=?"
)


class EvidenceUnavailable(ValueError):
    """No trustworthy local evidence exists for the scoped command."""


async def read_local_handoff_evidence(
    store: ApprovalStore, audit: AuditRepository, *,
    tenant_id: str, command_id: str,
) -> dict[str, object]:
    """Inspect redacted lineage without minting, returning or burning a token."""
    if not isinstance(command_id, str) or _COMMAND.fullmatch(command_id) is None:
        raise EvidenceUnavailable("Invalid command")
    row = await store.first(_READ, (tenant_id, command_id))
    if row is None:
        raise EvidenceUnavailable("No command for authenticated service tenant")
    state = row["state"]
    if state not in {"queued", "claimed", "uncertain"}:
        raise AuditStorageError("Unknown command state")
    digest = row["action_digest"]
    version = row["policy_version"]
    actor = row["principal_id"]
    if (not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
        or not isinstance(version, str) or not isinstance(actor, str)
        or not actor.startswith(tenant_id + ":")):
        raise AuditStorageError("Invalid source evidence")
    # Trust only canonical historical audit rows, not mutable HTTP fields.
    for key, reason in (
        ("decision_event_id", None),
        ("queue_audit_event_id", "LOCAL_COMMAND_QUEUED_NO_DISPATCH"),
    ):
        await _verify_audit(audit, tenant_id, row[key], actor, digest, version, reason)
    claim_event = row["claim_audit_event_id"]
    if state != "queued" and not claim_event:
        raise AuditStorageError("Claim audit is missing")
    if claim_event is not None:
        claim = await audit.get_event(tenant_id, claim_event)
        if (claim is None or claim.action_digest != digest
            or claim.policy_version != version or claim.effect != "allow"
            or claim.reason_codes != ("LOCAL_COMMAND_CLAIMED_NO_DISPATCH",)
            or not claim.principal_id.startswith(tenant_id + ":")
            or claim.principal_id == actor):
            raise AuditStorageError("Independent operator claim unverified")

    dispatch_id = row["dispatch_id"]
    dispatch_audit = row["dispatch_audit_event_id"]
    if (dispatch_id is None) != (dispatch_audit is None):
        raise AuditStorageError("Incomplete dispatch record")
    if dispatch_id is not None:
        await _verify_audit(
            audit, tenant_id, dispatch_audit, actor, digest, version,
            "LOCAL_MOCK_DISPATCH_RESERVED_NO_EXTERNAL_IO",
        )
    issuance_id = row["issuance_id"]
    token_hash = row["token_sha256"]
    issuance_audit = row["issuance_audit_id"]
    if issuance_id is not None:
        if (dispatch_id is None or not isinstance(token_hash, str)
            or _SHA256.fullmatch(token_hash) is None or not issuance_audit):
            raise AuditStorageError("Incomplete signed issuance evidence")
        await _verify_audit(
            audit, tenant_id, issuance_audit, actor, digest, version,
            "LOCAL_SIGNED_HANDOFF_ISSUED_NO_EXECUTION",
        )
    elif token_hash is not None or issuance_audit is not None:
        raise AuditStorageError("Inconsistent issuance evidence")

    return {
        "command_id": command_id,
        "tenant_id": tenant_id,
        "state": state,
        "policy_version": version,
        "action_sha256": digest,
        "dispatch_recorded": dispatch_id is not None,
        "issuance_recorded": issuance_id is not None,
        "token_sha256": token_hash if issuance_id is not None else None,
        "evidence_verified_locally": True,
        "transport_attested": False,
        "execution_authorized": False,
        "external_network_used": False,
        "production_ready": False,
        "local_only": True,
    }
