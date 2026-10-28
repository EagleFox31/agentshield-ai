"""LOCAL-ONLY durable outbox for a single synthetic invoice-read command.

No worker dispatch loop, external I/O, automatic redelivery or real execution.
A claimed command is fenced and must be reconciled, never auto-requeued.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from agentshield.approvals import ApprovalStore
from agentshield.audit import (
    AuditEvent, AuditRepository, AuditStorageError, action_digest, event_arguments,
)
from agentshield.demo_invoice import INVOICE
from agentshield.idempotent_decisions import decide_idempotently
from agentshield.identity import VerifiedAgent
from agentshield.policy import ToolAction
from agentshield.policy_registry import D1PolicyRegistry, SQLitePolicyRegistry, PolicyUnavailable

_RETENTION_MS = 30 * 86_400_000
_FIND = (
    "SELECT tenant_id,request_id,command_id,principal_id,decision_event_id,"
    "queue_audit_event_id,claim_audit_event_id,reconcile_audit_event_id,"
    "policy_version,policy_sha256,active_at_ms,active_marker,action_digest,"
    "state,claim_token,created_at_ms,claimed_at_ms,updated_at_ms "
    "FROM local_command_outbox WHERE tenant_id=? AND command_id=?"
)
_FIND_BY_REQUEST = _FIND.replace(
    "WHERE tenant_id=? AND command_id=?", "WHERE tenant_id=? AND request_id=?"
)
_ACTIVE = (
    "SELECT version,activated_at_ms,COALESCE(activation_marker,'') AS marker "
    "FROM active_policy_versions WHERE tenant_id=?"
)
_QUEUE = (
    "INSERT INTO local_command_outbox "
    "(tenant_id,request_id,command_id,principal_id,decision_event_id,"
    "queue_audit_event_id,policy_version,policy_sha256,active_at_ms,"
    "active_marker,action_digest,state,created_at_ms,updated_at_ms) "
    "SELECT dr.tenant_id,dr.request_id,?,dr.principal_id,dr.event_id,?,"
    "dr.policy_version,dr.policy_sha256,dr.active_at_ms,dr.active_marker,"
    "ae.action_digest,'queued',?,? "
    "FROM decision_requests dr JOIN audit_events ae "
    "ON ae.event_id=dr.event_id AND ae.tenant_id=dr.tenant_id "
    "JOIN active_policy_versions ap ON ap.tenant_id=dr.tenant_id "
    "WHERE dr.tenant_id=? AND dr.request_id=? AND dr.principal_id=? "
    "AND dr.event_id=? AND dr.effect='allow' AND ae.effect='allow' "
    "AND ae.action_digest=? AND dr.policy_version=? AND dr.policy_sha256=? "
    "AND ap.version=dr.policy_version AND ap.activated_at_ms=dr.active_at_ms "
    "AND COALESCE(ap.activation_marker,'')=dr.active_marker "
    "AND dr.expires_at_ms>? "
    "ON CONFLICT(tenant_id,request_id) DO NOTHING"
)
_QUEUE_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS("
    "SELECT 1 FROM local_command_outbox "
    "WHERE tenant_id=? AND request_id=? AND command_id=? "
    "AND queue_audit_event_id=?) ON CONFLICT(event_id) DO NOTHING"
)
_CLAIM = (
    "UPDATE local_command_outbox SET state='claimed',claim_token=?,"
    "claimed_at_ms=?,updated_at_ms=?,claim_audit_event_id=? "
    "WHERE tenant_id=? AND command_id=? AND state='queued' "
    "AND EXISTS(SELECT 1 FROM active_policy_versions "
    "WHERE tenant_id=? AND version=local_command_outbox.policy_version "
    "AND activated_at_ms=local_command_outbox.active_at_ms "
    "AND COALESCE(activation_marker,'')=local_command_outbox.active_marker)"
)
_CLAIM_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS("
    "SELECT 1 FROM local_command_outbox WHERE tenant_id=? AND command_id=? "
    "AND state='claimed' AND claim_token=? AND claim_audit_event_id=?)"
)
_UNCERTAIN = (
    "UPDATE local_command_outbox SET state='uncertain',updated_at_ms=?,"
    "reconcile_audit_event_id=? WHERE tenant_id=? AND command_id=? "
    "AND state='claimed' AND claim_token=?"
)
_UNCERTAIN_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS("
    "SELECT 1 FROM local_command_outbox WHERE tenant_id=? AND command_id=? "
    "AND state='uncertain' AND claim_token=? AND reconcile_audit_event_id=?)"
)


class CommandConflict(ValueError):
    """Stale, already claimed, altered or otherwise non-dispatchable command."""


@dataclass(frozen=True)
class CommandReceipt:
    command_id: str
    request_id: str
    decision_event_id: str
    queue_audit_event_id: str
    state: str
    policy_version: str
    replayed: bool


def _assert_agent(agent: VerifiedAgent) -> None:
    if agent.principal.id != f"{agent.tenant_id}:{agent.agent_id}":
        raise CommandConflict("Signed identity mismatch")


def _assert_operator(operator: VerifiedAgent, scope: str) -> None:
    _assert_agent(operator)
    if scope not in operator.principal.scopes:
        raise CommandConflict("Operator lacks command scope")


def _audit_event(
    event_id: str, tenant: str, actor: str, digest: str,
    version: str, reason: str, now_ms: int,
) -> AuditEvent:
    return AuditEvent(
        event_id=event_id, tenant_id=tenant, principal_id=actor,
        action_digest=digest, effect="allow", reason_codes=(reason,),
        policy_version=version, occurred_at_ms=now_ms,
        retention_until_ms=now_ms + _RETENTION_MS,
    )


async def _verify_audit(
    repository: AuditRepository, tenant: str, event_id: str,
    actor: str, digest: str, version: str, reason: str | None = None,
) -> None:
    event = await repository.get_event(tenant, event_id)
    if (event is None or event.principal_id != actor
        or event.action_digest != digest or event.policy_version != version
        or (reason is not None and event.reason_codes != (reason,))):
        raise AuditStorageError("Outbox audit missing or inconsistent")


async def queue_local_invoice(
    store: ApprovalStore, audit: AuditRepository,
    registry: D1PolicyRegistry | SQLitePolicyRegistry,
    agent: VerifiedAgent, *,
    request_id: str, now_ms: int,
) -> CommandReceipt:
    """One queue record per audited, permitted invoice read; never dispatch."""
    _assert_agent(agent)
    result = await decide_idempotently(
        store, audit, registry, agent, INVOICE,
        request_id=request_id, now_ms=now_ms,
    )
    if result.effect != "allow":
        raise CommandConflict("Only permitted synthetic invoice read can be queued")
    command_id = "local-command-" + secrets.token_hex(16)
    audit_id = "outbox-queued-" + secrets.token_hex(16)
    queued = _audit_event(
        audit_id, agent.tenant_id, agent.principal.id, result.action_sha256,
        result.policy_version, "LOCAL_COMMAND_QUEUED_NO_DISPATCH", now_ms,
    )
    await store.atomic([
        (_QUEUE, (command_id, audit_id, now_ms, now_ms, agent.tenant_id,
                  request_id, agent.principal.id, result.event_id,
                  result.action_sha256, result.policy_version,
                  result.policy_sha256, now_ms)),
        (_QUEUE_AUDIT, event_arguments(queued) +
         (agent.tenant_id, request_id, command_id, audit_id)),
    ])
    row = await store.first(_FIND_BY_REQUEST, (agent.tenant_id, request_id))
    if (row is None or row["principal_id"] != agent.principal.id
        or row["decision_event_id"] != result.event_id
        or row["policy_version"] != result.policy_version
        or row["policy_sha256"] != result.policy_sha256
        or row["action_digest"] != result.action_sha256):
        raise CommandConflict("Outbox request altered or not committed")
    await _verify_audit(
        audit, agent.tenant_id, row["queue_audit_event_id"],
        agent.principal.id, result.action_sha256, result.policy_version,
        "LOCAL_COMMAND_QUEUED_NO_DISPATCH",
    )
    return CommandReceipt(
        command_id=row["command_id"], request_id=request_id,
        decision_event_id=result.event_id,
        queue_audit_event_id=row["queue_audit_event_id"],
        state=row["state"], policy_version=row["policy_version"],
        replayed=row["command_id"] != command_id,
    )


async def claim_local_command(
    store: ApprovalStore, audit: AuditRepository,
    registry: D1PolicyRegistry | SQLitePolicyRegistry,
    operator: VerifiedAgent, *,
    command_id: str, now_ms: int,
) -> dict[str, object]:
    """Fence command once, with audited claim. Does NOT execute the command."""
    _assert_operator(operator, "commands:claim")
    row = await store.first(_FIND, (operator.tenant_id, command_id))
    if row is None or row["state"] != "queued":
        raise CommandConflict("Command unavailable for claiming")
    if type(now_ms) is not int or now_ms < row["created_at_ms"]:
        raise CommandConflict("Invalid claim time")
    if row["action_digest"] != action_digest(INVOICE.tool, INVOICE.operation, INVOICE.resource):
        raise CommandConflict("Command not in local allowlist")
    active = await registry.load_active(operator.tenant_id)
    state = await store.first(_ACTIVE, (operator.tenant_id,))
    if (active.version != row["policy_version"] or active.sha256 != row["policy_sha256"]
        or state is None or state["activated_at_ms"] != row["active_at_ms"]
        or state["marker"] != row["active_marker"]):
        raise CommandConflict("Policy generation changed; cannot claim")
    await _verify_audit(
        audit, operator.tenant_id, row["decision_event_id"],
        row["principal_id"], row["action_digest"], row["policy_version"],
    )
    await _verify_audit(
        audit, operator.tenant_id, row["queue_audit_event_id"],
        row["principal_id"], row["action_digest"], row["policy_version"],
        "LOCAL_COMMAND_QUEUED_NO_DISPATCH",
    )
    token = "claim-" + secrets.token_hex(16)
    event_id = "outbox-claimed-" + secrets.token_hex(16)
    event = _audit_event(
        event_id, operator.tenant_id, operator.principal.id,
        row["action_digest"], row["policy_version"],
        "LOCAL_COMMAND_CLAIMED_NO_DISPATCH", now_ms,
    )
    await store.atomic([
        (_CLAIM, (token, now_ms, now_ms, event_id, operator.tenant_id,
                  command_id, operator.tenant_id)),
        (_CLAIM_AUDIT, event_arguments(event) +
         (operator.tenant_id, command_id, token, event_id)),
    ])
    latest = await store.first(_FIND, (operator.tenant_id, command_id))
    if (latest is None or latest["state"] != "claimed"
        or latest["claim_token"] != token or latest["claim_audit_event_id"] != event_id):
        raise CommandConflict("Command already claimed or policy changed")
    await _verify_audit(
        audit, operator.tenant_id, event_id, operator.principal.id,
        row["action_digest"], row["policy_version"],
        "LOCAL_COMMAND_CLAIMED_NO_DISPATCH",
    )
    return {
        "command_id": command_id, "state": "claimed",
        "claim_audit_event_id": event_id,
        "real_tool_called": False, "executed": False, "enforcement_ready": False,
    }


async def mark_local_uncertain(
    store: ApprovalStore, audit: AuditRepository,
    operator: VerifiedAgent, *,
    command_id: str, now_ms: int,
) -> dict[str, object]:
    """Simulate crash recovery: never redispatch, only flag unknown outcome."""
    _assert_operator(operator, "commands:reconcile")
    row = await store.first(_FIND, (operator.tenant_id, command_id))
    if row is None or row["state"] != "claimed":
        raise CommandConflict("Only a claimed command can enter reconciliation")
    if type(now_ms) is not int or now_ms < row["claimed_at_ms"]:
        raise CommandConflict("Invalid recovery timestamp")
    event_id = "outbox-uncertain-" + secrets.token_hex(16)
    event = _audit_event(
        event_id, operator.tenant_id, operator.principal.id,
        row["action_digest"], row["policy_version"],
        "LOCAL_COMMAND_UNCERTAIN_NO_DISPATCH", now_ms,
    )
    await store.atomic([
        (_UNCERTAIN, (now_ms, event_id, operator.tenant_id,
                     command_id, row["claim_token"])),
        (_UNCERTAIN_AUDIT, event_arguments(event) +
         (operator.tenant_id, command_id, row["claim_token"], event_id)),
    ])
    latest = await store.first(_FIND, (operator.tenant_id, command_id))
    if (latest is None or latest["state"] != "uncertain"
        or latest["reconcile_audit_event_id"] != event_id):
        raise CommandConflict("Recovery already reconciled or raced")
    await _verify_audit(
        audit, operator.tenant_id, event_id, operator.principal.id,
        row["action_digest"], row["policy_version"],
        "LOCAL_COMMAND_UNCERTAIN_NO_DISPATCH",
    )
    return {
        "command_id": command_id, "state": "uncertain",
        "reconcile_audit_event_id": event_id,
        "real_tool_called": False, "executed": False, "enforcement_ready": False,
    }
