"""Fence one synthetic invoice invocation behind signed JWT and audited outbox.

No network, real third-party tools, automatic retries or externally usable
capabilities. Consuming a reservation before the stub yields AT MOST one
local stub invocation; a crash can leave it uninvoked and nonretryable.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from agentshield.approvals import ApprovalStore
from agentshield.audit import AuditRepository, AuditStorageError, action_digest, event_arguments
from agentshield.demo_invoice import INVOICE
from agentshield.idempotent_decisions import _fingerprint
from agentshield.identity import VerifiedAgent
from agentshield.local_command_outbox import _FIND, _ACTIVE, _audit_event, _verify_audit
from agentshield.local_tool_gate import LocalDryRunAdapter
from agentshield.policy import Effect
from agentshield.policy_registry import D1PolicyRegistry, SQLitePolicyRegistry

_DISPATCH = (
    "INSERT INTO local_mock_dispatch_reservations "
    "(tenant_id,command_id,dispatch_id,request_id,principal_id,"
    "claim_audit_event_id,dispatch_audit_event_id,decision_sha256,reserved_at_ms) "
    "SELECT c.tenant_id,c.command_id,?,c.request_id,c.principal_id,"
    "c.claim_audit_event_id,?,d.request_sha256,? "
    "FROM local_command_outbox c JOIN decision_requests d "
    "ON d.tenant_id=c.tenant_id AND d.request_id=c.request_id "
    "JOIN active_policy_versions a ON a.tenant_id=c.tenant_id "
    "WHERE c.tenant_id=? AND c.command_id=? AND c.state='claimed' "
    "AND c.claim_token=? AND c.claim_audit_event_id=? "
    "AND c.principal_id=? AND c.action_digest=? "
    "AND d.principal_id=? AND d.effect='allow' "
    "AND d.request_sha256=? AND d.policy_sha256=? "
    "AND d.policy_version=? AND d.expires_at_ms>? "
    "AND a.version=c.policy_version AND a.activated_at_ms=c.active_at_ms "
    "AND COALESCE(a.activation_marker,'')=c.active_marker "
    "ON CONFLICT(tenant_id,command_id) DO NOTHING"
)
_DISPATCH_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS("
    "SELECT 1 FROM local_mock_dispatch_reservations "
    "WHERE tenant_id=? AND command_id=? AND dispatch_id=? "
    "AND dispatch_audit_event_id=?)"
)
_FETCH_RESERVATION = (
    "SELECT tenant_id,command_id,dispatch_id,request_id,principal_id,"
    "claim_audit_event_id,dispatch_audit_event_id,decision_sha256 "
    "FROM local_mock_dispatch_reservations WHERE tenant_id=? AND command_id=?"
)


class MockDispatchRejected(ValueError):
    """One-shot capability proof was absent, invalid, stale or spent."""


@dataclass(frozen=True)
class MockDispatchReceipt:
    command_id: str
    dispatch_id: str
    audit_event_id: str
    policy_version: str
    stub_name: str


async def dispatch_claimed_invoice_mock(
    store: ApprovalStore,
    audit: AuditRepository,
    registry: D1PolicyRegistry | SQLitePolicyRegistry,
    agent: VerifiedAgent,
    *,
    command_id: str,
    now_ms: int,
    adapter: LocalDryRunAdapter,
) -> MockDispatchReceipt:
    """Only the original signed agent may consume a claimed invoice stub.

    Revalidate policy, original signed scopes, decision, queue and claim audit.
    Reserve a unique command dispatch and its audit atomically BEFORE invoking
    the in-process mock. The token never leaves D1 or reaches caller JSON.
    """
    if (agent.principal.id != f"{agent.tenant_id}:{agent.agent_id}"
        or type(now_ms) is not int or now_ms <= 0):
        raise MockDispatchRejected("Invalid signed identity or time")
    if (not isinstance(command_id, str)
        or not command_id.startswith("local-command-")
        or len(command_id) != len("local-command-") + 32
        or any(ch not in "0123456789abcdef" for ch in command_id[14:])):
        raise MockDispatchRejected("Invalid local command identifier")
    row = await store.first(_FIND, (agent.tenant_id, command_id))
    if (row is None or row["state"] != "claimed"
        or row["principal_id"] != agent.principal.id
        or not isinstance(row["claim_token"], str)
        or not isinstance(row["claim_audit_event_id"], str)
        or now_ms < row["claimed_at_ms"]):
        raise MockDispatchRejected("No eligible claimed command for this agent")
    digest = action_digest(INVOICE.tool, INVOICE.operation, INVOICE.resource)
    if row["action_digest"] != digest:
        raise MockDispatchRejected("Tool outside closed mock allowlist")

    active = await registry.load_active(agent.tenant_id)
    generation = await store.first(_ACTIVE, (agent.tenant_id,))
    if (active.version != row["policy_version"]
        or active.sha256 != row["policy_sha256"]
        or generation is None
        or generation["version"] != row["policy_version"]
        or generation["activated_at_ms"] != row["active_at_ms"]
        or generation["marker"] != row["active_marker"]
        or active.engine.evaluate(agent.principal, INVOICE).effect != Effect.ALLOW):
        raise MockDispatchRejected("Active signed policy no longer permits this action")
    decision_row = await store.first(
        "SELECT request_sha256,principal_id,policy_version,policy_sha256,"
        "expires_at_ms,event_id,effect FROM decision_requests "
        "WHERE tenant_id=? AND request_id=?",
        (agent.tenant_id, row["request_id"]),
    )
    expected = _fingerprint(
        agent, INVOICE, row["request_id"], active.version, active.sha256,
        row["active_at_ms"], row["active_marker"],
    )
    if (decision_row is None or decision_row["request_sha256"] != expected
        or decision_row["principal_id"] != agent.principal.id
        or decision_row["policy_version"] != active.version
        or decision_row["policy_sha256"] != active.sha256
        or decision_row["event_id"] != row["decision_event_id"]
        or decision_row["effect"] != "allow"
        or decision_row["expires_at_ms"] <= now_ms):
        raise MockDispatchRejected("Changed scope, identity or expired decision")
    await _verify_audit(
        audit, agent.tenant_id, row["decision_event_id"],
        agent.principal.id, digest, active.version,
    )
    await _verify_audit(
        audit, agent.tenant_id, row["queue_audit_event_id"],
        agent.principal.id, digest, active.version,
        "LOCAL_COMMAND_QUEUED_NO_DISPATCH",
    )
    claim = await audit.get_event(agent.tenant_id, row["claim_audit_event_id"])
    if (claim is None or claim.effect != "allow"
        or claim.reason_codes != ("LOCAL_COMMAND_CLAIMED_NO_DISPATCH",)
        or claim.action_digest != digest
        or claim.policy_version != active.version
        or not claim.principal_id.startswith(agent.tenant_id + ":")
        or claim.principal_id == agent.principal.id):
        raise AuditStorageError("Operator claim evidence unavailable")

    dispatch_id = "mock-dispatch-" + secrets.token_hex(16)
    audit_id = "mock-dispatch-audit-" + secrets.token_hex(16)
    evidence = _audit_event(
        audit_id, agent.tenant_id, agent.principal.id, digest,
        active.version, "LOCAL_MOCK_DISPATCH_RESERVED_NO_EXTERNAL_IO", now_ms,
    )
    await store.atomic([
        (_DISPATCH, (
            dispatch_id, audit_id, now_ms,
            agent.tenant_id, command_id, row["claim_token"],
            row["claim_audit_event_id"], agent.principal.id, digest,
            agent.principal.id, expected, active.sha256,
            active.version, now_ms,
        )),
        (_DISPATCH_AUDIT, event_arguments(evidence) +
         (agent.tenant_id, command_id, dispatch_id, audit_id)),
    ])
    reserved = await store.first(
        _FETCH_RESERVATION, (agent.tenant_id, command_id),
    )
    if (reserved is None or reserved["dispatch_id"] != dispatch_id
        or reserved["dispatch_audit_event_id"] != audit_id
        or reserved["principal_id"] != agent.principal.id
        or reserved["decision_sha256"] != expected
        or reserved["claim_audit_event_id"] != row["claim_audit_event_id"]):
        raise MockDispatchRejected("Command dispatch already spent or changed")
    await _verify_audit(
        audit, agent.tenant_id, audit_id, agent.principal.id, digest,
        active.version, "LOCAL_MOCK_DISPATCH_RESERVED_NO_EXTERNAL_IO",
    )
    # Drift after reservation must burn the command, not permit a later retry.
    current = await registry.load_active(agent.tenant_id)
    latest = await store.first(_ACTIVE, (agent.tenant_id,))
    if (current.version != active.version or current.sha256 != active.sha256
        or latest is None or latest["version"] != active.version
        or latest["activated_at_ms"] != row["active_at_ms"]
        or latest["marker"] != row["active_marker"]):
        raise MockDispatchRejected("Policy changed after reservation")
    # Only the preexisting in-memory invoice fixture is reachable here.
    stub_name = adapter.invoke(INVOICE)
    return MockDispatchReceipt(
        command_id=command_id, dispatch_id=dispatch_id,
        audit_event_id=audit_id, policy_version=active.version,
        stub_name=stub_name,
    )
