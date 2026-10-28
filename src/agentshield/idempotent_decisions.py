"""Bounded, fail-closed idempotent *decision* receipts (no tool execution).

Reuses immutable tenant policy snapshots, D1ApprovalStore.atomic and AuditEvent.
A decision_id is NOT a tool capability. Retries cannot restore a retired
policy, alter signed scopes or emit a second audit record.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass

from agentshield.approvals import ApprovalStore
from agentshield.audit import AuditEvent, AuditRepository, AuditStorageError, action_digest, event_arguments
from agentshield.identity import VerifiedAgent
from agentshield.policy import ToolAction
from agentshield.policy_registry import D1PolicyRegistry, SQLitePolicyRegistry, PolicyUnavailable

_REQUEST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{15,95}$")
_RETENTION_MS = 30 * 86_400_000
# Conservative LOCAL demo quota: one admission per fresh request key,
# shared by all authenticated principals of the signed tenant.
_WINDOW_MS = 60_000
_MAX_NEW_DECISIONS_PER_TENANT_WINDOW = 16
_INSERT_RATE_SLOT = (
    "INSERT INTO tenant_decision_rate_slots "
    "(tenant_id,window_start_ms,request_id,admitted_at_ms) "
    "SELECT ?,?,?,? WHERE NOT EXISTS ("
    "SELECT 1 FROM decision_requests WHERE tenant_id=? AND request_id=?) "
    "AND (SELECT COUNT(*) FROM tenant_decision_rate_slots "
    "WHERE tenant_id=? AND window_start_ms=?) < ? "
    "ON CONFLICT(tenant_id,request_id) DO NOTHING"
)

_ACTIVE = (
    "SELECT a.version,a.activated_at_ms,COALESCE(a.activation_marker,'') AS marker "
    "FROM active_policy_versions a WHERE a.tenant_id=?"
)
_FIND = (
    "SELECT tenant_id,request_id,principal_id,request_sha256,policy_version,"
    "policy_sha256,active_at_ms,active_marker,event_id,effect,reason_codes_json,"
    "matched_rule_ids_json,created_at_ms,expires_at_ms "
    "FROM decision_requests WHERE tenant_id=? AND request_id=?"
)
_INSERT = (
    "INSERT INTO decision_requests "
    "(tenant_id,request_id,principal_id,request_sha256,policy_version,policy_sha256,"
    "active_at_ms,active_marker,event_id,effect,reason_codes_json,"
    "matched_rule_ids_json,created_at_ms,expires_at_ms) "
    "SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS ("
    "SELECT 1 FROM active_policy_versions WHERE tenant_id=? AND version=? "
    "AND activated_at_ms=? AND COALESCE(activation_marker,'')=?) "
    "AND EXISTS (SELECT 1 FROM tenant_decision_rate_slots "
    "WHERE tenant_id=? AND request_id=? AND window_start_ms=?) "
    "ON CONFLICT(tenant_id,request_id) DO NOTHING"
)
_INSERT_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS ("
    "SELECT 1 FROM decision_requests WHERE tenant_id=? AND request_id=? "
    "AND event_id=? AND request_sha256=?) "
    "ON CONFLICT(event_id) DO NOTHING"
)


class DecisionReplayConflict(ValueError):
    """Request key reused with changed identity/action/policy, or expired."""


class DecisionRateLimited(ValueError):
    """Signed tenant reached its bounded local admission quota."""


@dataclass(frozen=True)
class DecisionReceipt:
    request_id: str
    event_id: str
    effect: str
    reason_codes: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    policy_version: str
    policy_sha256: str
    action_sha256: str
    replayed: bool


def _fingerprint(
    agent: VerifiedAgent, action: ToolAction, request_id: str,
    policy_version: str, policy_sha: str, epoch: int, marker: str,
) -> str:
    payload = {
        "schema": "agentshield.decision-request.v1",
        "tenant": agent.tenant_id, "principal": agent.principal.id,
        "scopes": sorted(agent.principal.scopes),
        "request_id": request_id, "tool": action.tool,
        "operation": action.operation, "resource": action.resource,
        "policy_version": policy_version, "policy_sha256": policy_sha,
        "activated_at_ms": epoch, "activation_marker": marker,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


async def decide_idempotently(
    store: ApprovalStore,
    repository: AuditRepository,
    registry: D1PolicyRegistry | SQLitePolicyRegistry,
    agent: VerifiedAgent,
    action: ToolAction,
    *,
    request_id: str,
    now_ms: int,
) -> DecisionReceipt:
    """Write one decision+audit per signed tenant/request key in one DB batch.

    A repeat with the same active generation and exact scope/action returns
    the original receipt and verified audit, but never authorizes execution.
    """
    if not isinstance(request_id, str) or not _REQUEST.fullmatch(request_id):
        raise ValueError("Invalid opaque request_id")
    if type(now_ms) is not int or now_ms <= 0:
        raise ValueError("Invalid decision timestamp")
    if agent.principal.id != f"{agent.tenant_id}:{agent.agent_id}":
        raise ValueError("Untrusted principal identity")

    active = await registry.load_active(agent.tenant_id)
    state = await store.first(_ACTIVE, (agent.tenant_id,))
    if (state is None or state["version"] != active.version
        or type(state["activated_at_ms"]) is not int
        or state["activated_at_ms"] <= 0
        or not isinstance(state["marker"], str)):
        raise PolicyUnavailable("Active policy generation unavailable")
    epoch, marker = state["activated_at_ms"], state["marker"]
    digest = _fingerprint(
        agent, action, request_id, active.version, active.sha256, epoch, marker
    )
    decision = active.engine.evaluate(agent.principal, action)
    event_id = "decision-" + secrets.token_hex(16)
    event = AuditEvent(
        event_id=event_id, tenant_id=agent.tenant_id,
        principal_id=agent.principal.id,
        action_digest=action_digest(action.tool, action.operation, action.resource),
        effect=decision.effect.value, reason_codes=decision.reasons,
        policy_version=active.version, occurred_at_ms=now_ms,
        retention_until_ms=now_ms + _RETENTION_MS,
    )
    # No existing receipt means a new request needs a quota slot.
    # The rate-slot reservation, immutable receipt and audit event are one
    # SERIALIZED D1/SQLite transaction. The slot check counts all principals
    # in the tenant, including denied actions, and prevents concurrent bypass.
    # Exact retries do not consume slots again.
    window = now_ms // _WINDOW_MS * _WINDOW_MS
    await store.atomic([
        (_INSERT_RATE_SLOT, (
            agent.tenant_id, window, request_id, now_ms,
            agent.tenant_id, request_id, agent.tenant_id, window,
            _MAX_NEW_DECISIONS_PER_TENANT_WINDOW,
        )),
        (_INSERT, (
            agent.tenant_id, request_id, agent.principal.id, digest,
            active.version, active.sha256, epoch, marker, event_id,
            decision.effect.value,
            json.dumps(list(decision.reasons), separators=(",", ":")),
            json.dumps(list(decision.matched_rule_ids), separators=(",", ":")),
            now_ms, now_ms + _RETENTION_MS,
            agent.tenant_id, active.version, epoch, marker,
            agent.tenant_id, request_id, window,
        )),
        (_INSERT_AUDIT, event_arguments(event) +
         (agent.tenant_id, request_id, event_id, digest)),
    ])
    row = await store.first(_FIND, (agent.tenant_id, request_id))
    if row is None:
        # A stale generation or a cap hit must never mint a fake ALLOW;
        # distinguish them only after confirming the current generation.
        current = await store.first(_ACTIVE, (agent.tenant_id,))
        if (current is None or current["version"] != active.version
            or current["activated_at_ms"] != epoch
            or current["marker"] != marker):
            raise DecisionReplayConflict("Policy version changed during admission")
        raise DecisionRateLimited("Tenant decision admission quota exceeded")
    if (row["principal_id"] != agent.principal.id
        or row["request_sha256"] != digest
        or row["policy_version"] != active.version
        or row["policy_sha256"] != active.sha256
        or row["active_at_ms"] != epoch
        or row["active_marker"] != marker):
        raise DecisionReplayConflict("Request ID reused for incompatible decision")
    if type(row["expires_at_ms"]) is not int or row["expires_at_ms"] <= now_ms:
        raise DecisionReplayConflict("Decision idempotency window expired")
    try:
        reasons = tuple(json.loads(row["reason_codes_json"]))
        matched = tuple(json.loads(row["matched_rule_ids_json"]))
    except (ValueError, TypeError) as exc:
        raise AuditStorageError("Corrupt decision receipt") from exc
    if (row["effect"] != decision.effect.value
        or reasons != decision.reasons or matched != decision.matched_rule_ids):
        raise AuditStorageError("Stored decision does not match active policy")
    stored = await repository.get_event(agent.tenant_id, row["event_id"])
    if (stored is None or stored.principal_id != agent.principal.id
        or stored.action_digest != event.action_digest
        or stored.effect != row["effect"] or stored.reason_codes != reasons
        or stored.policy_version != active.version
        or stored.occurred_at_ms != row["created_at_ms"]):
        raise AuditStorageError("Decision audit missing or inconsistent")
    latest = await registry.load_active(agent.tenant_id)
    generation = await store.first(_ACTIVE, (agent.tenant_id,))
    if (latest.version != active.version or latest.sha256 != active.sha256
        or generation is None or generation["version"] != active.version
        or generation["activated_at_ms"] != epoch or generation["marker"] != marker):
        raise DecisionReplayConflict("Policy changed while deciding")
    return DecisionReceipt(
        request_id=request_id, event_id=row["event_id"],
        effect=row["effect"], reason_codes=reasons,
        matched_rule_ids=matched, policy_version=active.version,
        policy_sha256=active.sha256, action_sha256=event.action_digest,
        replayed=row["event_id"] != event_id,
    )
