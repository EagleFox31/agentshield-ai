"""Fail-closed policy -> durable audit orchestration; no tool execution."""
from __future__ import annotations

from agentshield.audit import AuditEvent, AuditRepository, action_digest
from agentshield.policy import Decision, PolicyEngine, Principal, ToolAction


async def decide_and_audit(
    engine: PolicyEngine,
    repository: AuditRepository,
    principal: Principal,
    tenant_id: str,
    action: ToolAction,
    *,
    event_id: str,
    policy_version: str,
    occurred_at_ms: int,
    retention_days: int = 30,
) -> Decision:
    """Return a decision only after durable, verified audit persistence.

    This is not an execution permit. A future restricted adapter must also
    check current identity/scope, policy, nonce and approval obligations.
    """
    if not principal.id.startswith(f"{tenant_id}:"):
        raise ValueError("Verified principal does not belong to tenant")
    decision = engine.evaluate(principal, action)
    event = AuditEvent(
        event_id=event_id, tenant_id=tenant_id, principal_id=principal.id,
        action_digest=action_digest(action.tool, action.operation, action.resource),
        effect=decision.effect.value, reason_codes=decision.reasons,
        policy_version=policy_version,
        occurred_at_ms=occurred_at_ms,
        retention_until_ms=occurred_at_ms + retention_days * 86_400_000,
    )
    # Never swallow this error: a failed audit must never return ALLOW.
    await repository.record_event(event)
    return decision
