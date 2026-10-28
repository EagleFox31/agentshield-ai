"""Local-only, bounded fake tool execution after durable policy enforcement.

No real adapter, network access, file mutation, or external billing exists.
Approvals are atomically consumed and audited by the existing store before
the synthetic adapter records anything. This is NOT a production gateway.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from agentshield.approvals import (
    ApprovalRejected, ApprovalStore, consume_mock,
)
from agentshield.audit import AuditRepository
from agentshield.audit_service import decide_and_audit
from agentshield.demo_invoice import (
    INVOICE, SUPPLIER_CHANGE, POLICY_VERSION, RecordingMockTools,
    _rules,
)
from agentshield.identity import VerifiedAgent
from agentshield.policy import Effect, ToolAction

_MAX_NONCE_LIFETIME_MS = 120_000


class MockGateRejected(Exception):
    """An unauthorised, unavailable, or replayed synthetic action."""


@dataclass
class LocalDryRunAdapter:
    """Recording-only allowlist. No supplier updates, sockets or external SDKs."""

    calls: list[str] = field(default_factory=list)

    def invoke(self, action: ToolAction) -> str:
        if action == INVOICE:
            # Reuse the existing synthetic invoice reader, not an external API.
            text = RecordingMockTools().read_invoice()
            if not text:
                raise RuntimeError("Empty synthetic fixture")
            self.calls.append("mock_invoice_read")
            return "mock_invoice_read"
        if action == SUPPLIER_CHANGE:
            # Deliberately NEVER call RecordingMockTools.update_supplier() or
            # any real provider. This is a dry-run record, not a mutation.
            self.calls.append("mock_supplier_write_dry_run")
            return "mock_supplier_write_dry_run"
        raise MockGateRejected("No local adapter for this action")


async def execute_local_mock(
    repository: AuditRepository,
    approvals: ApprovalStore,
    agent: VerifiedAgent,
    action: ToolAction,
    *,
    fixture: str,
    nonce: str,
    approval_id: str | None,
    now_ms: int,
    adapter: LocalDryRunAdapter,
) -> dict[str, object]:
    """Fail closed: audit -> replay gate -> exact approval -> mock invocation.

    The nonce limits repeated local fixture runs. It is not a production-grade
    idempotent result registry and does not provide exactly-once real-world I/O.
    """
    if action not in (INVOICE, SUPPLIER_CHANGE):
        # Do not dispatch even if a future policy mistakenly allows it.
        raise MockGateRejected("Action outside local adapter allowlist")
    if fixture not in ("scenario-A", "scenario-B"):
        raise MockGateRejected("Unknown local fixture")
    if not isinstance(now_ms, int) or now_ms <= 0:
        raise MockGateRejected("Invalid evaluation time")
    if agent.principal.id != f"{agent.tenant_id}:{agent.agent_id}":
        raise MockGateRejected("Signed identity mismatch")

    decision_id = "mock-decision-" + secrets.token_hex(16)
    engine = _rules(agent.principal)
    decision = await decide_and_audit(
        engine, repository, agent.principal, agent.tenant_id, action,
        event_id=decision_id, policy_version=POLICY_VERSION,
        occurred_at_ms=now_ms, retention_days=30,
    )
    if decision.effect == Effect.DENY:
        raise MockGateRejected("Not permitted by policy")
    if decision.effect == Effect.REQUIRE_APPROVAL:
        if not approval_id:
            raise MockGateRejected("Human approval required")
    elif approval_id is not None:
        raise MockGateRejected("Unnecessary approval is not accepted")
    if not await repository.consume_nonce(
        agent.tenant_id, nonce, now_ms,
        now_ms + _MAX_NONCE_LIFETIME_MS,
    ):
        raise MockGateRejected("Repeated local request")
    if decision.effect == Effect.REQUIRE_APPROVAL:
        try:
            consumed = await consume_mock(
                approvals, agent, approval_id, action,
                {"fixture": fixture}, engine, now_ms,
            )
        except ApprovalRejected as exc:
            raise MockGateRejected("Invalid human approval") from exc
        if not consumed:
            raise MockGateRejected("Approval missing, expired, or already consumed")

    # This is the only call site for the stub. No real action can be run.
    result = adapter.invoke(action)
    return {
        "decision_id": decision_id,
        "effect": decision.effect.value,
        "mock_result": result,
        "mock_invoked": True,
        "audit_recorded": True,
        "real_tool_called": False,
        "executed": False,
        "enforcement_ready": False,
        "local_only": True,
    }
