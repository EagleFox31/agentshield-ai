"""Local-only approval API with cryptographically separate human operator JWTs.

No public approval endpoints or real tool execution are exposed in this slice.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict
from typing import Literal

from agentshield.approvals import (
    ApprovalRejected, D1ApprovalStore, POLICY_VERSION,
    consume_mock, create_pending, expire_if_needed, get_approval,
    list_approvals, review,
)
from agentshield.audit import AuditStorageError
from agentshield.identity import (
    AgentAuthenticationError, IdentityConfigurationError,
    VerifiedAgent, require_bearer,
)
from agentshield.policy import Effect, PolicyEngine, Rule, ToolAction
from agentshield.approvals_dashboard import DASHBOARD_HTML

router = APIRouter()


class DemoAction(BaseModel):
    """Only synthetic fixture IDs, never bank account fields or arbitrary tools."""
    model_config = ConfigDict(extra="forbid")
    fixture: Literal["scenario-A", "scenario-B"] = "scenario-A"


DEMO_ACTION = ToolAction("suppliers", "update_bank_account", "supplier/482")


def _local_env(request: Request):
    env = request.scope.get("env")
    if env is None or getattr(env, "LOCAL_SMOKE_ENABLED", None) != "true":
        raise HTTPException(status_code=404, detail="Not found")
    return env


def _identity(request: Request, prefix: str, required_scope: str | None = None) -> VerifiedAgent:
    env = _local_env(request)
    config = {
        "AGENT_JWT_ISSUER": str(getattr(env, prefix + "_JWT_ISSUER", "") or ""),
        "AGENT_JWT_AUDIENCE": str(getattr(env, prefix + "_JWT_AUDIENCE", "") or ""),
        "AGENT_JWKS_JSON": str(getattr(env, prefix + "_JWKS_JSON", "") or ""),
    }
    try:
        verified = require_bearer(request.headers.get("authorization"), config)
    except IdentityConfigurationError as exc:
        raise HTTPException(status_code=503, detail="Identity trust root unavailable") from exc
    except AgentAuthenticationError as exc:
        raise HTTPException(
            status_code=401, detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    if required_scope is not None and required_scope not in verified.principal.scopes:
        raise HTTPException(status_code=403, detail="Insufficient operator scope")
    return verified


def _store(request: Request) -> D1ApprovalStore:
    env = _local_env(request)
    try:
        return D1ApprovalStore(getattr(env, "DB", None))
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Approval storage unavailable") from exc


def _policy(agent: VerifiedAgent) -> PolicyEngine:
    # This fixture is NOT a dynamic authorization policy registry.
    # The scope must also be signed and present in the JWT.
    return PolicyEngine([
        Rule(
            id="local-supplier-mutation-review",
            principal_id=agent.principal.id,
            tool=DEMO_ACTION.tool,
            operation=DEMO_ACTION.operation,
            resource=DEMO_ACTION.resource,
            required_scope="supplier:write",
            effect=Effect.REQUIRE_APPROVAL,
        ),
    ])


def _now() -> int:
    return int(time.time() * 1000)


def _data(row, now_ms: int) -> dict:
    return {
        "approval_id": row.approval_id,
        "tenant_id": row.tenant_id,
        "action": "Simulated supplier bank detail change",
        "action_digest": row.action_digest,
        "state": "expired" if row.expires_at_ms <= now_ms and row.state in ("pending", "approved") else row.state,
        "expires_at_ms": row.expires_at_ms,
        "policy_version": row.policy_version,
        "executed": False,
    }


@router.post("/_local/demo/approval-requests")
async def demo_create(body: DemoAction, request: Request):
    agent = _identity(request, "AGENT")
    store = _store(request)
    now = _now()
    try:
        row = await create_pending(
            store, agent, DEMO_ACTION, {"fixture": body.fixture},
            _policy(agent), now,
        )
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail="Not eligible for review") from exc
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Audit write failed") from exc
    return _data(row, now)


@router.get("/_local/approvals")
async def operator_list(request: Request):
    operator = _identity(request, "OPERATOR", "approvals:read")
    store = _store(request)
    now = _now()
    try:
        rows = await list_approvals(store, operator.tenant_id)
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Approval read failed") from exc
    return {"approvals": [_data(x, now) for x in rows], "enforcement_ready": False}


@router.post("/_local/approvals/{approval_id}/{decision}")
async def operator_review(approval_id: str, decision: Literal["approve", "reject"], request: Request):
    operator = _identity(request, "OPERATOR", "approvals:decide")
    store = _store(request)
    now = _now()
    try:
        row = await get_approval(store, operator.tenant_id, approval_id)
        if row is not None and row.state == "pending" and row.expires_at_ms <= now:
            await expire_if_needed(store, operator.tenant_id, approval_id, now)
            raise HTTPException(status_code=409, detail="Approval expired")
        changed = await review(
            store, approval_id, operator.tenant_id,
            operator.principal.id,
            "approved" if decision == "approve" else "rejected", now,
        )
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail="Self-approval denied") from exc
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Approval audit failed") from exc
    if not changed:
        raise HTTPException(status_code=409, detail="Approval unavailable or already decided")
    return {"approval_id": approval_id, "state": "approved" if decision == "approve" else "rejected",
            "executed": False}


@router.get("/_local/approvals/{approval_id}/audit")
async def operator_audit(approval_id: str, request: Request):
    operator = _identity(request, "OPERATOR", "approvals:read")
    store = _store(request)
    try:
        row = await get_approval(store, operator.tenant_id, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Unknown approval")
        items = await store.many(
            "SELECT event_id,tenant_id,event_sha256,reason_codes_json,occurred_at_ms "
            "FROM audit_events WHERE tenant_id=? AND action_digest=? "
            "ORDER BY occurred_at_ms DESC LIMIT 25",
            (operator.tenant_id, row.action_digest),
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Audit read failed") from exc
    return {"approval_id": approval_id, "events": items}


@router.post("/_local/demo/approvals/{approval_id}/consume")
async def demo_consume(approval_id: str, body: DemoAction, request: Request):
    agent = _identity(request, "AGENT")
    store = _store(request)
    try:
        success = await consume_mock(
            store, agent, approval_id, DEMO_ACTION,
            {"fixture": body.fixture}, _policy(agent), _now(),
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Consumption audit failed") from exc
    if not success:
        raise HTTPException(status_code=409, detail="Action not approved or no longer valid")
    return {"approval_id": approval_id, "state": "consumed",
            "simulated_execution": True, "real_tool_called": False}


@router.get("/_local/dashboard", response_class=HTMLResponse)
async def local_dashboard(request: Request):
    _local_env(request)
    return HTMLResponse(
        DASHBOARD_HTML,
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; "
              "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
              "form-action 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        },
    )
