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
from agentshield.audit import AuditStorageError, decode_event
from agentshield.merkle import build_manifest, inclusion_path, validate_manifest, InvalidEvidence
from agentshield.identity import (
    AgentAuthenticationError, IdentityConfigurationError,
    VerifiedAgent,
)
from agentshield.policy import Effect, PolicyEngine, Principal, Rule, ToolAction
from agentshield.detection import UntrustedSegment, ToolObservation, assess_threat
from agentshield.ai_budget import D1AIBudget
from agentshield.workers_ai_adapter import WorkersAIBindingAdapter, WorkersAISettings

from agentshield.demo_invoice import INVOICE_TEXT, SUPPLIER_CHANGE
from agentshield.policy_registry import D1PolicyRegistry, PublishedPolicy
from agentshield.approvals_dashboard import DASHBOARD_HTML
from agentshield.webcrypto_es256_spike import verify_es256_signature_webcrypto
from agentshield.webcrypto_jwt_candidate import verify_agent_jwt_webcrypto, require_bearer_webcrypto

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


async def _identity(request: Request, prefix: str, required_scope: str | None = None) -> VerifiedAgent:
    env = _local_env(request)
    config = {
        "AGENT_JWT_ISSUER": str(getattr(env, prefix + "_JWT_ISSUER", "") or ""),
        "AGENT_JWT_AUDIENCE": str(getattr(env, prefix + "_JWT_AUDIENCE", "") or ""),
        "AGENT_JWKS_JSON": str(getattr(env, prefix + "_JWKS_JSON", "") or ""),
    }
    try:
        verified = await require_bearer_webcrypto(request.headers.get("authorization"), config)
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


async def _active_policy(request: Request, tenant_id: str) -> PublishedPolicy:
    """Load and verify the signed tenant's active snapshot (no caller version)."""
    store = D1PolicyRegistry(getattr(_local_env(request), "DB", None))
    return await store.load_active(tenant_id)


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
    agent = await _identity(request, "AGENT")
    store = _store(request)
    now = _now()
    try:
        active = await _active_policy(request, agent.tenant_id)
        row = await create_pending(
            store, agent, DEMO_ACTION, {"fixture": body.fixture},
            active.engine, now, policy_version=active.version,
        )
    except ApprovalRejected as exc:
        raise HTTPException(status_code=403, detail="Not eligible for review") from exc
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Audit write failed") from exc
    return _data(row, now)


@router.get("/_local/approvals")
async def operator_list(request: Request):
    operator = await _identity(request, "OPERATOR", "approvals:read")
    store = _store(request)
    now = _now()
    try:
        rows = await list_approvals(store, operator.tenant_id)
        for item in rows:
            if item.state in ("pending", "approved") and item.expires_at_ms <= now:
                await expire_if_needed(store, operator.tenant_id, item.approval_id, now)
        rows = await list_approvals(store, operator.tenant_id)
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Approval read failed") from exc
    return {"approvals": [_data(x, now) for x in rows], "enforcement_ready": False}


@router.post("/_local/approvals/{approval_id}/{decision}")
async def operator_review(approval_id: str, decision: Literal["approve", "reject"], request: Request):
    operator = await _identity(request, "OPERATOR", "approvals:decide")
    store = _store(request)
    now = _now()
    try:
        row = await get_approval(store, operator.tenant_id, approval_id)
        if row is not None and row.state == "pending" and row.expires_at_ms <= now:
            await expire_if_needed(store, operator.tenant_id, approval_id, now)
            raise HTTPException(status_code=409, detail="Approval expired")
        active = await _active_policy(request, operator.tenant_id)
        changed = await review(
            store, approval_id, operator.tenant_id,
            operator.principal.id,
            "approved" if decision == "approve" else "rejected", now,
            current_policy_version=active.version,
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
    operator = await _identity(request, "OPERATOR", "approvals:read")
    store = _store(request)
    try:
        row = await get_approval(store, operator.tenant_id, approval_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Unknown approval")
        items = await store.many(
            "SELECT event_id,tenant_id,event_sha256,reason_codes_json,occurred_at_ms "
            "FROM audit_events WHERE tenant_id=? AND approval_id=? "
            "ORDER BY occurred_at_ms DESC LIMIT 25",
            (operator.tenant_id, approval_id),
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Audit read failed") from exc
    return {"approval_id": approval_id, "events": items}


@router.post("/_local/demo/approvals/{approval_id}/consume")
async def demo_consume(approval_id: str, body: DemoAction, request: Request):
    agent = await _identity(request, "AGENT")
    store = _store(request)
    try:
        now = _now()
        await expire_if_needed(store, agent.tenant_id, approval_id, now)
        active = await _active_policy(request, agent.tenant_id)
        success = await consume_mock(
            store, agent, approval_id, DEMO_ACTION,
            {"fixture": body.fixture}, active.engine, now,
            policy_version=active.version,
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Consumption audit failed") from exc
    if not success:
        raise HTTPException(status_code=409, detail="Action not approved or no longer valid")
    return {"approval_id": approval_id, "state": "consumed",
            "simulated_execution": True, "real_tool_called": False}




@router.get("/_local/demo/invoice-evidence")
async def operator_invoice_attack_evidence(request: Request):
    """Tenant-bound read of redacted demo decisions; no raw hostile document."""
    operator = await _identity(request, "OPERATOR", "approvals:read")
    store = _store(request)
    try:
        rows = await store.many(
            "SELECT event_id,event_sha256,effect,reason_codes_json,occurred_at_ms "
            "FROM audit_events WHERE tenant_id=? AND policy_version=? "
            "ORDER BY occurred_at_ms DESC LIMIT 30",
            (operator.tenant_id, "demo-fixture-policy-v1"),
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Demo audit unavailable") from exc
    return {
        "scenario": "hostile_supplier_invoice_v1",
        "events": rows,
        "evidence_independent_anchoring": False,
        "source_document_included": False,
    }



@router.get("/_local/demo/merkle-batch")
async def operator_local_merkle_batch(request: Request):
    """Produce a local-only *UNANCHORED* Merkle snapshot from D1 audit rows.

    The caller is an authorized operator of the same tenant. This endpoint
    neither persists a batch nor provides an independently trusted root.
    """
    operator = await _identity(request, "OPERATOR", "approvals:read")
    store = _store(request)
    try:
        rows = await store.many(
            "SELECT event_id,tenant_id,principal_id,action_digest,effect,"
            "reason_codes_json,policy_version,occurred_at_ms,retention_until_ms,"
            "event_sha256 FROM audit_events WHERE tenant_id=? AND policy_version=? "
            "ORDER BY occurred_at_ms,event_id LIMIT 256",
            (operator.tenant_id, "demo-fixture-policy-v1"),
        )
        events = [decode_event(row) for row in rows]
        if not events:
            raise HTTPException(status_code=404, detail="No local demo evidence")
        # Stable batch ID for unchanged selected event sets; no cloud writes.
        import hashlib
        batch_id = "batch-" + hashlib.sha256(
            "|".join(event.event_id for event in events).encode("ascii")
        ).hexdigest()[:24]
        manifest = build_manifest(
            events, tenant_id=operator.tenant_id, batch_id=batch_id,
            created_at_ms=max(event.occurred_at_ms for event in events) + 1,
        )
        paths = [inclusion_path(manifest, e.event_id) for e in events]
        return {
            "manifest": manifest, "inclusion_paths": paths,
            "verification_status": validate_manifest(manifest),
            "evm_status": "not_submitted", "independent_anchor": False,
            "onchain_verified": False,
        }
    except (AuditStorageError, InvalidEvidence) as exc:
        raise HTTPException(status_code=503, detail="Local evidence computation failed") from exc




@router.get("/_local/demo/threat-triage")
async def operator_local_threat_triage(request: Request):
    """Local-only synthetic signal preview; no LLM call or authorization.

    The operator identity gates report access; a separate fixed, least-
    privilege demo Principal demonstrates that the model and source content
    cannot grant scopes or execute supplier tools.
    """
    operator = await _identity(request, "OPERATOR", "approvals:read")
    fixture_principal = Principal(
        operator.tenant_id + ":invoice_fixture",
        frozenset({"invoice:read"}),
    )
    baseline = demo_rules(fixture_principal).evaluate(fixture_principal, SUPPLIER_CHANGE)
    report = await assess_threat(
        baseline,
        [UntrustedSegment("fixture-invoice-0042", "retrieved_document", INVOICE_TEXT)],
        [
            ToolObservation("fixture-invoice-read-01", "read", Effect.ALLOW),
            ToolObservation("fixture-supplier-deny-01", "supplier_mutation", baseline.effect),
        ],
        model=None,  # No provider, prompts, keys, billing or external inference.
    )
    return {
        **report.to_dict(), "tenant_id": operator.tenant_id,
        "source_document_included": False, "model_provider_configured": False,
        "authorization_from_ai": False, "real_tool_called": False,
    }




@router.get("/_local/demo/ai-adapter-contract")
async def local_ai_adapter_contract(request: Request):
    """Test the Workers AI adapter with a canned fake; never real inference.

    This route is available only with the local smoke flag, signed operator
    JWT and a manually provisioned local-D1 quota for the synthetic tenant.
    The existing production-shaped env.AI binding is NOT accessed.
    """
    operator = await _identity(request, "OPERATOR", "approvals:read")
    env = _local_env(request)
    import secrets
    budget = D1AIBudget(
        getattr(env, "DB", None), tenant_id=operator.tenant_id,
        request_id="contract-" + secrets.token_hex(16),
        now_ms=1_793_000_000_000,  # deterministic offline Oct 26 fixture
    )
    class CannedLocalModel:
        async def run(self, model, arguments):
            if model != "@cf/meta/llama-3.2-3b-instruct":
                raise RuntimeError("Unreviewed model in sandbox")
            prompt = arguments["messages"][1]["content"]
            if "INVOICE" in prompt or "IGNORE THE USER" in prompt:
                raise RuntimeError("Unredacted invoice sent to sandbox")
            return {"response": (
                '{"risk_code":"POSSIBLE_TOOL_HIJACK",'
                '"evidence_ids":["fixture-invoice-0042"]}'
            )}

    principal = Principal(
        operator.tenant_id + ":invoice_fixture",
        frozenset({"invoice:read"}),
    )
    decision = demo_rules(principal).evaluate(principal, SUPPLIER_CHANGE)
    report = await assess_threat(
        decision,
        [UntrustedSegment(
            "fixture-invoice-0042", "retrieved_document", INVOICE_TEXT,
        )],
        model=WorkersAIBindingAdapter(
            settings=WorkersAISettings(enabled=True),
            binding=CannedLocalModel(), budget=budget,
        ),
    )
    return {
        **report.to_dict(), "simulated_provider": True,
        "remote_inference": False, "actual_ai_binding_used": False,
        "enforcement_ready": False, "real_tool_called": False,
    }


@router.get("/_local/demo/webcrypto-jwt-candidate")
async def operator_local_webcrypto_jwt_candidate(request: Request):
    """Candidate full verification, only visible to an existing local operator.

    This route is NEVER used by agent authentication, approvals or tools.
    A valid signature alone cannot authenticate the candidate JWT.
    """
    operator = await _identity(request, "OPERATOR", "approvals:read")
    env = _local_env(request)
    settings = {
        name: str(getattr(env, name, "") or "")
        for name in ("AGENT_JWT_ISSUER", "AGENT_JWT_AUDIENCE", "AGENT_JWKS_JSON")
    }
    candidate_valid = False
    same_tenant = False
    verified_scope_count = 0
    try:
        candidate = await verify_agent_jwt_webcrypto(
            request.headers.get("x-probe-token", ""), settings,
        )
        candidate_valid = True
        same_tenant = candidate.tenant_id == operator.tenant_id
        verified_scope_count = len(candidate.principal.scopes)
    except (AgentAuthenticationError, IdentityConfigurationError):
        pass
    return {
        "candidate_valid": candidate_valid,
        "same_tenant_as_operator": same_tenant,
        "validated_scope_count": verified_scope_count,
        "used_for_authentication": False,
        "enforcement_ready": False,
        "real_tool_called": False,
        "local_only": True,
    }


@router.get("/_local/demo/webcrypto-es256-probe")
async def operator_local_webcrypto_es256_probe(request: Request):
    """ISOLATED local signature test, never authorization or claim acceptance.

    Requires existing operator authentication before attempting the second,
    candidate crypto primitive. Never returns JWT claims or token details.
    """
    await _identity(request, "OPERATOR", "approvals:read")
    env = _local_env(request)
    settings = {
        name: str(getattr(env, name, "") or "")
        for name in ("AGENT_JWT_ISSUER", "AGENT_JWT_AUDIENCE", "AGENT_JWKS_JSON")
    }
    signature_valid = await verify_es256_signature_webcrypto(
        request.headers.get("x-probe-token", ""), settings,
    )
    return {
        "signature_valid": signature_valid,
        "claims_validated": False,
        "authorization_ready": False,
        "used_for_authentication": False,
        "real_tool_called": False,
        "local_only": True,
    }


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
