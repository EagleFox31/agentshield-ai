"""Experimental, local-only FastAPI smoke surface for Cloudflare Python Workers.

No public /v1/decisions endpoint exists here. Identity, approval, audit and
execution remain out of scope until their security gates pass.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from agentshield.identity import (
    AgentAuthenticationError, IdentityConfigurationError, require_bearer,
)
from agentshield.audit import AuditEvent, action_digest
from agentshield.audit_d1 import D1AuditRepository
from agentshield.policy import Effect, PolicyEngine, Principal, Rule, ToolAction

app = FastAPI(
    title="AgentShield AI - experimental gateway",
    version="0.1.0a0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class LocalAction(BaseModel):
    """No caller identity/scopes accepted: fixed test-only fixtures."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tool: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    operation: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    resource: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_-]+/[a-zA-Z0-9_-]+$")


_DEMO_PRINCIPAL = Principal("local-demo-agent", frozenset({"invoice:read"}))
_DEMO_POLICY = PolicyEngine([
    Rule(
        id="local-invoice-read", principal_id="local-demo-agent",
        tool="invoices", operation="read", resource="invoice/42",
        required_scope="invoice:read", effect=Effect.ALLOW,
    ),
])


def _require_local_smoke(request: Request) -> object:
    """Explicit opt-in for development; NOT a production authentication scheme."""
    env = request.scope.get("env")
    if env is None or getattr(env, "LOCAL_SMOKE_ENABLED", None) != "true":
        raise HTTPException(status_code=404, detail="Not found")
    return env


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "alive", "mode": "experimental",
        "enforcement_ready": False, "audit_ready": False,
    }


@app.get("/v1/identity")
async def authenticated_agent_identity(request: Request) -> dict[str, object]:
    """Read-only authentication proof; cannot authorize or execute tools.

    All privileged decisions will require the audit and enforcement work in
    issues #11/#12. Caller-provided JSON never supplies identity/scopes.
    """
    env = request.scope.get("env")
    configuration = {
        name: str(getattr(env, name, "") or "")
        for name in ("AGENT_JWT_ISSUER", "AGENT_JWT_AUDIENCE", "AGENT_JWKS_JSON")
    }
    try:
        result = require_bearer(request.headers.get("authorization"), configuration)
    except IdentityConfigurationError as exc:
        raise HTTPException(status_code=503, detail="Agent verifier unavailable") from exc
    except AgentAuthenticationError as exc:
        raise HTTPException(
            status_code=401, detail="Invalid agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return {
        "agent_id": result.agent_id,
        "tenant_id": result.tenant_id,
        "scopes": sorted(result.principal.scopes),
        "expires_at": result.expires_at,
        "authenticated": True,
        "enforcement_ready": False,
        "executed": False,
    }


@app.post("/_local/policy")
async def local_policy(action: LocalAction, request: Request) -> dict[str, object]:
    _require_local_smoke(request)
    decision = _DEMO_POLICY.evaluate(
        _DEMO_PRINCIPAL, ToolAction(action.tool, action.operation, action.resource)
    )
    return {
        "effect": decision.effect.value,
        "reason_codes": list(decision.reasons),
        "matched_rule_ids": list(decision.matched_rule_ids),
        "enforcement_ready": False,
        "executed": False,
    }


@app.post("/_local/d1-smoke")
async def local_d1_smoke(request: Request) -> dict[str, object]:
    """Fixed SQL only, local-only sentinel, no customer data or user SQL."""
    env = _require_local_smoke(request)
    database = getattr(env, "DB", None)
    if database is None:
        raise HTTPException(status_code=503, detail="Local D1 binding unavailable")
    try:
        await database.prepare(
            "CREATE TABLE IF NOT EXISTS _agentshield_local_smoke "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        ).run()
        await database.prepare(
            "INSERT OR IGNORE INTO _agentshield_local_smoke (key, value) "
            "VALUES ('binding', 'ready')"
        ).run()
        row = await database.prepare(
            "SELECT value FROM _agentshield_local_smoke WHERE key = 'binding'"
        ).first()
        if row is None:
            raise RuntimeError("Missing local smoke sentinel")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Local D1 query failed") from exc
    return {"d1_local_probe": "ok", "persistent_audit_ready": False}


@app.post("/_local/audit-contract")
async def local_audit_contract(request: Request) -> dict[str, object]:
    """Integration probe for local D1 migrations, event dedup and nonce races.

    This route is NOT authenticated and therefore must remain strictly local
    with LOCAL_SMOKE_ENABLED=true. It never executes tools or signs approvals.
    """
    env = _require_local_smoke(request)
    database = getattr(env, "DB", None)
    if database is None:
        raise HTTPException(status_code=503, detail="Local audit D1 unavailable")
    repository = D1AuditRepository(database)
    event = AuditEvent(
        event_id="local-audit-contract-0001",
        tenant_id="ci_local", principal_id="ci_local:demo_agent",
        action_digest=action_digest(
            "suppliers", "update_bank_account", "supplier/482",
        ), effect="deny", reason_codes=("NO_MATCHING_POLICY",),
        policy_version="policy-v1", occurred_at_ms=1_790_000_000_000,
        retention_until_ms=1_790_000_000_000 + 30 * 86_400_000,
    )
    try:
        await repository.record_event(event)
        replay_created = await repository.record_event(event)
        stored = await repository.get_event("ci_local", event.event_id)
        other_tenant = await repository.get_event("other_tenant", event.event_id)
        import secrets
        nonce = "local_" + secrets.token_hex(12)
        first = await repository.consume_nonce(
            "ci_local", nonce, 1_790_000_000_000, 1_790_000_060_000,
        )
        again = await repository.consume_nonce(
            "ci_local", nonce, 1_790_000_000_000, 1_790_000_060_000,
        )
        # This approved state is a synthetic local DB fixture only; no
        # approver identity or public approval API is implemented here.
        approval_id = "local_approval_" + secrets.token_hex(12)
        await database.prepare(
            "INSERT INTO approval_requests "
            "(approval_id,tenant_id,principal_id,action_digest,policy_version,"
            "state,expires_at_ms,created_at_ms) VALUES (?,?,?,?,?,?,?,?)"
        ).bind(
            approval_id, "ci_local", "ci_local:demo_agent", event.action_digest,
            "policy-v1", "approved", 1_790_000_060_000, 1_790_000_000_000,
        ).run()
        wrong = await repository.consume_approved_request(
            "other_tenant", approval_id, event.action_digest, 1_790_000_010_000,
        )
        consumed = await repository.consume_approved_request(
            "ci_local", approval_id, event.action_digest, 1_790_000_010_000,
        )
        consumed_again = await repository.consume_approved_request(
            "ci_local", approval_id, event.action_digest, 1_790_000_010_000,
        )
        if (stored != event or other_tenant is not None or replay_created
            or not first or again or wrong or not consumed or consumed_again):
            raise RuntimeError("Local audit contract mismatch")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Local audit contract failed") from exc
    return {
        "d1_audit_contract": "ok", "redacted_event_hash": event.fingerprint,
        "tenant_isolated": True, "event_idempotent": True,
        "nonce_once": True, "approval_once": True, "enforcement_ready": False,
        "executed": False,
    }
