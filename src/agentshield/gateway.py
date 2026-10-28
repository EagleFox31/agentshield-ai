"""Experimental, local-only FastAPI smoke surface for Cloudflare Python Workers.

No public /v1/decisions endpoint exists here. Identity, approval, audit and
execution remain out of scope until their security gates pass.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

from agentshield.identity import (
    AgentAuthenticationError, IdentityConfigurationError,
)
from agentshield.approval_api import router as approval_router, _identity as _verified_local_identity
from agentshield.webcrypto_jwt_candidate import require_bearer_webcrypto
from agentshield.audit import AuditStorageError
from agentshield.demo_invoice import run_invoice_attack, _rules as demo_rules
from agentshield.audit_service import decide_and_audit
from agentshield.idempotent_decisions import decide_idempotently, DecisionReplayConflict, DecisionRateLimited
from agentshield.mock_dispatch_boundary import dispatch_claimed_invoice_mock, MockDispatchRejected
from agentshield.egress_policy import (
    EgressRejected, _LOCAL_INVOICE_CAPABILITY, inspect_egress,
)
from agentshield.bound_transport_contract import (
    SyntheticTransportObservation, inspect_synthetic_transport,
)
from dataclasses import replace
from agentshield.demo_invoice import INVOICE
from agentshield.local_command_outbox import (
    queue_local_invoice, claim_local_command, mark_local_uncertain, CommandConflict,
)
from agentshield.policy_registry import D1PolicyRegistry, PolicyUnavailable
from agentshield.approvals import D1ApprovalStore
from agentshield.local_tool_gate import execute_local_mock, LocalDryRunAdapter, MockGateRejected
import secrets
import time
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


# All approval endpoints require explicit local mode; do not deploy these routes.
app.include_router(approval_router)

@app.middleware("http")
async def deny_disabled_local_paths(request: Request, call_next):
    """Before request-body validation, suppress local-only route visibility."""
    if request.url.path.startswith("/_local/"):
        env = request.scope.get("env")
        if env is None or getattr(env, "LOCAL_SMOKE_ENABLED", None) != "true":
            return Response(status_code=404, headers={"Cache-Control": "no-store"})
    return await call_next(request)



class LocalAction(BaseModel):
    """No caller identity/scopes accepted: fixed test-only fixtures."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    tool: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    operation: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_-]*$")
    resource: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_-]+/[a-zA-Z0-9_-]+$")


class LocalIdempotentDecision(LocalAction):
    """Caller-supplied opaque retry key is data, never an execution permit."""

    request_id: str = Field(
        min_length=16, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{15,95}$"
    )


class LocalTestExecution(LocalAction):
    """Strict synthetic action only. Never accept arbitrary provider args."""

    fixture: Literal["scenario-A", "scenario-B"] = "scenario-A"
    nonce: str = Field(
        min_length=8, max_length=96, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{7,95}$"
    )
    approval_id: str | None = Field(
        default=None, min_length=16, max_length=96,
        pattern=r"^approval-[0-9a-f]{32}$",
    )


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
        result = await require_bearer_webcrypto(request.headers.get("authorization"), configuration)
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


@app.get("/_local/platform-provenance")
async def local_platform_provenance(request: Request) -> dict[str, object]:
    """Read-only LOCAL CI evidence; authenticated operator, no environment dump.

    Pyodide selection is Cloudflare-controlled by compatibility date. We
    report observed versions, not claim that the host uv.lock freezes them.
    """
    _require_local_smoke(request)
    await _verified_local_identity(request, "OPERATOR", "approvals:read")
    import sys
    from importlib import metadata

    versions = {}
    try:
        for name in ("fastapi", "starlette", "pydantic", "pydantic_core"):
            versions[name] = metadata.version(name)
    except metadata.PackageNotFoundError as exc:
        raise HTTPException(status_code=503, detail="Runtime metadata incomplete") from exc

    pyodide_version = None
    try:
        import pyodide
        pyodide_version = getattr(pyodide, "__version__", None)
    except ImportError:
        pass
    if not isinstance(pyodide_version, str) or not pyodide_version:
        try:
            pyodide_version = metadata.version("pyodide")
        except metadata.PackageNotFoundError:
            pyodide_version = None

    return {
        "python_version": sys.version.split(" ", 1)[0],
        "pyodide_version": pyodide_version,
        "packages": versions,
        "local_only": True,
        "enforcement_ready": False,
        "real_tool_called": False,
    }


@app.post("/_local/test-executions")
async def local_test_execution(body: LocalTestExecution, request: Request) -> dict[str, object]:
    """Never execute an external tool; route only the audited mock adapter.

    Both the JWT and local D1 are mandatory. Client JSON cannot grant scopes
    or change policy; an approval is bound to the exact fixture and caller.
    """
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        database = getattr(env, "DB", None)
        repo = D1AuditRepository(database)
        approvals = D1ApprovalStore(database)
        return await execute_local_mock(
            repo, approvals, D1PolicyRegistry(database), agent,
            ToolAction(body.tool, body.operation, body.resource),
            fixture=body.fixture, nonce=body.nonce,
            approval_id=body.approval_id,
            now_ms=int(time.time() * 1000),
            adapter=LocalDryRunAdapter(),
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Security storage unavailable") from exc
    except MockGateRejected as exc:
        raise HTTPException(status_code=409, detail="Local mock execution denied") from exc


class LocalCommandQueueRequest(BaseModel):
    """Only an opaque signed-agent request ID; action fixed in the service."""

    model_config = ConfigDict(extra="forbid")
    request_id: str = Field(
        min_length=16, max_length=96,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{15,95}$",
    )


class LocalEgressFixture(BaseModel):
    """Fixed injection scenarios; no client-provided URL, IP, DNS or policy."""

    model_config = ConfigDict(extra="forbid")
    scenario: Literal["public", "loopback", "mixed", "redirect", "rebind"]


@app.post("/_local/egress-inspection")
async def local_egress_inspection(
    body: LocalEgressFixture, request: Request,
) -> dict[str, object]:
    """Signed-tenant offline SSRF inspection; NEVER opens network I/O.

    All candidate destinations and fake DNS outcomes are code-owned. This
    preview does not represent an address-pinned TLS provider adapter.
    """
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        current = await D1PolicyRegistry(getattr(env, "DB", None)).load_active(
            agent.tenant_id
        )
        fake_addresses = {
            "public": ("8.8.8.8", "2001:4860:4860::8888"),
            "loopback": ("127.0.0.1",),
            "mixed": ("8.8.8.8", "169.254.169.254"),
            "redirect": ("8.8.8.8",),
            "rebind": ("8.8.8.8",),
        }
        inspection = inspect_egress(
            agent.principal, INVOICE, current.engine,
            candidate_url=_LOCAL_INVOICE_CAPABILITY.url,
            resolved_addresses=fake_addresses[body.scenario],
            redirect_url=(
                "http://169.254.169.254/latest/meta-data/"
                if body.scenario == "redirect" else None
            ),
            next_addresses=(
                ("127.0.0.1",) if body.scenario == "rebind" else None
            ),
        )
    except EgressRejected as exc:
        raise HTTPException(status_code=409, detail="Unsafe egress inspection") from exc
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Policy evidence unavailable") from exc
    return {
        "inspection": "passed_offline_only",
        "capability_id": inspection.capability_id,
        "action_digest": inspection.action_digest,
        "address_count": inspection.address_count,
        "network_enabled": False,
        "transport_pinned": False,
        "execution_authorized": False,
        "real_tool_called": False,
        "enforcement_ready": False,
        "local_only": True,
    }


class LocalBoundTransportFixture(BaseModel):
    """Only code-owned synthetic connection events; never customer endpoints."""

    model_config = ConfigDict(extra="forbid")
    scenario: Literal[
        "matched", "peer-swap", "metadata-peer", "tls-sni", "bad-cert",
        "redirect", "proxy", "oversized", "timeout", "method-override",
    ]


@app.post("/_local/transport-binding-inspection")
async def local_transport_binding_inspection(
    body: LocalBoundTransportFixture, request: Request,
) -> dict[str, object]:
    """Inspect fake peer+TLS evidence. NO DNS, HTTP, sockets or live provider."""
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        active = await D1PolicyRegistry(getattr(env, "DB", None)).load_active(
            agent.tenant_id
        )
        original = SyntheticTransportObservation(
            selected_ip="8.8.8.8", connected_peer_ip="8.8.8.8",
            target_host=_LOCAL_INVOICE_CAPABILITY.host,
            tls_sni=_LOCAL_INVOICE_CAPABILITY.host,
            certificate_host=_LOCAL_INVOICE_CAPABILITY.host,
            certificate_chain_verified=True,
            certificate_hostname_verified=True,
            tls_version="TLSv1.3",
            method="GET", observed_url=_LOCAL_INVOICE_CAPABILITY.url,
            proxy_used=False, redirects_followed=0, http_status=200,
            response_body_bytes=128, elapsed_ms=100,
        )
        tampering = {
            "matched": {},
            "peer-swap": {"connected_peer_ip": "1.1.1.1"},
            "metadata-peer": {"connected_peer_ip": "169.254.169.254"},
            "tls-sni": {"tls_sni": "api.attacker.example"},
            "bad-cert": {"certificate_chain_verified": False},
            "redirect": {"redirects_followed": 1, "http_status": 302},
            "proxy": {"proxy_used": True},
            "oversized": {"response_body_bytes": 16_385},
            "timeout": {"elapsed_ms": 2_001},
            "method-override": {"method": "POST"},
        }
        inspected = inspect_synthetic_transport(
            agent.principal, INVOICE, active.engine,
            candidate_url=_LOCAL_INVOICE_CAPABILITY.url,
            dns_answers=("8.8.8.8", "1.1.1.1"),
            observation=replace(original, **tampering[body.scenario]),
        )
    except EgressRejected as exc:
        raise HTTPException(
            status_code=409, detail="Synthetic transport contract rejected"
        ) from exc
    except AuditStorageError as exc:
        raise HTTPException(
            status_code=503, detail="Policy evidence unavailable"
        ) from exc
    return {
        "inspection": "synthetic_transport_contract_only",
        "capability_id": inspected.capability_id,
        "body_limit_bytes": inspected.body_limit_bytes,
        "elapsed_limit_ms": inspected.elapsed_limit_ms,
        "simulation_only": True,
        "network_enabled": False,
        "transport_attested": False,
        "execution_authorized": False,
        "real_tool_called": False,
        "enforcement_ready": False,
        "local_only": True,
    }


@app.post("/_local/commands/{command_id}/dry-run")
async def local_fenced_mock_dispatch(
    command_id: str, request: Request,
) -> dict[str, object]:
    """Original signed agent + independent claimed outbox => one local stub.

    No arbitrary request arguments, URL, provider SDK or external execution.
    """
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        db = getattr(env, "DB", None)
        receipt = await dispatch_claimed_invoice_mock(
            D1ApprovalStore(db), D1AuditRepository(db), D1PolicyRegistry(db),
            agent, command_id=command_id,
            now_ms=int(time.time() * 1000), adapter=LocalDryRunAdapter(),
        )
    except MockDispatchRejected as exc:
        raise HTTPException(status_code=409, detail="Mock dispatch rejected") from exc
    except (AuditStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Mock dispatch evidence unavailable") from exc
    return {
        "command_id": receipt.command_id,
        "dispatch_id": receipt.dispatch_id,
        "audit_event_id": receipt.audit_event_id,
        "policy_version": receipt.policy_version,
        "mock_invoked": True, "mock_result": receipt.stub_name,
        "audit_recorded": True, "real_tool_called": False,
        "executed": False, "enforcement_ready": False, "local_only": True,
    }


@app.post("/_local/commands/queue")
async def local_queue_command(
    body: LocalCommandQueueRequest, request: Request,
) -> dict[str, object]:
    """Queue a single audited fake invoice-read; never execute an adapter."""
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        db = getattr(env, "DB", None)
        receipt = await queue_local_invoice(
            D1ApprovalStore(db), D1AuditRepository(db), D1PolicyRegistry(db),
            agent, request_id=body.request_id, now_ms=int(time.time() * 1000),
        )
    except CommandConflict as exc:
        raise HTTPException(status_code=409, detail="Command conflict") from exc
    except DecisionReplayConflict as exc:
        raise HTTPException(status_code=409, detail="Decision request conflict") from exc
    except DecisionRateLimited as exc:
        raise HTTPException(
            status_code=429, detail="Tenant decision rate limit exceeded",
            headers={"Retry-After": "60"},
        ) from exc
    except (AuditStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Command evidence unavailable") from exc
    return {
        "command_id": receipt.command_id, "request_id": receipt.request_id,
        "decision_event_id": receipt.decision_event_id,
        "queue_audit_event_id": receipt.queue_audit_event_id,
        "policy_version": receipt.policy_version,
        "state": receipt.state, "replayed": receipt.replayed,
        "audit_recorded": True, "real_tool_called": False,
        "executed": False, "enforcement_ready": False, "local_only": True,
    }


@app.post("/_local/commands/{command_id}/claim")
async def local_claim_command(command_id: str, request: Request) -> dict[str, object]:
    """One-use signed operator claim; no actual dispatcher is connected."""
    env = _require_local_smoke(request)
    operator = await _verified_local_identity(
        request, "OPERATOR", "commands:claim",
    )
    try:
        db = getattr(env, "DB", None)
        return await claim_local_command(
            D1ApprovalStore(db), D1AuditRepository(db), D1PolicyRegistry(db),
            operator, command_id=command_id, now_ms=int(time.time() * 1000),
        )
    except CommandConflict as exc:
        raise HTTPException(status_code=409, detail="Command unavailable") from exc
    except (AuditStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Command claim unavailable") from exc


@app.post("/_local/commands/{command_id}/mark-uncertain")
async def local_uncertain_command(command_id: str, request: Request) -> dict[str, object]:
    """Simulated interrupted claim. Never requeue or dispatch a tool."""
    env = _require_local_smoke(request)
    operator = await _verified_local_identity(
        request, "OPERATOR", "commands:reconcile",
    )
    try:
        db = getattr(env, "DB", None)
        return await mark_local_uncertain(
            D1ApprovalStore(db), D1AuditRepository(db), operator,
            command_id=command_id, now_ms=int(time.time() * 1000),
        )
    except CommandConflict as exc:
        raise HTTPException(status_code=409, detail="Command unavailable") from exc
    except (AuditStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Command recovery unavailable") from exc


@app.post("/_local/idempotent-decisions")
async def local_idempotent_decision(
    action: LocalIdempotentDecision, request: Request,
) -> dict[str, object]:
    """Authenticated, tenant-bound D1 request receipt + audit, no dispatch."""
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        db = getattr(env, "DB", None)
        proposed = ToolAction(action.tool, action.operation, action.resource)
        receipt = await decide_idempotently(
            D1ApprovalStore(db), D1AuditRepository(db), D1PolicyRegistry(db),
            agent, proposed, request_id=action.request_id,
            now_ms=int(time.time() * 1000),
        )
    except DecisionReplayConflict as exc:
        raise HTTPException(status_code=409, detail="Decision request conflict") from exc
    except DecisionRateLimited as exc:
        raise HTTPException(
            status_code=429,
            detail="Tenant decision rate limit exceeded",
            headers={"Retry-After": "60"},
        ) from exc
    except (AuditStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Decision evidence unavailable") from exc
    return {
        "request_id": receipt.request_id,
        "event_id": receipt.event_id,
        "effect": receipt.effect,
        "reason_codes": list(receipt.reason_codes),
        "matched_rule_ids": list(receipt.matched_rule_ids),
        "policy_version": receipt.policy_version,
        "policy_sha256": receipt.policy_sha256,
        "action_digest": receipt.action_sha256,
        "replayed": receipt.replayed,
        "audit_recorded": True,
        "authenticated": True,
        "execution_authorized": False,
        "executed": False,
        "enforcement_ready": False,
        "local_only": True,
    }


@app.post("/_local/registry-decisions")
async def local_registry_decision(action: LocalAction, request: Request) -> dict[str, object]:
    """Use only the active immutable D1 policy for the JWT-authenticated tenant.

    No caller-controlled policy version, grants, arguments or tool execution.
    Missing/corrupt policy or failed audit yields HTTP 503 (fail closed).
    """
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        db = getattr(env, "DB", None)
        active = await D1PolicyRegistry(db).load_active(agent.tenant_id)
        proposed = ToolAction(action.tool, action.operation, action.resource)
        audit = D1AuditRepository(db)
        event_id = "registry-decision-" + secrets.token_hex(16)
        decision = await decide_and_audit(
            active.engine, audit, agent.principal, agent.tenant_id,
            proposed, event_id=event_id,
            policy_version=active.version,
            occurred_at_ms=int(time.time() * 1000), retention_days=30,
        )
    except (PolicyUnavailable, AuditStorageError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Policy or audit unavailable") from exc
    return {
        "effect": decision.effect.value,
        "reason_codes": list(decision.reasons),
        "matched_rule_ids": list(decision.matched_rule_ids),
        "event_id": event_id,
        "policy_version": active.version,
        "policy_sha256": active.sha256,
        "action_digest": action_digest(proposed.tool, proposed.operation, proposed.resource),
        "authenticated": True,
        "audit_recorded": True,
        "execution_authorized": False,
        "executed": False,
        "enforcement_ready": False,
        "local_only": True,
    }


@app.post("/_local/decisions")
async def local_signed_decision(action: LocalAction, request: Request) -> dict[str, object]:
    """Local decision + durable D1 evidence; NEVER an execution capability.

    The caller signs identity and scopes via trusted ES256 JWT. Only exact
    synthetic fixture rules exist. Tool arguments, policy and privileges
    cannot be supplied by the request body. No actual tool adapter is wired.
    """
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        repository = D1AuditRepository(getattr(env, "DB", None))
        proposed = ToolAction(action.tool, action.operation, action.resource)
        event_id = "local-decision-" + secrets.token_hex(16)
        now_ms = int(time.time() * 1000)
        decision = await decide_and_audit(
            demo_rules(agent.principal), repository, agent.principal,
            agent.tenant_id, proposed,
            event_id=event_id, policy_version="demo-fixture-policy-v1",
            occurred_at_ms=now_ms, retention_days=30,
        )
    except (AuditStorageError, ValueError) as exc:
        # Never disclose internal DB state or emit ALLOW without stored evidence.
        raise HTTPException(status_code=503, detail="Decision audit unavailable") from exc
    return {
        "effect": decision.effect.value,
        "reason_codes": list(decision.reasons),
        "matched_rule_ids": list(decision.matched_rule_ids),
        "event_id": event_id,
        "action_digest": action_digest(proposed.tool, proposed.operation, proposed.resource),
        "policy_version": "demo-fixture-policy-v1",
        "authenticated": True,
        "audit_recorded": True,
        "execution_authorized": False,
        "executed": False,
        "enforcement_ready": False,
        "local_only": True,
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


@app.post("/_local/demo/invoice-injection")
async def invoice_attack_demo(request: Request) -> dict[str, object]:
    """Local-only, signed agent + durable D1 proof of zero supplier writes.

    Requests provide NO principal, tool, scopes, or invoice text; only the
    server-side synthetic fixture is evaluated by the existing PolicyEngine.
    """
    env = _require_local_smoke(request)
    agent = await _verified_local_identity(request, "AGENT")
    try:
        repository = D1AuditRepository(getattr(env, "DB", None))
        report = await run_invoice_attack(
            repository, agent.principal, agent.tenant_id,
            occurred_at_ms=int(time.time() * 1000),
        )
    except AuditStorageError as exc:
        raise HTTPException(status_code=503, detail="Security audit unavailable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Demo requires a read-only invoice agent") from exc
    return {**report.to_dict(), "jwt_verified_by_gateway": True,
            "enforcement_ready": False, "hosted": False}
