"""Local, fail-closed human approval state machine backed by SQLite or D1.

A state transition AND its redacted audit event are persisted in one database
transaction (SQLite with connection / D1.batch). No real tool execution here.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Protocol

from agentshield.audit import AuditEvent, AuditStorageError, event_arguments
from agentshield.policy import Effect, PolicyEngine, ToolAction
from agentshield.identity import VerifiedAgent

POLICY_VERSION = "demo-policy-v1"
RETENTION_MS = 30 * 86_400_000
MAX_APPROVAL_MS = 120_000
INSERT_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "VALUES (?,?,?,?,?,?,?,?,?,?)"
)
INSERT_APPROVAL = (
    "INSERT INTO approval_requests "
    "(approval_id,tenant_id,principal_id,action_digest,policy_version,state,"
    "expires_at_ms,created_at_ms) VALUES (?,?,?,?,?,'pending',?,?)"
)
SELECT_APPROVAL = (
    "SELECT approval_id,tenant_id,principal_id,action_digest,policy_version,"
    "state,expires_at_ms,created_at_ms,decision_id,consumed_at_ms "
    "FROM approval_requests WHERE approval_id=? AND tenant_id=?"
)
LIST_APPROVALS = (
    "SELECT approval_id,tenant_id,principal_id,action_digest,policy_version,"
    "state,expires_at_ms,created_at_ms,decision_id,consumed_at_ms "
    "FROM approval_requests WHERE tenant_id=? ORDER BY created_at_ms DESC LIMIT 30"
)


class ApprovalRejected(ValueError):
    """A human grant cannot be created, reviewed or consumed."""


@dataclass(frozen=True)
class Approval:
    approval_id: str
    tenant_id: str
    principal_id: str
    action_digest: str
    policy_version: str
    state: str
    expires_at_ms: int
    created_at_ms: int

    @classmethod
    def from_row(cls, row: dict) -> Approval:
        return cls(**{key: row[key] for key in cls.__dataclass_fields__})


def _to_python(value: object) -> object:
    if hasattr(value, "to_py"):
        return value.to_py()
    return value


class ApprovalStore(Protocol):
    async def first(self, sql: str, params: tuple) -> dict | None: ...
    async def many(self, sql: str, params: tuple) -> list[dict]: ...
    async def atomic(self, statements: list[tuple[str, tuple]]) -> None: ...


class SQLiteApprovalStore:
    def __init__(self, connection: sqlite3.Connection):
        self.db = connection
        self.db.row_factory = sqlite3.Row

    async def first(self, sql: str, params: tuple) -> dict | None:
        try:
            result = self.db.execute(sql, params).fetchone()
            return dict(result) if result is not None else None
        except sqlite3.Error as exc:
            raise AuditStorageError("Approval lookup failed") from exc

    async def many(self, sql: str, params: tuple) -> list[dict]:
        try:
            return [dict(row) for row in self.db.execute(sql, params).fetchall()]
        except sqlite3.Error as exc:
            raise AuditStorageError("Approval lookup failed") from exc

    async def atomic(self, statements: list[tuple[str, tuple]]) -> None:
        try:
            with self.db:
                for sql, params in statements:
                    self.db.execute(sql, params)
        except sqlite3.Error as exc:
            raise AuditStorageError("Approval transaction failed") from exc


class D1ApprovalStore:
    def __init__(self, binding: object):
        if binding is None:
            raise AuditStorageError("D1 approval binding unavailable")
        self.db = binding

    def _prepare(self, sql: str, params: tuple):
        return self.db.prepare(sql).bind(*params)

    async def first(self, sql: str, params: tuple) -> dict | None:
        try:
            row = _to_python(await self._prepare(sql, params).first())
            if row is None:
                return None
            if not isinstance(row, dict):
                raise TypeError("Invalid D1 approval row")
            return row
        except Exception as exc:
            raise AuditStorageError("D1 approval lookup failed") from exc

    async def many(self, sql: str, params: tuple) -> list[dict]:
        try:
            response = _to_python(await self._prepare(sql, params).all())
            if isinstance(response, dict):
                rows = _to_python(response.get("results"))
            else:
                rows = _to_python(getattr(response, "results", None))
            if not isinstance(rows, list):
                raise TypeError("Invalid D1 approval result")
            output = [_to_python(row) for row in rows]
            if not all(isinstance(row, dict) for row in output):
                raise TypeError("Invalid D1 approval row")
            return output
        except Exception as exc:
            raise AuditStorageError("D1 approval list failed") from exc

    async def atomic(self, statements: list[tuple[str, tuple]]) -> None:
        try:
            # Cloudflare D1.batch runs statements in a single transaction.
            # An unsuccessful statement rolls back the full transaction.
            await self.db.batch([self._prepare(sql, args) for sql, args in statements])
        except Exception as exc:
            raise AuditStorageError("D1 approval transaction failed") from exc


def exact_digest(agent: VerifiedAgent, action: ToolAction, args: dict[str, str]) -> str:
    if (not isinstance(args, dict) or len(args) > 8
        or any(not isinstance(k, str) or not isinstance(v, str)
               or len(k) > 32 or len(v) > 128 for k, v in args.items())):
        raise ApprovalRejected("Invalid action arguments")
    canonical = json.dumps(
        {"schema": "agentshield.exact-action.v1", "tenant": agent.tenant_id,
         "actor": agent.principal.id, "scopes": sorted(agent.principal.scopes),
         "policy_version": POLICY_VERSION, "tool": action.tool,
         "operation": action.operation, "resource": action.resource,
         "arguments": args},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    if len(canonical.encode()) > 2048:
        raise ApprovalRejected("Action too large")
    return hashlib.sha256(canonical.encode()).hexdigest()


def _event(tenant: str, actor: str, digest: str, reason: str, now_ms: int) -> AuditEvent:
    return AuditEvent(
        event_id="audit-" + secrets.token_hex(16), tenant_id=tenant,
        principal_id=actor, action_digest=digest, effect="require_approval",
        reason_codes=(reason,), policy_version=POLICY_VERSION,
        occurred_at_ms=now_ms, retention_until_ms=now_ms + RETENTION_MS,
    )


def _id(prefix: str) -> str:
    return prefix + "-" + secrets.token_hex(16)


def _audit_if_transition(
    approval_id: str, unique_column: str, marker: str,
    state: str, event: AuditEvent,
) -> tuple[str, tuple]:
    # No audit entry is created when no approval transition succeeded.
    # Column is an internal fixed constant, never obtained from request input.
    if unique_column not in {"decision_id", "consume_event_id"}:
        raise ValueError("Unrecognized transition marker")
    cols = (
        "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
        "policy_version,occurred_at_ms,retention_until_ms,event_sha256)"
    )
    sql = (
        f"INSERT INTO audit_events {cols} SELECT ?,?,?,?,?,?,?,?,?,? "
        f"WHERE EXISTS (SELECT 1 FROM approval_requests "
        f"WHERE approval_id=? AND {unique_column}=? AND state=?)"
    )
    return sql, event_arguments(event) + (approval_id, marker, state)


async def create_pending(
    store: ApprovalStore, agent: VerifiedAgent,
    action: ToolAction, arguments: dict[str, str], engine: PolicyEngine, now_ms: int,
) -> Approval:
    decision = engine.evaluate(agent.principal, action)
    if decision.effect != Effect.REQUIRE_APPROVAL:
        raise ApprovalRejected("Action not eligible for human review")
    digest = exact_digest(agent, action, arguments)
    approval_id = _id("approval")
    expires = now_ms + MAX_APPROVAL_MS
    audit = _event(agent.tenant_id, agent.principal.id, digest, "HUMAN_APPROVAL_REQUIRED", now_ms)
    await store.atomic([
        (INSERT_APPROVAL, (approval_id, agent.tenant_id, agent.principal.id,
                           digest, POLICY_VERSION, expires, now_ms)),
        (INSERT_AUDIT, event_arguments(audit)),
    ])
    return Approval(approval_id, agent.tenant_id, agent.principal.id,
                    digest, POLICY_VERSION, "pending", expires, now_ms)


async def get_approval(store: ApprovalStore, tenant: str, approval_id: str) -> Approval | None:
    row = await store.first(SELECT_APPROVAL, (approval_id, tenant))
    return Approval.from_row(row) if row else None


async def list_approvals(store: ApprovalStore, tenant: str) -> list[Approval]:
    return [Approval.from_row(row) for row in await store.many(LIST_APPROVALS, (tenant,))]


async def review(
    store: ApprovalStore, approval_id: str, tenant: str, operator_id: str,
    decision: str, now_ms: int,
) -> bool:
    if decision not in ("approved", "rejected"):
        raise ApprovalRejected("Unrecognized human decision")
    existing = await get_approval(store, tenant, approval_id)
    if existing is None or existing.state != "pending" or existing.expires_at_ms <= now_ms:
        return False
    if operator_id == existing.principal_id:
        raise ApprovalRejected("Agent cannot approve itself")
    transition_id = _id("decision")
    event = _event(tenant, operator_id, existing.action_digest,
                   "HUMAN_APPROVAL_GRANTED" if decision == "approved" else "HUMAN_APPROVAL_REJECTED",
                   now_ms)
    await store.atomic([
        ("UPDATE approval_requests SET state=?,decision_id=? "
         "WHERE approval_id=? AND tenant_id=? AND state='pending' AND expires_at_ms>?",
         (decision, transition_id, approval_id, tenant, now_ms)),
        ("INSERT INTO approval_decisions "
         "(decision_id,approval_id,tenant_id,approver_id,decision,decided_at_ms) "
         "SELECT ?,approval_id,tenant_id,?,?,? FROM approval_requests "
         "WHERE approval_id=? AND tenant_id=? AND decision_id=? AND state=?",
         (transition_id, operator_id, decision, now_ms,
          approval_id, tenant, transition_id, decision)),
        _audit_if_transition(approval_id, "decision_id", transition_id, decision, event),
    ])
    final = await store.first(
        "SELECT decision_id,state FROM approval_requests WHERE approval_id=? AND tenant_id=?",
        (approval_id, tenant),
    )
    return bool(final and final["decision_id"] == transition_id and final["state"] == decision)


async def expire_if_needed(
    store: ApprovalStore, tenant: str, approval_id: str, now_ms: int,
) -> bool:
    previous = await get_approval(store, tenant, approval_id)
    if previous is None or previous.state not in ("pending", "approved") or previous.expires_at_ms > now_ms:
        return False
    marker = _id("expire")
    event = _event(tenant, tenant + ":system", previous.action_digest,
                   "HUMAN_APPROVAL_EXPIRED", now_ms)
    # decision_id identifies an expiry transition. Only unreviewed pending
    # approvals can expire here; approved expiry is enforced by consume().
    if previous.state != "pending":
        return False
    await store.atomic([
        ("UPDATE approval_requests SET state='expired',decision_id=? "
         "WHERE approval_id=? AND tenant_id=? AND state='pending' AND expires_at_ms<=?",
         (marker, approval_id, tenant, now_ms)),
        _audit_if_transition(approval_id, "decision_id", marker, "expired", event),
    ])
    return True


async def consume_mock(
    store: ApprovalStore, agent: VerifiedAgent, approval_id: str,
    action: ToolAction, arguments: dict[str, str],
    engine: PolicyEngine, now_ms: int,
) -> bool:
    existing = await get_approval(store, agent.tenant_id, approval_id)
    if (existing is None or existing.state != "approved"
        or existing.principal_id != agent.principal.id
        or existing.policy_version != POLICY_VERSION
        or existing.expires_at_ms <= now_ms
        or existing.action_digest != exact_digest(agent, action, arguments)
        or engine.evaluate(agent.principal, action).effect != Effect.REQUIRE_APPROVAL):
        return False
    marker = _id("consumption")
    event = _event(agent.tenant_id, agent.principal.id, existing.action_digest,
                   "HUMAN_APPROVAL_CONSUMED", now_ms)
    await store.atomic([
        ("UPDATE approval_requests SET state='consumed',consumed_at_ms=?,consume_event_id=? "
         "WHERE approval_id=? AND tenant_id=? AND principal_id=? "
         "AND action_digest=? AND policy_version=? AND state='approved' AND expires_at_ms>?",
         (now_ms, marker, approval_id, agent.tenant_id, agent.principal.id,
          existing.action_digest, POLICY_VERSION, now_ms)),
        _audit_if_transition(approval_id, "consume_event_id", marker, "consumed", event),
    ])
    final = await store.first(
        "SELECT consume_event_id,state FROM approval_requests WHERE approval_id=? AND tenant_id=?",
        (approval_id, agent.tenant_id),
    )
    return bool(final and final["consume_event_id"] == marker and final["state"] == "consumed")
