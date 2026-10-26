"""Cloudflare D1 Python Worker binding adapter for the audit port.

All statement values are parameter-bound. No migration or infrastructure
creation happens during HTTP requests. The binding is provided by the Worker.
"""
from __future__ import annotations

from agentshield.audit import (
    AuditConflict, AuditEvent, AuditStorageError, FETCH_EVENT_SQL,
    CONSUME_APPROVAL_SQL, FINGERPRINT_SQL, INSERT_EVENT_SQL, INSERT_NONCE_SQL, decode_event,
    event_arguments, validate_approval, validate_nonce,
)


def _as_row(value: object) -> dict | None:
    if value is None:
        return None
    # Cloudflare's Python Workers D1 API exposes a JavaScript object as JsProxy.
    try:
        if hasattr(value, "to_py"):
            value = value.to_py()
        if isinstance(value, dict):
            return value
        raise TypeError("Invalid D1 row representation")
    except Exception as exc:
        raise AuditStorageError("Invalid D1 response") from exc


class D1AuditRepository:
    def __init__(self, binding: object) -> None:
        if binding is None:
            raise AuditStorageError("D1 audit binding is missing")
        self._db = binding

    async def _first(self, query: str, values: tuple) -> dict | None:
        try:
            # first() works for SELECT and SQLite's INSERT ... RETURNING.
            row = await self._db.prepare(query).bind(*values).first()
            return _as_row(row)
        except AuditStorageError:
            raise
        except Exception as exc:
            raise AuditStorageError("D1 audit operation failed") from exc

    async def record_event(self, event: AuditEvent) -> bool:
        inserted = await self._first(INSERT_EVENT_SQL, event_arguments(event))
        existing = await self._first(FINGERPRINT_SQL, (event.event_id,))
        if (
            existing is None or existing.get("tenant_id") != event.tenant_id
            or existing.get("event_sha256") != event.fingerprint
        ):
            raise AuditConflict("Immutable event ID collision")
        return inserted is not None

    async def consume_approved_request(
        self, tenant_id: str, approval_id: str, action_digest: str, now_ms: int,
    ) -> bool:
        validate_approval(tenant_id, approval_id, action_digest, now_ms)
        row = await self._first(
            CONSUME_APPROVAL_SQL,
            (now_ms, approval_id, tenant_id, action_digest, now_ms),
        )
        return row is not None

    async def get_event(self, tenant_id: str, event_id: str) -> AuditEvent | None:
        row = await self._first(FETCH_EVENT_SQL, (event_id, tenant_id))
        return decode_event(row) if row is not None else None

    async def consume_nonce(
        self, tenant_id: str, nonce: str, used_at_ms: int, expires_at_ms: int,
    ) -> bool:
        validate_nonce(tenant_id, nonce, used_at_ms, expires_at_ms)
        row = await self._first(
            INSERT_NONCE_SQL, (tenant_id, nonce, used_at_ms, expires_at_ms),
        )
        return row is not None
