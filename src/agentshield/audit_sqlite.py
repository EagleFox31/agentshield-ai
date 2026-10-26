"""Local SQLite adapter for the same audit contract used by Cloudflare D1.

No schema changes at request time. Caller must apply migrations explicitly.
Use one connection per worker/test, never share writable connections between
unrelated threads; database constraints guard retries across connections.
"""
from __future__ import annotations

import sqlite3

from agentshield.audit import (
    AuditConflict, AuditEvent, AuditStorageError, FETCH_EVENT_SQL,
    CONSUME_APPROVAL_SQL, FINGERPRINT_SQL, INSERT_EVENT_SQL, INSERT_NONCE_SQL, decode_event,
    event_arguments, validate_approval, validate_nonce,
)


class SQLiteAuditRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection
        self._db.row_factory = sqlite3.Row

    async def record_event(self, event: AuditEvent) -> bool:
        try:
            with self._db:
                added = self._db.execute(INSERT_EVENT_SQL, event_arguments(event)).fetchone()
                row = self._db.execute(FINGERPRINT_SQL, (event.event_id,)).fetchone()
                if row is None or row["tenant_id"] != event.tenant_id or (
                    row["event_sha256"] != event.fingerprint
                ):
                    raise AuditConflict("Immutable event ID collision")
                return added is not None
        except AuditConflict:
            raise
        except sqlite3.Error as exc:
            raise AuditStorageError("Audit write could not be confirmed") from exc

    async def consume_approved_request(
        self, tenant_id: str, approval_id: str, action_digest: str, now_ms: int,
    ) -> bool:
        validate_approval(tenant_id, approval_id, action_digest, now_ms)
        try:
            with self._db:
                result = self._db.execute(
                    CONSUME_APPROVAL_SQL,
                    (now_ms, approval_id, tenant_id, action_digest, now_ms),
                ).fetchone()
                return result is not None
        except sqlite3.Error as exc:
            raise AuditStorageError("Approval state transition failed") from exc

    async def get_event(self, tenant_id: str, event_id: str) -> AuditEvent | None:
        try:
            row = self._db.execute(FETCH_EVENT_SQL, (event_id, tenant_id)).fetchone()
            return decode_event(dict(row)) if row is not None else None
        except sqlite3.Error as exc:
            raise AuditStorageError("Audit read failed") from exc

    async def consume_nonce(
        self, tenant_id: str, nonce: str, used_at_ms: int, expires_at_ms: int,
    ) -> bool:
        validate_nonce(tenant_id, nonce, used_at_ms, expires_at_ms)
        try:
            with self._db:
                row = self._db.execute(
                    INSERT_NONCE_SQL, (tenant_id, nonce, used_at_ms, expires_at_ms),
                ).fetchone()
                return row is not None
        except sqlite3.Error as exc:
            raise AuditStorageError("Nonce consumption could not be confirmed") from exc
