"""Pure, privacy-minimized audit contract shared by SQLite and Cloudflare D1.

This module is independent from FastAPI, Cloudflare, JWT libraries, and EVM.
Only explicit known metadata enters records; no prompts, arguments, tokens or PII.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_REASON = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED = frozenset({"allow", "deny", "require_approval"})
_DAY_MS = 86_400_000
_MAX_RETENTION_MS = 90 * _DAY_MS


class AuditStorageError(RuntimeError):
    """An audit storage operation was not durably confirmed; deny execution."""


class AuditConflict(AuditStorageError):
    """An event ID was already used for a different immutable event."""


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    tenant_id: str
    principal_id: str
    action_digest: str
    effect: str
    reason_codes: tuple[str, ...]
    policy_version: str
    occurred_at_ms: int
    retention_until_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not _ID.fullmatch(self.event_id):
            raise ValueError("Invalid event ID")
        if not isinstance(self.tenant_id, str) or not _TENANT.fullmatch(self.tenant_id):
            raise ValueError("Invalid tenant")
        if not isinstance(self.principal_id, str) or not _ID.fullmatch(self.principal_id):
            raise ValueError("Invalid principal ID")
        if not isinstance(self.policy_version, str) or not _ID.fullmatch(self.policy_version):
            raise ValueError("Invalid policy version")
        if not isinstance(self.action_digest, str) or not _SHA256.fullmatch(self.action_digest):
            raise ValueError("Only canonical SHA-256 action digests are stored")
        if self.effect not in _ALLOWED:
            raise ValueError("Unknown policy decision")
        if not isinstance(self.reason_codes, tuple) or not (
            1 <= len(self.reason_codes) <= 12
        ) or any(
            not isinstance(x, str) or not _REASON.fullmatch(x) for x in self.reason_codes
        ):
            raise ValueError("Invalid reason codes")
        if type(self.occurred_at_ms) is not int or type(self.retention_until_ms) is not int:
            raise ValueError("Audit timestamps must be integers")
        delta = self.retention_until_ms - self.occurred_at_ms
        if self.occurred_at_ms <= 0 or not (_DAY_MS <= delta <= _MAX_RETENTION_MS):
            raise ValueError("Retention must be 1–90 days")

    def canonical_payload(self) -> str:
        """Versioned, stable encoding used by an independent future verifier."""
        return json.dumps(
            {
                "schema": "agentshield.audit.v1",
                "event_id": self.event_id,
                "tenant_id": self.tenant_id,
                "principal_id": self.principal_id,
                "action_digest": self.action_digest,
                "effect": self.effect,
                "reason_codes": list(self.reason_codes),
                "policy_version": self.policy_version,
                "occurred_at_ms": self.occurred_at_ms,
                "retention_until_ms": self.retention_until_ms,
            },
            separators=(",", ":"), sort_keys=True, ensure_ascii=True,
        )

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_payload().encode("utf-8")).hexdigest()


class AuditRepository(Protocol):
    async def record_event(self, event: AuditEvent) -> bool:
        """Return True on first insert, False on exact retry; conflict fails closed."""
        ...

    async def get_event(self, tenant_id: str, event_id: str) -> AuditEvent | None:
        """Tenant-scoped read, never return another tenant's event."""
        ...

    async def consume_nonce(
        self, tenant_id: str, nonce: str, used_at_ms: int, expires_at_ms: int,
    ) -> bool:
        """Single-statement insert, True only for the first durable write."""
        ...


def validate_nonce(tenant_id: str, nonce: str, used_at_ms: int, expires_at_ms: int) -> None:
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise ValueError("Invalid tenant")
    if not isinstance(nonce, str) or not _ID.fullmatch(nonce):
        raise ValueError("Invalid opaque nonce")
    if type(used_at_ms) is not int or type(expires_at_ms) is not int:
        raise ValueError("Nonce timestamps must be integers")
    if used_at_ms <= 0 or not 0 < expires_at_ms - used_at_ms <= 300_000:
        raise ValueError("Nonce expiry must be within 5 minutes")


def decode_event(row: dict) -> AuditEvent:
    """Reconstitute immutable event and validate its stored fingerprint."""
    try:
        event = AuditEvent(
            event_id=row["event_id"], tenant_id=row["tenant_id"],
            principal_id=row["principal_id"], action_digest=row["action_digest"],
            effect=row["effect"], reason_codes=tuple(json.loads(row["reason_codes_json"])),
            policy_version=row["policy_version"], occurred_at_ms=row["occurred_at_ms"],
            retention_until_ms=row["retention_until_ms"],
        )
        if event.fingerprint != row["event_sha256"]:
            raise AuditStorageError("Stored audit integrity mismatch")
        return event
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditStorageError("Invalid stored audit event") from exc


INSERT_EVENT_SQL = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "VALUES (?,?,?,?,?,?,?,?,?,?) "
    "ON CONFLICT(event_id) DO NOTHING RETURNING event_id"
)
FETCH_EVENT_SQL = (
    "SELECT event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256 "
    "FROM audit_events WHERE event_id=? AND tenant_id=?"
)
FINGERPRINT_SQL = "SELECT event_sha256,tenant_id FROM audit_events WHERE event_id=?"
INSERT_NONCE_SQL = (
    "INSERT INTO used_action_nonces (tenant_id,nonce,used_at_ms,expires_at_ms) "
    "VALUES (?,?,?,?) ON CONFLICT(tenant_id,nonce) DO NOTHING RETURNING nonce"
)


def event_arguments(event: AuditEvent) -> tuple:
    return (
        event.event_id, event.tenant_id, event.principal_id, event.action_digest,
        event.effect, json.dumps(list(event.reason_codes), separators=(",", ":")),
        event.policy_version, event.occurred_at_ms, event.retention_until_ms,
        event.fingerprint,
    )
