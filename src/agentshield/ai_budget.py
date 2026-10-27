"""Opt-in durable AI token/request budget, portable across SQLite and D1.

Zero quota unless an authorized operator has explicitly configured a
tenant's UTC-day budget in the local database. This is an inference *call*
reservation, not the provider's authoritative billing or cost statement.

A retry of an already-reserved request is rejected: never infer a second
time unless a separately reviewed, cached original result is available.
"""
from __future__ import annotations

import re
import sqlite3
import time
from datetime import datetime, timezone

TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
REQUEST_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}$")
INSERT_RESERVATION = (
    "INSERT INTO ai_triage_reservations "
    "(tenant_id,utc_day,request_id,reserved_input_tokens,"
    "reserved_output_tokens,created_at_ms) "
    "VALUES (?,?,?,?,?,?) "
    "ON CONFLICT(tenant_id,utc_day,request_id) DO NOTHING RETURNING request_id"
)


class BudgetUnavailable(RuntimeError):
    """No additional model inference is authorized."""


def _check(tenant: str, request_id: str, input_tokens: int,
           output_tokens: int, now_ms: int) -> tuple:
    if not isinstance(tenant, str) or not TENANT.fullmatch(tenant):
        raise BudgetUnavailable("Invalid tenant")
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise BudgetUnavailable("Invalid request ID")
    if (type(input_tokens) is not int or type(output_tokens) is not int or
        not 1 <= input_tokens <= 4096 or not 1 <= output_tokens <= 256):
        raise BudgetUnavailable("Invalid reservation ceiling")
    if type(now_ms) is not int or now_ms <= 0:
        raise BudgetUnavailable("Invalid clock")
    utc_day = datetime.fromtimestamp(now_ms / 1000, timezone.utc).date().isoformat()
    return tenant, utc_day, request_id, input_tokens, output_tokens, now_ms


class SQLiteAIBudget:
    def __init__(self, connection: sqlite3.Connection, *, tenant_id: str,
                 request_id: str, now_ms: int | None = None):
        self.db = connection
        self.tenant_id = tenant_id
        self.request_id = request_id
        self.now_ms = now_ms

    async def reserve(self, *, estimated_input_tokens: int,
                      max_output_tokens: int) -> bool:
        data = _check(
            self.tenant_id, self.request_id, estimated_input_tokens,
            max_output_tokens,
            self.now_ms if self.now_ms is not None else int(time.time() * 1000),
        )
        try:
            with self.db:
                row = self.db.execute(INSERT_RESERVATION, data).fetchone()
                return row is not None
        except sqlite3.Error as exc:
            raise BudgetUnavailable("No AI inference quota available") from exc


class D1AIBudget:
    """Must receive the trusted env.DB D1 binding and a server-created request ID."""

    def __init__(self, binding: object, *, tenant_id: str,
                 request_id: str, now_ms: int | None = None):
        if binding is None:
            raise BudgetUnavailable("D1 binding unavailable")
        self.db = binding
        self.tenant_id, self.request_id, self.now_ms = tenant_id, request_id, now_ms

    async def reserve(self, *, estimated_input_tokens: int,
                      max_output_tokens: int) -> bool:
        data = _check(
            self.tenant_id, self.request_id, estimated_input_tokens,
            max_output_tokens,
            self.now_ms if self.now_ms is not None else int(time.time() * 1000),
        )
        try:
            result = await self.db.prepare(INSERT_RESERVATION).bind(*data).first()
            return result is not None
        except Exception as exc:
            raise BudgetUnavailable("No D1 AI quota available") from exc
