"""Tenant-scoped, immutable policy snapshot reader for local D1/SQLite.

RAIDER: extend the existing policy_versions table and reuse PolicyEngine.
No agent-supplied version, policy write HTTP endpoint, or execution permit.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol, Sequence

from agentshield.audit import AuditStorageError
from agentshield.policy import Effect, PolicyEngine, Rule

_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_VERSION = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{7,127}$")
_VALUE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_:/.-]{0,127}$")
_FIELDS = frozenset({"id", "principal_id", "tool", "operation", "resource",
                     "required_scope", "effect"})
_SCHEMA = "agentshield.policy.snapshot.v1"
_SELECT = (
    "SELECT p.tenant_id,p.version,p.sha256,p.rules_json "
    "FROM active_policy_versions a JOIN policy_versions p "
    "ON p.tenant_id=a.tenant_id AND p.version=a.version "
    "WHERE a.tenant_id=?"
)


class PolicyUnavailable(AuditStorageError):
    """A trusted active policy could not be loaded and validated."""


@dataclass(frozen=True)
class PublishedPolicy:
    tenant_id: str
    version: str
    sha256: str
    rules_json: str
    engine: PolicyEngine


class PolicyRowStore(Protocol):
    async def first(self, tenant_id: str) -> dict | None: ...


def _pairs_unique(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON policy field")
        out[key] = value
    return out


def _validate_identifiers(tenant_id: str, version: str) -> None:
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise ValueError("Invalid policy tenant")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ValueError("Invalid policy version")


def _rule_object(rule: Rule, tenant_id: str) -> dict[str, str]:
    data = {
        "id": rule.id, "principal_id": rule.principal_id,
        "tool": rule.tool, "operation": rule.operation,
        "resource": rule.resource, "required_scope": rule.required_scope,
        "effect": rule.effect.value,
    }
    if not rule.principal_id.startswith(tenant_id + ":"):
        raise ValueError("Policy rule belongs to another tenant")
    if any(not isinstance(v, str) or not _VALUE.fullmatch(v) or "*" in v
           for v in data.values()):
        raise ValueError("Unbounded policy field")
    return data


def canonical_snapshot(
    tenant_id: str, version: str, rules: Sequence[Rule],
) -> tuple[str, str]:
    """Return canonical, hashable snapshot; no implicit grants/wildcards."""
    _validate_identifiers(tenant_id, version)
    if not 1 <= len(rules) <= 64:
        raise ValueError("Policy needs 1–64 explicit rules")
    entries = sorted((_rule_object(r, tenant_id) for r in rules),
                     key=lambda item: item["id"])
    PolicyEngine(tuple(rules))  # Reuse the engine's duplicate-ID rejection.
    value = {"schema": _SCHEMA, "tenant_id": tenant_id,
             "version": version, "rules": entries}
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True)
    if len(encoded.encode("ascii")) > 32_768:
        raise ValueError("Policy snapshot too large")
    return encoded, hashlib.sha256(encoded.encode("ascii")).hexdigest()


def parse_snapshot(row: dict, trusted_tenant: str) -> PublishedPolicy:
    """Check the signed tenant's active record, digest and strict schema."""
    try:
        if not isinstance(row, dict) or row.get("tenant_id") != trusted_tenant:
            raise ValueError("Wrong tenant policy row")
        tenant, version = row["tenant_id"], row["version"]
        _validate_identifiers(tenant, version)
        raw = row["rules_json"]
        digest = row["sha256"]
        if not isinstance(raw, str) or len(raw) > 32_768 or not raw:
            raise ValueError("Missing or oversized policy")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Missing digest")
        document = json.loads(raw, object_pairs_hook=_pairs_unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonstandard JSON")))
        if not isinstance(document, dict) or set(document) != {
            "schema", "tenant_id", "version", "rules",
        } or document["schema"] != _SCHEMA or document["tenant_id"] != tenant or document["version"] != version:
            raise ValueError("Unexpected policy format")
        entries = document["rules"]
        if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
            raise ValueError("Missing or excessive rules")
        rules = []
        for item in entries:
            if not isinstance(item, dict) or set(item) != _FIELDS:
                raise ValueError("Invalid rule fields")
            if any(not isinstance(value, str) for value in item.values()):
                raise ValueError("Non-string rule value")
            rules.append(Rule(
                id=item["id"], principal_id=item["principal_id"],
                tool=item["tool"], operation=item["operation"],
                resource=item["resource"], required_scope=item["required_scope"],
                effect=Effect(item["effect"]),
            ))
        canonical, expected = canonical_snapshot(tenant, version, rules)
        if raw != canonical or digest != expected:
            raise ValueError("Policy integrity mismatch")
        return PublishedPolicy(tenant, version, digest, raw, PolicyEngine(rules))
    except (KeyError, ValueError, TypeError, UnicodeError) as exc:
        raise PolicyUnavailable("Invalid active policy snapshot") from exc


class D1PolicyRegistry:
    """Read only. Publishing/activating versions is an offline admin action."""

    def __init__(self, binding: object):
        if binding is None:
            raise PolicyUnavailable("Policy DB binding unavailable")
        self.db = binding

    async def load_active(self, tenant_id: str) -> PublishedPolicy:
        try:
            if not _TENANT.fullmatch(tenant_id):
                raise ValueError("Invalid tenant")
            row = await self.db.prepare(_SELECT).bind(tenant_id).first()
            if hasattr(row, "to_py"):
                row = row.to_py()
            if row is None:
                raise PolicyUnavailable("No active tenant policy")
            return parse_snapshot(row, tenant_id)
        except PolicyUnavailable:
            raise
        except Exception as exc:
            raise PolicyUnavailable("Active policy lookup unavailable") from exc


class SQLitePolicyRegistry:
    """CPython test/admin reference using the exact same SQL and parser."""

    def __init__(self, connection):
        self.db = connection

    async def load_active(self, tenant_id: str) -> PublishedPolicy:
        try:
            if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
                raise ValueError("Invalid tenant")
            row = self.db.execute(_SELECT, (tenant_id,)).fetchone()
            if row is None:
                raise PolicyUnavailable("No active tenant policy")
            return parse_snapshot(dict(row), tenant_id)
        except PolicyUnavailable:
            raise
        except Exception as exc:
            raise PolicyUnavailable("Active policy lookup unavailable") from exc
