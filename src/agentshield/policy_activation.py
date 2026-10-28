"""Local-only CAS policy activation reusing D1/SQLite atomic audit primitives.

No published-policy write endpoint and no agent-supplied authority. The
current and target snapshots must pass the existing SHA/canonical verifier.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass

from agentshield.approvals import ApprovalStore
from agentshield.audit import AuditEvent, AuditStorageError, decode_event, event_arguments
from agentshield.identity import VerifiedAgent
from agentshield.policy_registry import (
    D1PolicyRegistry, PolicyUnavailable, SQLitePolicyRegistry, parse_snapshot,
)

_TARGET = (
    "SELECT tenant_id,version,sha256,rules_json FROM policy_versions "
    "WHERE tenant_id=? AND version=?"
)
_UPDATE = (
    "UPDATE active_policy_versions SET version=?,activated_at_ms=?,"
    "activation_marker=? WHERE tenant_id=? AND version=? "
    "AND activated_at_ms<? AND EXISTS "
    "(SELECT 1 FROM policy_versions WHERE tenant_id=? AND version=? AND sha256=?)"
)
_INSERT_HISTORY = (
    "INSERT INTO policy_activation_history "
    "(activation_id,tenant_id,previous_version,new_version,new_sha256,"
    "operator_id,activated_at_ms,audit_event_id) "
    "SELECT ?,?,?,?,?,?,?,? WHERE EXISTS "
    "(SELECT 1 FROM active_policy_versions "
    "WHERE tenant_id=? AND version=? AND activation_marker=?)"
)
_INSERT_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS "
    "(SELECT 1 FROM policy_activation_history "
    "WHERE activation_id=? AND tenant_id=? AND audit_event_id=?)"
)
_HISTORY = (
    "SELECT activation_id,tenant_id,previous_version,new_version,new_sha256,"
    "operator_id,activated_at_ms,audit_event_id FROM policy_activation_history "
    "WHERE activation_id=? AND tenant_id=?"
)
_AUDIT = (
    "SELECT event_id,tenant_id,principal_id,action_digest,effect,"
    "reason_codes_json,policy_version,occurred_at_ms,retention_until_ms,"
    "event_sha256 FROM audit_events WHERE event_id=? AND tenant_id=?"
)
_MAX_RETENTION = 30 * 86_400_000


class PolicyActivationConflict(ValueError):
    """Missing, stale, or mismatched target/expected active version."""


@dataclass(frozen=True)
class PolicyActivation:
    activation_id: str
    tenant_id: str
    previous_version: str
    new_version: str
    new_sha256: str
    audit_event_id: str
    operator_id: str


async def activate_policy(
    store: ApprovalStore,
    registry: D1PolicyRegistry | SQLitePolicyRegistry,
    operator: VerifiedAgent,
    *,
    expected_version: str,
    target_version: str,
    target_sha256: str,
    now_ms: int,
) -> PolicyActivation:
    """Compare-and-swap pointer + append-only activation and audit atomically.

    The current version is rechecked *in the SQL transaction*. If another
    administrator wins first, the losing activation has no audit or history,
    and it cannot return success.
    """
    if "policies:activate" not in operator.principal.scopes:
        raise PolicyActivationConflict("Operator lacks activation scope")
    if operator.principal.id != f"{operator.tenant_id}:{operator.agent_id}":
        raise PolicyActivationConflict("Operator principal mismatch")
    if type(now_ms) is not int or now_ms <= 0:
        raise ValueError("Invalid activation timestamp")
    if not isinstance(expected_version, str) or not isinstance(target_version, str):
        raise PolicyActivationConflict("Invalid policy version")
    if expected_version == target_version:
        raise PolicyActivationConflict("No-op activation not permitted")
    if not isinstance(target_sha256, str) or len(target_sha256) != 64:
        raise PolicyActivationConflict("Invalid target digest")

    active = await registry.load_active(operator.tenant_id)
    if active.version != expected_version:
        raise PolicyActivationConflict("Active policy changed")
    try:
        target_row = await store.first(_TARGET, (operator.tenant_id, target_version))
    except AuditStorageError as exc:
        raise PolicyUnavailable("Target policy lookup unavailable") from exc
    if target_row is None:
        raise PolicyActivationConflict("Target policy version not published")
    target = parse_snapshot(target_row, operator.tenant_id)
    if target.sha256 != target_sha256:
        raise PolicyActivationConflict("Target policy digest mismatch")

    activation_id = "policy-activation-" + secrets.token_hex(16)
    action = json.dumps(
        {"schema": "agentshield.policy.activation.v1",
         "tenant": operator.tenant_id, "previous": active.version,
         "target": target.version, "sha256": target.sha256,
         "operator": operator.principal.id},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    event = AuditEvent(
        event_id=activation_id,
        tenant_id=operator.tenant_id,
        principal_id=operator.principal.id,
        action_digest=hashlib.sha256(action.encode("ascii")).hexdigest(),
        effect="allow",
        reason_codes=("POLICY_VERSION_ACTIVATED",),
        policy_version=target.version,
        occurred_at_ms=now_ms,
        retention_until_ms=now_ms + _MAX_RETENTION,
    )
    record = PolicyActivation(
        activation_id, operator.tenant_id, active.version, target.version,
        target.sha256, event.event_id, operator.principal.id,
    )
    # The transaction is atomic in SQLite and Cloudflare D1.batch.
    # A rejected CAS writes neither history nor audit.
    await store.atomic([
        (_UPDATE, (target.version, now_ms, activation_id,
                   operator.tenant_id, active.version, now_ms,
                   operator.tenant_id, target.version, target.sha256)),
        (_INSERT_HISTORY, (
            activation_id, operator.tenant_id, active.version,
            target.version, target.sha256, operator.principal.id,
            now_ms, event.event_id,
            operator.tenant_id, target.version, activation_id,
        )),
        (_INSERT_AUDIT, event_arguments(event) +
         (activation_id, operator.tenant_id, event.event_id)),
    ])
    history = await store.first(_HISTORY, (activation_id, operator.tenant_id))
    if history is None:
        raise PolicyActivationConflict("Concurrent policy change; activation not committed")
    actual = await store.first(_AUDIT, (event.event_id, operator.tenant_id))
    if actual is None or decode_event(actual).fingerprint != event.fingerprint:
        raise PolicyUnavailable("Activation audit confirmation failed")
    if any(history[key] != value for key, value in (
        ("previous_version", active.version), ("new_version", target.version),
        ("new_sha256", target.sha256), ("operator_id", operator.principal.id),
        ("audit_event_id", event.event_id),
    )):
        raise PolicyUnavailable("Activation history integrity mismatch")
    return record
