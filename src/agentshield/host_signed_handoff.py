"""HOST-ONLY signed one-use handoff proof for a future isolated executor.

NO Cloudflare gateway import, provider URL, HTTP transport, remote D1 or real
tool dispatch. A trusted host test issuer verifies the existing D1/SQLite
outbox, one-shot dispatch reservation and redacted audits BEFORE signing.
The consumer pins an independent ES256 public key and durably burns a JTI
before any local demonstration can proceed. NOT production authorization.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import sqlite3
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from agentshield.approvals import ApprovalStore
from agentshield.audit import AuditRepository, AuditStorageError, action_digest, event_arguments
from agentshield.demo_invoice import INVOICE
from agentshield.egress_policy import EgressRejected
from agentshield.idempotent_decisions import _fingerprint
from agentshield.identity import VerifiedAgent
from agentshield.local_command_outbox import _ACTIVE, _FIND, _verify_audit, _audit_event
from agentshield.policy import Effect
from agentshield.policy_registry import SQLitePolicyRegistry, D1PolicyRegistry

_ISSUER = "agentshield-local-handoff-v1"
_AUDIENCE = "agentshield-isolated-host-test-v1"
_LIFETIME_MS = 30_000
_HEX_ID = re.compile(r"^[a-z0-9-]+-[0-9a-f]{32}$")
_HEX_SHA = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_FIELDS = frozenset((
    "schema", "iss", "aud", "jti", "tenant", "agent", "command_id",
    "dispatch_id", "decision_event_id", "dispatch_audit_event_id",
    "policy_version", "policy_sha256", "action_sha256", "scopes",
    "issued_at_ms", "expires_at_ms",
))
_RESERVATION = (
    "SELECT tenant_id,command_id,dispatch_id,request_id,principal_id,"
    "claim_audit_event_id,dispatch_audit_event_id,decision_sha256 "
    "FROM local_mock_dispatch_reservations WHERE tenant_id=? AND command_id=?"
)
_DECISION = (
    "SELECT event_id,principal_id,policy_version,policy_sha256,"
    "request_sha256,effect,expires_at_ms FROM decision_requests "
    "WHERE tenant_id=? AND request_id=?"
)
# Persist only hashes; neither token nor private signing key belongs in D1.
# The active generation and decision are checked again *inside* the insert,
# preventing a stale-policy race from leaving an issuance record.
_ISSUE = (
    "INSERT INTO local_handoff_issuances "
    "(tenant_id,command_id,issuance_id,principal_id,dispatch_id,"
    "dispatch_audit_event_id,policy_version,policy_sha256,action_digest,"
    "jti_sha256,token_sha256,issued_at_ms,expires_at_ms,audit_event_id) "
    "SELECT c.tenant_id,c.command_id,?,c.principal_id,r.dispatch_id,"
    "r.dispatch_audit_event_id,c.policy_version,c.policy_sha256,"
    "c.action_digest,?,?,?,?,? "
    "FROM local_command_outbox c "
    "JOIN local_mock_dispatch_reservations r "
    "ON r.tenant_id=c.tenant_id AND r.command_id=c.command_id "
    "JOIN decision_requests d "
    "ON d.tenant_id=c.tenant_id AND d.request_id=c.request_id "
    "JOIN active_policy_versions a ON a.tenant_id=c.tenant_id "
    "WHERE c.tenant_id=? AND c.command_id=? AND c.state='claimed' "
    "AND c.principal_id=? AND r.principal_id=c.principal_id "
    "AND r.dispatch_id=? AND r.dispatch_audit_event_id=? "
    "AND r.decision_sha256=? "
    "AND d.event_id=c.decision_event_id AND d.effect='allow' "
    "AND d.request_sha256=r.decision_sha256 "
    "AND d.policy_version=c.policy_version AND d.policy_sha256=c.policy_sha256 "
    "AND d.expires_at_ms>? "
    "AND a.version=c.policy_version "
    "AND a.activated_at_ms=c.active_at_ms "
    "AND COALESCE(a.activation_marker,'')=c.active_marker "
    "ON CONFLICT(tenant_id,command_id) DO NOTHING"
)
_ISSUE_AUDIT = (
    "INSERT INTO audit_events "
    "(event_id,tenant_id,principal_id,action_digest,effect,reason_codes_json,"
    "policy_version,occurred_at_ms,retention_until_ms,event_sha256) "
    "SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS("
    "SELECT 1 FROM local_handoff_issuances "
    "WHERE tenant_id=? AND command_id=? AND issuance_id=? "
    "AND audit_event_id=?)"
)
_ISSUE_ROW = (
    "SELECT issuance_id,principal_id,dispatch_id,dispatch_audit_event_id,"
    "policy_version,policy_sha256,action_digest,jti_sha256,"
    "token_sha256,audit_event_id FROM local_handoff_issuances "
    "WHERE tenant_id=? AND command_id=?"
)



class HandoffRejected(ValueError):
    """Untrusted, stale, replayed, cross-tenant or unaudited handoff."""


@dataclass(frozen=True)
class HostHandoffReceipt:
    command_id: str
    dispatch_id: str
    tenant_id: str
    action_sha256: str
    token_used: bool = True
    external_network_used: bool = False
    execution_authorized: bool = False
    production_ready: bool = False


def _encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode(part: str) -> bytes:
    if not isinstance(part, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", part):
        raise HandoffRejected("Invalid signed handoff encoding")
    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    if _encode(raw) != part:
        raise HandoffRejected("Noncanonical handoff encoding")
    return raw


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


async def issue_offline_handoff(
    store: ApprovalStore,
    audit: AuditRepository,
    registry: SQLitePolicyRegistry | D1PolicyRegistry,
    agent: VerifiedAgent,
    *,
    command_id: str,
    now_ms: int,
    private_key: ec.EllipticCurvePrivateKey,
) -> str:
    """Sign a 30s *local test* handoff after verifying durable source evidence.

    Signing key is an ephemeral HOST test key, never an AgentShield Worker or
    secret deployed in production. This is not a public issuance endpoint.
    """
    if (agent.principal.id != f"{agent.tenant_id}:{agent.agent_id}"
        or type(now_ms) is not int or now_ms <= 0
        or not isinstance(private_key, ec.EllipticCurvePrivateKey)
        or not isinstance(private_key.curve, ec.SECP256R1)
        or not isinstance(command_id, str)
        or re.fullmatch(r"local-command-[0-9a-f]{32}", command_id) is None):
        raise HandoffRejected("Invalid signed local handoff request")
    row = await store.first(_FIND, (agent.tenant_id, command_id))
    reservation = await store.first(_RESERVATION, (agent.tenant_id, command_id))
    if (row is None or row["state"] != "claimed"
        or row["principal_id"] != agent.principal.id
        or reservation is None
        or reservation["principal_id"] != agent.principal.id
        or reservation["request_id"] != row["request_id"]
        or reservation["claim_audit_event_id"] != row["claim_audit_event_id"]):
        raise HandoffRejected("Missing original-agent claimed dispatch")
    active = await registry.load_active(agent.tenant_id)
    generation = await store.first(_ACTIVE, (agent.tenant_id,))
    digest = action_digest(INVOICE.tool, INVOICE.operation, INVOICE.resource)
    if (row["action_digest"] != digest or active.version != row["policy_version"]
        or active.sha256 != row["policy_sha256"]
        or generation is None or generation["version"] != row["policy_version"]
        or generation["activated_at_ms"] != row["active_at_ms"]
        or generation["marker"] != row["active_marker"]
        or active.engine.evaluate(agent.principal, INVOICE).effect != Effect.ALLOW):
        raise HandoffRejected("Stale tenant policy or forbidden tool")
    decision = await store.first(_DECISION, (agent.tenant_id, row["request_id"]))
    expected = _fingerprint(
        agent, INVOICE, row["request_id"], active.version, active.sha256,
        row["active_at_ms"], row["active_marker"],
    )
    if (decision is None or decision["event_id"] != row["decision_event_id"]
        or decision["effect"] != "allow"
        or decision["principal_id"] != agent.principal.id
        or decision["policy_version"] != active.version
        or decision["policy_sha256"] != active.sha256
        or decision["request_sha256"] != expected
        or reservation["decision_sha256"] != expected
        or decision["expires_at_ms"] <= now_ms):
        raise HandoffRejected("Missing or expired immutable decision evidence")
    for key, principal, reason in (
        ("decision_event_id", agent.principal.id, None),
        ("queue_audit_event_id", agent.principal.id, "LOCAL_COMMAND_QUEUED_NO_DISPATCH"),
    ):
        await _verify_audit(
            audit, agent.tenant_id, row[key], principal,
            digest, active.version, reason,
        )
    claim = await audit.get_event(agent.tenant_id, row["claim_audit_event_id"])
    if (claim is None or claim.action_digest != digest
        or claim.effect != "allow"
        or claim.reason_codes != ("LOCAL_COMMAND_CLAIMED_NO_DISPATCH",)
        or claim.policy_version != active.version
        or not claim.principal_id.startswith(agent.tenant_id + ":")
        or claim.principal_id == agent.principal.id):
        raise HandoffRejected("Missing independent operator claim audit")
    await _verify_audit(
        audit, agent.tenant_id, reservation["dispatch_audit_event_id"],
        agent.principal.id, digest, active.version,
        "LOCAL_MOCK_DISPATCH_RESERVED_NO_EXTERNAL_IO",
    )
    # Avoid issuing after any observed generation drift.
    current = await registry.load_active(agent.tenant_id)
    latest = await store.first(_ACTIVE, (agent.tenant_id,))
    if (current.version != active.version or current.sha256 != active.sha256
        or latest is None or latest["version"] != active.version
        or latest["activated_at_ms"] != row["active_at_ms"]
        or latest["marker"] != row["active_marker"]):
        raise HandoffRejected("Policy changed before handoff signing")
    data: dict[str, Any] = {
        "schema": 1, "iss": _ISSUER, "aud": _AUDIENCE,
        "jti": secrets.token_hex(16),
        "tenant": agent.tenant_id, "agent": agent.principal.id,
        "command_id": command_id, "dispatch_id": reservation["dispatch_id"],
        "decision_event_id": row["decision_event_id"],
        "dispatch_audit_event_id": reservation["dispatch_audit_event_id"],
        "policy_version": active.version, "policy_sha256": active.sha256,
        "action_sha256": digest, "scopes": sorted(agent.principal.scopes),
        "issued_at_ms": now_ms, "expires_at_ms": now_ms + _LIFETIME_MS,
    }
    raw = _canonical(data)
    der = private_key.sign(raw, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    token = _encode(raw) + "." + _encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    )
    token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    issuance_id = "handoff-issuance-" + secrets.token_hex(16)
    audit_id = "handoff-issued-" + secrets.token_hex(16)
    evidence = _audit_event(
        audit_id, agent.tenant_id, agent.principal.id, digest,
        active.version, "LOCAL_SIGNED_HANDOFF_ISSUED_NO_EXECUTION", now_ms,
    )
    # One database transaction: D1/SQLite records this handoff + its audit.
    # A duplicated command cannot mint a second usable token; if a signed
    # response is lost after commit, the command is intentionally exhausted.
    await store.atomic([
        (_ISSUE, (
            issuance_id,
            hashlib.sha256(data["jti"].encode("ascii")).hexdigest(),
            token_digest, now_ms, now_ms + _LIFETIME_MS, audit_id,
            agent.tenant_id, command_id, agent.principal.id,
            reservation["dispatch_id"], reservation["dispatch_audit_event_id"],
            expected, now_ms,
        )),
        (_ISSUE_AUDIT, event_arguments(evidence) + (
            agent.tenant_id, command_id, issuance_id, audit_id,
        )),
    ])
    saved = await store.first(_ISSUE_ROW, (agent.tenant_id, command_id))
    if (saved is None or saved["issuance_id"] != issuance_id
        or saved["token_sha256"] != token_digest
        or saved["jti_sha256"] != hashlib.sha256(
            data["jti"].encode("ascii")
        ).hexdigest()
        or saved["principal_id"] != agent.principal.id
        or saved["dispatch_id"] != reservation["dispatch_id"]
        or saved["dispatch_audit_event_id"] != reservation["dispatch_audit_event_id"]
        or saved["policy_version"] != active.version
        or saved["policy_sha256"] != active.sha256
        or saved["action_digest"] != digest
        or saved["audit_event_id"] != audit_id):
        raise HandoffRejected("Handoff already issued or issuance evidence changed")
    await _verify_audit(
        audit, agent.tenant_id, audit_id, agent.principal.id,
        digest, active.version, "LOCAL_SIGNED_HANDOFF_ISSUED_NO_EXECUTION",
    )
    return token


def init_host_replay_db(conn: sqlite3.Connection) -> None:
    """Host-only durable replay ledger. Independent of the D1 Worker DB."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS used_local_handoffs("
        "issuer TEXT NOT NULL,jti TEXT NOT NULL,tenant TEXT NOT NULL,"
        "command_id TEXT NOT NULL,dispatch_id TEXT NOT NULL,"
        "consumed_at_ms INTEGER NOT NULL,"
        "PRIMARY KEY(issuer,jti), UNIQUE(tenant,command_id))"
    )


def verify_and_burn_local_handoff(
    conn: sqlite3.Connection,
    token: str,
    trusted_public_key: ec.EllipticCurvePublicKey,
    *,
    now_ms: int,
    expected_tenant: str,
    expected_command_id: str,
) -> HostHandoffReceipt:
    """Verify pinned issuer key, bound claims and commit durable one-use burn.

    This deliberately DOES NOT perform network I/O. The caller must not
    re-run any operation after an interrupted/ambiguous handoff.
    """
    if (not isinstance(token, str) or len(token) > 2500
        or token.count(".") != 1
        or not isinstance(trusted_public_key, ec.EllipticCurvePublicKey)
        or not isinstance(trusted_public_key.curve, ec.SECP256R1)
        or type(now_ms) is not int or now_ms <= 0):
        raise HandoffRejected("Invalid handoff verifier input")
    p, sig = token.split(".")
    raw, signature = _decode(p), _decode(sig)
    if len(signature) != 64:
        raise HandoffRejected("Invalid fixed ES256 signature size")
    try:
        trusted_public_key.verify(
            utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            ),
            raw, ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError) as exc:
        raise HandoffRejected("Handoff signer not trusted") from exc
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HandoffRejected("Invalid handoff payload") from exc
    if not isinstance(data, dict) or set(data) != _ALLOWED_FIELDS or raw != _canonical(data):
        raise HandoffRejected("Noncanonical or additional claims")
    if (type(data["schema"]) is not int or data["schema"] != 1
        or data["iss"] != _ISSUER or data["aud"] != _AUDIENCE
        or data["tenant"] != expected_tenant
        or data["command_id"] != expected_command_id
        or not isinstance(data["agent"], str)
        or not data["agent"].startswith(expected_tenant + ":")
        or not isinstance(data["policy_version"], str)
        or not 8 <= len(data["policy_version"]) <= 128
        or not isinstance(data["scopes"], list)
        or data["scopes"] != ["invoice:read"]
        or not isinstance(data["jti"], str)
        or re.fullmatch(r"[0-9a-f]{32}", data["jti"]) is None
        or any(not isinstance(data[k], str) or _HEX_ID.fullmatch(data[k]) is None
               for k in ("command_id", "dispatch_id", "decision_event_id",
                         "dispatch_audit_event_id"))
        or any(not isinstance(data[k], str) or _HEX_SHA.fullmatch(data[k]) is None
               for k in ("policy_sha256", "action_sha256"))
        or data["action_sha256"] != action_digest(
            INVOICE.tool, INVOICE.operation, INVOICE.resource
        )
        or type(data["issued_at_ms"]) is not int
        or type(data["expires_at_ms"]) is not int
        or not data["issued_at_ms"] <= now_ms < data["expires_at_ms"]
        or data["expires_at_ms"] - data["issued_at_ms"] != _LIFETIME_MS):
        raise HandoffRejected("Cross-tenant, stale or altered handoff claims")
    try:
        # Explicit transaction: unique JTI and command ID MUST survive crash
        # before any hypothetical host-side action can happen.
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO used_local_handoffs "
            "(issuer,jti,tenant,command_id,dispatch_id,consumed_at_ms) "
            "VALUES (?,?,?,?,?,?)",
            (_ISSUER, data["jti"], data["tenant"], data["command_id"],
             data["dispatch_id"], now_ms),
        )
        conn.commit()
    except sqlite3.DatabaseError as exc:
        conn.rollback()
        raise HandoffRejected("Replay or host replay-ledger unavailable") from exc
    return HostHandoffReceipt(
        command_id=data["command_id"], dispatch_id=data["dispatch_id"],
        tenant_id=data["tenant"], action_sha256=data["action_sha256"],
    )
