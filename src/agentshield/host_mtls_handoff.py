"""HOST-ONLY, one-shot, mutually authenticated LOOPBACK TLS handoff.

A genuine TCP/TLS 1.3 socket conveys an already issued, D1/SQLite-audited
ES256 token to an isolated verifier. Both peer identities are independently
pinned; the receiver burns the token in its own durable SQLite ledger before
acknowledging. This never invokes an external tool or exposes an API route.
Not imported into Cloudflare Pyodide; not a production service.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import socket
import ssl
import struct
import time
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.host_signed_handoff import (
    HandoffRejected, HostHandoffReceipt, verify_and_burn_local_handoff,
)

_LOOPBACK = "127.0.0.1"
_HOSTNAME = "handoff.agentshield.test"
_DEADLINE = 2.0
_MAX_TOKEN = 2500
_ACK = b"ACK"


@dataclass(frozen=True)
class LocalMTLSDeliveryReceipt:
    """Authenticated local ACK means *consumed*, never *executed*."""

    peer_ip: str = _LOOPBACK
    tls_version: str = "TLSv1.3"
    acknowledged: bool = True
    network_used: bool = True
    external_network_used: bool = False
    execution_authorized: bool = False
    production_ready: bool = False


def _check_port(port: int) -> None:
    if type(port) is not int or not 1 <= port <= 65535:
        raise HandoffRejected("Invalid local TLS test port")


def _check_ca(ca_pem: str) -> None:
    if (not isinstance(ca_pem, str)
        or not ca_pem.startswith("-----BEGIN CERTIFICATE-----")
        or len(ca_pem) > 16_384):
        raise HandoffRejected("Invalid pinned local test CA")


def _check_fingerprint(digest: str) -> None:
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise HandoffRejected("Invalid client certificate pin")


def _remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise HandoffRejected("Local handoff total deadline exceeded")
    return seconds


def _read_exact(sock: ssl.SSLSocket, count: int, deadline: float) -> bytes:
    data = b""
    while len(data) < count:
        sock.settimeout(_remaining(deadline))
        part = sock.recv(count - len(data))
        if not part:
            raise HandoffRejected("Truncated local handoff frame")
        data += part
    return data


def _read_frame(sock: ssl.SSLSocket, limit: int, deadline: float) -> bytes:
    length = struct.unpack("!I", _read_exact(sock, 4, deadline))[0]
    if not 1 <= length <= limit:
        raise HandoffRejected("Invalid or oversized local handoff frame")
    return _read_exact(sock, length, deadline)


def _write_frame(sock: ssl.SSLSocket, payload: bytes, deadline: float) -> None:
    if not payload or len(payload) > _MAX_TOKEN:
        raise HandoffRejected("Invalid local handoff payload size")
    sock.settimeout(_remaining(deadline))
    sock.sendall(struct.pack("!I", len(payload)) + payload)
    _remaining(deadline)


def _tls13(context: ssl.SSLContext) -> None:
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3


def deliver_local_mtls_handoff(
    token: str, *, test_port: int, trusted_server_ca_pem: str,
    client_cert: Path, client_key: Path,
) -> LocalMTLSDeliveryReceipt:
    """Send one already-issued token to ONLY 127.0.0.1 over client mTLS.

    A missing ACK is ambiguous after delivery. NEVER mint or replay a token
    automatically; manual reconciliation is required.
    """
    _check_port(test_port)
    _check_ca(trusted_server_ca_pem)
    if (not isinstance(token, str) or not 1 <= len(token) <= _MAX_TOKEN
        or not token.isascii() or token.count(".") != 1):
        raise HandoffRejected("Invalid signed token transport input")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _tls13(context)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    deadline = time.monotonic() + _DEADLINE
    try:
        context.load_verify_locations(cadata=trusted_server_ca_pem)
        context.load_cert_chain(str(client_cert), str(client_key))
        with socket.create_connection((_LOOPBACK, test_port), timeout=_remaining(deadline)) as raw:
            if raw.getpeername()[0] != _LOOPBACK:
                raise HandoffRejected("Unexpected local TCP peer")
            raw.settimeout(_remaining(deadline))
            with context.wrap_socket(raw, server_hostname=_HOSTNAME) as tls:
                if tls.version() != "TLSv1.3" or tls.getpeername()[0] != _LOOPBACK:
                    raise HandoffRejected("Unexpected local TLS peer")
                _write_frame(tls, token.encode("ascii"), deadline)
                if _read_frame(tls, len(_ACK), deadline) != _ACK:
                    raise HandoffRejected("Missing authenticated local burn ACK")
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise HandoffRejected("Local mTLS delivery not acknowledged") from exc
    return LocalMTLSDeliveryReceipt()


def receive_one_local_mtls_handoff(
    listener: socket.socket, *, server_cert: Path, server_key: Path,
    trusted_client_ca_pem: str, pinned_client_cert_sha256: str,
    replay_db: sqlite3.Connection,
    trusted_issuer_public_key: ec.EllipticCurvePublicKey,
    now_ms: int, expected_tenant: str, expected_command_id: str,
) -> HostHandoffReceipt:
    """One accept on a pre-bound LOOPBACK listener: verify mTLS then burn.

    Server identity is a test certificate; client identity must match both
    CA and a separately provisioned DER fingerprint. TLS does not replace
    token issuer signature, tenant binding or durable replay denial.
    """
    _check_ca(trusted_client_ca_pem)
    _check_fingerprint(pinned_client_cert_sha256)
    if not isinstance(listener, socket.socket) or listener.getsockname()[0] != _LOOPBACK:
        raise HandoffRejected("Listener must be bound to literal loopback")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _tls13(context)
    context.verify_mode = ssl.CERT_REQUIRED
    deadline = time.monotonic() + _DEADLINE
    try:
        context.load_cert_chain(str(server_cert), str(server_key))
        context.load_verify_locations(cadata=trusted_client_ca_pem)
        listener.settimeout(_remaining(deadline))
        raw, address = listener.accept()
        with raw:
            if address[0] != _LOOPBACK:
                raise HandoffRejected("Unexpected inbound TCP peer")
            raw.settimeout(_remaining(deadline))
            with context.wrap_socket(raw, server_side=True) as tls:
                if tls.version() != "TLSv1.3" or tls.getpeername()[0] != _LOOPBACK:
                    raise HandoffRejected("Unexpected local TLS peer")
                client_der = tls.getpeercert(binary_form=True)
                if (not client_der or not hmac.compare_digest(
                    hashlib.sha256(client_der).hexdigest(), pinned_client_cert_sha256
                )):
                    raise HandoffRejected("Untrusted client service certificate")
                token = _read_frame(tls, _MAX_TOKEN, deadline).decode("ascii")
                receipt = verify_and_burn_local_handoff(
                    replay_db, token, trusted_issuer_public_key,
                    now_ms=now_ms, expected_tenant=expected_tenant,
                    expected_command_id=expected_command_id,
                )
                # This ACK follows the independent durable replay commit.
                # Its loss is ambiguous, NOT a reason to resend or reissue.
                _write_frame(tls, _ACK, deadline)
                return receipt
    except (OSError, ssl.SSLError, UnicodeError, ValueError) as exc:
        raise HandoffRejected("Local mTLS receive refused") from exc
