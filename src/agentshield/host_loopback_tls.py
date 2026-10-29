"""HOST-ONLY TLS loopback fixture probe; never a production egress proxy.

This is the first REAL TCP/TLS handshake test of the previous offline contract.
It is deliberately restricted to 127.0.0.1 and a code-owned .example hostname.
It is NOT imported by the Worker, exposed over HTTP, or connected to the outbox.
Do not extend to arbitrary IPs without independent security review.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import time
from dataclasses import dataclass

from agentshield.audit import action_digest
from agentshield.demo_invoice import INVOICE
from agentshield.egress_policy import EgressRejected, _LOCAL_INVOICE_CAPABILITY
from agentshield.policy import Effect, PolicyEngine, Principal, ToolAction

_MAX_BODY_BYTES = 16_384
_MAX_HEADERS_BYTES = 8_192
_MAX_HEADER_COUNT = 32
_DEADLINE_SECONDS = 2.0
_ONLY_LOOPBACK_IP = "127.0.0.1"


@dataclass(frozen=True)
class LocalTLSProbeReceipt:
    """A loopback test receipt, NEVER an external execution permit."""

    capability_id: str
    peer_ip: str
    tls_version: str
    status: int
    body_sha256: str
    body_bytes: int
    network_used: bool = True
    external_network_used: bool = False
    execution_authorized: bool = False
    production_ready: bool = False


def _read_response(sock: ssl.SSLSocket, deadline: float) -> tuple[int, bytes]:
    """Parse a tightly constrained HTTP/1.1 response without redirects/streaming.

    Reject chunked/ambiguous framing and oversized headers before accepting
    data. Enforce a monotonic TOTAL deadline rather than per-read-only timeout.
    """
    def recv_limited(max_bytes: int) -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EgressRejected("Local TLS total deadline exceeded")
        sock.settimeout(remaining)
        return sock.recv(max_bytes)

    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if len(buffer) >= _MAX_HEADERS_BYTES:
            raise EgressRejected("HTTP header budget exhausted")
        chunk = recv_limited(min(4096, _MAX_HEADERS_BYTES - len(buffer)))
        if not chunk:
            raise EgressRejected("Incomplete HTTP headers")
        buffer += chunk
    raw_headers, body = buffer.split(b"\r\n\r\n", 1)
    try:
        lines = raw_headers.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise EgressRejected("Non-ASCII HTTP response headers") from exc
    if not lines or lines[0] != "HTTP/1.1 200 OK":
        raise EgressRejected("Unexpected HTTP status, including redirects")
    if len(lines) - 1 > _MAX_HEADER_COUNT:
        raise EgressRejected("Too many HTTP response headers")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line or line[:1] in (" ", "\t"):
            raise EgressRejected("Malformed or folded HTTP header")
        key, value = line.split(":", 1)
        key = key.lower()
        value = value.strip()
        if (not key or any(not (c.isascii() and
            (c.isalnum() or c == "-")) for c in key)
            or key in headers or "\x00" in value):
            raise EgressRejected("Duplicate or unsafe HTTP header")
        headers[key] = value
    if "transfer-encoding" in headers or "content-encoding" in headers:
        raise EgressRejected("Unsupported transfer/content encoding")
    length = headers.get("content-length")
    if (length is None or not length.isascii() or not length.isdigit()
        or len(length) > 5):
        raise EgressRejected("A single decimal Content-Length is required")
    count = int(length)
    if count > _MAX_BODY_BYTES or len(body) > count:
        raise EgressRejected("Response body exceeds declared limit")
    while len(body) < count:
        chunk = recv_limited(min(4096, count - len(body)))
        if not chunk:
            raise EgressRejected("Truncated HTTP response")
        body += chunk
    if time.monotonic() >= deadline:
        raise EgressRejected("Local TLS total deadline exceeded")
    return 200, body


def probe_local_tls_fixture(
    principal: Principal,
    action: ToolAction,
    engine: PolicyEngine,
    *,
    selected_ip: str,
    test_port: int,
    trusted_test_ca_pem: str,
) -> LocalTLSProbeReceipt:
    """Real handshake and GET to one TEST server on 127.0.0.1 only.

    The code-reviewed original hostname remains TLS SNI and certificate
    verification identity even though the TCP peer is a pinned literal IP.
    Caller cannot select a URL/path, arbitrary IP, auth header, or method.
    """
    cap = _LOCAL_INVOICE_CAPABILITY
    if (selected_ip != _ONLY_LOOPBACK_IP
        or type(test_port) is not int or not 1 <= test_port <= 65535
        or not isinstance(trusted_test_ca_pem, str)
        or not trusted_test_ca_pem.startswith("-----BEGIN CERTIFICATE-----")
        or len(trusted_test_ca_pem) > 16_384):
        raise EgressRejected("Only an explicit loopback TLS test fixture is allowed")
    if (action != INVOICE
        or action_digest(action.tool, action.operation, action.resource)
        != cap.action_digest
        or engine.evaluate(principal, action).effect != Effect.ALLOW):
        raise EgressRejected("Action not permitted by existing deterministic policy")
    # Context trusts ONLY the test CA and checks the ORIGINAL hostname.
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_context.verify_mode = ssl.CERT_REQUIRED
    tls_context.check_hostname = True
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
    tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        tls_context.load_verify_locations(cadata=trusted_test_ca_pem)
        deadline = time.monotonic() + _DEADLINE_SECONDS
        with socket.create_connection(
            (selected_ip, test_port), timeout=_DEADLINE_SECONDS,
        ) as tcp:
            if tcp.getpeername()[0] != _ONLY_LOOPBACK_IP:
                raise EgressRejected("Connected TCP peer differs from pinned IP")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EgressRejected("Local TLS connection timed out")
            tcp.settimeout(remaining)
            with tls_context.wrap_socket(tcp, server_hostname=cap.host) as tls:
                if (tls.getpeername()[0] != _ONLY_LOOPBACK_IP
                    or tls.version() != "TLSv1.3"):
                    raise EgressRejected("TLS peer IP or negotiated version differs")
                request = (
                    f"GET {cap.path} HTTP/1.1\r\n"
                    f"Host: {cap.host}\r\n"
                    "Accept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EgressRejected("Local TLS send timed out")
                tls.settimeout(remaining)
                tls.sendall(request)
                status, body = _read_response(tls, deadline)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise EgressRejected("Local loopback TLS verification or I/O failed") from exc
    return LocalTLSProbeReceipt(
        capability_id=cap.capability_id,
        peer_ip=_ONLY_LOOPBACK_IP,
        tls_version="TLSv1.3",
        status=status,
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_bytes=len(body),
    )
