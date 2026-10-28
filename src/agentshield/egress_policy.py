"""Offline-only candidate egress checks for a future constrained tool adapter.

An inspection is NOT a network authorization. We intentionally ship NO HTTP
transport: CPython and Cloudflare Python Workers must be unable to turn these
checks into a live fetch until address pinning, TLS and redirect handling have
been independently reviewed.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

from agentshield.audit import action_digest
from agentshield.demo_invoice import INVOICE
from agentshield.policy import Effect, PolicyEngine, Principal, ToolAction

_HOST = re.compile(r"^[a-z][a-z0-9.-]{2,251}$")
_MAX_ANSWERS = 8


class EgressRejected(ValueError):
    """Candidate endpoint, DNS result, redirect or capability was unsafe."""


@dataclass(frozen=True)
class EgressCapability:
    """Reviewed code-owned metadata, never built from an agent-provided URL."""

    capability_id: str
    action_digest: str
    method: str
    scheme: str
    host: str
    path: str
    port: int

    def __post_init__(self) -> None:
        if (self.scheme != "https" or self.port != 443
            or self.method != "GET"
            or not isinstance(self.host, str)
            or not _HOST.fullmatch(self.host)
            or self.host.startswith(".") or self.host.endswith(".")
            or ".." in self.host
            or self.host.count(".") < 2
            or any(not part or len(part) > 63 or part.startswith("-")
                   or part.endswith("-") for part in self.host.split("."))
            or not re.fullmatch(r"/[a-z0-9_/-]{1,100}", self.path)
            or "//" in self.path or "/../" in self.path
            or self.path.endswith("/..") or "/./" in self.path
            or self.path.endswith("/.")
            or not re.fullmatch(r"[0-9a-f]{64}", self.action_digest)):
            raise EgressRejected("Untrusted egress capability configuration")

    @property
    def url(self) -> str:
        return f"https://{self.host}{self.path}"


# Compile-time reviewed candidate for demonstration; .example is an
# intentionally non-live RFC 2606 reserved domain. NO provider calls exist.
_LOCAL_INVOICE_CAPABILITY = EgressCapability(
    capability_id="demo-invoice-read-v1",
    action_digest=action_digest(
        INVOICE.tool, INVOICE.operation, INVOICE.resource
    ),
    method="GET", scheme="https",
    host="api.invoices.example", path="/v1/invoices/42", port=443,
)


@dataclass(frozen=True)
class EgressInspection:
    """A preflight observation without a transport or invocation capability."""

    capability_id: str
    action_digest: str
    hostname: str
    address_count: int
    network_enabled: bool = False
    transport_pinned: bool = False
    execution_authorized: bool = False


def _validate_url(candidate: str, expected: EgressCapability) -> None:
    # Exact comparison is the primary boundary: do not normalize or repair a
    # caller-controlled URL into an allowed destination. Reject any encoding,
    # credentials, port, query, fragment, IP literal, slash or host alias.
    if (not isinstance(candidate, str) or len(candidate) > 384
        or candidate != expected.url
        or any(ord(char) < 33 or ord(char) > 126 for char in candidate)
        or "%" in candidate or "\\" in candidate):
        raise EgressRejected("Endpoint is not exact reviewed capability")
    try:
        parsed = urlsplit(candidate)
        if (parsed.scheme != expected.scheme
            or parsed.netloc != expected.host
            or parsed.hostname != expected.host
            or parsed.port not in (None, expected.port)
            or parsed.username is not None or parsed.password is not None
            or parsed.path != expected.path
            or parsed.query or parsed.fragment):
            raise EgressRejected("Endpoint origin or path differs")
    except (ValueError, TypeError) as exc:
        raise EgressRejected("Malformed endpoint URL") from exc


def _public_addresses(addresses: Sequence[str]) -> frozenset[str]:
    if (isinstance(addresses, (str, bytes))
        or not isinstance(addresses, (tuple, list))
        or not 1 <= len(addresses) <= _MAX_ANSWERS):
        raise EgressRejected("Missing or excessive DNS results")
    validated: set[str] = set()
    for raw in addresses:
        if not isinstance(raw, str) or len(raw) > 64 or "%" in raw:
            raise EgressRejected("Untrusted DNS address")
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise EgressRejected("Invalid DNS address") from exc
        # Do not permit IPv4-mapped, scoped, private, metadata, loopback,
        # reserved/documentation, link-local or unspecified destinations.
        if (not ip.is_global
            or getattr(ip, "ipv4_mapped", None) is not None
            or getattr(ip, "scope_id", None) is not None):
            raise EgressRejected("Non-global DNS address")
        validated.add(str(ip))
    if not validated:
        raise EgressRejected("No valid destination addresses")
    return frozenset(validated)


def inspect_egress(
    principal: Principal,
    action: ToolAction,
    engine: PolicyEngine,
    *,
    candidate_url: str,
    resolved_addresses: Sequence[str],
    redirect_url: str | None = None,
    next_addresses: Sequence[str] | None = None,
) -> EgressInspection:
    """Check a trusted single-target candidate and fake DNS answers.

    DNS input comes from the INJECTED offline test resolver in this version.
    Never treat this inspection as permission to use a network transport.
    """
    expected = _LOCAL_INVOICE_CAPABILITY
    if (action != INVOICE
        or action_digest(action.tool, action.operation, action.resource)
        != expected.action_digest
        or engine.evaluate(principal, action).effect != Effect.ALLOW):
        raise EgressRejected("Signed action and explicit policy not eligible")
    _validate_url(candidate_url, expected)
    if redirect_url is not None:
        # No redirects allowed, even to the same host, until a bound
        # transport enforces a fresh exact-origin/DNS check for every hop.
        raise EgressRejected("Redirect disabled")
    initial = _public_addresses(resolved_addresses)
    if next_addresses is not None:
        # This flags a synthetic DNS rebinding between inspections. An
        # actual HTTP client MUST connect to a pinned vetted address while
        # validating TLS for the original hostname, or it is NOT safe.
        later = _public_addresses(next_addresses)
        if later != initial:
            raise EgressRejected("DNS changed after preflight")
    return EgressInspection(
        capability_id=expected.capability_id,
        action_digest=expected.action_digest,
        hostname=expected.host,
        address_count=len(initial),
    )


class DisabledNetworkTransport:
    """The sole shipped transport; no fetch, socket or side effect is possible."""

    def send(self, inspection: EgressInspection) -> None:
        raise EgressRejected(
            "Live network transport disabled: no pinned DNS/TLS connector"
        )
