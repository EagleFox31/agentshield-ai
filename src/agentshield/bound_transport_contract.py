"""Offline-only transport binding contract for a future restricted HTTPS proxy.

This module consumes INJECTED, SYNTHETIC observations. It cannot attest that
a network connection happened, and deliberately provides no socket or fetch
implementation, execution token, or trusted TLS proof. The real transport
must independently bind the selected address to the actual connected peer
and cryptographically verify the original hostname.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from agentshield.egress_policy import (
    DisabledNetworkTransport, EgressRejected, _LOCAL_INVOICE_CAPABILITY,
    _public_addresses, inspect_egress,
)
from agentshield.policy import PolicyEngine, Principal, ToolAction

_MAX_BODY_BYTES = 16_384
_MAX_ELAPSED_MS = 2_000


@dataclass(frozen=True)
class SyntheticTransportObservation:
    """Untrusted test fixture, NEVER a runtime TLS attestation."""

    selected_ip: str
    connected_peer_ip: str
    target_host: str
    tls_sni: str
    certificate_host: str
    certificate_chain_verified: bool
    certificate_hostname_verified: bool
    tls_version: str
    method: str
    observed_url: str
    proxy_used: bool
    redirects_followed: int
    http_status: int
    response_body_bytes: int
    elapsed_ms: int


@dataclass(frozen=True)
class OfflineTransportReview:
    """Only a simulation outcome. Even a valid fixture grants no authority."""

    capability_id: str
    peer_ip: str
    body_limit_bytes: int
    elapsed_limit_ms: int
    simulation_only: bool = True
    network_enabled: bool = False
    transport_attested: bool = False
    execution_authorized: bool = False


def inspect_synthetic_transport(
    principal: Principal,
    action: ToolAction,
    engine: PolicyEngine,
    *,
    candidate_url: str,
    dns_answers: Sequence[str],
    observation: SyntheticTransportObservation,
) -> OfflineTransportReview:
    """Model a fail-closed bound HTTPS exchange *without executing* one.

    Neither an IP string nor boolean flags prove TLS verification. This
    inspection checks a future transport's mandatory observable invariants,
    not their authenticity. A real Worker fetch MUST NOT use its result.
    """
    if not isinstance(observation, SyntheticTransportObservation):
        raise EgressRejected("Missing synthetic transport observation")
    expected = _LOCAL_INVOICE_CAPABILITY
    inspect_egress(
        principal, action, engine, candidate_url=candidate_url,
        resolved_addresses=dns_answers,
    )
    addresses = _public_addresses(dns_answers)
    # A future connection must select one of the reviewed DNS addresses,
    # then prove the network peer is EXACTLY the selected address. A separate
    # fetch-by-name is inherently unsafe because it can re-resolve.
    if (type(observation.selected_ip) is not str
        or type(observation.connected_peer_ip) is not str
        or observation.selected_ip not in addresses
        or observation.connected_peer_ip != observation.selected_ip):
        raise EgressRejected("Selected IP not bound to actual peer")
    if (observation.target_host != expected.host
        or observation.tls_sni != expected.host
        or observation.certificate_host != expected.host
        or observation.observed_url != expected.url
        or observation.method != expected.method):
        raise EgressRejected("Origin, TLS hostname, method or URL mismatch")
    if (observation.certificate_chain_verified is not True
        or observation.certificate_hostname_verified is not True
        or observation.tls_version != "TLSv1.3"):
        raise EgressRejected("TLS identity not verified")
    if (observation.proxy_used is not False
        or type(observation.redirects_followed) is not int
        or observation.redirects_followed != 0):
        raise EgressRejected("Unreviewed proxy or redirect")
    if (type(observation.http_status) is not int
        or observation.http_status != 200):
        # In particular, no 3xx redirect may be followed or considered OK.
        raise EgressRejected("Unsupported upstream status")
    if (type(observation.response_body_bytes) is not int
        or not 0 <= observation.response_body_bytes <= _MAX_BODY_BYTES
        or type(observation.elapsed_ms) is not int
        or not 0 <= observation.elapsed_ms <= _MAX_ELAPSED_MS):
        raise EgressRejected("Unbounded response or duration")
    # Crucially, do not expose a network transport or a transferable token.
    # Even a fabricated all-green observation is never a runtime permission.
    return OfflineTransportReview(
        capability_id=expected.capability_id,
        peer_ip=observation.connected_peer_ip,
        body_limit_bytes=_MAX_BODY_BYTES,
        elapsed_limit_ms=_MAX_ELAPSED_MS,
    )


def send_live_network(*_args: object, **_kwargs: object) -> None:
    """Explicit denial: real IP-pinned TLS egress is not integrated."""
    DisabledNetworkTransport().send(None)  # type: ignore[arg-type]
