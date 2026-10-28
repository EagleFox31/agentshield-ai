"""Adversarial tests for offline peer-bound/TLS egress contract.

Only synthetic observations are inspected. NO DNS resolution or HTTP I/O.
"""
from __future__ import annotations

from dataclasses import replace
import unittest

from agentshield.bound_transport_contract import (
    SyntheticTransportObservation, inspect_synthetic_transport,
    send_live_network,
)
from agentshield.demo_invoice import INVOICE, demo_rule_records
from agentshield.egress_policy import EgressRejected, _LOCAL_INVOICE_CAPABILITY
from agentshield.policy import PolicyEngine, Principal, ToolAction

BASE = _LOCAL_INVOICE_CAPABILITY.url
DNS = ("8.8.8.8", "1.1.1.1")


def valid_observation() -> SyntheticTransportObservation:
    return SyntheticTransportObservation(
        selected_ip="8.8.8.8", connected_peer_ip="8.8.8.8",
        target_host="api.invoices.example",
        tls_sni="api.invoices.example",
        certificate_host="api.invoices.example",
        certificate_chain_verified=True,
        certificate_hostname_verified=True,
        tls_version="TLSv1.3", method="GET", observed_url=BASE,
        proxy_used=False, redirects_followed=0, http_status=200,
        response_body_bytes=128, elapsed_ms=100,
    )


class BoundedTransportContractTests(unittest.TestCase):
    def setUp(self):
        self.actor = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        self.engine = PolicyEngine(demo_rule_records(self.actor))

    def validate(self, observation=None, *, addresses=DNS, actor=None, action=None):
        return inspect_synthetic_transport(
            actor or self.actor, action or INVOICE, self.engine,
            candidate_url=BASE, dns_answers=addresses,
            observation=observation or valid_observation(),
        )

    def test_clean_fixture_never_authorizes_network_or_dispatch(self):
        result = self.validate()
        self.assertEqual(result.capability_id, "demo-invoice-read-v1")
        self.assertEqual(result.peer_ip, "8.8.8.8")
        self.assertEqual(result.body_limit_bytes, 16_384)
        self.assertEqual(result.elapsed_limit_ms, 2_000)
        self.assertTrue(result.simulation_only)
        self.assertFalse(result.network_enabled)
        self.assertFalse(result.transport_attested)
        self.assertFalse(result.execution_authorized)
        with self.assertRaises(EgressRejected):
            send_live_network(result)

    def test_dns_rebinding_to_nonpreflight_peer_fails(self):
        base = valid_observation()
        for change in (
            {"connected_peer_ip": "127.0.0.1"},
            {"connected_peer_ip": "169.254.169.254"},
            {"connected_peer_ip": "1.1.1.1"},
            {"selected_ip": "127.0.0.1", "connected_peer_ip": "127.0.0.1"},
            {"selected_ip": "9.9.9.9", "connected_peer_ip": "9.9.9.9"},
        ):
            with self.subTest(change=change), self.assertRaises(EgressRejected):
                self.validate(replace(base, **change))
        with self.assertRaises(EgressRejected):
            self.validate(base, addresses=("1.1.1.1",))
        with self.assertRaises(EgressRejected):
            self.validate(base, addresses=("8.8.8.8", "169.254.169.254"))

    def test_tls_sni_and_certificate_must_match_original_host(self):
        base = valid_observation()
        for change in (
            {"tls_sni": "evil.example"},
            {"certificate_host": "evil.example"},
            {"target_host": "evil.example"},
            {"certificate_chain_verified": False},
            {"certificate_hostname_verified": False},
            {"certificate_chain_verified": "true"},
            {"certificate_hostname_verified": 1},
            {"tls_version": "TLSv1.2"},
            {"tls_version": ""},
        ):
            with self.subTest(change=change), self.assertRaises(EgressRejected):
                self.validate(replace(base, **change))

    def test_proxy_redirect_method_and_url_changes_fail(self):
        base = valid_observation()
        for change in (
            {"proxy_used": True},
            {"proxy_used": 1},
            {"redirects_followed": 1},
            {"redirects_followed": True},
            {"redirects_followed": -1},
            {"method": "POST"},
            {"observed_url": "https://api.invoices.example/v1/invoices/43"},
            {"observed_url": "http://169.254.169.254/"},
            {"http_status": 302},
            {"http_status": 301},
            {"http_status": 307},
            {"http_status": 500},
            {"http_status": True},
        ):
            with self.subTest(change=change), self.assertRaises(EgressRejected):
                self.validate(replace(base, **change))

    def test_response_size_and_duration_are_bounded(self):
        base = valid_observation()
        for change in (
            {"response_body_bytes": 16_385},
            {"response_body_bytes": -1},
            {"response_body_bytes": True},
            {"elapsed_ms": 2_001},
            {"elapsed_ms": -1},
            {"elapsed_ms": False},
        ):
            with self.subTest(change=change), self.assertRaises(EgressRejected):
                self.validate(replace(base, **change))
        result = self.validate(replace(
            base, response_body_bytes=16_384, elapsed_ms=2_000,
        ))
        self.assertTrue(result.simulation_only)

    def test_wrong_action_or_scope_fail_even_for_perfect_tls_fixture(self):
        with self.assertRaises(EgressRejected):
            self.validate(actor=Principal(self.actor.id, frozenset()))
        with self.assertRaises(EgressRejected):
            self.validate(action=ToolAction(
                "suppliers", "update_bank_account", "supplier/482",
            ))
        with self.assertRaises(EgressRejected):
            self.validate(actor=Principal(
                "ci_local:different-agent", frozenset({"invoice:read"}),
            ))

    def test_untrusted_fixture_cannot_be_substituted_for_attestation(self):
        with self.assertRaises(EgressRejected):
            inspect_synthetic_transport(
                self.actor, INVOICE, self.engine,
                candidate_url=BASE, dns_answers=DNS,
                observation={"tls_sni": "api.invoices.example"},  # type: ignore[arg-type]
            )
        # A fake verifier that reports all-green booleans is still only a
        # fixture; no cryptographic TLS / remote peer attestation is claimed.
        good = self.validate()
        self.assertFalse(good.transport_attested)
        self.assertFalse(good.execution_authorized)


if __name__ == "__main__":
    unittest.main()
