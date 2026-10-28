"""Negative SSRF tests for an inspection-only egress capability.

No DNS lookup, socket, HTTP client, provider SDK or external network used.
"""
from __future__ import annotations

import unittest

from agentshield.demo_invoice import INVOICE, demo_rule_records
from agentshield.egress_policy import (
    DisabledNetworkTransport, EgressCapability, EgressRejected,
    _LOCAL_INVOICE_CAPABILITY, inspect_egress,
)
from agentshield.policy import PolicyEngine, Principal, ToolAction

BASE = _LOCAL_INVOICE_CAPABILITY.url
PUBLIC = ("8.8.8.8", "2001:4860:4860::8888")


class OfflineEgressSafetyTests(unittest.TestCase):
    def setUp(self):
        self.actor = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        self.engine = PolicyEngine(demo_rule_records(self.actor))

    def check(self, **kwargs):
        return inspect_egress(
            self.actor, INVOICE, self.engine,
            candidate_url=kwargs.get("url", BASE),
            resolved_addresses=kwargs.get("addresses", PUBLIC),
            redirect_url=kwargs.get("redirect"),
            next_addresses=kwargs.get("next_addresses"),
        )

    def test_exact_reviewed_target_is_inspection_only(self):
        result = self.check()
        self.assertEqual(result.capability_id, "demo-invoice-read-v1")
        self.assertEqual(result.hostname, "api.invoices.example")
        self.assertEqual(result.address_count, 2)
        self.assertFalse(result.network_enabled)
        self.assertFalse(result.transport_pinned)
        self.assertFalse(result.execution_authorized)
        with self.assertRaises(EgressRejected):
            DisabledNetworkTransport().send(result)

    def test_ip_literally_known_ssrf_targets_all_denied(self):
        for addr in (
            "127.0.0.1", "0.0.0.0", "10.1.2.3", "172.16.4.5",
            "192.168.1.1", "169.254.169.254", "100.64.0.1",
            "192.0.2.10", "198.51.100.2", "203.0.113.5",
            "224.0.0.1", "255.255.255.255",
            "::1", "::", "fe80::1", "fc00::1",
            "::ffff:127.0.0.1", "::ffff:8.8.8.8",
            "2001:db8::1", "fe80::1%eth0",
        ):
            with self.subTest(ip=addr), self.assertRaises(EgressRejected):
                self.check(addresses=(addr,))

    def test_mixed_dns_results_fail_even_when_one_address_public(self):
        for addresses in (
            ("8.8.8.8", "127.0.0.1"),
            ("1.1.1.1", "169.254.169.254"),
            ("2606:4700:4700::1111", "fc00::1"),
            (),
            ("8.8.8.8",) * 9,
            ("not-an-ip",),
            ("8.8.8.8", "8.8.8.8", "127.0.0.1"),
        ):
            with self.subTest(addresses=addresses), self.assertRaises(EgressRejected):
                self.check(addresses=addresses)
        self.assertEqual(self.check(addresses=["8.8.8.8", "8.8.8.8"]).address_count, 1)

    def test_url_aliases_and_normalization_attempts_are_rejected(self):
        for url in (
            "http://api.invoices.example/v1/invoices/42",
            "https://api.invoices.example:443/v1/invoices/42",
            "https://API.INVOICES.EXAMPLE/v1/invoices/42",
            "https://api.invoices.example./v1/invoices/42",
            "https://api.invoices.example.evil.test/v1/invoices/42",
            "https://api.invoices.example@127.0.0.1/v1/invoices/42",
            "https://user:pass@api.invoices.example/v1/invoices/42",
            "https://127.0.0.1/v1/invoices/42",
            "https://2130706433/v1/invoices/42",
            "https://[::1]/v1/invoices/42",
            "https://api.invoices.example/v1/invoices/43",
            "https://api.invoices.example/v1/invoices/42?url=http://127.0.0.1",
            "https://api.invoices.example/v1/invoices/42#redirect",
            "https://api.invoices.example/%2e%2e/v1/invoices/42",
            "https://api.invoices.example/v1/invoices/42\r\nHost:127.0.0.1",
            "https://api.invoices.example\\@evil.test/v1/invoices/42",
            " https://api.invoices.example/v1/invoices/42",
        ):
            with self.subTest(url=url), self.assertRaises(EgressRejected):
                self.check(url=url)

    def test_all_redirects_disabled_including_same_origin(self):
        for redirect in (
            BASE, "https://api.invoices.example/v1/invoices/43",
            "http://localhost/admin", "https://example.org/",
        ):
            with self.subTest(redirect=redirect), self.assertRaises(EgressRejected):
                self.check(redirect=redirect)

    def test_rebinding_or_dns_answer_mutation_fail_closed(self):
        for later in (
            ("127.0.0.1",),
            ("8.8.8.8",),
            ("8.8.8.8", "1.1.1.1"),
            ("8.8.8.8", "169.254.169.254"),
        ):
            with self.subTest(later=later), self.assertRaises(EgressRejected):
                self.check(next_addresses=later)
        self.assertEqual(self.check(next_addresses=PUBLIC).address_count, 2)

    def test_signed_scope_and_exact_policy_required_even_for_preview(self):
        bad_actor = Principal("ci_local:local-demo-agent", frozenset())
        with self.assertRaises(EgressRejected):
            inspect_egress(
                bad_actor, INVOICE, self.engine,
                candidate_url=BASE, resolved_addresses=PUBLIC,
            )
        with self.assertRaises(EgressRejected):
            self.check(url=BASE, addresses=("8.8.8.8",), redirect=BASE)
        with self.assertRaises(EgressRejected):
            inspect_egress(
                self.actor, ToolAction("suppliers", "update_bank_account", "supplier/482"),
                self.engine, candidate_url=BASE, resolved_addresses=PUBLIC,
            )
        foreign = Principal("ci_local:another-agent", frozenset({"invoice:read"}))
        with self.assertRaises(EgressRejected):
            inspect_egress(
                foreign, INVOICE, self.engine,
                candidate_url=BASE, resolved_addresses=PUBLIC,
            )

    def test_unreviewed_capability_configuration_rejected(self):
        known = _LOCAL_INVOICE_CAPABILITY
        for host in ("127.0.0.1", ".api.example.com", "api.example.com.",
                     "api..example.com", "api_example.com", "evil"):
            with self.subTest(host=host), self.assertRaises(EgressRejected):
                EgressCapability(
                    "bad-cap", known.action_digest, "GET", "https",
                    host, known.path, 443,
                )
        with self.assertRaises(EgressRejected):
            EgressCapability(
                "bad-cap", known.action_digest, "POST", "https",
                known.host, known.path, 443,
            )
        with self.assertRaises(EgressRejected):
            EgressCapability(
                "bad-cap", known.action_digest, "GET", "http",
                known.host, known.path, 80,
            )


if __name__ == "__main__":
    unittest.main()
