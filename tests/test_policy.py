"""Regression tests for deterministic tool authorization.

No remote execution, external services or real credentials are used.
"""
import unittest

from agentshield.policy import Decision, Effect, PolicyEngine, Principal, Rule, ToolAction


class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.reader = Principal("invoice-agent", frozenset({"invoice:read"}))
        self.action = ToolAction("invoices", "read", "invoice/42")
        self.allow_rule = Rule(
            "invoice-read", "invoice-agent", "invoices", "read",
            "invoice/42", "invoice:read", Effect.ALLOW
        )

    def test_explicit_allow_for_exact_resource(self):
        decision = PolicyEngine([self.allow_rule]).evaluate(self.reader, self.action)
        self.assertEqual(decision.effect, Effect.ALLOW)
        self.assertEqual(decision.matched_rule_ids, ("invoice-read",))

    def test_unknown_tool_operation_resource_and_actor_are_denied(self):
        engine = PolicyEngine([self.allow_rule])
        for principal, action in (
            (self.reader, ToolAction("invoices", "write", "invoice/42")),
            (self.reader, ToolAction("invoices", "read", "invoice/43")),
            (self.reader, ToolAction("payments", "read", "invoice/42")),
            (Principal("other-agent", self.reader.scopes), self.action),
        ):
            with self.subTest(principal=principal, action=action):
                self.assertEqual(engine.evaluate(principal, action).effect, Effect.DENY)

    def test_required_scope_cannot_be_supplied_by_untrusted_action(self):
        missing_scope = Principal("invoice-agent", frozenset())
        decision = PolicyEngine([self.allow_rule]).evaluate(missing_scope, self.action)
        self.assertEqual(decision.effect, Effect.DENY)
        self.assertEqual(decision.reasons, ("REQUIRED_SCOPE_MISSING",))

    def test_explicit_deny_overrides_allows(self):
        block = Rule(
            "sensitive-block", "invoice-agent", "invoices", "read",
            "invoice/42", "admin:block", Effect.DENY
        )
        decision = PolicyEngine([self.allow_rule, block]).evaluate(self.reader, self.action)
        self.assertEqual(decision.effect, Effect.DENY)
        self.assertEqual(decision.matched_rule_ids, ("sensitive-block",))

    def test_human_approval_has_precedence_over_allow(self):
        approval = Rule(
            "review", "invoice-agent", "invoices", "read",
            "invoice/42", "invoice:read", Effect.REQUIRE_APPROVAL
        )
        decision = PolicyEngine([self.allow_rule, approval]).evaluate(self.reader, self.action)
        self.assertEqual(decision.effect, Effect.REQUIRE_APPROVAL)
        self.assertEqual(decision.reasons, ("HUMAN_APPROVAL_REQUIRED",))

    def test_approval_does_not_execute_tool(self):
        approval = Rule(
            "review", "invoice-agent", "invoices", "read",
            "invoice/42", "invoice:read", Effect.REQUIRE_APPROVAL
        )
        result = PolicyEngine([approval]).evaluate(self.reader, self.action)
        self.assertIsInstance(result, Decision)

    def test_duplicate_ids_and_invalid_types_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            PolicyEngine([self.allow_rule, self.allow_rule])
        with self.assertRaises(ValueError):
            Rule("bad", "invoice-agent", "invoices", "read", "invoice/42", "invoice:read", "allow")

    def test_blank_principal_or_resource_is_rejected(self):
        with self.assertRaises(ValueError):
            Principal("", frozenset())
        with self.assertRaises(ValueError):
            ToolAction("invoices", "", "invoice/42")
        with self.assertRaises(ValueError):
            ToolAction("invoices", "read", " ")

    def test_prompt_injection_cannot_extend_permissions(self):
        poisoned_action = ToolAction("suppliers", "update_bank_account", "supplier/482")
        self.assertEqual(PolicyEngine([self.allow_rule]).evaluate(self.reader, poisoned_action).effect, Effect.DENY)

    def test_repeated_evaluation_has_no_side_effects(self):
        engine = PolicyEngine([self.allow_rule])
        self.assertEqual(engine.evaluate(self.reader, self.action), engine.evaluate(self.reader, self.action))


if __name__ == "__main__":
    unittest.main()
