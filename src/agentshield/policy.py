"""Policy-first, fail-closed decisions for proposed AI agent tool calls.

The caller MUST authenticate the principal independently of the agent/model
payload. This pure engine does not execute tools, approve requests, call LLMs,
write logs or interact with blockchains.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Sequence


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Principal:
    id: str
    scopes: FrozenSet[str]

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("Authenticated principal id cannot be empty")
        if any(not scope or not scope.strip() for scope in self.scopes):
            raise ValueError("Scopes must be non-empty")


@dataclass(frozen=True)
class ToolAction:
    tool: str
    operation: str
    resource: str

    def __post_init__(self) -> None:
        if any(not value or not value.strip()
               for value in (self.tool, self.operation, self.resource)):
            raise ValueError("Tool, operation and resource must be non-empty")


@dataclass(frozen=True)
class Rule:
    id: str
    principal_id: str
    tool: str
    operation: str
    resource: str
    required_scope: str
    effect: Effect

    def __post_init__(self) -> None:
        if any(not value or not value.strip() for value in (
                self.id, self.principal_id, self.tool,
                self.operation, self.resource, self.required_scope)):
            raise ValueError("Rules require explicit, non-empty identities, actions, resources and scope")
        if not isinstance(self.effect, Effect):
            raise ValueError("Rule effect must be an Effect enum")

    def matches(self, principal: Principal, action: ToolAction) -> bool:
        return (
            self.principal_id == principal.id
            and self.tool == action.tool
            and self.operation == action.operation
            and self.resource == action.resource
        )


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reasons: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]


class PolicyEngine:
    """Exact-match policy v0: explicit deny > approval > allow.

    Scope checks precede permitting decisions. No implicit glob/wildcard
    matching is permitted, avoiding ambiguous resource-policy semantics.
    """

    def __init__(self, rules: Sequence[Rule]) -> None:
        self._rules = tuple(rules)
        rule_ids = [rule.id for rule in self._rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Policy rule IDs must be unique")

    def evaluate(self, principal: Principal, action: ToolAction) -> Decision:
        matching = [rule for rule in self._rules if rule.matches(principal, action)]
        if not matching:
            return Decision(Effect.DENY, ("NO_MATCHING_POLICY",), ())

        # An explicit deny is an unqualified block, even if the principal does
        # not hold the required scope listed on the denying rule.
        denies = [rule for rule in matching if rule.effect == Effect.DENY]
        if denies:
            return Decision(Effect.DENY, ("EXPLICIT_DENY",), tuple(r.id for r in denies))

        eligible = [rule for rule in matching if rule.required_scope in principal.scopes]
        if not eligible:
            return Decision(
                Effect.DENY, ("REQUIRED_SCOPE_MISSING",),
                tuple(rule.id for rule in matching)
            )

        approvals = [rule for rule in eligible if rule.effect == Effect.REQUIRE_APPROVAL]
        if approvals:
            return Decision(
                Effect.REQUIRE_APPROVAL, ("HUMAN_APPROVAL_REQUIRED",),
                tuple(rule.id for rule in approvals)
            )

        allows = [rule for rule in eligible if rule.effect == Effect.ALLOW]
        if allows:
            return Decision(
                Effect.ALLOW, ("EXPLICIT_ALLOW",),
                tuple(rule.id for rule in allows)
            )

        return Decision(Effect.DENY, ("NO_PERMITTING_POLICY",), ())
