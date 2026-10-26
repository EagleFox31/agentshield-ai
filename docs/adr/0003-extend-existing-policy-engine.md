# ADR-0003 — Evolve the existing deterministic policy core

- **Date:** 2026-10-26
- **Status:** Accepted for MVP

## Context
`src/agentshield/policy.py` already implements exact-match policies with **explicit deny > required human approval > explicit allow** and default-deny. Rewriting this in a separate rules engine at this stage adds migration and assurance work without closing the immediate enforcement gap.

## Decision
Retain and extend the current Python PolicyEngine. Introduce versioned, schema-validated policy declarations, canonical action envelopes, tested scope/resource semantics and independent policy storage. Unknown tools, invalid policy, invalid resource, missing scopes, unavailable validation and ambiguous rules **deny**. A high-risk action must not be downgraded to allow by new lower-priority rules, AI scores or approval UI.

Make the policy interface replaceable through a provider contract so Casbin/OPA can later be evaluated under RAIDER Adopt/Adapt/Build review. Do not treat approximate matching or wildcard syntax as supported until formally specified and regression-tested.

## Alternatives
- Casbin: potential RBAC/ABAC integration with an added rules-language and adapter surface.
- Open Policy Agent: powerful policies, additional runtime/distribution complexity.

## Acceptance
Property and adversarial tests enforce precedence, idempotence, no privilege amplification and deterministic results across contexts. No UI, AI or persistence adapter may mutate the decision after the deterministic gate.

## References
- [Policy core](../../src/agentshield/policy.py)
- [MVP scope](../MVP_SCOPE.md)
