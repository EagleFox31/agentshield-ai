# ADR-0004 — Human approvals through dashboard and CLI

- **Date:** 2026-10-26
- **Status:** Accepted for MVP

## Context
Some tool actions may be legitimate but high-impact. Approval must not be a reusable permission grant or a social-engineering shortcut.

## Decision
Expose the **same authenticated approval service** through (1) a minimal dashboard and (2) a developer CLI. Store pending requests with an **exact canonical action digest**, effective actor/scopes, trusted user-intent reference, policy version, creation time and bounded expiry. Only specifically authorized human approvers may accept or reject. Approval transitions are atomic and replay-safe, with a unique request/grant ID; one-time grants cannot be applied to a changed tool/resource/arguments/user or after expiry. Re-evaluate the effective policy and delegated scope before release; an explicit deny cannot be overridden even by an approver.

For the MVP, approval grants authorize a **controlled test adapter** only. Notification integration via Telegram/WhatsApp is deferred; messages are not independently trusted approval channels.

## Alternatives
- CLI-only: smaller UI but not sufficient for demonstration and human review.
- Messaging approvals: useful later through trusted adapters; introduces phishing and identity challenges.

## Failure modes / tests
Expired, replayed, revoked, concurrent, cross-tenant and mismatched approvals must not authorize execution; unavailable persistence or authentication causes denial, not fallback allow.

## References
- [MVP scope](../MVP_SCOPE.md)
