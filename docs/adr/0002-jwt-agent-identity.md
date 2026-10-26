# ADR-0002 — Short-lived asymmetrically signed JWT identity

- **Date:** 2026-10-26
- **Status:** Accepted for MVP

## Context
Model output and untrusted documents may forge agent names or permissions. The service must establish **agent and delegating user/tenant identity from a trusted issuer**, not from action JSON.

## Decision
Use short-lived signed JWT access tokens with an explicit trusted issuer. Verify **signature**, pinned algorithm allowlist, `kid` in a trusted key set, `iss`, **AgentShield-specific `aud`**, `sub`, `exp`, `nbf`, `iat`, bounded `jti`, principal/tenant context and granted scopes. Reject expired, wrong-audience, unsigned, unknown-key, untrusted-issuer or malformed tokens. Never accept an algorithm supplied solely by token content or silently fall back to HS256. Signer keys are independent of LLM/agent text, rotate safely and stay outside Git. Prefer established JOSE implementation that passes an actual Python Workers compatibility smoke test; do not write cryptographic primitives from scratch.

Use separate human/operator authentication for dashboard and approval decisions. A model may request an action, but cannot mint its own delegated privileges. Explicitly document token invalidation windows and jti replay controls for privileged actions. MVP can use a controlled development issuer for fixtures; a production issuer is not part of this ADR's completion.

## Alternatives
- Static API keys: simpler but weak on delegation and TTL.
- mTLS: stronger workload binding for some environments, but heavier for initial clients.

## Security tests
Token expiry, issuer/audience mismatch, key rotation, algorithm confusion, cross-tenant substitution, tampered claims and model-supplied fake identity must all fail closed.

## References
- [MVP scope](../MVP_SCOPE.md)
