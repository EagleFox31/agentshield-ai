# ADR-0001 — FastAPI security gateway as the first enforcement interface

- **Date:** 2026-10-26
- **Status:** Accepted for MVP
- **Decision owner:** AgentShield AI
- **Supersedes:** no previous ADR

## Context
The current Python PolicyEngine can return allow, deny and require_approval but does not authenticate clients, handle HTTP, or execute tools. Autonomous tool calls must be intercepted **before** execution. A framework-agnostic domain core is already present and must not be replaced by a new platform-specific engine.

## Decision
Use FastAPI as an ASGI **control/enforcement gateway** with versioned `/v1/` routes. Verify the authenticated caller first, construct the Principal from trusted token claims, normalize the target operation and resource, evaluate the existing PolicyEngine, and persist an audit decision **before** an enforcement authorization is returned. The gateway **does not execute arbitrary tools** in MVP. Only a separately authorized test adapter may consume an ALLOW outcome, and it must bind authorization to the same request digest, scopes and expiry. `REQUIRE_APPROVAL` never authorizes execution without a later single-use grant and policy re-evaluation.

## Alternatives
- MCP proxy: important follow-up but a larger and more complex transport surface.
- Embedded Python SDK: easy integration but by itself can be bypassed.
- TypeScript rewrite: unnecessary duplication of the existing Python policy core.

## Consequences and proof
Separate the pure PolicyEngine from FastAPI, auth, D1 and EVM adapters. Version the JSON envelope and error codes; no raw internal exceptions. Tests: health, schema, policy ordering, untrusted identity fields, duplicate request IDs, adapter bypass. The security guarantee applies only to tool calls **routed through this gateway**.

## References
- [Cloudflare FastAPI Workers support](https://developers.cloudflare.com/workers/languages/python/packages/fastapi/)
- [MVP scope](../MVP_SCOPE.md)
