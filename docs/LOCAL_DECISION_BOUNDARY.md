# Authenticated decision boundary — local-only P0 milestone

**Scope:** issue #3 incremental implementation; no deployed/public tool gateway and no execution adapter.

The experimental `POST /_local/decisions` is only accessible with the `LOCAL_SMOKE_ENABLED=true` binding; the existing local-mode middleware suppresses it with HTTP 404 otherwise. A real ES256-signed agent bearer token authenticates the principal and scopes. The endpoint accepts **only** the exact bounded `tool`, `operation`, and `resource` fields, never an identity, scope, dynamic policy, argument payload or requested effect.

## Existing components reused (RAIDER)

- `approval_api._identity(request, "AGENT")` checks the existing signed agent JWKS and denies wrong issuer/algorithm/signature. An operator token is **not** accepted as an agent token.
- `demo_invoice._rules` supplies one **shared** synthetic policy for the invoice read and supplier mutation, now returning `require_approval` for a correctly scoped supplier mutation. The human approval API shares the same rules (no second PolicyEngine).
- `audit_service.decide_and_audit` evaluates the policy and writes an `AuditEvent` through the existing `D1AuditRepository` with 30-day bounded retention, canonical action SHA-256, caller-bound identity and policy version. No prompts, bank details or arbitrary tool arguments are persisted. A missing or failing D1 binding produces HTTP 503 — no permit.
- Every response contains a new audit event ID and trace digest. **The `allow` effect is informational**, not a capability or permission to invoke any external tool. The response therefore always reports `execution_authorized:false`, `executed:false` and `enforcement_ready:false`.

## Local acceptance and adversarial evidence

- CPython HTTP-contract tests: read `allow`, supplier write without scope `deny`, supplier write with signed `supplier:write` `require_approval`, unknown cloud tool `deny`, malformed/forged body `422`, audit failure `503`, disabled route `404`, missing D1 `503`.
- Real Cloudflare Worker/Pyodide + local D1 CI signs throwaway agent JWTs and asserts all three effects are **persisted first**, no tool call occurs, missing or invalid bearer is HTTP 401, spoofed JSON scope is HTTP 422 and public `POST /v1/decisions` remains absent (HTTP 404).
- The prior offline invoice prompt-injection demo, exact-action human approval mock and deterministic Merkle evidence suite remain unchanged except that both approval and demo now share one rule definition.

## Remaining blockers before closing issue #3

A **public** `POST /v1/decisions` requires versioned, tenant-verified policy storage, requests with idempotency/replay control, bounded normalization of real action arguments, rate limiting, audit-idempotent decision responses and identity/tenant-specific read APIs. Most importantly, a **non-bypassable and constrained tool execution adapter** must reevaluate authorization, consume exact-action approval once, enforce capability TTL/scopes, and refuse execution on any missing audit or resource restriction. Network-accessing tools need SSRF safeguards (redirect, DNS rebinding, private IP blocks). Independent security review and no deployment remain separate gates.

The blockchain will enter **after** durable events exist, by batching their cryptographic digests into Merkle commitments and (only upon separate approval) optionally anchoring a commitment to an EVM testnet. It cannot replace deny/approval evaluation or audit-before-execution checks.

**No actual external action, paid AI model, blockchain transaction, cloud deployment or real D1 resource is invoked.**
