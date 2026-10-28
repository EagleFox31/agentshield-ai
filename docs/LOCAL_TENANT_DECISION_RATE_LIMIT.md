# Local tenant decision rate limit — issue #3 (P0)

**Scope:** a bounded LOCAL-only admission gate for the existing signed, non-executing `/_local/idempotent-decisions` endpoint. This is **not** a public, distributed gateway rate limiter, WAF or network I/O defense.

## RAIDER implementation

Reuse the immutable `decision_requests` receipt (migration 0006), existing `AuditEvent`, `D1ApprovalStore.atomic` (Cloudflare D1 batch transaction) and signed JWT tenant ID. Migration `0007_tenant_decision_quota.sql` adds an immutable admission slot keyed by `(tenant_id, request_id)` with an indexed `(tenant_id, window_start_ms)` window.

For this local proof, the fixed, non-client-configurable quota is **16 new requests per tenant per 60-second fixed wall-clock window**, shared across all agents of the signed tenant. It counts *all* new requests, including deterministic denials, so an attacker cannot bypass accounting by requesting prohibited actions. The server computes the window from its own clock, never from the request JSON or untrusted LLM text.

For every authenticated request, one D1/SQLite transaction:
1. Conditionally reserves a tenant/window/request slot only if no immutable decision receipt already exists and the window holds fewer than 16 slots. A database uniqueness constraint ensures a request ID can never acquire two slots.
2. Creates the immutable decision receipt only when the new request owns a slot **in that window**, and only when the expected active policy version and activation marker still match.
3. Inserts the canonical redacted audit event for the winning receipt only. D1 batch/SQLite transaction rollback removes the admission and receipt on any failed audit.

The post-transaction read verifies the receipt and its audit, including agent, scopes, action and policy generation. A first-time request beyond the cap has **no** receipt or event and gets HTTP **429** with `Retry-After: 60`. A **true identical replay** returns the original validated event and `replayed:true` without consuming another slot, even if all 16 slots are occupied. A reused key with a different agent, action, scope or policy generation still receives 409 and cannot exploit the retry exemption.

All other routes, including the previously existing demo approval and synthetic adapter routes, are unchanged. No global WAF, rate limiting of unauthenticated JWT attempts, per-IP controls, distributed edge throttling, tenant billing, remote D1, real tool calls or blockchain anchoring is implied.

## CI evidence and limitations

Tests cover 16 admitted requests, rejection of the 17th, retry after saturation, denied-policy requests consuming slots, two signed principals sharing the tenant allowance, an independent tenant's allowance, the next clock window, SQL audit failure rolling back the slot, and immutable admission rows. The existing Pyodide+local D1 signed JWT regression additionally fills the local quota, checks HTTP 429/Retry-After and allows a validated original replay without increment.

**Release blockers:** production must set approved quotas (not the synthetic 16/min), harden the edge against credential brute force and traffic spikes, add reviewed abuse telemetry and storage retention for immutable decision/admission records, and test concurrency under production-like D1 latency. The current append-only slots deliberately have **no unreviewed automatic deletion**; production retention/archival must not violate the 30-day receipt replay contract. The wall-clock fixed window can burst at boundaries and may be affected by clock skew. Rate-limit rejection is not currently separately persisted as a security event; a production security monitor needs a bounded, non-PII abuse summary.

**No hosted enforcement, external provider, real tool or EVM transaction. Issue #3 remains open.**
