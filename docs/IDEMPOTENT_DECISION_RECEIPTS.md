# Durable local idempotent decisions — P0 issue #3

**Status: local-only security proof. No deployed/public execution gateway, production tenant onboarding, real tool side effect, remote Cloudflare D1 or blockchain transaction.**

## RAIDER: reuse canonical policy, signed identity, existing D1 audit

The new `POST /_local/idempotent-decisions` requires the **existing ES256-signed AGENT** identity and accepts only four bounded fields: `tool`, `operation`, `resource` and an opaque 16–96-character `request_id`. No caller-provided scopes, tenant, policy, version, arbitrary arguments, or desired authorization.

The existing `D1PolicyRegistry` chooses and SHA-validates the active immutable policy of the JWT tenant. `PolicyEngine` evaluates the action. The new `decision_requests` table (migration `0006`) retains an **immutable, tenant-scoped, request-id keyed decision receipt** bound by SHA-256 to principal, signed scopes, exact action, policy version and digest, plus active-policy activation timestamp and marker.

A D1/SQLite **single atomic batch** conditionally creates that receipt **only if the same policy generation is still active**, and inserts the redacted canonical `AuditEvent` for the winning receipt only. A repeated request uses the existing receipt and verifies its corresponding immutable audit fingerprint via the existing `AuditRepository`. A lost response after commit can be retried without another event. A concurrent loser cannot overwrite the winner's receipt or create an audit event for a different candidate.

On a repeated `request_id`:
- If the **same actor, scopes, exact action and policy generation** are still active and the receipt plus audit are intact, return the original `event_id`, decision and policy digest with `replayed:true`.
- If **any** of those dimensions changed—including V1→V2→V1 reactivation—or the 30-day receipt window expired, fail with HTTP **409**. A reused key is not a fresh authorization attempt.
- If the policy is corrupted or absent, D1/audit unavailable or stored evidence inconsistent, fail with HTTP **503** rather than returning a cached `allow`.
- The local-only route is hidden with HTTP **404** outside the local smoke environment. Signed operators are not agents. Public `/v1/idempotent-decisions` does not exist.

The response ALWAYS contains `execution_authorized:false`, `executed:false`, `enforcement_ready:false`. The decision is informational, **not a permit or a tool capability**, and the new receipt is deliberately not a durable command/outbox for external I/O. The existing `/_local/test-executions` adapter is unchanged and remains synthetic.

## Tests and limits

SQLite regressions cover exact repeated requests producing **one** receipt and audit row, changed resource/operation, different signed scope or principal, separate request keys, missing tenant policy, live V1→V2 and V2→V1 activation, a change during the database CAS, actual audit-insert failure rolling back the receipt, deletion of an existing audit row, expiration and immutable-record triggers. The real local Cloudflare Worker/Pyodide/D1 test repeats an agent request after audited V2 activation, verifies the **same** event ID on retry, and rejects changed actions, changed signed scopes, invalid/operator JWTs, forged policy version and public routing.

**Important limitations:** the audit and receipts remain in the same D1 trust domain; they are not independently anchored on an EVM chain. The 30-day window is bounded, but production needs a reviewed archival/retention and reuse policy before garbage collection. No global rate limiting, abuse throttling, resource quotas, real-tool idempotency, distributed exactly-once side effects, retry-after-crash outbox reconciliation, or independent penetration test is claimed. Cloudflare's runtime remains platform-managed. The verified local policy is not a production signed customer policy.

This implementation only reduces ambiguity and duplicate audit decisions **before** a real external execution boundary is introduced. No release or deployment is authorized.
