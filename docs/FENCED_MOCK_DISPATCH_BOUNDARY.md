# Fenced synthetic command dispatch — issue #3 P0

**Experimental, local-only proof. Not a public or production-grade tool gateway. No external network calls, real supplier mutation, remote D1, deployment or blockchain transaction.**

## RAIDER architecture

Reuses the established **ES256 AGENT versus OPERATOR trust roots**, tenant-scoped immutable policy registry, canonical SHA-256 action and request fingerprints, audited idempotent decisions, outbox `queued → claimed → uncertain` state machine and D1 batch transactions. There is exactly one executable in-memory action: the existing `LocalDryRunAdapter.invoke(INVOICE)`, which reads a synthetic fixture, not a provider.

The outbox queue is created by the signed original agent, and a **different signed operator** with `commands:claim` must atomically claim it. Neither act triggers a tool. New `POST /_local/commands/{command_id}/dry-run` requires the **original signed agent**, not an operator, to request a one-shot synthetic invocation **after** the operator claim. No client-selected tool, URL, host, arguments, policy, tenant, scopes, claim token or arbitrary code can enter this API.

Before any mock invocation, the dispatcher checks:

1. The outbox is currently `claimed`, and the caller's principal is the exact signed original actor.
2. The claim's internal, unreturned fence token and claim audit ID exist.
3. The policy is still active, including exact **version, SHA-256, activation timestamp and activation marker**, and the current `PolicyEngine` evaluates `INVOICE` to explicit `allow` for the **current signed scopes**.
4. The immutable original `decision_requests` fingerprint recomputed from **this JWT** and the stored policy generation matches; the decision is still inside its retention window.
5. The original decision, queue audit and independent operator-claim audit exist in the same signed tenant, with the exact action digest and expected reason codes.

Only then, **in one D1/SQLite transaction**, the system inserts an immutable `local_mock_dispatch_reservations` row keyed by `(tenant_id, command_id)` and its corresponding canonical redacted audit event. A duplicate loses the insert race, cannot satisfy the freshly generated reservation ID and fails. If audit insertion fails, the reservation rolls back, so no mock runs. If the policy changes before the final re-read, the reservation stays consumed but the mock is not invoked—**fail closed**, not automatic retry.

Only after the unique dispatch reservation and its audit have been verified does the gateway invoke the existing local fixture reader. It never exposes the fence token and always returns `real_tool_called:false`, `executed:false`, `enforcement_ready:false`.

## Failure and recovery semantics

The stored reservation is durable **before** invoking the local mock. If the process crashes immediately afterward, **zero** mock invocations may have occurred, but the command remains permanently spent and cannot be redispatched. This is a deliberate **at-most-once synthetic invocation** guarantee, not exactly-once execution. A real network-capable adapter would need a provider-side idempotency key, bounded worker claims, reconciliation of ambiguous outcomes, secure URL/DNS/redirect handling, and an independently reviewed action capability/egress architecture before release.

Tests cover missing operator claim, changed actor/scopes/tenant, stale policy generation, missing canonical decision/queue/claim audit, failed dispatch-audit writes, one immutable reservation, replays, irreversible `uncertain` states and post-reservation simulated crashes. The real Pyodide/D1 signed JWT smoke proves the same local boundary and ensures the public `/v1/commands/{id}/dry-run` does not exist.

**Blockchain placement:** command, claim and mock-dispatch audit events can later be batched as Merkle leaves and separately anchored to EVM. No chain transaction is performed by this feature. Blockchain integrity evidence never substitutes for policy/approval enforcement.
