# Local transactional command outbox — issue #3 P0

**EXPERIMENTAL AND LOCAL ONLY. No real tool execution, external SDK, network dispatch, Cloudflare deployment, public endpoint, remote D1, or EVM anchoring.**

## RAIDER design

This reuses the native ES256 agent/operator JWT separation, immutable tenant policy snapshots, D1 policy generation marker, the **existing idempotent decision receipt and its audit**, the existing quota, the `D1ApprovalStore.atomic` transaction, and the canonical `AuditEvent` schema. It does **not** build a second PolicyEngine, a new queue service or a hosted worker.

Migration `0008_local_command_outbox.sql` adds a tenant/request-bound outbox row and append-only queue/claim/reconciliation audit IDs. An agent can only queue **the existing synthetic `INVOICE` read**; there is no input for a tool URL, payload, arbitrary action, supplier mutation, policy override or model call.

### Local state machine

- **`queued`**: a signed agent's exact request ID must have a validated current-policy **ALLOW** decision with a stored canonical audit, or be created through the existing idempotent decision pipeline. The outbox entry and its own queue audit are then written in **one D1 transaction**. Retrying the same signed request ID returns the original command, original decision event and original queue audit, with no extra quota. A changed identity, signed scopes or policy generation still fails.
- **`claimed`**: only an independently signed operator with `commands:claim` may atomically claim an existing **queued** command while the same policy generation remains active. The transaction conditionally advances the state once, records a fresh unguessable fencing token *internally* and appends an audited operator claim. The claim token is not exposed in HTTP responses. A second claim fails. **There is no executor attached.**
- **`uncertain`**: an operator with `commands:reconcile` can simulate an interrupted claim by recording an audited irreversible uncertainty transition. Neither the claim nor this simulated recovery calls an external tool. The database forbids returning to `queued`; a retry can never silently dispatch again.

Every state transition has a unique redacted audit event; the original event linked to the idempotent decision remains immutable. SQL triggers prohibit deleting a command, modifying its tenant/action/policy binding, or moving backward through the state machine. Failed audit insertion rolls back the entire matching command state change.

### Guarantees and omissions

- Tests prove a lost HTTP response after queue commit can be retried without another command; two claim attempts cannot both succeed; corrupt/missing audit prevents claiming; the signed operator is tenant-scoped; policy V1→V2 invalidates unclaimed V1; and a claimed command cannot be silently requeued or redelivered after an interrupted local simulation.
- This is a **non-dispatching command ledger**, not a production transactional outbox runner. A *real* executor needs an explicit capability boundary, signed policy freshness, exact-action and optional human approval, a separate durable worker/lease design, bounded attempts, a provider idempotency key when available, reconciliation of outcomes after a crash, SSRF restrictions, per-tenant quotas and an independent security review.
- Neither D1 nor any other local database can atomically commit a real third-party side effect. We deliberately **do not promise exactly-once external execution**. Claims remain blocked until a separately designed, authenticated reconciliation procedure is approved.
- There is no automatic TTL/cleanup for outbox records; manual archival and retention rules must preserve the 30-day decision audit evidence and any eventual anchored Merkle commitment. There is no on-chain proof yet.

**No production release, real tool side effect, SaaS enforcement or blockchain transaction was authorized by this work.**
