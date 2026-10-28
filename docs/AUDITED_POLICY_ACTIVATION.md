# Audited tenant policy activation — local-only security milestone

**Status:** experimental issue #3. No live tool execution, remote D1, paid model inference, public admin API or blockchain RPC.

## RAIDER: reuse existing state and proof primitives

The policy registry from PR #42 already stores **immutable** canonical JSON+SHA-256 snapshots in `policy_versions`, and an independently selected active version in `active_policy_versions`. PR #43 already ties exact-action approvals to the active version. This milestone adds only the missing *authorization and durable activation path*.

`POST /_local/policies/activate` requires a **native ES256 verified OPERATOR** JWT with a dedicated `policies:activate` scope; the agent JWT trust root cannot impersonate an operator. Input only contains `expected_version`, `target_version` and `target_sha256`. The tenant and operator ID come exclusively from the verified JWT. There is **no policy publication or SQL upload endpoint**: a target snapshot must already have been reviewed/published offline.

The service checks the current tenant snapshot using `D1PolicyRegistry`, the target's full canonical SHA-256 integrity using `parse_snapshot`, and rejects no-op or mismatched versions. A **single SQLite/D1 transaction** then:

1. Executes a compare-and-swap of the tenant's active version, conditional on the expected prior version, monotonic activation time, and exact target digest. It records an unpredictable activation marker in the pointer.
2. Inserts an immutable history record only if the pointer contains *that exact marker*.
3. Inserts a redacted `AuditEvent` only if that history record exists. Its actor is the signed human operator, its reason is `POLICY_VERSION_ACTIVATED`, its version is the target, and its canonical action digest cryptographically commits the tenant, old/new versions, target SHA and operator. No JWT, raw rules or personal data are stored in the audit event.

The service confirms history and the canonical audit fingerprint after commit. A stale compare-and-swap returns a conflict without creating an activation history or audit entry. A database error in the activation/audit batch rolls back the whole activation. The history has database-level update/delete rejection triggers. Existing published snapshots remain immutable. A rollback is a **new, explicitly approved CAS activation**, not an edit to a previous version.

## Security and integration tests

SQLite tests cover correct V1→V2 activation, immutable history, audited operator identity, old-version replay conflicts, untrusted target SHA, missing operator scope, cross-tenant denial and audit/storage failure. The actual local Pyodide/Worker+D1 integration additionally proves that signed agents and read-only operators cannot activate; wrong target SHA fails, V1→V2 is recorded, a repeated request fails, and an already approved V1 supplier grant can no longer be consumed even though V2 has **identical rule effects**. New V2 grants can still be reviewed and used only for an in-memory mock adapter with `real_tool_called:false`.

### Security limitations that remain

- This is **not** a production authorization service; no external tool dispatch, full tenant administration UI or public `/v1/decisions` endpoint exists.
- The audit is durable in the local D1 transaction, but local audit retention is 30 days. Independent, long-lived Merkle/EVM anchoring of policy activations is not implemented; the root is **not** on-chain.
- D1 only atomically controls its own storage. It cannot protect against a privileged database administrator changing the active pointer directly or create an atomic transaction with an external API.
- Production must add a controlled policy publishing/signing review workflow, stricter tenant ownership lifecycle, explicit operator separation of duties, concurrency/rollback monitoring, durable request idempotency, and independent security review.
- Tests do **not** prove safety of concurrent remote I/O or exactly-once external execution. Remain fail-closed and do not deploy.

See [issue #3](https://github.com/EagleFox31/agentshield-ai/issues/3) for remaining requirements.
