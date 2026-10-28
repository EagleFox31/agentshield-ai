# Active policy consistency for local agent approvals and fake execution

**Scope:** issue #3; a local-only security invariant, not production authorization, deployment or a chain transaction.

## Security invariant

An approval for an action is valid only while **the exact trusted tenant policy version used to create it is still active**. Updating a policy by publishing an immutable new version and changing the active pointer invalidates approvals issued under the prior version—even if the rules have identical effects.

Reuse the existing `policy_versions`, `active_policy_versions`, D1 policy registry with SHA-256 verification, `PolicyEngine`, `AuditEvent`, approval state machine, and local test adapter; do **not** introduce a second policy engine or an independently mutable copy of authorization rules.

- `/_local/demo/approval-requests` loads the active policy from D1 using the signed agent tenant, checks it with `D1PolicyRegistry`, and creates a tenant-, actor-, action-, argument- and **policy-version** bound digest. When the version is supplied, pending request creation and its audit row are conditional on the active version **inside the same D1 batch**. If the policy changed, no approval is returned.
- `/_local/approvals/{id}/approve` or `reject` requires an independently signed operator, and refuses any pending request if its version is no longer active; the guarded state transition and audit share a D1 transaction. Historical expired/rejected/consumed audit entries keep the **original** policy version.
- `/_local/demo/approvals/{id}/consume` and `/_local/test-executions` use the same active snapshot for deterministic evaluation, exact digest and atomic one-use consumption. The conditional update verifies the active pointer **again inside the batch**. A stale or missing policy, tampered snapshot, database failure, changed fixture, wrong tenant/actor or expired approval refuses the action.
- The fake execution gate rereads active version **and policy SHA-256** before dispatching either of its two in-memory mock methods; it returns the policy version/digest for CI evidence, but always has `real_tool_called:false` and `enforcement_ready:false`.
- Earlier direct offline demonstrations that call pure approval functions **without** a supplied `policy_version` retain their legacy test contract. All HTTP approval and fake execution entry points now supply the **validated active version**, without any caller-provided version override.

## Tests and limits

SQLite regression tests seed an immutable tenant policy, then verify that (1) old grants cannot be consumed after a version change with identical rules, (2) creation against an inactive version fails without an approval insert, (3) an old pending request cannot be reviewed after activation, and (4) a policy change between two reads rejects the mock action. Existing cross-tenant/scope/expiry/nonces/audit failure tests remain enforced. Real Worker/Pyodide+D1 smoke validates that newly created approvals and mock decisions use `ci-local-policy-v1`, including a recorded SHA-256, and still checks one-use review and replay.

**Important remaining risk:** D1 cannot create a distributed atomic transaction with an external HTTP side effect. Rechecking the version immediately before our **local in-memory mock** mitigates policy drift but does not establish a production-grade non-bypassable real tool proxy or global exactly-once execution. A real execution adapter will need durable command/outbox, crash/retry reconciliation, freshness checks under concurrency, rate limiting and SSRF controls, plus an independent security review.

No public `/v1/decisions`, no real tools, no remote D1, no EVM transaction or deployment.
