# Local dry-run execution gate — P0 issue #3

**Stage:** experimental, local-only; no public execution endpoint, real supplier mutation, payment processing, deployment or chain transaction.

## Enforcement flow

A signed ES256 agent JWT (not an operator JWT) enters `POST /_local/test-executions` with an exact synthetic `tool`, `operation`, `resource`, `fixture`, one-use `nonce`, and an optional exact human `approval_id`. FastAPI rejects all additional JSON keys: no caller-provided tenant, policy, identity, scopes, remote URL, arbitrary arguments or credentials are accepted.

The existing shared invoice/supplier `PolicyEngine` and `audit_service.decide_and_audit` run first. A denied tool is never dispatched; an `allow` is still insufficient until the audit is durably confirmed. The existing D1 audit repository atomically rejects a reused tenant-bound nonce. For `require_approval` the **existing** `consume_mock` function validates the principal, tenant, exact action+fixture+signed scopes, policy version, review state and expiration, and atomically commits the one-use consumed state **together with its redacted audit event** before the adapter can run.

Only after these gates does the new `LocalDryRunAdapter` record a synthetic invocation. It supports precisely two in-memory cases: the existing fake invoice reader and a harmless `mock_supplier_write_dry_run` marker that **never** calls `RecordingMockTools.update_supplier()` (which deliberately raises) or any external provider. No sockets, real bank accounts, files, external API calls or cloud billing occur.

The response always distinguishes `mock_invoked:true` from `real_tool_called:false`, `executed:false` and `enforcement_ready:false`. A stub reaching a test endpoint **is not evidence of a non-bypassable production execution boundary**.

## Security evidence

- SQLite domain tests check audit ordering, unknown-tool default deny, missing scope, missing grant, one-use consumption, repeated nonce, changed fixture, expired grant, other agent/tenant/scope, audit storage failure, consumption rollback and adapter allowlist.
- Local Python HTTP tests remain separate from the real signed-token integration; CPython lacks native Workers JS Web Crypto and never silently falls back to PyJWT.
- The existing Cloudflare Python Worker/Pyodide + local D1 workflow signs fresh ES256 JWTs, creates and reviews a fresh human grant, proves one dry-run supplier action and denied replay, rejects wrong fixture, wrong trust root, missing scope, input scope forgery and non-existing public endpoint.

## Remaining work

This milestone **does not implement** `POST /v1/decisions`, a tenant policy registry, SSRF protection, a real tool capability, transactionally consistent outbox/recovery for external tool calls, rate limits, or independently reviewed production auth. A real mutable tool cannot be safely supported by this in-process mock: atomic D1 updates and external side effects cannot form a distributed transaction, so release-grade exactly-once outcomes require a separate design and reconciliation plan.

The blockchain comes **after durable audit** through Merkle batch evidence and separately authorized EVM commitments. It is not a permission oracle and is never contacted here.

**RAIDER:** reuse the existing exact-digest approval state machine, nonce contract, policy, identity, redacted event schema and local Worker test infrastructure; no new provider or parallel policy engine. Keep issue #3 open and do not deploy.
