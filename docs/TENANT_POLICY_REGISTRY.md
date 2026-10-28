# Tenant-scoped immutable policy registry — local-only proof (issue #3)

**Status:** experimental prototype. It is not production authorization, not a customer policy administration service, and not permission to deploy.

## Reuse and architecture (RAIDER)

- Reuses the existing `policy_versions (tenant_id, version, sha256, created_at_ms)` table in audit schema v1. Migration [0004](../migrations/0004_policy_snapshots.sql) adds `rules_json`, immutable published-version triggers and an `active_policy_versions` table with a **composite tenant/version foreign key**. Published snapshots cannot be edited or deleted; a policy change requires a **new version** and a separately controlled activation.
- Reuses exactly the original `PolicyEngine` / `Rule` contract for effects and scope matching, and the single existing synthetic `demo_rule_records` fixture to create its first local policy. It does **not** invent a second decision engine.
- A snapshot is canonical ASCII JSON using a named versioned schema and sorted explicit rule IDs, **SHA-256 verified on every read**, bounded to 64 exact rules/32 KiB, and rejects duplicate JSON names, altered hashes, foreign-tenant principal IDs, unapproved fields and wildcard policy targets.
- `D1PolicyRegistry.load_active(signed_tenant)` selects the server-side current version. **The agent cannot select a tenant, policy version, rule, effect, or scope through request JSON**.
- `POST /_local/registry-decisions` uses the existing Web Crypto ES256 agent JWT and signed tenant identity, looks up/validates the current snapshot, then reuses `decide_and_audit` with the exact active `policy_version`. It returns only after the redacted D1 event is stored. Missing active policy, corrupted storage, wrong identity or D1 failure fail closed. The response is informational: `execution_authorized:false`, `executed:false`, `enforcement_ready:false`.
- The reviewed offline helper `scripts/seed_local_policy_registry.py --output /tmp/agentshield-ci-policy.sql` generates deterministic tenant `ci_local` fixtures from the existing demo rules; the CI applies them using `wrangler d1 execute --local` after migration 0004. **There is no agent policy publication, activation or administrative write endpoint.** The fixture SQL is idempotent via `INSERT OR IGNORE`, so an existing active version is not overwritten.

## Regression and security coverage

- Independent SQLite tests: immutable version update/delete blocked by database triggers, tenant composite key isolation, empty tenant fail closed, canonical ordering, duplicate and wildcard rejection, corrupted stored SHA-256 rejected, explicit version promotion without editing past content, exact active policy version carried into the redacted audit event, and storage outage.
- Existing real local Cloudflare Python Worker/Pyodide+D1 smoke: JWT-signed allow/read, human-review supplier mutation, unknown action deny, policy version and hash equality, malformed token/operator impersonation denied, caller-supplied version rejected with 422, public route absent with 404. The new tests run after the earlier invoice and Merkle fixture assertions to avoid changing legacy evidence counts.
- Existing policy/approval/mock execution routes remain unchanged. This new **independent local** proof is additive, not a premature migration of the production tool adapter.

## Unresolved gates before a real policy management plane

- Explicit owner/operator-reviewed policy publication, version activation (with durable actor audit), rollback controls, concurrency and cache invalidation, limits on policy cardinality, policy signing, and a tenant management permission model. Current offline fixture SQL **does not audit activation**; it must never be used as a hosted administrator route.
- Bind the **current** active policy to every approval creation and consumption. The older local synthetic approval implementation still uses the original fixture `POLICY_VERSION`; do not claim safe external execution when the active version changes. A real execution gate must reevaluate current policy and verify approval policy-version exactness.
- Authenticated public `/v1/decisions`, request idempotency and durable decision-result records, real safe tool adapters (SSRF, redirects and DNS rebinding protection), external-side-effect recovery and independent security review are still open in issue #3.
- Blockchain commitments remain downstream of durable audit and only after separately authorized testnet work; no blockchain calls are made here.

**Deployment: none. Remote D1: none. External AI inference: none. Real tool mutations: none.**
