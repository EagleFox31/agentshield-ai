# ADR-0005 — Cloudflare D1 for hosted audit, SQLite for offline tests

- **Date:** 2026-10-26
- **Status:** Accepted; replaces the earlier SQLite-only storage choice
- **User decision:** Cloudflare deployment + D1 audit persistence
- **No remote resource provisioning in this ADR**

## Context
The original local SQLite proposal simplified prototype setup but a per-instance SQLite file in an edge Worker is not a durable database. Cloudflare provides D1, a managed SQLite-backed SQL service accessible to Python Workers using Cloudflare bindings. Audit storage must support approval states and later evidence verification without coupling the policy engine to a provider.

## Decision
Define an `AuditRepository` **port/interface** and two adapters:
- **SQLite:** deterministic, temporary local database for unit and integration tests; no remote dependencies.
- **Cloudflare D1:** persistent hosted storage **via the Worker binding**. Python Worker code uses the supported Workers FFI/binding route rather than assuming normal `sqlite3` filesystem access to D1.

MVP tables: `audit_events`, `policy_versions`, `approval_requests`, `approval_decisions`, `used_action_nonces`, and `evidence_batches` (optional for blockchain extension). Each event uses a unique event ID, trusted actor, action digest, decision/reason codes, policy version, UTC timestamp and privacy-minimized metadata; hash-chain batch information is versioned. Store no raw prompts, access tokens or financial account numbers by default.

Store approvals and nonce/one-time consumption in **atomic transactions or compare-and-set equivalents** with deduplication constraints; never infer safety from eventual UI updates. The service fails closed for controlled execution if the audit or required authorization write fails. D1 alone **does not make logs immutable**; delete/update permissions and retention must be minimized, and independent exported proofs must detect later alteration.

## Consequences
Use portable SQL schema where practical; preserve migration ordering and report adapter-specific differences. Explicitly test D1 local emulation **and Python Worker binding behavior** before deployment. Validate limits of D1 multi-statement operations and concurrency before advertising replay protection; avoid application-global mutable counters or uncoordinated hash-chain sequence assignment. Optional R2 batches and EVM anchoring are separate interfaces and are not prerequisites for storing MVP decisions.

## Acceptance criteria
- [ ] Offline SQLite contract tests, D1-compatible migration tests and idempotency/nonce-race tests.
- [ ] Cross-tenant audit-read denial; redaction; encrypted transport; restricted retention.
- [ ] D1 connection errors never silently become an ALLOW.
- [ ] Python binding smoke test using a local Worker simulator before enabling hosted writes.
- [ ] No production database created in design phase.

## References
- [Python Workers bindings](https://developers.cloudflare.com/workers/languages/python/ffi/)
- [D1 Worker binding API](https://developers.cloudflare.com/d1/worker-api/)
- [MVP scope](../MVP_SCOPE.md)
