# Audit repository v1 — SQLite / Cloudflare D1

**Stage:** locally testable storage foundation; **no hosted database provisioned**.  
**Issue:** [#11](https://github.com/EagleFox31/agentshield-ai/issues/11) · **Decision:** [ADR-0005](adr/0005-cloudflare-d1-audit-storage.md).

## Contract

`AuditRepository` is provider-independent. Its pure event format, hashing and policy/audit sequencing contain no Cloudflare or FastAPI dependencies:

| API | Behaviour |
| --- | --- |
| `record_event(AuditEvent)` | Immutable row; first insert true, exact replay false, conflicting payload fails |
| `get_event(verified_tenant, id)` | Tenant-scoped retrieval; verifies stored record's canonical SHA-256 |
| `consume_nonce(verified_tenant, nonce, now, expiry)` | Single `INSERT…ON CONFLICT DO NOTHING RETURNING`; true only for the first durable use |
| `consume_approved_request(verified_tenant, approval_id, action_digest, now)` | Single conditional `UPDATE…RETURNING`; only existing, unexpired, approved and exact-action records transition to `consumed` once |

The public JWT endpoint remains **read only**. Domain `decide_and_audit` never returns an `ALLOW` decision if the required storage operation failed; it does **not** execute tools. Live approval authorization, policy and scope re-evaluation at execution time, and atomic coupled audit/approval workflows are reserved for [#12](https://github.com/EagleFox31/agentshield-ai/issues/12).

## Schema and privacy

`migrations/0001_audit_core.sql` is the **single versioned migration**, compatible with SQLite and D1, and declares:

- `schema_migrations` and `policy_versions`.
- `audit_events` with unique event IDs, tenant/principal, **SHA-256 of canonical target**, policy effect/reason codes, version, UTC epoch milliseconds and explicit retention boundary.
- `approval_requests` and `approval_decisions` (schema for #12).
- `used_action_nonces` with a **tenant + nonce composite primary key**.
- `evidence_batches` reserved for the eventual independent Merkle/EVM proof service (#5).

The log **never contains** raw invoices, free-form prompts, tool arguments, JWTs or bank account fields. The domain accepts only known, bounded event types and reason codes and a configured 1–90-day retention window (30 days in the prototype). No automated deletion/pruning is installed yet. **Do not delete a used nonce merely because its token has expired while a replay remains possible.** Define durable retention/revocation and distributed audit integrity before production.

All SQL that accepts variable values uses **parameterized prepared statements**. Migrations are manually applied offline; neither adapter migrates the database during a request.

The stored event fingerprint can detect a modified covered record when it is read, but it does **not** provide an independent tamper-proof ledger: a privileged database writer could change both payload and fingerprint or delete events. Independent hash-chain/Merkle verification and optional external anchoring belong to issue [#5](https://github.com/EagleFox31/agentshield-ai/issues/5).

## Local SQLite contract

SQLite unit tests create an isolated memory database, apply the *same* SQL migration, and exercise tenant isolation, tamper detection, idempotence, failure behaviour, nonce and conditional approval consumption.

```bash
PYTHONPATH=src python -m unittest discover -s tests/gateway -v
```

## Actual Cloudflare D1 local binding

Cloudflare Python Workers use `env.DB.prepare(sql).bind(*values).first()`; JS result objects are converted to Python dictionaries. The CI starts the actual **Pywrangler/Pyodide Worker** and applies the same migration using **Wrangler local-only**:

```bash
npx wrangler d1 execute agentshield-local-only --local --file=migrations/0001_audit_core.sql
uv run --group worker python scripts/make_local_identity_fixture.py
uv run --group worker pywrangler dev

# Local-only probe, requires LOCAL_SMOKE_ENABLED=true in .dev.vars
curl -X POST http://127.0.0.1:8787/_local/audit-contract
```

`/_local/audit-contract` uses a **synthetic fixed event**, an ephemeral nonce and a synthetic approved-row fixture. It checks insertion, exact retry, tenant denial, at-most-once approval and nonce consumption against D1. It **never executes tools**. Do not turn on `LOCAL_SMOKE_ENABLED` on a public Worker. All-zero database IDs in `wrangler.jsonc` are deliberate placeholders; no live D1 instance, R2 bucket, wallet or Worker is created.

## Failure gates and next work

- Missing/unmigrated D1 binding, malformed result, checksum disagreement or SQL failure must raise `AuditStorageError`/return **HTTP 503** for isolated probes; never silently allow tool execution.
- Same event ID with a different tenant, digest, decision or reason must be rejected.
- Actual **approval issuance, human authentication, revocation, coupled transaction between audit/approval and execution** are not implemented by this foundational schema. The SQL conditional update is only a race-safe primitive, not a complete execution authorization.
- Hosted D1 authorization configuration, backup/retention policies, tenant auth and independent proof verification require separate implementation and security review.

**RAIDER:** reuses core policy and existing Worker, avoids vendor-specific domain objects, exact-retry semantics and database uniqueness enforce idempotence, tests migrations across SQLite and local D1, and preserves existing JWT/worker CI.

## Evidence / references

- [D1 prepare + batch API](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [Python Workers D1 example](https://developers.cloudflare.com/d1/examples/query-d1-from-python-workers/)
- [D1 prepared-statement interface](https://developers.cloudflare.com/d1/worker-api/prepared-statements/)
