# AgentShield AI — Human approvals (local MVP)

**Scope:** Human approval API, CLI and browser dashboard, guarded by the local-only Worker development flag. **No real tool execution, production issuer or Cloudflare deployment.**

## How an approval works

1. A **signed agent JWT** with `supplier:write` requests the synthetic `suppliers.update_bank_account` action against a fake `supplier/482` resource and chooses a synthetic fixture `scenario-A` or `scenario-B`.
2. The existing deterministic PolicyEngine returns `require_approval`; an approval request and a redacted audit event are committed atomically to SQLite or D1.
3. A **different, independently signed human operator JWT** (separate issuer, audience, public JWKS) may read and approve/reject a pending request, if it carries the appropriate `approvals:read` or `approvals:decide` scopes.
4. The operator's decision, state transition and related audit event are committed **in one database transaction** using SQLite or D1 batch. No approval is granted if the audit write fails. An expired or already reviewed request cannot be approved.
5. To simulate a release, the **original agent** submits the exact same action/arguments. The service recomputes a versioned digest including the tenant, actor identity, signed scopes, policy version, tool, operation, resource and arguments, and **re-evaluates the policy**. An explicit deny, changed arguments, altered scopes, different actor, wrong tenant, expired grant or already consumed approval fails.
6. The local-only mock consumes the grant and writes its audit event atomically; it reports `"simulated_execution": true, "real_tool_called": false`. It does **not** call any external tool, make payments or modify suppliers.

**Audit privacy:** Only a digest of the exact action and a structured effect, reason, actor, policy version, tenant, timestamp and **approval reference** are persisted. No bank account fields, JWTs, raw invoice text, prompts or tool arguments are saved. Audit queries are restricted to the operator's signed tenant and the exact approval ID. This is not an immutable blockchain proof.

## Trust boundaries

- **Agents**: `AGENT_JWT_ISSUER`, `AGENT_JWT_AUDIENCE`, `AGENT_JWKS_JSON`.
- **Operators**: `OPERATOR_JWT_ISSUER`, `OPERATOR_JWT_AUDIENCE`, `OPERATOR_JWKS_JSON`.
- Different ES256 verification-only keys and audiences prevent treating a self-signed or model-controlled agent token as a human identity.
- The `LOCAL_SMOKE_ENABLED=true` flag is **not authentication**. All approval routes are under `/_local/`; **never expose them on a hosted Worker**. A production dashboard will need a separate trusted human identity provider, session protections, authorization policy and origin/CSP hardening.
- No operator JWTs are stored in browser localStorage, cookies or repository. The dashboard keeps the short-lived token in a password input while the page is open; the CLI only reads `AGENTSHIELD_OPERATOR_TOKEN` from the environment and will connect **only to HTTP loopback**, with redirects blocked.
- Human consent is shown against a synthetic known action summary and SHA-256 digest. For a real product, trustworthy human-intent evidence, a meaningful verified diff/preview and an operational approval authority remain required. The fixture is **not production authorization**.
- `audit_events` and `approval_decisions` record request/decision/consumption/expiration. `migrations/0002_approval_review.sql` adds unique decision constraints, single-use consume markers and per-request audit IDs.

## Run the complete workflow locally

With the Python Worker dependencies, Node/Wrangler and Python runtime installed:

```bash
uv sync --group worker
uv run --group worker python scripts/make_local_identity_fixture.py
npx wrangler d1 execute agentshield-local-only --local --file=migrations/0001_audit_core.sql
npx wrangler d1 execute agentshield-local-only --local --file=migrations/0002_approval_review.sql
uv run --group worker pywrangler dev
```

In a second terminal, create a synthetic request using the agent token:

```bash
curl -s http://127.0.0.1:8787/_local/demo/approval-requests \
  -H "Authorization: Bearer $(cat .local-jwt/approval_agent.txt)" \
  -H "Content-Type: application/json" \
  -d '{"fixture":"scenario-A"}'
```

Copy the returned `approval_id`.

**Dashboard:** open `http://127.0.0.1:8787/_local/dashboard` and paste the *temporary operator token* from `.local-jwt/operator_valid.txt` into the local password field. Click **Load approval requests**, inspect the digest and review event, then approve or reject. A read-only operator cannot approve.

**CLI:** in a local test shell, set `AGENTSHIELD_OPERATOR_TOKEN` from the ephemeral operator fixture **without putting it into shell command history in production**. The CLI provides:

```bash
python scripts/approval_cli.py list
python scripts/approval_cli.py audit <approval_id>
python scripts/approval_cli.py approve <approval_id>
python scripts/approval_cli.py reject <approval_id>
```

The approval can be consumed exactly once by the matching simulated request:

```bash
curl -s http://127.0.0.1:8787/_local/demo/approvals/<approval_id>/consume \
  -H "Authorization: Bearer $(cat .local-jwt/approval_agent.txt)" \
  -H "Content-Type: application/json" \
  -d '{"fixture":"scenario-A"}'
```

A second call, different fixture, a missing human decision or an expired grant receives HTTP 409. The sample requires no real banking information.

## RAIDER acceptance

- Reuse `PolicyEngine`, existing JWT verification, portable audit contracts and D1 schema instead of building a separate ad hoc authorization engine.
- Keep both database implementations idempotent and audited, with concurrency tests for the actual conditional state transition.
- Negative tests cover forged agent approval, missing operator scopes, expired requests, wrong actor/tenant, changed arguments, policy denial, SQL failure rollback and replay.
- GitHub Actions must run actual `pywrangler dev` against a local D1 migration and check that the API, browser route and CLI all use the same authenticated workflow.
- **Deferred:** production deployment, authenticated authorizations for real tools, verified human-intent evidence, transactional coupling to actual external tool execution, paid services and independent Merkle/EVM anchoring.

[Architecture ADR-0004](adr/0004-human-approvals-dashboard-cli.md) · [Audit ADR-0005](adr/0005-cloudflare-d1-audit-storage.md) · [Audit implementation](AUDIT_D1.md) · [Issue #12](https://github.com/EagleFox31/agentshield-ai/issues/12) · [PR #17](https://github.com/EagleFox31/agentshield-ai/pull/17).
