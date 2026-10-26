# AgentShield Python Workers / D1 feasibility slice

**Status:** experimental local adapter, not an authenticated or production-ready gateway. Tracked by [issue #9](https://github.com/EagleFox31/agentshield-ai/issues/9) and [ADR-0008](adr/0008-cloudflare-python-workers-deployment-target.md).

This adapts Cloudflare's *official* FastAPI ASGI Worker entrypoint and Python D1 FFI binding; it does not build another runtime or rewrite AgentShield's Python policy core.

## Implemented diagnostic boundaries

- `src/worker.py`: minimal `WorkerEntrypoint` + `asgi.fetch(app, request, env)` bridge.
- `GET /health`: reports experimental liveness only, always `enforcement_ready: false` and `audit_ready: false`.
- `POST /_local/policy`: guarded developer-only, fixed principal/scopes and existing `PolicyEngine` decision; **no tool execution**, even on ALLOW.
- `POST /_local/d1-smoke`: guarded developer-only, fixed SQL creates an isolated local probe table and writes/reads a harmless sentinel via `env.DB`. This is not an audit repository.
- Developer diagnostics are disabled unless `LOCAL_SMOKE_ENABLED=true` is injected into the Worker environment. **This flag is not an authentication mechanism and must never be enabled for any remotely hosted Worker.**
- A placeholder all-zero D1 ID in `wrangler.jsonc` intentionally identifies **no provisioned hosted database**. No real credentials or remote resource IDs are present.

There are no authenticated public decision endpoints, JWT verification, policy storage, approvals, D1 audit tables, remote workers, R2 resources or blockchain wallets in this slice.

## Local execution, never deploy

With Python 3.13, Node.js and [uv](https://docs.astral.sh/uv/):

```bash
uv sync --extra gateway --group worker
printf 'LOCAL_SMOKE_ENABLED=true\n' > .dev.vars
uv run --extra gateway --group worker pywrangler dev

# From a second terminal:
curl http://127.0.0.1:8787/health
curl -X POST http://127.0.0.1:8787/_local/policy \
  -H 'content-type: application/json' \
  -d '{"tool":"suppliers","operation":"update_bank_account","resource":"supplier/482"}'
curl -X POST http://127.0.0.1:8787/_local/d1-smoke
```

Expected: liveness indicates NOT ready; malicious bank-account change receives `deny` and `executed:false`; the local D1 query returns `d1_local_probe:ok`. The one-time local smoke table contains no user data. Remove `.dev.vars` after the test. Its content and `.wrangler/` state must not be committed.

**Never run `pywrangler deploy`, `wrangler d1 create`, `wrangler d1 execute --remote` or any remote apply command for this issue.** CI intentionally has no cloud credentials and uses only `pywrangler dev`.

## Required proof before closing issue #9

- Local ordinary Python HTTP unit tests are green.
- GitHub Actions **Pywrangler local** job demonstrates actual FastAPI/Pyodide compatibility and a D1 binding read/write query. Stub/mock unit tests alone are **not** sufficient.
- Dependency-resolution/lock and reproducibility are verified or tracked transparently for the next foundation milestone.
- Cloudflare's experimental runtime, D1 binding and JWT library compatibility are evaluated before production planning.

Next: [#10 JWT agent identity](https://github.com/EagleFox31/agentshield-ai/issues/10), [#11 portable audit repository](https://github.com/EagleFox31/agentshield-ai/issues/11), and [#12 approvals](https://github.com/EagleFox31/agentshield-ai/issues/12).

## References

- [Cloudflare FastAPI support](https://developers.cloudflare.com/workers/languages/python/packages/fastapi/)
- [D1 from Python Workers](https://developers.cloudflare.com/d1/examples/query-d1-from-python-workers/)
- [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/)
