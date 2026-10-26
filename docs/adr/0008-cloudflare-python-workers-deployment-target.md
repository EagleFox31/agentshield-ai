# ADR-0008 — Cloudflare Python Workers deployment target (not deployed)

- **Date:** 2026-10-26
- **Status:** Accepted as deployment target, subject to local compatibility gate

## Context
User selected Cloudflare rather than local Docker as the eventual hosting platform, while maintaining **FastAPI**, Python policy engine and D1. Cloudflare currently documents Python Workers with ASGI/FastAPI and binding access via Pyodide/FFI. Python dependency compatibility and native extension support still need empirical validation.

## Decision
Target a Cloudflare **Python Worker** with FastAPI via the supported `workers.asgi` entrypoint and `python_workers` compatibility flag. Follow current Pywrangler guidance. New Python Worker packaging (currently Python >=3.13 in examples) must be tested separately from the existing offline PolicyEngine (currently Python >=3.11); document the compatibility boundary before modifying its supported interpreter. Use a D1 binding rather than local filesystem storage for hosted audits. Serve a minimal separately built dashboard as Workers static assets or a separate static frontend only after route/authorization tests. Keep optional R2 and proof publishing decoupled.

Define **plan → test → review → deploy** with the final deploy step outside this initial PR/backlog phase. No Cloudflare credentials or production configuration are committed, no Worker, D1, R2, domain or blockchain wallet is provisioned, and CI must not automatically deploy as a side effect of documentation changes.

## Risks and gates
- [ ] Reproducible local Pywrangler/FastAPI ASGI smoke and complete PolicyEngine suite.
- [ ] JWT verification dependency compatible with Python Workers/FFI, algorithm allowlist tested.
- [ ] D1 binding, migrations, transaction/idempotency and SQLite parity tests.
- [ ] Confirm runtime quotas, database limits and key-handling capabilities before production planning.
- [ ] Document offline local fallback, request tracing and recovery/rollback strategy.
- [ ] Require explicit approval for any live provisioning, testnet gas or deployment.

## References
- [FastAPI in Python Workers](https://developers.cloudflare.com/workers/languages/python/packages/fastapi/)
- [Python Workers](https://developers.cloudflare.com/workers/languages/python/)
- [D1 bindings via Python Workers FFI](https://developers.cloudflare.com/workers/languages/python/ffi/)
- [MVP scope](../MVP_SCOPE.md)
