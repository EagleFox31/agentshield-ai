# Cloudflare Python Worker toolchain provenance — baseline v1

**Scope:** local-only engineering reproducibility contract for AgentShield issue #2. This is **not** a published/released security gateway, a cryptographic platform freeze, an independent audit or authorization to deploy.

## Source of truth (RAIDER — reuse existing tools)

- Cloudflare chooses a specific Python/Pyodide runtime from the `wrangler.jsonc` **compatibility_date: 2026-10-26** and the `python_workers` flag. This is a platform selection, **not** a locally vendored interpreter image.
- Native Cloudflare Python Worker verification on [GitHub Actions run 40649796186](https://github.com/EagleFox31/agentshield-ai/actions/runs/40649796186) observed Python **3.14.2**, Pyodide **314.0.6**, FastAPI **0.139.2**, Starlette **1.3.1**, Pydantic **2.14.1**, and Pydantic Core **2.50.1**.
- Host-only contributor tests use **Python 3.13** and `uv==0.12.3`, with a committed `uv.lock`. **Host CPython is not the Worker interpreter.**
- Pinned `wrangler==4.154.0` in a private root `package.json`; `package-lock.json` commits the npm v3 tree with integrity hashes (92 package entries when generated). The existing Worker/D1 CI installs using `npm ci --ignore-scripts`, invokes only the local Wrangler binary, and adds `node_modules/.bin` to PATH for local Pywrangler. No more `npx --yes wrangler` resolving an unreviewed latest version.
- The authenticated local-only `/_local/platform-provenance` endpoint reports a **minimal allowlisted** set of version numbers. It is protected by local-mode middleware and the existing signed `OPERATOR` identity with `approvals:read`, returns no environment values, key IDs, tokens or network configuration, and has no tool-execution effect.
- [`docs/WORKER_RUNTIME_BASELINE.json`](WORKER_RUNTIME_BASELINE.json) holds the reviewed version observations; `scripts/check_worker_provenance.py` compares them against a live Worker probe, `wrangler.jsonc`, locked npm metadata and `pyproject.toml` required deps. A synthetic mismatched Pyodide version must make the CI step fail.
- GitHub Actions retains the non-sensitive `local-worker-runtime-provenance` evidence artifact for 14 days. Actual JWT, approval, D1 and invoice-denial integration tests must remain green on the **same** commit.

## How to reproduce locally (no deployment)

From a clean checkout with Node.js 22, Python 3.13, `uv==0.12.3`, and npm installed:

```bash
npm ci --ignore-scripts --no-audit --no-fund
./node_modules/.bin/wrangler --version
uv lock --check --python 3.13
uv run --locked --group worker python scripts/make_local_identity_fixture.py
```

Run only local D1 migrations with `./node_modules/.bin/wrangler d1 execute ... --local`, and the existing `uv run --locked --group worker pywrangler dev`. For full automation and test fixtures follow [`.github/workflows/gateway-smoke-ci.yml`](../.github/workflows/gateway-smoke-ci.yml); do not manually contact a remote Cloudflare D1 database or issue production credentials.

## Explicit limitations and review requirements

**Detecting drift is not preventing drift.** Cloudflare may change the internal Pyodide package index, runtime snapshot, or workerd binary distribution independently; the compatibility date is a selection boundary, not an immutable image hash. The lock gives integrity information for published npm artifacts but not proof of remote runtime behavior or an attestation from Cloudflare. As such, the checked-in baseline provides a **fail-closed regression signal**, not full reproducible independent rebuilds of the platform.

If any observed version or package changes, the CI fails. Never change the baseline solely to make a red workflow green: investigate release notes/advisories and compatibility, compare JWT/D1 security negative tests, examine npm lock diff, and approve a new baseline as a **separate reviewed PR**. No automatic baseline refresh or vulnerability ignores.

Remaining separate gates in issue #2: independent JWT migration security review, expanded strict typing and formatting coverage and broader build provenance beyond locally observed platform versions. No deployment, paid model calls, real tool mutations or remote D1 operations were used in these checks.

References: [Cloudflare Python Workers runtime](https://developers.cloudflare.com/workers/languages/python/how-python-workers-work/), [Python package management](https://developers.cloudflare.com/workers/languages/python/packages/).
