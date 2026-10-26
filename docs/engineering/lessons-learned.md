# Engineering lessons learned — AgentShield AI

This repository follows [RAIDER failure-memory requirements](https://github.com/EagleFox31/project-registry/blob/main/RAIDER.md). Significant failures must have an identified root cause, a regression guard, and a reusable prevention pattern.

## LESSON-2026-001 — Python Worker local install differs from ordinary uv extras

**Date:** 2026-10-26  
**Category:** Python Workers / dependency packaging / CI  
**Scope:** AgentShield [#9](https://github.com/EagleFox31/agentshield-ai/issues/9), [PR #14](https://github.com/EagleFox31/agentshield-ai/pull/14)

**Symptom:** The ordinary Python FastAPI/TestClient suite passed, but Cloudflare's local `pywrangler dev` failed at Python Worker startup with `ModuleNotFoundError: No module named 'fastapi'`. D1 was correctly declared as a local binding; the failure occurred before reaching it.

**Root cause:** The initial `pyproject.toml` declared FastAPI only in the optional `gateway` extra. `uv run --extra gateway` made FastAPI available to the *host* environment, but Pywrangler's Pyodide dependency lock for the Worker was derived from the **required project dependencies**, so FastAPI was not bundled into the Worker interpreter.

**Correction:** Declare FastAPI in the required project dependencies, keep the pure PolicyEngine source independent of FastAPI, and run Pywrangler with Cloudflare's standard Worker tooling. Constrain reviewed top-level runtime versions. Continue to use a deliberately nonfunctional hosted D1 identifier and local-only diagnostic paths.

**Prevention:**
- Dedicated `tests/gateway/test_worker_packaging.py` rejects a configuration in which FastAPI is available only through a dev extra and flags accidental real D1 IDs or deploy commands.
- Path-scoped GitHub Actions executes actual `pywrangler dev` on Python Workers/Pyodide, queries a local D1 binding (write/read), and validates a denial on a synthetic supplier-change action.
- A passing CPython unit test is **not** a substitute for actual Python Worker compatibility, and a passing local D1 binding test is **not** proof of production-ready hosted audit storage.

**Reusable RAIDER rule:** On cross-runtime platforms (Python → Pyodide/Workers, web → native mobile, Node → bundled sandbox), dependency resolution and artifact import paths must be integration-tested **in the target runtime**, not just in the host's unit-test interpreter.

**Status:** mitigation implemented and independently tested in PR #14; no Cloudflare production deployment.
