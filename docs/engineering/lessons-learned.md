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


## LESSON-2026-002 — Pyodide cryptography wheels are version-specific

**Date:** 2026-10-26  
**Category:** Security / Python Workers / cryptography packaging / CI  
**Scope:** [AgentShield #10](https://github.com/EagleFox31/agentshield-ai/issues/10), [PR #15](https://github.com/EagleFox31/agentshield-ai/pull/15)

**Symptom:** FastAPI/ES256 unit tests succeeded in CPython, but local Cloudflare Python Worker packaging refused `cryptography>=46,<47` because those versions had no compatible Pyodide 314.0.7 wheels. The Pywrangler local integration job did not get as far as importing the gateway or testing ES256.

**Root cause:** Pywrangler and Python Workers use a **WASM/Pyodide runtime**, not the host CPython wheel index; availability of the cryptography extension varies by exact Pyodide distribution. The chosen native version range excluded Pyodide's compatible, prebuilt `cryptography==47.0.0`.

**Corrective action:** Pin `cryptography==47.0.0` in the required Worker dependency set and independently validate a signed ES256 JWT and rejection of wrong signatures/audiences/expired claims against a **real local Python Worker**, not just a CPython TestClient. Do not weaken the cryptographic algorithm or remove signature verification to work around wheel errors.

**Second finding:** A test initially asserted missing JWKS configuration must produce HTTP 503 **when no Bearer token was supplied**. Missing credentials appropriately return HTTP 401 before testing trust configuration. The test was corrected to provide a syntactically and cryptographically valid token against an absent trust root before expecting HTTP 503. This is a test-fixture precondition error, not a security bypass.

**Regression prevention:** `test_worker_packaging.py` pins the reviewed Pyodide-compatible dependency, and GitHub Actions continuously tests actual signed/forged JWTs in `pywrangler dev` while preserving the D1 binding check. All signature verification stays with maintained PyJWT/pyca cryptography rather than custom code.

**RAIDER lesson:** Versions must be evaluated against the **target runtime wheel index** when shipping native/compiled security libraries on the edge. Always test cryptographic outcomes end-to-end under the production-shaped runtime and keep error-precedence unit tests semantically correct.

**Limit:** Local cryptographic verification does not imply the service is deployed, that replayed access tokens are blocked, or that a production identity provider/key rotation system exists.
