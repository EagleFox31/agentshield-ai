# Python Worker cryptography advisory and migration decision

**Date:** 2026-10-27  
**Status:** Open P0 security decision; **no deployment**, no vulnerability waiver, no production approval.  
**Tracking:** [issue #2](https://github.com/EagleFox31/agentshield-ai/issues/2) and [PR #26](https://github.com/EagleFox31/agentshield-ai/pull/26).

## Observed evidence (do not confuse resolution with exploitability)

- CPython 3.12 `pip-audit==2.10.1` found 17 advisory *entries* (some repeated) across the earlier `cryptography 47.0.0` and `starlette 0.50.0` dependency resolution. This is not a claim of 17 distinct independently exploitable flaws.
- Updating to `fastapi 0.139.2` with `starlette 1.3.1` passed the Python policy and local Cloudflare Workers/Pyodide+D1 regression suites when `cryptography 47.0.0` was retained. The supply-chain audit **still failed**, as it must.
- Replacing that crypto pin with `cryptography 50.0.2` made the CPython dependency audit succeed but broke the *real* `pywrangler dev` integration because Pyodide 314.0.7 had no usable wheel. The issue is a packaging constraint, not an indication that an unsafe verifier can be used safely.
- Official Pyodide package index: https://index.pyodide.org/314.0.7/cryptography/ currently offers `cryptography-47.0.0-...-pyemscripten...`, and no patched WebAssembly wheel. See also https://index.pyodide.org/.
- Cloudflare documents its Python Workers FFI and the Workers Web Crypto API:
  https://developers.cloudflare.com/workers/languages/python/ffi/
  https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- Security advisories include https://osv.dev/vulnerability/PYSEC-2026-3554 and related findings. **Whether a CVE affects the current ES256-only code path is a separate expert review question, not a justification for silently suppressing alerts.**

## RAIDER — adopt / adapt / build assessment

| Option | Reuse and engineering trade-off | Decision |
| --- | --- | --- |
| **A. Upgrade Pyodide runtime or use an official, security-patched PyEmscripten wheel** | Minimal code change; keeps independently vetted PyJWT+cryptography signature validation. Must work inside real local Cloudflare Worker and D1; do not download an untrusted custom wheel. | **First priority. Not currently available in the inspected official 314.0.7 index.** |
| **B. Use Cloudflare Workers native Web Crypto through the documented Python FFI** | Reuses a maintained ECDSA P-256 primitive instead of implementing elliptic-curve math. Requires carefully reviewed JWT JOSE decoding/claim verification, async identity integration, explicit key validation and strict fail-closed behavior. Existing PyJWT verifier remains the independent cross-oracle in CPython tests. | **Candidate security spike only**, isolated from production. Do not remove cryptography or switch runtime auth before full parity and adversarial tests. |
| **C. Introduce a separate trusted JWT gateway/service** | Dedicated security boundary and possibly mature JOSE library; introduces new hop, signed identity propagation risks, operational complexity and potential bypass. | Not preferred without measured need and explicit review. |
| **D. Ignore `pip-audit`, force downgrade, use a hand-rolled ECDSA/HS256 substitute, or force-merge** | Would risk insecure verification, downgrade to symmetric authority, or false green status. | **Rejected** |

## Mandatory acceptance gates before release

1. Keep algorithm pinned to **ES256 only**, enforce allowlisted `kid`, `typ`, `iss`, exact `aud`, bounded `exp/nbf/iat`, tenant, subject and scope, and a trusted local **public** JWKS; disallow remote key lookup, unsigned/HS256 JWT, private JWK fields, and unrecognized headers.
2. Negative tests: signature mutation, valid signature from wrong key, algorithm confusion, expired/future/oversized tokens, swapped agent-vs-operator JWKS, forged scopes, malformed EC coordinates, key rotation, and concurrent requests across tenants. No exception details or secrets in client responses/logs.
3. *Actual local* Pyodide/Cloudflare Worker+D1 test must run and verify positive and negative ES256 cases. CPython-only passing tests do not prove Worker compatibility.
4. `pip-audit` of actual relevant runtimes must be green without `--ignore-vuln`, `|| true`, forced `continue-on-error`, or suppression; produce reviewable SBOM from the resolved dependencies, and lock transitive resolutions for CPython and the Pyodide index.
5. Maintain non-deployment and default-deny posture. Any production or paid provider activation requires an explicit separate go/no-go decision.

## Reproducibility

- `AgentShield Python CI`: clean install, Python policy regressions, vulnerability audit and saved CycloneDX SBOM even if an audit fails.
- `AgentShield FastAPI/D1 Local Compatibility`: gateway unit tests and real local Worker/Pyodide + D1 + ES256 fixtures, with no remote D1 or cloud deployment.
- Most recent prior successful local-Worker run for the Starlette update and old crypto pin: https://github.com/EagleFox31/agentshield-ai/actions/runs/40540184574
- Known dependency-audit failure on the same pin: https://github.com/EagleFox31/agentshield-ai/actions/runs/40540184543

**Exit criterion:** choose and validate a path satisfying all gates, green checks and accurate evidence. Until then, keep #2 and PR #26 open.
