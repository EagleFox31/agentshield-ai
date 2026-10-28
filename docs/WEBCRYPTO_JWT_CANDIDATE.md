# Native Web Crypto ES256 — experimental gateway migration

**State:** PR #29 implementation candidate. Migration is tested locally with Cloudflare Python Workers/Pyodide and D1; there is **no public enforcement endpoint, deployment, or production approval**. This supersedes the earlier *signature-only* and *full-claims diagnostic* milestones, without erasing their audit trail.

## RAIDER design

- **Reuse:** `src/agentshield/webcrypto_es256_spike.py` delegates P-256/SHA-256 to native `crypto.subtle` rather than implementing cryptography. `src/agentshield/webcrypto_jwt_candidate.py` calls the existing shared `identity.validated_claims_to_agent` logic and an allowlisted local JWKS.
- **Agnostic:** the `VerifiedAgent` and `PolicyEngine` contracts are independent of the crypto provider. The gateway and operator APIs now share an async native-Worker verifier; a caller cannot supply signing algorithms, effective scopes or remote verification keys.
- **Idempotent and durable:** no stateful auth side effects; approval and D1 nonce/audit workflows are still tested for exact-once and replay safety. Keep the GitHub evidence and explicit local-only non-deploy boundary.
- **Engineering-grade:** the token's ES256 signature must be valid **before** reading trusted claims; exact issuer and single-string audience, bounded exp/nbf/iat, tenant, subject, jti and scoped privileges must pass. Missing Worker JS FFI fails closed — there is no silent PyJWT fallback.
- **Retroactive:** the previous `cryptography==47.0.0` vulnerability remains recorded in issue #2. The vulnerable dependency is **removed from the Worker runtime set**; the host-only test/fixture group uses patched `cryptography==50.0.2` and the incumbent PyJWT as an independent comparison oracle.

## Runtime and test dependency boundary

The Pyodide Worker resolves only the top-level runtime `[project.dependencies]`: patched FastAPI and Starlette. There is no `PyJWT` or `cryptography` package in this required set. `[dependency-groups].worker` supplies Pywrangler plus patched host-only libraries to *generate synthetic JWTs*, and `[dependency-groups].test` supplies the independent CPython oracle. `identity.verify_agent_jwt` imports PyJWT lazily and must **never** be called from a Worker authentication route.

The following receive only native-verified identities: `GET /v1/identity` (read-only proof) and locally guarded operator/agent approval, demonstration and redacted-audit routes. There remains **no public `/v1/decisions` and no production tool dispatch**.

## Verifiable CI gates

- **Python tests:** `AgentShield Python CI` with deterministic policy regression, Ruff safety checks, package clean installation, unwaived `pip-audit` and CycloneDX runtime SBOM artifact.
- **Host HTTP security tests:** `gateway-unit` installs only patched host-only PyJWT and cryptography for generating/signing tokens, with a strictly test-scoped oracle injected for one positive CPython HTTP-contract check. Another test asserts the native path fails closed with no JS FFI.
- **Actual local Cloudflare/Pyodide/D1:** `python-worker-d1-local` proves real native verification for both agent and independent operator JWKS, expiration, forged signature, audience mismatch, untrusted `kid`, safe key rotation, approval replay and denied supplier action; no real external provider is used.

**Evidence before final documentation edits:** [Python CI 40605715888](https://github.com/EagleFox31/agentshield-ai/actions/runs/40605715888), [Worker/D1 CI 40605715875](https://github.com/EagleFox31/agentshield-ai/actions/runs/40605715875). Rerun all checks on the final head before merge.

## Remaining P0 acceptance work

- Review broader adversarial/differential JWT corpus and normalize more subtle token encoding issues across languages.
- Establish reproducible **transitive** dependency locks for the CPython and Pyodide runtimes and an independent full dependency inventory; the current SBOM is scoped to the audited runtime.
- Verify remaining formatting/type/dependency-update policies and independent reviewer acceptance.
- Keep #2 open until the declared foundation acceptance criteria are fully met.

No live model inference, no real D1 cloud access, no real credentials, no external effects, no deployment.
