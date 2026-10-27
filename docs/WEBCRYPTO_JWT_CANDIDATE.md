# Candidate JWT ES256 via Workers Web Crypto — full claim parity

**Date:** 2026-10-27 · **Security status:** isolated local-only candidate, **NOT** the active identity verifier.

## Purpose / RAIDER architecture

Instead of writing another cryptographic implementation, reuse the *proven* `crypto.subtle.verify(ECDSA P-256, SHA-256)` Python/JavaScript FFI from merged [PR #27](https://github.com/EagleFox31/agentshield-ai/pull/27). The accepted signature bytes are exactly the compact JWS protected header and payload, and the key comes only from the already pinned local trusted JWKS. No remote discovery, imported private keys, downgrade algorithms or custom elliptic-curve arithmetic.

The former `identity.verify_agent_jwt` still performs signature validation through PyJWT. Its established post-verification claim-to-principal logic has been extracted into **one shared function**, `identity.validated_claims_to_agent`, and reused by the candidate to avoid diverging authorization semantics.

The candidate verifies these contracts **after** native signature verification: exact trusted `iss`, exactly one string `aud`, required claims `sub,exp,nbf,iat,jti,tenant_id,scope`, integer and bounded time claims (maximum 5-minute lifetime), valid principal/tenant format, unique bounded scopes, limited JOSE header, canonical base64url, unique JSON claim keys and no non-standard NaN constants. ES256 signatures with wrong audience **must be rejected**, unlike the signature-only probe.

The candidate is importable as `verify_agent_jwt_webcrypto` and `require_bearer_webcrypto`; **nothing calls it in production**. Its isolated `/_local/demo/webcrypto-jwt-candidate` endpoint first authenticates a human operator using the incumbent verifier, then compares a synthetic submitted test token. It returns only a boolean and bounded metadata, never accepts the submitted token for tool execution or privilege assignment.

## Tests

- `tests/gateway/test_webcrypto_jwt_candidate.py` compares the shared principal contract and negative claims against the incumbent PyJWT verifier with the signature port **mocked**; this proves claim logic, **not** cryptographic validity.
- The original `tests/gateway/test_identity.py` still runs against the actual incumbent signature implementation.
- The existing local `gateway-smoke-ci.yml` runs a **real Pywrangler/Pyodide/Cloudflare native Web Crypto + D1** probe against synthetic signed fixtures for valid/invalid signature, wrong issuer/audience, expiry, future dates, missing JTI, malformed tenant/scopes, and untrusted operator key. A valid JWT must produce a tenant-bound principal without executing a tool. Missing operator credentials must produce HTTP 401.
- All production-shaped endpoints and approval flows still use original PyJWT until an explicitly reviewed transition.

## Remaining migration gates (issue #2)

1. Review cross-verifier semantics with a larger property/adversarial corpus, including duplicate JSON keys, key rotation and imported point validity.
2. Move `PyJWT` and a **patched** CPython `cryptography` to test-only tool dependencies. Refactor existing production gateways and approval flows to async native WebCrypto; never provide silent CPython or insecure crypto fallback in production.
3. Test exact agent/operator trust separation, rate/limit, D1 and approval invariants **under the replacement** (not only the probe).
4. Validate complete CPython+Pyodide transitive dependency locks and an **unwaived** `pip-audit` with SBOM; the old pinned `cryptography==47.0.0` remains vulnerable until removed from the runtime.
5. Merge only on green CI, keep all real execution disabled and continue P0 review of issue #2 before closure.

Sources: [Cloudflare Python FFI](https://developers.cloudflare.com/workers/languages/python/ffi/) and [Cloudflare Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/).

**No deployment, model/provider activation, cloud D1, real credentials or costs.**
