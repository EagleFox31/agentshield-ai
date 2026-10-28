# Web Crypto ES256 — isolated Pyodide verification spike

**Historical scope:** This document records the initial *signature-only* proof in PR #27. Subsequent PR #28 validated complete JWT claims, and PR #29 migrates experimental local gateway/approval authentication to native Web Crypto. **This probe still is not an authorization module**, production enforcement or deployment permission. See [WEBCRYPTO_JWT_CANDIDATE.md](WEBCRYPTO_JWT_CANDIDATE.md) for the active migration contract.

**Motivation:** [issue #2](https://github.com/EagleFox31/agentshield-ai/issues/2) tracks the Pyodide `cryptography` wheel vulnerability/compatibility constraint. The shared JWT claim rules in `src/agentshield/identity.py` remain authoritative, while PR #29 switches the experimental Worker signature primitive to native Web Crypto. This experiment uses a different cryptographic primitive only.

## How it is isolated

- `webcrypto_es256_spike.py` reuses the existing validated, pinned trust-root parsing from `identity._trust_store` to select a **trusted P-256 public key**. It never follows a URL, accepts a token-supplied JWK, trusts a `kid` from an unrecognized key or permits another algorithm.
- ES256 compact-JWS raw signatures are exactly **64 bytes** (`r || s`); the signed bytes are exactly the ASCII protected-header and payload segments joined by a period. There is no DER conversion or hand-rolled elliptic curve arithmetic. ECDSA P-256 with SHA-256 is delegated to the Workers native `crypto.subtle.importKey/verify` via supported Python/JavaScript FFI.
- The test endpoint `GET /_local/demo/webcrypto-es256-probe` is guarded by the existing **local-only flag** and an independently authenticated **operator**. The requested synthetic token is supplied in `X-Probe-Token`; the endpoint returns only a boolean and explicit `claims_validated: false`, `authorization_ready: false`, `used_for_authentication: false` and `real_tool_called: false`. It must **never** substitute for `/v1/identity`.
- Because this is a signature-only primitive, a correctly signed but **wrong-audience JWT also returns `signature_valid: true`**. The existing production-shaped JWT verifier must still reject its claims. Mistaking this predicate for authentication is a critical security bug.
- All conversion, parsing, missing runtime and provider exceptions fail to a boolean false without logging secrets, model inputs or key material. Only signed public test fixtures are used in CI.

## Reproducibility / review

- CPython unit tests exercise JOSE header trust selection, base64url strictness, duplicate JSON headers, 64-byte raw signature shape and the explicit distinction between signature validity and claim validity.
- The **existing** `gateway-smoke-ci.yml` runs the *real* local Pywrangler/Pyodide Worker with synthetic signed operator and agent fixtures and local D1. It asserts native WebCrypto accepts the correct key/signature, rejects an unrelated signature, and still accepts the signature of a wrong-audience token without granting authorization. It also denies unauthenticated use of the probe.
- Code does not remove PyJWT/`cryptography` or modify the public authentication/approval decisions, `wrangler.jsonc`, real tool dispatch, live bindings, or cloud deployment.
- Before replacing the old verifier, conduct a separate security design review and extend the prototype to the **entire** JWT contract (key rotation, issuer, exact audience, expiry, nbf, iat, tenant, scopes, operator separation, replay) with full parity and unwaived dependency scans. Only then contemplate changing the runtime dependency graph.

Official sources:
- [Cloudflare Python FFI](https://developers.cloudflare.com/workers/languages/python/ffi/)
- [Cloudflare Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Cloudflare Python example signing requests](https://developers.cloudflare.com/workers/examples/signing-requests/)

**RAIDER:** reuse trusted identity parser, portable signature shape and existing CI/runtime; independent spike; idempotent tests; durable evidence; no bypasses; retroactively record the persistent dependency constraint in issue #2.
