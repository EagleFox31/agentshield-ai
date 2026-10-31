# Local signed-service identity and Worker/D1 handoff evidence read — issue #3

**Status: a real local Cloudflare Python Worker/Pyodide/D1 read over HTTP by a
separate host CPython process, but NOT a remotely authenticated D1-to-host
authorization channel. No deployed Worker, no provider I/O.**

## Reused components and trust boundaries (RAIDER)

This checkpoint reuses the **existing** native Worker WebCrypto ES256 JWT
verification, D1ApprovalStore/SQLiteApprovalStore ports, redacted audit
repository and immutable outbox/dispatch/issuance schema (migrations 0008–0010).
It does not add another policy engine, signer, mock-dispatch state machine,
database migration or public /v1 API.

1. CI creates a *third* ephemeral ES256 trust root for a HOST SERVICE, fully
   separate from signed agent and signed human operator JWT roots. The host
   caller has a dedicated audience, tenant, fixed principal name
   `local-host-reconciler`, and exactly `handoff:evidence:read` scope.
   Its short-lived signing key is only in the fixture generator's memory,
   never in Git, D1 or the Python Worker.
2. `GET /_local/commands/{command_id}/service-evidence` is visible only
   when the already-existing `LOCAL_SMOKE_ENABLED=true` switch is explicitly
   set. The Worker validates the SERVICE bearer using the existing native
   WebCrypto path, derives the tenant **only from signed claims**, and uses
   parameterized D1 queries. Unknown command/tenant returns 404, no scope
   returns 403, invalid signer/agent/operator token returns 401; missing D1
   or tampered audit fails closed with 503. No request body or caller-supplied
   tenant, policy, scopes, URL, arbitrary SQL or action arguments.
3. The read-only source checks original decision, queued and independent
   operator claim audit lineage, single synthetic dispatch reservation and
   optional issuance audit. It returns bounded redacted metadata: fixed
   command/tenant, historical policy version and action digest, flags showing
   whether dispatch/issuance exists, and at most the SHA-256 of a signed
   issuance token **if D1 actually has such a record**. Never token,
   JTI, signing key, raw invoice or secret. No new audit record, mutation,
   service claim or execution is created by reading.
4. `scripts/probe_local_worker_evidence.py` runs as a separate **host
   CPython process**. It reads the SERVICE bearer from stdin, calls ONLY
   `http://127.0.0.1:<test_port>` using the built-in HTTP client (no proxy,
   redirects, hostname choices or arbitrary destinations), checks the
   exact command/tenant echo and strictly non-authorizing flags, and outputs
   redacted diagnostic flags. Response caching is explicitly prohibited.

## Real integration test in CI

`gateway-smoke-ci.yml` provisions the **local-only** D1 schema, starts actual
Pywrangler/Pyodide, verifies signed tenant/agent decision, independent human
claim and exactly one synthetic invoice mock dispatch, then performs the
read-only SERVICE endpoint and a separate CPython host GET. Both observe
`dispatch_recorded=true` and `issuance_recorded=false`. This is important:
the local D1 source has **not** minted a host token and cannot pretend that
the test fixture's independently issued SQLite token exists in Worker D1.

CI rejects forged service signatures, agent/human substitution, wrong scope,
cross-tenant service, unauthenticated requests, public route, wrong D1
lineage or missing storage. The host probe reports
`service_request_authenticated_by_worker=true` but explicitly
`source_claim_authenticated=false` because a **plain local HTTP response
has no independent cryptographic server attestation**.

## Remaining P0 requirements

This is **read-only diagnostic connectivity**. It is not a secure deployed
bidirectional service, live D1-to-host issuer, mTLS Worker transport, or
execution authorization. Loopback and an authenticated *request* do not
cryptographically prove the *response* came from an authoritative Worker.
No hosted D1/Worker, external public API, production identities, KMS/key
rotation, remote proxy allowlist, provider idempotency, automated recovery,
or blockchain transaction is enabled.

Before any host verifier can rely on remote Worker evidence, independently
review authenticated server-origin responses (for example a narrowly scoped
asymmetric signed server attestation with managed rotation), a tenant-bound
read-only authoritative D1 adapter, mutual service authentication and
recoverable failure semantics. Continue to fail closed on lost delivery:
no reissue or redispatch without manual reconciliation.

**Issues #2 and #3 remain OPEN.**

## Follow-up: fresh source-origin attestation

The next local-only increment signs the audited Worker/D1 response with an ephemeral native WebCrypto ES256 test key and checks its exact, fresh challenge with a separately pinned host key. This upgrades the local diagnostic from unsigned HTTP metadata, but **does not create a production deployment, authorize any tool, or attest Cloudflare's platform identity**. See [local Worker evidence attestation](LOCAL_WORKER_EVIDENCE_ATTESTATION.md).
