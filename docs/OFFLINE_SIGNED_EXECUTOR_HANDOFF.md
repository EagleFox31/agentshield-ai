# Host-only signed execution handoff proof — issue #3 P0

**Security status: OFFLINE proof of a cross-service protocol, NOT a connected executor.** No real provider call, externally reachable network socket, Cloudflare Worker signing key, public token issuer, deployed host service, remote D1, or EVM blockchain operation exists.

## Reusing the existing security chain (RAIDER)

PRs #47–#48 already create a tenant-scoped, immutable, audit-linked outbox command, require an independently signed human operator to claim it, and write a single-use **synthetic** dispatch reservation and redacted audit. PR #51 provides a separate **real local TLS** test server and a host TCP/TLS client restricted to literal `127.0.0.1`. This milestone does **not** duplicate those state machines or loosen any protections.

`src/agentshield/host_signed_handoff.py` supplies a **host-only** ES256 signed, canonical JSON handoff contract:

1. A trusted, test-only issuer receives an already verified `VerifiedAgent` identity and retrieves an existing claimed command, dispatch reservation, original audited ALLOW decision, queue/claim/dispatch audit events and exact current tenant policy from the existing SQLite/D1-compatible ports.
2. It re-computes the original immutable decision fingerprint with the signed principal's **exact scopes**, verifies original actor, action digest, active-policy SHA+activation marker, recorded approval by an independent operator, unexpired decision and the canonical audit records before issuing anything. A current policy generation change refuses issuance. **No issuance occurs for a merely queued/claimed command without the prior mock reservation.**
3. The host test issuer signs a fixed-shape, canonical JSON payload using an **ephemeral P-256 ECDSA private key**. The payload binds tenant, original actor and scope set, command ID, dispatch reservation ID, original decision audit, dispatch audit, active policy version+SHA, exact action digest, issuance time, 30-second expiration and a random JTI. There is **no hostname, URL, tool argument, credential or arbitrary provider request** in the token.
4. A logically separate host-only verifier trusts a **pinned ES256 public key passed out of band**, not a self-supplied token key or `alg` header. It verifies the signature, exact claim names, canonical serialization, fixed audience/issuer, tenant/command, scope, action digest and expiry. It performs a durable `BEGIN IMMEDIATE` SQLite insert with **unique JTI and unique (tenant, command)**. The burn commits **before** any subsequent host-only test operation; a replay or missing/locked ledger refuses.
5. The verified receipt reports `token_used:true`, but deliberately `external_network_used:false`, `execution_authorized:false` and `production_ready:false`. This handoff confirms a prior synthetic reservation; it is **not** a grant to run that command again or to call the TLS probe.

### Evidence and limits

Host integration tests construct the complete signed-agent → versioned policy → idempotent decision+audit → outbox → independent operator claim → one-shot **local mock** reservation chain using existing SQLite adapters, then issue and verify an ephemeral ES256 handoff. They check signer substitution, signature tampering, cross-tenant/command binding, timeout/early use, changed scopes/actor, activation drift, missing audit or reservation, no storage, duplicate token and a **second separately signed token for the same command** (also rejected at the host). No signing key or token is checked into git, and no test sends any outbound request. A separate file-backed SQLite restart test verifies that the consumed JTI and command cannot be reused after the host process closes and reopens the replay database. The issuer now additionally refuses to sign a second token for the same command after a durable local source issuance, rather than relying solely on the consumer's ledger.

**Important:** source data is currently read from a local SQLite-compatible fixture, **not a cryptographically signed live D1 export**. The issuer's P-256 signing key is generated in the host test only, not backed by KMS; the verifier runs as an in-process test, not a separately deployed service. Real enforcement would require independent issuer authentication to D1, strictly controlled signer/key rotation, signed tenant ownership, an atomic handoff issuance record in D1, mTLS/service-to-service transport or equivalent, destination/IP/TLS enforcement at the production proxy, provider idempotency and reconciliation of ambiguous side effects. A signed token alone does not make external execution safe or exactly-once.

Keep all live connections disabled; no public `/v1` execution endpoint is added. Issue #3 remains open.

## Local D1-compatible issuance ledger — PR #54 checkpoint

Migration `0010_local_handoff_issuance.sql` adds **one append-only issuance per (tenant, command)** with an immutable unique ID, original principal, policy/action/digest binding, source dispatch reservation, SHA-256 hash of the random JTI, SHA-256 hash of the **complete signed token**, a 30-second expiry and a dedicated redacted audit event ID. The signed token, private key, arbitrary agent input and provider credentials are **never stored in this ledger**. DB triggers refuse changing or deleting an issuance.

The host-only issuer still verifies the existing signed agent, active policy, canonical decision and **all** original/claim/dispatch audit events. After computing a fresh ES256 signature, it commits a **single D1/SQLite batch** that conditionally records issuance only if the same active policy generation, original agent and unexpired decision remain valid and atomically records a linked canonical audit event. It then re-reads the unique record and checks both token digest and recorded audit **before returning the token**. A second request for the same command loses the unique constraint and returns no new usable proof; no audit entry is generated for the loser. Audit insertion failure rolls back the issuance record, and missing/unreadable storage fails closed.

**Lost-response tradeoff:** if the record commits but the response carrying the token is lost, no automatic reissue occurs. The command remains exhausted until separately reviewed manual reconciliation. This is intentional at-most-one **issuance** behavior; neither source ledger nor host consumer guarantees a third-party execution happened.

This prototype uses the already existing D1-compatible SQL/SQLite ports to prove atomic writes and tests that migration `0010` applies in real **local D1 CI**. **Actual ES256 signing remains in host CPython**, not in Cloudflare Pyodide; there is no authenticated network protocol connecting D1 to a live host signer. Therefore it must **not** be advertised as deployed D1-to-host authorization.

## Upstream runtime drift gate

This feature's first Worker CI failed **closed** when the platform started providing Pydantic 2.14.2/Core 2.50.2 instead of its reviewed earlier versions. The separately reviewed [security provenance PR #53](https://github.com/EagleFox31/agentshield-ai/pull/53) updated the local Worker observation after checking Pydantic's official 29 October 2026 security patch; the full Worker/D1 smoke and deliberate drift-failure checks passed before PR #53 was merged into `main`. Revalidate **this feature** against the updated base before merging. The ES256 host-only test signer remains explicitly separate from the Cloudflare Python Worker and its dependencies.
 The existing Merkle proof demonstration stays **off-chain**.

## Local mutual-TLS transport — PR #55 candidate

An independently documented **local-only** host mTLS channel now conveys the already issued token over real loopback TCP/TLS 1.3 and obtains an ACK **only after** an isolated host-side SQLite burn. The client validates the server hostname/CA, while the receiving server requires a pinned mTLS client certificate and a separately pinned ES256 handoff issuer key. No tools are executed, no remote D1 is read, and a lost ACK is still ambiguous. See [local mTLS security contract](LOCAL_MTLS_HANDOFF.md). This does **not** connect a deployed Worker to a real executor; all production limitations above remain valid.
