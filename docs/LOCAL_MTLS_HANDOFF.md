# Loopback mTLS handoff checkpoint — issue #3 (local only)

**Status: genuine, mutually authenticated local TCP/TLS traffic; NOT a
Cloudflare-to-host service connection, live executor, or production grant.**

## RAIDER reuse and exact security boundary

This checkpoint composes the existing audited chain, rather than adding a
second policy engine or another simulated dispatch:

1. Existing host-only `issue_offline_handoff` verifies the signed original
   agent, active tenant policy, durable ALLOW decision, independent operator
   claim, single synthetic mock reservation and canonical audit. Migration
   `0010_local_handoff_issuance.sql` records one issuance and its redacted
   audit atomically, **before** the signed 30-second ES256 token is returned.
2. The new `host_mtls_handoff.py` sends that token through a **real OS socket**
   to literal `127.0.0.1` only. Client TLS 1.3 authenticates the code-owned
   `handoff.agentshield.test` server name against a provisioned test CA and
   presents a client certificate. No caller-provided URL, host, path, method,
   tenant, or arbitrary payload is allowed.
3. The one-shot server will accept **only a socket bound to 127.0.0.1**.
   Server TLS 1.3 **requires a client certificate** trusted by its separate
   test CA and independently pins its exact DER certificate SHA-256. This
   prevents accepting any other CA-issued client without a pin review.
4. The server verifies the **existing pinned ES256 issuer public key** and
   fixed tenant/command/scopes/action/expiry with
   `verify_and_burn_local_handoff`, committing the independent host SQLite
   replay record **before** returning the fixed, authenticated `ACK`.
   That ACK proves only that the local verifier consumed the proof. It does
   not authorize or report a second dispatch.
5. Each connection carries a fixed length-prefixed token frame (max 2,500
   ASCII bytes), with strict total two-second deadline and exact ACK parsing.
   TLS certs/keys are generated at test time only and kept out of git.

## Failure modes and reconciliation

An invalid server CA/name, absent/untrusted/changed client certificate,
unexpected peer IP, invalid signature, changed tenant/command, expired
handoff, replayed JTI or unavailable replay DB must result in **no accepted
delivery**. The server does not echo the token, log it, or issue any
credentials. There is no retry policy in the transport.

**Ambiguous ACK:** if the host has committed its replay burn but the
connection breaks before the client reads ACK, it remains ambiguous whether
the token was accepted. The source ledger also forbids reissuance.
Operators must investigate source issuance, outbox audit, host burn and
provider state separately before choosing a recovery action. No automatic
retry, replacement token, re-dispatch, or provider side effect is safe.

## Explicit gaps before production

- Both endpoints are currently **host CPython roles within local test
  fixtures**, not independent deployed services. The source is a locally
  D1-compatible SQLite ledger; the live Cloudflare D1 Worker does not
  communicate with this host signer. No secure Worker-to-host issuer
  authentication or authoritative remote D1 reads exist.
- Trust roots, pinned client fingerprint, server certificate and ES256 issuer
  public key are **ephemeral test provisioning**, not KMS/CA or managed
  rotation. There is no certificate revocation policy, signed deployment
  identity, or failover.
- The one-shot local host **only verifies and burns**; it cannot call an
  external provider, choose a destination, run an arbitrary tool, or make
  an EVM blockchain transaction. A real isolated egress proxy still needs
  destination IP/TLS binding, bounded request/response streaming,
  provider idempotency, durable result receipt and crash reconciliation.

No public API, remote D1, live credentials, cloud deployment or blockchain
transactions. Keep **issue #3 OPEN** until the end-to-end *production*
execution boundary is independently reviewed and proven.

## Separate process boundary (PR #56 candidate)

The same reviewed local mTLS send/receive functions now run in **two OS subprocesses**, with distinct PIDs and a file-backed host replay database that survives server restarts. Source signing and audit remain local D1-compatible test fixtures. The caller passes the signed proof through stdin (never argv) and both CLI roles require explicit test-only opt-in. See [host process isolation and limitations](LOCAL_HOST_PROCESS_ISOLATION.md). **No deployed Cloudflare Worker-to-host service, remote D1 verification, external execution or blockchain write.**
