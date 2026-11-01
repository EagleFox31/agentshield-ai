# P0 key lifecycle checkpoint — LOCAL attestation trust only

**Status:** a deterministic local keyring and regression-tested rotation,
overlap, revocation and generation floor. **NOT production PKI, KMS or
Cloudflare deployment identity.**

## Architecture and RAIDER reuse

The existing PR #58 path already obtains signed SERVICE claims, verifies D1
audit evidence, signs a nonce-bound response with WebCrypto P-256/SHA-256 and
verifies it with independent host CPython cryptography. This checkpoint only
adds a **host-provisioned key lifecycle policy**. No new authentication
algorithm, policy engine, D1 table, public endpoint or execution adapter.

The local fixture creates two unrelated ephemeral P-256 signers:

- `ci-worker-evidence-v1`: revoked, even if its old signature remains
  cryptographically valid and its configured key-validity window has not passed
- `ci-worker-evidence-v2`: the sole active signer, placed in the ignored
  Worker `.dev.vars` for the current local CI run

A separate ignored `.local-jwt/worker-evidence-trust.json` contains
only the public keys, explicit `active | retiring | revoked` states, bounded
validity timestamps, schema `agentshield.local.worker-keyring.v1` and
monotonic **test generation 2**. The host gets this file *before* network
I/O, never from the HTTP response. The probe's signed path requires this
keyring; the previous single-PEM CLI flag is no longer accepted.

Host verification rejects unknown/duplicate key IDs, reused public material,
unknown fields, two simultaneously active keys, no active key, invalid P-256
keys, stale/future key windows, revoked keys and any generation below the
locally pinned minimum. A `retiring` key may verify only within its
explicit overlap window; after revocation, even a previously valid signature
fails. The earlier strict source proof verification still checks nonce,
ten-second TTL, tenant, command, canonical JSON and *non-authorizing* flags.

CI uses the actual **local** Pyodide Worker/D1 service signer v2 and host
keyring to verify signed read-only evidence. It also deliberately submits
a generation-1 rollback and requires denial. Offline host regressions test
old-key acceptance only during an approved overlap and its rejection after
retirement/revocation, including tampered signatures and trust manifests.

## Critical trust distinction

This registry is a **local operator-provisioned test fixture** and is not a
cryptographically signed policy file. A malicious actor who can replace its
contents and change the host's minimum acceptable generation can alter trust.
No KMS, HSM, Secrets Store, authenticated key-distribution channel, secure
monotonic counter, remote deployment identity, revocation propagation SLA,
disaster recovery or production key custody has been established.

**No deploy, paid Cloudflare operation, remote D1 read, provider execution,
automatic retry, public decision gateway or EVM transaction.**

Next P0: design remotely authenticated provisioning and independent operator
approval of signing-key changes, deployer-identity validation, persistent
rollback guard and key-custody incident response **before** remotely trusted
Worker evidence can authorize any next workflow. Continue to keep issues
#2 and #3 OPEN.
