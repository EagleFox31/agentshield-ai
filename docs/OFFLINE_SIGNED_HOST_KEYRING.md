# Operator-signed local Worker keyring + persistent host install

**Status: local host trust provisioning prototype — no cloud deployment, no
production root custody, no remote D1, no external tool authorization.**

## Why this change follows PR #59

PR #59 already checks key validity, immediate revocation, a retiring-key
overlap and a caller-provided minimum generation. However, an unsigned
keyring file and a user-supplied generation floor cannot, by themselves,
authenticate an update or prevent a stale local install.

This increment reuses the existing strict Worker key validator and the
ES256 evidence challenge-verifier without adding a second policy engine,
execution gateway, public API route, D1 migration or Cloudflare binding.

## What was implemented

1. The local CI fixture generates **an independent offline P-256 operator
   signing key** in host memory, completely separate from both the Worker
   evidence attestor and the agent/operator SERVICE JWT issuers. Only the
   operator public PEM and signed keyring envelope are persisted. The
   operator **private** key is never written to disk, D1 or the Worker.
2. The offline signed envelope fixes its schema, operator key identifier,
   exact canonical manifest and raw 64-byte ES256 signature. The
   **operator public key must be separately pinned**: it is never accepted
   from HTTP, the manifest itself, an agent, model output or a JWKS URL.
3. The standalone HOST-only installer verifies the signature and
   validates the **existing** Worker keyring schema *before* installing.
   A file-backed SQLite ledger records one atomically committed current
   generation, operator key fingerprint, manifest digest and canonical
   signed envelope. `PRAGMA synchronous=FULL` and `BEGIN IMMEDIATE`
   protect each local update against interrupted writes and concurrent
   local installers.
4. Reinstalling byte-equivalent signed state is idempotent; changing the
   contents of the same generation is forbidden. New generations refuse
   silently replaced key material, revoked-key revival, retiring-key
   reactivation, extended old key-validity windows or implicit key deletion.
   The last installed generation is read from the ledger, not supplied
   by the HTTP caller.
5. The existing host nonce-challenged evidence probe now reads the
   **installed, signature-verified** local trust ledger through the common
   Worker attestation verifier. It cannot select an alternate single-key
   PEM or untrusted JSON keyring in its CLI. The old unsigned diagnostic
   still remains non-authorizing and is not a fallback path for a signed
   host attestation.

## Real local CI acceptance criteria

The gateway test creates the fixture's independently signed generation-2
keyring, installs it twice (the second attempt must be idempotent), and
uses the actual native Pyodide Worker/D1 P-256 response signature through
the host's persisted trust ledger. It rejects tampered signed manifest
updates **before installing** and the absence of a provisioned host
ledger. Unit tests additionally check successive signed generations,
restart persistence, same-generation substitution, wrong operator root,
corrupt storage and key revival attempts. No signed evidence grants
permission to invoke an external adapter.

## Threat model, limitations and next milestone

The SQLite ledger protects against **accidental** rollback with a surviving
database. It does **NOT** detect rollback by someone able to replace or
delete the entire database or alter the independently provisioned operator
root. Its signature protects integrity and origin of local updates relative
to that *ephemeral fixture root*, **not** real-world administrator identity
or deployed Worker provenance. It is not a tamperproof monotonic counter,
KMS/HSM, Secrets Store binding, remote key-distribution system or
two-person change-approval workflow.

Production would require independently protected operator key custody,
authenticated key distribution and deployment identity, hardware-backed or
externally anchored monotonic state, rotation/revocation propagation,
security incident response and live D1/egress verification. We deliberately
do not configure or purchase any such resource in this PR.

**No deploy, live provider request, cloud secrets, remote D1 or blockchain
transaction. Keep issues #2 and #3 OPEN.**
