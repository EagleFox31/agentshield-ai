# Independent OS-process host handoff — issue #3, local-only

**Status: separately launched CPython sender and receiver over real mutual
TLS loopback. NO remotely deployed Cloudflare-to-host integration.**

## Scope and RAIDER reuse

PR #55 authenticated a token handoff between two host roles sharing a single
test process. This checkpoint moves the existing **unchanged** TLS sender and
one-shot verifier to **two distinct OS processes** without introducing a
new policy engine, new dispatch, external proxy, or network destination.

- Source of authority stays the prior signed-agent → active-policy → audited
  decision → independent operator claim → synthetic mock dispatch → immutable
  issuance chain from PRs #40–#54. A source ledger permits **one** signed token
  per tenant/command, not an arbitrary tool grant.
- `scripts/local_handoff_process.py receive` starts one TCP listener bound
  exclusively to literal `127.0.0.1`. It accepts exactly one attempt and
  exits. Its TLS 1.3 server certificate and client CA/DER fingerprint come
  from the test fixture; the trusted ES256 issuer public key is provisioned
  separately. Its replay ledger is a **file-backed SQLite database**, with
  full synchronous commits, rather than shared in-memory process state.
- `... send` reads the signed token from standard input (never a command
  argument, environment variable or persisted token file). It authenticates
  the server identity with the previously reviewed code-owned hostname
  `handoff.agentshield.test`, TLS 1.3 and a test trust root, then sends
  one bounded length-framed token. A fixed ACK means only that the receiving
  process completed its independent durable replay burn.
- Both commands require explicit `AGENTSHIELD_LOCAL_HANDOFF_TEST_ONLY=1`
  **before argument parsing**, use the reviewed, loopback-only transport
  functions and output only redacted status, PID and fixed metadata.
  Fixture time is provided explicitly for deterministic *local tests only*,
  not to emulate a secure production clock.

CI runs independent Python subprocesses, inspects different OS PIDs,
authenticates both TLS sides, proves one durable burn, terminates the receiver,
starts a fresh receiver with the same SQLite file and confirms replay is
denied. Negative tests cover certificate substitution, wrong CA, signature
tamper, expiry, tenant mismatch, disabled opt-in and unavailable ledger.
The original synthetic invoice mock remains invoked **once**, before handoff.
No additional tool invocation follows the signed proof.

## Limits and threat model

These processes still run on **the same local host in CI**. Test fixture
certificates are ephemeral files, not operational PKI; nor does this prove
KMS rotation, remote identity issuance, host compromise isolation, remote
Cloudflare D1 authenticity, actual provider IP/TLS egress or result
reconciliation. No background worker, public endpoint, arbitrary listener,
external provider credentials, paid API, remote D1 or blockchain transaction.

If the client loses ACK, consumption is ambiguous: the operator must compare
the immutable source record with the independent host replay database and
later provider evidence. Neither the process runner nor the protocol
reissues tokens or retries delivery automatically. A burned token remains
burned across process restarts. Even a successful ACK explicitly reports
`execution_authorized: false`.

The next production-design gate is **authenticated Worker-to-host evidence
retrieval** with tenant-scoped, immutable remote D1 binding and keys managed
outside tests, followed by a separately reviewed constrained egress boundary,
provider idempotency and crash recovery. Keep issue #3 open.

## Local Worker/D1 SERVICE read-only probe (next P0 increment)

The subsequent checkpoint adds a separately signed service JWT for an actual **local** Pyodide/Worker/D1 reconciliation read, plus an independent host CPython loopback client. This exposes only redacted, audit-verified lineage and **never authenticates the Worker response as a source of execution authority**. See [Worker/D1 host evidence contract](LOCAL_WORKER_D1_SERVICE_EVIDENCE.md). No deployed D1, remote issuer or provider use.
