# Challenge-bound Worker ES256 evidence attestation — local only

**Scope: proof of origin from an ephemeral local Worker signer, not a
production Worker-to-host connection or permission to execute any tool.**

## RAIDER adoption, not a second security architecture

PR #57 established read-only tenant-scoped access to actual **local**
Pywrangler/Pyodide/D1 evidence under a third independently signed SERVICE JWT.
The host still could not authenticate the origin of an ordinary HTTP reply.

This checkpoint reuses the **same** SERVICE bearer authentication, existing
D1 outbox/claim/dispatch/issuance evidence verification, and native Worker
WebCrypto infrastructure. It only adds a signature to a strictly
versioned payload at a new **local-only** endpoint:
`GET /_local/commands/{command_id}/attested-evidence`.

1. Host CPython generates a new unpredictable **256-bit challenge** with
   `secrets.token_hex(32)` for each request. It sends the challenge in a
   fixed `X-AgentShield-Nonce` header with its separately signed, narrowly
   scoped SERVICE bearer. It connects only to literal `127.0.0.1`.
2. Worker authenticates the tenant/identity, verifies D1 historical
   decision/queue/claim/dispatch/optional issuance evidence, then signs
   **only this fixed redacted evidence schema** using native WebCrypto
   ECDSA P-256/SHA-256, the versioned literal
   `agentshield.local.d1-evidence.v1`, fixed key identifier,
   challenge and a ten-second bounded lifetime.
3. The signing private P-256 JWK is generated fresh by the existing
   ephemeral CI fixture script and written **only** to ignored local
   `.dev.vars`. A separately saved public PEM is provisioned **before**
   the network request. No caller-supplied key, JWKS URL, private key in Git,
   D1 row or HTTP response; no Python cryptography wheel in the Worker.
4. Host verifies a strict JSON shape (duplicate keys forbidden), exact
   challenge/tenant/command/type/kid, bounded timestamp and expiry, canonical
   SHA-256 bytes and **raw WebCrypto P1363 ES256 signature** against the
   independently pinned public key. Altered metadata, replaced key,
   replayed response under a different nonce, expired/future timestamp,
   extra payload fields and any execution-permission claim are rejected.
5. Client reports `source_claim_authenticated:true` only for the
   **ephemeral local attestor**. It explicitly reports
   `production_source_trusted:false` and
   `execution_authorized:false`. No new command, signer issuance,
   outbox transition, approval or external tool dispatch is created.

A genuine local CI test uses the actual Cloudflare Python Worker and local
D1 from PR #57. It also checks that no nonce, invalid nonce, wrong JWT,
and public route cannot elicit a signed response. Unit tests exercise
host cryptographic verification and negative tampering/replay cases.

## Security and production exclusions

A signature proves origin relative to the **provisioned test public key**,
not that Cloudflare produced a trusted deployment or that D1 contents are
authoritative in production. Runtime compromise and a stolen ephemeral
private key can still forge evidence. Local plain HTTP remains restricted to
loopback; the signed payload alone does not imply transport encryption,
durable anti-replay storage, server platform attestation, remote D1 access,
host authorization or safe outbound egress.

**Next gates**: independent audited Worker deployment identity, managed
signing key/KMS or Secrets Store, key-id rotation/revocation,
strict production transport and tenant-bound authoritative D1 reads,
crash reconciliation, and an independently reviewed read-only provider
adapter. No real provider, cloud deployment, paid resources, EVM write or
blockchain transaction enabled here. Keep issues #2 and #3 **OPEN**.
