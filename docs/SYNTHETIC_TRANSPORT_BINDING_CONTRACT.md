# Synthetic transport peer/TLS binding contract — issue #3 (P0)

**Security boundary: NO real network adapter.** This is an offline contract and adversarial fixture suite for a future egress service. It does not perform live DNS resolution, TCP/TLS, socket connection, HTTP fetch, credential forwarding, remote D1 access, blockchain write, or deployment.

## Why PR #49 is not enough

PR #49 validates a reviewed exact HTTPS endpoint, signed-policy eligibility and synthetic DNS answers. But **preflight DNS checks do not protect a hostname-based HTTP client that resolves again during the connection** (DNS rebinding/TOCTOU). A future production tool proxy has to enforce the origin at the actual transport boundary rather than trusting a check returned by the application.

Cloudflare Workers standard [fetch()](https://developers.cloudflare.com/workers/runtime-apis/fetch/) should **not be assumed** to provide an independently verified, application-controlled peer-IP pinning/TLS-SNI contract. The [Workers VPC](https://developers.cloudflare.com/workers-vpc/) and [Containers outbound traffic](https://developers.cloudflare.com/containers/configuration/outbound-traffic/) features provide different egress architectures, but must be separately threat-modelled and validated for this use case. None is enabled here.

## RAIDER implementation

The stdlib-only `bound_transport_contract.py` reuses:

- The existing code-reviewed, non-live `EgressCapability` for the exact invoice-read GET/HTTPS host/path and its canonical action digest.
- The existing `inspect_egress` deterministic current-policy `allow` check and strict public-IP DNS validation.
- The existing ES256 agent JWT and D1 tenant policy in the **local** gateway for demo assertions. The agent never chooses a destination IP, peer IP, certificate, TLS setting or DNS answer.

For an **injected synthetic observation only**, the contract requires an IP selected from the vetted DNS answers to exactly match the connected peer IP; the original code-reviewed hostname to exactly match the destination host, TLS SNI and verified certificate name; a verified chain and hostname; TLS 1.3; no proxy and zero HTTP redirects; exact method and target URL; status 200; maximum 16 KiB response and 2-second observed duration. Rejects missing, inconsistent, private/metadata or mismatched fields, including booleans masquerading as integers.

**Important security distinction:** `SyntheticTransportObservation` is caller-constructible test data. The validator does **not** cryptographically establish that the remote peer or certificate is real. Its result always states `simulation_only:true`, `transport_attested:false`, `network_enabled:false`, `execution_authorized:false`. `send_live_network` always raises, even with an all-green fixture; it cannot be used as a permission token. Nothing here replaces real transport-side verification.

The `POST /_local/transport-binding-inspection` route accepts only a fixed scenario name, never a destination or observation, and derives its principal/policy from the already-required signed agent and D1. It exercises simulated peer-swapping, metadata IP, wrong SNI, invalid certificate, redirect, proxy, oversize, timeout and method substitution. Public `/v1/transport-binding-inspection` remains HTTP 404.

## Requirements before any REAL outbound execution

1. Design a separate egress component with **enforced IP selection + connection peer binding** and verifiable original-host TLS/SNI; prove a client cannot silently re-resolve, follow a redirect, use an environment proxy, downgrade TLS, or route privately. Do not infer this guarantee from unverified user-space metadata.
2. Ensure all external tool operations pass through the existing signed agent → tenant policy → exact action+human approval → canonical audit → one-use outbox reservation boundary; no alternate direct fetch/SDK code path.
3. Implement hard request/response streaming limits, timeouts at the actual socket, credential isolation, provider idempotency and crash/retry reconciliation. HTTP response length fields alone are not reliable size enforcement.
4. Test real local TLS endpoints with controlled DNS rebinding, malicious redirects, alternate IP families, certificate substitution, race conditions, network faults and independent security review before production deployment.
5. Keep the gateway and all outbound transports disabled by default and ensure no bypass through proxy, service binding, worker environments or asynchronous background tasks.

### Evidence

Unit tests use only synthetic injected observations and verify all negative paths. The existing actual **local Pyodide/Worker+D1** smoke checks the signed-tenant route using code-owned synthetic scenarios. Tests are evidence of deterministic **contract checks**, **not** evidence of secure live networking.

No provider action or EVM anchoring occurs. Issue #3 remains OPEN.
