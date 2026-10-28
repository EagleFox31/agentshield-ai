# Offline egress capability preflight — issue #3 (P0)

**Stage:** security-checking prototype, not a network connector. Absolutely no live DNS, TCP, TLS, HTTP fetch, deployment, remote D1, provider action, or blockchain transaction is performed.

## Threat model / RAIDER

The previous [fenced mock boundary](FENCED_MOCK_DISPATCH_BOUNDARY.md) already requires independent ES256 operator claim, original agent JWT, exact active tenant policy, stored decision and audit, and a one-shot local invocation reservation. This milestone adds a **separate, reusable stdlib-only egress preflight** to prepare future network adapters without enabling a bypass today.

- A code-reviewed `EgressCapability` defines an **exact** action digest, GET-only method, HTTPS-only scheme, FQDN and port 443, plus an exact path. The only current fixture is `https://api.invoices.example/v1/invoices/42`; `.example` is a reserved non-live domain. **No agent/client may provide a destination, host, URL, port, credentials, DNS response or policy override to the HTTP endpoint.**
- The validator checks that the signed principal's exact policy currently evaluates the synthetic invoice read to `allow`. URL validation demands exact match; it never canonicalizes attacker input into a permitted target. It rejects aliases, userinfo, IP literals, alternate ports, fragments, queries, redirects, percent encoding and CR/LF / backslash ambiguity.
- DNS observations are **offline injected fixtures only**. The validator rejects no answers, more than eight answers, malformed records, any mixed public/private set, loopback, link-local, metadata IPs, IPv4-mapped IPv6, reserved/documentation IPs, multicast, non-global and scoped addresses. A synthetic second answer set must match the initial set; a changed answer is rejected.
- **All HTTP redirects are forbidden**, even same-origin ones. A redirect must never automatically turn an approved destination into a private endpoint.
- `DisabledNetworkTransport.send` **always fails**. No socket, Cloudflare `fetch`, HTTP client or importable live provider transport exists. The success response of `POST /_local/egress-inspection` reports `network_enabled:false`, `transport_pinned:false`, `execution_authorized:false`, `real_tool_called:false`, `enforcement_ready:false`. It is not an execution permit.

### What the checks do **not** prove

**A standalone preflight CANNOT stop DNS rebinding if a real HTTP client re-resolves the hostname after inspection.** A future provider connector must enforce an end-to-end connection to a vetted pinned address *while authenticating the certificate and SNI for the original hostname*, prohibit proxy/environment URL substitution, and re-evaluate redirects and upstream service hops through the same policy. Cloudflare Workers' standard fetch APIs must not be assumed to support arbitrary per-connection DNS/IP pinning; do not attach a live fetch to this module until a deployment-specific design and proof exists.

Other release requirements: signed tenant/provider capability registry and versioning, credentials isolated in a secret manager, request and response streaming size/time limits, non-GET mutation approvals, egress audit correlation to immutable command/claim, provider-side idempotency and crash outcome reconciliation, private DNS/egress controls, rate limits and independent adversarial security review. No live action is safe based only on these checks.

### Tests

- Standard library unit tests reject localhost, 169.254.169.254 and other private/reserved addresses, IPv4-mapped IPv6, non-ASCII/encoded URL bypasses, scheme/host/path/port aliases, all redirects, mixed DNS answers and synthetic DNS rebinding. Incorrect actor scopes and unknown tools fail closed.
- The existing Worker/Pyodide/local D1 workflow validates the **signed tenant's active policy**, exercises code-owned fake DNS scenarios, requires 409 for unsafe targets, 401 for wrong trust root, 422 for client URL/DNS injection and 404 for absent public route. The offline public-IP fixture is a test value, **not evidence of an actual resolution**.

**The tool execution boundary remains local and fake; issue #3 remains open.** The existing Merkle audit demonstration is still off-chain and no root has been anchored on EVM.
