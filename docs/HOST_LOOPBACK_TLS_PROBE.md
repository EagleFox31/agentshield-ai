# Host-only real loopback TLS probe — issue #3, P0

**This is an isolated real TCP/TLS integration checkpoint, not a deployable HTTP proxy.**
There are no external provider calls, real LLM tool executions, production Cloudflare binding, public route, remote D1 writes or blockchain transactions.

## Why this step

PRs #49–#50 supplied deterministic simulated SSRF and TLS/peer contracts. Such contracts cannot establish real certificate verification or prove that the TCP connection goes to the selected address. This checkpoint demonstrates actual OS socket and TLS behavior **only against an ephemeral test server bound to `127.0.0.1`**.

The host-CPython-only module `host_loopback_tls.py` reuses the single reviewed `_LOCAL_INVOICE_CAPABILITY` (fixed `api.invoices.example`, GET `/v1/invoices/42`) and the **existing** `PolicyEngine` and canonical action digest. It deliberately does **not** import into the Cloudflare Worker gateway and is not connected to the outbox or dispatcher.

### Transport controls exercised by an actual socket

1. The function accepts a literal TCP destination only if `selected_ip == "127.0.0.1"`. No hostname DNS resolution, proxy or arbitrary remote-IP parameter can be used. The test server chooses an ephemeral local port; the function rejects invalid port types/ranges.
2. A real `socket.create_connection((selected_ip, test_port))` connects to this literal IP and `getpeername()` verifies the real TCP peer before and after the TLS handshake.
3. `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` requires certificate-chain validation, automatic **hostname verification against the original, code-owned `api.invoices.example`**, TLS 1.3, and a test-only CA explicitly supplied by the hermetic test fixture. The TLS handshake sends SNI for that original name even though TCP connects to `127.0.0.1`. No insecure `verify=False` or `check_hostname=False` path exists.
4. The only request is a hard-coded HTTP/1.1 GET of the reviewed path and a Host header for the original name. No JWT, API token, agent-created URL, arbitrary HTTP header or provider credential is transmitted.
5. The response parser accepts only the exact `HTTP/1.1 200 OK`, rejects redirects (without following them), duplicate/folded/malformed headers, transfer/content encoding, missing/ambiguous content length and large headers. It enforces a 16-KiB response and a **single 2-second monotonic deadline** across connection, TLS, request and reading; incomplete responses fail closed.
6. The response is not returned to the caller: only a SHA-256 of its body and byte count are reported. The typed receipt explicitly reports `network_used:true` (local TCP/TLS was used) but `external_network_used:false`, `execution_authorized:false` and `production_ready:false`.

### Tests

`tests/gateway/test_host_loopback_tls.py` generates a fresh temporary CA and ECDSA server certificates **at test runtime**, not in the repository. Its server listens exclusively on the OS loopback address. It tests the genuine negotiated peer/SNI/certificate, wrong hostname and invalid trust root, denied action/scopes, attempted non-loopback IP, HTTP 302 to metadata, oversized bodies, chunked response, duplicated lengths, truncated body, excessive headers and total-deadline failure. No internet or public service is contacted.

The existing Worker/D1 compatibility CI will continue to run its other signed-agent and outbox tests; it does **not** import or activate this host-only module. The Python host CI runs the real loopback TLS tests.

## Production release blockers

This deliberately **cannot** contact `api.invoices.example` or any public address: the loopback restriction is non-configurable, and the hostname is still a reserved `.example` placeholder. The caller-supplied ephemeral CA is test input, not a trusted production PKI. A real production proxy needs all of the following independently reviewed before any remote connection:

- Strict egress sandbox and verified public-IP destination pinning for every address family, plus DNS policy, direct-connection enforcement, TLS trust-store governance, redirect disabling and SNI original hostname assurance.
- Separate service identity, tenant-bound signed authorization and service-to-service auth from the existing audited outbox reservation; the host helper is **not** an execution capability and has no connection to the policy/approval API.
- Provider-specific authenticated API bindings, credentials in a secret manager, request/response streaming limits, timeout/connection-pool protection, sensible status handling, idempotency keys and outcome reconciliation after crashes.
- Host/Cloudflare deployment architecture, WAF/rate control, secret rotation, observability, independent security review and real adversarial integration before enabling any customer traffic.

This checkpoint is evidence that the **host OS/TLS primitive can bind an IP and verify an original hostname under local test**, not proof that the eventual production proxy is safe. Do not deploy and do not close issue #3.
