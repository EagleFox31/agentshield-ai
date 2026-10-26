# AgentShield AI — JWT agent identity v0 (issue #10)

**Implementation stage:** read-only authentication adapter and local cloud-runtime tests. This is **not** an identity issuer, approval system, action gateway or deployed authentication service.

## Auth boundary

```text
Bearer access token from a trusted external issuer
         |
   Fixed server configuration
   (issuer, audience, public JWKS)
         |
   PyJWT + cryptography:
   header algorithm, kid, ES256 signature
   trusted issuer, exact audience
   exp / iat / nbf / bounded TTL
   sub / tenant_id / scope / jti shape
         |
  VerifiedAgent + frozen Principal
         |
  /v1/identity (read-only)
  NOT action execution, NOT an audit receipt
```

- Algorithm **ES256 only**, no `none`, HS256, key URL discovery, `jku`, `jwk`, or header-selected policy.
- JWKS is a bounded JSON collection of verification-only **public EC P-256** keys, from server-controlled configuration. Unknown or duplicate `kid`, unsafe public-key fields, wrong curve/type/algorithm and malformed coordinate data are rejected. A new key can be introduced side by side, then the retired key can be removed after the maximum token lifetime and clock skew.
- Required claims: `iss`, `aud` (strict single audience), `sub`, `tenant_id`, `iat`, `nbf`, `exp`, `jti`, and OAuth-style `scope` string. Max issued token lifetime 5 minutes; hard rejection on missing/invalid claims; only a small fixed leeway for trusted clock skew.
- Effective `Principal` is assembled exclusively from **verified** `tenant_id:sub` and scopes, never an agent body, model output, invoice, or tool result. No wildcards in scope; unknown operations still default-deny in `PolicyEngine`.
- Public keys and issuer configuration are **not** embedded in the application or taken from the token. Set `AGENT_JWT_ISSUER`, `AGENT_JWT_AUDIENCE`, and `AGENT_JWKS_JSON` as trusted Worker environment bindings. These settings must be present to handle authenticated requests.
- `GET /v1/identity` confirms agent/tenant/scopes from validated claims, and always reports `enforcement_ready:false`, `executed:false`. It is the only authenticated remote API surface in this milestone. **It does not grant approval, execute tools, modify policies or record durable audit events.**
- No private signing key is accepted by the gateway. The issuer/service key lifecycle is an independent operational responsibility.

## Test locally (no deploy)

```bash
uv sync --group worker
uv run --group worker python scripts/make_local_identity_fixture.py
uv run --group worker pywrangler dev

# In a second terminal, exercise the isolated identity endpoint:
curl -H "Authorization: Bearer $(cat .local-jwt/valid.txt)" http://127.0.0.1:8787/v1/identity
```

Local fixtures generate ephemeral signing material in **memory**, write four short-lived test tokens under `.local-jwt/` and put **public JWKS** trust settings in `.dev.vars`. Both directories/files are ignored by Git. Tokens are synthetic and cannot authenticate to a real deployed issuer; do not reuse them with external services.

The GitHub Actions local Worker job tests a correctly signed ES256 token and rejects signatures made with the wrong key, wrong-audience tokens, expired tokens, and missing/invalid authorization. The CPython suite separately covers key rotation, algorithm confusion, jku/jwk substitution, tenant forgery, untrusted scopes, missing time fields and invalid identity shapes.

## Deliberate MVP boundaries

- Access tokens are **reusable** during their lifetime; checking `jti` shape does not imply replay prevention. Enforcing one-time actions and revocation requires the planned durable nonce/approval store in [#11](https://github.com/EagleFox31/agentshield-ai/issues/11) and [#12](https://github.com/EagleFox31/agentshield-ai/issues/12).
- Operator/dashboard identity **must be separate**; no human approval credentials are accepted via the agent endpoint.
- This adapter **must not** be reused as a full OAuth/OIDC authorization server, nor should client tokens be stored in logs.
- Hosted trust roots, issuer operational security and JWKS refresh need separate review before deployment. No Cloudflare resources or paid services are created here.
- The local-only diagnostic endpoints from issue #9 remain a **separate development surface**; they are not part of this JWT authentication enforcement.

## RAIDER

Reuse maintained **PyJWT + cryptography**, do not implement ECDSA manually. Pin algorithm and issuer in trusted configuration, keep state-independent verification reusable and tests agnostic, rotate public keys without redeploying the domain policy engine, and validate the same crypto library inside **Pyodide Python Workers**, not only CPython. Add negative fixtures before claiming cryptographic compatibility.

See [ADR-0002](adr/0002-jwt-agent-identity.md), [Cloudflare Python Workers](https://developers.cloudflare.com/workers/languages/python/), and [PyJWT API](https://pyjwt.readthedocs.io/en/latest/api.html).
