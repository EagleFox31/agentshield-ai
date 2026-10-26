# Architecture — AgentShield AI

**Status:** Design proposal, not a description of deployed infrastructure.

## Security architecture
```text
Authenticated user task / agent identity
               |
       AI agent orchestrator
               |
    normalized proposed tool call
               v
+---------------------------------------+
|           AgentShield API             |
|  1. Validate schema & authenticated   |
|     principal / delegated scopes      |
|  2. Resolve tool registry & resources |
|  3. Evaluate deterministic policies   |
|  4. Route high-risk action to approval|
|  5. Emit evidence / decision          |
+--------------+------------------------+
               | allow only
               v
    Tool adapter / sandbox / MCP proxy
               |
               v
     Authorized external resource

Audit: decisions -> redacted event store -> hash chain
                                 -> optional batch Merkle root
                                 -> optional EVM testnet anchor
```

## First-class domain objects

### ActionRequest
- `request_id`: replay-safe unique identifier
- `agent_id` and authenticated `principal_id`
- `tool_id`, `operation`, canonicalized `resource`
- `arguments`: validated data; never log raw secrets
- `delegated_scopes`: capability bounds independently authenticated
- `context_signals`: advisory observations, explicitly untrusted
- `intent_reference`: identifier for trusted user-approved intent

### PolicyDecision
- `decision`: `allow | deny | require_approval`
- `reason_codes`: deterministic control identifiers
- `policy_version`: immutable rule set reference
- `decision_id`, `request_digest`, `expires_at`
- `evidence_ids` and safe redacted explanation

### ApprovalGrant
- authenticated approver
- exact action digest and resource/operation scope
- expiration, replay protection and immutable decision trail
- cannot exceed the user's original delegated privileges

## Proposed policy lifecycle
1. Authenticate the caller and validate schemas.
2. Canonicalize target resource, operation, arguments and effective privileges.
3. Evaluate hard deny rules, scope constraints and required approvals.
4. Record a privacy-minimized decision event.
5. Return an explicit decision; a tool adapter executes only an `allow` decision.
6. Optionally run heuristic/AI triage for analyst context. **The model cannot elevate a deny to allow.**

## Data and privacy
- Encrypt in transit and at rest; segregate tenants if multi-tenant support is introduced.
- Treat the audit log as security-sensitive, with strict access and configurable retention.
- Retain only normalized metadata and bounded redacted evidence, not raw prompts by default.
- Use authenticated event producers, forward-secure ordering and tamper-evident verification.
- Anchor aggregate hashes rather than individual events. Verification detects modifications **after recording** but does not prove original event accuracy.

## Interfaces & extension points
- **Planned:** Python SDK / proxy adapter for one selected agent framework.
- **Planned:** MCP-compatible tool proxy, contingent on conformance/security testing.
- **Deferred:** dashboard, orchestration UI, multi-agent collaboration and production blockchain integration.

## Decisions pending ADRs
- API authentication and agent identity issuance
- Rule language and canonicalization semantics
- Approval transport and user identity proof
- Database and retention strategy
- Which framework adapter to support first
- Signature/hashing scheme, batch windows and verifier trust roots

## Definition of Done for core controls
A control is not considered implemented until it has positive, negative and bypass tests, observable error behavior, threat-reference mapping, documentation and a CI check.
