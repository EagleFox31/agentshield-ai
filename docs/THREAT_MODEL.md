# Threat model — AgentShield AI

**Status:** Design security review candidate v0.2 (implementation and reviewer acceptance separate) | **Scope:** Proposed MVP, local prototype only

## System boundary

AgentShield is an enforcement gateway invoked **before** an agent's tool call reaches an external capability. Any tool execution path not routed through AgentShield is **outside the enforcement boundary**. Tool adapters, infrastructure credentials and host-level permissions must still be constrained independently.

### Assets to protect
- Secrets, tokens, delegated OAuth scopes and service credentials
- User-approved task intent and permitted resource boundaries
- Sensitive external systems: filesystem, databases, payment APIs, repositories and messaging
- Audit-log integrity and approval records

### Adversaries and untrusted input
- External documents, webpages, retrieved chunks and tool responses containing malicious instructions
- Compromised or malicious MCP tool descriptions and servers
- Untrusted agents or third-party plugins requesting excess access
- Unauthorized insiders and accidental over-privileged configurations

### Trust boundaries
1. **User intent → orchestrator:** establish scope, identity and available privileges. Natural language alone is not an authorization token.
2. **LLM intent → tool gateway:** all tool calls must be normalized and deterministically evaluated.
3. **Gateway → host execution:** enforce resource-scoped credentials and environment isolation; return explicit decisions.
4. **Tool response → model context:** treat tool output as data, never privileged instructions.
5. **Events → evidence store:** redact secrets, authenticate producers and make changes detectably auditable.
6. **Evidence store → public chain:** anchor only batch fingerprints, never raw content.

## Abuse-case matrix

| Threat | Example (defensive scenario) | Required control | Reference |
| --- | --- | --- | --- |
| Goal hijack | Retrieved page requests exporting a secret | Separate trusted intent from untrusted context; policy denies exfiltration tool | OWASP ASI01 |
| Tool misuse | Agent attempts an external transfer without approval | Allow/deny/approval policy at tool boundary | OWASP ASI02 |
| SSRF / internal metadata access | Retrieved instructions induce an HTTP tool to request an internal IP, link-local metadata or redirect to a private host | Default-deny unknown HTTP tools; enforce destination allowlist, validated scheme/host/port, DNS resolution and redirect checks at a constrained execution adapter; disallow credentials on untrusted destinations | OWASP ASI02 / ASI05 |
| Identity & privilege abuse | Tool receives wildcard cloud scope | Per-agent scopes, expiry and service-side authorization | OWASP ASI03 |
| Supply-chain / tool poisoning | A tool changes schema or misrepresents output | Tool registry trust, schema pinning, signed manifests where available | OWASP ASI04 / MCP03 |
| Unexpected code execution | Agent asks shell tool to execute an arbitrary snippet | Default deny, sandbox, command parameter validation | OWASP ASI05 |
| Memory poisoning | Stored content attempts to change authority rules | Data/instruction separation and isolated memory | OWASP ASI06 |
| Inter-agent spoofing | Untrusted agent falsely claims supervisor privileges | Authenticated agent identity and explicit delegation policy | OWASP ASI07 |
| Cascading failures | One failed tool causes broad unbounded remediation | Limits on retries, scope and blast radius | OWASP ASI08 |
| Human-agent manipulation | Approval request hides the sensitive action | Canonical risk summary, approval authenticity and expiry | OWASP ASI09 |
| Rogue agent | Agent repeatedly attempts denied operations | Rate limits, policy revocation and audit events | OWASP ASI10 |

## Security invariants (to be tested)
- Unknown tools and unbound resources are denied.
- A model-generated rationale cannot authorize an action.
- Requested privileges cannot exceed the authenticated principal's effective scope.
- An approval is scoped to an exact action digest, expires and is single-use.
- Sensitive arguments are redacted before evidence persistence.
- Gateway errors and unavailable approvers never become silent allow decisions.
- Blockchain verification never substitutes for collection integrity or source authentication.

## Control-to-test traceability and residual risks

| Invariant / abuse scenario | Current evidence | Remaining enforcement gap |
| --- | --- | --- |
| Unrecognized tool, resource or operation => deny | `tests/test_policy.py::PolicyEngineTests.test_unknown_tool_operation_resource_and_actor_are_denied`; `src/agentshield/policy.py` | Protect only calls that pass through the policy gateway |
| Insufficient principal scope => deny | `test_required_scope_cannot_be_supplied_by_untrusted_action` | Signed identity integration into public action endpoint remains incomplete |
| Explicit deny over allow and approval over allow | `test_explicit_deny_overrides_allows`, `test_human_approval_has_precedence_over_allow` | Do not treat review request as execution capability |
| Prompt injection cannot grant additional permissions | `test_prompt_injection_cannot_extend_permissions` | Does not prove detection of all injections |
| SSRF and redirection to private destinations | Threat scenario and intended adapter contract above | **Not implemented or tested end-to-end**: network-capable adapter must reject private/link-local/multicast/loopback targets after DNS resolution and every redirect; add rebinding tests before enabling HTTP tools |
| Approval expiration/replay, redacted audit, failsafe persistence | Local approval/audit code and regression suites developed in subsequent issues | No hosted enforcement/readiness claim; verify cross-boundary end-to-end in #3 |

**Review boundaries:** This document inventories intended controls and traces existing test evidence, rather than attesting production security. Reviewer sign-off must verify scenarios, mappings, coverage gaps and explicit risk acceptance before converting this design review candidate to accepted design.

## Authorization decision contract (design scope)

The gateway must derive tenant, principal and **effective** delegated scopes from verified authentication, rather than tool arguments, model content or retrieved documents. Policy checks apply to a canonicalized tool, operation and resource **before execution**:

1. `deny`: unknown action/resource, explicit deny, or missing scope; never execute or invite an approval override of an explicit deny.
2. `require_approval`: only a specifically scoped action eligible under policy may be reviewed by an independently authenticated operator; grant must bind the exact action digest, tenant, actor, scopes and expiry, with atomic one-time consumption. A pending approval is **not** an execution token.
3. `allow`: only for a recognized, authorized action with adequate scope, and only when the corresponding constrained adapter is implemented, authenticated and its required audit can be persisted. `allow` is a policy decision, not proof that execution succeeded.

The first prototype covers policy evaluation and local mock execution; it does not yet expose a production-ready public authorization/execution endpoint. On missing audit storage, malformed identity, unavailable approver, unknown tool, inconsistent state or timeout, **do not execute**. Model triage is advisory and never changes the policy effect.

## Data minimization and incident evidence requirements

- Persist only a bounded, redacted decision/event schema: opaque event ID, tenant and authenticated principal references, canonical **action digest**, policy/ruleset version, effect, reason codes, UTC timestamp, and an explicit retention boundary. Do not save invoice bodies, prompt contents, plaintext credentials, JWTs, account details, arbitrary tool arguments or third-party response bodies.
- Apply evidence authentication, tenant isolation, immutable event identity, and rejection/deduplication of replays. Storage errors cannot silently turn a denied or unrecorded action into a successful execution.
- Treat source-derived strings, model recommendations and tool responses as untrusted; evidence of a detected injection is not proof that the source is malicious or that any tool action was executed.
- Document a configurable deletion/retention process and incident responder access policy **before production**; schema fields alone are not proof that lifecycle cleanup or immutable remote storage exists.
- Cryptographic hashes and optional Merkle/testnet anchoring attest only to defined-record integrity, **not** truth of original events, authenticated collection or incident completeness. No raw incident content belongs on-chain.

## Engineering design review record — 27 October 2026

**Review type:** AI-assisted engineering/documentation review for the *design milestone* in issue #1; **not** an independent penetration test, regulatory attestation, or human security sign-off. Reviewed the threat model against `src/agentshield/policy.py`, `tests/test_policy.py`, and the declared local-only gateway boundary.

| Design review check | Result / qualification |
| --- | --- |
| Assets, adversaries and trust boundaries | Documented, including tool responses, agent identity, approval path, audit and optional blockchain proof |
| Prompt injection, poison, privilege abuse, SSRF, secrets, unauthorized execution | Explicit scenarios included, SSRF network/redirect controls identified as *future adapter requirements* |
| Policy semantics and default-deny | Mapped to named deterministic unit tests; runtime network execution and public gateway are excluded from this issue |
| Incident minimization, residual risks and out-of-scope limits | Defined above; production retention, audit independence and SSRF-safe adapter remain future gates |

**Design review disposition:** Acceptable as a documented, scoped *threat-model baseline*, with open implementation risks assigned to the enforcement/approval/audit follow-up work. This review does not authorize live execution, hosted deployment or model calls. Any change to tool capability, HTTP/network exposure or trust boundaries requires a subsequent threat-model revision.

## Excluded from MVP
- Guarantees that all prompt injection is detectable
- Execution isolation for tools that bypass the gateway
- Universal coverage of all MCP and agent frameworks
- On-chain storage of prompts, customer events or raw log records

## Test plan
- Unit and property tests for decision rules, identity and approval binding
- Adversarial input fixtures mapped to OWASP ASI IDs
- Malformed and replayed action requests; token expiry; dependency failures
- False-positive/false-negative reporting for heuristic detection
- Hostile tool response tests and tampered evidence verification

## References
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI RMF: Generative AI Profile, AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
