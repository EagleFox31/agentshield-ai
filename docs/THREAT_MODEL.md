# Threat model — AgentShield AI

**Status:** Draft v0.1 | **Scope:** Proposed MVP (not an implementation report)

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
