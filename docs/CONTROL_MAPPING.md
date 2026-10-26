# Security control mapping

**Interpretation:** The standards and frameworks below guide the design. AgentShield has not been audited, certified, benchmarked or assessed as compliant with any of them.

| Control objective | External reference | AgentShield planned evidence | Current status |
| --- | --- | --- | --- |
| Preserve agent task intent | OWASP Agentic ASI01; MITRE ATLAS | Trust-boundary policy tests and attacker-controlled context fixtures | Planned |
| Prevent unauthorized tool use | OWASP Agentic ASI02 | Deny-by-default policy decisions and scope test suite | Planned |
| Enforce least privilege | OWASP Agentic ASI03; OWASP MCP02 | Scoped identities, expiring grants, policy tests | Planned |
| Constrain dangerous execution | OWASP Agentic ASI05; OWASP MCP05 | Restricted tools, sandbox adapters, command validation tests | Planned |
| Defend against malicious tool outputs | OWASP Agentic ASI04/ASI06; MCP03 | Trusted tool registry, schema and provenance checks | Planned |
| Make high-impact decisions reviewable | OWASP Agentic ASI09 | Exact-action approval, expiry and replay tests | Planned |
| Trace security decisions | OWASP MCP08 | Structured audit metadata, retention and integrity verifier | Planned |
| Manage AI risks over the lifecycle | NIST AI RMF / AI 600-1 | Threat model, evaluation, incident handling and documented residual risk | Planned |
| Catalog AI adversary behavior | MITRE ATLAS | Mapped adversarial cases and detection coverage report | Planned |

## Evaluation targets (proposed, not measured)
- 100% of **enumerated high-risk sample actions** blocked or routed to approval in the public test suite.
- 100% of unspecified tool/operation combinations denied in deterministic policy tests.
- Demonstrate approval expiry/replay protection with repeatable negative tests.
- Publish confusion matrices for detection heuristics, including false positive and false negative counts.
- Benchmark policy-gateway latency on representative local workloads and publish environment details.
- Verify deliberate event tampering against an independently implemented verifier.

**No unmeasured percentage will be marketed as a real security detection rate.**

## References
- [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI RMF / Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
