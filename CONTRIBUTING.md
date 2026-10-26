# Contributing to AgentShield AI

Thank you for improving an open-source project focused on practical security boundaries for autonomous agents.

## Before contributing
1. Check the [roadmap and issues](https://github.com/EagleFox31/agentshield-ai/issues).
2. For substantial changes, open an Issue describing your proposed threat, defense, interface or test scenario.
3. Keep security controls deterministic wherever possible; a language model may help explain risk, but must not be the only authorization mechanism.
4. Never commit real prompts, credentials, access tokens or user-identifying data.

## Contribution quality bar
- Include tests for both allowed and denied paths, plus failure/replay cases when relevant.
- Document scope, guarantees, exclusions and limitations.
- Link affected threats to an OWASP ASI/MCP identifier or MITRE ATLAS technique where applicable.
- Use Conventional Commit subjects (`feat:`, `fix:`, `docs:`, `test:`, `security:`).
- Avoid promising compatibility, detection rates or production hardening without evidence.

Project development is managed by [AppFactory Project Automation](https://github.com/EagleFox31/appfactory-project-automation). Technical work belongs in the existing GitHub repository and its Issues, not separate ZIP deliverables.

Security issues: follow [SECURITY.md](SECURITY.md) rather than opening a public exploit report.
