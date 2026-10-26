# AgentShield AI

**A security gateway for autonomous AI agents — built to make tool calls auditable, constrained and safer by design.**

> **Status: design and foundation.** No production security guarantees or released detection engine yet. This is an independent open-source project by [EagleFox31](https://github.com/EagleFox31).

## Why AgentShield?

AI agents can execute tools, retrieve untrusted content and trigger actions on a user's behalf. These capabilities create new attack paths: prompt injection, unsafe tool use, excessive privileges, credential exposure and weak auditability.

**AgentShield AI** is being designed as a policy-first protection layer **between the agent and its tools**. Its primary job is to enforce deterministic safety boundaries, with AI-assisted triage as a complementary capability rather than the final authority.

## Planned MVP

- **Policy gateway:** evaluate each proposed tool call against explicit allow, deny and require-approval rules.
- **Runtime signals:** flag suspicious instructions and tool-use patterns; expose the supporting evidence.
- **Human-in-the-loop controls:** require approval for sensitive actions such as external writes or privilege changes.
- **Tamper-evident audit log:** record structured, privacy-minimized security events with integrity proofs.
- **Optional blockchain anchoring:** periodically anchor batches of audit hashes on a testnet without putting prompts, credentials or sensitive data on-chain.
- **Developer integrations:** publish a documented local API and a minimal integration example.

## How it is intended to work

```text
AI agent -> Proposed tool call
                |
                v
      AgentShield policy gateway
                |
      +---------+---------+
      |         |         |
    Allow      Deny    Approval
      |         |         |
      v         v         v
 Execute    Block +    Human review
   tool      explain       |
      \_________|_________/
                |
                v
      Structured audit events
                |
                v
     Hash chaining / batch root
                |
                v
    Optional testnet anchoring
```

## Architecture principles

1. **Policy before prediction.** A classifier or LLM must never override a deny rule.
2. **Least privilege.** Each agent/tool integration has explicit scopes and action boundaries.
3. **Fail closed** when policy evaluation or required approval is unavailable.
4. **Privacy by design.** No raw customer prompts, credentials or personal information on public blockchains.
5. **Verifiability, not infallibility.** A blockchain proof can detect changes to stored evidence; it does not prove an event was truthful when first captured.
6. **Security claims require tests.** Every advertised defense must have adversarial and regression coverage.

## Technology direction

Python · FastAPI · Pydantic · PostgreSQL · Docker · GitHub Actions · optional EVM testnet

The stack and interfaces will be refined during the threat-modeling milestone. Production hosting is intentionally not assumed.

## Roadmap

- **Foundation:** threat model, policies, tool-call schema and reproducible CI.
- **Policy MVP:** allow/deny/approval decisions with test fixtures.
- **Detection:** runtime signals and attacker-controlled content test cases.
- **Audit:** event integrity, verification and privacy controls.
- **Proof of concept:** optional blockchain anchoring and a public demo.

Development is tracked through the [AgentShield AI GitHub Project board](https://github.com/users/EagleFox31/projects/12), [GitHub Issues](https://github.com/EagleFox31/agentshield-ai/issues) and **[AppFactory Project Automation](https://github.com/EagleFox31/appfactory-project-automation)**. No ZIP-based setup is required.

## Maintainer

Developed independently by **[Jennifer Lawrynn / EagleFox31](https://github.com/EagleFox31)**. Not part of the Trigenys commercial product portfolio.
