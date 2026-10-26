# ADR-0007 — Hybrid detection with deterministic authority

- **Date:** 2026-10-26
- **Status:** Accepted for MVP, staged delivery

## Context
Heuristics/ML can help prioritize prompt-injection attempts and suspicious tool-use sequences but cannot reliably establish authorization. A model verdict is probabilistic and susceptible to manipulated prompts.

## Decision
Implement versioned **deterministic** abuse rules and a safe regression fixture set first. Optionally call an isolated AI analysis adapter to produce **advisory** risk indicators with evidence IDs, model/provider version and cost/latency metadata. Its input is minimized and redacted. AI may flag an already policy-allowed call for additional review **only under a documented policy**; it can never turn `DENY` or `REQUIRE_APPROVAL` into `ALLOW`, grant scopes, create approval grants or execute tools. If AI is unavailable, deterministic policy behavior continues, with an explicit `triage_unavailable` signal.

## Alternatives
- Rules only: MVP baseline and offline fallback.
- AI as authorizer: explicitly rejected.

## Acceptance
Publish synthetic adversarial fixtures and a confusion matrix including false positives/negatives; ensure AI error, timeout or malicious suggestion cannot cause privilege escalation. Provider support remains optional to keep local tests and security controls independent of inference costs.

## References
- [Threat model](../THREAT_MODEL.md)
- [MVP scope](../MVP_SCOPE.md)
