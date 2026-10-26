# AgentShield AI — MVP v0.1 scope and acceptance contract

**Baseline date:** 26 October 2026 · **Stage:** specification / no deployment · **Owner:** EagleFox31  
**Decisions:** [ADR index](adr/README.md) · **Delivery:** [GitHub Project #12](https://github.com/users/EagleFox31/projects/12)

## 1. Product goal and demonstrable threat

Demonstrate an agent-tool **authorization boundary** that a malicious supplier invoice cannot bypass. The legitimate user only authorizes `invoice:read`; a retrieved invoice tries to change a supplier bank account. The agent requests `suppliers.update_bank_account`. AgentShield authenticates the caller, derives scope from signed claims, canonicalizes the exact action, applies deterministic policy, records a redacted decision, and refuses the unauthorized write **before any test tool runs**. A separate permitted action can require bounded human approval through dashboard or CLI; a single-use grant permits only that exact authorized test action.

**Security claim boundary:** only requests routed through the gateway are covered. This MVP is a *local/security prototype* until runtime compatibility, hosted persistence and independent deployment review succeed.

## 2. In-scope P0 deliverables

| Surface | Contract / scope | Exit evidence |
| --- | --- | --- |
| Gateway | FastAPI `/v1/` JSON API, strict schemas, rate/size limits, stable reason codes; no arbitrary tool execution | Positive/negative HTTP tests and real security-policy fixtures |
| Identity | JWT asymmetric signature, trusted `iss`/`aud`/`kid`/`alg`, `sub`/`exp`/`nbf`/`iat`/`jti`, verified delegated scopes; separate authorized operator identity | Expired, fake, wrong-audience, malformed, forged-privilege, and cross-tenant tests |
| Policy | Existing Python PolicyEngine; exact action/resource semantics, versioned policy documents and deny-by-default | Existing unit tests remain green; new adversarial/property tests |
| Approvals | Dashboard + CLI acting on one authenticated approval API; single-use action-digest grants; expiry and race safety | Replays, double-spends, changed arguments and missing approver denied |
| Audit | Portable `AuditRepository`, SQLite offline adapter, hosted D1 adapter through Python Worker binding; versioned schema, redaction and bounded retention | SQLite contract suite + D1/local binding smoke; failed audit persistence blocks execution |
| Evidence | Deterministic event hashes + local Merkle batch/verifier with versioned canonicalization and idempotent batch IDs | Tampering/reordering/deletion fixtures detected inside declared coverage |
| Detection | Deterministic suspicious-request rules; **optional** isolated AI triage interface which cannot alter authorization | Fixture-based false positives/negatives; injection into detector never grants privileges |
| Demo | Controlled invoice assistant with a mock invoice reader and supplier write tool; no payment data or real writes | CLI scenario + dashboard shows denied/read/approval/audit events |
| CI | Python tests + schema/ADR checks with narrow paths; no automatic cloud provisioning | Repeatable green CI, negative fixtures, proof-of-done checklist |

**First controlled API contracts (design targets, not yet shipped):**

- `GET /health`: liveness/readiness without secrets; liveness **does not imply** enforcement readiness.
- `POST /v1/decisions`: authenticated proposed action, returns `decision_id`, effect `allow|deny|require_approval`, reason codes, policy version, canonical `request_digest`, and audit reference.
- `GET /v1/decisions/{id}`: authorized, tenant-bound redacted decision read.
- `POST /v1/approvals/{id}/approve` and `.../reject`: human-only exact-action review.
- `POST /v1/test-executions`: restricted mock adapter only, consumes a matching, unexpired execution capability and records outcome.
- `GET /v1/audit/events` and `GET /v1/audit/batches/{id}/proof`: authorized inspection/proof verification; avoid raw sensitive data.
- `GET /v1/policies/active`: read-only version inspection; privileged policy mutation is *not* an MVP public endpoint.

Every mutating endpoint uses replay-safe request IDs, explicit authorization and normalized error bodies. An approval response is **not** executable proof until consumed by the constrained adapter.

## 3. Main data contracts

```text
Authenticated JWT ---> Trusted Principal / bounded scopes
Untrusted agent ---> ActionRequest { request_id, tool, operation, resource, arguments }
                         |
              Canonicalize + hash arguments
                         |
                  Deterministic policy
                   /       |       \
                 DENY     REVIEW    ALLOW
                   \        |        /
               AuditRepository { decision/event, no raw secrets }
                         |
           optional verifier --> Merkle batches --> EVM testnet (later)
```

**Core records:** `policy_versions`, `audit_events`, `approval_requests`, `approval_decisions`, `used_action_nonces`, `evidence_batches`. Primary identity/tenant context must be derived from trusted authentication, never from agent-supplied metadata. Design transactional uniqueness and compare-and-set for approval consumption; do not assume Worker local memory is shared across requests.

**Portable repository interface:** pure domain/core → `AuditRepository` port → local SQLite / hosted Cloudflare D1 binding adapter. A test fixture must pass on both adapters before D1 is considered ready.

## 4. Delivery phases and review gates

1. **P0 — Domain/transport foundation:** FastAPI local app, Python Workers ASGI compatibility smoke, JWT authenticator, schemas, policy adapter. No hosted execution. Links: original #1, #2, #3.
2. **P0 — Reliable decision and approvals:** D1-compatible audit schema, SQLite tests, exact-action grant lifecycle and mock adapter. Gateway fails closed when required auditing/identity is unavailable.
3. **P1 — Observable security MVP:** dashboard, CLI, redacted incident history, negative demo and deterministic detection with optional advisory AI.
4. **P1 — Offline verifiable proofs:** reproducible canonical hashes, Merkle batch verifier and mock blockchain anchor manifest; no testnet funds.
5. **Optional after separate approval:** Python Worker + D1 provision/deploy, R2 export, EVM testnet transaction, richer MCP bridge and model providers.

## 5. Explicit exclusions

- Production Cloudflare Worker deployment, D1/R2 resource creation, DNS, paid service activation or key provisioning in this phase.
- Production blockchain deployment, gas, private key storage in source control, real customer data on-chain.
- Universal MCP proxy/SDK or arbitrary code tool execution.
- Autonomous high-impact actions, approval bypass, authenticated policy mutation by agents or automatic payments.
- Reliance on a detector model as sole authorization source.
- Security certification, penetration-test/compliance claims or invented detection metrics.

## 6. Adversarial Definition of Done

- [ ] Unauthorized supplier-bank write is **never executed** after malicious invoice text; actual mock tool invocation count = 0.
- [ ] Unknown principal/action/resource, excess scope, malformed token, expired approval, revoked approver, replay or audit failure fail closed.
- [ ] Concurrent duplicate grants are consumed **at most once** with durable constraints.
- [ ] Policy, schema, identity and approval tests work offline; D1 Worker binding tests independently validate hosted adapter compatibility locally.
- [ ] All decision artifacts have IDs, policy versions and redacted evidence; no prompt, secret or bank account number persisted by default.
- [ ] An independent verifier detects altered and reordered covered events and reports anchoring status accurately.
- [ ] Optional AI cannot elevate a denied decision or forge approval and provides measured false positives/negatives on published synthetic fixtures.
- [ ] CI is path-scoped, green and deployment-free; tests include a second context beyond finance invoice scenario.
- [ ] Docs distinguish **designed**, **implemented**, **locally verified** and **hosted** states.
- [ ] Product README and GitHub Project reflect real statuses; PRs cite matching issues, close only completed scope.

## 7. RAIDER architecture review

**Reusable:** pure policy/identity/audit contracts, shared through adapters, not product-specific copies.  
**Agnostic:** local SQLite and Cloudflare D1 are replaceable; no repo-specific secrets.  
**Idempotent:** request IDs, unique nonce consumption, evidence batch IDs and safe retries.  
**Durable:** preserve existing PolicyEngine tests and version all public records.  
**Engineering-grade:** fail closed, minimize retained evidence, negative tests and CI impact control.  
**Retroactive:** build around existing README, policy core, threat model and GitHub Project without destroying prior work.

## 8. References and constraints

- [FastAPI on Cloudflare Python Workers](https://developers.cloudflare.com/workers/languages/python/packages/fastapi/)
- [Cloudflare Python Worker bindings](https://developers.cloudflare.com/workers/languages/python/ffi/)
- [D1 Worker binding](https://developers.cloudflare.com/d1/worker-api/)
- [Canonical RAIDER standard](https://github.com/EagleFox31/project-registry/blob/main/RAIDER.md)
- [AgentShield threat model](THREAT_MODEL.md)
