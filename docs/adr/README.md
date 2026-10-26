# AgentShield AI — Architecture Decision Records

**Status:** user decisions accepted 26 October 2026. ADRs specify the target; they do **not** mean features are deployed.

| ADR | Decision | State |
| --- | --- | --- |
| [0001](0001-fastapi-security-gateway.md) | FastAPI enforcement API | Accepted |
| [0002](0002-jwt-agent-identity.md) | Signed, short-lived JWT principals/scopes | Accepted |
| [0003](0003-extend-existing-policy-engine.md) | Preserve/extend Python PolicyEngine | Accepted |
| [0004](0004-human-approvals-dashboard-cli.md) | Dashboard + CLI human approvals | Accepted |
| [0005](0005-cloudflare-d1-audit-storage.md) | Hosted Cloudflare D1 + local SQLite adapters | Accepted; updates previous SQLite-only suggestion |
| [0006](0006-merkle-evm-proof-boundary.md) | Off-chain Merkle roots + optional EVM testnet anchor | Accepted as architecture |
| [0007](0007-hybrid-detection-advisory-only.md) | Deterministic policy + optional AI triage | Accepted |
| [0008](0008-cloudflare-python-workers-deployment-target.md) | Cloudflare Python Workers and D1 target; no deployment | Accepted pending smoke tests |

**Status semantics:** accepted architecture != implemented or production ready. Changes require a new decision or a superseding ADR; preserve history.

See [MVP scope](../MVP_SCOPE.md), [architecture](../ARCHITECTURE.md), [threat model](../THREAT_MODEL.md) and [GitHub Project](https://github.com/users/EagleFox31/projects/12).

**Cloudflare runtime compatibility gate:** Cloudflare's official FastAPI Python Worker documentation currently shows Python >=3.13 packaging in Worker examples. The existing pure Python policy package declares >=3.11. These versions must be reconciled by tested adapters, not silently broadened or broken.

**RAIDER:** reusable and agnostic core, fail-closed behavior, idempotent audit/approval, traceable tests and retroactive adoption.
