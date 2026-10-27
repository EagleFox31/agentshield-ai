# ADR-0008 — Candidate Workers AI adapter without deployment

**Date:** 2026-10-27 · **Status:** Implemented for *local fake-binding verification*; live provider selection and external inference are **NOT approved**.  
**Backlog:** [#22](https://github.com/EagleFox31/agentshield-ai/issues/22), [ADR-0007](adr/0007-hybrid-detection-advisory-only.md).

## Decision

Prefer **Cloudflare Workers AI `@cf/meta/llama-3.2-3b-instruct` as a candidate** because AgentShield already targets Cloudflare Python Workers, and its `env.AI.run(model, options)` binding can be dependency-injected without adding HTTP credentials or another SDK. The model is neither installed nor invoked in this iteration: `wrangler.jsonc` has **no AI binding** and the `WorkersAISettings.enabled` default is `False`.

### Provider comparison — verified official material, 27 October 2026

| Candidate | Advantages | Risks / blockers | Decision |
| --- | --- | --- | --- |
| **Workers AI / Llama 3.2 3B Instruct** | Direct Worker binding, lightweight instruction model, published token pricing; Cloudflare says standard stateless inference isn't used for training and has zero data retention subject to exceptions | Still third-party cloud processing and billing; output is probabilistic and can fail exact JSON; Python Worker *real model invocation* untested; receiving only rule codes limits marginal detection value | **Prepared, disabled** |
| Workers AI / Llama Guard 3 8B | Designed for harmful text classification | Its safety classification is **not an agent authorization rule**, and analyzing untrusted raw text would violate this prototype's explicit minimal-payload requirement | Not selected |
| AI Gateway + hosted third-party model | Cross-provider routing and analytics | Gateway logs are enabled by default and can contain request/response payloads; third-party retention, international transfers, key handling, billing and logging review required | **Do not connect** |
| In-process deterministic rules | No model/data-transfer cost, strong reproducibility and explicit evidence | False positives and false negatives; no semantic understanding | **Always-on fallback** |

Cloudflare sources (check again before any deployment):
- [Workers AI binding API](https://developers.cloudflare.com/workers-ai/configuration/bindings/)
- [Llama 3.2 3B documentation & pricing](https://developers.cloudflare.com/workers-ai/models/llama-3.2-3b-instruct/)
- [Workers AI pricing/free allocation](https://developers.cloudflare.com/workers-ai/platform/pricing/)
- [Workers AI data usage and exceptions](https://developers.cloudflare.com/workers-ai/platform/data-usage/)
- [AI Gateway logging default and opt-out](https://developers.cloudflare.com/ai-gateway/observability/logging/)

Cloudflare's published price for this model as checked was approximately **$0.051 per million input tokens** and **$0.335 per million output tokens**; total neuron quota and other platform charges are separate. The model is a **candidate only**. We do not claim a production inference latency or real classifier accuracy because no hosted calls were made.

## Strict data boundary

`WorkersAIBindingAdapter` receives only `RedactedFeatures`, already produced by deterministic rules: rule version, allowlisted signal codes, independently issued **opaque** evidence IDs and bounded item counts. It does **not** see source documents, secrets, raw prompts, account numbers, tool parameters, JWTs or human approval credentials.

The adapter serializes those fields into a fixed system instruction plus a bounded JSON payload. It calls `AI.run` **only** if enabled, injected with a binding, and after an atomic quota reservation succeeds. No retry is performed. It accepts a strictly parsed JSON response with `risk_code` and evidence references only, then inserts a trusted local model-version marker. The existing `assess_threat` validator retains the same fixed allowlists and rejects policy/execution proposals. Provider errors, malformed JSON, budgets and timeouts become explicit `triage_unavailable` or `timeout`; the original policy decision remains unchanged.

Since the model receives *signal codes instead of the original document*, it cannot reliably discover unseen semantic prompt injections. Its possible value is **summarizing/prioritizing signals**, and that incremental value must be proven against a held-out dataset before a live launch. This tradeoff is deliberate for privacy.

## Durable quota gate — SQLite/D1

`migrations/0003_ai_triage_budget.sql` adds a **tenant + UTC-day** quota, and unique request-ID reservations. No quota row means **zero entitlement**. SQLite triggers check both request count and pessimistically reserved tokens in the same transaction. Concurrent Worker instances cannot spend beyond the configured local D1 cap if all inference flows use this adapter and these tables.

Every proposed call reserves **2048 nominal input tokens + 96 maximum output tokens** before reaching the binding. The input is also strictly bounded in characters and includes a fixed system prompt. This reservation is a *coarse conservative application limiter*, **not actual token usage or billing**. Do not promise absolute monetary caps based on estimated tokens: deploy with Cloudflare account-level spend controls, true usage reconciliation, model rate limits, quota expiry/retention and monitoring after explicit review.

An idempotency key (`tenant,utc_day,request_id`) can be reserved at most once. A retry will not start another inference; the response from a prior call is not cached. Failed provider calls intentionally consume their reservation to favor no surprise charges and avoid retries. This is safe but not yet an optimized billing protocol.

## Tests and security gates

- Offline fake `AI.run` only: disabled feature, missing D1 budget/binding, exhausted day, malformed provider responses, malicious suggestions, forged evidence IDs, sensitive raw-text leakage and `BENIGN_CONTEXT` cannot elevate `DENY`.
- SQLite and D1 prepared-statement parity; 4-way concurrent SQLite reservations have exactly one winner at a one-call cap; day/tenant isolation and replay checks.
- Actual **local Python Worker/Pyodide** tests use a *canned in-process fake* and the **real D1 budget**. The fake explicitly does not invoke `env.AI`. The third request after a 2-call test quota returns `triage_unavailable`.
- The existing signed-agent vs signed-operator separation remains in force. No new public endpoint or real tool execution.
- `wrangler.jsonc` must remain **without** `ai.binding`. No account, model, secret, wallet, remote D1, or deployed Worker was created.

## What remains in issue #22

**Keep issue #22 open** until actual provider activation is authorized. A future implementation must obtain an explicit permission decision for cost/data processing, add a dedicated reviewed AI binding, test the Python Worker FFI against a real (sandbox) Workers AI call, validate the provider's exact response contract and token usage, reconcile usage against D1, measure quality on an *independent, held-out* red-team corpus, and confirm billing/logging/privacy settings. A real model's false-positive/negative rates and invocation latency remain **unknown**.

RAIDER: reuses existing policy and redacted features, isolates the binding at a single pure Python port, makes budget idempotent/durable, uses Cloudflare's native D1 and binding shapes, documents false claims before they happen, and provides repeatable adversarial regressions.
