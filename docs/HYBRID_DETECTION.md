# AgentShield AI — Hybrid threat triage (MVP local baseline)

**State:** deterministic signal engine and model-provider **interface**, tested against synthetic cases. **No live inference provider connected, no remote processing, no cloud deployment or real tool execution.**  
**Issue:** [#4](https://github.com/EagleFox31/agentshield-ai/issues/4) · [ADR-0007](adr/0007-hybrid-detection-advisory-only.md) · [OWASP Prompt Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

## Critical separation: evidence ≠ authorization

A retrieved invoice, tool output or external page can suggest an instruction. The detection layer extracts **advisory-only** risk signals, but a verified agent JWT, deterministic `PolicyEngine`, durable SQLite/D1 audit, and any required human approval still decide if an action may run.

`assess_threat(decision, sources, observations, model=None)` accepts an already-evaluated **trusted PolicyEngine Decision** and returns it **unchanged**. It has no method for authorizing tools, issuing JWTs/scopes, creating approvals or executing side effects. A model error, timeout or false reassurance **never** elevates `DENY` or `REQUIRE_APPROVAL` to `ALLOW`. The local dashboard continues to show `enforcement_ready: false`.

## Detection pipeline

| Stage | Source | Output | Authority |
| --- | --- | --- | --- |
| Deterministic policy | Trusted identity + exact operation | ALLOW, DENY or REQUIRE_APPROVAL | **Sole authorizer** |
| Text heuristics | Bounded, transient text from externally retrieved documents/tools | Fixed reason codes + opaque evidence IDs | Advisory only |
| Action-sequence heuristics | Structured redacted tool categories and policy outcomes | Repeated-deny and sensitive-after-read indicators | Advisory only |
| Optional model adapter | **Only** versioned signal codes, feature counts and opaque evidence IDs | One allowlisted risk code, a known-evidence reference, bounded model version and locally templated summary | Advisory only |
| Local human dashboard | Verified operator JWT | Read-only synthetic triage result | No tool execution |

Rules in `src/agentshield/detection.py` include: `INSTRUCTION_OVERRIDE`, `ROLE_SPOOFING`, `PRIVILEGE_REQUEST`, `CREDENTIAL_EXFILTRATION`, `AUDIT_EVASION`, `TOOL_AUTHORITY_SPOOF`, `HIDDEN_UNICODE`, `SENSITIVE_ACTION_AFTER_READ`, and `REPEATED_DENIED_ACTION`.

*These are imperfect signatures, not a proof of malicious intent.* Limit each source to 8192 characters for transient inspection and report `SOURCE_TRUNCATED`/incomplete when longer. Inputs remain untrusted even if no rule matches. In particular, quoted fiction may be falsely flagged and an attacker can paraphrase around keyword rules.

## AI adapter contract and minimization

An implementer can supply an asynchronous `TriageAdapter.classify(RedactedFeatures)` without changing the policy engine. Its *only* input is a typed `RedactedFeatures` object:

- `schema`, `rule_version`, fixed `signal_codes`, opaque `evidence_ids`, `sources_scanned`, `observations_scanned`.
- **Never** original documents, raw prompts, tool parameters/resources, customer details, invoices, provider credentials, identity tokens or bank account values.
- The model response must have **exactly** `risk_code`, `evidence_ids`, `model_version`; the code must be from a finite allowlist, evidence IDs must already exist, and the analyst sentence comes from a **local template**. Any extra `allow`, `scope`, `approved`, `tool_call`, free-form answer, unknown evidence citation or invalid model version is rejected.
- The model has a strict bounded timeout (default 250 ms, maximum one second), with explicit `timeout`, `not_configured` or `unavailable_or_invalid`. Invalid models and outages do not silently claim AI coverage.
- No provider is installed or configured in this milestone, and test models are **in-memory fakes only**. A later connector must separately pass privacy/cost/runtime/network/provider security review before real inference is allowed.

The source text **can still contain sensitive material during in-memory inspection**; this layer promises minimization of *outgoing triage features* and response payloads, not magical elimination of all sensitive-data risk. Do not log source/model exceptions.

## Reproducible adversarial corpus and metrics

```bash
PYTHONPATH=src python scripts/evaluate_detection.py --assert-contract
PYTHONPATH=src python -m unittest discover -s tests/gateway -p 'test_detection.py' -v
```

The versioned corpus `tests/fixtures/detection_v1.json` has **16 synthetic cases**: 8 malicious-intent fixtures and 8 benign. It deliberately includes a semantic attack missed by keyword rules and a benign fictional quote that triggers a false alarm. The script reports a confusion matrix, precision/recall/FPR/FNR and observed per-fixture runtime on the local test machine; the exact values are snapshot-regression data only, not empirical claims about production traffic.

**Known result for this curated corpus:** TP=7, FP=1, TN=7, FN=1 (precision=87.5%, recall=87.5%, FPR=12.5%, FNR=12.5%). The sample is too small and manually written to establish population statistics or a provider's performance. Runtime overhead varies by machine; only actual CI run measurements are useful.

Also covered in negative tests: forged model advice to allow restricted tools or grant scopes, hallucinated evidence IDs, prompt/credential leakage, malformed model output, timeout, exception, Unicode-obfuscated instructions, repeated denials, and current policy effect invariant.

## Local dashboard, no hosted AI

With the previous [local Worker setup](APPROVALS_LOCAL.md), open `http://127.0.0.1:8787/_local/dashboard` using the **human operator JWT**. Select **Threat triage (rules only)**. This calls:

```bash
curl -H "Authorization: Bearer $(cat .local-jwt/operator_valid.txt)" \
  http://127.0.0.1:8787/_local/demo/threat-triage
```

It examines a *fixed synthetic invoice fixture* and sanitized sequence, confirms baseline `policy_effect:deny`, and returns code/evidence signals. `model_status:not_configured` explicitly states that no AI provider was contacted. An agent token cannot access the human operator triage endpoint. Responses never include the raw invoice, provider API keys or model prompts.

## Limits and future gates

- This is a deterministic **triage MVP plus optional AI adapter contract**; not an operational LLM classifier, live SOC dashboard, general injection filter or production threat detector.
- The detector has no authority to unblock a denial or bypass a human approval. Model-based escalation of otherwise allowed actions would require a **separate explicit policy change**, tested before the execution boundary; this MVP does not create such a change.
- Repeated-denial signals currently analyze a **bounded supplied sequence**, not persisted real-time streams from every agent. No distributed aggregation, incident alert delivery, training data collection or provider inference runs.
- Must benchmark on independent attacker/benign corpora and measure alert fatigue before real user-facing deployment. Protect retention and avoid sending private text to third parties.
- AppFactory Project Automation and GitHub CI must stay deployment-free.

## RAIDER

**Reusable** typed security reports; **Agnostic** no model provider/Cloudflare dependency in the detector; **Idempotent** pure deterministic source/sequence analysis; **Durable** versioned reasons/corpus and explicit model failure statuses; **Engineering-grade** source minimization, bounded time/input, adversarial tests and evidence-only advice; **Retroactive** reuses #3 policy core, #10 JWT, #11 audit, #12 approval and #13 invoice fixture without replacing any of those security gates.
