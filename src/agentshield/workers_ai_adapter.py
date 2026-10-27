"""DISABLED-by-default, provider-bound advisory adapter for Cloudflare Workers AI.

No binding, tokens, dashboard switch or model invocation is provisioned here.
Requires BOTH explicit opt-in and a caller-supplied *durable atomic* budget
reservation. Tests use in-memory fake AI and quota objects only.

This module does not import Cloudflare packages, HTTP clients or operator
credentials. It cannot authorize tools or export raw source documents.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Protocol

from agentshield.detection import RedactedFeatures

MODEL_ID = "@cf/meta/llama-3.2-3b-instruct"
LOCAL_MODEL_VERSION = "workers-ai-llama-3.2-3b-v1"
MAX_OUTPUT_TOKENS = 96
# Ceiling for fixed system instructions + bounded redacted metadata;
# NOT a claim of exact Cloudflare billing or tokenizer counts.
INPUT_TOKENS_RESERVED = 2048
SYSTEM_INSTRUCTION = (
    "You are an advisory security triage classifier, NOT an authorization "
    "engine. These are redacted deterministic signal codes and opaque evidence "
    "identifiers, not raw prompt content. Return exactly a JSON object with "
    "risk_code from [SUSPICIOUS_INSTRUCTION, POSSIBLE_EXFILTRATION, "
    "POSSIBLE_TOOL_HIJACK, BENIGN_CONTEXT, UNCERTAIN] and evidence_ids "
    "as a list of 1 to 8 identifiers from the supplied evidence_ids array. "
    "Never propose permissions, actions, tool calls, identity changes, or "
    "human approvals. No prose, code blocks, extra keys or explanations."
)
_VALID_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,95}$")
_ALLOWED_CODES = frozenset({
    "INSTRUCTION_OVERRIDE", "ROLE_SPOOFING", "PRIVILEGE_REQUEST",
    "CREDENTIAL_EXFILTRATION", "AUDIT_EVASION", "TOOL_AUTHORITY_SPOOF",
    "HIDDEN_UNICODE", "SENSITIVE_ACTION_AFTER_READ", "REPEATED_DENIED_ACTION",
    "SOURCE_TRUNCATED", "SIGNAL_LIMIT_REACHED",
})
_ALLOWED_OUTPUT = frozenset({
    "SUSPICIOUS_INSTRUCTION", "POSSIBLE_EXFILTRATION",
    "POSSIBLE_TOOL_HIJACK", "BENIGN_CONTEXT", "UNCERTAIN",
})


class AIAdapterUnavailable(RuntimeError):
    """No inference happened. Do not include raw provider errors in logs."""


class AtomicBudget(Protocol):
    async def reserve(self, *, estimated_input_tokens: int,
                      max_output_tokens: int) -> bool:
        """Atomically reserve before calling the provider.

        Production implementation MUST be durable across Worker instances
        and enforce per-tenant/account budget + request rate. This repository
        deliberately does NOT provide a production ledger yet.
        """
        ...


@dataclass(frozen=True)
class WorkersAISettings:
    # Feature is OFF unless a deliberate future configuration enables it.
    enabled: bool = False
    model: str = MODEL_ID

    def __post_init__(self):
        if self.model != MODEL_ID:
            raise ValueError("Unreviewed AI model is not permitted")


def _checked_features(features: RedactedFeatures) -> dict:
    if not isinstance(features, RedactedFeatures):
        raise AIAdapterUnavailable("invalid_features")
    if features.schema != "agentshield.triage.features.v1":
        raise AIAdapterUnavailable("invalid_schema")
    if features.rule_version != "agentshield.detector.v1":
        raise AIAdapterUnavailable("unreviewed_rules")
    codes, identifiers = features.signal_codes, features.evidence_ids
    if (not isinstance(codes, tuple) or len(codes) > 32
        or any(not isinstance(c, str) or c not in _ALLOWED_CODES for c in codes)):
        raise AIAdapterUnavailable("invalid_codes")
    if (not isinstance(identifiers, tuple) or not 1 <= len(identifiers) <= 44
        or any(not isinstance(i, str) or not _OPAQUE_ID.fullmatch(i)
               for i in identifiers) or len(set(identifiers)) != len(identifiers)):
        raise AIAdapterUnavailable("invalid_evidence_ids")
    if (type(features.sources_scanned) is not int
        or type(features.observations_scanned) is not int
        or not 0 <= features.sources_scanned <= 12
        or not 0 <= features.observations_scanned <= 32
        or features.sources_scanned + features.observations_scanned != len(identifiers)):
        raise AIAdapterUnavailable("invalid_counts")
    payload = {
        "schema": features.schema,
        "rule_version": features.rule_version,
        "signal_codes": list(codes),
        "evidence_ids": list(identifiers),
        "sources_scanned": features.sources_scanned,
        "observations_scanned": features.observations_scanned,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded) > 5000:
        raise AIAdapterUnavailable("payload_too_large")
    return {"payload": encoded}


class WorkersAIBindingAdapter:
    """Optional candidate adapter; NEVER selected by the current Worker.

    Arguments are dependency injected so tests do not reach any live model.
    AI.run must be provided by a reviewed external caller in a future phase.
    """

    def __init__(
        self, *, settings: WorkersAISettings = WorkersAISettings(),
        binding: object | None = None, budget: AtomicBudget | None = None,
    ):
        self._settings, self._binding, self._budget = settings, binding, budget

    async def classify(self, features: RedactedFeatures) -> dict:
        # This check runs before touching the model binding or quota.
        if not self._settings.enabled:
            raise AIAdapterUnavailable("feature_disabled")
        if self._binding is None or self._budget is None:
            raise AIAdapterUnavailable("binding_or_budget_unavailable")
        sanitized = _checked_features(features)["payload"]
        # Reservation MUST be durable/atomic in production. Reserve pessimistic
        # maximum tokens; no automatic retry, to prevent surprise charges.
        try:
            allowed = await self._budget.reserve(
                estimated_input_tokens=INPUT_TOKENS_RESERVED,
                max_output_tokens=MAX_OUTPUT_TOKENS,
            )
        except Exception as exc:
            raise AIAdapterUnavailable("budget_unavailable") from exc
        if allowed is not True:
            raise AIAdapterUnavailable("budget_exhausted")
        try:
            response = await self._binding.run(
                self._settings.model,
                {
                    "messages": [
                        {"role": "system", "content": SYSTEM_INSTRUCTION},
                        {"role": "user", "content": sanitized},
                    ],
                    "temperature": 0,
                    "max_tokens": MAX_OUTPUT_TOKENS,
                    "stream": False,
                },
            )
            if hasattr(response, "to_py"):
                response = response.to_py()
            if not isinstance(response, dict) or not set(response).issubset(
                {"response", "usage"}
            ):
                raise ValueError("Unexpected provider envelope")
            raw = response.get("response")
            if not isinstance(raw, str) or not 1 <= len(raw) <= 1024:
                raise ValueError("Unexpected provider response")
            parsed = json.loads(raw)
            if not isinstance(parsed, dict) or set(parsed) != {"risk_code", "evidence_ids"}:
                raise ValueError("Provider output schema mismatch")
            code, refs = parsed["risk_code"], parsed["evidence_ids"]
            ids = json.loads(sanitized)["evidence_ids"]
            if (not isinstance(code, str) or code not in _ALLOWED_OUTPUT
                or not isinstance(refs, list) or not 1 <= len(refs) <= 8
                or len(refs) != len(set(map(str, refs)))
                or any(not isinstance(r, str) or r not in ids for r in refs)):
                raise ValueError("Untrusted response fields")
            return {
                "risk_code": code, "evidence_ids": refs,
                # Trusted local model marker, not an untrusted provider claim.
                "model_version": LOCAL_MODEL_VERSION,
            }
        except Exception as exc:
            # No raw output, token, cost, prompt or exception string escapes.
            raise AIAdapterUnavailable("provider_unavailable_or_invalid") from exc
