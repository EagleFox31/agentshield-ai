"""Advisory-only hybrid threat detection on transient untrusted content.

The PolicyEngine Decision is passed through unchanged. Neither these pattern
rules nor an optional model adapter can mint scopes, approve, or execute tools.
Source strings are processed in memory and never included in reports or
model requests: only bounded reason codes and opaque evidence references.
"""
from __future__ import annotations

import asyncio
import re
import time
import unicodedata
from dataclasses import asdict, dataclass
from typing import Mapping, Protocol, Sequence

from agentshield.policy import Decision, Effect

RULESET_VERSION = "agentshield.detector.v1"
_MAX_SEGMENTS = 12
_MAX_TEXT = 8192
_MAX_OBSERVATIONS = 32
_MAX_SIGNALS = 32
_EVIDENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,95}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SOURCE_TYPES = frozenset({"retrieved_document", "tool_output", "external_page"})
_SEVERITIES = frozenset({"low", "medium", "high"})
_ADVISORY_CODES = frozenset({
    "SUSPICIOUS_INSTRUCTION", "POSSIBLE_EXFILTRATION",
    "POSSIBLE_TOOL_HIJACK", "BENIGN_CONTEXT", "UNCERTAIN",
})
_SUMMARIES = {
    "SUSPICIOUS_INSTRUCTION": "Untrusted content may contain instructions to the agent.",
    "POSSIBLE_EXFILTRATION": "Review a possible credential-disclosure request.",
    "POSSIBLE_TOOL_HIJACK": "Review a proposed sensitive tool action.",
    "BENIGN_CONTEXT": "No additional model concern reported for cited evidence.",
    "UNCERTAIN": "Model classification is uncertain; retain deterministic controls.",
}
# These heuristics intentionally have incomplete recall. They are not policy
# rules, and matches do not prove intent or a successful prompt injection.
_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("INSTRUCTION_OVERRIDE", "high", re.compile(
        r"\b(?:ignore|disregard|override)\s+(?:all\s+)?"
        r"(?:previous|earlier|prior|system|developer)\s+(?:instructions|rules|messages|prompts)\b")),
    ("ROLE_SPOOFING", "high", re.compile(
        r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+"
        r"(?:the\s+|an?\s+)?(?:system|developer|(?:finance\s+)?administrator|admin|root)\b")),
    ("PRIVILEGE_REQUEST", "high", re.compile(
        r"\b(?:claim|grant|add|assume|obtain|elevate)\s+"
        r"(?:the\s+|your\s+)?(?:scope|permission|privilege|role|admin)\b")),
    ("CREDENTIAL_EXFILTRATION", "high", re.compile(
        r"\b(?:send|upload|transmit|exfiltrate|forward)\b"
        r".{0,90}\b(?:token|secret|api\s*key|password|credentials?)\b")),
    ("AUDIT_EVASION", "high", re.compile(
        r"\b(?:disable\s+(?:audit|logging)|delete\s+(?:the\s+)?audit"
        r"|do\s+not\s+log|without\s+(?:logging|audit))\b")),
    ("TOOL_AUTHORITY_SPOOF", "medium", re.compile(
        r"\b(?:tool\s+(?:result|output)|retrieved\s+document)\s+"
        r"(?:overrides|supersedes|is\s+(?:a\s+)?(?:system|developer))\b")),
)


@dataclass(frozen=True)
class UntrustedSegment:
    evidence_id: str
    source_type: str
    text: str

    def __post_init__(self):
        if not isinstance(self.evidence_id, str) or not _EVIDENCE.fullmatch(self.evidence_id):
            raise ValueError("Invalid opaque evidence ID")
        if self.source_type not in _SOURCE_TYPES or not isinstance(self.text, str):
            raise ValueError("Invalid untrusted segment")


@dataclass(frozen=True)
class ToolObservation:
    evidence_id: str
    action_category: str
    effect: Effect

    def __post_init__(self):
        if not isinstance(self.evidence_id, str) or not _EVIDENCE.fullmatch(self.evidence_id):
            raise ValueError("Invalid observation ID")
        if self.action_category not in ("read", "supplier_mutation", "data_export", "other_sensitive"):
            raise ValueError("Invalid redacted action category")
        if not isinstance(self.effect, Effect):
            raise ValueError("Tool effect must come from PolicyEngine")


@dataclass(frozen=True)
class ThreatSignal:
    code: str
    severity: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class RedactedFeatures:
    """The ONLY payload permitted to reach an optional model adapter."""
    schema: str
    rule_version: str
    signal_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    sources_scanned: int
    observations_scanned: int

    def __post_init__(self):
        if self.schema != "agentshield.triage.features.v1":
            raise ValueError("Unrecognized triage feature schema")


@dataclass(frozen=True)
class ModelAdvisory:
    risk_code: str
    evidence_ids: tuple[str, ...]
    model_version: str
    summary: str


@dataclass(frozen=True)
class ThreatReport:
    rule_version: str
    policy_effect: str
    signals: tuple[ThreatSignal, ...]
    model_status: str
    model_advisory: ModelAdvisory | None
    assessed_sources: int
    assessed_observations: int
    signals_incomplete: bool
    detector_elapsed_ms: float
    # Never include raw text, action arguments, JWT, prompts or URL values.
    enforcement_ready: bool = False
    real_tool_called: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class TriageAdapter(Protocol):
    async def classify(self, features: RedactedFeatures) -> Mapping[str, object]: ...


def _normalize(text: str) -> str:
    # Strip zero-width joiners only in the *inspection copy*; the original
    # source is not forwarded to the adapter.
    folded = unicodedata.normalize("NFKC", text[:_MAX_TEXT]).casefold()
    return "".join(ch for ch in folded if ch not in "\u200b\u200c\u200d\ufeff")


def deterministic_signals(
    sources: Sequence[UntrustedSegment],
    observations: Sequence[ToolObservation] = (),
) -> tuple[tuple[ThreatSignal, ...], bool]:
    if not isinstance(sources, (tuple, list)) or len(sources) > _MAX_SEGMENTS:
        raise ValueError("Too many untrusted source segments")
    if not isinstance(observations, (tuple, list)) or len(observations) > _MAX_OBSERVATIONS:
        raise ValueError("Too many redacted tool observations")
    if any(not isinstance(item, UntrustedSegment) for item in sources):
        raise ValueError("Invalid source")
    if any(not isinstance(item, ToolObservation) for item in observations):
        raise ValueError("Invalid observation")
    identifiers = [item.evidence_id for item in (*sources, *observations)]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Evidence identifiers must be unique")

    result: list[ThreatSignal] = []
    incomplete = False
    for source in sources:
        if len(source.text) > _MAX_TEXT:
            incomplete = True
            result.append(ThreatSignal("SOURCE_TRUNCATED", "medium", (source.evidence_id,)))
        sample = _normalize(source.text)
        if any(ch in source.text for ch in ("\u200b", "\u200c", "\ufeff", "\u2060")):
            result.append(ThreatSignal("HIDDEN_UNICODE", "medium", (source.evidence_id,)))
        for code, severity, pattern in _PATTERNS:
            if pattern.search(sample):
                result.append(ThreatSignal(code, severity, (source.evidence_id,)))

    for idx, event in enumerate(observations):
        if idx and event.action_category in ("supplier_mutation", "data_export", "other_sensitive"):
            earlier = observations[:idx]
            if any(previous.action_category == "read" for previous in earlier):
                result.append(ThreatSignal(
                    "SENSITIVE_ACTION_AFTER_READ", "medium",
                    (earlier[-1].evidence_id, event.evidence_id),
                ))
        if (event.effect == Effect.DENY
            and any(previous.effect == Effect.DENY for previous in observations[:idx])):
            result.append(ThreatSignal("REPEATED_DENIED_ACTION", "medium", (event.evidence_id,)))

    if len(result) > _MAX_SIGNALS:
        incomplete = True
        result = result[:_MAX_SIGNALS - 1] + [
            ThreatSignal("SIGNAL_LIMIT_REACHED", "medium", (identifiers[-1],))
        ]
    return tuple(result), incomplete


def _validate_model_answer(answer: Mapping, allowed_ids: frozenset[str]) -> ModelAdvisory:
    if not isinstance(answer, Mapping) or set(answer) != {
        "risk_code", "evidence_ids", "model_version",
    }:
        raise ValueError("Model response contains untrusted or unauthorized fields")
    code, ids, version = answer["risk_code"], answer["evidence_ids"], answer["model_version"]
    if code not in _ADVISORY_CODES or not isinstance(version, str) or not _MODEL.fullmatch(version):
        raise ValueError("Invalid model classification")
    if (not isinstance(ids, (list, tuple)) or not 1 <= len(ids) <= 8
        or any(not isinstance(value, str) or value not in allowed_ids for value in ids)
        or len(ids) != len(set(ids))):
        raise ValueError("AI must cite already known evidence IDs")
    return ModelAdvisory(code, tuple(ids), version, _SUMMARIES[code])


async def assess_threat(
    decision: Decision,
    sources: Sequence[UntrustedSegment],
    observations: Sequence[ToolObservation] = (),
    *,
    model: TriageAdapter | None = None,
    timeout_seconds: float = 0.25,
) -> ThreatReport:
    """Return a risk report; never modifies policy, approval or execution.

    A bad model result, timeout or exception is contained as unavailable.
    Even 'benign' model classifications cannot turn DENY into ALLOW.
    """
    if not isinstance(decision, Decision) or not isinstance(decision.effect, Effect):
        raise ValueError("A trusted deterministic PolicyEngine decision is required")
    if not 0 < timeout_seconds <= 1:
        raise ValueError("Invalid model timeout")
    start = time.perf_counter()
    signals, incomplete = deterministic_signals(sources, observations)
    status = "not_configured"
    advisory = None
    if model is not None:
        features = RedactedFeatures(
            schema="agentshield.triage.features.v1",
            rule_version=RULESET_VERSION,
            signal_codes=tuple(signal.code for signal in signals),
            evidence_ids=tuple(item.evidence_id for item in (*sources, *observations)),
            sources_scanned=len(sources),
            observations_scanned=len(observations),
        )
        try:
            raw = await asyncio.wait_for(model.classify(features), timeout=timeout_seconds)
            advisory = _validate_model_answer(raw, frozenset(features.evidence_ids))
            status = "available"
        except asyncio.TimeoutError:
            status = "timeout"
        except (Exception,):
            # No exception messages, model-generated text, prompt or secret leaks.
            status = "unavailable_or_invalid"
    return ThreatReport(
        rule_version=RULESET_VERSION, policy_effect=decision.effect.value,
        signals=signals, model_status=status, model_advisory=advisory,
        assessed_sources=len(sources), assessed_observations=len(observations),
        signals_incomplete=incomplete,
        detector_elapsed_ms=round((time.perf_counter() - start) * 1000, 3),
    )
