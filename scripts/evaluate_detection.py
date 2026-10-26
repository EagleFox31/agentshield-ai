"""Measure synthetic detector FP/FN and local runtime overhead.

The numbers describe ONLY this versioned, synthetic test corpus. They are
not production detection performance or effectiveness against real agents.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

from agentshield.detection import (
    RULESET_VERSION, UntrustedSegment, assess_threat,
)
from agentshield.policy import Effect, PolicyEngine, Principal, ToolAction

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/detection_v1.json"


def metrics() -> dict:
    corpus = json.loads(FIXTURES.read_text(encoding="utf-8"))
    if corpus["schema"] != "agentshield.synthetic-detector-fixtures.v1":
        raise ValueError("Unrecognized corpus")
    principal = Principal("synthetic_tenant:agent-01", frozenset({"invoice:read"}))
    baseline = PolicyEngine([]).evaluate(principal, ToolAction("invoices", "read", "invoice/42"))
    tp = tn = fp = fn = 0
    seconds = []
    rows = []
    for item in corpus["cases"]:
        source = UntrustedSegment(item["id"], item["source_type"], item["text"])
        start = time.perf_counter()
        result = asyncio.run(assess_threat(baseline, [source]))
        seconds.append((time.perf_counter() - start) * 1000)
        codes = [signal.code for signal in result.signals]
        if not set(item["expected_codes"]).issubset(set(codes)):
            raise AssertionError("Fixture expected code mismatch: " + item["id"])
        attack = item["label"] == "attack"
        predicted = any(code not in ("SOURCE_TRUNCATED", "HIDDEN_UNICODE") for code in codes)
        if attack and predicted:
            tp += 1
        elif attack:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
        if result.policy_effect != Effect.DENY.value:
            raise AssertionError("Detector modified the deterministic baseline")
        rows.append({
            "evidence_id": item["id"], "label": item["label"],
            "predicted_suspicious": predicted, "reason_codes": codes,
        })
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    duration_sorted = sorted(seconds)
    return {
        "corpus_version": corpus["schema"],
        "detector_version": RULESET_VERSION,
        "model_provider": "not_configured",
        "real_model_evaluated": False,
        "sample_size": len(rows), "repetitions": 1,
        "confusion_matrix": {
            "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn,
        },
        "precision": precision, "recall": recall,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "latency_ms": {
            "median": round(statistics.median(seconds), 3),
            "p95_nearest_rank": round(duration_sorted[max(0, (95 * len(duration_sorted) + 99) // 100 - 1)], 3),
            "total": round(sum(seconds), 3),
        },
        "per_fixture": rows,
        "limitations": [
            "Small manually authored synthetic test set, not an independent benchmark.",
            "Pattern matching may miss novel, paraphrased or obfuscated attacks.",
            "Quoted/fictional text can trigger false alarms.",
            "No live LLM provider, real tool or externally generated adversary was tested.",
            "PolicyEngine authorization is independent of detector classification.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentShield synthetic advisory detector report")
    parser.add_argument("--assert-contract", action="store_true")
    args = parser.parse_args()
    report = metrics()
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.assert_contract:
        expected = {"true_positive": 7, "false_positive": 1,
                    "true_negative": 7, "false_negative": 1}
        if report["sample_size"] != 16 or report["confusion_matrix"] != expected:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
