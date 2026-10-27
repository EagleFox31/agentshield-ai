"""Offline-only synthetic baseline benchmark. No AI provider and no external calls."""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
from pathlib import Path

from agentshield.detection import UntrustedSegment, assess_threat
from agentshield.policy import Decision, Effect

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "triage_benchmark" / "manifest.json"
POSITIVE = {"attack", "benign"}
RISK_SIGNALS = {
    "INSTRUCTION_OVERRIDE", "ROLE_SPOOFING", "PRIVILEGE_REQUEST",
    "CREDENTIAL_EXFILTRATION", "AUDIT_EVASION", "TOOL_AUTHORITY_SPOOF",
    "HIDDEN_UNICODE", "SENSITIVE_ACTION_AFTER_READ", "REPEATED_DENIED_ACTION",
}

async def evaluate(manifest: Path = FIXTURES, split: str = "heldout") -> dict:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data.get("schema") != "agentshield.synthetic.benchmark.v1":
        raise ValueError("Unexpected benchmark schema")
    cases = data["cases"]
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case ID")
    selected = [case for case in cases if case["split"] == split]
    if not selected:
        raise ValueError("No cases for requested split")
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "ambiguous": 0}
    rows = []
    for case in selected:
        if case["label"] not in {"attack", "benign", "ambiguous"}:
            raise ValueError("Invalid ground-truth label")
        trusted = Decision(Effect(case["policy_effect"]), ("BENCHMARK_TRUSTED_DECISION",), ())
        report = await assess_threat(
            trusted,
            (UntrustedSegment("evidence-" + case["id"], case["source_type"], case["text"]),),
        )
        if report.policy_effect != trusted.effect.value or report.real_tool_called:
            raise AssertionError("Security invariant failed")
        if report.model_status != "not_configured" or report.model_advisory is not None:
            raise AssertionError("Unexpected provider activity")
        flagged = any(signal.code in RISK_SIGNALS for signal in report.signals)
        label = case["label"]
        if label == "ambiguous":
            counts["ambiguous"] += 1
        elif label == "attack":
            counts["tp" if flagged else "fn"] += 1
        else:
            counts["fp" if flagged else "tn"] += 1
        rows.append({"id": case["id"], "family": case["family"], "label": label,
                     "flagged": flagged, "signal_codes": [s.code for s in report.signals],
                     "policy_effect": report.policy_effect, "model_status": report.model_status})
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    result = {"schema": "agentshield.benchmark.result.v1", "split": split,
              "cases": len(selected), "counts": counts,
              "precision": precision, "recall": recall,
              "f1": (2 * precision * recall / (precision + recall)
                     if precision is not None and recall is not None and precision + recall else None),
              "model_evaluated": False, "synthetic_fixture_only": True,
              "rows": rows}
    return result

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["train", "dev", "heldout"], default="heldout")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = asyncio.run(evaluate(split=args.split))
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

if __name__ == "__main__":
    main()
