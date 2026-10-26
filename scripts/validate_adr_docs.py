"""Read-only, offline validation for AgentShield architecture decisions.

Checks dated ADR coverage and relative links. Never contacts Cloudflare,
publishes a blockchain transaction or starts a deployment.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADR_DIR = ROOT / "docs" / "adr"
EXPECTED = 8
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def main() -> int:
    files = [ADR_DIR / "README.md"] + sorted(ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md"))
    files.extend((ROOT / "docs" / "MVP_SCOPE.md", ROOT / "docs" / "ARCHITECTURE.md"))
    findings: list[str] = []

    decisions = [path for path in files if path.name[:4].isdigit()]
    if len(decisions) != EXPECTED:
        findings.append(f"Expected {EXPECTED} ADRs, found {len(decisions)}.")

    index = (ADR_DIR / "README.md").read_text(encoding="utf-8")
    for number in range(1, EXPECTED + 1):
        if f"{number:04d}" not in index:
            findings.append(f"ADR index omits {number:04d}.")

    for path in files:
        if not path.is_file():
            findings.append(f"Missing documentation: {path}")
            continue
        body = path.read_text(encoding="utf-8")
        if not body.startswith("# "):
            findings.append(f"{path}: missing top-level heading.")
        if path.name[:4].isdigit():
            if f"ADR-{path.name[:4]}" not in body:
                findings.append(f"{path}: title does not match ADR number.")
            if "**Date:**" not in body or "**Status:**" not in body:
                findings.append(f"{path}: missing decision date or status.")
        for target in LINK.findall(body):
            target = target.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            resolved = path.parent / target
            if not resolved.exists():
                findings.append(f"{path.relative_to(ROOT)}: dangling link: {target}")

    mvp = (ROOT / "docs" / "MVP_SCOPE.md").read_text(encoding="utf-8")
    for expected in ("FastAPI", "JWT", "SQLite", "D1", "Merkle", "Definition of Done"):
        if expected not in mvp:
            findings.append(f"MVP_SCOPE missing required decision/exit topic: {expected}")

    if findings:
        for finding in findings:
            print("FAIL:", finding)
        return 1
    print(f"OK: {EXPECTED} ADRs, MVP scope, architecture and relative links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
