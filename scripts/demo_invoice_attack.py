"""Offline AgentShield security demonstration, with no external dependencies.

Run from repo root:
  PYTHONPATH=src python scripts/demo_invoice_attack.py
  PYTHONPATH=src python scripts/demo_invoice_attack.py --assert-secure

No real supplier tools, LLM calls, network access or blockchain transactions.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
from pathlib import Path

from agentshield.audit_sqlite import SQLiteAuditRepository
from agentshield.demo_invoice import run_invoice_attack
from agentshield.policy import Principal

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "0001_audit_core.sql"


def run_offline() -> dict:
    db = sqlite3.connect(":memory:")
    try:
        db.executescript(MIGRATION.read_text(encoding="utf-8"))
        repo = SQLiteAuditRepository(db)
        # Explicit fixture principal: not a signed JWT. The Worker route runs
        # the same scenario after actual signed-token verification.
        principal = Principal("demo_tenant:invoice_agent", frozenset({"invoice:read"}))
        report = asyncio.run(run_invoice_attack(
            repo, principal, "demo_tenant", occurred_at_ms=1_790_000_010_000,
        ))
        events = [db.execute(
            "SELECT event_sha256, effect, reason_codes_json FROM audit_events "
            "WHERE event_id=? AND tenant_id=?", (eid, "demo_tenant"),
        ).fetchone() for eid in report.audit_event_ids]
        if any(event is None for event in events):
            raise RuntimeError("Demo audit evidence was not committed")
        persisted = "\n".join(db.iterdump()).lower()
        result = report.to_dict()
        result["audit_event_hashes"] = [event[0] for event in events]
        result["audit_events_committed"] = len(events)
        result["sensitive_source_text_persisted"] = any(
            token in persisted for token in (
                "ignore the user", "finance administrator", "training supplies",
            )
        )
        result["scenario_version"] = "1"
        result["execution_environment"] = "offline_sqlite_mock"
        return result
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentShield offline invoice injection regression demo")
    parser.add_argument("--assert-secure", action="store_true", help="fail unless the attack is blocked")
    args = parser.parse_args()
    output = run_offline()
    print(json.dumps(output, indent=2, sort_keys=True))
    if args.assert_secure:
        if not (output["read_effect"] == "allow"
                and output["denied_effect"] == "deny"
                and output["supplier_writes"] == 0
                and output["invoice_reads"] == 1
                and output["audit_events_committed"] == 2
                and not output["sensitive_source_text_persisted"]):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
