"""Write OFFLINE/local D1 policy fixture SQL, never connect to D1 or cloud.

The published JSON and SHA-256 are derived from the same demo rules as
the current PolicyEngine. This command only writes SQL for review/local CI.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from agentshield.demo_invoice import demo_rule_records
from agentshield.policy import Principal
from agentshield.policy_registry import canonical_snapshot

TENANT = "ci_local"
VERSION = "ci-local-policy-v1"
PRINCIPAL = Principal("ci_local:local-demo-agent", frozenset({
    "invoice:read", "supplier:write",
}))


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def make_sql() -> str:
    rules_json, digest = canonical_snapshot(
        TENANT, VERSION, demo_rule_records(PRINCIPAL),
    )
    return (
        "-- Offline-reviewed local test fixture; no cloud or production use.\n"
        "INSERT OR IGNORE INTO policy_versions "
        "(tenant_id,version,sha256,created_at_ms,rules_json) VALUES ("
        f"{sql_literal(TENANT)},{sql_literal(VERSION)},"
        f"{sql_literal(digest)},1790000000000,{sql_literal(rules_json)});\n"
        "INSERT OR IGNORE INTO active_policy_versions "
        "(tenant_id,version,activated_at_ms) VALUES ("
        f"{sql_literal(TENANT)},{sql_literal(VERSION)},1790000000000);\n"
    )


REVIEWED_V2 = "ci-local-policy-v2"


def reviewed_v2_digest() -> str:
    return canonical_snapshot(
        TENANT, REVIEWED_V2, demo_rule_records(PRINCIPAL),
    )[1]


def reviewed_v2_sql() -> str:
    """Publish but never activate the identical-rules V2 local test fixture."""
    rules_json, digest = canonical_snapshot(
        TENANT, REVIEWED_V2, demo_rule_records(PRINCIPAL),
    )
    return (
        "INSERT OR IGNORE INTO policy_versions "
        "(tenant_id,version,sha256,created_at_ms,rules_json) VALUES ("
        f"{sql_literal(TENANT)},{sql_literal(REVIEWED_V2)},"
        f"{sql_literal(digest)},1790000000001,{sql_literal(rules_json)});\\n"
    ).replace("\\\\n", "\\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-v2", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite an existing fixture SQL file")
    args.output.write_text(make_sql() + (reviewed_v2_sql() if args.include_v2 else ""), encoding="utf-8")
    print("Prepared reviewed CI-only tenant policy seed SQL; no D1 connection.")


if __name__ == "__main__":
    main()
