"""Offline, independently executable Merkle verifier for AgentShield audit logs.

The trusted commitment must be obtained from a SEPARATE source (e.g. a
verified published anchor). The CLI does not fetch chain data, attest to
finality or print 'verified on-chain' from an untrusted manifest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentshield.audit import AuditEvent
from agentshield.merkle import (
    InvalidEvidence, verify_complete_batch, verify_inclusion,
    verify_manifest_chain,
)


def parse_events(path: Path) -> list[AuditEvent]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise InvalidEvidence("Expected a JSON list of canonical audit events")
    fields = set(AuditEvent.__dataclass_fields__)
    result = []
    for item in data:
        if not isinstance(item, dict) or set(item) != fields:
            raise InvalidEvidence("Invalid event data shape")
        result.append(AuditEvent(**{
            **item, "reason_codes": tuple(item["reason_codes"]),
        }))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline AgentShield Merkle verifier")
    sub = parser.add_subparsers(dest="command", required=True)
    complete = sub.add_parser("batch")
    complete.add_argument("--manifest", required=True, type=Path)
    complete.add_argument("--events", required=True, type=Path)
    complete.add_argument("--trusted-commitment", required=True,
                          help="Externally pinned SHA-256 commitment, NOT merely copied from manifest")
    inclusion = sub.add_parser("inclusion")
    inclusion.add_argument("--manifest", required=True, type=Path)
    inclusion.add_argument("--event", required=True, type=Path)
    inclusion.add_argument("--proof", required=True, type=Path)
    inclusion.add_argument("--trusted-commitment", required=True)
    chain = sub.add_parser("chain")
    chain.add_argument("--manifests", required=True, type=Path)
    chain.add_argument("--trusted-head", required=True,
                       help="Externally pinned head commitment")
    args = parser.parse_args(argv)

    try:
        if args.command == "chain":
            manifests = json.loads(args.manifests.read_text(encoding="utf-8"))
            ok = verify_manifest_chain(manifests, trusted_head=args.trusted_head)
        else:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            if args.command == "batch":
                ok = verify_complete_batch(
                    parse_events(args.events), manifest,
                    trusted_commitment=args.trusted_commitment,
                )
            else:
                events = parse_events(args.event)
                if len(events) != 1:
                    raise InvalidEvidence("Inclusion mode expects one audit event")
                proof = json.loads(args.proof.read_text(encoding="utf-8"))
                ok = verify_inclusion(
                    events[0], manifest, proof,
                    trusted_commitment=args.trusted_commitment,
                )
        print(json.dumps({
            "result": "matches_supplied_trust_root" if ok else "invalid",
            "onchain_finality_verified": False,
            "note": "Trust root must be acquired independently; this CLI makes no network calls.",
        }, sort_keys=True))
        return 0 if ok else 2
    except (InvalidEvidence, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({
            "result": "invalid_or_incomplete_evidence",
            "onchain_finality_verified": False,
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
